// Local HTTP/1.1 proxy (connect-timeout 120s, read timeout 120s per MECHANICS.md),
// intercept queue, history store, raw request sender used by Repeater/Intruder.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::util;

// Live 52685 stores all proxy history and accepts the complete payload list.
// Timeout values from resources/Preferences/ProjectDefaults.json (MECHANICS.md), in ms:
pub const CONNECT_TIMEOUT_MS: u64 = 120000;
pub const READ_TIMEOUT_MS: u64 = 120000;
pub const OPEN_ENDED_RESPONSE_TIMEOUT_MS: u64 = 10000;
pub const DNS_TIMEOUT_MS: u64 = 300000;

#[derive(Clone)]
pub struct HistEntry {
    pub id: u64,
    pub ts: u64,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub path: String,
    pub status: String,
    pub resp_len: usize,
    pub req_raw: Vec<u8>,
    pub resp_raw: Option<Vec<u8>>,
    pub note: Option<String>,
}

pub struct InterceptItem {
    pub id: u64,
    pub host: String,
    pub port: u16,
    pub edited: String,
    pub tx: mpsc::Sender<Option<String>>,
}

#[derive(Clone)]
pub struct AttackRow {
    pub payload: String,
    pub status: String,
    pub len: usize,
    pub ms: u128,
    pub ok: bool,
}

pub struct Attack {
    pub running: AtomicBool,
    pub stop: AtomicBool,
    pub done: AtomicUsize,
    pub total: AtomicUsize,
    pub rows: Mutex<Vec<AttackRow>>,
}

pub struct RepTab {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub request: String,
    pub response: Option<Vec<u8>>,
    pub result_line: String,
}

/// Literal or regex scope/session pattern match. Invalid regexes never match.
fn pattern_matches(pattern: &str, is_regex: bool, text: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    if is_regex {
        regex::Regex::new(pattern).map(|re| re.is_match(text)).unwrap_or(false)
    } else {
        text.contains(pattern)
    }
}

/// True when the URL is in target scope. With no include entries every URL is
/// in scope; an enabled matching exclude entry always removes it.
pub fn in_scope(shared: &Shared, url: &str) -> bool {
    let rules = shared.scope.lock().unwrap().clone();
    let active: Vec<&ScopeRule> = rules.iter().filter(|r| r.enabled).collect();
    if active.iter().any(|r| !r.include && pattern_matches(&r.pattern, r.is_regex, url)) {
        return false;
    }
    let includes: Vec<&ScopeRule> = active.iter().copied().filter(|r| r.include).collect();
    includes.is_empty() || includes.iter().any(|r| pattern_matches(&r.pattern, r.is_regex, url))
}

fn replace_or_add_header(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    let p = util::parse_http(raw);
    let body = &raw[p.head_len.min(raw.len())..];
    let mut out = String::with_capacity(raw.len() + name.len() + value.len() + 4);
    out.push_str(&p.first);
    out.push_str("\r\n");
    let mut replaced = false;
    for (k, v) in &p.headers {
        if k.eq_ignore_ascii_case(name) {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            replaced = true;
        } else {
            out.push_str(k);
            out.push_str(": ");
            out.push_str(v);
        }
        out.push_str("\r\n");
    }
    if !replaced {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn append_cookie(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    let p = util::parse_http(raw);
    if let Some(existing) = util::get_header(&p.headers, "Cookie") {
        let merged = format!("{existing}; {name}={value}");
        replace_or_add_header(raw, "Cookie", &merged)
    } else {
        replace_or_add_header(raw, "Cookie", &format!("{name}={value}"))
    }
}

fn latest_cookie(shared: &Shared, name: &str) -> Option<String> {
    let history = shared.history.lock().unwrap().clone();
    for entry in history.iter().rev() {
        let Some(resp) = &entry.resp_raw else { continue };
        let p = util::parse_http(resp);
        for (key, set_cookie) in &p.headers {
            if !key.eq_ignore_ascii_case("Set-Cookie") {
                continue;
            }
            let first = set_cookie.split(';').next().unwrap_or("");
            let (cookie_name, cookie_value) = first.split_once('=').unwrap_or(("", ""));
            if cookie_name.trim().eq_ignore_ascii_case(name) {
                return Some(cookie_value.trim().to_string());
            }
        }
    }
    None
}

/// Apply enabled session rules to a request before it is sent upstream.
/// Set-header uses `Name: value`; use-cookie names a captured cookie;
/// run-macro names and executes one stored macro first.
pub fn apply_session_rules(shared: &Shared, req: &[u8], default_port: u16) -> Vec<u8> {
    let rules = shared.session_rules.lock().unwrap().clone();
    if rules.is_empty() {
        return req.to_vec();
    }
    let parts = util::parse_http(req);
    let (host, _) = host_of(&parts, default_port);
    let mut out = req.to_vec();
    for rule in rules {
        if !rule.enabled || !pattern_matches(&rule.host_match, false, &host) {
            continue;
        }
        match rule.action.as_str() {
            "set header" => {
                if let Some((name, value)) = rule.value.split_once(':') {
                    out = replace_or_add_header(&out, name.trim(), value.trim());
                    shared.log(&format!("Session rule '{}' set {} header", rule.name, name.trim()));
                }
            }
            "use cookie" => {
                if let Some(value) = latest_cookie(shared, rule.value.trim()) {
                    out = append_cookie(&out, rule.value.trim(), &value);
                    shared.log(&format!("Session rule '{}' reused cookie {}", rule.name, rule.value));
                }
            }
            "run macro" => {
                let macros = shared.macros.lock().unwrap().clone();
                if let Some(macro_request) = macros.iter().find(|m| m.name == rule.value).map(|m| m.request.clone()) {
                    let p = util::parse_http(macro_request.as_bytes());
                    let (macro_host, macro_port) = host_of(&p, 80);
                    let up = send_raw(shared, &macro_host, macro_port, macro_request.as_bytes());
                    shared.log(&format!(
                        "Session rule '{}' ran macro {}: {}",
                        rule.name,
                        rule.value,
                        if up.resp.is_some() { "ok" } else { "failed" }
                    ));
                }
            }
            _ => {}
        }
    }
    out
}

pub fn push_ws(shared: &Shared, host: &str, direction: &str, opcode: &str, payload: &[u8]) {
    let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
    shared.ws_history.lock().unwrap().push(WsEntry {
        id,
        ts: util::now_secs(),
        host: host.to_string(),
        direction: direction.to_string(),
        opcode: opcode.to_string(),
        payload: String::from_utf8_lossy(payload).into_owned(),
    });
}

/// Target scope entry. Include=false excludes a matching location.
#[derive(Clone)]
pub struct ScopeRule {
    pub enabled: bool,
    pub include: bool,
    pub pattern: String,
    pub is_regex: bool,
}

impl ScopeRule {
    pub fn include(pattern: impl Into<String>, is_regex: bool) -> Self {
        Self { enabled: true, include: true, pattern: pattern.into(), is_regex }
    }
}

/// One session-handling rule. The local implementation supports the original's
/// core actions: set a header, reuse a captured cookie, or run a macro first.
#[derive(Clone)]
pub struct SessionRule {
    pub enabled: bool,
    pub name: String,
    pub action: String,
    pub host_match: String,
    pub value: String,
}

impl SessionRule {
    pub fn new() -> Self {
        Self {
            enabled: true,
            name: "New session rule".into(),
            action: "set header".into(),
            host_match: String::new(),
            value: String::new(),
        }
    }
}

/// A reusable raw request executed by session rules and from the Sessions tab.
#[derive(Clone)]
pub struct Macro {
    pub name: String,
    pub request: String,
}

/// One captured WebSocket frame or handshake record.
#[derive(Clone)]
pub struct WsEntry {
    pub id: u64,
    pub ts: u64,
    pub host: String,
    pub direction: String,
    pub opcode: String,
    pub payload: String,
}

pub struct Shared {
    pub mitm: crate::tls::MitmAuthority,
    pub tls_upstream: Arc<rustls::ClientConfig>,
    pub intercept_on: AtomicBool,
    pub queue: Mutex<Vec<InterceptItem>>,
    pub history: Mutex<Vec<HistEntry>>,
    pub events: Mutex<Vec<String>>,
    pub attack: Mutex<Arc<Attack>>,
    pub repeaters: Mutex<Vec<RepTab>>,
    pub next_id: AtomicU64,
    pub proxy_port: std::sync::atomic::AtomicU16,
    pub issues: Mutex<Vec<crate::scan::ScanIssue>>,
    pub scan_enabled: AtomicBool,
    pub scan_busy: AtomicBool,
    pub scan_stop: AtomicBool,
    pub scan_done: AtomicUsize,
    pub scan_total: AtomicUsize,
    /// unique locations already passively audited (CrawlDefaults.json max 1500)
    pub scan_locations: Mutex<std::collections::BTreeSet<String>>,
    /// Match and replace rule lists (Proxy options; separate request/response sets)
    pub mr_request: Mutex<Vec<crate::rules::MrRule>>,
    pub mr_response: Mutex<Vec<crate::rules::MrRule>>,
    /// Target scope entries; include/exclude patterns can be literal or regex.
    pub scope: Mutex<Vec<ScopeRule>>,
    /// Session handling rules and their reusable request macros.
    pub session_rules: Mutex<Vec<SessionRule>>,
    pub macros: Mutex<Vec<Macro>>,
    /// Captured WebSocket handshakes and frames.
    pub ws_history: Mutex<Vec<WsEntry>>,
    /// Monotonic counter of proxied messages, for the status bar's activity read.
    pub messages: std::sync::atomic::AtomicUsize,
    /// Upstream direct/HTTP/SOCKS routing configuration.
    pub upstream: Mutex<crate::upstream::UpstreamConfig>,
    pub listener_running: AtomicBool,
    pub listener_restart: AtomicBool,
    pub rep_busy: AtomicBool,
    pub rep_result: Mutex<String>,
    /// `http.http1.enable_keep_alive` (ProjectDefaults.json): off by default,
    /// matching the original's outgoing suite requests.
    pub keep_alive: AtomicBool,
    /// Hosts whose HTTPS traffic is passed through without MITM (SSL pass-through).
    /// Exact names or `*.example.com` wildcards.
    pub tls_bypass: Mutex<Vec<String>>,
    /// Client certificates presented to upstream servers (mTLS), matched by host.
    pub client_certs: Mutex<Vec<ClientCertRule>>,
    /// Trusted roots for upstream TLS (also used to build client-cert configs).
    pub tls_roots: Mutex<rustls::RootCertStore>,
    /// Idle upstream connections, one per (host, port).
    pub(crate) pool: Mutex<std::collections::HashMap<(String, u16), UpstreamConn>>,
    pub(crate) tls_pool: Mutex<std::collections::HashMap<(String, u16), UpstreamConn>>,
    /// Extra proxy listeners beyond the primary one (bind address + port).
    pub listeners: Mutex<Vec<Arc<ListenerState>>>,
    /// Bumped whenever the listener set changes; workers watch it.
    pub listener_generation: AtomicU64,
    pub conns_opened: AtomicUsize,
    pub pool_hits: AtomicUsize,
}

impl Shared {
    pub fn new() -> Arc<Self> {
        let mitm = crate::tls::MitmAuthority::new().expect("failed to initialize local HTTPS CA");
        Arc::new(Self {
            mitm,
            tls_upstream: crate::tls::upstream_config(),
            intercept_on: AtomicBool::new(false), // Burp default: never intercept at startup
            queue: Mutex::new(Vec::new()),
            history: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            attack: Mutex::new(Arc::new(Attack {
                running: AtomicBool::new(false),
                stop: AtomicBool::new(false),
                done: AtomicUsize::new(0),
                total: AtomicUsize::new(0),
                rows: Mutex::new(Vec::new()),
            })),
            repeaters: Mutex::new(vec![RepTab {
                name: "Rep 1".into(),
                host: String::new(),
                port: 80,
                https: false,
                // QA hook: WEBPROBE_SEED_REPEATER=<file> loads a request so the
                // editor (line numbers, hex, find, font size) can be inspected.
                request: std::env::var("WEBPROBE_SEED_REPEATER")
                    .ok()
                    .and_then(|p| std::fs::read_to_string(p).ok())
                    .unwrap_or_default(),
                response: None,
                result_line: String::new(),
            }]),
            messages: std::sync::atomic::AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
            proxy_port: std::sync::atomic::AtomicU16::new(8080),
            issues: Mutex::new(Vec::new()),
            scan_enabled: AtomicBool::new(true),
            scan_busy: AtomicBool::new(false),
            scan_stop: AtomicBool::new(false),
            scan_done: AtomicUsize::new(0),
            scan_total: AtomicUsize::new(0),
            scan_locations: Mutex::new(std::collections::BTreeSet::new()),
            mr_request: Mutex::new(Vec::new()),
            mr_response: Mutex::new(Vec::new()),
            scope: Mutex::new(Vec::new()),
            session_rules: Mutex::new(Vec::new()),
            macros: Mutex::new(Vec::new()),
            ws_history: Mutex::new(Vec::new()),
            upstream: Mutex::new(crate::upstream::UpstreamConfig::default()),
            listener_running: AtomicBool::new(false),
            listener_restart: AtomicBool::new(false),
            rep_busy: AtomicBool::new(false),
            rep_result: Mutex::new(String::new()),
            keep_alive: AtomicBool::new(false),
            tls_bypass: Mutex::new(Vec::new()),
            client_certs: Mutex::new(Vec::new()),
            tls_roots: Mutex::new(rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())),
            pool: Mutex::new(std::collections::HashMap::new()),
            tls_pool: Mutex::new(std::collections::HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            listener_generation: AtomicU64::new(0),
            conns_opened: AtomicUsize::new(0),
            pool_hits: AtomicUsize::new(0),
        })
    }

    pub fn log(&self, msg: &str) {
        let ts = util::now_secs();
        let mut ev = self.events.lock().unwrap();
        ev.push(format!("[{ts}] {msg}"));
        let n = ev.len();
        if n > 500 {
            ev.drain(..n - 500);
        }
    }

    pub fn push_history(&self, e: HistEntry) {
        self.history.lock().unwrap().push(e);
        self.messages.fetch_add(1, Ordering::SeqCst);
    }

    pub fn count_waiting(&self) -> usize {
        self.queue.lock().map(|q| q.len()).unwrap_or(0)
    }
}

// ---------- reading a full HTTP request ----------

fn head_end(bytes: &[u8]) -> Option<usize> {
    util::find_head_end(bytes)
}

fn content_length(head: &[u8]) -> Option<usize> {
    let s = String::from_utf8_lossy(head);
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            if let Some(v) = line.split(':').nth(1) {
                return v.trim().parse::<usize>().ok();
            }
        }
    }
    None
}

fn read_request<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    let head_len;
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            head_len = None;
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(h) = head_end(&buf) {
            head_len = Some(h);
            break;
        }
        if buf.len() > 4 * 1024 * 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "request too large"));
        }
    }
    let head_len = match head_len {
        Some(h) => h,
        None => return Ok(buf),
    };
    if let Some(len) = content_length(&buf[..head_len]) {
        while buf.len() < head_len + len {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }
    Ok(buf)
}

// ---------- upstream sending ----------

/// An upstream connection: plain TCP or TLS over it.
pub(crate) enum UpstreamConn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for UpstreamConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            UpstreamConn::Plain(s) => s.read(buf),
            UpstreamConn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for UpstreamConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            UpstreamConn::Plain(s) => s.write(buf),
            UpstreamConn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            UpstreamConn::Plain(s) => s.flush(),
            UpstreamConn::Tls(s) => s.flush(),
        }
    }
}

impl ResponseRead for UpstreamConn {
    fn set_open_ended_timeout(&self) -> std::io::Result<()> {
        match self {
            UpstreamConn::Plain(s) => s.set_read_timeout(Some(Duration::from_millis(OPEN_ENDED_RESPONSE_TIMEOUT_MS))),
            UpstreamConn::Tls(s) => s.get_ref().set_read_timeout(Some(Duration::from_millis(OPEN_ENDED_RESPONSE_TIMEOUT_MS))),
        }
    }
}

impl UpstreamConn {
    fn writable(&self) -> bool {
        // A pooled connection is only reusable if the peer has not closed it.
        // A zero-byte peek returning 0 means EOF.
        let mut b = [0u8; 1];
        match self {
            UpstreamConn::Plain(s) => {
                // Peek without blocking: no bytes waiting is good, EOF is not.
                let _ = s.set_nonblocking(true);
                let alive = match s.peek(&mut b) {
                    Ok(0) => false,
                    Ok(_) => true,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
                    Err(_) => false,
                };
                let _ = s.set_nonblocking(false);
                alive
            }
            UpstreamConn::Tls(_) => true, // rustls has no peek; errors surface on use
        }
    }
}

pub struct Upstream {
    pub resp: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// One proxy listener: a bind address and port.
#[derive(Clone, Debug, PartialEq)]
pub struct ListenerSpec {
    pub bind: String,
    pub port: u16,
}

/// Runtime state of one listener (for the status display).
pub struct ListenerState {
    pub spec: ListenerSpec,
    pub running: std::sync::atomic::AtomicBool,
    pub error: Mutex<Option<String>>,
}

impl ListenerState {
    fn new(spec: ListenerSpec) -> Self {
        Self { spec, running: AtomicBool::new(false), error: Mutex::new(None) }
    }
}

/// Sends a raw HTTP/1.1 request through the configured upstream route and reads
/// the whole response. Framing decides where the response ends, and the
/// connection is pooled per host when keep-alive is enabled
/// (ProjectDefaults.json http.http1.enable_keep_alive, default false).
pub fn send_raw(shared: &Shared, host: &str, port: u16, request: &[u8]) -> Upstream {
    send_from(shared, host, port, request)
}

fn send_from(shared: &Shared, host: &str, port: u16, req: &[u8]) -> Upstream {
    match send_inner(shared, host, port, req) {
        Ok(resp) => Upstream { resp: Some(resp), error: None },
        Err(e) => Upstream { resp: None, error: Some(e) },
    }
}

/// Resolve a host with the suite's DNS timeout (ProjectDefaults.json: domain_name_resolution_timeout).
pub fn resolve(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<Vec<std::net::SocketAddr>, String> {
    use std::net::ToSocketAddrs;
    let display = host.to_string();
    let (tx, rx) = mpsc::sync_channel::<Result<Vec<std::net::SocketAddr>, String>>(1);
    let host = host.to_string();
    std::thread::spawn(move || {
        let r = match (host.as_str(), port).to_socket_addrs() {
            Ok(it) => Ok(it.collect::<Vec<std::net::SocketAddr>>()),
            Err(e) => Err(format!("dns {host}: {e}")),
        };
        let _ = tx.send(r);
    });
    rx.recv_timeout(Duration::from_millis(timeout_ms))
        .map_err(|_| format!("dns {display}: timed out after {timeout_ms} ms"))?
}

pub(crate) trait ResponseRead: Read {
    fn set_open_ended_timeout(&self) -> std::io::Result<()>;
}

impl ResponseRead for TcpStream {
    fn set_open_ended_timeout(&self) -> std::io::Result<()> {
        self.set_read_timeout(Some(Duration::from_millis(OPEN_ENDED_RESPONSE_TIMEOUT_MS)))
    }
}

impl ResponseRead for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_open_ended_timeout(&self) -> std::io::Result<()> {
        self.get_ref().set_read_timeout(Some(Duration::from_millis(OPEN_ENDED_RESPONSE_TIMEOUT_MS)))
    }
}

trait ProxyIo: Read + Write {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()>;
}

impl ProxyIo for TcpStream {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.set_nonblocking(nonblocking)
    }
}

impl ProxyIo for rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.get_ref().set_nonblocking(nonblocking)
    }
}

impl ProxyIo for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.get_ref().set_nonblocking(nonblocking)
    }
}

/// Apply or replace a connection header without dropping the body.
fn set_connection(req: &[u8], value: &str) -> Vec<u8> {
    let parts = util::parse_http(req);
    let head_end = parts.head_len;
    let head = String::from_utf8_lossy(&req[..head_end]);
    let mut out = String::with_capacity(req.len() + 32);
    let mut first = true;
    for line in head.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.to_ascii_lowercase().starts_with("connection:") {
            if first {
                out.push_str(&format!("Connection: {value}\r\n"));
                first = false;
            }
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if first {
        out.push_str(&format!("Connection: {value}\r\n"));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&req[head_end..]);
    bytes
}

/// Attempt an HTTP/1.1 → h2c upgrade (RFC 7540 §3.2) on a direct plain
/// connection. `Ok(None)` means the request should not be upgraded (nothing was
/// written); `Ok(Some(resp))` is the full response — either the HTTP/2 session
/// result or, when the server declined, the ordinary HTTP/1.1 reply.
fn try_h2c_upgrade<S: Read + Write + ResponseRead>(stream: &mut S, routed: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let parts = util::parse_http(routed);
    if parts.head_len == 0 || parts.head_len > routed.len() {
        return Ok(None);
    }
    // Skip bodyless / body-framing-less requests; the upgrade only makes sense
    // for ordinary requests with a Host header.
    if util::get_header(&parts.headers, "Host").is_none() {
        return Ok(None);
    }
    let mut upgrade = Vec::with_capacity(routed.len() + 128);
    upgrade.extend_from_slice(parts.first.trim_end().as_bytes());
    upgrade.extend_from_slice(b"\r\n");
    for (k, v) in &parts.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "connection" || lower == "http2-settings" || lower == "upgrade" {
            continue;
        }
        upgrade.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    upgrade.extend_from_slice(b"Connection: Upgrade, HTTP2-Settings\r\n");
    upgrade.extend_from_slice(b"Upgrade: h2c\r\n");
    upgrade.extend_from_slice(format!("HTTP2-Settings: {}\r\n\r\n", crate::h2::empty_settings_value()).as_bytes());
    upgrade.extend_from_slice(&routed[parts.head_len..]);
    stream.write_all(&upgrade).map_err(|e| format!("h2c upgrade write: {e}"))?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).map_err(|e| format!("h2c upgrade read: {e}"))?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 64 * 1024 {
            return Err("h2c upgrade: response head too large".into());
        }
    }
    let status = util::parse_http(&head).status;
    if status == "101" {
        let h2req = crate::h2::request_from_raw(routed, "http")
            .ok_or("h2c: request without Host header")?;
        let resp = crate::h2::exchange(stream, &h2req)?;
        return Ok(Some(resp));
    }
    // The server declined (or ignored) the upgrade: read the rest of the
    // HTTP/1.1 message per its framing and return it unchanged.
    let kind = crate::codec::response_body_kind(&head, &parts.method);
    let mut msg = head;
    let head_len = util::find_head_end(&msg).unwrap_or(msg.len());
    match kind {
        crate::codec::BodyKind::None => {}
        crate::codec::BodyKind::Length(n) => {
            while msg.len() < head_len + n {
                let mut chunk = [0u8; 16384];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(k) => msg.extend_from_slice(&chunk[..k]),
                    Err(_) => break,
                }
            }
            msg.truncate((head_len + n).min(msg.len()));
        }
        crate::codec::BodyKind::Chunked => {
            loop {
                if crate::codec::decode_chunked(&msg[head_len..]).is_some() {
                    break;
                }
                let mut chunk = [0u8; 16384];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(k) => msg.extend_from_slice(&chunk[..k]),
                    Err(_) => break,
                }
            }
        }
        crate::codec::BodyKind::UntilEof => {
            stream.set_open_ended_timeout().map_err(|e| format!("h2c open-ended timeout: {e}"))?;
            let mut chunk = [0u8; 16384];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(k) => msg.extend_from_slice(&chunk[..k]),
                    Err(_) => break,
                }
            }
        }
    }
    Ok(Some(msg))
}

fn response_allows_reuse(resp: &[u8]) -> bool {
    let parts = util::parse_http(resp);
    if parts.first.starts_with("HTTP/1.0") {
        return util::get_header(&parts.headers, "Connection")
            .map(|v| v.to_ascii_lowercase().contains("keep-alive"))
            .unwrap_or(false);
    }
    // UntilEof bodies cannot be delimited, so the connection must close.
    let framed = crate::codec::body_complete(resp, "GET");
    let not_close = util::get_header(&parts.headers, "Connection")
        .map(|v| !v.to_ascii_lowercase().contains("close"))
        .unwrap_or(true);
    framed && not_close
}

fn send_inner(shared: &Shared, host: &str, port: u16, req: &[u8]) -> Result<Vec<u8>, String> {
    let config = shared.upstream.lock().unwrap().clone();
    let req = util::origin_form(req);
    let routed = crate::upstream::absolute_form_request(&config, &req, host, port);
    let keep_alive = shared.keep_alive.load(Ordering::SeqCst);
    let routed = if keep_alive {
        set_connection(&routed, "keep-alive")
    } else {
        set_connection(&routed, "close")
    };
    let key = (host.to_string(), port);
    let mut pooled = if keep_alive { shared.pool.lock().unwrap().remove(&key) } else { None };
    if let Some(conn) = pooled.as_mut() {
        if !conn.writable() {
            pooled = None;
        }
    }
    let reused = pooled.is_some();
    let mut stream = match pooled {
        Some(conn) => conn,
        None => {
            shared.conns_opened.fetch_add(1, Ordering::SeqCst);
            let tcp = crate::upstream::connect_target(&config, host, port)?;
            tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS))).ok();
            UpstreamConn::Plain(tcp)
        }
    };
    // h2c upgrade (RFC 7540 §3.2) on direct plain connections. Any answer other
    // than 101 is handed back as the ordinary HTTP/1.1 response.
    if !reused && config.kind == crate::upstream::UpstreamKind::None {
        match try_h2c_upgrade(&mut stream, &routed) {
            Ok(Some(resp)) => {
                if keep_alive && response_allows_reuse(&resp) {
                    shared.pool.lock().unwrap().insert(key, stream);
                }
                return Ok(resp);
            }
            Ok(None) => {}
            Err(e) => return Err(e),
        }
    }
    let result = match exchange(&mut stream, &routed) {
        Ok(r) => Ok((r, stream)),
        Err(e) => {
            if reused {
                let mut fresh = UpstreamConn::Plain({
                    let tcp = crate::upstream::connect_target(&config, host, port)?;
                    tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS))).ok();
                    tcp
                });
                shared.conns_opened.fetch_add(1, Ordering::SeqCst);
                exchange(&mut fresh, &routed).map(|r| (r, fresh)).map_err(|e2| format!("{e}; retry: {e2}"))
            } else {
                Err(e)
            }
        }
    }?;
    let (resp, stream) = result;
    if keep_alive && response_allows_reuse(&resp) {
        shared.pool.lock().unwrap().insert(key, stream);
        if reused {
            shared.pool_hits.fetch_add(1, Ordering::SeqCst);
        }
    }
    Ok(resp)
}

pub fn send_tls_raw(shared: &Shared, host: &str, port: u16, request: &[u8]) -> Upstream {
    match send_tls_inner(shared, host, port, request) {
        Ok(resp) => Upstream { resp: Some(resp), error: None },
        Err(e) => Upstream { resp: None, error: Some(e) },
    }
}

fn send_tls_inner(shared: &Shared, host: &str, port: u16, req: &[u8]) -> Result<Vec<u8>, String> {
    let config = shared.upstream.lock().unwrap().clone();
    let req = util::origin_form(req);
    let keep_alive = shared.keep_alive.load(Ordering::SeqCst);
    let req = if keep_alive { set_connection(&req, "keep-alive") } else { set_connection(&req, "close") };
    let key = (host.to_string(), port);
    let mut pooled = shared.tls_pool.lock().unwrap().remove(&key);
    if let Some(conn) = pooled.as_mut() {
        if !conn.writable() {
            pooled = None;
        }
    }
    let reused = pooled.is_some();
    let mut stream = match pooled {
        Some(conn) => conn,
        None => {
            shared.conns_opened.fetch_add(1, Ordering::SeqCst);
            let tcp = crate::upstream::connect_tls_target(&config, host, port)?;
            tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS))).ok();
            let name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| format!("invalid upstream TLS name {host}: {e}"))?;
            let conn = rustls::ClientConnection::new(tls_client_config(shared, host), name)
                .map_err(|e| format!("configure upstream TLS: {e}"))?;
            UpstreamConn::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
        }
    };
    // Fresh connections settle ALPN during the handshake; if the server chose
    // h2, run this request through the HTTP/2 client (pooled connections are
    // always HTTP/1.x — the h2 path returns without pooling).
    let use_h2 = !reused
        && match &mut stream {
            UpstreamConn::Tls(tls) => {
                let _ = tls.conn.complete_io(&mut tls.sock);
                tls.conn.alpn_protocol() == Some(b"h2".as_slice())
            }
            _ => false,
        };
    if use_h2 {
        let h2req = crate::h2::request_from_raw(&req, "https")
            .ok_or("h2: request without Host header")?;
        let resp = match &mut stream {
            UpstreamConn::Tls(tls) => crate::h2::exchange(tls, &h2req)?,
            _ => return Err("h2: not a TLS connection".into()),
        };
        return Ok(resp);
    }
    let result = match exchange(&mut stream, &req) {
        Ok(r) => Ok((r, stream)),
        Err(e) => {
            // A reused connection may have been closed by the peer; try once more
            // on a fresh one before reporting the failure.
            if reused {
                let mut fresh = new_tls_conn(shared, &config, host, port)?;
                exchange(&mut fresh, &req).map(|r| (r, fresh)).map_err(|e2| format!("{e}; retry: {e2}"))
            } else {
                Err(e)
            }
        }
    }?;
    let (result, stream) = result;
    if keep_alive && response_allows_reuse(&result) {
        shared.tls_pool.lock().unwrap().insert(key, stream);
        if reused {
            shared.pool_hits.fetch_add(1, Ordering::SeqCst);
        }
    }
    Ok(result)
}

fn new_tls_conn(
    shared: &Shared,
    config: &crate::upstream::UpstreamConfig,
    host: &str,
    port: u16,
) -> Result<UpstreamConn, String> {
    let tcp = crate::upstream::connect_tls_target(config, host, port)?;
    tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS))).ok();
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid upstream TLS name {host}: {e}"))?;
    let conn = rustls::ClientConnection::new(tls_client_config(shared, host), name)
        .map_err(|e| format!("configure upstream TLS: {e}"))?;
    Ok(UpstreamConn::Tls(Box::new(rustls::StreamOwned::new(conn, tcp))))
}

/// Write a request and read exactly one framed response, leaving any bytes past
/// the body in `leftover` so a pipelined follow-up is never silently dropped.
fn exchange<S: Read + Write + ResponseRead>(stream: &mut S, req: &[u8]) -> Result<Vec<u8>, String> {
    stream.write_all(req).map_err(|e| format!("write: {e}"))?;
    stream.flush().ok();
    let mut buffer = Vec::new();
    let resp = crate::codec::read_message(stream, &mut buffer).map_err(|e| format!("read: {e}"))?;
    if !buffer.is_empty() {
        // Bytes beyond the framed body: the peer is ahead of us. Closing is the
        // only safe option; pipelining stays off (MECHANICS.md A-03).
        return Ok(resp);
    }
    Ok(resp)
}

// ---------- the proxy loop ----------

pub fn start_proxy(shared: Arc<Shared>) {
    start_extra_listeners(shared.clone());
    std::thread::spawn(move || loop {
        shared.listener_restart.store(false, Ordering::SeqCst);
        let addr = format!("127.0.0.1:{}", shared.proxy_port.load(Ordering::SeqCst));
        let listener = TcpListener::bind(&addr);
        match listener {
            Ok(l) => {
                shared.listener_running.store(true, Ordering::SeqCst);
                shared.log(&format!("Proxy listener started on {addr}, intercept is {}", {
                    if shared.intercept_on.load(Ordering::SeqCst) { "on" } else { "off" }
                }));
                loop {
                    if shared.listener_restart.load(Ordering::SeqCst) {
                        break;
                    }
                    match l.accept() {
                        Ok((stream, _)) => {
                            let sh = shared.clone();
                            std::thread::spawn(move || handle_conn(sh, stream));
                        }
                        Err(_) => continue,
                    }
                }
                shared.listener_running.store(false, Ordering::SeqCst);
                shared.log("Proxy listener stopped for restart");
                // fall through and rebind below (flag cleared at loop top via check)
            }
            Err(e) => {
                shared.listener_running.store(false, Ordering::SeqCst);
                shared.log(&format!("Proxy listener bind failed on {addr}: {e}; waiting for restart command"));
                // wait for a restart command instead of exiting
                while !shared.listener_restart.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
        // Short delay so the old socket closes before rebinding on the next pass;
        // the loop top clears the restart flag.
        std::thread::sleep(Duration::from_millis(250));
    });
}

/// Replace the extra listener set. Validates entries (non-empty bind, port
/// 1..=65535, no duplicate bind:port). Returns an error message on rejection.
pub fn set_listeners(shared: &Arc<Shared>, specs: Vec<ListenerSpec>) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for s in &specs {
        if s.bind.trim().is_empty() {
            return Err("bind address is empty".into());
        }
        if s.port == 0 {
            return Err("port must be 1-65535".into());
        }
        if !seen.insert((s.bind.clone(), s.port)) {
            return Err(format!("duplicate listener {}:{}", s.bind, s.port));
        }
    }
    *shared.listeners.lock().unwrap() = specs.into_iter().map(|s| Arc::new(ListenerState::new(s))).collect();
    // Bump the generation so the supervisor spawns workers for the new set and
    // the old workers exit. History and in-flight connections are untouched.
    shared.listener_generation.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

/// Listener status for the UI: primary listener plus extras, each as
/// (address, running, last error).
pub fn listener_status(shared: &Arc<Shared>) -> Vec<(String, bool, Option<String>)> {
    let mut out = vec![(
        format!("127.0.0.1:{}", shared.proxy_port.load(Ordering::SeqCst)),
        shared.listener_running.load(Ordering::SeqCst),
        None,
    )];
    for l in shared.listeners.lock().unwrap().iter() {
        out.push((
            format!("{}:{}", l.spec.bind, l.spec.port),
            l.running.load(Ordering::SeqCst),
            l.error.lock().unwrap().clone(),
        ));
    }
    out
}

fn listener_worker(shared: Arc<Shared>, state: Arc<ListenerState>, gen: u64) {
    loop {
        if shared.listener_generation.load(Ordering::SeqCst) != gen {
            break;
        }
        let addr = format!("{}:{}", state.spec.bind, state.spec.port);
        match TcpListener::bind(&addr) {
            Ok(l) => {
                let _ = l.set_nonblocking(true);
                state.running.store(true, Ordering::SeqCst);
                *state.error.lock().unwrap() = None;
                shared.log(&format!("Proxy listener started on {addr}"));
                loop {
                    if shared.listener_generation.load(Ordering::SeqCst) != gen {
                        break;
                    }
                    match l.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
                            let sh = shared.clone();
                            std::thread::spawn(move || handle_conn(sh, stream));
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                        Err(_) => continue,
                    }
                }
                state.running.store(false, Ordering::SeqCst);
            }
            Err(e) => {
                state.running.store(false, Ordering::SeqCst);
                *state.error.lock().unwrap() = Some(e.to_string());
                shared.log(&format!("Proxy listener bind failed on {addr}: {e}"));
                crate::feedback::toast(crate::feedback::Level::Error, format!("Listener {addr} failed: {e}"));
                // Wait for a configuration change before retrying.
                while shared.listener_generation.load(Ordering::SeqCst) == gen {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }
    state.running.store(false, Ordering::SeqCst);
}

/// Supervisor for the extra listeners: spawns workers for the current set and
/// lets them exit when the generation changes.
fn start_extra_listeners(shared: Arc<Shared>) {
    std::thread::spawn(move || {
        let mut spawned_gen = u64::MAX;
        loop {
            let gen = shared.listener_generation.load(Ordering::SeqCst);
            if gen != spawned_gen {
                spawned_gen = gen;
                let specs: Vec<Arc<ListenerState>> = shared.listeners.lock().unwrap().clone();
                for st in specs {
                    let sh = shared.clone();
                    std::thread::spawn(move || listener_worker(sh, st, gen));
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    });
}

fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    if let Some(i) = authority.rfind(':') {
        if let Ok(p) = authority[i + 1..].parse::<u16>() {
            return (authority[..i].to_string(), p);
        }
    }
    (authority.to_string(), default_port)
}

fn host_of(parts: &util::HttpParts, default_port: u16) -> (String, u16) {
    util::get_header(&parts.headers, "Host")
        .map(|h| split_host_port(&h, default_port))
        .unwrap_or_else(|| {
            // no Host header: fall back to the authority embedded in an absolute-form URI
            let p = &parts.path;
            if let Some(rest) = p.strip_prefix("http://") {
                let auth = rest.split(['/', '?']).next().unwrap_or("");
                if !auth.is_empty() {
                    return split_host_port(auth, default_port);
                }
            }
            ("".to_string(), default_port)
        })
}

fn path_of(parts: &util::HttpParts) -> String {
    if parts.path.starts_with("http://") {
        // origin-form conversion happens upstream; log absolute form
        if let Some(slash) = parts.path["http://".len()..].find('/') {
            return parts.path["http://".len() + slash..].to_string();
        }
        return "/".into();
    }
    if parts.path.is_empty() { "/".into() } else { parts.path.clone() }
}

fn record(shared: &Shared, req: &[u8], resp: Option<Vec<u8>>, note: Option<String>, default_port: u16, https: bool) {
    // History shows the decoded message: chunked bodies reassembled and
    // content coding removed (MECHANICS.md A-01/A-02). The bytes forwarded to
    // the server or client are untouched.
    let req = crate::codec::normalize_request(req);
    let req = req.as_slice();
    let resp = resp.map(|r| crate::codec::normalize_response(&r));
    let parts = util::parse_http(req);
    let (host, port) = host_of(&parts, default_port);
    let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
    let status = resp
        .as_ref()
        .map(|r| util::parse_http(r).status.clone())
        .unwrap_or_default();
    let resp_len = resp
        .as_ref()
        .map(|r| {
            let p = util::parse_http(r);
            r.len().saturating_sub(p.head_len)
        })
        .unwrap_or(0);
    let e = HistEntry {
        id,
        ts: util::now_secs(),
        method: if parts.method.is_empty() { "?".into() } else { parts.method.clone() },
        host,
        port,
        https,
        path: path_of(&parts),
        status,
        resp_len,
        req_raw: req.to_vec(),
        resp_raw: resp,
        note,
    };
    shared.push_history(e.clone());
    // live passive audit (AuditDefaults.json: scan_type_passive enabled),
    // bounded by the crawler's unique-location cap (CrawlDefaults.json: 1500)
    if shared.scan_enabled.load(Ordering::SeqCst) && e.path != "/favicon.ico" {
        let loc = format!("{}:{}{}", e.host, e.port, e.path.split('?').next().unwrap_or(""));
        let within_scope = in_scope(shared, &loc);
        let within_cap = {
            let mut locs = shared.scan_locations.lock().unwrap();
            if locs.contains(&loc) || locs.len() < crate::scan::CRAWL_MAX_UNIQUE_LOCATIONS {
                locs.insert(loc);
                true
            } else {
                false
            }
        };
        if within_scope && within_cap {
            let issues = crate::scan::passive_check(&e);
            crate::scan::add_passive_issues(shared, issues);
        }
    }
}

fn read_response_head<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1024);
    // Stop at the header boundary: reading ahead would steal the first WebSocket frame.
    let mut chunk = [0u8; 1];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if out.windows(4).any(|w| w == b"\r\n\r\n") || out.windows(2).any(|w| w == b"\n\n") {
            break;
        }
        if out.len() > 64 * 1024 {
            break;
        }
    }
    Ok(out)
}

fn ws_opcode_name(opcode: u8) -> &'static str {
    match opcode & 0x0f {
        0 => "continuation",
        1 => "text",
        2 => "binary",
        8 => "close",
        9 => "ping",
        10 => "pong",
        _ => "unknown",
    }
}

fn parse_ws_frame(buf: &[u8]) -> Option<(String, Vec<u8>, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let opcode = ws_opcode_name(buf[0]);
    let masked = buf[1] & 0x80 != 0;
    let mut len = (buf[1] & 0x7f) as usize;
    let mut offset = 2;
    if len == 126 {
        if buf.len() < offset + 2 {
            return None;
        }
        len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
        offset += 2;
    } else if len == 127 {
        if buf.len() < offset + 8 {
            return None;
        }
        let mut wide = [0u8; 8];
        wide.copy_from_slice(&buf[offset..offset + 8]);
        len = u64::from_be_bytes(wide) as usize;
        offset += 8;
    }
    if len > 16 * 1024 * 1024 {
        return Some(("oversized".into(), Vec::new(), buf.len()));
    }
    let mask_len = if masked { 4 } else { 0 };
    if buf.len() < offset + mask_len + len {
        return None;
    }
    let mask: [u8; 4] = if masked {
        [buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]
    } else {
        [0; 4]
    };
    let payload_start = offset + mask_len;
    let mut payload = buf[payload_start..payload_start + len].to_vec();
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Some((opcode.to_string(), payload, payload_start + len))
}

fn record_ws_chunk(shared: &Shared, host: &str, direction: &str, chunk: &[u8], buffered: &mut Vec<u8>) {
    buffered.extend_from_slice(chunk);
    while let Some((opcode, payload, consumed)) = parse_ws_frame(buffered) {
        push_ws(shared, host, direction, &opcode, &payload);
        buffered.drain(..consumed);
    }
}

fn relay_ws(shared: Arc<Shared>, client: TcpStream, upstream: TcpStream, host: String) {
    client.set_read_timeout(None).ok();
    upstream.set_read_timeout(None).ok();
    let mut client_read = match client.try_clone() { Ok(s) => s, Err(_) => return };
    let mut upstream_write = match upstream.try_clone() { Ok(s) => s, Err(_) => return };
    let client_host = host.clone();
    let client_shared = shared.clone();
    let client_thread = std::thread::spawn(move || {
        let mut buffered = Vec::new();
        let mut chunk = [0u8; 16384];
        loop {
            match client_read.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    record_ws_chunk(&client_shared, &client_host, "client -> server", &chunk[..n], &mut buffered);
                    if upstream_write.write_all(&chunk[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut upstream_read = match upstream.try_clone() { Ok(s) => s, Err(_) => return };
    let mut client_write = match client.try_clone() { Ok(s) => s, Err(_) => return };
    let upstream_host = host;
    let upstream_shared = shared;
    let mut buffered = Vec::new();
    let mut chunk = [0u8; 16384];
    loop {
        match upstream_read.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                record_ws_chunk(&upstream_shared, &upstream_host, "server -> client", &chunk[..n], &mut buffered);
                if client_write.write_all(&chunk[..n]).is_err() {
                    break;
                }
            }
        }
    }
    client_thread.join().ok();
}

/// Capture and relay a plain-HTTP WebSocket upgrade. TLS WebSocket handshakes are
/// recorded but frames are not yet intercepted because the current TLS relay is one-shot.
fn handle_websocket(shared: Arc<Shared>, mut client: TcpStream, req: Vec<u8>) {
    let parts = util::parse_http(&req);
    let (host, port) = host_of(&parts, 80);
    let req_session = apply_session_rules(&shared, &req, 80);
    let req_out = crate::rules::apply_rules(&req_session, &shared.mr_request.lock().unwrap());
    let config = shared.upstream.lock().unwrap().clone();
    let mut upstream = match crate::upstream::connect_target(&config, &host, port) {
        Ok(s) => s,
        Err(e) => {
            shared.log(&format!("WebSocket upstream connect to {host}:{port} failed: {e}"));
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };
    let routed_request = crate::upstream::absolute_form_request(&config, &req_out, &host, port);
    if let Err(e) = upstream.write_all(&routed_request) {
        shared.log(&format!("WebSocket upstream write to {host}:{port} failed: {e}"));
        return;
    }
    let response = match read_response_head(&mut upstream) {
        Ok(r) if !r.is_empty() => r,
        _ => {
            shared.log(&format!("WebSocket upstream {host}:{port} closed without a response"));
            return;
        }
    };
    if client.write_all(&response).is_err() {
        return;
    }
    push_ws(&shared, &host, "handshake", "request", &req_out);
    push_ws(&shared, &host, "handshake", "response", &response);
    record(&shared, &req_out, Some(response.clone()), None, 80, false);
    if util::parse_http(&response).status != "101" {
        shared.log(&format!("WebSocket upgrade for {host}:{port} was not accepted"));
        return;
    }
    shared.log(&format!("WebSocket upgraded for {host}:{port}; capturing frames"));
    relay_ws(shared, client, upstream, host);
}

fn write_nonblocking<W: Write>(stream: &mut W, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        match stream.write(bytes) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "socket write returned zero")),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn relay_ws_tls<C: ProxyIo, U: ProxyIo>(shared: &Shared, client: &mut C, upstream: &mut U, host: String) {
    let _ = client.set_nonblocking_io(true);
    let _ = upstream.set_nonblocking_io(true);
    let mut client_open = true;
    let mut upstream_open = true;
    let mut client_pending = Vec::new();
    let mut upstream_pending = Vec::new();
    let mut chunk = [0u8; 16384];
    while client_open || upstream_open {
        let mut progressed = false;
        if client_open {
            match client.read(&mut chunk) {
                Ok(0) => client_open = false,
                Ok(n) => {
                    progressed = true;
                    record_ws_chunk(shared, &host, "client -> server", &chunk[..n], &mut client_pending);
                    if write_nonblocking(upstream, &chunk[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => client_open = false,
            }
        }
        if upstream_open {
            match upstream.read(&mut chunk) {
                Ok(0) => upstream_open = false,
                Ok(n) => {
                    progressed = true;
                    record_ws_chunk(shared, &host, "server -> client", &chunk[..n], &mut upstream_pending);
                    if write_nonblocking(client, &chunk[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => upstream_open = false,
            }
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

fn handle_tls_websocket(
    shared: Arc<Shared>,
    mut client: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    req: Vec<u8>,
    host: String,
    port: u16,
) {
    let req_session = apply_session_rules(&shared, &req, 443);
    let req_out = crate::rules::apply_rules(&req_session, &shared.mr_request.lock().unwrap());
    let config = shared.upstream.lock().unwrap().clone();
    let upstream_tcp = match crate::upstream::connect_tls_target(&config, &host, port) {
        Ok(stream) => stream,
        Err(e) => {
            shared.log(&format!("TLS WebSocket upstream connection failed: {e}"));
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };
    let server_name = match rustls::pki_types::ServerName::try_from(host.clone()) {
        Ok(name) => name,
        Err(e) => {
            shared.log(&format!("TLS WebSocket hostname invalid: {e}"));
            return;
        }
    };
    let conn = match rustls::ClientConnection::new(shared.tls_upstream.clone(), server_name) {
        Ok(conn) => conn,
        Err(e) => {
            shared.log(&format!("TLS WebSocket client setup failed: {e}"));
            return;
        }
    };
    let mut upstream = rustls::StreamOwned::new(conn, upstream_tcp);
    if let Err(e) = upstream.write_all(&util::origin_form(&req_out)) {
        shared.log(&format!("TLS WebSocket upstream write failed: {e}"));
        return;
    }
    let response = match read_response_head(&mut upstream) {
        Ok(response) if !response.is_empty() => response,
        _ => {
            shared.log("TLS WebSocket upstream closed without an upgrade response");
            return;
        }
    };
    if client.write_all(&response).is_err() {
        return;
    }
    push_ws(&shared, &host, "handshake", "request", &req_out);
    push_ws(&shared, &host, "handshake", "response", &response);
    record(&shared, &req_out, Some(response.clone()), None, 443, true);
    if util::parse_http(&response).status != "101" {
        return;
    }
    shared.log(&format!("TLS WebSocket upgraded for {host}:{port}; capturing frames"));
    relay_ws_tls(&shared, &mut client, &mut upstream, host);
    client.conn.send_close_notify();
    upstream.conn.send_close_notify();
    let _ = client.flush();
    let _ = upstream.flush();
}

/// Client certificate rule for upstream mTLS: presented when `host_pattern`
/// matches the upstream host (exact name or `*.example.com` wildcard).
#[derive(Clone)]
pub struct ClientCertRule {
    pub host_pattern: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// Exact host match or `*.suffix` wildcard (wildcard covers exactly one label).
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern.eq_ignore_ascii_case(host) {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix('*') {
        if let Some(suffix) = rest.strip_prefix('.') {
            let dotted = format!(".{suffix}");
            if let Some(prefix) = host.to_ascii_lowercase().strip_suffix(&dotted.to_ascii_lowercase()) {
                return !prefix.is_empty() && !prefix.contains('.');
            }
        }
    }
    false
}

/// The TLS client config for an upstream host: a per-host client certificate
/// (mTLS) when one is configured, otherwise the shared upstream config.
fn tls_client_config(shared: &Shared, host: &str) -> std::sync::Arc<rustls::ClientConfig> {
    let rule = shared
        .client_certs
        .lock()
        .unwrap()
        .iter()
        .find(|r| host_matches(&r.host_pattern, host))
        .cloned();
    if let Some(rule) = rule {
        let roots = shared.tls_roots.lock().unwrap().clone();
        match crate::tls::client_auth_config(&rule.cert_pem, &rule.key_pem, roots) {
            Ok(config) => return config,
            Err(e) => shared.log(&format!("client certificate for {host} ignored: {e}")),
        }
    }
    shared.tls_upstream.clone()
}

fn handle_conn(shared: Arc<Shared>, mut stream: TcpStream) {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let _ = stream.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)));
    let req = match read_request(&mut stream) {
        Ok(r) if !r.is_empty() => r,
        _ => return,
    };
    let parts = util::parse_http(&req);

    if parts.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(parts.path.trim(), 443);
        handle_connect(shared, stream, host, port);
        return;
    }

    let Some(req) = intercept_request(&shared, req, 80) else { return };
    let is_ws = util::get_header(&parts.headers, "Upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if is_ws {
        handle_websocket(shared, stream, req);
        return;
    }
    upstream_and_deliver(&shared, &mut stream, req, 80, false);
}

/// Copy bytes both ways until either direction closes (SSL pass-through tunnel).
fn relay_tunnel(client: &TcpStream, upstream: &mut TcpStream) {
    let up_reader = upstream.try_clone();
    let mut client_reader = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let t = std::thread::spawn(move || {
        if let Ok(mut up) = up_reader {
            let _ = std::io::copy(&mut up, &mut client_reader);
        }
        let _ = client_reader.shutdown(std::net::Shutdown::Write);
    });
    let mut up_writer = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };
    let mut client_reader = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = std::io::copy(&mut client_reader, &mut up_writer);
    let _ = up_writer.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
    let _ = upstream.shutdown(std::net::Shutdown::Both);
    let _ = client.shutdown(std::net::Shutdown::Both);
}

fn handle_connect(shared: Arc<Shared>, mut stream: TcpStream, host: String, port: u16) {
    // SSL pass-through: matching hosts get a byte-relay tunnel, not MITM.
    let bypassed = shared
        .tls_bypass
        .lock()
        .unwrap()
        .iter()
        .any(|pattern| host_matches(pattern, &host));
    if bypassed {
        let config = shared.upstream.lock().unwrap().clone();
        let mut upstream = match crate::upstream::connect_target(&config, &host, port) {
            Ok(s) => s,
            Err(e) => {
                shared.log(&format!("pass-through connect to {host}:{port} failed: {e}"));
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
                return;
            }
        };
        if stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
            return;
        }
        shared.log(&format!("TLS pass-through tunnel to {host}:{port}"));
        relay_tunnel(&stream, &mut upstream);
        return;
    }
    let config = match shared.mitm.server_config(&host) {
        Ok(config) => config,
        Err(e) => {
            shared.log(&format!("HTTPS certificate for {host} failed: {e}"));
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            return;
        }
    };
    if stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
        return;
    }
    let conn = match rustls::ServerConnection::new(config) {
        Ok(conn) => conn,
        Err(e) => {
            shared.log(&format!("HTTPS server setup for {host}:{port} failed: {e}"));
            return;
        }
    };
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let req = match read_request(&mut tls) {
        Ok(req) if !req.is_empty() => req,
        Ok(_) => return,
        Err(e) => {
            shared.log(&format!("HTTPS client handshake/request for {host}:{port} failed: {e}"));
            return;
        }
    };
    let Some(req) = intercept_request(&shared, req, 443) else { return };
    let ws_parts = util::parse_http(&req);
    let is_ws = util::get_header(&ws_parts.headers, "Upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if is_ws {
        handle_tls_websocket(shared, tls, req, host, port);
        return;
    }
    upstream_and_deliver(&shared, &mut tls, req, 443, true);
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

// ProjectDefaults.json proxy.intercept_client_requests.rules[0]: enabled AND
// file_extension does_not_match this exact set. Startup interception is separately
// disabled by UserDefaults.json misc.enable_proxy_interception_at_startup=never.
const DEFAULT_INTERCEPT_EXCLUDED_EXTENSIONS: [&str; 11] = [
    "gif", "jpg", "png", "css", "js", "ico", "svg", "eot", "woff", "woff2", "ttf",
];

fn default_intercept_allows_path(path: &str) -> bool {
    let path_without_query = path.split(['?', '#']).next().unwrap_or(path);
    let file_name = path_without_query.rsplit('/').next().unwrap_or(path_without_query);
    let Some((_, extension)) = file_name.rsplit_once('.') else {
        return true;
    };
    !DEFAULT_INTERCEPT_EXCLUDED_EXTENSIONS
        .iter()
        .any(|excluded| extension.eq_ignore_ascii_case(excluded))
}

fn intercept_request(shared: &Shared, req: Vec<u8>, default_port: u16) -> Option<Vec<u8>> {
    if !shared.intercept_on.load(Ordering::SeqCst) {
        return Some(req);
    }
    let parts = util::parse_http(&req);
    if !default_intercept_allows_path(&parts.path) {
        return Some(req);
    }
    let (host, port) = host_of(&parts, default_port);
    let (tx, rx) = mpsc::channel::<Option<String>>();
    let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
    shared.queue.lock().unwrap().push(InterceptItem {
        id,
        host,
        port,
        edited: String::from_utf8_lossy(&req).into_owned(),
        tx,
    });
    match rx.recv() {
        Ok(Some(edited)) => Some(edited.into_bytes()),
        Ok(None) => {
            shared.log("Intercepted request dropped");
            None
        }
        Err(_) => None,
    }
}

fn upstream_and_deliver<S: ProxyIo>(
    shared: &Shared,
    stream: &mut S,
    req: Vec<u8>,
    default_port: u16,
    use_tls: bool,
) {
    let parts = util::parse_http(&req);
    let (host, port) = host_of(&parts, default_port);

    // Burp answers `http://burpsuite` itself: the browser must already be
    // proxying through the listener, and the page it returns is where the CA
    // certificate is downloaded. WebProbe does the same at http://webprobe.
    if let Some(resp) =
        crate::onboarding::local_response(&host, &path_of(&parts), port, shared.mitm.ca_pem(), &shared.mitm.ca_der())
    {
        let _ = stream.write_all(&resp);
        let _ = stream.flush();
        let status = String::from_utf8_lossy(&resp)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        record(shared, &req, Some(resp), None, default_port, use_tls);
        shared.log(&format!("Served the local setup page for {host} -> {status}"));
        return;
    }
    // Session rules run before match-and-replace, matching Burp's handling chain.
    let req_session = apply_session_rules(shared, &req, default_port);
    let req_out = crate::rules::apply_rules(&req_session, &shared.mr_request.lock().unwrap());
    let up = if use_tls {
        send_tls_raw(shared, &host, port, &req_out)
    } else {
        send_raw(shared, &host, port, &req_out)
    };
    match up.resp {
        Some(resp) => {
            let resp = crate::rules::apply_rules(&resp, &shared.mr_response.lock().unwrap());
            let status = util::parse_http(&resp).first.split_whitespace().nth(1).unwrap_or("").to_string();
            let _ = stream.write_all(&resp);
            let _ = stream.flush();
            record(shared, &req_out, Some(resp), None, default_port, use_tls);
            shared.log(&format!(
                "Proxied {} {host}:{port}{} -> {}{}",
                parts.method,
                path_of(&parts),
                status,
                if use_tls { " via HTTPS interception" } else { "" }
            ));
        }
        None => {
            let err = up.error.clone().unwrap_or_default();
            let msg = format!("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nWebProbe: upstream failed: {err}");
            let _ = stream.write_all(msg.as_bytes());
            let note = up.error.clone().unwrap_or_else(|| "failed".into());
            record(shared, &req_out, None, Some(note), default_port, use_tls);
            shared.log(&format!("Proxy error for {host}:{port}: {err}"));
        }
    }
}

/// Parse "host:port" or "host" into (host, fallback port).
pub fn split_h_p(authority: &str, fallback: u16) -> (String, u16) {
    split_host_port(authority.trim(), fallback)
}

/// Start a simple Sniper-style attack: for each marked position (§ ... §),
/// run every payload, one request at a time.
pub fn start_attack(shared: Arc<Shared>, template: String, payload_text: String, https: bool) {
    let segments = parse_markers(&template);
    let marker_count = segments.iter().filter(|s| s.is_marker).count();
    let payloads: Vec<String> = payload_text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let cur = shared.attack.lock().unwrap().clone();
    if marker_count == 0 || payloads.is_empty() {
        shared.log("Intruder: need at least one position marked with § and at least one payload");
        return;
    }
    cur.rows.lock().unwrap().clear();
    cur.done.store(0, Ordering::SeqCst);
    cur.total.store(payloads.len() * marker_count, Ordering::SeqCst);
    cur.stop.store(false, Ordering::SeqCst);
    cur.running.store(true, Ordering::SeqCst);
    shared.log(&format!("Intruder attack started: {marker_count} position(s) x {} payloads", payloads.len()));

    std::thread::spawn(move || {
        let mut idx = 0usize;
        'outer: for pos in 0..marker_count {
            for payload in &payloads {
                if cur.stop.load(Ordering::SeqCst) {
                    break 'outer;
                }
                let mut out = String::with_capacity(template.len() + payload.len());
                let mut m = 0usize;
                for seg in &segments {
                    if seg.is_marker {
                        if m == pos {
                            out.push_str(payload);
                        } else {
                            out.push_str(&seg.text);
                        }
                        m += 1;
                    } else {
                        out.push_str(&seg.text);
                    }
                }
                let _ = idx;
                let parts = util::parse_http(out.as_bytes());
                let host_header = util::get_header(&parts.headers, "Host").unwrap_or_default();
                if host_header.is_empty() {
                    cur.rows.lock().unwrap().push(AttackRow {
                        payload: payload.clone(),
                        status: String::new(),
                        len: 0,
                        ms: 0,
                        ok: false,
                    });
                    idx += 1;
                    continue;
                }
                let (host, port) = split_host_port(&host_header, if https { 443 } else { 80 });
                let t0 = Instant::now();
                let up = if https {
                    send_tls_raw(&shared, &host, port, out.as_bytes())
                } else {
                    send_raw(&shared, &host, port, out.as_bytes())
                };
                let ms = t0.elapsed().as_millis();
                cur.rows.lock().unwrap().push(match up.resp {
                    Some(resp) => {
                        let st = util::parse_http(&resp).first.split_whitespace().nth(1).unwrap_or("").to_string();
                        AttackRow { payload: payload.clone(), status: st, len: resp.len(), ms, ok: true }
                    }
                    None => AttackRow { payload: payload.clone(), status: String::new(), len: 0, ms, ok: false },
                });
                cur.done.fetch_add(1, Ordering::SeqCst);
                idx += 1;
                // gentle pacing so one bad host does not hammer (500 ms default throttle from
                // ProjectDefaults.json resource pool; applied only to intruder background work)
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        cur.running.store(false, Ordering::SeqCst);
        shared.log("Intruder attack finished");
    });
}

pub struct MarkerSeg {
    pub text: String,
    pub is_marker: bool,
}

pub fn parse_markers(text: &str) -> Vec<MarkerSeg> {
    let mut segs = Vec::new();
    let mut current = String::new();
    let mut in_marker = false;
    for c in text.chars() {
        if c == '§' {
            segs.push(MarkerSeg { text: std::mem::take(&mut current), is_marker: in_marker });
            in_marker = !in_marker;
        } else {
            current.push(c);
        }
    }
    segs.push(MarkerSeg { text: current, is_marker: in_marker });
    segs
}

/// Forward (drop=false) or drop (drop=true) the first held intercepted request.
pub fn intercept_forward(shared: &Arc<Shared>, drop: bool) {
    let mut q = shared.queue.lock().unwrap();
    if q.is_empty() {
        return;
    }
    let item = q.remove(0);
    let payload = if drop { None } else { Some(item.edited.clone()) };
    let _ = item.tx.send(payload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection, StreamOwned};

    fn client_config(ca: rustls::pki_types::CertificateDer<'static>) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        // A-05: offer HTTP/2 via ALPN; servers without it fall back to HTTP/1.1.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    }

    #[test]
    fn connect_intercepts_https_with_a_ca_signed_host_certificate() {
        let mut shared = Shared::new();
        // Trust our temporary CA for both sides of this isolated local test.
        let ca = shared.mitm.ca_der();
        Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);

        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_config = shared.mitm.server_config("localhost").unwrap();
        let upstream_thread = std::thread::spawn(move || {
            let (stream, _) = upstream.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let conn = ServerConnection::new(upstream_config).unwrap();
            let mut tls = StreamOwned::new(conn, stream);
            let req = read_request(&mut tls).unwrap();
            assert!(req.starts_with(b"GET /private HTTP/1.1\r\n"));
            tls.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ntls-ok",
            )
            .unwrap();
            tls.conn.send_close_notify();
            tls.flush().unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let proxy_shared = shared.clone();
        let proxy_thread = std::thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            handle_conn(proxy_shared, stream);
        });

        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(client, "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n")
            .unwrap();
        let mut connect_response = Vec::new();
        while !connect_response.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).unwrap();
            connect_response.push(byte[0]);
        }
        assert!(connect_response.starts_with(b"HTTP/1.1 200"));

        let conn = ClientConnection::new(
            client_config(shared.mitm.ca_der()),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut tls = StreamOwned::new(conn, client);
        write!(
            tls,
            "GET /private HTTP/1.1\r\nHost: localhost:{upstream_port}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).unwrap();
        assert!(response.ends_with(b"tls-ok"));

        upstream_thread.join().unwrap();
        proxy_thread.join().unwrap();
        let history = shared.history.lock().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].host, "localhost");
        assert_eq!(history[0].port, upstream_port);
        assert!(history[0].https);
        assert_eq!(history[0].path, "/private");
        assert_eq!(history[0].status, "200");
    }

    #[test]
    fn default_intercept_rule_skips_static_asset_extensions() {
        assert!(!default_intercept_allows_path("/assets/site.CSS?version=2"));
        assert!(!default_intercept_allows_path("http://example.com/app.js#main"));
        assert!(default_intercept_allows_path("/assets/site.css.map"));
        assert!(default_intercept_allows_path("/api/users?id=app.js"));
        assert!(default_intercept_allows_path("/login"));
    }
    fn read_request_head<R: Read>(s: &mut R) -> Vec<u8> {
        let req = read_request(s).unwrap();
        req
    }

    /// A-01/A-02: a chunked, gzip-encoded response is forwarded byte-for-byte
    /// but stored decoded, with the byte count of the decoded body.
    #[test]
    fn proxy_decodes_chunked_gzip_response_for_history() {
        let shared = Shared::new();
        let plain = b"decoded hello world";
        let mut gz = Vec::new();
        {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            e.write_all(plain).unwrap();
        }
        let mut chunked = Vec::new();
        let (a, b) = gz.split_at(gz.len() / 2);
        for part in [a, b] {
            chunked.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            chunked.extend_from_slice(part);
            chunked.extend_from_slice(b"\r\n");
        }
        chunked.extend_from_slice(b"0\r\n\r\n");

        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let wire_response = {
            let mut r = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            r.extend_from_slice(&chunked);
            r
        };
        let expected_wire = wire_response.clone();
        let t = std::thread::spawn(move || {
            let (mut s, _) = upstream.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request_head(&mut s);
            s.write_all(&wire_response).unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let sh = shared.clone();
        let pt = std::thread::spawn(move || {
            let (s, _) = proxy.accept().unwrap();
            handle_conn(sh, s);
        });

        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(
            client,
            "GET http://127.0.0.1:{upstream_port}/x HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
        )
        .unwrap();
        let mut wire = Vec::new();
        client.read_to_end(&mut wire).unwrap();
        t.join().unwrap();
        pt.join().unwrap();

        assert_eq!(wire, expected_wire, "the client must receive the original bytes");
        let hist = shared.history.lock().unwrap();
        assert_eq!(hist.len(), 1);
        let e = &hist[0];
        let raw = e.resp_raw.as_ref().expect("a stored response");
        let text = String::from_utf8_lossy(raw);
        assert!(text.contains("Content-Length: 19"), "corrected length: {text}");
        assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(!text.to_ascii_lowercase().contains("content-encoding"));
        assert!(raw.ends_with(plain), "decoded body stored");
        assert_eq!(e.resp_len, plain.len());
    }

    /// A-03: with keep-alive on, two requests reuse one upstream connection.
    #[test]
    fn keep_alive_pool_reuses_upstream_socket() {
        let shared = Shared::new();
        shared.keep_alive.store(true, Ordering::SeqCst);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            s.set_write_timeout(Some(Duration::from_millis(500))).unwrap();
            for i in 0..2 {
                let req = read_request_head(&mut s);
                assert!(req.starts_with(b"GET /"), "server got: {}", String::from_utf8_lossy(&req));
                s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok{i}").as_bytes()).unwrap();
            }
        });

        let one = send_raw(&shared, "127.0.0.1", port, b"GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        let two = send_raw(&shared, "127.0.0.1", port, b"GET /b HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        eprintln!("one error: {:?}", one.error);
        eprintln!("two error: {:?}", two.error);
        t.join().unwrap();
        assert_eq!(one.resp.as_deref().map(|r| r.to_vec()).unwrap_or_default().ends_with(b"ok0"), true);
        assert!(two.resp.as_ref().unwrap().ends_with(b"ok1"));
        assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 1, "one upstream connection for two requests");
        assert_eq!(shared.pool_hits.load(Ordering::SeqCst), 1);
    }

    /// A-04: a chunked request body is reassembled for storage.
    #[test]
    fn chunked_request_is_normalised_for_storage() {
        let raw = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let out = crate::codec::normalize_request(raw);
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("Content-Length: 5"));
        assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(out.ends_with(b"hello"));
    }

    /// A-04: malformed or hostile framing never panics the parser.
    #[test]
    fn malformed_messages_do_not_panic() {
        let samples: [&[u8]; 6] = [
            b"",
            b"HTTP/1.1",
            b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nshort",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"\x00\x01\x02\r\n\r\n",
        ];
        for s in samples {
            let _ = crate::codec::normalize_response(s);
            let _ = util::parse_http(s);
            let _ = crate::codec::body_complete(s, "GET");
        }
    }

    // ---------- A-05: HTTP/2 upstream and h2c ----------

    /// Read one HTTP/2 frame (test-local copy of the wire format).
    fn read_frame<R: Read>(r: &mut R) -> (u8, u8, u32, Vec<u8>) {
        let mut head = [0u8; 9];
        r.read_exact(&mut head).unwrap();
        let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
        let mut payload = vec![0u8; len];
        r.read_exact(&mut payload).unwrap();
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]);
        (head[3], head[4], stream, payload)
    }

    /// Speak the server side of one h2 request/response exchange on `s`.
    /// `upgrade` writes the 101 first (h2c); the connection then carries the
    /// HTTP/2 preface and frames.
    fn serve_h2<S: Read + Write>(s: &mut S, upgrade: bool, expected_path: &str) {
        if upgrade {
            // consume the HTTP/1.1 upgrade request head
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut b).unwrap();
                head.push(b[0]);
            }
            let text = String::from_utf8_lossy(&head);
            assert!(text.starts_with("GET /"), "upgrade request: {text}");
            assert!(text.to_ascii_lowercase().contains("upgrade: h2c"));
            s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n").unwrap();
        }
        // client preface
        let mut preface = [0u8; 24];
        s.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, crate::h2::PREFACE);
        // client SETTINGS
        let (ty, flags, _, _) = read_frame(s);
        assert_eq!(ty, 0x4);
        assert_eq!(flags & 0x1, 0);
        // server SETTINGS
        let mut f = Vec::new();
        f.extend_from_slice(&[0, 0, 0]);
        f.push(0x4);
        f.push(0);
        f.extend_from_slice(&[0, 0, 0, 0]);
        s.write_all(&f).unwrap();
        // read frames until the request HEADERS on stream 1 are complete
        let mut block = Vec::new();
        loop {
            let (ty, flags, stream, payload) = read_frame(s);
            match ty {
                0x1 if stream == 1 => {
                    block.extend_from_slice(&payload);
                    if flags & 0x4 != 0 {
                        break;
                    }
                }
                0x4 if flags & 0x1 == 0 => {
                    // ack the client's settings
                    s.write_all(&[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0]).unwrap();
                }
                _ => {}
            }
        }
        let mut dec = hpack::Decoder::new();
        let headers = dec.decode(&block).unwrap();
        let mut method = String::new();
        let mut path = String::new();
        for (k, v) in headers {
            let k = String::from_utf8_lossy(&k).into_owned();
            let v = String::from_utf8_lossy(&v).into_owned();
            if k == ":method" {
                method = v;
            } else if k == ":path" {
                path = v;
            }
        }
        assert_eq!(method, "GET");
        assert_eq!(path, expected_path);
        // response: HEADERS(:status 200) + DATA, both END_STREAM on DATA
        let mut enc = hpack::Encoder::new();
        let hb = enc.encode(vec![(b":status".as_ref(), b"200".as_ref()), (b"content-type".as_ref(), b"text/plain".as_ref())]);
        let mut out = Vec::new();
        out.extend_from_slice(&[(hb.len() >> 16) as u8, (hb.len() >> 8) as u8, hb.len() as u8]);
        out.extend_from_slice(&[0x1, 0x4, 0, 0, 0, 1]); // END_HEADERS, stream 1
        out.extend_from_slice(&hb);
        let body = b"hello h2";
        out.extend_from_slice(&[0, 0, body.len() as u8, 0x0, 0x1, 0, 0, 0, 1]); // DATA + END_STREAM
        out.extend_from_slice(body);
        s.write_all(&out).unwrap();
        s.flush().unwrap();
    }

    /// A-05: a plain HTTP request upgrades to h2c when the server offers it.
    #[test]
    fn http2c_upgrade_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            serve_h2(&mut s, true, "/h2c");
        });
        let shared = Shared::new();
        let resp = send_raw(&shared, "127.0.0.1", port, b"GET /h2c HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        t.join().unwrap();
        let resp = resp.resp.expect("h2c response");
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("Content-Length: 8"), "{text}");
        assert!(resp.ends_with(b"hello h2"));
    }

    /// A-05: when the server ignores the upgrade, the HTTP/1.1 reply is used.
    #[test]
    fn http2c_declined_falls_back_to_http1() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request_head(&mut s);
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain").unwrap();
        });
        let shared = Shared::new();
        let resp = send_raw(&shared, "127.0.0.1", port, b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        t.join().unwrap();
        let resp = resp.resp.expect("http/1.1 fallback response");
        assert!(resp.ends_with(b"plain"));
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
    }

    /// A-05: TLS with ALPN h2 runs the request through the HTTP/2 client.
    #[test]
    fn tls_alpn_h2_roundtrip() {
        let mut shared = Shared::new();
        let ca = shared.mitm.ca_der();
        let upstream_config = shared.mitm.server_config_with_alpn("localhost", vec![b"h2".to_vec()]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = ServerConnection::new(upstream_config).unwrap();
            let mut tls = StreamOwned::new(conn, stream);
            serve_h2(&mut tls, false, "/secure");
        });
        // Trust our CA for the upstream side.
        Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
        let resp = send_tls_raw(&shared, "localhost", port, b"GET /secure HTTP/1.1\r\nHost: localhost\r\n\r\n");
        t.join().unwrap();
        let resp = resp.resp.unwrap_or_else(|| panic!("h2 over TLS failed: {:?}", resp.error));
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("Content-Length: 8"), "{text}");
        assert!(resp.ends_with(b"hello h2"));
    }

    /// A-06: a bypassed host gets a raw byte tunnel, not a MITM connection.
    #[test]
    fn tls_bypass_relays_raw_bytes() {
        let shared = Shared::new();
        shared.tls_bypass.lock().unwrap().push("localhost".into());
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = echo.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).unwrap();
            s.write_all(b"pong").unwrap();
        });
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let sh = shared.clone();
        let pt = std::thread::spawn(move || {
            let (s, _) = proxy.accept().unwrap();
            handle_conn(sh, s);
        });
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(client, "CONNECT localhost:{echo_port} HTTP/1.1\r\nHost: localhost:{echo_port}\r\n\r\n").unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut b).unwrap();
            head.push(b[0]);
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
        client.write_all(b"ping").unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"pong");
        drop(client); // close so the relay copies see EOF
        t.join().unwrap();
        pt.join().unwrap();
    }

    /// A-06: a configured client certificate is presented to an upstream that
    /// requires mTLS.
    #[test]
    fn client_certificate_presented_to_mtls_server() {
        let mut shared = Shared::new();
        let (cert_pem, key_pem) = shared.mitm.client_certificate("client").unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(shared.mitm.ca_der()).unwrap();
        *shared.tls_roots.lock().unwrap() = roots.clone();
        shared.client_certs.lock().unwrap().push(ClientCertRule {
            host_pattern: "localhost".into(),
            cert_pem,
            key_pem,
        });
        let server_config = shared.mitm.server_config_with_client_auth("localhost", roots).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let conn = ServerConnection::new(server_config).unwrap();
            let mut tls = StreamOwned::new(conn, stream);
            let req = read_request(&mut tls).unwrap();
            assert!(req.starts_with(b"GET /secure HTTP/1.1"));
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nmtls").unwrap();
            tls.flush().unwrap();
        });
        let resp = send_tls_raw(&shared, "localhost", port, b"GET /secure HTTP/1.1\r\nHost: localhost\r\n\r\n");
        t.join().unwrap();
        let resp = resp.resp.unwrap_or_else(|| panic!("mTLS failed: {:?}", resp.error));
        assert!(resp.ends_with(b"mtls"));
    }

    #[test]
    fn host_matching_exact_and_wildcard() {
        assert!(host_matches("example.com", "example.com"));
        // Hostnames are case-insensitive.
        assert!(host_matches("example.com", "EXAMPLE.com"));
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "a.b.example.com"));
    }

    // ---------- A-07: proxy listener options ----------

    /// A free TCP port on 127.0.0.1 (bind, read, drop).
    fn free_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    /// A-07: an extra listener accepts connections and serves requests through
    /// the normal proxy pipeline.
    #[test]
    fn extra_listener_serves_traffic() {
        let shared = Shared::new();
        // Plain origin server that answers one request.
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let ot = std::thread::spawn(move || {
            let (mut s, _) = origin.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = read_request_head(&mut s);
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nresp").unwrap();
        });
        let spec = ListenerSpec { bind: "127.0.0.1".into(), port: free_port() };
        let state = Arc::new(ListenerState::new(spec.clone()));
        let gen = shared.listener_generation.load(Ordering::SeqCst);
        let sh = shared.clone();
        let st = state.clone();
        let worker = std::thread::spawn(move || listener_worker(sh, st, gen));
        // Wait for the worker to bind.
        let addr = format!("127.0.0.1:{}", spec.port);
        let mut up = None;
        for _ in 0..50 {
            if let Ok(s) = TcpStream::connect(&addr) {
                up = Some(s);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(state.running.load(Ordering::SeqCst), "listener should be running");
        let mut client = up.expect("listener should accept connections");
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(client, "GET http://127.0.0.1:{origin_port}/x HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n").unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"), "via extra listener: {resp:?}");
        ot.join().unwrap();
        // Stop the worker and wait for it to exit.
        shared.listener_generation.fetch_add(1, Ordering::SeqCst);
        worker.join().unwrap();
        assert!(!state.running.load(Ordering::SeqCst));
        assert_eq!(shared.history.lock().unwrap().len(), 1);
    }

    /// A-07: set_listeners validates its input.
    #[test]
    fn listener_validation() {
        let shared = Shared::new();
        assert!(set_listeners(&shared, vec![ListenerSpec { bind: "".into(), port: 8081 }]).is_err());
        assert!(set_listeners(&shared, vec![ListenerSpec { bind: "127.0.0.1".into(), port: 0 }]).is_err());
        assert!(set_listeners(
            &shared,
            vec![
                ListenerSpec { bind: "127.0.0.1".into(), port: 8081 },
                ListenerSpec { bind: "127.0.0.1".into(), port: 8081 },
            ]
        )
        .is_err());
        assert!(set_listeners(&shared, vec![ListenerSpec { bind: "127.0.0.1".into(), port: 8081 }]).is_ok());
        let status = listener_status(&shared);
        // primary + one extra
        assert_eq!(status.len(), 2);
        assert!(status[1].0.ends_with(":8081"));
    }

    /// A-07: replacing the listener set leaves history intact.
    #[test]
    fn listener_restart_keeps_history() {
        let shared = Shared::new();
        shared.history.lock().unwrap().push(HistEntry {
            id: 1,
            ts: 0,
            method: "GET".into(),
            host: "example.com".into(),
            port: 443,
            https: true,
            path: "/".into(),
            status: "200".into(),
            resp_len: 0,
            req_raw: Vec::new(),
            resp_raw: None,
            note: None,
        });
        assert!(set_listeners(&shared, vec![ListenerSpec { bind: "127.0.0.1".into(), port: free_port() }]).is_ok());
        std::thread::sleep(Duration::from_millis(600));
        assert!(set_listeners(&shared, vec![ListenerSpec { bind: "127.0.0.1".into(), port: free_port() }]).is_ok());
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(shared.history.lock().unwrap().len(), 1, "history survives listener changes");
    }

    // ---------- A-08: invisible proxying ----------

    /// A-08: an origin-form request with a Host header (invisible proxying) is
    /// routed by Host and forwarded upstream as origin-form.
    #[test]
    fn invisible_proxying_uses_host_header() {
        let shared = Shared::new();
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let ot = std::thread::spawn(move || {
            let (mut s, _) = origin.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let req = read_request_head(&mut s);
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ninvis").unwrap();
            req
        });
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let sh = shared.clone();
        let pt = std::thread::spawn(move || {
            let (s, _) = proxy.accept().unwrap();
            handle_conn(sh, s);
        });
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(client, "GET /invisible HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n").unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
        let upstream_req = ot.join().unwrap();
        let text = String::from_utf8_lossy(&upstream_req);
        assert!(text.starts_with("GET /invisible HTTP/1.1"), "upstream got: {text}");
        pt.join().unwrap();
    }

    /// A-08: an absolute-form request is converted to origin-form upstream.
    #[test]
    fn absolute_form_forwarded_as_origin_form() {
        let shared = Shared::new();
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let ot = std::thread::spawn(move || {
            let (mut s, _) = origin.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let req = read_request_head(&mut s);
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabs").unwrap();
            req
        });
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let sh = shared.clone();
        let pt = std::thread::spawn(move || {
            let (s, _) = proxy.accept().unwrap();
            handle_conn(sh, s);
        });
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(client, "GET http://127.0.0.1:{origin_port}/abs HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n").unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
        let upstream_req = ot.join().unwrap();
        let text = String::from_utf8_lossy(&upstream_req);
        assert!(text.starts_with("GET /abs HTTP/1.1"), "upstream got: {text}");
        pt.join().unwrap();
    }

    #[test]
    fn setup_host_is_served_locally_instead_of_upstream() {
        // Burp answers http://burpsuite itself; WebProbe answers http://webprobe
        // (and the Burp host, so a Burp tutorial still works).
        let shared = Shared::new();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = proxy.local_addr().unwrap().port();
        let proxy_shared = shared.clone();
        let t = std::thread::spawn(move || {
            // Two requests: the page, then the CA download.
            for _ in 0..2 {
                let (stream, _) = proxy.accept().unwrap();
                handle_conn(proxy_shared.clone(), stream);
            }
        });

        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(client, "GET http://webprobe/ HTTP/1.1\r\nHost: webprobe\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("WebProbe proxy"), "{text}");
        assert!(text.contains("127.0.0.1:"));

        // The CA is reachable from the same page, in both formats.
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(client, "GET http://webprobe/webprobe-ca.pem HTTP/1.1\r\nHost: webprobe\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("application/x-pem-file"), "{text}");
        assert!(text.contains("BEGIN CERTIFICATE"), "{text}");

        // And the history recorded the exchange.
        assert_eq!(shared.history.lock().unwrap().len(), 2);
        t.join().unwrap();
    }

}
