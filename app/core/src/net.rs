// Local HTTP/1.1 proxy (connect-timeout 120s, read timeout 120s per MECHANICS.md),
// intercept queue, history store, raw request sender used by Repeater/Intruder.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::Arc;

use crate::sync::Mutex;
use std::time::{Duration, Instant};

use crate::util;

// Live 52685 stores all proxy history and accepts the complete payload list.
// Timeout values from resources/Preferences/ProjectDefaults.json (MECHANICS.md), in ms:
pub const CONNECT_TIMEOUT_MS: u64 = 120000;
pub const READ_TIMEOUT_MS: u64 = 120000;
pub const OPEN_ENDED_RESPONSE_TIMEOUT_MS: u64 = 10000;
pub const DNS_TIMEOUT_MS: u64 = 300000;

#[derive(Clone, Default)]
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
    /// Request and response bytes: cheap to clone; Proxy history keeps them
    /// in the on-disk store (`body::spill`).
    pub req_raw: crate::body::Body,
    pub resp_raw: Option<crate::body::Body>,
    pub note: Option<String>,
    /// Burp's row highlight (ui.highlight.0..8 in LightTheme.json).
    pub highlight: Option<u8>,
    /// The live passive audit looked at this item (Dashboard > Audit items).
    pub audited: bool,
    /// Derived once at insert (P-05), so a table frame never recomputes them.
    /// Whether the request carries a query string, body parameters or cookies.
    pub params: bool,
    /// Whether the user edited the message (intercept, match/replace).
    pub edited: bool,
    /// URL file extension (lower case, no dot); empty when there is none.
    pub extension: String,
    /// HTML <title> text, empty for non-HTML responses.
    pub title: String,
    /// Cookies set by the response, "name=value" pairs joined by "; ".
    pub cookies: String,
    /// Listener port the request arrived on.
    pub listener_port: u16,
    /// Upstream IP the host resolved to (history "IP" column, live 52685:
    /// e.g. 104.20.23.154 for example.com); empty when unresolvable.
    pub ip: String,
    /// How many response attributes changed vs. the previous exchange of the
    /// same request location ("Diff count" column, burp.Zxwu.java:56).
    pub diffs: usize,
}

impl HistEntry {
    /// This entry with its bodies in the on-disk store, as Proxy history
    /// keeps every entry (N-06).
    pub fn spilled(mut self) -> Self {
        self.req_raw = crate::body::spill(&self.req_raw);
        self.resp_raw = self.resp_raw.as_ref().map(crate::body::spill);
        self
    }
}

/// Host -> resolved-IP cache backing the history "IP" column, so repeated
/// requests to the same host do not re-resolve.
fn resolve_ip(shared: &Shared, host: &str) -> String {
    if host.is_empty() {
        return String::new();
    }
    {
        let cache = shared.ip_cache.lock().unwrap();
        if let Some(ip) = cache.get(host) {
            return ip.clone();
        }
    }
    let ip = std::net::ToSocketAddrs::to_socket_addrs(&(host, 80u16))
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    {
        let mut cache = shared.ip_cache.lock().unwrap();
        if cache.len() > 4096 {
            cache.clear();
        }
        cache.insert(host.to_string(), ip.clone());
    }
    ip
}

/// What an intercepted message is: an HTTP request on its way upstream, or a
/// WebSocket message in one direction (Burp's intercept table "Type" and
/// "Direction" columns).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterceptKind {
    Request { https: bool },
    /// A response held by the response interception rules.
    Response { https: bool },
    WebSocket { to_server: bool },
}

/// What happened to a request on its way through Intercept, for the
/// response interception rules ("Request was modified / was intercepted").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReqState {
    pub edited: bool,
    pub held: bool,
}

/// Burp's "Response interception rules" (Proxy settings), with its defaults:
/// the master switch off; Content type header matches `text` (on); Or
/// request was modified (off); Or request was intercepted (off); And status
/// code does not match `^304$` (on); And URL is in target scope (off).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResponseInterceptRules {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "rir_true")]
    pub content_type_on: bool,
    #[serde(default = "rir_text")]
    pub content_type: String,
    #[serde(default)]
    pub was_modified: bool,
    #[serde(default)]
    pub was_intercepted: bool,
    #[serde(default = "rir_true")]
    pub status_not_on: bool,
    #[serde(default = "rir_304")]
    pub status_not: String,
    #[serde(default)]
    pub in_scope: bool,
}

fn rir_true() -> bool {
    true
}
fn rir_text() -> String {
    "text".into()
}
fn rir_304() -> String {
    "^304$".into()
}

impl Default for ResponseInterceptRules {
    fn default() -> Self {
        Self { enabled: false, content_type_on: true, content_type: rir_text(), was_modified: false, was_intercepted: false, status_not_on: true, status_not: rir_304(), in_scope: false }
    }
}

impl ResponseInterceptRules {
    /// Burp evaluates the enabled rules in order, each joined to the result
    /// so far by its operator (Or, Or, And, And here).
    pub fn matches(&self, content_type: &str, status: &str, req: ReqState, in_scope: bool) -> bool {
        if !self.enabled {
            return false;
        }
        let re = |p: &str, t: &str| regex::RegexBuilder::new(p).case_insensitive(true).build().map(|r| r.is_match(t)).unwrap_or(false);
        let rules: [(bool, bool, bool); 5] = [
            // (enabled, is_and, result)
            (self.content_type_on, false, re(&self.content_type, content_type)),
            (self.was_modified, false, req.edited),
            (self.was_intercepted, false, req.held),
            (self.status_not_on, true, !re(&self.status_not, status)),
            (self.in_scope, true, in_scope),
        ];
        let mut acc: Option<bool> = None;
        for (on, is_and, result) in rules {
            if !on {
                continue;
            }
            acc = Some(match acc {
                None => result,
                Some(a) if is_and => a && result,
                Some(a) => a || result,
            });
        }
        acc.unwrap_or(true)
    }
}

pub struct InterceptItem {
    pub id: u64,
    pub host: String,
    pub port: u16,
    pub edited: String,
    pub tx: mpsc::Sender<Option<String>>,
    pub kind: InterceptKind,
    /// Unix seconds when the message was held (intercept table "Time").
    pub ts: u64,
}

impl InterceptItem {
    pub fn new(id: u64, host: &str, port: u16, edited: String, tx: mpsc::Sender<Option<String>>, kind: InterceptKind) -> Self {
        Self { id, host: host.to_string(), port, edited, tx, kind, ts: util::now_secs() }
    }
}

/// Remembers the previous exchange's response attributes per request location
/// so each new history entry can report a diff count (Proxy history
/// "Diff count" column, build 52685 burp.Zxwu.java:56). The location is
/// method + host:port + path without query; the first sighting diffs 0.
#[derive(Default)]
pub struct DiffTracker {
    prev: std::collections::HashMap<String, Vec<(String, String)>>,
}

impl DiffTracker {
    /// Compare ordered name/value attributes against the stored set for
    /// `key`: changed, added and removed attributes all count. The new set
    /// is stored either way.
    pub fn diff(&mut self, key: &str, attrs: Vec<(String, String)>) -> usize {
        let count = match self.prev.get(key) {
            None => 0,
            Some(prev) => {
                let changed = attrs
                    .iter()
                    .filter(|(n, v)| prev.iter().any(|(pn, pv)| pn == n && pv != v))
                    .count();
                let added = attrs.iter().filter(|(n, _)| !prev.iter().any(|(pn, _)| pn == n)).count();
                let removed = prev.iter().filter(|(pn, _)| !attrs.iter().any(|(n, _)| n == pn)).count();
                changed + added + removed
            }
        };
        self.prev.insert(key.to_string(), attrs);
        count
    }
}

/// The attribute set a history diff covers: status, length, cookies and every
/// response header, matching what Logger's diff columns surface.
fn diff_attrs(e: &HistEntry) -> Vec<(String, String)> {
    let mut attrs = vec![
        ("status".to_string(), e.status.clone()),
        ("length".to_string(), e.resp_len.to_string()),
        ("cookies".to_string(), e.cookies.clone()),
    ];
    if let Some(resp) = &e.resp_raw {
        for (k, v) in &util::parse_http(resp).headers {
            attrs.push((format!("h:{k}"), v.clone()));
        }
    }
    attrs
}

#[derive(Clone)]
pub struct AttackRow {
    pub payload: String,
    pub status: String,
    pub len: usize,
    pub ms: u128,
    pub ok: bool,
    /// The request sent and the response received (attack results window).
    pub req: Vec<u8>,
    pub resp: Option<Vec<u8>>,
}

pub struct Attack {
    pub running: AtomicBool,
    pub stop: AtomicBool,
    pub done: AtomicUsize,
    pub total: AtomicUsize,
    pub rows: Mutex<Vec<AttackRow>>,
}

pub struct RepTab {
    /// Stable identity: sends route by it, never by the (display) name.
    pub id: u64,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub request: String,
    pub response: Option<Vec<u8>>,
    pub result_line: String,
    /// Burp's per-tab history: every sent (request, response, status line),
    /// stepped through with the < > buttons.
    pub history: Vec<(String, Option<Vec<u8>>, String)>,
    /// Position in `history` being shown (len = the live, editable item).
    pub hist_pos: usize,
    /// A WebSocket Repeater tab: its session (`Shared::ws_sessions`).
    pub ws: Option<u64>,
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

/// Insert or replace a header in a raw HTTP message, keeping head order and
/// the body intact. Public: the scanner's header-manipulation probe reuses it.
pub fn replace_or_add_header(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
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
    let history = shared.history.snapshot();
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

/// Session rule actions, as offered in the rule editor (Burp's list: set a
/// header, set a cookie value, use the cookie jar, run a macro, check the
/// session is valid, run a post-request macro). "use cookie" is WebProbe's
/// older "reuse the newest Set-Cookie value from history".
pub const SESSION_ACTIONS: [&str; 8] = ["set header", "set cookie", "use cookie", "use cookie jar", "run macro", "check session", "post-request macro", "invoke extension"];

/// "check session" recovery choice, offered next to the macros: instead of
/// running a login macro, ask the user to log in again in the browser
/// (Burp's "Prompt for in-browser session recovery"). The proxied login
/// feeds the cookie jar, and the waiting request picks the cookies up.
pub const BROWSER_RECOVERY: &str = "<in-browser session recovery>";

/// How long a request waits for the user to finish an in-browser login.
pub const BROWSER_RECOVERY_WAIT: Duration = Duration::from_secs(300);

/// A pending in-browser session recovery, shown to the user as a prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub id: u64,
    pub host: String,
    pub rule: String,
}

#[derive(Default)]
struct RecoveryState {
    pending: Option<RecoveryRequest>,
    answered: Option<(u64, bool)>,
    next_id: u64,
}

/// The prompt shared by every request that finds the session invalid: one
/// prompt at a time; requests that find it already open wait for the same
/// answer.
#[derive(Default)]
pub struct BrowserRecovery {
    state: std::sync::Mutex<RecoveryState>,
    cv: std::sync::Condvar,
}

impl BrowserRecovery {
    /// The prompt the UI should show, if any.
    pub fn pending(&self) -> Option<RecoveryRequest> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).pending.clone()
    }

    /// The user's answer: `true` once they have logged in again.
    pub fn answer(&self, ok: bool) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = st.pending.take() {
            st.answered = Some((p.id, ok));
            self.cv.notify_all();
        }
    }

    /// Block until the user answers (or `wait` passes, which counts as no).
    fn ask(&self, host: &str, rule: &str, wait: Duration, wake: impl Fn()) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let id = match &st.pending {
            Some(p) => p.id,
            None => {
                st.next_id += 1;
                let id = st.next_id;
                st.pending = Some(RecoveryRequest { id, host: host.to_string(), rule: rule.to_string() });
                id
            }
        };
        wake();
        let deadline = std::time::Instant::now() + wait;
        loop {
            if let Some((aid, ok)) = st.answered {
                if aid == id {
                    return ok;
                }
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                if st.pending.as_ref().is_some_and(|p| p.id == id) {
                    st.pending = None;
                }
                return false;
            }
            st = self.cv.wait_timeout(st, left).unwrap_or_else(|e| e.into_inner()).0;
        }
    }
}

thread_local! {
    /// Set while a session rule is itself sending (a macro, a validation
    /// request), so those requests do not trigger the rules again.
    static IN_SESSION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `f` with session handling suspended on this thread.
fn in_session<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            IN_SESSION.with(|s| s.set(self.0));
        }
    }
    let _reset = Reset(IN_SESSION.with(|s| s.replace(true)));
    f()
}

/// Set one cookie of a request to `value`, replacing it if present.
pub fn set_request_cookie(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    let p = util::parse_http(raw);
    let existing = util::get_header(&p.headers, "Cookie").unwrap_or_default();
    let mut pairs: Vec<(String, String)> =
        existing.split(';').filter_map(|c| c.split_once('=').map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))).filter(|(n, _)| !n.is_empty()).collect();
    match pairs.iter_mut().find(|(n, _)| n == name) {
        Some(pair) => pair.1 = value.to_string(),
        None => pairs.push((name.to_string(), value.to_string())),
    }
    replace_or_add_header(raw, "Cookie", &pairs.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join("; "))
}

/// What one macro step did.
#[derive(Clone, Debug, PartialEq)]
pub struct MacroStepResult {
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
    /// Parameters filled from the previous step's response.
    pub derived: Vec<(String, String)>,
}

/// Run the steps of a macro text in order (see `macros.rs` for the format).
/// Each request goes to the host in its Host header (TLS for an `https` step
/// or port 443), carries the cookie jar's cookies, has its derived parameters
/// filled from the previous response, and feeds the cookies it gets back to
/// the jar - Burp's macro defaults. Stops at the first step with no response.
pub fn run_macro_text(shared: &Shared, text: &str) -> Vec<MacroStepResult> {
    let mut results: Vec<MacroStepResult> = Vec::new();
    for step in crate::macros::parse(text) {
        let previous = results.last().and_then(|r| r.response.clone());
        let (request, derived) = crate::macros::prepare(&step, previous.as_deref());
        let p = util::parse_http(&request);
        let (host, port) = host_of(&p, if step.https { 443 } else { 80 });
        let https = step.https || port == 443;
        let request = shared.cookie_jar.lock().unwrap().apply(&request, &host, https, util::now_secs());
        let up = in_session(|| if https { send_tls_raw(shared, &host, port, &request) } else { send_raw(shared, &host, port, &request) });
        if let Some(resp) = &up.resp {
            shared.cookie_jar.lock().unwrap().update_from_response(&host, &p.path, resp, util::now_secs());
        }
        let failed = up.resp.is_none();
        results.push(MacroStepResult { request, response: up.resp, derived });
        if failed {
            break;
        }
    }
    if let Some(resp) = results.last().and_then(|r| r.response.clone()) {
        *shared.macro_last_response.lock().unwrap() = resp;
    }
    results
}

/// A rule value with each `{name}` replaced by that value from the most
/// recent macro response (form field, JSON member or cookie). A placeholder
/// with no such value is left as written.
pub fn expand_placeholders(shared: &Shared, value: &str) -> String {
    if !value.contains('{') {
        return value.to_string();
    }
    let last = shared.macro_last_response.lock().unwrap().clone();
    let mut out = String::new();
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        match rest[open..].find('}') {
            Some(close) => {
                let name = &rest[open + 1..open + close];
                match (!name.is_empty() && !last.is_empty()).then(|| crate::macros::extract_value(&last, name)).flatten() {
                    Some(v) => out.push_str(&v),
                    None => out.push_str(&rest[open..=open + close]),
                }
                rest = &rest[open + close + 1..];
            }
            None => {
                out.push_str(&rest[open..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Run a stored macro by name. Returns the last step's response, or `None`
/// when the macro is unknown, empty, or a step got no response.
pub fn run_macro(shared: &Shared, name: &str) -> Option<Vec<u8>> {
    let text = shared.macros.lock().unwrap().iter().find(|m| m.name == name).map(|m| m.request.clone())?;
    run_macro_text(shared, &text).pop().and_then(|r| r.response)
}

/// Apply the proxy's session rules to a request before it is sent upstream.
pub fn apply_session_rules(shared: &Shared, req: &[u8], default_port: u16) -> Vec<u8> {
    apply_session_rules_for(shared, "Proxy", req, default_port, default_port == 443)
}

/// Apply the enabled session rules whose tool scope includes `tool` and
/// whose host pattern matches, in order, to a request about to be sent.
///
/// * set header: `Name: value`
/// * set cookie: `name=value`, replacing that cookie in the request
/// * use cookie: reuse the newest Set-Cookie value of that name from history
/// * use cookie jar: put the jar's cookies for this URL on the request
/// * run macro: run the named macro first, then update the request's
///   cookies from the jar (which the macro's response has just fed)
/// * check session: send the request as it stands and look for the rule's
///   expression in the response; when that shows the session is invalid,
///   run the named macro (a login) and update the request's cookies
pub fn apply_session_rules_for(shared: &Shared, tool: &str, req: &[u8], default_port: u16, https: bool) -> Vec<u8> {
    if IN_SESSION.with(|s| s.get()) {
        return req.to_vec();
    }
    let rules = shared.session_rules.lock().unwrap().clone();
    if rules.is_empty() {
        return req.to_vec();
    }
    let parts = util::parse_http(req);
    let (host, port) = host_of(&parts, default_port);
    let mut out = req.to_vec();
    let from_jar = |out: &[u8]| shared.cookie_jar.lock().unwrap().apply(out, &host, https, util::now_secs());
    for rule in rules {
        if !rule.enabled || !rule.tools.iter().any(|t| t == tool) || !pattern_matches(&rule.host_match, false, &host) {
            continue;
        }
        match rule.action.as_str() {
            "set header" => {
                let filled = expand_placeholders(shared, &rule.value);
                if let Some((name, value)) = filled.split_once(':') {
                    out = replace_or_add_header(&out, name.trim(), value.trim());
                    shared.log(&format!("Session rule '{}' set {} header", rule.name, name.trim()));
                }
            }
            "set cookie" => {
                let filled = expand_placeholders(shared, &rule.value);
                if let Some((name, value)) = filled.split_once('=') {
                    out = set_request_cookie(&out, name.trim(), value.trim());
                    shared.log(&format!("Session rule '{}' set cookie {}", rule.name, name.trim()));
                }
            }
            "use cookie" => {
                if let Some(value) = latest_cookie(shared, rule.value.trim()) {
                    out = append_cookie(&out, rule.value.trim(), &value);
                    shared.log(&format!("Session rule '{}' reused cookie {}", rule.name, rule.value));
                }
            }
            "use cookie jar" => out = from_jar(&out),
            "invoke extension" => {
                let exts = shared.ext_host.lock().unwrap().active();
                let svc = crate::ext_host::HttpService::new(&host, port, https);
                match exts.iter().find(|e| e.ui().is_some_and(|u| u.session_actions.iter().any(|a| *a == rule.value))) {
                    Some(e) => match e.session_action(&rule.value, &svc, &out) {
                        Ok(r) => {
                            out = r;
                            shared.log(&format!("Session rule '{}' invoked the extension action {}", rule.name, rule.value));
                        }
                        Err(why) => shared.log(&format!("Session rule '{}': the extension action {} failed: {why}", rule.name, rule.value)),
                    },
                    None => shared.log(&format!("Session rule '{}': no loaded extension provides the action {}", rule.name, rule.value)),
                }
            }
            "run macro" => {
                let ok = run_macro(shared, &rule.value).is_some();
                out = from_jar(&out);
                shared.log(&format!("Session rule '{}' ran macro {}: {}", rule.name, rule.value, if ok { "ok" } else { "failed" }));
            }
            "check session" => {
                let probe = in_session(|| if https { send_tls_raw(shared, &host, port, &out) } else { send_raw(shared, &host, port, &out) });
                let Some(resp) = probe.resp else {
                    shared.log(&format!("Session rule '{}': validation request failed", rule.name));
                    continue;
                };
                let found = !rule.check.is_empty() && String::from_utf8_lossy(&resp).to_ascii_lowercase().contains(&rule.check.to_ascii_lowercase());
                let invalid = found == rule.check_invalid_on_match;
                if invalid && rule.value == BROWSER_RECOVERY {
                    shared.log(&format!("Session rule '{}': session invalid, waiting for an in-browser login to {host}", rule.name));
                    let ok = shared.browser_recovery.ask(&host, &rule.name, BROWSER_RECOVERY_WAIT, || shared.wake());
                    out = from_jar(&out);
                    shared.log(&format!("Session rule '{}': in-browser recovery {}", rule.name, if ok { "done" } else { "cancelled" }));
                } else if invalid {
                    let ok = !rule.value.is_empty() && run_macro(shared, &rule.value).is_some();
                    out = from_jar(&out);
                    shared.log(&format!("Session rule '{}': session invalid, macro {} {}", rule.name, rule.value, if ok { "ran" } else { "did not run" }));
                }
            }
            _ => {}
        }
    }
    out
}

/// Run the "post-request macro" rules for a request that was just sent.
pub fn run_post_request_rules(shared: &Shared, tool: &str, host: &str) {
    if IN_SESSION.with(|s| s.get()) {
        return;
    }
    let rules = shared.session_rules.lock().unwrap().clone();
    for rule in rules {
        if rule.enabled && rule.action == "post-request macro" && rule.tools.iter().any(|t| t == tool) && pattern_matches(&rule.host_match, false, host) {
            let ok = run_macro(shared, &rule.value).is_some();
            shared.log(&format!("Session rule '{}' ran post-request macro {}: {}", rule.name, rule.value, if ok { "ok" } else { "failed" }));
        }
    }
}

pub fn push_ws(shared: &Shared, host: &str, direction: &str, opcode: &str, payload: &[u8]) -> u64 {
    push_ws_in(shared, 0, host, direction, opcode, payload)
}

/// Record one WebSocket message of connection `socket` (bytes kept exactly).
pub fn push_ws_in(shared: &Shared, socket: u64, host: &str, direction: &str, opcode: &str, payload: &[u8]) -> u64 {
    let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
    shared.ws_history.push(WsEntry {
        id,
        ts: util::now_secs(),
        host: host.to_string(),
        direction: direction.to_string(),
        opcode: opcode.to_string(),
        payload: payload.into(),
        socket,
    });
    shared.wake();
    id
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
    /// One of [`SESSION_ACTIONS`].
    pub action: String,
    pub host_match: String,
    /// The action's argument: `Name: value`, `name=value`, a cookie name, a
    /// macro name, or an extension's session handling action.
    pub value: String,
    /// Tools the rule applies to (Burp's "Tools scope").
    pub tools: Vec<String>,
    /// "check session": the expression looked for in the validation response.
    pub check: String,
    /// "check session": true when finding the expression means the session
    /// is invalid ("Please log in"), false when it means valid.
    pub check_invalid_on_match: bool,
}

/// Burp's default tool scope for a new session rule: everything except the
/// Proxy (which Burp marks "use with caution").
pub const SESSION_DEFAULT_TOOLS: [&str; 5] = ["Target", "Scanner", "Repeater", "Intruder", "Sequencer"];

impl SessionRule {
    pub fn new() -> Self {
        Self {
            enabled: true,
            name: "New session rule".into(),
            action: "set header".into(),
            host_match: String::new(),
            value: String::new(),
            tools: SESSION_DEFAULT_TOOLS.iter().map(|t| t.to_string()).collect(),
            check: String::new(),
            check_invalid_on_match: true,
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
pub use crate::ws_history::WsEntry;

pub struct Shared {
    pub mitm: crate::tls::MitmAuthority,
    pub tls_upstream: Arc<rustls::ClientConfig>,
    pub intercept_on: AtomicBool,
    /// Response interception rules (Proxy settings).
    pub response_rules: Mutex<ResponseInterceptRules>,
    pub queue: Mutex<Vec<InterceptItem>>,
    pub history: crate::history::ProxyHistory,
    pub events: Mutex<Vec<String>>,
    /// Attempt an h2c upgrade on direct cleartext connections. Off by default:
    /// Burp never does it and Node servers drop the socket (WEBPROBE_H2C=1).
    pub h2c_upgrade: AtomicBool,
    /// Dashboard task 1, "Live passive crawl from Proxy": while on, links in
    /// proxied responses are added to the site map as unrequested items.
    pub crawl_capture: AtomicBool,
    /// Unrequested site-map items found by the live passive crawl:
    /// (origin "scheme://host[:port]", path).
    pub site_links: Mutex<std::collections::BTreeSet<(String, String)>>,
    /// Items requested by the crawler (site map contents that are not proxy
    /// history, as in Burp).
    pub crawl_items: crate::history::ProxyHistory,
    /// Report WebProbe-only passive checks (names Burp's KB does not have).
    pub extra_checks: AtomicBool,
    pub attack: Mutex<Arc<Attack>>,
    pub repeaters: Mutex<Vec<RepTab>>,
    pub next_id: AtomicU64,
    pub proxy_port: std::sync::atomic::AtomicU16,
    /// The private listener of the embedded browser (0 until first opened).
    pub browser_port: std::sync::atomic::AtomicU16,
    /// Browsers opened from WebProbe (main pid, profile dir), closed on exit.
    pub browsers: Mutex<Vec<(u32, String)>>,
    pub issues: Mutex<Vec<crate::scan::ScanIssue>>,
    /// The primary listener's "Support HTTP/2" (ProjectDefaults.json
    /// request_listeners[].enable_http2, default on): ALPN offers h2 to
    /// HTTPS clients. Extra listeners have their own (`ListenerState`).
    pub listener_http2: AtomicBool,
    /// Streaming responses (Settings > Network > HTTP; R-06).
    pub streaming: Mutex<crate::streaming::StreamSettings>,
    /// (host, reason) pairs already reported as skipped for a streaming
    /// response: the Event log says it once per host and reason.
    pub stream_skips: Mutex<std::collections::HashSet<(String, &'static str)>>,
    /// The Organizer's items (shared, so extensions can add and read them).
    pub organizer: Mutex<crate::organizer::Organizer>,
    /// What extensions sent to tools whose state is the desktop app's
    /// (Intruder, Comparer, Decoder); the app takes them every frame.
    pub tool_sends: Mutex<Vec<crate::ext_calls::ToolSend>>,
    pub scan_enabled: AtomicBool,
    /// The active scanner's run state (claim, stop, pause, progress).
    pub scan: crate::scan_run::ScanRun,
    /// Collaborator ids: the payload pool, registered ids and matching.
    pub oob: crate::oob::OobState,
    /// Stored input pairing of the current scan run (D-10).
    pub stored: crate::stored::StoredInputs,
    /// Passive-scan state across responses (password fields and values
    /// per host); project-scoped, cleared on project load.
    pub passive: crate::passive_state::PassiveState,
    /// Repeater: send in flight, its generation, status line, tab ids.
    pub rep: crate::repeater_run::RepeaterRun,
    /// Client connections being handled right now (see `MAX_CONNECTIONS`).
    pub active_connections: AtomicUsize,
    /// The scan task queue (`tasks.rs`).
    pub tasks: Mutex<Vec<crate::tasks::ScanTask>>,
    pub next_task_id: AtomicU64,
    pub task_runner: AtomicBool,
    /// Called when engine state a front end shows has changed (new traffic,
    /// a held message, a log line): lets a UI redraw on events instead of
    /// polling.
    pub waker: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Burp scan configuration "Audit speed" (burp.Zsv7): 0 fast, 1 normal, 2 thorough.
    pub scan_speed: AtomicU8,
    /// Which checks run and which insertion point types are attacked.
    pub scan_config: Mutex<crate::scan_config::ScanConfig>,
    /// Issue selection of live passive auditing of proxied traffic: its
    /// own setting, as Burp's live passive tasks have their own
    /// configuration (None = every issue type). A scan's library
    /// selection never changes it.
    pub live_passive_issues: Mutex<Option<crate::scan_library::IssueFilter>>,
    /// Burp scan configuration "Audit accuracy" (burp.Zgnf): 0 minimise false
    /// negatives, 1 normal, 2 minimise false positives.
    pub scan_accuracy: AtomicU8,
    /// The REST API settings (user_options.misc.api, R-15) and whether the
    /// server was started.
    pub api_config: Mutex<crate::burp_config::ApiConfig>,
    pub api_started: AtomicBool,
    /// unique locations already passively audited (CrawlDefaults.json max 1500)
    pub scan_locations: Mutex<std::collections::BTreeSet<String>>,
    /// Match and replace rule lists (Proxy options; separate request/response sets)
    pub mr_request: Mutex<Vec<crate::rules::MrRule>>,
    pub mr_response: Mutex<Vec<crate::rules::MrRule>>,
    /// Target scope entries; include/exclude patterns can be literal or regex.
    pub scope: Mutex<Vec<ScopeRule>>,
    /// Session handling rules and their reusable request macros.
    pub session_rules: Mutex<Vec<SessionRule>>,
    /// In-browser session recovery prompt ("check session" rules).
    pub browser_recovery: BrowserRecovery,
    pub macros: Mutex<Vec<Macro>>,
    /// Captured WebSocket handshakes and frames.
    pub ws_history: crate::ws_history::WsHistory,
    /// WebSocket match and replace rules (Proxy settings) and their "Only
    /// apply to in-scope items" (proxy.ws_match_replace_disable_out_of_scope).
    pub ws_rules: Mutex<Vec<crate::ws_rules::WsRule>>,
    pub ws_rules_in_scope_only: AtomicBool,
    /// proxy.intercept_web_sockets_messages.intercept_in_scope_only (off).
    pub ws_intercept_in_scope: AtomicBool,
    /// proxy.miscellaneous.strip_sec_websocket_extensions_headers_in_incoming_requests (on).
    pub ws_strip_extensions: AtomicBool,
    /// Live proxied WebSockets by connection id (WebSocket Repeater attaches).
    pub ws_live: Mutex<HashMap<u64, LiveWs>>,
    /// WebSocket Repeater connections.
    pub ws_sessions: Mutex<Vec<Arc<crate::ws_repeater::WsSession>>>,
    /// Diff-count state for the history table ("Diff count", burp.Zxwu.java:56).
    pub diff_tracker: Mutex<DiffTracker>,
    /// Extension host (Montoya-shaped, Path A): hooks run in the proxy pipeline.
    pub ext_host: Mutex<crate::ext_host::ExtensionHost>,
    /// WebSocket message interception per direction. Burp's
    /// proxy.intercept_web_sockets_messages defaults both to true; messages
    /// are only held while Intercept is on (ProjectDefaults.json).
    pub ws_intercept_client: AtomicBool,
    pub ws_intercept_server: AtomicBool,
    /// WebSockets history ids whose payload was edited before forwarding
    /// (Burp's "Edited" column).
    pub ws_edited: Mutex<std::collections::HashSet<u64>>,
    /// Host -> IP cache for the history "IP" column.
    pub ip_cache: Mutex<std::collections::HashMap<String, String>>,
    /// Exchanges sent by the tools (Repeater, Intruder, Scanner, ...), waiting
    /// for the Logger to collect them. Proxy traffic reaches the Logger
    /// through `history` instead.
    pub tool_log: Mutex<Vec<ToolExchange>>,
    /// The session-handling cookie jar (Burp's suite-wide jar): fed by the
    /// responses of the tools it monitors, applied to the requests of the
    /// tools its rule covers.
    pub cookie_jar: Mutex<crate::cookie_jar::CookieJar>,
    /// The final response of the macro that ran most recently: session rules
    /// fill `{name}` placeholders in their values from it (a bearer token out
    /// of a JSON login response, for instance).
    pub macro_last_response: Mutex<Vec<u8>>,
    /// Which requests the Intercept tab holds (Burp's request interception
    /// rules table).
    pub intercept_rules: Mutex<Vec<crate::intercept_rules::InterceptRule>>,
    /// Burp's listener "Redirect to host / port": requests arriving on the
    /// listener with this port all go to the given host and port, whatever
    /// host they name.
    pub listener_redirects: Mutex<std::collections::HashMap<u16, (String, u16)>>,
    /// Monotonic counter of proxied messages, for the status bar's activity read.
    pub messages: std::sync::atomic::AtomicUsize,
    /// Upstream direct/HTTP/SOCKS routing configuration.
    pub upstream: Mutex<crate::upstream::UpstreamConfig>,
    /// Per-destination upstream proxy rules, checked before `upstream`.
    pub upstream_rules: Mutex<Vec<crate::upstream::UpstreamRule>>,
    pub listener_running: AtomicBool,
    pub listener_restart: AtomicBool,
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
            response_rules: Mutex::new(ResponseInterceptRules::default()),
            queue: Mutex::new(Vec::new()),
            history: Default::default(),
            events: Mutex::new(Vec::new()),
            extra_checks: AtomicBool::new(false),
            crawl_capture: AtomicBool::new(true),
            site_links: Mutex::new(std::collections::BTreeSet::new()),
            crawl_items: Default::default(),
            h2c_upgrade: AtomicBool::new(std::env::var("WEBPROBE_H2C").map(|v| v == "1").unwrap_or(false)),
            attack: Mutex::new(Arc::new(Attack {
                running: AtomicBool::new(false),
                stop: AtomicBool::new(false),
                done: AtomicUsize::new(0),
                total: AtomicUsize::new(0),
                rows: Mutex::new(Vec::new()),
            })),
            repeaters: Mutex::new(vec![RepTab {
                id: 1,
                name: "1".into(),
                host: String::new(),
                port: 80,
                https: false,
                // QA hook: WEBPROBE_SEED_REPEATER=<file> loads a request so the
                // editor (line numbers, hex, find, font size) can be inspected.
                request: std::env::var("WEBPROBE_SEED_REPEATER")
                    .ok()
                    .and_then(|p| crate::util::read_text_file_capped(std::path::Path::new(&p), crate::util::MAX_TEXT_FILE_BYTES).ok())
                    .unwrap_or_default(),
                response: None,
                result_line: String::new(),
            history: Vec::new(),
            hist_pos: 0,
            ws: None,
            }]),
            messages: std::sync::atomic::AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
            proxy_port: std::sync::atomic::AtomicU16::new(8080),
            browser_port: std::sync::atomic::AtomicU16::new(0),
            browsers: Mutex::new(Vec::new()),
            issues: Mutex::new(Vec::new()),
            listener_http2: AtomicBool::new(true),
            streaming: Mutex::new(crate::streaming::StreamSettings::default()),
            stream_skips: Mutex::new(std::collections::HashSet::new()),
            organizer: Mutex::new(crate::organizer::Organizer::new()),
            tool_sends: Mutex::new(Vec::new()),
            scan: Default::default(),
            oob: Default::default(),
            stored: Default::default(),
            passive: Default::default(),
            rep: Default::default(),
            scan_enabled: AtomicBool::new(true),
            active_connections: AtomicUsize::new(0),
            tasks: Mutex::new(Vec::new()),
            next_task_id: AtomicU64::new(1),
            task_runner: AtomicBool::new(false),
            waker: Mutex::new(None),
            scan_config: Mutex::new(crate::scan_config::ScanConfig::default()),
            live_passive_issues: Mutex::new(None),
            // AuditDefaults.json: scan_speed / scan_accuracy "normal"
            scan_speed: AtomicU8::new(1),
            scan_accuracy: AtomicU8::new(1),
            api_config: Mutex::new(crate::burp_config::ApiConfig::default()),
            api_started: AtomicBool::new(false),
            scan_locations: Mutex::new(std::collections::BTreeSet::new()),
            mr_request: Mutex::new(Vec::new()),
            mr_response: Mutex::new(Vec::new()),
            scope: Mutex::new(Vec::new()),
            session_rules: Mutex::new(Vec::new()),
            browser_recovery: BrowserRecovery::default(),
            macros: Mutex::new(Vec::new()),
            ws_history: crate::ws_history::WsHistory::new(),
            ws_rules: Mutex::new(Vec::new()),
            ws_rules_in_scope_only: AtomicBool::new(false),
            ws_intercept_in_scope: AtomicBool::new(false),
            ws_strip_extensions: AtomicBool::new(true),
            ws_live: Mutex::new(HashMap::new()),
            ws_sessions: Mutex::new(Vec::new()),
            diff_tracker: Mutex::new(DiffTracker::default()),
            ext_host: Mutex::new(crate::ext_host::ExtensionHost::default()),
            ws_intercept_client: AtomicBool::new(true),
            ws_intercept_server: AtomicBool::new(true),
            ws_edited: Mutex::new(std::collections::HashSet::new()),
            ip_cache: Mutex::new(std::collections::HashMap::new()),
            tool_log: Mutex::new(Vec::new()),
            cookie_jar: Mutex::new(crate::cookie_jar::CookieJar::default()),
            macro_last_response: Mutex::new(Vec::new()),
            intercept_rules: Mutex::new(crate::intercept_rules::defaults()),
            listener_redirects: Mutex::new(std::collections::HashMap::new()),
            upstream: Mutex::new(crate::upstream::UpstreamConfig::default()),
            upstream_rules: Mutex::new(Vec::new()),
            listener_running: AtomicBool::new(false),
            listener_restart: AtomicBool::new(false),
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
        {
            let mut ev = self.events.lock().unwrap();
            ev.push(format!("[{ts}] {msg}"));
            let n = ev.len();
            if n > 500 {
                ev.drain(..n - 500);
            }
        }
        self.wake();
    }

    /// Add crawl-only site map items (Target), bodies in the on-disk store
    /// like Proxy history.
    pub fn add_crawl_items(&self, items: impl IntoIterator<Item = HistEntry>) {
        self.crawl_items.extend(items);
    }

    pub fn push_history(&self, e: HistEntry) {
        self.history.push(e);
        self.messages.fetch_add(1, Ordering::SeqCst);
        self.wake();
    }

    /// Install the front end's wake-up call (see `waker`).
    pub fn set_waker(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *self.waker.lock().unwrap() = Some(f);
    }

    /// Tell the front end that something it shows has changed.
    pub fn wake(&self) {
        let f = self.waker.lock().unwrap().clone();
        if let Some(f) = f {
            f();
        }
    }

    pub fn count_waiting(&self) -> usize {
        self.queue.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// The upstream route for a destination host (Settings > Network >
    /// Upstream proxy servers, then the global setting).
    pub fn upstream_for(&self, host: &str) -> crate::upstream::UpstreamConfig {
        crate::upstream::choose(&self.upstream_rules.lock().unwrap(), &self.upstream.lock().unwrap(), host)
    }

    /// Extension request hooks (Montoya-shaped, Path A): run every enabled
    /// extension in registration order; false means one dropped the message.
    /// The registry is only locked to take the list, not while hooks run.
    /// `ann` collects the exchange's Montoya annotations (comment and
    /// highlight for Proxy history).
    pub fn ext_handle_request(&self, svc: &crate::ext_host::HttpService, method: &str, path: &str, req: &mut Vec<u8>, ann: &mut crate::ext_host::Annotations) -> bool {
        let exts = self.ext_host.lock().unwrap().active();
        if exts.is_empty() {
            return true;
        }
        let pass = crate::ext_host::run_request_hooks_annotated(&exts, svc, method, path, req, ann);
        self.collect_ext_issues(&exts, &svc.host, path);
        pass
    }

    /// Extension response hooks: false means one dropped the message. Issues
    /// the extensions reported are added for `host` + `path`.
    pub fn ext_handle_response(&self, svc: &crate::ext_host::HttpService, method: &str, path: &str, req: &[u8], resp: &mut Vec<u8>, ann: &mut crate::ext_host::Annotations) -> bool {
        let exts = self.ext_host.lock().unwrap().active();
        if exts.is_empty() {
            return true;
        }
        let pass = crate::ext_host::run_response_hooks_annotated(&exts, svc, method, path, req, resp, ann);
        self.collect_ext_issues(&exts, &svc.host, path);
        pass
    }

    fn collect_ext_issues(&self, exts: &[Arc<dyn crate::ext_host::ProxyHooks>], host: &str, path: &str) {
        let issues: Vec<crate::scan::ScanIssue> = exts
            .iter()
            .flat_map(|e| e.take_issues())
            .map(|i| crate::scan::ScanIssue {
                id: 0,
                sev: match i.severity.to_ascii_lowercase().as_str() {
                    s @ ("high" | "medium" | "low") => s.to_string(),
                    _ => "info".to_string(),
                },
                type_id: crate::scan::issue_type_id(&i.name),
                name: i.name,
                host: if i.host.is_empty() { host.to_string() } else { i.host },
                path: if i.path.is_empty() { path.split('?').next().unwrap_or("").to_string() } else { i.path },
                detail: i.detail,
                false_positive: false,
                confidence: match i.confidence.as_str() {
                    c @ ("Certain" | "Firm" | "Tentative") => c.to_string(),
                    _ => "Tentative".to_string(),
                },
                ts: util::now_secs(),
                evidence: Vec::new(),
                ident: String::new(),
            })
            .collect();
        crate::scan::add_issues(self, issues);
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
    let too_large = || std::io::Error::new(std::io::ErrorKind::InvalidData, "request body too large");
    // Transfer-Encoding wins over Content-Length (RFC 9112 §6.3). A chunked
    // upload is read to its last chunk; it used to be forwarded with only the
    // bytes of the first read.
    let head = String::from_utf8_lossy(&buf[..head_len]).to_ascii_lowercase();
    let chunked = head.lines().any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"));
    if chunked {
        let mut cur = crate::codec::ChunkCursor::default();
        while crate::codec::scan_chunked(&buf[head_len..], &mut cur, |_| {}) == crate::codec::Chunked::Partial {
            if buf.len() - head_len > crate::codec::MAX_BODY {
                return Err(too_large());
            }
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    } else if let Some(len) = content_length(&buf[..head_len]) {
        if len > crate::codec::MAX_BODY {
            return Err(too_large());
        }
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
    fn set_read_timeout_ms(&self, ms: u64) -> std::io::Result<()> {
        match self {
            UpstreamConn::Plain(s) => s.set_read_timeout(Some(Duration::from_millis(ms))),
            UpstreamConn::Tls(s) => s.get_ref().set_read_timeout(Some(Duration::from_millis(ms))),
        }
    }
}

impl UpstreamConn {
    fn writable(&mut self) -> bool {
        // A pooled connection is reusable only if the peer has neither closed
        // it nor sent anything unasked: bytes waiting now (a late or extra
        // response) would otherwise be read as the next request's response.
        let mut b = [0u8; 1];
        match self {
            UpstreamConn::Plain(s) => {
                let _ = s.set_nonblocking(true);
                let idle = matches!(s.peek(&mut b), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock);
                let _ = s.set_nonblocking(false);
                idle
            }
            UpstreamConn::Tls(tls) => {
                // TLS 1.3 servers send session tickets after the handshake:
                // records that carry no application data. Let rustls consume
                // whatever is waiting; only plaintext or a close is stale.
                let _ = tls.sock.set_nonblocking(true);
                let idle = matches!(tls.read(&mut b), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock);
                let _ = tls.sock.set_nonblocking(false);
                idle
            }
        }
    }
}

pub struct Upstream {
    pub resp: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// One proxy listener: a bind address and port, and Burp's listener option
/// "Support HTTP/2" (request_listeners[].enable_http2, default on).
#[derive(Clone, Debug, PartialEq)]
pub struct ListenerSpec {
    pub bind: String,
    pub port: u16,
    pub http2: bool,
}

impl ListenerSpec {
    /// A listener with Burp's defaults (HTTP/2 supported).
    pub fn new(bind: &str, port: u16) -> Self {
        ListenerSpec { bind: bind.to_string(), port, http2: true }
    }
}

/// Runtime state of one listener (for the status display).
pub struct ListenerState {
    pub spec: ListenerSpec,
    pub running: std::sync::atomic::AtomicBool,
    pub error: Mutex<Option<String>>,
    /// "Support HTTP/2", changeable without restarting the listener.
    pub http2: AtomicBool,
}

impl ListenerState {
    fn new(spec: ListenerSpec) -> Self {
        let http2 = AtomicBool::new(spec.http2);
        Self { spec, running: AtomicBool::new(false), error: Mutex::new(None), http2 }
    }
}

/// "scheme://host[:port]" of a history entry, the port omitted when it is the
/// scheme's default (Burp's Host column).
pub fn history_host(e: &HistEntry) -> String {
    let scheme = if e.https { "https" } else { "http" };
    let default = if e.https { 443 } else { 80 };
    if e.port == default || e.port == 0 {
        format!("{scheme}://{}", e.host)
    } else {
        format!("{scheme}://{}:{}", e.host, e.port)
    }
}

/// Sends a raw HTTP/1.1 request through the configured upstream route and reads
/// the whole response. Framing decides where the response ends, and the
/// connection is pooled per host when keep-alive is enabled
/// (ProjectDefaults.json http.http1.enable_keep_alive, default false).
pub fn send_raw(shared: &Shared, host: &str, port: u16, request: &[u8]) -> Upstream {
    send_raw_with(shared, host, port, request, None)
}

/// [`send_raw`] with a response sink (streaming responses, R-06); without
/// one, the tool on this thread gets Burp's "other tools" handling: a
/// streaming response is cut after its head.
pub fn send_raw_with(shared: &Shared, host: &str, port: u16, request: &[u8], sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>) -> Upstream {
    let request = jar_request(shared, host, false, request);
    let request = session_request(shared, port, false, request);
    let mut tool_sink = tool_sink(shared, host, port, false, &request);
    let up = match (sink, tool_sink.as_mut()) {
        (Some(s), _) => send_from(shared, host, port, &request, Some(s)),
        (None, Some(t)) => send_from(shared, host, port, &request, Some(t)),
        (None, None) => send_from(shared, host, port, &request, None),
    };
    jar_response(shared, host, &request, &up);
    session_after(shared, host);
    log_tool_exchange(shared, host, port, false, &request, &up);
    up
}

/// The full URL of a request sent to host:port (for the streaming rule).
pub(crate) fn request_url(host: &str, port: u16, https: bool, request: &[u8]) -> String {
    let parts = util::parse_http(request);
    history_host(&HistEntry { host: host.to_string(), port, https, ..Default::default() }) + &path_of(&parts)
}

/// Burp's "other tools ignore streaming responses and close the
/// connection": the sink of a tool (Scanner, Intruder, crawler, ...) other
/// than the Proxy and Repeater, which bring their own.
struct ToolSink<'a> {
    shared: &'a Shared,
    url: String,
    settings: crate::streaming::StreamSettings,
}

impl crate::streaming::ResponseSink for ToolSink<'_> {
    fn head(&mut self, head: &[u8]) -> crate::streaming::BodyMode {
        if crate::streaming::decide(&self.url, head, &self.settings) == crate::streaming::Decision::Buffered {
            return crate::streaming::BodyMode::Buffer;
        }
        let tool = TOOL.with(|t| t.get()).unwrap_or("A tool");
        self.shared.log(&format!("{tool} ignored the streaming response from {} and closed the connection", self.url));
        crate::streaming::BodyMode::HeadOnly
    }
    fn wire(&mut self, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn payload(&mut self, _: &[u8]) {}
    fn end(&mut self, _: bool) {}
}

fn tool_sink<'a>(shared: &'a Shared, host: &str, port: u16, https: bool, request: &[u8]) -> Option<ToolSink<'a>> {
    let tool = TOOL.with(|t| t.get())?;
    if tool == "Proxy" || tool == "Repeater" {
        return None;
    }
    Some(ToolSink { shared, url: request_url(host, port, https, request), settings: shared.streaming.lock().unwrap().clone() })
}

/// How a sender wants HTTP/2 used on its thread (Repeater's protocol
/// control): `want_h2` Some(true) = HTTP/2 only, Some(false) = HTTP/1
/// only, None = negotiate by ALPN (the Proxy, and Repeater with "Allow
/// HTTP/2 ALPN override"). `strip_connection`: Repeater's "Strip
/// Connection header over HTTP/2" (default on).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Http2Choice {
    pub want_h2: Option<bool>,
    pub strip_connection: bool,
}

thread_local! {
    static H2_CHOICE: std::cell::Cell<Option<Http2Choice>> = const { std::cell::Cell::new(None) };
    static LAST_PROTOCOL: std::cell::Cell<&'static str> = const { std::cell::Cell::new("HTTP/1.1") };
}

/// Restores the thread's previous HTTP/2 choice when dropped.
pub struct Http2Scope(Option<Http2Choice>);

impl Drop for Http2Scope {
    fn drop(&mut self) {
        H2_CHOICE.with(|c| c.set(self.0));
    }
}

/// Use `choice` for sends on this thread until the scope ends.
pub fn http2_scope(choice: Http2Choice) -> Http2Scope {
    Http2Scope(H2_CHOICE.with(|c| c.replace(Some(choice))))
}

/// The protocol the last send on this thread used ("HTTP/1.1"/"HTTP/2").
pub fn last_protocol() -> &'static str {
    LAST_PROTOCOL.with(|p| p.get())
}

/// An HTTP/1.1 request line for a request shown as `HTTP/2` (the
/// listener's h2 requests, Repeater tabs) that goes out over HTTP/1.
fn as_http1(req: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let line_end = req.iter().position(|&b| b == b'\n').unwrap_or(req.len());
    let line = &req[..line_end];
    let trimmed = line.strip_suffix(b"\r").unwrap_or(line);
    for v in [b"HTTP/2".as_slice(), b"HTTP/2.0".as_slice()] {
        if trimmed.ends_with(v) && trimmed.len() > v.len() && trimmed[trimmed.len() - v.len() - 1] == b' ' {
            let mut out = trimmed[..trimmed.len() - v.len()].to_vec();
            out.extend_from_slice(b"HTTP/1.1");
            out.extend_from_slice(&req[trimmed.len()..]);
            return out.into();
        }
    }
    req.into()
}

/// The request a tool is about to send, with the cookie jar's cookies when
/// the jar's rule covers the tool working on this thread; otherwise as given.
fn jar_request<'a>(shared: &Shared, host: &str, https: bool, request: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
    let Some(tool) = TOOL.with(|t| t.get()) else { return request.into() };
    let jar = shared.cookie_jar.lock().unwrap();
    if !jar.applies_to(tool) || jar.cookies.is_empty() {
        return request.into();
    }
    jar.apply(request, host, https, util::now_secs()).into()
}

/// The session rules scoped to the tool working on this thread, applied to
/// the request it is about to send.
fn session_request<'a>(shared: &Shared, port: u16, https: bool, request: std::borrow::Cow<'a, [u8]>) -> std::borrow::Cow<'a, [u8]> {
    let Some(tool) = TOOL.with(|t| t.get()) else { return request };
    if shared.session_rules.lock().unwrap().is_empty() {
        return request;
    }
    apply_session_rules_for(shared, tool, &request, port, https).into()
}

/// Post-request macros for the tool working on this thread.
fn session_after(shared: &Shared, host: &str) {
    if let Some(tool) = TOOL.with(|t| t.get()) {
        if !shared.session_rules.lock().unwrap().is_empty() {
            run_post_request_rules(shared, tool, host);
        }
    }
}

/// Feed a tool's response to the cookie jar when the jar monitors that tool.
fn jar_response(shared: &Shared, host: &str, request: &[u8], up: &Upstream) {
    let (Some(tool), Some(resp)) = (TOOL.with(|t| t.get()), up.resp.as_deref()) else { return };
    let mut jar = shared.cookie_jar.lock().unwrap();
    if jar.updates_from(tool) {
        let path = util::parse_http(request).path;
        jar.update_from_response(host, &path, resp, util::now_secs());
    }
}

/// One request a tool sent, summarised for the Logger (Burp's Logger lists
/// every tool's traffic, not only the proxy's).
#[derive(Clone, Debug, PartialEq)]
pub struct ToolExchange {
    pub ts: u64,
    pub tool: &'static str,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub method: String,
    pub path: String,
    /// Status code text, empty when no response arrived.
    pub status: String,
    pub req_len: usize,
    pub resp_len: usize,
    /// Response Content-Type without parameters.
    pub mime: String,
    /// The messages, each cut at [`TOOL_LOG_MESSAGE_MAX`] bytes.
    pub request: Arc<[u8]>,
    pub response: Option<Arc<[u8]>>,
}

/// Bytes of each message kept for the Logger's detail pane.
pub const TOOL_LOG_MESSAGE_MAX: usize = 256 * 1024;

/// Unlogged tool exchanges kept while nothing collects them (a headless run).
const TOOL_LOG_MAX: usize = 5000;

thread_local! {
    static TOOL: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

/// Marks the current thread as working for `tool` until the guard is dropped:
/// every request it sends through `send_raw`/`send_tls_raw` is then recorded
/// in `Shared::tool_log` under that name.
pub fn tool_scope(tool: &'static str) -> ToolScope {
    ToolScope(TOOL.with(|t| t.replace(Some(tool))))
}

pub struct ToolScope(Option<&'static str>);

impl Drop for ToolScope {
    fn drop(&mut self) {
        TOOL.with(|t| t.set(self.0));
    }
}

fn log_tool_exchange(shared: &Shared, host: &str, port: u16, https: bool, request: &[u8], up: &Upstream) {
    let Some(tool) = TOOL.with(|t| t.get()) else { return };
    let first = request.split(|b| *b == b'\n').next().unwrap_or_default();
    let first = String::from_utf8_lossy(first);
    let mut words = first.split_whitespace();
    let method = words.next().unwrap_or_default().to_string();
    let path = words.next().unwrap_or_default().to_string();
    let (status, resp_len, mime) = match &up.resp {
        Some(resp) => {
            let parts = crate::util::parse_http(resp);
            let status = String::from_utf8_lossy(resp.split(|b| *b == b'\n').next().unwrap_or_default())
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let ct = crate::util::get_header(&parts.headers, "Content-Type").unwrap_or_default();
            (status, resp.len(), ct.split(';').next().unwrap_or_default().trim().to_ascii_lowercase())
        }
        None => (String::new(), 0, String::new()),
    };
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut log = shared.tool_log.lock().unwrap();
    if log.len() >= TOOL_LOG_MAX {
        log.remove(0);
    }
    let keep = |b: &[u8]| -> Arc<[u8]> { Arc::from(&b[..b.len().min(TOOL_LOG_MESSAGE_MAX)]) };
    log.push(ToolExchange {
        ts,
        tool,
        host: host.to_string(),
        port,
        https,
        method,
        path,
        status,
        req_len: request.len(),
        resp_len,
        mime,
        request: keep(request),
        response: up.resp.as_deref().map(keep),
    });
}

fn send_from(shared: &Shared, host: &str, port: u16, req: &[u8], sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>) -> Upstream {
    let t0 = std::time::Instant::now();
    let r = send_inner(shared, host, port, req, sink);
    // Debug aid: WB_TRACE=1 prints every upstream exchange slower than 2 s.
    if std::env::var_os("WB_TRACE").is_some() && t0.elapsed().as_millis() > 2000 {
        let first = req.split(|b| *b == b'\n').next().map(|l| String::from_utf8_lossy(l).into_owned()).unwrap_or_default();
        eprintln!("TRACE slow {} ms {first} -> {:?}", t0.elapsed().as_millis(), r.as_ref().err());
    }
    match r {
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
    /// The read timeout from now on (idle time allowed between reads).
    fn set_read_timeout_ms(&self, ms: u64) -> std::io::Result<()>;
    /// A body without length information is bounded by the open-ended
    /// timeout (ProjectDefaults.json connections.timeouts).
    fn set_open_ended_timeout(&self) -> std::io::Result<()> {
        self.set_read_timeout_ms(OPEN_ENDED_RESPONSE_TIMEOUT_MS)
    }
}

impl ResponseRead for TcpStream {
    fn set_read_timeout_ms(&self, ms: u64) -> std::io::Result<()> {
        self.set_read_timeout(Some(Duration::from_millis(ms)))
    }
}

impl ResponseRead for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_read_timeout_ms(&self, ms: u64) -> std::io::Result<()> {
        self.get_ref().set_read_timeout(Some(Duration::from_millis(ms)))
    }
}

trait ProxyIo: Read + Write {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()>;
    /// The peer closed the connection (checked without consuming data).
    fn peer_closed(&self) -> bool {
        false
    }
}

/// EOF or a hard error on a (non-blocking) socket, seen with a peek that
/// consumes nothing.
fn tcp_closed(s: &TcpStream) -> bool {
    let mut b = [0u8; 1];
    match s.peek(&mut b) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted | std::io::ErrorKind::TimedOut),
    }
}

impl ProxyIo for TcpStream {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.set_nonblocking(nonblocking)
    }
    fn peer_closed(&self) -> bool {
        tcp_closed(self)
    }
}

impl ProxyIo for rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.get_ref().set_nonblocking(nonblocking)
    }
    fn peer_closed(&self) -> bool {
        tcp_closed(self.get_ref())
    }
}

impl ProxyIo for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_nonblocking_io(&self, nonblocking: bool) -> std::io::Result<()> {
        self.get_ref().set_nonblocking(nonblocking)
    }
    fn peer_closed(&self) -> bool {
        tcp_closed(self.get_ref())
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
/// connection. `Ok(None)` means nothing was written and the caller should send
/// the request normally. `Ok(Some((resp, upgraded)))` is the full response:
/// `upgraded = true` means the socket now speaks HTTP/2 (never pool it);
/// `upgraded = false` means the server declined and `resp` is an ordinary
/// HTTP/1.1 reply whose connection may still be pooled for keep-alive.
fn try_h2c_upgrade<S: Read + Write + ResponseRead>(stream: &mut S, routed: &[u8]) -> Result<Option<(Vec<u8>, bool)>, String> {
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
        // Stream 1 is the HTTP/1.1 request that was just sent; only the
        // preface and SETTINGS follow (RFC 7540 §3.2).
        let resp = crate::h2::exchange_upgraded(stream)?;
        return Ok(Some((resp, true)));
    }
    // The server declined (or ignored) the upgrade: read the rest of the
    // HTTP/1.1 message per its framing and return it unchanged.
    let kind = crate::codec::response_body_kind(&head, &parts.method);
    let mut msg = head;
    let head_len = util::find_head_end(&msg).unwrap_or(msg.len());
    match kind {
        crate::codec::BodyKind::None => {}
        crate::codec::BodyKind::Length(n) => {
            let end = head_len.saturating_add(n);
            while msg.len() < end && msg.len() - head_len <= crate::codec::MAX_BODY {
                let mut chunk = [0u8; 16384];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(k) => msg.extend_from_slice(&chunk[..k]),
                    Err(_) => break,
                }
            }
            msg.truncate(end.min(msg.len()));
        }
        crate::codec::BodyKind::Chunked => {
            let mut cur = crate::codec::ChunkCursor::default();
            loop {
                if crate::codec::scan_chunked(&msg[head_len..], &mut cur, |_| {}) != crate::codec::Chunked::Partial || msg.len() - head_len > crate::codec::MAX_BODY {
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
            // Bounded like every response body (codec::MAX_BODY).
            let mut rest = util::read_capped(stream, crate::codec::MAX_BODY, "the response body").map_err(|e| format!("h2c fallback: {e}"))?;
            msg.append(&mut rest);
        }
    }
    Ok(Some((msg, false)))
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

fn send_inner(shared: &Shared, host: &str, port: u16, req: &[u8], mut sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>) -> Result<Vec<u8>, String> {
    let config = shared.upstream_for(&host);
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
    // h2c upgrade (RFC 7540 §3.2) on direct plain connections. Burp never
    // sends one (cleartext traffic stays HTTP/1.1), and servers such as Node's
    // http module drop the socket on an unhandled `Upgrade: h2c`, so it is
    // opt-in (WEBPROBE_H2C=1). Any answer other than 101 is handed back as the
    // ordinary HTTP/1.1 response.
    let h2c = shared.h2c_upgrade.load(Ordering::SeqCst);
    if h2c && !reused && config.kind == crate::upstream::UpstreamKind::None {
        match try_h2c_upgrade(&mut stream, &routed) {
            Ok(Some((resp, upgraded))) => {
                // A real upgrade leaves the socket speaking HTTP/2, so it must
                // never enter the HTTP/1.x pool. A declined upgrade is just an
                // ordinary HTTP/1.1 reply: keep the connection reusable so a
                // later keep-alive request can actually reuse it.
                if !upgraded && keep_alive && response_allows_reuse(&resp) {
                    shared.pool.lock().unwrap().insert(key, stream);
                }
                return Ok(resp);
            }
            Ok(None) => {}
            Err(_) => {
                // The server hung up on the upgrade: retry plainly on a new socket.
                let tcp = crate::upstream::connect_target(&config, host, port)?;
                tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS))).ok();
                shared.conns_opened.fetch_add(1, Ordering::SeqCst);
                stream = UpstreamConn::Plain(tcp);
            }
        }
    }
    // Cleartext is HTTP/1 here: a request shown as HTTP/2 goes as HTTP/1.1.
    let routed = as_http1(&routed).into_owned();
    LAST_PROTOCOL.with(|p| p.set("HTTP/1.1"));
    let result = match exchange(&mut stream, &routed, sink.as_deref_mut()) {
        Ok((r, reusable)) => Ok((r, reusable, stream)),
        Err(e) => {
            if reused {
                let mut fresh = UpstreamConn::Plain({
                    let tcp = crate::upstream::connect_target(&config, host, port)?;
                    tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS))).ok();
                    tcp
                });
                shared.conns_opened.fetch_add(1, Ordering::SeqCst);
                exchange(&mut fresh, &routed, sink.as_deref_mut()).map(|(r, reusable)| (r, reusable, fresh)).map_err(|e2| format!("{e}; retry: {e2}"))
            } else {
                Err(e)
            }
        }
    }?;
    let (resp, reusable, stream) = result;
    if keep_alive && reusable && response_allows_reuse(&resp) {
        shared.pool.lock().unwrap().insert(key, stream);
        if reused {
            shared.pool_hits.fetch_add(1, Ordering::SeqCst);
        }
    }
    Ok(resp)
}

pub fn send_tls_raw(shared: &Shared, host: &str, port: u16, request: &[u8]) -> Upstream {
    send_tls_raw_with(shared, host, port, request, None)
}

/// [`send_tls_raw`] with a response sink (see [`send_raw_with`]).
pub fn send_tls_raw_with(shared: &Shared, host: &str, port: u16, request: &[u8], sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>) -> Upstream {
    let request = jar_request(shared, host, true, request);
    let request = session_request(shared, port, true, request);
    let mut tool_sink = tool_sink(shared, host, port, true, &request);
    let sent = match (sink, tool_sink.as_mut()) {
        (Some(s), _) => send_tls_inner(shared, host, port, &request, Some(s)),
        (None, Some(t)) => send_tls_inner(shared, host, port, &request, Some(t)),
        (None, None) => send_tls_inner(shared, host, port, &request, None),
    };
    let up = match sent {
        Ok(resp) => Upstream { resp: Some(resp), error: None },
        Err(e) => Upstream { resp: None, error: Some(e) },
    };
    jar_response(shared, host, &request, &up);
    session_after(shared, host);
    log_tool_exchange(shared, host, port, true, &request, &up);
    up
}

fn send_tls_inner(shared: &Shared, host: &str, port: u16, req: &[u8], mut sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>) -> Result<Vec<u8>, String> {
    let config = shared.upstream_for(&host);
    let req = util::origin_form(req);
    let keep_alive = shared.keep_alive.load(Ordering::SeqCst);
    let req = if keep_alive { set_connection(&req, "keep-alive") } else { set_connection(&req, "close") };
    let key = (host.to_string(), port);
    let choice = H2_CHOICE.with(|c| c.get());
    let want_h2 = choice.and_then(|c| c.want_h2);
    // Pooled connections are HTTP/1.x: HTTP/2 asked for needs a fresh one.
    let mut pooled = if want_h2 == Some(true) { None } else { shared.tls_pool.lock().unwrap().remove(&key) };
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
    LAST_PROTOCOL.with(|p| p.set(if use_h2 { "HTTP/2" } else { "HTTP/1.1" }));
    if want_h2 == Some(true) && !use_h2 {
        return Err("the server did not agree to HTTP/2 (ALPN); switch the request to HTTP/1".into());
    }
    if use_h2 {
        let mut h2req = crate::h2::request_from_raw(&req, "https")
            .ok_or("h2: request without Host header")?;
        if choice.is_some_and(|c| !c.strip_connection) {
            // Repeater's "Strip Connection header over HTTP/2" off: send it.
            let parts = util::parse_http(&req);
            h2req.connection = util::get_header(&parts.headers, "Connection");
        }
        let first = match &mut stream {
            UpstreamConn::Tls(tls) => crate::h2::exchange(tls, &h2req, sink.as_deref_mut()),
            _ => return Err("h2: not a TLS connection".into()),
        };
        match first {
            Ok(resp) => return Ok(resp),
            Err(e) if crate::h2::retryable(&e) => {
                // The server never processed stream 1 (GOAWAY/REFUSED_STREAM),
                // so one retry on a fresh connection is safe.
                shared.conns_opened.fetch_add(1, Ordering::SeqCst);
                let mut fresh = new_tls_conn(shared, &config, host, port)?;
                let retried = match &mut fresh {
                    UpstreamConn::Tls(tls) => {
                        let _ = tls.conn.complete_io(&mut tls.sock);
                        if tls.conn.alpn_protocol() == Some(b"h2".as_slice()) {
                            crate::h2::exchange(tls, &h2req, sink.as_deref_mut())
                        } else {
                            Err(e.clone())
                        }
                    }
                    _ => Err(e.clone()),
                };
                return retried.map_err(|e2| format!("{e}; retry: {e2}"));
            }
            Err(e) => return Err(e),
        }
    }
    // HTTP/1 on the wire: a request shown as HTTP/2 goes out as HTTP/1.1.
    let req = as_http1(&req).into_owned();
    let result = match exchange(&mut stream, &req, sink.as_deref_mut()) {
        Ok((r, reusable)) => Ok((r, reusable, stream)),
        Err(e) => {
            // A reused connection may have been closed by the peer; try once more
            // on a fresh one before reporting the failure.
            if reused {
                let mut fresh = new_tls_conn(shared, &config, host, port)?;
                exchange(&mut fresh, &req, sink.as_deref_mut()).map(|(r, reusable)| (r, reusable, fresh)).map_err(|e2| format!("{e}; retry: {e2}"))
            } else {
                Err(e)
            }
        }
    }?;
    let (result, reusable, stream) = result;
    if keep_alive && reusable && response_allows_reuse(&result) {
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

/// Write a request and read exactly one framed response. Returns the response
/// and whether the connection may go back to the pool: not when the body was
/// EOF-delimited, malformed or cut short, and not when the peer sent bytes
/// past it (pipelining stays off, MECHANICS.md A-03; those bytes would
/// otherwise become the next request's response).
fn exchange<S: Read + Write + ResponseRead>(stream: &mut S, req: &[u8], sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>) -> Result<(Vec<u8>, bool), String> {
    stream.write_all(req).map_err(|e| format!("write: {e}"))?;
    stream.flush().ok();
    let method = req.split(|&b| b == b' ').next().map(String::from_utf8_lossy).unwrap_or_default();
    let mut buffer = Vec::new();
    let (resp, reusable) = crate::codec::read_message(stream, &mut buffer, &method, sink).map_err(|e| format!("read: {e}"))?;
    Ok((resp, reusable && buffer.is_empty()))
}

// ---------- the proxy loop ----------

/// The embedded browser's own listener. Burp's browser does not use the
/// user's proxy listener: it gets a private one on a random loopback port
/// (its process runs with --proxy-server=localhost:<random>), so it works
/// even when the configured port (8080) is taken by another tool and could
/// otherwise reach that tool instead. Traffic takes the same path as the main
/// listener (history, interception, scanner).
pub fn browser_listener(shared: &Arc<Shared>) -> Result<u16, String> {
    let p = shared.browser_port.load(Ordering::SeqCst);
    if p != 0 {
        return Ok(p);
    }
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("browser listener: {e}"))?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    if let Err(existing) = shared.browser_port.compare_exchange(0, port, Ordering::SeqCst, Ordering::SeqCst) {
        return Ok(existing);
    }
    let sh = shared.clone();
    std::thread::spawn(move || {
        for stream in l.incoming().flatten() {
            let sh = sh.clone();
            spawn_connection(sh, stream);
        }
    });
    shared.log(&format!("Browser listener started on 127.0.0.1:{port}"));
    Ok(port)
}

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
                // Non-blocking accept, so a restart (port change, restored
                // project) takes effect at once; a blocking accept only saw
                // the flag after the next client connected.
                let _ = l.set_nonblocking(true);
                loop {
                    if shared.listener_restart.load(Ordering::SeqCst) {
                        break;
                    }
                    match l.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let sh = shared.clone();
                            spawn_connection(sh, stream);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(50)),
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
                // Burp alerts on this; a silent failure leaves the user
                // browsing through nothing.
                crate::notice::toast(
                    crate::notice::Level::Error,
                    format!("Failed to start proxy service on {addr}. Check whether another service is already using this port. ({e})"),
                );
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

/// The extra listeners' configuration, for editing and re-applying with
/// `set_listeners`.
pub fn listener_specs(shared: &Arc<Shared>) -> Vec<ListenerSpec> {
    shared.listeners.lock().unwrap().iter().map(|l| ListenerSpec { http2: l.http2.load(Ordering::SeqCst), ..l.spec.clone() }).collect()
}

/// "Support HTTP/2" of the listener on `port`: an extra listener's own
/// option, else the primary listener's (also the embedded browser's).
pub fn listener_supports_http2(shared: &Shared, port: Option<u16>) -> bool {
    let extra = port.and_then(|p| shared.listeners.lock().unwrap().iter().find(|l| l.spec.port == p).map(|l| l.http2.load(Ordering::SeqCst)));
    extra.unwrap_or_else(|| shared.listener_http2.load(Ordering::SeqCst))
}

/// Set "Support HTTP/2" of the listener shown at `row` of the listener
/// table (0 = primary, 1.. = extra listeners).
pub fn set_listener_http2(shared: &Shared, row: usize, on: bool) {
    if row == 0 {
        shared.listener_http2.store(on, Ordering::SeqCst);
    } else if let Some(l) = shared.listeners.lock().unwrap().get(row - 1) {
        l.http2.store(on, Ordering::SeqCst);
    }
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
                            spawn_connection(sh, stream);
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
                crate::notice::toast(crate::notice::Level::Error, format!("Listener {addr} failed: {e}"));
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

/// Derived history fields (P-05), computed once at insert: (params, extension, title, cookies).
pub fn derive_history_fields(e: &HistEntry) -> (bool, String, String, String) {
    let parts = util::parse_http(&e.req_raw);
    let query = parts.path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let body = e.req_raw.get(parts.head_len..).unwrap_or(&[]);
    let ct = util::get_header(&parts.headers, "Content-Type").unwrap_or_default().to_ascii_lowercase();
    let body_params = ct.contains("application/x-www-form-urlencoded") && !body.is_empty();
    let params = !query.is_empty() || body_params || util::get_header(&parts.headers, "Cookie").is_some();

    let path = parts.path.split('?').next().unwrap_or("");
    // Proxied requests arrive in absolute form (http://host:port/path): the
    // extension comes from the last segment of the path only.
    let path = match path.split_once("://") {
        Some((_, rest)) => rest.find('/').map(|i| &rest[i..]).unwrap_or("/"),
        None => path,
    };
    let last = path.rsplit('/').next().unwrap_or("");
    let extension = last.rsplit_once('.').map(|(_, x)| x.to_ascii_lowercase()).unwrap_or_default();

    let mut title = String::new();
    let mut cookies = String::new();
    if let Some(resp) = &e.resp_raw {
        let rp = util::parse_http(resp);
        let ct = util::get_header(&rp.headers, "Content-Type").unwrap_or_default().to_ascii_lowercase();
        if ct.contains("html") {
            let body = String::from_utf8_lossy(resp.get(rp.head_len..).unwrap_or(&[]));
            // The closing tag is searched after the opening one, so the
            // range is never reversed ("</title>x<title>" has no title).
            if let Some(a) = body.find("<title") {
                if let Some(b) = body[a..].find("</title>").map(|b| a + b) {
                    let inner = &body[a..b];
                    if let Some(gt) = inner.find('>') {
                        title = inner[gt + 1..].trim().to_string();
                    }
                }
            }
        }
        let set = rp.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
            .map(|(_, v)| v.split(';').next().unwrap_or("").trim().to_string())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        cookies = set.join("; ");
    }
    (params, extension, title, cookies)
}

#[allow(clippy::too_many_arguments)]
fn record(shared: &Shared, req: &[u8], resp: Option<Vec<u8>>, note: Option<String>, default_port: u16, https: bool, listener_port: u16, edited: bool, ann: &crate::ext_host::Annotations) {
    // History shows the decoded message: chunked bodies reassembled and
    // content coding removed (MECHANICS.md A-01/A-02). The bytes forwarded to
    // the server or client are untouched.
    let resp = resp.map(|r| crate::body::Body::from(crate::codec::normalize_response(&r)));
    record_entry(shared, req, resp, note, default_port, https, listener_port, edited, ann, true);
}

/// Record one proxied exchange whose response is already in its history
/// form. `scan`: run the passive checks (not for a streaming response whose
/// body was not stored).
#[allow(clippy::too_many_arguments)]
fn record_entry(
    shared: &Shared,
    req: &[u8],
    resp: Option<crate::body::Body>,
    note: Option<String>,
    default_port: u16,
    https: bool,
    listener_port: u16,
    edited: bool,
    ann: &crate::ext_host::Annotations,
    scan: bool,
) {
    let req = crate::codec::normalize_request(req);
    let req = req.as_slice();
    let parts = util::parse_http(req);
    let (host, port) = host_of(&parts, default_port);
    // Proxied responses feed the session-handling cookie jar (Burp's default).
    if let Some(r) = &resp {
        let mut jar = shared.cookie_jar.lock().unwrap();
        if jar.updates_from("Proxy") {
            jar.update_from_response(&host, &path_of(&parts), r, util::now_secs());
        }
    }
    let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
    let status = resp
        .as_ref()
        .map(|r| util::parse_http(&r[..util::find_head_end(r).unwrap_or(r.len())]).status.clone())
        .unwrap_or_default();
    // Burp's history "Length" is the whole response, headers included
    // (live 2026.7.3: example.com shows 917 for a 513-byte body).
    let resp_len = resp.as_ref().map(|r| r.len()).unwrap_or(0);
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
        req_raw: req.to_vec().into(),
        resp_raw: resp,
        note,
        highlight: None,
        audited: false,
        params: false,
        edited,
        extension: String::new(),
        title: String::new(),
        cookies: String::new(),
        listener_port,
        ip: String::new(),
        diffs: 0,
    };
    let mut e = e;
    annotate(&mut e, ann);
    let derived = derive_history_fields(&e);
    e.params = derived.0;
    e.extension = derived.1;
    e.title = derived.2;
    e.cookies = derived.3;
    e.ip = resolve_ip(shared, &e.host);
    // Diff count vs the previous exchange of the same request location
    // ("Diff count" column, burp.Zxwu.java:56); the location drops the query,
    // the same way Logger groups repeated requests.
    let loc = format!(
        "{}|{}:{}{}",
        e.method,
        e.host,
        e.port,
        e.path.split('?').next().unwrap_or("")
    );
    e.diffs = shared.diff_tracker.lock().unwrap().diff(&loc, diff_attrs(&e));
    e.audited = shared.scan_enabled.load(Ordering::SeqCst) && e.path != "/favicon.ico";
    shared.push_history(e.clone());
    // Live passive crawl (Dashboard task 1): "Add links. Add item itself, same
    // domain and URLs in suite scope."
    if shared.crawl_capture.load(Ordering::SeqCst) {
        if let Some(resp) = &e.resp_raw {
            let origin = history_host(&e);
            let mut links = shared.site_links.lock().unwrap();
            for path in crate::scan::crawl_links(&origin, &e.path, resp) {
                links.insert((origin.clone(), path));
            }
        }
    }
    // live passive audit (AuditDefaults.json: scan_type_passive enabled),
    // bounded by the crawler's unique-location cap (CrawlDefaults.json: 1500)
    if scan && shared.scan_enabled.load(Ordering::SeqCst) && e.path != "/favicon.ico" {
        let loc = format!("{}:{}{}", e.host, e.port, e.path.split('?').next().unwrap_or(""));
        // Scope rules match full URLs ("https://host/..."): the location key
        // has no scheme, so with any include rule nothing was ever in scope.
        let within_scope = in_scope(shared, &(history_host(&e) + &e.path));
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
            let issues = crate::scan::passive_check_live(shared, &e);
            crate::scan::add_passive_issues(shared, issues);
        }
    }
}

/// `/show/<id>`: the stored response verbatim. `/repeat/<id>`: make the
/// browser issue the stored request (a redirect for GET, an auto-submitting
/// form otherwise).
pub fn browser_item_response(shared: &Shared, path: &str) -> Option<Vec<u8>> {
    let p = path.split('?').next().unwrap_or(path);
    let (kind, id) = if let Some(n) = p.strip_prefix("/show/") {
        ("show", n)
    } else if let Some(n) = p.strip_prefix("/repeat/") {
        ("repeat", n)
    } else {
        return None;
    };
    let id: u64 = id.trim_end_matches('/').parse().ok()?;
    let e = shared.history.get(id)?;
    if kind == "show" {
        let resp = e.resp_raw.clone()?;
        return Some(String::from_utf8_lossy(&set_connection(&resp, "close")).into_owned().into_bytes());
    }
    let scheme = if e.https { "https" } else { "http" };
    let default = if e.https { 443 } else { 80 };
    let origin = if e.port == default { format!("{scheme}://{}", e.host) } else { format!("{scheme}://{}:{}", e.host, e.port) };
    let req_path = String::from_utf8_lossy(&util::origin_form(&e.req_raw)).split_whitespace().nth(1).unwrap_or("/").to_string();
    let url = format!("{origin}{req_path}");
    if e.method.eq_ignore_ascii_case("GET") {
        return Some(format!("HTTP/1.1 302 Found\r\nLocation: {url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes());
    }
    let parts = util::parse_http(&e.req_raw);
    let body = String::from_utf8_lossy(&e.req_raw[parts.head_len.min(e.req_raw.len())..]).into_owned();
    let esc = |v: &str| v.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;");
    let mut inputs = String::new();
    for kv in body.split('&').filter(|x| !x.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        inputs.push_str(&format!("<input type=\"hidden\" name=\"{}\" value=\"{}\">", esc(&util::url_decode(k)), esc(&util::url_decode(v))));
    }
    let html = format!("<html><body><form method=\"{}\" action=\"{}\">{inputs}</form><script>document.forms[0].submit()</script></body></html>", esc(&e.method), esc(&url));
    Some(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}", html.len()).into_bytes())
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

/// Largest frame payload the relay buffers to parse, record and intercept.
/// Bigger frames are relayed raw (Burp also refuses to hold huge messages).
const MAX_WS_FRAME: usize = 16 * 1024 * 1024;

/// Header of one frame: (first byte, masked, payload offset incl. mask,
/// declared payload length). None when the header is incomplete.
fn ws_frame_header(buf: &[u8]) -> Option<(u8, bool, usize, usize)> {
    if buf.len() < 2 {
        return None;
    }
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
        len = usize::try_from(u64::from_be_bytes(wide)).unwrap_or(usize::MAX);
        offset += 8;
    }
    if masked {
        offset += 4;
    }
    Some((buf[0], masked, offset, len))
}

/// Parse one complete frame: (opcode, masked, payload, bytes consumed).
/// Text/binary payloads are unmasked; None when more bytes are needed.
pub(crate) fn parse_ws_frame(buf: &[u8]) -> Option<(u8, bool, Vec<u8>, usize)> {
    let (first, masked, start, len) = ws_frame_header(buf)?;
    let opcode = first & 0x0f;
    if len > MAX_WS_FRAME {
        return Some((opcode, masked, Vec::new(), buf.len()));
    }
    if buf.len() < start + len {
        return None;
    }
    let mut payload = buf[start..start + len].to_vec();
    if masked {
        let mask = [buf[start - 4], buf[start - 3], buf[start - 2], buf[start - 1]];
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Some((opcode, masked, payload, start + len))
}

/// Rebuild a WebSocket frame around a (possibly edited) payload. `first` is
/// the original first byte (FIN, RSV bits and opcode), so a final frame stays
/// final. Client frames must stay masked (the server requires it); server
/// frames are unmasked.
pub(crate) fn build_ws_frame(first: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    let mask_bit = if masked { 0x80u8 } else { 0 };
    let len = payload.len();
    let mut out = vec![first];
    if len > 65_535 {
        out.push(127 | mask_bit);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    } else if len > 125 {
        out.push(126 | mask_bit);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push((len as u8) | mask_bit);
    }
    if masked {
        // RFC 6455 5.3: a fresh, unpredictable key per frame.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        let mut x = nanos ^ (len as u64).rotate_left(17) ^ 0x2545_F491_4F6C_DD1D;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let mask = (x as u32).to_be_bytes();
        out.extend_from_slice(&mask);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/// Largest WebSocket message (all its fragments) the relay assembles;
/// a bigger one closes the connection with 1009 (Message Too Big).
pub(crate) const MAX_WS_MESSAGE: usize = MAX_WS_FRAME;

/// A message being assembled from its fragments.
struct WsPartial {
    /// First frame's first byte (opcode, RSV1 for permessage-deflate).
    first: u8,
    payload: Vec<u8>,
    /// The frames as received, forwarded unchanged when nothing changed.
    raw: Vec<u8>,
}

/// One direction of a relayed WebSocket: bytes of an incomplete frame, the
/// message being assembled, and the connection's extensions.
#[derive(Default)]
pub(crate) struct WsStream {
    buf: Vec<u8>,
    /// Extensions whose handlers watch this socket.
    watch: Option<Arc<WsWatch>>,
    /// The connection (for history rows).
    socket: u64,
    partial: Option<WsPartial>,
    /// permessage-deflate negotiated: this direction's inflater, and
    /// whether the sender resets its context per message.
    inflate: Option<(flate2::Decompress, bool)>,
    /// A close (1009 or protocol error) was sent: drop everything after.
    closed: bool,
}

impl WsStream {
    #[cfg(test)]
    pub(crate) fn watched(watch: &Option<Arc<WsWatch>>) -> Self {
        WsStream { watch: watch.clone(), ..Default::default() }
    }

    /// One direction of connection `socket`; `deflate` = Some(no context
    /// takeover for this sender) when permessage-deflate was negotiated.
    pub(crate) fn new(watch: &Option<Arc<WsWatch>>, socket: u64, deflate: Option<bool>) -> Self {
        WsStream { watch: watch.clone(), socket, inflate: deflate.map(|nct| (flate2::Decompress::new(false), nct)), ..Default::default() }
    }
}

/// What a chunk of WebSocket bytes produced: bytes for the destination,
/// bytes back to the sender (a close the proxy sends), and whether the
/// connection is over.
#[derive(Default, Debug)]
pub(crate) struct WsOut {
    pub(crate) forward: Vec<u8>,
    pub(crate) back: Vec<u8>,
    pub(crate) closed: bool,
}

/// The largest WebSocket message the proxy and Repeater assemble.
pub const WS_MAX_MESSAGE: usize = MAX_WS_MESSAGE;

/// One WebSocket frame around `payload` (`first`: FIN, RSV and opcode).
pub fn ws_frame(first: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    build_ws_frame(first, payload, masked)
}

/// The first complete frame of `buf`: (first byte, unmasked payload, bytes
/// used). None while incomplete; a frame over the limit comes back with an
/// empty payload.
pub fn ws_parse_frame(buf: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
    let (_, _, payload, used) = parse_ws_frame(buf)?;
    Some((buf[0], payload, used))
}

/// A close frame with `code` and `reason`, masked when a client sends it.
pub fn ws_close_frame(code: u16, reason: &str, masked: bool) -> Vec<u8> {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(reason.as_bytes());
    build_ws_frame(0x88, &p, masked)
}

/// The permessage-deflate parameters a 101 response agreed to:
/// (client no context takeover, server no context takeover).
pub(crate) fn ws_deflate_agreed(response: &[u8]) -> Option<(bool, bool)> {
    let parts = util::parse_http(response);
    let ext = parts.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("Sec-WebSocket-Extensions")).map(|(_, v)| v.clone()).collect::<Vec<_>>().join(",");
    ext.split(',').find_map(|e| {
        let mut params = e.split(';').map(|p| p.trim().to_ascii_lowercase());
        (params.next()? == "permessage-deflate").then(|| {
            let rest: Vec<String> = params.collect();
            (rest.iter().any(|p| p == "client_no_context_takeover"), rest.iter().any(|p| p == "server_no_context_takeover"))
        })
    })
}

/// Burp's "Strip Sec-WebSocket-Extensions headers in incoming requests"
/// (proxy.miscellaneous, default on): with the header gone no extension
/// (permessage-deflate) is negotiated, so both peers see plain frames.
pub(crate) fn ws_strip_extensions(req: &[u8]) -> Vec<u8> {
    let Some(end) = util::find_head_end(req) else { return req.to_vec() };
    let head = String::from_utf8_lossy(&req[..end]);
    let mut out = String::new();
    for line in head.split("\r\n") {
        if line.to_ascii_lowercase().starts_with("sec-websocket-extensions:") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    // `head` ended with its blank line: one CRLF pair too many now.
    while out.ends_with("\r\n\r\n\r\n") {
        out.pop();
        out.pop();
    }
    let mut v = out.into_bytes();
    v.extend_from_slice(&req[end..]);
    v
}

/// Inflate one permessage-deflate message (RFC 7692 §7.2.2), bounded by
/// [`MAX_WS_MESSAGE`]. None when the data is not valid or too big.
fn ws_inflate(z: &mut flate2::Decompress, reset: bool, data: &[u8]) -> Option<Vec<u8>> {
    if reset {
        z.reset(false);
    }
    let mut input = data.to_vec();
    input.extend_from_slice(&[0, 0, 0xff, 0xff]);
    let mut out: Vec<u8> = Vec::new();
    let mut at = 0;
    loop {
        if out.capacity() - out.len() < 32 * 1024 {
            out.reserve(64 * 1024);
        }
        let (in0, out0) = (z.total_in(), z.total_out());
        let status = z.decompress_vec(&input[at..], &mut out, flate2::FlushDecompress::Sync).ok()?;
        at += (z.total_in() - in0) as usize;
        if out.len() > MAX_WS_MESSAGE {
            return None;
        }
        if at >= input.len() || status == flate2::Status::StreamEnd {
            return Some(out);
        }
        if z.total_in() == in0 && z.total_out() == out0 && out.capacity() > out.len() {
            return None;
        }
    }
}

/// The extensions watching one proxied WebSocket (Montoya proxy WebSocket
/// creation and message handlers). Dropping the last reference (both
/// directions closed) tells them the socket closed.
pub(crate) struct WsWatch {
    socket: u64,
    hooks: Vec<Arc<dyn crate::ext_host::ProxyHooks>>,
}

impl WsWatch {
    pub(crate) fn open(shared: &Shared, host: &str, port: u16, secure: bool, upgrade: &[u8]) -> Option<Arc<WsWatch>> {
        let exts = shared.ext_host.lock().unwrap().active();
        if exts.is_empty() {
            return None;
        }
        let socket = shared.next_id.fetch_add(1, Ordering::SeqCst);
        let svc = crate::ext_host::HttpService::new(host, port, secure);
        let hooks: Vec<_> = exts.into_iter().filter(|e| e.ws_open(socket, &svc, upgrade)).collect();
        (!hooks.is_empty()).then(|| Arc::new(WsWatch { socket, hooks }))
    }

    /// Run one data message through every watching extension; the first
    /// drop wins, the last intercept verdict counts.
    fn message(&self, stage: crate::ext_host::WsStage, to_server: bool, binary: bool, payload: &mut Vec<u8>) -> crate::ext_host::WsVerdict {
        use crate::ext_host::WsVerdict;
        let mut verdict = WsVerdict::Continue;
        for h in &self.hooks {
            match h.ws_message(self.socket, stage, to_server, binary, payload) {
                WsVerdict::Drop => return WsVerdict::Drop,
                WsVerdict::Continue => {}
                v => verdict = v,
            }
        }
        verdict
    }
}

impl Drop for WsWatch {
    fn drop(&mut self) {
        for h in &self.hooks {
            h.ws_close(self.socket);
        }
    }
}

/// Burp holds a WebSocket message when Intercept is on and the direction is
/// enabled in Proxy settings > WebSocket interception rules.
fn ws_should_hold(shared: &Shared, client_to_server: bool) -> bool {
    shared.intercept_on.load(Ordering::SeqCst)
        && if client_to_server {
            shared.ws_intercept_client.load(Ordering::SeqCst)
        } else {
            shared.ws_intercept_server.load(Ordering::SeqCst)
        }
}

/// Relay one chunk of a WebSocket stream in one direction (bytes for the
/// destination only; see [`ws_relay_chunk`]).
#[cfg(test)]
pub(crate) fn intercept_ws_stream(shared: &Shared, host: &str, chunk: &[u8], st: &mut WsStream, client_to_server: bool) -> Vec<u8> {
    ws_relay_chunk(shared, host, chunk, st, client_to_server).forward
}

/// Relay one chunk of a WebSocket stream in one direction. Frames are
/// parsed as they complete; data messages are assembled from their
/// fragments (control frames in between pass at once), inflated when
/// permessage-deflate is on, and then go through extension handlers,
/// WebSocket match and replace, interception and history as one message.
/// An unchanged message is forwarded as its original frames, byte for
/// byte; a changed one as a single frame. A frame or message over
/// [`MAX_WS_MESSAGE`] closes both sides with 1009; a fragment out of place
/// with 1002.
#[cfg(test)]
pub(crate) fn ws_relay_chunk(shared: &Shared, host: &str, chunk: &[u8], st: &mut WsStream, client_to_server: bool) -> WsOut {
    ws_relay_chunk_alive(shared, host, chunk, st, client_to_server, &|| true)
}

/// [`ws_relay_chunk`] where a held message is let go when `alive` says
/// either side of the connection closed.
pub(crate) fn ws_relay_chunk_alive(shared: &Shared, host: &str, chunk: &[u8], st: &mut WsStream, client_to_server: bool, alive: &dyn Fn() -> bool) -> WsOut {
    let mut out = WsOut::default();
    if st.closed {
        out.closed = true;
        return out;
    }
    let direction = if client_to_server { "client -> server" } else { "server -> client" };
    st.buf.extend_from_slice(chunk);
    let fail = |st: &mut WsStream, out: &mut WsOut, code: u16, why: &str| {
        shared.log(&format!("WebSocket to {host} closed by the proxy ({code}): {why}"));
        // Destination and sender both get a close; masking follows the
        // direction each frame travels.
        out.forward.extend(ws_close_frame(code, why, client_to_server));
        out.back.extend(ws_close_frame(code, why, !client_to_server));
        out.closed = true;
        st.closed = true;
        st.buf.clear();
        st.partial = None;
    };
    while let Some((first, masked, start, len)) = ws_frame_header(&st.buf) {
        let opcode = first & 0x0f;
        let control = opcode >= 0x8;
        if first & 0x30 != 0
            || (control && (first & 0x70 != 0 || first & 0x80 == 0 || len > 125))
            || matches!(opcode, 0x3..=0x7 | 0xb..=0xf)
            || masked != client_to_server
        {
            fail(st, &mut out, 1002, "invalid WebSocket frame");
            return out;
        }
        if len > MAX_WS_MESSAGE {
            fail(st, &mut out, 1009, "frame too big");
            return out;
        }
        if st.buf.len() < start + len {
            break;
        }
        let raw: Vec<u8> = st.buf.drain(..start + len).collect();
        let Some((_, _, payload, _)) = parse_ws_frame(&raw) else { break };
        let opcode = first & 0x0f;
        let fin = first & 0x80 != 0;
        if opcode >= 0x8 {
            // Control frames (close, ping, pong) pass at once, also between
            // the fragments of a message, and are recorded.
            ws_record(shared, host, st.socket, direction, ws_opcode_name(opcode), &payload);
            out.forward.extend_from_slice(&raw);
            continue;
        }
        match (opcode, st.partial.as_mut()) {
            (0, Some(p)) => {
                if p.payload.len() + payload.len() > MAX_WS_MESSAGE {
                    fail(st, &mut out, 1009, "message too big");
                    return out;
                }
                p.payload.extend_from_slice(&payload);
                p.raw.extend_from_slice(&raw);
            }
            (1 | 2, None) => st.partial = Some(WsPartial { first, payload, raw }),
            (0, None) => {
                fail(st, &mut out, 1002, "continuation frame without a message");
                return out;
            }
            (1 | 2, Some(_)) => {
                fail(st, &mut out, 1002, "new message before the last one ended");
                return out;
            }
            _ => {
                // Reserved opcodes: relayed untouched, as received.
                ws_record(shared, host, st.socket, direction, ws_opcode_name(opcode), &payload);
                out.forward.extend_from_slice(&raw);
                continue;
            }
        }
        if !fin {
            continue;
        }
        let Some(msg) = st.partial.take() else { continue };
        match ws_message(shared, host, st, msg, client_to_server, alive) {
            Ok(bytes) => out.forward.extend(bytes),
            Err((code, why)) => {
                fail(st, &mut out, code, &why);
                return out;
            }
        }
    }
    out
}

fn ws_record(shared: &Shared, host: &str, socket: u64, direction: &str, opcode: &str, payload: &[u8]) -> u64 {
    push_ws_in(shared, socket, host, direction, opcode, payload)
}

/// One complete data message: inflate, extension handlers, match and
/// replace, interception, history; the bytes to forward (empty when it was
/// dropped).
fn ws_message(shared: &Shared, host: &str, st: &mut WsStream, msg: WsPartial, client_to_server: bool, alive: &dyn Fn() -> bool) -> Result<Vec<u8>, (u16, String)> {
    let direction = if client_to_server { "client -> server" } else { "server -> client" };
    let opcode = msg.first & 0x0f;
    let binary = opcode == 0x2;
    let compressed = msg.first & 0x40 != 0;
    let mut payload = msg.payload;
    // permessage-deflate: shown and edited inflated, forwarded plain (RSV1
    // clear), so the receiver's inflate context is never involved.
    let mut changed = false;
    if compressed {
        let Some((z, reset)) = st.inflate.as_mut() else {
            return Err((1002, "compressed message without permessage-deflate".into()));
        };
        payload = ws_inflate(z, *reset, &payload).ok_or((1009, "compressed message invalid or too big".to_string()))?;
        changed = true;
    }
    let mut hold = ws_should_hold(shared, client_to_server) && (!shared.ws_intercept_in_scope.load(Ordering::SeqCst) || ws_in_scope(shared, host));
    let watch = st.watch.clone();
    if let Some(w) = &watch {
        let before = payload.clone();
        match w.message(crate::ext_host::WsStage::Received, client_to_server, binary, &mut payload) {
            crate::ext_host::WsVerdict::Drop => {
                shared.log(&format!("An extension dropped a WebSocket message ({direction}, {host})"));
                return Ok(Vec::new());
            }
            crate::ext_host::WsVerdict::Intercept => hold = true,
            crate::ext_host::WsVerdict::DoNotIntercept => hold = false,
            crate::ext_host::WsVerdict::Continue => {}
        }
        changed |= payload != before;
    }
    // WebSocket match and replace (Proxy settings), before interception as
    // for HTTP messages.
    if !shared.ws_rules_in_scope_only.load(Ordering::SeqCst) || ws_in_scope(shared, host) {
        if let Some(new) = crate::ws_rules::apply(&shared.ws_rules.lock().unwrap(), client_to_server, binary, &payload) {
            payload = new;
            changed = true;
        }
    }
    if hold {
        let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel::<Option<String>>();
        shared.queue.lock().unwrap().push(InterceptItem::new(id, host, 0, String::from_utf8_lossy(&payload).into_owned(), tx, InterceptKind::WebSocket { to_server: client_to_server }));
        shared.wake();
        shared.log(&format!("Intercepted WebSocket message queued (id {id})"));
        match intercept_wait(shared, id, &rx, alive) {
            // Binary payloads shown lossily stay untouched unless the user
            // really changed the text.
            Some(edited) if edited.as_bytes() != String::from_utf8_lossy(&payload).as_bytes() => {
                payload = edited.into_bytes();
                changed = true;
            }
            Some(_) => {}
            _ => {
                shared.log(&format!("Intercepted WebSocket message dropped (id {id})"));
                return Ok(Vec::new());
            }
        }
    }
    if let Some(w) = &watch {
        let before = payload.clone();
        if w.message(crate::ext_host::WsStage::ToBeSent, client_to_server, binary, &mut payload) == crate::ext_host::WsVerdict::Drop {
            shared.log(&format!("An extension dropped a WebSocket message ({direction}, {host})"));
            return Ok(Vec::new());
        }
        changed |= payload != before;
    }
    let hid = ws_record(shared, host, st.socket, direction, ws_opcode_name(opcode), &payload);
    if !changed {
        return Ok(msg.raw);
    }
    shared.ws_edited.lock().unwrap().insert(hid);
    // One final frame, RSV bits clear, masked when it goes to the server.
    Ok(build_ws_frame(0x80 | opcode, &payload, client_to_server))
}

/// Whether a WebSocket host is in the Target scope (either scheme).
fn ws_in_scope(shared: &Shared, host: &str) -> bool {
    in_scope(shared, &format!("http://{host}/")) || in_scope(shared, &format!("https://{host}/"))
}

/// One upgraded WebSocket connection: its id (history rows), the
/// extensions watching it, permessage-deflate if it was agreed (client no
/// context takeover, server no context takeover), and the frames Repeater
/// injects into it (to the server: true).
pub(crate) struct WsSetup {
    pub(crate) watch: Option<Arc<WsWatch>>,
    pub(crate) socket: u64,
    pub(crate) deflate: Option<(bool, bool)>,
    pub(crate) inject: Option<mpsc::Receiver<(bool, Vec<u8>)>>,
}

impl WsSetup {
    fn streams(&self) -> (WsStream, WsStream) {
        (WsStream::new(&self.watch, self.socket, self.deflate.map(|d| d.0)), WsStream::new(&self.watch, self.socket, self.deflate.map(|d| d.1)))
    }
}

/// A live proxied WebSocket that WebSocket Repeater can attach to.
#[derive(Clone)]
pub struct LiveWs {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// The upgrade request as sent upstream.
    pub handshake: Vec<u8>,
    /// Frames to write: (to the server, the whole frame).
    pub inject: mpsc::Sender<(bool, Vec<u8>)>,
}

/// The handshake is done: what the relay needs. The connection is listed
/// in `Shared::ws_live` until the relay ends.
fn ws_setup(shared: &Shared, socket: u64, host: &str, port: u16, secure: bool, req_out: &[u8], response: &[u8]) -> WsSetup {
    let (tx, rx) = mpsc::channel();
    shared.ws_live.lock().unwrap().insert(socket, LiveWs { host: host.to_string(), port, tls: secure, handshake: req_out.to_vec(), inject: tx });
    WsSetup { watch: WsWatch::open(shared, host, port, secure, req_out), socket, deflate: ws_deflate_agreed(response), inject: Some(rx) }
}

/// Capture and relay a plain-HTTP WebSocket upgrade; frames are recorded and
/// held by `intercept_ws_stream` (the TLS path is `handle_tls_websocket`).
fn handle_websocket(shared: Arc<Shared>, mut client: TcpStream, req: Vec<u8>) {
    let parts = util::parse_http(&req);
    let (host, port) = host_of(&parts, 80);
    let req_session = apply_session_rules(&shared, &req, 80);
    let mut req_out = crate::rules::apply_rules(&req_session, &shared.mr_request.lock().unwrap());
    if shared.ws_strip_extensions.load(Ordering::SeqCst) {
        req_out = ws_strip_extensions(&req_out);
    }
    if !shared.ext_handle_request(&crate::ext_host::HttpService::new(&host, port, false), &parts.method, &path_of(&parts), &mut req_out, &mut Default::default()) {
        shared.log("WebSocket handshake dropped by an extension hook");
        return;
    }
    let config = shared.upstream_for(&host);
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
    let socket = shared.next_id.fetch_add(1, Ordering::SeqCst);
    push_ws_in(&shared, socket, &host, "handshake", "request", &req_out);
    push_ws_in(&shared, socket, &host, "handshake", "response", &response);
    record(&shared, &req_out, Some(response.clone()), None, 80, false, listener_port(&shared), false, &Default::default());
    if util::parse_http(&response).status != "101" {
        shared.log(&format!("WebSocket upgrade for {host}:{port} was not accepted"));
        return;
    }
    shared.log(&format!("WebSocket upgraded for {host}:{port}; capturing frames"));
    let setup = ws_setup(&shared, socket, &host, port, false, &req_out, &response);
    let (mut client, mut upstream) = (client, upstream);
    relay_ws_tls(&shared, &mut client, &mut upstream, host, setup);
}

fn write_nonblocking<W: Write>(stream: &mut W, mut bytes: &[u8]) -> std::io::Result<()> {
    // A peer that stops reading ends the relay after the normal timeout.
    let deadline = std::time::Instant::now() + Duration::from_millis(READ_TIMEOUT_MS);
    while !bytes.is_empty() {
        match stream.write(bytes) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "socket write returned zero")),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() > deadline {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "the peer stopped reading"));
                }
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn relay_ws_tls<C: ProxyIo, U: ProxyIo>(shared: &Shared, client: &mut C, upstream: &mut U, host: String, setup: WsSetup) {
    let _ = client.set_nonblocking_io(true);
    let _ = upstream.set_nonblocking_io(true);
    let mut client_open = true;
    let mut upstream_open = true;
    let (mut client_pending, mut upstream_pending) = setup.streams();
    let (socket, inject) = (setup.socket, setup.inject);
    drop(setup.watch);
    let mut chunk = [0u8; 16384];
    while client_open || upstream_open {
        let mut progressed = false;
        // Messages WebSocket Repeater sends over this connection.
        if let Some(rx) = &inject {
            while let Ok((to_server, frame)) = rx.try_recv() {
                progressed = true;
                let sent = if to_server { write_nonblocking(upstream, &frame) } else { write_nonblocking(client, &frame) };
                if sent.is_err() {
                    break;
                }
            }
        }
        if client_open {
            match client.read(&mut chunk) {
                Ok(0) => client_open = false,
                Ok(n) => {
                    progressed = true;
                    let alive = || !client.peer_closed() && !upstream.peer_closed();
                    let out = ws_relay_chunk_alive(shared, &host, &chunk[..n], &mut client_pending, true, &alive);
                    if !out.forward.is_empty() && write_nonblocking(upstream, &out.forward).is_err() {
                        break;
                    }
                    if !out.back.is_empty() {
                        let _ = write_nonblocking(client, &out.back);
                    }
                    if out.closed {
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
                    let alive = || !client.peer_closed() && !upstream.peer_closed();
                    let out = ws_relay_chunk_alive(shared, &host, &chunk[..n], &mut upstream_pending, false, &alive);
                    if !out.forward.is_empty() && write_nonblocking(client, &out.forward).is_err() {
                        break;
                    }
                    if !out.back.is_empty() {
                        let _ = write_nonblocking(upstream, &out.back);
                    }
                    if out.closed {
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
    shared.ws_live.lock().unwrap().remove(&socket);
}

fn handle_tls_websocket(
    shared: Arc<Shared>,
    mut client: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    req: Vec<u8>,
    host: String,
    port: u16,
) {
    let parts = util::parse_http(&req);
    let req_session = apply_session_rules(&shared, &req, 443);
    let mut req_out = crate::rules::apply_rules(&req_session, &shared.mr_request.lock().unwrap());
    if shared.ws_strip_extensions.load(Ordering::SeqCst) {
        req_out = ws_strip_extensions(&req_out);
    }
    if !shared.ext_handle_request(&crate::ext_host::HttpService::new(&host, port, true), &parts.method, &path_of(&parts), &mut req_out, &mut Default::default()) {
        shared.log("TLS WebSocket handshake dropped by an extension hook");
        return;
    }
    let config = shared.upstream_for(&host);
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
    let socket = shared.next_id.fetch_add(1, Ordering::SeqCst);
    push_ws_in(&shared, socket, &host, "handshake", "request", &req_out);
    push_ws_in(&shared, socket, &host, "handshake", "response", &response);
    record(&shared, &req_out, Some(response.clone()), None, 443, true, listener_port(&shared), false, &Default::default());
    if util::parse_http(&response).status != "101" {
        return;
    }
    shared.log(&format!("TLS WebSocket upgraded for {host}:{port}; capturing frames"));
    let setup = ws_setup(&shared, socket, &host, port, true, &req_out, &response);
    relay_ws_tls(&shared, &mut client, &mut upstream, host, setup);
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
    let base = tls_client_config_base(shared, host);
    // A sender that chose the protocol (Repeater) offers only that one.
    match H2_CHOICE.with(|c| c.get()).and_then(|c| c.want_h2) {
        Some(h2) => {
            let mut c = (*base).clone();
            c.alpn_protocols = vec![if h2 { b"h2".to_vec() } else { b"http/1.1".to_vec() }];
            Arc::new(c)
        }
        None => base,
    }
}

fn tls_client_config_base(shared: &Shared, host: &str) -> std::sync::Arc<rustls::ClientConfig> {
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

/// A WebSocket Repeater connection of its own (plain or TLS).
pub enum WsClientConn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for WsClientConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WsClientConn::Plain(s) => s.read(buf),
            WsClientConn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for WsClientConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WsClientConn::Plain(s) => s.write(buf),
            WsClientConn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WsClientConn::Plain(s) => s.flush(),
            WsClientConn::Tls(s) => s.flush(),
        }
    }
}

impl WsClientConn {
    pub fn set_nonblocking(&self, on: bool) -> std::io::Result<()> {
        match self {
            WsClientConn::Plain(s) => s.set_nonblocking(on),
            WsClientConn::Tls(s) => s.get_ref().set_nonblocking(on),
        }
    }

    /// Write all of `bytes` on a non-blocking connection (bounded wait).
    pub fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        write_nonblocking(self, bytes)
    }
}

/// Open a WebSocket for WebSocket Repeater: connect (through the upstream
/// proxy settings, TLS offering HTTP/1.1 only), send the upgrade request as
/// written, and read the response head. Ok only for 101; the connection is
/// returned blocking.
pub fn ws_client_connect(shared: &Shared, host: &str, port: u16, tls: bool, handshake: &[u8]) -> Result<(WsClientConn, Vec<u8>), String> {
    let config = shared.upstream_for(host);
    let mut conn = if tls {
        let tcp = crate::upstream::connect_tls_target(&config, host, port)?;
        tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS))).ok();
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| format!("invalid TLS name {host}: {e}"))?;
        let mut cfg = (*tls_client_config_base(shared, host)).clone();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let c = rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|e| format!("configure TLS: {e}"))?;
        WsClientConn::Tls(Box::new(rustls::StreamOwned::new(c, tcp)))
    } else {
        let tcp = crate::upstream::connect_target(&config, host, port)?;
        tcp.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS))).ok();
        WsClientConn::Plain(tcp)
    };
    let req = if tls { util::origin_form(handshake) } else { crate::upstream::absolute_form_request(&config, &util::origin_form(handshake), host, port) };
    conn.write_all(&req).map_err(|e| format!("write: {e}"))?;
    conn.flush().ok();
    let resp = read_response_head(&mut conn).map_err(|e| format!("read: {e}"))?;
    let status = util::parse_http(&resp).status;
    if status != "101" {
        return Err(format!("the server answered {status}, not 101 Switching Protocols"));
    }
    Ok((conn, resp))
}

/// Most client connections handled at once, across all listeners. Each one
/// is a thread; beyond this a flood (or a runaway client) would exhaust
/// threads and memory, so further connections get a 503 and are closed.
pub const MAX_CONNECTIONS: usize = 1024;

/// Handle a client connection on its own thread, within [`MAX_CONNECTIONS`].
fn spawn_connection(shared: Arc<Shared>, mut stream: TcpStream) {
    let admitted = stream_limit_check(&shared, &mut stream, MAX_CONNECTIONS);
    spawn_connection_limited(shared, admitted, stream);
}

/// Reserve a connection slot; on refusal answer 503 and say so.
fn stream_limit_check(shared: &Shared, stream: &mut TcpStream, limit: usize) -> bool {
    let taken = shared.active_connections.fetch_add(1, Ordering::SeqCst);
    if taken >= limit {
        shared.active_connections.fetch_sub(1, Ordering::SeqCst);
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: 39\r\n\r\nWebProbe: too many connections at once");
        return false;
    }
    true
}

fn spawn_connection_limited(shared: Arc<Shared>, admitted: bool, stream: TcpStream) {
    if !admitted {
        shared.log(&format!("Refused a connection: {MAX_CONNECTIONS} already open"));
        return;
    }
    struct Slot(Arc<Shared>);
    impl Drop for Slot {
        fn drop(&mut self) {
            self.0.active_connections.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let counter = shared.clone();
    let spawned = std::thread::Builder::new().name("proxy-conn".into()).spawn(move || {
        let _slot = Slot(shared.clone());
        handle_conn(shared, stream);
    });
    if spawned.is_err() {
        // The closure (and its slot) was never run.
        counter.active_connections.fetch_sub(1, Ordering::SeqCst);
    }
}

thread_local! {
    /// Port of the listener the connection on this thread arrived on.
    static LISTENER_PORT: std::cell::Cell<Option<u16>> = const { std::cell::Cell::new(None) };
}

/// The upstream target for a request on this connection: the listener's
/// redirect when one is set, otherwise the host the request names.
/// The listener port of this thread's connection (history "Listener port"),
/// the main listener when the thread is not serving one.
fn listener_port(shared: &Shared) -> u16 {
    LISTENER_PORT.with(|p| p.get()).unwrap_or_else(|| shared.proxy_port.load(Ordering::SeqCst))
}

fn upstream_target(shared: &Shared, host: &str, port: u16) -> (String, u16) {
    LISTENER_PORT
        .with(|p| p.get())
        .and_then(|lp| shared.listener_redirects.lock().unwrap().get(&lp).cloned())
        .unwrap_or_else(|| (host.to_string(), port))
}

fn handle_conn(shared: Arc<Shared>, mut stream: TcpStream) {
    LISTENER_PORT.with(|p| p.set(stream.local_addr().ok().map(|a| a.port())));
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

    let (req, req_state) = intercept_request(&shared, req, 80);
    let Some(req) = req else { return };
    let is_ws = util::get_header(&parts.headers, "Upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if is_ws {
        handle_websocket(shared, stream, req);
        return;
    }
    upstream_and_deliver(&shared, &mut stream, req, 80, false, req_state);
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
        let config = shared.upstream_for(&host);
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
    let config = match shared.mitm.listener_config(&host, listener_supports_http2(&shared, LISTENER_PORT.with(|p| p.get()))) {
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
    // The client chose HTTP/2 by ALPN: serve the connection's streams.
    let _ = tls.conn.complete_io(&mut tls.sock);
    if tls.conn.alpn_protocol() == Some(b"h2".as_slice()) {
        serve_h2_client(shared, tls, host, port);
        return;
    }
    let req = match read_request(&mut tls) {
        Ok(req) if !req.is_empty() => req,
        Ok(_) => return,
        Err(e) => {
            shared.log(&format!("HTTPS client handshake/request for {host}:{port} failed: {e}"));
            return;
        }
    };
    let (req, req_state) = intercept_request(&shared, req, 443);
    let Some(req) = req else { return };
    let ws_parts = util::parse_http(&req);
    let is_ws = util::get_header(&ws_parts.headers, "Upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if is_ws {
        handle_tls_websocket(shared, tls, req, host, port);
        return;
    }
    upstream_and_deliver(&shared, &mut tls, req, 443, true, req_state);
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// An HTTPS client that negotiated h2: every stream runs the proxy's
/// per-request pipeline (intercept, match and replace, extensions,
/// history, streaming) on its own thread; `h2_server` frames the results.
fn serve_h2_client(shared: Arc<Shared>, mut tls: rustls::StreamOwned<rustls::ServerConnection, TcpStream>, host: String, port: u16) {
    if tls.get_ref().set_nonblocking(true).is_err() {
        return;
    }
    shared.log(&format!("HTTP/2 client connection for {host}:{port}"));
    let listener = LISTENER_PORT.with(|p| p.get());
    let pipeline_shared = Arc::clone(&shared);
    let handler: crate::h2_server::Handler = Arc::new(move |req: Vec<u8>, mut out: crate::h2_server::ResponseWriter| {
        LISTENER_PORT.with(|p| p.set(listener));
        let (req, state) = intercept_request(&pipeline_shared, req, 443);
        let Some(req) = req else { return };
        upstream_and_deliver(&pipeline_shared, &mut out, req, 443, true, state);
    });
    crate::h2_server::serve(&mut tls, handler);
    tls.conn.send_close_notify();
    let _ = tls.get_ref().set_nonblocking(false);
    let _ = tls.flush();
}

impl ProxyIo for crate::h2_server::ResponseWriter {
    fn set_nonblocking_io(&self, _: bool) -> std::io::Result<()> {
        Ok(())
    }
}

/// What Forward sends for a held message: the original bytes when the text
/// is unchanged from what was shown (a binary body survives exactly, its
/// lossy text view would replace bytes with U+FFFD), else the edited text.
/// Returns the bytes and whether the user changed the message.
fn forwarded(original: Vec<u8>, shown: &str, edited: String) -> (Vec<u8>, bool) {
    if edited == shown {
        (original, false)
    } else {
        (edited.into_bytes(), true)
    }
}

fn intercept_request(shared: &Shared, req: Vec<u8>, default_port: u16) -> (Option<Vec<u8>>, ReqState) {
    if !shared.intercept_on.load(Ordering::SeqCst) {
        return (Some(req), ReqState::default());
    }
    let parts = util::parse_http(&req);
    let (host, port) = host_of(&parts, default_port);
    {
        let head = parts.head_len.min(req.len());
        let url = history_host(&HistEntry { host: host.clone(), port, https: default_port == 443, ..Default::default() }) + &path_of(&parts);
        let facts = crate::intercept_rules::Facts {
            in_scope: in_scope(shared, &url),
            domain: host.clone(),
            method: parts.method.clone(),
            extension: crate::intercept_rules::extension_of(&parts.path),
            headers: String::from_utf8_lossy(&req[..head]).into_owned(),
            body: String::from_utf8_lossy(&req[head..]).into_owned(),
            has_parameters: parts.path.contains('?') || req.len() > head,
            url,
        };
        if !crate::intercept_rules::should_intercept(&shared.intercept_rules.lock().unwrap(), &facts) {
            return (Some(req), ReqState::default());
        }
    }
    let (tx, rx) = mpsc::channel::<Option<String>>();
    let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
    let shown = String::from_utf8_lossy(&req).into_owned();
    shared.queue.lock().unwrap().push(InterceptItem::new(id, &host, port, shown.clone(), tx, InterceptKind::Request { https: default_port == 443 }));
    shared.wake();
    match rx.recv() {
        Ok(Some(edited)) => match forwarded(req, &shown, edited) {
            (bytes, changed) => (Some(bytes), ReqState { edited: changed, held: true }),
        },
        Ok(None) => {
            shared.log("Intercepted request dropped");
            (None, ReqState { edited: false, held: true })
        }
        Err(_) => (None, ReqState { edited: false, held: true }),
    }
}

/// Hold a response that the response interception rules select, as Burp
/// does: the user forwards (possibly edited) or drops it.
fn intercept_response(shared: &Shared, resp: Vec<u8>, host: &str, port: u16, https: bool, url: &str, st: ReqState) -> Option<Vec<u8>> {
    if !shared.intercept_on.load(Ordering::SeqCst) {
        return Some(resp);
    }
    let p = util::parse_http(&resp);
    let ct = util::get_header(&p.headers, "Content-Type").unwrap_or_default();
    let status = p.status.split_whitespace().next().unwrap_or("").to_string();
    let rules = shared.response_rules.lock().unwrap().clone();
    if !rules.matches(&ct, &status, st, rules.in_scope && in_scope(shared, url)) {
        return Some(resp);
    }
    let (tx, rx) = mpsc::channel::<Option<String>>();
    let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
    let shown = String::from_utf8_lossy(&resp).into_owned();
    shared.queue.lock().unwrap().push(InterceptItem::new(id, host, port, shown.clone(), tx, InterceptKind::Response { https }));
    shared.wake();
    match rx.recv() {
        Ok(Some(edited)) => Some(forwarded(resp, &shown, edited).0),
        _ => {
            shared.log("Intercepted response dropped");
            None
        }
    }
}

/// The Proxy's response sink: a streaming response is written to the
/// client as it arrives, and kept for history in a bounded [`Tee`] when
/// "Store streaming responses" is on.
///
/// [`Tee`]: crate::streaming::Tee
struct ProxySink<'a, W: Write> {
    client: &'a mut W,
    url: String,
    settings: crate::streaming::StreamSettings,
    head: Option<Vec<u8>>,
    tee: Option<crate::streaming::Tee>,
    wired: usize,
    complete: bool,
    client_gone: bool,
}

/// A streamed response, for history.
struct Streamed {
    head: Vec<u8>,
    message: crate::body::Body,
    note: String,
    stored: bool,
}

impl<'a, W: Write> ProxySink<'a, W> {
    fn new(shared: &Shared, client: &'a mut W, url: &str) -> Self {
        ProxySink { client, url: url.to_string(), settings: shared.streaming.lock().unwrap().clone(), head: None, tee: None, wired: 0, complete: false, client_gone: false }
    }

    /// The streamed response, when this one was streaming.
    fn finish(self) -> Option<Streamed> {
        let head = self.head?;
        let stored = self.tee.is_some();
        let (message, cut) = match self.tee {
            Some(t) => {
                let cut = t.truncated();
                (t.finish(), cut)
            }
            None => (crate::body::Body::from(crate::streaming::unframed_head(&head)), false),
        };
        let mut note = String::from("Streaming response");
        if !stored {
            note.push_str(" (not stored)");
        } else if cut {
            note.push_str(" (stored copy cut at the size limit)");
        }
        if self.client_gone {
            note.push_str("; client closed it");
        } else if !self.complete {
            note.push_str("; ended early");
        }
        Some(Streamed { head, message, note, stored })
    }
}

impl<W: Write> crate::streaming::ResponseSink for ProxySink<'_, W> {
    fn head(&mut self, head: &[u8]) -> crate::streaming::BodyMode {
        if crate::streaming::decide(&self.url, head, &self.settings) == crate::streaming::Decision::Buffered {
            return crate::streaming::BodyMode::Buffer;
        }
        self.head = Some(head.to_vec());
        if self.settings.store {
            let mut tee = crate::streaming::Tee::new();
            tee.push(&if self.settings.strip_chunked { crate::streaming::unframed_head(head) } else { head.to_vec() });
            self.tee = Some(tee);
        }
        crate::streaming::BodyMode::Stream
    }

    fn wire(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.wired += 1;
        // Without stripping, the stored copy is the body as it was framed.
        if !self.settings.strip_chunked && self.wired > 1 {
            if let Some(t) = self.tee.as_mut() {
                t.push(bytes);
            }
        }
        let sent = self.client.write_all(bytes).and_then(|()| self.client.flush());
        self.client_gone = sent.is_err();
        sent
    }

    fn payload(&mut self, bytes: &[u8]) {
        if self.settings.strip_chunked {
            if let Some(t) = self.tee.as_mut() {
                t.push(bytes);
            }
        }
    }

    fn end(&mut self, complete: bool) {
        self.complete = complete;
    }
}

/// A streaming response passes through unmodified, as in Burp: say once
/// per host and reason that response interception, response
/// match-and-replace or extension response handlers did not apply to it.
fn report_stream_skips(shared: &Shared, host: &str, url: &str, head: &[u8], st: ReqState) {
    let mut reasons: Vec<&'static str> = Vec::new();
    if shared.intercept_on.load(Ordering::SeqCst) {
        let p = util::parse_http(head);
        let ct = util::get_header(&p.headers, "Content-Type").unwrap_or_default();
        let status = p.status.split_whitespace().next().unwrap_or("").to_string();
        let rules = shared.response_rules.lock().unwrap().clone();
        if rules.matches(&ct, &status, st, rules.in_scope && in_scope(shared, url)) {
            reasons.push("response interception");
        }
    }
    if shared.mr_response.lock().unwrap().iter().any(|r| r.enabled) {
        reasons.push("response match and replace rules");
    }
    if !shared.ext_host.lock().unwrap().active().is_empty() {
        reasons.push("extension response handlers");
    }
    for reason in reasons {
        if shared.stream_skips.lock().unwrap().insert((host.to_string(), reason)) {
            shared.log(&format!("Streaming responses from {host} pass straight through: {reason} did not apply to them"));
        }
    }
}

fn upstream_and_deliver<S: ProxyIo>(
    shared: &Shared,
    stream: &mut S,
    req: Vec<u8>,
    default_port: u16,
    use_tls: bool,
    req_state: ReqState,
) {
    let was_edited = req_state.edited;
    let parts = util::parse_http(&req);
    let (host, port) = host_of(&parts, default_port);

    // Burp's "Show response in browser" / "Request in browser" URLs
    // (http://burpsuite/show/N, /repeat/N): WebProbe serves the same under
    // http://webprobe.
    if host.eq_ignore_ascii_case("webprobe") {
        if let Some(resp) = browser_item_response(shared, &path_of(&parts)) {
            let _ = stream.write_all(&resp);
            let _ = stream.flush();
            shared.log(&format!("Served {} for the browser", path_of(&parts)));
            return;
        }
    }
    // Burp answers `http://burpsuite` itself: the browser must already be
    // proxying through the listener, and the page it returns is where the CA
    // certificate is downloaded. WebProbe does the same at http://webprobe.
    if let Some(resp) =
        crate::setup_page::local_response(&host, &path_of(&parts), shared.proxy_port.load(Ordering::SeqCst), shared.mitm.ca_pem(), &shared.mitm.ca_der())
    {
        let _ = stream.write_all(&resp);
        let _ = stream.flush();
        let status = String::from_utf8_lossy(&resp)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        // Not recorded: Burp keeps http://burpsuite out of Proxy history and
        // the scanner (live 52685: history stays empty, live audit 0 issues).
        shared.log(&format!("Served the local setup page for {host} -> {status}"));
        return;
    }
    // Session rules run before match-and-replace, matching Burp's handling chain.
    let req_session = apply_session_rules(shared, &req, default_port);
    let mut req_out = crate::rules::apply_rules(&req_session, &shared.mr_request.lock().unwrap());
    // Extension hooks run after the built-in chain (session rules, M&R);
    // a Drop verdict closes the client connection without a response.
    let mut ann = crate::ext_host::Annotations::default();
    if !shared.ext_handle_request(&crate::ext_host::HttpService::new(&host, port, use_tls), &parts.method, &path_of(&parts), &mut req_out, &mut ann) {
        shared.log("Request dropped by an extension hook");
        return;
    }
    let (up_host, up_port) = upstream_target(shared, &host, port);
    let url = history_host(&HistEntry { host: host.clone(), port, https: use_tls, ..Default::default() }) + &path_of(&parts);
    // A streaming response (Burp's rule, `streaming::decide`) goes to the
    // client as it arrives, straight from the response reader.
    let mut sink = ProxySink::new(shared, stream, &url);
    let up = if use_tls {
        send_tls_raw_with(shared, &up_host, up_port, &req_out, Some(&mut sink))
    } else {
        send_raw_with(shared, &up_host, up_port, &req_out, Some(&mut sink))
    };
    if let Some(done) = sink.finish() {
        report_stream_skips(shared, &host, &url, &done.head, req_state);
        let status = util::parse_http(&done.head).first.split_whitespace().nth(1).unwrap_or("").to_string();
        record_entry(shared, &req_out, Some(done.message), Some(done.note), default_port, use_tls, listener_port(shared), was_edited, &ann, done.stored);
        shared.log(&format!("Streamed {} {host}:{port}{} -> {status}", parts.method, path_of(&parts)));
        return;
    }
    match up.resp {
        Some(resp) => {
            let mut resp = crate::rules::apply_rules(&resp, &shared.mr_response.lock().unwrap());
            if !shared.ext_handle_response(&crate::ext_host::HttpService::new(&host, port, use_tls), &parts.method, &path_of(&parts), &req_out, &mut resp, &mut ann) {
                shared.log("Response dropped by an extension hook");
                return;
            }
            let Some(resp) = intercept_response(shared, resp, &host, port, use_tls, &url, req_state) else { return };
            let status = util::parse_http(&resp).first.split_whitespace().nth(1).unwrap_or("").to_string();
            let _ = stream.write_all(&resp);
            let _ = stream.flush();
            record(shared, &req_out, Some(resp), None, default_port, use_tls, listener_port(shared), was_edited, &ann);
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
            record(shared, &req_out, None, Some(note), default_port, use_tls, listener_port(shared), was_edited, &ann);
            shared.log(&format!("Proxy error for {host}:{port}: {err}"));
        }
    }
}

/// Extension annotations on a history entry: the notes become (or join)
/// its comment, the highlight its row colour (Burp shows Montoya
/// annotations the same way).
pub(crate) fn annotate(e: &mut HistEntry, ann: &crate::ext_host::Annotations) {
    if !ann.notes.is_empty() {
        e.note = Some(match e.note.take() {
            Some(n) if !n.is_empty() => format!("{n}; {}", ann.notes),
            _ => ann.notes.clone(),
        });
    }
    if ann.highlight.is_some() {
        e.highlight = ann.highlight;
    }
}

/// Parse "host:port" or "host" into (host, fallback port).
pub fn split_h_p(authority: &str, fallback: u16) -> (String, u16) {
    split_host_port(authority.trim(), fallback)
}

/// Requests one Intruder attack will send before the cap kicks in (N-04 guard).
pub const INTRUDER_REQUEST_LIMIT: usize = 100_000;

/// Start an Intruder attack of any type (C-01): the request matrix comes from
/// `intruder::requests`, so Sniper, Battering ram, Pitchfork and Cluster bomb all
/// run through this one runner. `sets` is one payload list per position (Sniper
/// and Battering ram use only the first). Payloads are one per line; the `§`
/// markers never reach the wire (the template strips them).
pub fn start_attack(
    shared: Arc<Shared>,
    template: String,
    kind: crate::intruder::AttackType,
    sets: Vec<Vec<String>>,
    https: bool,
) -> Result<(), String> {
    let parsed = crate::intruder::Template::parse(&template)?;
    let rows = crate::intruder::requests(&parsed, kind, &sets, INTRUDER_REQUEST_LIMIT)?;

    let cur = shared.attack.lock().unwrap().clone();
    cur.rows.lock().unwrap().clear();
    cur.done.store(0, Ordering::SeqCst);
    cur.total.store(rows.len(), Ordering::SeqCst);
    cur.stop.store(false, Ordering::SeqCst);
    cur.running.store(true, Ordering::SeqCst);
    shared.log(&format!(
        "Intruder attack started: {} ({}) x {} request(s)",
        kind.label(),
        parsed.positions(),
        rows.len()
    ));

    std::thread::spawn(move || {
        for attack in rows {
            if cur.stop.load(Ordering::SeqCst) {
                break;
            }
            let payload = attack
                .payloads
                .iter()
                .filter_map(|p| p.clone())
                .collect::<Vec<_>>()
                .join(", ");
            let parts = util::parse_http(attack.request.as_bytes());
            let host_header = util::get_header(&parts.headers, "Host").unwrap_or_default();
            if host_header.is_empty() {
                cur.rows.lock().unwrap().push(AttackRow {
                    payload,
                    status: String::new(),
                    len: 0,
                    ms: 0,
                    ok: false,
                    req: attack.request.clone().into_bytes(),
                    resp: None,
                });
                cur.done.fetch_add(1, Ordering::SeqCst);
                continue;
            }
            let (host, port) = split_host_port(&host_header, if https { 443 } else { 80 });
            let t0 = Instant::now();
            let up = if https {
                send_tls_raw(&shared, &host, port, attack.request.as_bytes())
            } else {
                send_raw(&shared, &host, port, attack.request.as_bytes())
            };
            let ms = t0.elapsed().as_millis();
            let req_bytes = attack.request.clone().into_bytes();
            cur.rows.lock().unwrap().push(match up.resp {
                Some(resp) => {
                    let st = util::parse_http(&resp).first.split_whitespace().nth(1).unwrap_or("").to_string();
                    AttackRow { payload, status: st, len: resp.len(), ms, ok: true, req: req_bytes, resp: Some(resp) }
                }
                None => AttackRow { payload, status: String::new(), len: 0, ms, ok: false, req: req_bytes, resp: None },
            });
            cur.done.fetch_add(1, Ordering::SeqCst);
            // Gentle pacing so one bad host does not hammer (500 ms default throttle
            // from ProjectDefaults.json resource pool; C-06 turns this into a pool).
            std::thread::sleep(Duration::from_millis(50));
        }
        cur.running.store(false, Ordering::SeqCst);
        shared.log("Intruder attack finished");
    });
    Ok(())
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

/// Turn interception on or off. Off releases every held message unchanged
/// (forwarded with its current content), as Burp does when the toggle goes
/// off. The one place the toggle changes (UI, extensions).
pub fn set_intercept(shared: &Shared, on: bool) -> usize {
    shared.intercept_on.store(on, Ordering::SeqCst);
    if on {
        return 0;
    }
    let n = intercept_release_all(shared, false);
    if n > 0 {
        shared.log(&format!("Interception turned off: forwarded {n} held message(s)"));
    }
    n
}

/// Wait for the user's verdict on held message `id`. Returns early (None,
/// and the item leaves the queue) when `alive` says the connection is gone;
/// the toggle going off and shutdown answer through the queue
/// ([`set_intercept`], [`intercept_release_all`]).
pub(crate) fn intercept_wait(shared: &Shared, id: u64, rx: &mpsc::Receiver<Option<String>>, alive: &dyn Fn() -> bool) -> Option<String> {
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(v) => return v,
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !alive() {
                    shared.queue.lock().unwrap().retain(|i| i.id != id);
                    shared.wake();
                    return None;
                }
            }
        }
    }
}

/// Burp's "Forward all" / "Drop all" (burp.Zub8 / Zubj): release every held
/// message at once, each with its current (possibly edited) content.
pub fn intercept_release_all(shared: &Shared, drop: bool) -> usize {
    let items: Vec<_> = shared.queue.lock().unwrap().drain(..).collect();
    let n = items.len();
    for item in items {
        let payload = if drop { None } else { Some(item.edited.clone()) };
        let _ = item.tx.send(payload);
    }
    n
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

/// Release one held message by id (the row selected in the intercept table):
/// forwarded with `edited` when given (else its stored content), or dropped.
/// False when the message is no longer held.
pub fn intercept_release(shared: &Shared, id: u64, drop: bool, edited: Option<String>) -> bool {
    let item = {
        let mut q = shared.queue.lock().unwrap();
        match q.iter().position(|i| i.id == id) {
            Some(pos) => q.remove(pos),
            None => return false,
        }
    };
    let payload = if drop { None } else { Some(edited.unwrap_or(item.edited)) };
    let _ = item.tx.send(payload);
    true
}

#[cfg(test)]
mod intercept_all_tests {
    use super::*;

    /// Burp's default response rules: off until enabled; then text content
    /// that is not a 304; "was intercepted" / "was modified" Or in.
    #[test]
    fn response_rules_follow_burps_defaults() {
        let mut r = ResponseInterceptRules::default();
        let plain = ReqState::default();
        assert!(!r.matches("text/html", "200", plain, false), "off by default");
        r.enabled = true;
        assert!(r.matches("text/html; charset=utf-8", "200", plain, false));
        assert!(!r.matches("image/png", "200", plain, false));
        assert!(!r.matches("text/html", "304", plain, false), "And not 304");
        r.was_intercepted = true;
        assert!(r.matches("image/png", "200", ReqState { edited: false, held: true }, false), "Or was intercepted");
        r.in_scope = true;
        assert!(!r.matches("text/html", "200", plain, false), "And in scope");
        assert!(r.matches("text/html", "200", plain, true));
    }

    /// A response the rules select is held in the Intercept queue; Forward
    /// with an edit delivers the edited response to the client.
    /// Review finding 10: with a scope rule, in-scope traffic is still
    /// passively audited (the scope check used a URL without its scheme).
    #[test]
    fn passive_audit_runs_for_in_scope_traffic() {
        let shared = Shared::new();
        shared.scan_enabled.store(true, Ordering::SeqCst);
        shared.scope.lock().unwrap().push(ScopeRule { enabled: true, include: true, pattern: "http://app.test".into(), is_regex: false });
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=abc; Path=/\r\n\r\n<html></html>".to_vec();
        record(&shared, b"GET http://app.test/login HTTP/1.1\r\nHost: app.test\r\n\r\n", Some(resp.clone()), None, 80, false, 8080, false, &Default::default());
        let n = shared.issues.lock().unwrap().len();
        assert!(n > 0, "in-scope response audited");
        record(&shared, b"GET http://other.test/login HTTP/1.1\r\nHost: other.test\r\n\r\n", Some(resp), None, 80, false, 8080, false, &Default::default());
        assert!(shared.issues.lock().unwrap().iter().all(|i| !i.host.contains("other.test")), "out-of-scope response not audited");
    }

    /// Review finding 8: forwarding a held binary message unchanged sends
    /// its exact bytes and does not mark it edited.
    #[test]
    fn unchanged_binary_messages_forward_exactly() {
        let original = b"POST /up HTTP/1.1\r\nContent-Length: 4\r\n\r\n\xff\x00\xfe\x01".to_vec();
        let shown = String::from_utf8_lossy(&original).into_owned();
        assert_eq!(forwarded(original.clone(), &shown, shown.clone()), (original.clone(), false));
        let edited = shown.replace("/up", "/up2");
        let (bytes, changed) = forwarded(original, &shown, edited.clone());
        assert!(changed && bytes == edited.into_bytes());
    }

    #[test]
    fn matching_responses_are_held_and_forwarded_edited() {
        use std::io::{Read, Write};
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let oport = origin.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in origin.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody");
            }
        });
        let shared = Shared::new();
        let pport = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        shared.proxy_port.store(pport, Ordering::SeqCst);
        shared.intercept_on.store(true, Ordering::SeqCst);
        shared.response_rules.lock().unwrap().enabled = true;
        start_proxy(shared.clone());
        while !shared.listener_running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let client = std::thread::spawn(move || {
            let mut c = TcpStream::connect(("127.0.0.1", pport)).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            // A .css request: Burp's default request rules do not hold it.
            write!(c, "GET http://127.0.0.1:{oport}/site.css HTTP/1.1\r\nHost: 127.0.0.1:{oport}\r\nConnection: close\r\n\r\n").unwrap();
            let mut out = Vec::new();
            let _ = c.read_to_end(&mut out);
            out
        });
        let t0 = std::time::Instant::now();
        let held = loop {
            if let Some(i) = shared.queue.lock().unwrap().iter().find(|i| matches!(i.kind, InterceptKind::Response { .. })).map(|i| (i.id, i.edited.clone())) {
                break i;
            }
            assert!(t0.elapsed() < Duration::from_secs(10), "no response held");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(held.1.ends_with("\r\n\r\nbody"));
        let item = { let mut q = shared.queue.lock().unwrap(); let i = q.iter().position(|i| i.id == held.0).unwrap(); q.remove(i) };
        item.tx.send(Some(held.1.replace("body", "EDIT"))).unwrap();
        let out = String::from_utf8(client.join().unwrap()).unwrap();
        assert!(out.ends_with("EDIT"), "{out}");
    }

    /// burp.Zub8 / Zubj "Forward all" / "Drop all": every held message is
    /// released, forwarded with its edited content or dropped.
    #[test]
    fn release_all_forwards_or_drops_every_held_message() {
        let sh = Shared::new();
        let mut rx = Vec::new();
        for i in 0..3 {
            let (tx, r) = mpsc::channel();
            sh.queue.lock().unwrap().push(InterceptItem::new(i, "h", 80, format!("req{i}"), tx, InterceptKind::Request { https: false }));
            rx.push(r);
        }
        assert_eq!(intercept_release_all(&sh, false), 3);
        assert!(sh.queue.lock().unwrap().is_empty());
        let got: Vec<_> = rx.iter().map(|r| r.recv().unwrap()).collect();
        assert_eq!(got, vec![Some("req0".into()), Some("req1".into()), Some("req2".into())]);
        let (tx, r) = mpsc::channel();
        sh.queue.lock().unwrap().push(InterceptItem::new(9, "h", 80, "x".into(), tx, InterceptKind::Request { https: false }));
        assert_eq!(intercept_release_all(&sh, true), 1);
        assert_eq!(r.recv().unwrap(), None);
    }

    /// The intercept table releases the selected row, not the queue head.
    #[test]
    fn release_by_id_forwards_the_selected_message_with_its_edit() {
        let sh = Shared::new();
        let mut rx = Vec::new();
        for i in 0..3 {
            let (tx, r) = mpsc::channel();
            sh.queue.lock().unwrap().push(InterceptItem::new(i, "h", 80, format!("req{i}"), tx, InterceptKind::Request { https: false }));
            rx.push(r);
        }
        assert!(intercept_release(&sh, 1, false, Some("edited".into())));
        assert_eq!(rx[1].recv().unwrap(), Some("edited".into()));
        assert!(intercept_release(&sh, 2, true, None));
        assert_eq!(rx[2].recv().unwrap(), None);
        assert!(!intercept_release(&sh, 2, false, None), "already released");
        let left: Vec<u64> = sh.queue.lock().unwrap().iter().map(|i| i.id).collect();
        assert_eq!(left, vec![0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection, StreamOwned};

    /// An HTTP/1.1 client of the proxy listener (no ALPN: the listener
    /// would otherwise negotiate h2, R-05).
    fn browser_config(ca: rustls::pki_types::CertificateDer<'static>) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
    }

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
            browser_config(shared.mitm.ca_der()),
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
        let history = shared.history.snapshot();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].host, "localhost");
        assert_eq!(history[0].port, upstream_port);
        assert!(history[0].https);
        assert_eq!(history[0].path, "/private");
        assert_eq!(history[0].status, "200");
    }

    #[test]
    fn browser_item_routes_show_and_repeat() {
        let shared = Shared::new();
        let mut e = HistEntry::default();
        e.id = 7;
        e.method = "GET".into();
        e.host = "h".into();
        e.port = 80;
        e.req_raw = b"GET http://h/a?b=1 HTTP/1.1\r\nHost: h\r\n\r\n".to_vec().into();
        e.resp_raw = Some(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec().into());
        shared.history.push(e);
        let show = String::from_utf8(browser_item_response(&shared, "/show/7").unwrap()).unwrap();
        assert!(show.ends_with("ok") && show.contains("200 OK"));
        let rep = String::from_utf8(browser_item_response(&shared, "/repeat/7").unwrap()).unwrap();
        assert!(rep.contains("Location: http://h/a?b=1"), "{rep}");
        assert!(browser_item_response(&shared, "/other").is_none());
    }

    #[test]
    fn title_with_closing_tag_before_opening_tag_does_not_panic() {
        // Audit H1: two independent find() calls used to give a reversed range.
        let mut e = HistEntry::default();
        e.req_raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec().into();
        e.resp_raw = Some(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n</title>hello<title>".to_vec().into());
        assert_eq!(derive_history_fields(&e).2, "");
        e.resp_raw = Some(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title>ok</title>".to_vec().into());
        assert_eq!(derive_history_fields(&e).2, "ok");
    }

    #[test]
    fn extension_comes_from_the_last_path_segment_of_absolute_form() {
        let mut e = HistEntry::default();
        e.req_raw = b"GET http://127.0.0.1:3001/rest/user/login HTTP/1.1\r\nHost: 127.0.0.1:3001\r\n\r\n".to_vec().into();
        assert_eq!(derive_history_fields(&e).1, "");
        e.req_raw = b"GET http://127.0.0.1:3001/main.js?v=1 HTTP/1.1\r\nHost: x\r\n\r\n".to_vec().into();
        assert_eq!(derive_history_fields(&e).1, "js");
        e.req_raw = b"GET /a.b/c HTTP/1.1\r\nHost: x\r\n\r\n".to_vec().into();
        assert_eq!(derive_history_fields(&e).1, "");
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
        let hist = shared.history.snapshot();
        assert_eq!(hist.len(), 1);
        let e = &hist[0];
        let raw = e.resp_raw.as_ref().expect("a stored response");
        let text = String::from_utf8_lossy(raw);
        assert!(text.contains("Content-Length: 19"), "corrected length: {text}");
        assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(!text.to_ascii_lowercase().contains("content-encoding"));
        assert!(raw.ends_with(plain), "decoded body stored");
        assert_eq!(e.resp_len, raw.len(), "Length is the whole response, as in Burp");
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
    /// `upgrade` writes the 101 first (h2c); stream 1 is then the HTTP/1.1
    /// request already sent, so no HEADERS may follow.
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
            assert!(text.starts_with(&format!("GET {expected_path} ")), "upgrade request: {text}");
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
        if upgrade {
            // Stream 1 is the upgrade request: the client may only ACK our
            // SETTINGS, never resend HEADERS/DATA for it.
            loop {
                let (ty, flags, stream, _) = read_frame(s);
                assert!(ty == 0x4, "unexpected frame type {ty} on upgraded stream 1");
                assert_eq!(stream, 0);
                if flags & 0x1 != 0 {
                    break;
                }
            }
        } else {
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
                // RFC 9113 §8.2: field names must be lowercase on the wire.
                assert_eq!(k, k.to_ascii_lowercase(), "uppercase h2 field name {k}");
                if k == ":method" {
                    method = v;
                } else if k == ":path" {
                    path = v;
                }
            }
            assert_eq!(method, "GET");
            assert_eq!(path, expected_path);
        }
        // response: HEADERS(:status 200) + DATA, both END_STREAM on DATA.
        // The content-length field lets the client deduplicate framing headers.
        let mut enc = hpack::Encoder::new();
        let hb = enc.encode(vec![
            (b":status".as_ref(), b"200".as_ref()),
            (b"content-type".as_ref(), b"text/plain".as_ref()),
            (b"content-length".as_ref(), b"8".as_ref()),
        ]);
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

    /// Exactly one framing header and a normal HTTP/1.1 status line.
    fn assert_normalised_h2_view(resp: &[u8]) {
        let text = String::from_utf8_lossy(resp);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert_eq!(text.matches("Content-Length:").count(), 1, "{text}");
        assert_eq!(text.to_ascii_lowercase().matches("content-length:").count(), 1, "{text}");
        assert!(resp.ends_with(b"hello h2"), "{text}");
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
        shared.h2c_upgrade.store(true, Ordering::SeqCst);
        let resp = send_raw(&shared, "127.0.0.1", port, b"GET /h2c HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        t.join().unwrap();
        let resp = resp.resp.expect("h2c response");
        assert_normalised_h2_view(&resp);
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
        shared.h2c_upgrade.store(true, Ordering::SeqCst);
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
        assert_normalised_h2_view(&resp);
    }

    /// A-05 end to end: a browser-style CONNECT + MITM request through the
    /// proxy listener reaches an upstream that negotiated h2 via ALPN, and the
    /// client still receives a normal HTTP/1.1 response.
    #[test]
    fn tls_alpn_h2_end_to_end_through_proxy_listener() {
        let mut shared = Shared::new();
        let ca = shared.mitm.ca_der();
        Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);

        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_config = shared.mitm.server_config_with_alpn("localhost", vec![b"h2".to_vec()]).unwrap();
        let upstream_thread = std::thread::spawn(move || {
            let (stream, _) = upstream.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
            let conn = ServerConnection::new(upstream_config).unwrap();
            let mut tls = StreamOwned::new(conn, stream);
            tls.conn.complete_io(&mut tls.sock).unwrap();
            // Proof that the upstream side really spoke HTTP/2.
            assert_eq!(tls.conn.alpn_protocol(), Some(b"h2".as_slice()));
            serve_h2(&mut tls, false, "/e2e");
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let proxy_shared = shared.clone();
        let proxy_thread = std::thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            handle_conn(proxy_shared, stream);
        });

        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        // Certificates are RSA-2048 generated per host; debug builds can take a
        // while under a parallel test run.
        client.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        write!(client, "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n").unwrap();
        let mut connect_response = Vec::new();
        while !connect_response.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).unwrap();
            connect_response.push(byte[0]);
        }
        assert!(connect_response.starts_with(b"HTTP/1.1 200"));

        let conn = ClientConnection::new(browser_config(shared.mitm.ca_der()), ServerName::try_from("localhost").unwrap()).unwrap();
        let mut tls = StreamOwned::new(conn, client);
        write!(tls, "GET /e2e HTTP/1.1\r\nHost: localhost:{upstream_port}\r\nConnection: close\r\n\r\n").unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).unwrap();

        assert_normalised_h2_view(&response);
        upstream_thread.join().unwrap();
        proxy_thread.join().unwrap();
        let history = shared.history.snapshot();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].path, "/e2e");
        assert_eq!(history[0].status, "200");
        assert!(history[0].https);
    }

    /// A-05 end to end: a plain request through the proxy listener upgrades to
    /// h2c and the client sees the normalized HTTP/1.1 response. The upgraded
    /// socket must not be pooled as if it were HTTP/1.x.
    #[test]
    fn http2c_end_to_end_through_proxy_listener() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_thread = std::thread::spawn(move || {
            let (mut s, _) = upstream.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            serve_h2(&mut s, true, "/h2c-e2e");
        });

        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let shared = Shared::new();
        shared.h2c_upgrade.store(true, Ordering::SeqCst);
        let proxy_shared = shared.clone();
        let proxy_thread = std::thread::spawn(move || {
            let (stream, _) = proxy.accept().unwrap();
            handle_conn(proxy_shared, stream);
        });

        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            client,
            "GET http://127.0.0.1:{upstream_port}/h2c-e2e HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        assert_normalised_h2_view(&response);
        upstream_thread.join().unwrap();
        proxy_thread.join().unwrap();
        assert!(shared.pool.lock().unwrap().is_empty(), "h2c connection must not enter the HTTP/1.x pool");
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
        let shared = Shared::new();
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
    fn connections_beyond_the_limit_get_a_503_and_slots_are_returned() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // A limit already reached: the connection is refused with a 503.
        let client = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut resp = Vec::new();
            let _ = c.read_to_end(&mut resp);
            String::from_utf8_lossy(&resp).into_owned()
        });
        let (mut server_side, _) = listener.accept().unwrap();
        assert!(!stream_limit_check(&shared, &mut server_side, 0));
        drop(server_side);
        assert!(client.join().unwrap().starts_with("HTTP/1.1 503"));
        assert_eq!(shared.active_connections.load(Ordering::SeqCst), 0, "a refused connection holds no slot");
        // Within the limit a slot is taken and released when the handler ends.
        let mut a = TcpStream::connect(addr).unwrap();
        let (mut b, _) = listener.accept().unwrap();
        assert!(stream_limit_check(&shared, &mut b, 10));
        assert_eq!(shared.active_connections.load(Ordering::SeqCst), 1);
        spawn_connection_limited(shared.clone(), true, b);
        let _ = a.write_all(b"\r\n\r\n");
        drop(a);
        let t0 = std::time::Instant::now();
        while shared.active_connections.load(Ordering::SeqCst) > 0 && t0.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(shared.active_connections.load(Ordering::SeqCst), 0, "the handler gave its slot back");
    }

    #[test]
    fn listener_redirect_and_non_proxy_style_requests() {
        let shared = Shared::new();
        // An origin that says which Host header it was sent.
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in origin.incoming().flatten() {
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let head = String::from_utf8_lossy(&read_request_head(&mut s)).into_owned();
                let host = head.lines().find(|l| l.to_ascii_lowercase().starts_with("host:")).unwrap_or("Host: ?").to_string();
                let body = format!("origin saw [{host}]");
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        let spec = ListenerSpec::new("127.0.0.1", free_port());
        let state = Arc::new(ListenerState::new(spec.clone()));
        let gen = shared.listener_generation.load(Ordering::SeqCst);
        let (sh, st) = (shared.clone(), state.clone());
        let worker = std::thread::spawn(move || listener_worker(sh, st, gen));
        let addr = format!("127.0.0.1:{}", spec.port);
        let ask = |request: String| -> String {
            let mut client = None;
            for _ in 0..50 {
                if let Ok(s) = TcpStream::connect(&addr) {
                    client = Some(s);
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let mut client = client.expect("listener should accept connections");
            client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            client.write_all(request.as_bytes()).unwrap();
            let mut resp = Vec::new();
            let _ = client.read_to_end(&mut resp);
            String::from_utf8_lossy(&resp).into_owned()
        };
        // Invisible proxying of plain HTTP: a client that is not proxy-aware
        // sends an origin-form request; the Host header says where it goes.
        let direct = ask(format!("GET /x HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"));
        assert!(direct.contains(&format!("origin saw [Host: 127.0.0.1:{origin_port}]")), "{direct}");

        // Redirect: the request names a host that does not exist, yet it is
        // delivered to the redirect target with its Host header unchanged.
        shared.listener_redirects.lock().unwrap().insert(spec.port, ("127.0.0.1".to_string(), origin_port));
        let redirected = ask("GET http://no-such-host.invalid/y HTTP/1.1\r\nHost: no-such-host.invalid\r\nConnection: close\r\n\r\n".to_string());
        assert!(redirected.contains("origin saw [Host: no-such-host.invalid]"), "{redirected}");
        // Without the redirect the same request cannot be delivered.
        shared.listener_redirects.lock().unwrap().clear();
        let failed = ask("GET http://no-such-host.invalid/y HTTP/1.1\r\nHost: no-such-host.invalid\r\nConnection: close\r\n\r\n".to_string());
        assert!(failed.starts_with("HTTP/1.1 502"), "{failed}");

        shared.listener_generation.fetch_add(1, Ordering::SeqCst);
        worker.join().unwrap();
    }

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
        let spec = ListenerSpec::new("127.0.0.1", free_port());
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
        assert_eq!(shared.history.len(), 1);
    }

    /// A-07: set_listeners validates its input.
    #[test]
    fn listener_validation() {
        let shared = Shared::new();
        assert!(set_listeners(&shared, vec![ListenerSpec::new("", 8081)]).is_err());
        assert!(set_listeners(&shared, vec![ListenerSpec::new("127.0.0.1", 0)]).is_err());
        assert!(set_listeners(
            &shared,
            vec![
                ListenerSpec::new("127.0.0.1", 8081),
                ListenerSpec::new("127.0.0.1", 8081),
            ]
        )
        .is_err());
        assert!(set_listeners(&shared, vec![ListenerSpec::new("127.0.0.1", 8081)]).is_ok());
        let status = listener_status(&shared);
        // primary + one extra
        assert_eq!(status.len(), 2);
        assert!(status[1].0.ends_with(":8081"));
        assert_eq!(
            listener_specs(&shared),
            vec![ListenerSpec::new("127.0.0.1", 8081)]
        );
    }

    /// P-10: the matrix runner sends one request per matrix row and records a row per request.
    #[test]
    fn intruder_runner_sends_the_matrix() {
        use crate::intruder::AttackType;
        let shared = Shared::new();
        // Mock origin: answers one request per connection with a 200.
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = origin.local_addr().unwrap().port();
        let ot = std::thread::spawn(move || {
            for _ in 0..4 {
                let (mut s, _) = origin.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let _ = read_request_head(&mut s);
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
            }
        });
        // Cluster bomb over two positions: 2 x 2 = 4 requests.
        let template = format!("GET /p?a=§1§&b=§2§ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let sets = vec![vec!["x".to_string(), "y".to_string()], vec!["1".to_string(), "2".to_string()]];
        start_attack(shared.clone(), template, AttackType::ClusterBomb, sets, false).expect("attack starts");
        let attack = shared.attack.lock().unwrap().clone();
        for _ in 0..200 {
            if attack.done.load(Ordering::SeqCst) >= 4 { break; }
            std::thread::sleep(Duration::from_millis(25));
        }
        let rows = attack.rows.lock().unwrap().clone();
        assert_eq!(rows.len(), 4, "one row per matrix request");
        assert!(rows.iter().all(|r| r.ok && r.status == "200"));
        assert_eq!(attack.total.load(Ordering::SeqCst), 4);
        ot.join().unwrap();
    }

    /// "Diff count" (burp.Zxwu.java:56): changed, added and removed response
    /// attributes count against the previous exchange of the same location.
    #[test]
    fn diff_counts_changed_attributes_per_location() {
        let mut t = DiffTracker::default();
        let a = vec![
            ("status".to_string(), "200".to_string()),
            ("h:Server".to_string(), "nginx".to_string()),
        ];
        assert_eq!(t.diff("GET|example.com:80/a", a.clone()), 0, "first sighting diffs nothing");
        assert_eq!(t.diff("GET|example.com:80/a", a.clone()), 0, "identical repeat diffs nothing");
        let b = vec![
            ("status".to_string(), "500".to_string()),
            ("h:Server".to_string(), "lighttpd".to_string()),
        ];
        assert_eq!(t.diff("GET|example.com:80/a", b), 2, "each changed attribute counts");
        assert_eq!(t.diff("GET|example.com:80/b", a), 0, "another location is independent");
        let c = vec![("h:WWW-Authenticate".to_string(), "Basic".to_string())];
        assert_eq!(t.diff("GET|example.com:80/a", c), 3, "2 removed + 1 added");
    }

    /// resolve_ip: empty hosts never resolve; the cache answers without DNS.
    #[test]
    fn resolve_ip_uses_cache_and_handles_empty_host() {
        let shared = Shared::new();
        assert_eq!(resolve_ip(&shared, ""), "", "empty host resolves to nothing");
        shared.ip_cache.lock().unwrap().insert("cached.example".into(), "203.0.113.7".into());
        assert_eq!(resolve_ip(&shared, "cached.example"), "203.0.113.7", "cache hit avoids DNS");
    }

    /// record() stamps the diff count into each history entry.
    #[test]
    fn record_stamps_diff_count_against_previous_exchange() {
        let shared = Shared::new();
        let req = b"GET /diff HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let r1 = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok".to_vec();
        record(&shared, &req, Some(r1), None, 80, false, 8080, false, &Default::default());
        let r2 = b"HTTP/1.1 304 Not Modified\r\nContent-Type: text/plain\r\n\r\n".to_vec();
        record(&shared, &req, Some(r2), None, 80, false, 8080, false, &Default::default());
        let h = shared.history.snapshot();
        assert_eq!(h[0].diffs, 0);
        // The 304 changes the status, the length and the recomputed
        // Content-Length header normalize_response stamps in.
        assert_eq!(h[1].diffs, 3, "status, length and Content-Length all changed");
    }

    /// WS frame rebuild roundtrips: masked and unmasked, short, 16-bit and
    /// 64-bit length encodings all survive a parse after a rebuild, and the
    /// FIN bit of the original first byte is kept.
    #[test]
    fn build_ws_frame_roundtrips_through_parse() {
        for (len, masked) in [(5usize, true), (200, false), (300, true), (70_000, false)] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let frame = build_ws_frame(0x81, &payload, masked);
            assert_eq!(frame[0], 0x81, "FIN + text opcode kept");
            let (op, m, parsed, consumed) = parse_ws_frame(&frame).expect("complete frame");
            assert_eq!(op, 0x1);
            assert_eq!(m, masked);
            assert_eq!(parsed, payload, "payload survives the roundtrip at len {len}");
            assert_eq!(consumed, frame.len());
        }
    }

    /// With interception off, frames pass through byte-identical and are
    /// recorded once; a frame split across reads is forwarded when complete.
    /// Control frames relay untouched even when intercepting.
    #[test]
    fn ws_intercept_off_relays_raw_bytes_and_control_frames_pass() {
        let shared = Shared::new();
        let mut st = WsStream::default();
        let frame = build_ws_frame(0x81, b"plain", true);
        let out = intercept_ws_stream(&shared, "example.com", &frame, &mut st, true);
        assert_eq!(out, frame, "with interception off, bytes pass through unchanged");
        // Split frame: nothing forwarded until the second half arrives.
        let big = build_ws_frame(0x82, &[7u8; 300], false);
        assert!(intercept_ws_stream(&shared, "example.com", &big[..10], &mut st, false).is_empty());
        assert_eq!(intercept_ws_stream(&shared, "example.com", &big[10..], &mut st, false), big);
        // Ping frames are control frames: relayed even when intercepting.
        shared.intercept_on.store(true, Ordering::SeqCst);
        let ping = build_ws_frame(0x89, b"keepalive", true);
        let out = intercept_ws_stream(&shared, "example.com", &ping, &mut st, true);
        assert_eq!(out, ping, "control frames are never queued");
        assert!(st.buf.is_empty());
        assert!(shared.queue.lock().unwrap().is_empty());
        let h = shared.ws_history.with_rows(|r| r.to_vec());
        let rows: Vec<(String, String, usize)> = h.iter().map(|e| (e.direction.clone(), e.opcode.clone(), e.payload.len())).collect();
        assert_eq!(
            rows,
            vec![
                ("client -> server".to_string(), "text".to_string(), 5),
                ("server -> client".to_string(), "binary".to_string(), 300),
                ("client -> server".to_string(), "ping".to_string(), 9),
            ]
        );
    }

    /// Messages are only held while Intercept is on and the direction is
    /// enabled (Burp: both directions default to on).
    #[test]
    fn ws_hold_follows_intercept_toggle_and_direction_flags() {
        let shared = Shared::new();
        assert!(!ws_should_hold(&shared, true), "Intercept off: never held");
        shared.intercept_on.store(true, Ordering::SeqCst);
        assert!(ws_should_hold(&shared, true) && ws_should_hold(&shared, false));
        shared.ws_intercept_server.store(false, Ordering::SeqCst);
        assert!(ws_should_hold(&shared, true) && !ws_should_hold(&shared, false));
    }

    /// Intercept on: text frames are queued, Forward rewrites the payload,
    /// Drop skips the frame; history records the edited text as edited.
    #[test]
    fn ws_intercept_queues_edits_and_drops() {
        let shared = Shared::new();
        shared.intercept_on.store(true, Ordering::SeqCst);
        let q_shared = shared.clone();
        let answerer = std::thread::spawn(move || {
            for verdict in ["HELLO", ""] {
                loop {
                    let item = {
                        let mut queue = q_shared.queue.lock().unwrap();
                        if queue.is_empty() { None } else { Some(queue.remove(0)) }
                    };
                    if let Some(item) = item {
                        assert_eq!(item.kind, InterceptKind::WebSocket { to_server: true });
                        let edited = if verdict.is_empty() { None } else { Some(verdict.to_string()) };
                        item.tx.send(edited).unwrap();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });
        let mut st = WsStream::default();
        let mut chunk = build_ws_frame(0x81, b"hello", true);
        chunk.extend_from_slice(&build_ws_frame(0x81, b"dropme", true));
        let out = intercept_ws_stream(&shared, "example.com", &chunk, &mut st, true);
        let (op, masked, payload, consumed) = parse_ws_frame(&out).expect("one frame forwarded");
        assert_eq!((op, masked, payload.as_slice(), consumed), (0x1, true, &b"HELLO"[..], out.len()), "first frame edited, second dropped");
        assert_eq!(out[0], 0x81, "the edited frame is still final");
        assert!(st.buf.is_empty());
        answerer.join().unwrap();
        let h = shared.ws_history.with_rows(|r| r.to_vec());
        assert_eq!(h.len(), 1, "the dropped frame is not recorded");
        assert_eq!(h[0].payload, "HELLO");
        assert!(shared.ws_edited.lock().unwrap().contains(&h[0].id));
    }

    /// B-09 loopback: browser -> proxy -> WebSocket server on 127.0.0.1.
    /// With Intercept on, the handshake request is held and forwarded, the
    /// client's message is held, edited and forwarded, the server's echo is
    /// held and forwarded, and both land in WebSockets history.
    #[test]
    fn ws_messages_are_held_edited_and_forwarded_end_to_end() {
        let shared = Shared::new();
        shared.intercept_on.store(true, Ordering::SeqCst);
        // Echo WebSocket server.
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = origin.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let _ = read_request_head(&mut s);
            s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n").unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let payload = loop {
                if let Some((_, _, p, _)) = parse_ws_frame(&buf) {
                    break p;
                }
                let n = s.read(&mut chunk).unwrap();
                assert!(n > 0, "client frame never arrived");
                buf.extend_from_slice(&chunk[..n]);
            };
            let mut echo = b"echo:".to_vec();
            echo.extend_from_slice(&payload);
            s.write_all(&build_ws_frame(0x81, &echo, false)).unwrap();
            payload
        });
        // The proxy side: one connection handled by the normal pipeline.
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let sh = shared.clone();
        std::thread::spawn(move || {
            let (s, _) = proxy.accept().unwrap();
            handle_conn(sh, s);
        });
        // The user at the Intercept tab.
        let ui_shared = shared.clone();
        let user = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            while seen.len() < 3 && Instant::now() < deadline {
                let head = ui_shared.queue.lock().unwrap().first().map(|i| (i.id, i.kind, i.edited.clone()));
                match head {
                    Some((id, kind, text)) => {
                        let edit = match kind {
                            InterceptKind::WebSocket { to_server: true } => Some(text.to_uppercase()),
                            _ => None,
                        };
                        assert!(intercept_release(&ui_shared, id, false, edit));
                        seen.push(kind);
                    }
                    None => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            seen
        });
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            client,
            "GET http://127.0.0.1:{origin_port}/ws HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .unwrap();
        let head = read_response_head(&mut client).unwrap();
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"), "{head:?}");
        client.write_all(&build_ws_frame(0x81, b"hello", true)).unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let reply = loop {
            if let Some((_, masked, p, _)) = parse_ws_frame(&buf) {
                assert!(!masked, "server frames reach the client unmasked");
                break p;
            }
            let n = client.read(&mut chunk).unwrap();
            assert!(n > 0, "echo never arrived");
            buf.extend_from_slice(&chunk[..n]);
        };
        assert_eq!(server.join().unwrap(), b"HELLO", "the server got the edited message");
        assert_eq!(reply, b"echo:HELLO");
        let kinds = user.join().unwrap();
        assert_eq!(
            kinds,
            vec![
                InterceptKind::Request { https: false },
                InterceptKind::WebSocket { to_server: true },
                InterceptKind::WebSocket { to_server: false },
            ]
        );
        let h = shared.ws_history.with_rows(|r| r.to_vec());
        let frames: Vec<(String, String)> = h.iter().filter(|e| e.direction != "handshake").map(|e| (e.direction.clone(), e.text().into_owned())).collect();
        assert_eq!(frames, vec![("client -> server".to_string(), "HELLO".to_string()), ("server -> client".to_string(), "echo:HELLO".to_string())]);
        let edited = shared.ws_edited.lock().unwrap();
        assert_eq!(h.iter().filter(|e| edited.contains(&e.id)).count(), 1, "only the edited message is marked");
    }

    /// B-09 over TLS: CONNECT, MITM handshake, WebSocket upgrade to a local
    /// TLS server; with Intercept on the client's message is held, edited
    /// and forwarded, and the server's reply reaches the client.
    #[test]
    fn tls_ws_messages_are_held_edited_and_forwarded_end_to_end() {
        let mut shared = Shared::new();
        let ca = shared.mitm.ca_der();
        Arc::get_mut(&mut shared).unwrap().tls_upstream = client_config(ca);
        shared.intercept_on.store(true, Ordering::SeqCst);
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_config = shared.mitm.server_config("localhost").unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = upstream.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
            let mut tls = StreamOwned::new(ServerConnection::new(upstream_config).unwrap(), stream);
            let _ = read_request_head(&mut tls);
            tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").unwrap();
            tls.flush().unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let payload = loop {
                if let Some((_, _, p, _)) = parse_ws_frame(&buf) {
                    break p;
                }
                let n = tls.read(&mut chunk).unwrap();
                assert!(n > 0, "client frame never arrived");
                buf.extend_from_slice(&chunk[..n]);
            };
            tls.write_all(&build_ws_frame(0x81, b"pong", false)).unwrap();
            tls.flush().unwrap();
            // Hold the socket until the client has read the reply.
            std::thread::sleep(Duration::from_millis(500));
            payload
        });
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let sh = shared.clone();
        std::thread::spawn(move || {
            let (s, _) = proxy.accept().unwrap();
            handle_conn(sh, s);
        });
        let ui_shared = shared.clone();
        let user = std::thread::spawn(move || {
            let mut kinds = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(60);
            while kinds.len() < 3 && Instant::now() < deadline {
                let head = ui_shared.queue.lock().unwrap().first().map(|i| (i.id, i.kind, i.edited.clone()));
                match head {
                    Some((id, kind, text)) => {
                        let edit = matches!(kind, InterceptKind::WebSocket { to_server: true }).then(|| format!("{text}!"));
                        assert!(intercept_release(&ui_shared, id, false, edit));
                        kinds.push(kind);
                    }
                    None => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            kinds
        });
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        write!(client, "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n").unwrap();
        let mut connect_response = Vec::new();
        while !connect_response.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            client.read_exact(&mut byte).unwrap();
            connect_response.push(byte[0]);
        }
        assert!(connect_response.starts_with(b"HTTP/1.1 200"));
        let conn = ClientConnection::new(browser_config(shared.mitm.ca_der()), ServerName::try_from("localhost").unwrap()).unwrap();
        let mut tls = StreamOwned::new(conn, client);
        write!(
            tls,
            "GET /ws HTTP/1.1\r\nHost: localhost:{upstream_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .unwrap();
        tls.flush().unwrap();
        let head = read_response_head(&mut tls).unwrap();
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"), "{head:?}");
        tls.write_all(&build_ws_frame(0x81, b"ping", true)).unwrap();
        tls.flush().unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let reply = loop {
            if let Some((_, _, p, _)) = parse_ws_frame(&buf) {
                break p;
            }
            let n = tls.read(&mut chunk).unwrap();
            assert!(n > 0, "reply never arrived");
            buf.extend_from_slice(&chunk[..n]);
        };
        assert_eq!(reply, b"pong");
        assert_eq!(server.join().unwrap(), b"ping!", "the server got the edited message");
        let kinds = user.join().unwrap();
        assert_eq!(
            kinds,
            vec![
                InterceptKind::Request { https: true },
                InterceptKind::WebSocket { to_server: true },
                InterceptKind::WebSocket { to_server: false },
            ]
        );
        let h = shared.ws_history.with_rows(|r| r.to_vec());
        let frames: Vec<String> = h.iter().filter(|e| e.direction != "handshake").map(|e| e.text().into_owned()).collect();
        assert_eq!(frames, vec!["ping!", "pong"]);
    }

    /// A-07: replacing the listener set leaves history intact.
    #[test]
    fn listener_restart_keeps_history() {
        let shared = Shared::new();
        shared.history.push(HistEntry {
            id: 1,
            ts: 0,
            method: "GET".into(),
            host: "example.com".into(),
            port: 443,
            https: true,
            path: "/".into(),
            status: "200".into(),
            resp_len: 0,
            req_raw: Vec::new().into(),
            resp_raw: None,
            note: None,
            highlight: None,
            audited: false,
            params: false,
            edited: false,
            extension: String::new(),
            title: String::new(),
            cookies: String::new(),
            listener_port: 0,
            ip: String::new(),
            diffs: 0,
        });
        assert!(set_listeners(&shared, vec![ListenerSpec::new("127.0.0.1", free_port())]).is_ok());
        std::thread::sleep(Duration::from_millis(600));
        assert!(set_listeners(&shared, vec![ListenerSpec::new("127.0.0.1", free_port())]).is_ok());
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(shared.history.len(), 1, "history survives listener changes");
    }

    /// A port change moves the primary listener without waiting for a client
    /// to connect (a blocking accept used to hold the old port until then).
    #[test]
    fn primary_listener_moves_on_restart_without_a_connection() {
        let shared = Shared::new();
        let (a, b) = (free_port(), free_port());
        shared.proxy_port.store(a, Ordering::SeqCst);
        start_proxy(shared.clone());
        let bound = |p: u16| std::net::TcpStream::connect(("127.0.0.1", p)).is_ok();
        let wait = |cond: &dyn Fn() -> bool| {
            let t0 = std::time::Instant::now();
            while !cond() && t0.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(20));
            }
            cond()
        };
        assert!(wait(&|| shared.listener_running.load(Ordering::SeqCst)), "listener up");
        shared.proxy_port.store(b, Ordering::SeqCst);
        shared.listener_restart.store(true, Ordering::SeqCst);
        // No connection to the old port in between: the new one must come up.
        assert!(wait(&|| std::net::TcpListener::bind(("127.0.0.1", a)).is_ok()), "old port released");
        assert!(wait(&|| bound(b)), "new port listening");
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

        // Like http://burpsuite, the internal page stays out of history (and
        // so out of the scanner).
        assert_eq!(shared.history.len(), 0);
        t.join().unwrap();
    }

}

#[cfg(test)]
mod tool_log_tests {
    use super::*;
    use std::io::{Read, Write};

    /// A local origin that answers every connection with one fixed response.
    fn origin() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno");
            }
        });
        port
    }

    #[test]
    fn tool_requests_are_logged_under_the_tool_name_and_untagged_ones_are_not() {
        let shared = Shared::new();
        let port = origin();
        let request = b"GET /admin?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

        // No tool scope (the proxy's own forwarding, tests): nothing recorded.
        assert!(send_raw(&shared, "127.0.0.1", port, request).resp.is_some());
        assert!(shared.tool_log.lock().unwrap().is_empty());

        {
            let _tool = tool_scope("Repeater");
            assert!(send_raw(&shared, "127.0.0.1", port, request).resp.is_some());
            // Scopes nest and restore the outer tool when dropped.
            {
                let _inner = tool_scope("Scanner");
                send_raw(&shared, "127.0.0.1", port, request);
            }
            send_raw(&shared, "127.0.0.1", port, request);
        }
        send_raw(&shared, "127.0.0.1", port, request);

        let log = shared.tool_log.lock().unwrap();
        assert_eq!(log.iter().map(|e| e.tool).collect::<Vec<_>>(), ["Repeater", "Scanner", "Repeater"]);
        let e = &log[0];
        assert_eq!((e.method.as_str(), e.path.as_str(), e.status.as_str()), ("GET", "/admin?x=1", "404"));
        assert_eq!((e.host.as_str(), e.port, e.https), ("127.0.0.1", port, false));
        assert_eq!(e.mime, "text/html");
        assert_eq!(e.req_len, request.len());
        assert!(e.resp_len > 0);
        assert_eq!(&e.request[..], &request[..]);
        assert!(e.response.as_deref().is_some_and(|r| r.starts_with(b"HTTP/1.1 404")));
    }
}

#[cfg(test)]
mod cookie_jar_tests {
    use super::*;
    use std::io::{Read, Write};

    /// A local origin that sets a cookie and echoes the Cookie header it got.
    fn origin() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let cookie = req.lines().find(|l| l.to_ascii_lowercase().starts_with("cookie:")).unwrap_or("Cookie: none").to_string();
                let body = format!("got [{cookie}]");
                let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nSet-Cookie: sid=from-origin; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        port
    }

    fn body(up: &Upstream) -> String {
        String::from_utf8_lossy(up.resp.as_deref().unwrap_or_default()).into_owned()
    }

    #[test]
    fn proxied_responses_feed_the_jar_unless_proxy_monitoring_is_off() {
        let shared = Shared::new();
        let req = b"GET /account/home HTTP/1.1\r\nHost: shop.test\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; Path=/; HttpOnly\r\nSet-Cookie: pref=1\r\nContent-Length: 0\r\n\r\n".to_vec();
        record(&shared, req, Some(resp.clone()), None, 80, false, 8080, false, &Default::default());
        {
            let jar = shared.cookie_jar.lock().unwrap();
            let mut got: Vec<(String, String, String)> = jar.cookies.iter().map(|c| (c.name.clone(), c.domain.clone(), c.path.clone())).collect();
            got.sort();
            assert_eq!(got, [("pref".to_string(), "shop.test".to_string(), "/account".to_string()), ("sid".to_string(), "shop.test".to_string(), "/".to_string())]);
        }
        // With Proxy unticked the jar is left alone.
        {
            let mut jar = shared.cookie_jar.lock().unwrap();
            jar.cookies.clear();
            jar.update_from.clear();
        }
        record(&shared, req, Some(resp), None, 80, false, 8080, false, &Default::default());
        assert!(shared.cookie_jar.lock().unwrap().cookies.is_empty());
    }

    #[test]
    fn jar_is_applied_to_covered_tools_and_fed_by_monitored_ones() {
        let shared = Shared::new();
        let port = origin();
        let req = b"GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        shared.cookie_jar.lock().unwrap().set_cookie("127.0.0.1", "/", "sid=jar-value; Path=/", util::now_secs());

        // Defaults: the Scanner gets the jar's cookies; Repeater does not.
        {
            let _t = tool_scope("Scanner");
            assert!(body(&send_raw(&shared, "127.0.0.1", port, req)).contains("got [Cookie: sid=jar-value]"));
        }
        {
            let _t = tool_scope("Repeater");
            assert!(body(&send_raw(&shared, "127.0.0.1", port, req)).contains("got [Cookie: none]"));
        }
        // No tool on this thread (the proxy's own forwarding): untouched.
        assert!(body(&send_raw(&shared, "127.0.0.1", port, req)).contains("got [Cookie: none]"));
        // Neither tool is monitored by default, so the origin's Set-Cookie did
        // not replace the jar's value.
        assert_eq!(shared.cookie_jar.lock().unwrap().cookies[0].value, "jar-value");

        // Monitor Repeater: its responses now update the jar.
        shared.cookie_jar.lock().unwrap().update_from.push("Repeater".into());
        {
            let _t = tool_scope("Repeater");
            send_raw(&shared, "127.0.0.1", port, req);
        }
        assert_eq!(shared.cookie_jar.lock().unwrap().cookies[0].value, "from-origin");
        // ...and the Scanner sends the updated value; the logged request shows it.
        {
            let _t = tool_scope("Scanner");
            assert!(body(&send_raw(&shared, "127.0.0.1", port, req)).contains("got [Cookie: sid=from-origin]"));
        }
        let log = shared.tool_log.lock().unwrap();
        assert!(String::from_utf8_lossy(&log.last().unwrap().request).contains("Cookie: sid=from-origin"));
    }
}

#[cfg(test)]
mod session_rule_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::AtomicUsize;

    /// A local application: `/login` sets the session cookie, `/protected`
    /// greets a logged-in client and asks everyone else to log in, anything
    /// else echoes the request head. Counts logins.
    fn app() -> (u16, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let logins = Arc::new(AtomicUsize::new(0));
        let counter = logins.clone();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (extra, body) = if path == "/login" {
                    counter.fetch_add(1, Ordering::SeqCst);
                    ("Set-Cookie: sid=ok; Path=/\r\n", "logged in".to_string())
                } else if path == "/protected" {
                    ("", if req.contains("sid=ok") { "welcome".to_string() } else { "Please log in".to_string() })
                } else {
                    ("", req.clone())
                };
                let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        (port, logins)
    }

    fn body(up: &Upstream) -> String {
        let resp = up.resp.clone().unwrap_or_default();
        let head = util::parse_http(&resp).head_len;
        String::from_utf8_lossy(&resp[head.min(resp.len())..]).into_owned()
    }

    fn rule(action: &str, value: &str, tools: &[&str]) -> SessionRule {
        SessionRule { action: action.into(), value: value.into(), tools: tools.iter().map(|t| t.to_string()).collect(), ..SessionRule::new() }
    }

    /// A request that finds the session invalid waits for the in-browser
    /// login, then carries the cookie the login put in the jar.
    #[test]
    fn browser_recovery_waits_for_the_login_and_uses_the_new_cookie() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nPlease login");
            }
        });
        let shared = Shared::new();
        let mut r = rule("check session", BROWSER_RECOVERY, &["Scanner"]);
        r.check = "please login".into();
        r.check_invalid_on_match = true;
        shared.session_rules.lock().unwrap().push(r);
        shared.cookie_jar.lock().unwrap().apply_to = vec!["Scanner".into()];
        let req = format!("GET /account HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes();
        let sh = shared.clone();
        let worker = std::thread::spawn(move || apply_session_rules_for(&sh, "Scanner", &req, port, false));
        // The prompt appears; the user logs in (the proxy feeds the jar) and confirms.
        let t0 = std::time::Instant::now();
        let p = loop {
            if let Some(p) = shared.browser_recovery.pending() {
                break p;
            }
            assert!(t0.elapsed() < Duration::from_secs(20), "no prompt");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(p.host, "127.0.0.1");
        let login = format!("HTTP/1.1 302 Found\r\nSet-Cookie: session=fresh; Path=/\r\n\r\n").into_bytes();
        shared.cookie_jar.lock().unwrap().update_from_response("127.0.0.1", "/login", &login, crate::util::now_secs());
        shared.browser_recovery.answer(true);
        let out = String::from_utf8(worker.join().unwrap()).unwrap();
        assert!(out.contains("session=fresh"), "{out}");
        assert!(shared.browser_recovery.pending().is_none());
    }

    #[test]
    fn check_session_logs_in_once_and_only_for_tools_in_scope() {
        let shared = Shared::new();
        let (port, logins) = app();
        shared.macros.lock().unwrap().push(Macro { name: "login".into(), request: format!("GET /login HTTP/1.1\nHost: 127.0.0.1:{port}") });
        let mut check = rule("check session", "login", &["Scanner"]);
        check.check = "please LOG in".into(); // case-insensitive
        check.check_invalid_on_match = true;
        shared.session_rules.lock().unwrap().push(check);
        let req = format!("GET /protected HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");

        // Repeater is outside the rule's tool scope: no validation, no login.
        {
            let _t = tool_scope("Repeater");
            assert_eq!(body(&send_raw(&shared, "127.0.0.1", port, req.as_bytes())), "Please log in");
        }
        assert_eq!(logins.load(Ordering::SeqCst), 0);

        // Scanner: the validation request shows the session is invalid, the
        // login macro runs, its cookie reaches the real request.
        {
            let _t = tool_scope("Scanner");
            assert_eq!(body(&send_raw(&shared, "127.0.0.1", port, req.as_bytes())), "welcome");
            assert_eq!(logins.load(Ordering::SeqCst), 1);
            // Second request: the jar already holds the cookie, the session
            // validates, and the macro is not run again.
            assert_eq!(body(&send_raw(&shared, "127.0.0.1", port, req.as_bytes())), "welcome");
        }
        assert_eq!(logins.load(Ordering::SeqCst), 1);
        assert!(shared.cookie_jar.lock().unwrap().cookies.iter().any(|c| c.name == "sid" && c.value == "ok"));
    }

    #[test]
    fn header_cookie_and_post_request_actions_apply_in_order() {
        let shared = Shared::new();
        let (port, logins) = app();
        shared.macros.lock().unwrap().push(Macro { name: "ping".into(), request: format!("GET /login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n") });
        {
            let mut rules = shared.session_rules.lock().unwrap();
            rules.push(rule("set header", "X-Session: abc", &["Intruder"]));
            rules.push(rule("set cookie", "role=admin", &["Intruder"]));
            rules.push(rule("post-request macro", "ping", &["Intruder"]));
            // A disabled rule and a rule for another host change nothing.
            rules.push(SessionRule { enabled: false, ..rule("set header", "X-Off: 1", &["Intruder"]) });
            rules.push(SessionRule { host_match: "other.test".into(), ..rule("set header", "X-Other: 1", &["Intruder"]) });
        }
        let req = format!("GET /echo HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: role=user; lang=en\r\nConnection: close\r\n\r\n");
        let echoed = {
            let _t = tool_scope("Intruder");
            body(&send_raw(&shared, "127.0.0.1", port, req.as_bytes()))
        };
        assert!(echoed.contains("X-Session: abc"), "{echoed}");
        assert!(echoed.contains("Cookie: role=admin; lang=en"), "{echoed}");
        assert!(!echoed.contains("X-Off") && !echoed.contains("X-Other"), "{echoed}");
        // The post-request macro ran once, after the request.
        assert_eq!(logins.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn multi_step_macro_derives_a_token_and_carries_cookies() {
        // /form hands out a token and a cookie; /submit accepts only that pair.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let (extra, body) = if req.starts_with("GET /form") {
                    ("Set-Cookie: flow=f1; Path=/\r\n", "<form><input type=\"hidden\" name=\"csrf\" value=\"t0k3n\"></form>".to_string())
                } else if req.contains("flow=f1") && req.ends_with("user=a&csrf=t0k3n") {
                    ("Set-Cookie: sid=in; Path=/\r\n", "accepted".to_string())
                } else {
                    ("", format!("rejected: {req}"))
                };
                let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        let shared = Shared::new();
        let text = format!(
            "###\nGET /form HTTP/1.1\nHost: 127.0.0.1:{port}\n\n### derive=csrf\nPOST /submit HTTP/1.1\nHost: 127.0.0.1:{port}\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 17\n\nuser=a&csrf=stale\n"
        );
        let results = run_macro_text(&shared, &text);
        assert_eq!(results.len(), 2);
        assert!(results[0].derived.is_empty());
        assert_eq!(results[1].derived, [("csrf".to_string(), "t0k3n".to_string())]);
        assert!(body(&Upstream { resp: results[1].response.clone(), error: None }).contains("accepted"), "{}", String::from_utf8_lossy(results[1].response.as_deref().unwrap_or_default()));
        // The request really sent shows the derived value and the jar's cookie.
        let sent = String::from_utf8_lossy(&results[1].request).into_owned();
        assert!(sent.contains("Cookie: flow=f1") && sent.ends_with("user=a&csrf=t0k3n"), "{sent}");
        // Both steps' cookies are now in the jar for later tool requests.
        let jar = shared.cookie_jar.lock().unwrap();
        let mut names: Vec<&str> = jar.cookies.iter().map(|c| c.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["flow", "sid"]);
        drop(jar);
        // By name, the stored macro returns its last response.
        shared.macros.lock().unwrap().push(Macro { name: "flow".into(), request: text });
        assert!(run_macro(&shared, "flow").is_some());
        assert!(run_macro(&shared, "unknown").is_none());
    }

    #[test]
    fn recorded_login_supplies_a_bearer_token_to_later_requests() {
        // /login returns a JSON token; /api answers only that bearer token.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let logins = Arc::new(AtomicUsize::new(0));
        let counter = logins.clone();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let body = if req.starts_with("POST /login") {
                    counter.fetch_add(1, Ordering::SeqCst);
                    "{\"authentication\":{\"token\":\"jwt-123\",\"bid\":7}}".to_string()
                } else if req.contains("Authorization: Bearer jwt-123") {
                    "api data".to_string()
                } else {
                    "401 unauthorised".to_string()
                };
                let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        let shared = Shared::new();
        shared.macros.lock().unwrap().push(Macro {
            name: "login".into(),
            request: format!("POST /login HTTP/1.1\nHost: 127.0.0.1:{port}\nContent-Type: application/json\nContent-Length: 2\n\n{{}}"),
        });
        {
            let mut rules = shared.session_rules.lock().unwrap();
            let mut check = rule("check session", "login", &["Repeater"]);
            check.check = "401 unauthorised".into();
            rules.push(check);
            rules.push(rule("set header", "Authorization: Bearer {token}", &["Repeater"]));
        }
        // Before any macro has run the placeholder stays as written.
        assert_eq!(expand_placeholders(&shared, "Authorization: Bearer {token}"), "Authorization: Bearer {token}");
        let req = format!("GET /api HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        let _t = tool_scope("Repeater");
        assert_eq!(body(&send_raw(&shared, "127.0.0.1", port, req.as_bytes())), "api data");
        assert_eq!(logins.load(Ordering::SeqCst), 1);
        assert_eq!(expand_placeholders(&shared, "x={token};{bid};{nope}"), "x=jwt-123;7;{nope}");
    }

    #[test]
    fn proxy_rules_need_proxy_in_their_tool_scope() {
        let shared = Shared::new();
        {
            let mut rules = shared.session_rules.lock().unwrap();
            rules.push(rule("set header", "X-Tools: 1", &["Scanner", "Repeater"]));
            rules.push(rule("set header", "X-Proxy: 1", &["Proxy"]));
        }
        let out = String::from_utf8(apply_session_rules(&shared, b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n", 80)).unwrap();
        assert!(out.contains("X-Proxy: 1") && !out.contains("X-Tools"), "{out}");
        assert_eq!(set_request_cookie(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", "a", "1"), b"GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1\r\n\r\n".to_vec());
    }
}
