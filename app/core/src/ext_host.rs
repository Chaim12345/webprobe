// Montoya-shaped extension host.
// Path A (2026-11-15): Burp extensions are in-process plugins that hook the
// message pipeline through the Montoya API (ProxyRequestHandler /
// ProxyResponseHandler). WebProbe is a self-contained Rust binary, so the
// same hook surface is expressed as Rust traits and runs in-process.
// Path B (wave 30): real Burp Montoya .jar extensions load through a
// sidecar JVM bridge (sidecar/MontoyaBridge.java, single-file source mode)
// that runs the extension against Burp's own Montoya API classes from
// /opt/BurpSuite/burpsuite.jar and speaks JSON-lines over stdin/stdout.

/// What an extension wants done with a message (Montoya's
/// ProxyRequestReceived / ProxyResponseReceived action).
pub enum ProxyAction {
    /// Let the message continue through the pipeline.
    Continue,
    /// Drop the message (Montoya `drop`).
    Drop,
}

/// The service a message goes to (Montoya `HttpService`): host, port and
/// whether TLS is used, so extensions that scope by service or URL see the
/// real target.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpService {
    pub host: String,
    pub port: u16,
    pub secure: bool,
}

impl HttpService {
    pub fn new(host: &str, port: u16, secure: bool) -> Self {
        HttpService { host: host.to_string(), port, secure }
    }

    /// `scheme://host[:port]`, the port omitted when it is the default.
    pub fn origin(&self) -> String {
        let scheme = if self.secure { "https" } else { "http" };
        let default = if self.secure { 443 } else { 80 };
        if self.port == default || self.port == 0 {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
}

/// The hook surface an extension registers. Every method defaults to
/// Continue with no edits, mirroring Montoya's default implementations.
pub trait ProxyHooks: Send + Sync {
    /// Extension name shown in the Extensions tab.
    fn extension_name(&self) -> &str;
    /// Which hook kinds this extension registered (Montoya:
    /// isProxyRequestHandler() / isProxyResponseHandler()).
    fn hooks_registered(&self) -> &'static str {
        ""
    }
    fn handle_request_received(&self, _svc: &crate::ext_host::HttpService, _method: &str, _path: &str, _req: &mut Vec<u8>) -> ProxyAction {
        ProxyAction::Continue
    }
    fn handle_response_received(&self, _svc: &crate::ext_host::HttpService, _method: &str, _path: &str, _resp: &mut Vec<u8>) -> ProxyAction {
        ProxyAction::Continue
    }
    /// Issue types the extension can report (Burp's custom issue
    /// definitions), shown in the Extensions tab.
    fn issue_definitions(&self) -> Vec<IssueDefinition> {
        Vec::new()
    }
    /// Issues reported since the last call; the host adds them to the
    /// issue list, attributed to the message they were reported on.
    fn take_issues(&self) -> Vec<ExtIssue> {
        Vec::new()
    }
    /// Title of the extension's own tab, if it registered one.
    fn tab_title(&self) -> Option<String> {
        None
    }
    /// Text of the extension's tab as of the last `refresh_tab` (cheap:
    /// the UI may call it every frame).
    fn tab_content(&self) -> String {
        String::new()
    }
    /// Fetch fresh tab text; may block on the extension, so the UI runs it
    /// off its thread.
    fn refresh_tab(&self) {}
    /// Recent errors (crashes, timeouts, protocol errors, stderr lines),
    /// newest last, for the Extensions tab's Errors pane.
    fn errors(&self) -> Vec<String> {
        Vec::new()
    }
    /// False once the extension has stopped working (its hooks then let
    /// everything through).
    fn healthy(&self) -> bool {
        true
    }
}

/// An issue type an extension declares.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssueDefinition {
    pub name: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
}

/// An issue an extension reported on a message. Empty `host`/`path` are
/// filled from the message the hook ran on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtIssue {
    pub name: String,
    /// high | medium | low | info
    pub severity: String,
    /// Certain | Firm | Tentative
    pub confidence: String,
    pub detail: String,
    pub host: String,
    pub path: String,
}

pub struct LoadedExtension {
    pub enabled: bool,
    pub hooks: Arc<dyn ProxyHooks>,
    /// Where it was installed from, for extensions the user added (saved
    /// in the extension list); None for built-in / test-hook extensions.
    pub source: Option<crate::ext_store::Installed>,
}

impl LoadedExtension {
    pub fn new(hooks: impl ProxyHooks + 'static) -> Self {
        Self { enabled: true, hooks: Arc::new(hooks), source: None }
    }
}

/// Registry the proxy pipeline runs. Extensions run in registration order;
/// the first Drop verdict stops the chain and the message.
#[derive(Default)]
pub struct ExtensionHost {
    pub extensions: Vec<LoadedExtension>,
    /// Remembered extensions that failed to load this session (no `java`,
    /// a moved jar): kept so saving the list does not forget them.
    pub not_loaded: Vec<crate::ext_store::Installed>,
}

impl ExtensionHost {
    /// The enabled extensions, in order. Callers run hooks on this snapshot
    /// with the host unlocked, so one slow extension does not hold up every
    /// other connection waiting for the registry.
    pub fn active(&self) -> Vec<Arc<dyn ProxyHooks>> {
        self.extensions.iter().filter(|e| e.enabled).map(|e| Arc::clone(&e.hooks)).collect()
    }

    pub fn run_request_hooks(&self, svc: &HttpService, method: &str, path: &str, req: &mut Vec<u8>) -> bool {
        run_request_hooks(&self.active(), svc, method, path, req)
    }

    pub fn run_response_hooks(&self, svc: &HttpService, method: &str, path: &str, resp: &mut Vec<u8>) -> bool {
        run_response_hooks(&self.active(), svc, method, path, resp)
    }
}

/// Run request hooks in order; false when one dropped the message.
pub fn run_request_hooks(exts: &[Arc<dyn ProxyHooks>], svc: &HttpService, method: &str, path: &str, req: &mut Vec<u8>) -> bool {
    exts.iter().all(|e| !matches!(e.handle_request_received(svc, method, path, req), ProxyAction::Drop))
}

/// Run response hooks in order; false when one dropped the message.
pub fn run_response_hooks(exts: &[Arc<dyn ProxyHooks>], svc: &HttpService, method: &str, path: &str, resp: &mut Vec<u8>) -> bool {
    exts.iter().all(|e| !matches!(e.handle_response_received(svc, method, path, resp), ProxyAction::Drop))
}

/// Built-in example (QA hook WEBPROBE_EXT_TEST): adds an X-WebProbe-Extension
/// header to every request, so the pipeline run is observable in history.
pub struct ExampleHeaderExtension;

impl ProxyHooks for ExampleHeaderExtension {
    fn extension_name(&self) -> &str {
        "Example header add"
    }
    fn hooks_registered(&self) -> &'static str {
        "ProxyRequestHandler"
    }
    fn handle_request_received(&self, _svc: &crate::ext_host::HttpService, _method: &str, _path: &str, req: &mut Vec<u8>) -> ProxyAction {
        *req = crate::net::replace_or_add_header(req, "X-WebProbe-Extension", "example");
        ProxyAction::Continue
    }
}

// ---------- Path B: sidecar JVM for real Montoya .jar extensions ----------

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use crate::sync::Mutex;

/// Runs a real Burp Montoya .jar extension in a sidecar JVM
/// (`java -cp burpsuite.jar MontoyaBridge.java <ext.jar>`, single-file
/// source mode) and proxies WebProbe's ProxyHooks surface to the
/// extension's ProxyRequestHandler / ProxyResponseHandler via JSON lines.
///
/// v1 scope (mirrors the bridge): extensions initialize, log, and return
/// continue/drop verdicts; the *Received halves run, the *ToBeSent halves
/// do not (WebProbe's hooks have no ToBeSent stage either). If the sidecar
/// dies, hooks degrade to pass-through instead of breaking the proxy.
/// How long a Montoya handler may take on one message before the bridge is
/// stopped (its hooks then pass everything through).
const HOOK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub struct JavaSidecar {
    name: String,
    child: Mutex<Option<Child>>,
    /// Lines to the bridge, written by a writer thread: a bridge that stops
    /// reading must not block a proxy thread on a full pipe.
    to_bridge: Mutex<Option<std::sync::mpsc::Sender<String>>>,
    /// Lines from the bridge, read by a reader thread, so a reply can be
    /// waited for with a deadline.
    from_bridge: Mutex<std::sync::mpsc::Receiver<String>>,
    io_lock: Mutex<()>,
    next_id: AtomicU64,
    dead: AtomicBool,
    /// JVM stderr and bridge errors (last 200 lines) for the Errors pane.
    errors: Arc<Mutex<std::collections::VecDeque<String>>>,
}

fn push_line(errors: &Mutex<std::collections::VecDeque<String>>, line: String) {
    let mut e = errors.lock().unwrap();
    if e.len() >= 200 {
        e.pop_front();
    }
    e.push_back(line);
}

/// Splits a raw HTTP message into `[(name, value), ...]` headers and the
/// body after the first blank line (tolerates \n-only line endings).
fn split_headers_body(raw: &[u8]) -> (Vec<(String, String)>, String) {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| (p, 4))
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|p| (p, 2)));
    let (head, body) = match sep {
        Some((p, n)) => (&raw[..p], raw[p + n..].to_vec()),
        None => (&raw[..], Vec::new()),
    };
    let text = String::from_utf8_lossy(head);
    let mut headers = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue; // request line / status line
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    (headers, String::from_utf8_lossy(&body).into_owned())
}

/// The message a Montoya extension continued with (the bridge reports
/// `"edited":true` with method/path/status, headers and body). The original
/// request target is kept unless the path changed (absolute-form proxy
/// targets survive), and the original body bytes are kept unless the body
/// changed, so binary bodies are not re-encoded; Content-Length follows.
fn apply_bridge_edit(orig: &[u8], reply: &serde_json::Value, request: bool) -> Option<Vec<u8>> {
    if reply.get("edited").and_then(|e| e.as_bool()) != Some(true) {
        return None;
    }
    let s = |k: &str| reply.get(k).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = reply
        .get("headers")?
        .as_array()?
        .iter()
        .filter_map(|h| Some((h.get(0)?.as_str()?.to_string(), h.get(1)?.as_str()?.to_string())))
        .collect();
    let (_, orig_body) = split_headers_body(orig);
    let first_orig = String::from_utf8_lossy(orig.split(|&b| b == b'\n').next().unwrap_or(&[])).trim_end().to_string();
    let version = s("httpVersion");
    let first = if request {
        let mut w = first_orig.split_whitespace();
        let (_, target) = (w.next(), w.next().unwrap_or("/"));
        let orig_path = target.find("://").and_then(|i| target[i + 3..].find('/').map(|j| &target[i + 3 + j..])).unwrap_or(target);
        let path = s("path");
        let target = if path.is_empty() || path == orig_path { target.to_string() } else { path };
        format!("{} {} {}", s("method"), target, if version.is_empty() { "HTTP/1.1" } else { &version })
    } else {
        let status = reply.get("status").and_then(|v| v.as_i64()).unwrap_or(200);
        format!("{} {} {}", if version.is_empty() { "HTTP/1.1" } else { &version }, status, s("reason"))
    };
    let new_body = s("body");
    let body_changed = new_body != orig_body;
    let body: Vec<u8> = if body_changed {
        new_body.into_bytes()
    } else {
        let sep = orig.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).or_else(|| orig.windows(2).position(|w| w == b"\n\n").map(|p| p + 2));
        sep.map(|p| orig[p..].to_vec()).unwrap_or_default()
    };
    let mut out = first.into_bytes();
    // A changed body is sent as one plain body: any chunked coding is gone
    // and Content-Length is set even when the message had none (an extension
    // adding a body to a POST, or editing a chunked response, used to send
    // a message whose framing no longer matched).
    let framing = |k: &str| k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("transfer-encoding");
    for (k, v) in &headers {
        if body_changed && framing(k) {
            continue;
        }
        out.extend_from_slice(format!("\r\n{k}: {v}").as_bytes());
    }
    if body_changed && (!body.is_empty() || headers.iter().any(|(k, _)| framing(k))) {
        out.extend_from_slice(format!("\r\nContent-Length: {}", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(&body);
    Some(out)
}

/// First line of a raw response, e.g. ("HTTP/1.1", 200, "OK").
fn response_status_line(raw: &[u8]) -> (String, i64, String) {
    let head = raw.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let line = String::from_utf8_lossy(head).trim_end().to_string();
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    let status = parts.next().and_then(|s| s.parse().ok()).unwrap_or(200);
    let reason = parts.next().unwrap_or("").to_string();
    (version, status, reason)
}

impl JavaSidecar {
    /// Burp jar carrying the Montoya API classes (override with
    /// WEBPROBE_BURP_JAR).
    pub fn burp_jar() -> String {
        std::env::var("WEBPROBE_BURP_JAR")
            .unwrap_or_else(|_| "/opt/BurpSuite/burpsuite.jar".into())
    }

    /// Launches the sidecar JVM and waits for it to load the extension
    /// (the ping reply only comes back after `initialize()` completed).
    pub fn spawn(ext_jar: &str) -> Result<JavaSidecar, String> {
        let burp_jar = Self::burp_jar();
        let bridge = concat!(env!("CARGO_MANIFEST_DIR"), "/../sidecar/MontoyaBridge.java");
        if !std::path::Path::new(&burp_jar).exists() {
            return Err(format!("Burp jar with the Montoya API not found: {burp_jar}"));
        }
        if !std::path::Path::new(bridge).exists() {
            return Err(format!("Bridge source missing: {bridge}"));
        }
        if !std::path::Path::new(ext_jar).exists() {
            return Err(format!("Extension jar not found: {ext_jar}"));
        }
        let mut child = Command::new("java")
            .arg("-cp")
            .arg(&burp_jar)
            .arg(bridge)
            .arg(ext_jar)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("java launch failed: {e}"))?;
        let errors = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        if let Some(stderr) = child.stderr.take() {
            let errors = Arc::clone(&errors);
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    push_line(&errors, format!("stderr: {line}"));
                }
            });
        }
        let mut stdin = child.stdin.take().ok_or("sidecar stdin unavailable")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("sidecar stdout unavailable")?);
        let (to_bridge, writer_rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in writer_rx {
                if writeln!(stdin, "{line}").and_then(|_| stdin.flush()).is_err() {
                    break;
                }
            }
        });
        let (reader_tx, from_bridge) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in stdout.lines().map_while(Result::ok) {
                if reader_tx.send(line).is_err() {
                    break;
                }
            }
        });
        let file_label = std::path::Path::new(ext_jar)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let sidecar = JavaSidecar {
            name: format!("Montoya bridge ({file_label})"),
            child: Mutex::new(Some(child)),
            to_bridge: Mutex::new(Some(to_bridge)),
            from_bridge: Mutex::new(from_bridge),
            io_lock: Mutex::new(()),
            next_id: AtomicU64::new(1),
            dead: AtomicBool::new(false),
            errors,
        };
        // Loading the jar and running initialize() may take a while; it must
        // not take forever (load_all waits for every extension in turn).
        if let Err(e) = sidecar.ping() {
            // The JVM's own words are the useful part of a load failure.
            std::thread::sleep(std::time::Duration::from_millis(200));
            let tail: Vec<String> = sidecar.errors.lock().unwrap().iter().rev().take(5).rev().cloned().collect();
            return Err(if tail.is_empty() { e } else { format!("{e}; {}", tail.join(" | ")) });
        }
        Ok(sidecar)
    }

    fn ping(&self) -> Result<(), String> {
        // The first ping waits for the JVM to compile the bridge against
        // Burp's jar and run the extension's initialize(): about 20 s on an
        // idle machine, over 60 s under a build. Generous, but bounded.
        let reply = self.exchange(r#"{"type":"ping"}"#, None, std::time::Duration::from_secs(180))?;
        match reply.get("type").and_then(|v| v.as_str()) {
            Some("pong") => Ok(()),
            other => Err(format!("unexpected ping reply: {other:?}")),
        }
    }

    /// One JSON-lines round trip; any failure marks the sidecar dead so the
    /// hooks degrade to pass-through without blocking the pipeline. The reply
    /// must carry `id` (pings have none and answer `{"type":"pong"}`); other
    /// lines are logged and skipped. No reply within `wait` stops the bridge.
    fn exchange(&self, line: &str, id: Option<u64>, wait: std::time::Duration) -> Result<serde_json::Value, String> {
        let _guard = self.io_lock.lock().unwrap();
        if self.dead.load(Ordering::Relaxed) {
            return Err("sidecar is dead".into());
        }
        let mark_dead = |sc: &Self, why: &str| {
            sc.dead.store(true, Ordering::Relaxed);
            push_line(&sc.errors, format!("sidecar stopped ({why}); its hooks now let everything through"));
            sc.kill();
        };
        let sent = self.to_bridge.lock().unwrap().as_ref().is_some_and(|tx| tx.send(line.to_string()).is_ok());
        if !sent {
            mark_dead(self, "stdin closed");
            return Err("sidecar stdin closed".into());
        }
        let deadline = std::time::Instant::now() + wait;
        let rx = self.from_bridge.lock().unwrap();
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match rx.recv_timeout(left) {
                Ok(buf) => {
                    let Ok(reply) = serde_json::from_str::<serde_json::Value>(&buf) else {
                        push_line(&self.errors, format!("stdout: {buf}"));
                        continue;
                    };
                    let matches = match id {
                        Some(id) => reply.get("id").and_then(|v| v.as_u64()) == Some(id),
                        None => reply.get("type").is_some(),
                    };
                    if matches {
                        return Ok(reply);
                    }
                    // A late reply to a message that already timed out.
                    push_line(&self.errors, format!("skipped unmatched reply: {buf}"));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    mark_dead(self, &format!("no reply within {} s", wait.as_secs()));
                    return Err("sidecar did not answer in time".into());
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    mark_dead(self, "stdout closed");
                    return Err("sidecar closed stdout (extension load failure?)".into());
                }
            }
        }
    }

    fn kill(&self) {
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for JavaSidecar {
    fn drop(&mut self) {
        self.kill();
    }
}

impl ProxyHooks for JavaSidecar {
    fn extension_name(&self) -> &str {
        &self.name
    }

    fn hooks_registered(&self) -> &'static str {
        "ProxyRequestHandler + ProxyResponseHandler (sidecar JVM)"
    }

    fn errors(&self) -> Vec<String> {
        self.errors.lock().unwrap().iter().cloned().collect()
    }

    fn healthy(&self) -> bool {
        !self.dead.load(Ordering::Relaxed)
    }

    fn handle_request_received(&self, svc: &crate::ext_host::HttpService, method: &str, path: &str, req: &mut Vec<u8>) -> ProxyAction {
        if self.dead.load(Ordering::Relaxed) {
            return ProxyAction::Continue;
        }
        let (headers, body) = split_headers_body(req);
        // The real service: extensions scope by httpService() and URL.
        let (host, port, secure) = (svc.host.clone(), svc.port, svc.secure);
        let url = if path.contains("://") { path.to_string() } else { format!("{}{path}", svc.origin()) };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let msg = serde_json::json!({
            "type": "request",
            "id": id,
            "method": method,
            "path": path,
            "headers": headers.iter().map(|(k, v)| [k, v]).collect::<Vec<_>>(),
            "body": body,
            "url": url,
            "host": host,
            "port": port,
            "secure": secure,
            "httpVersion": "HTTP/1.1",
        });
        match self.exchange(&msg.to_string(), Some(id), HOOK_TIMEOUT) {
            Ok(reply) if reply.get("action").and_then(|a| a.as_str()) == Some("drop") => {
                ProxyAction::Drop
            }
            Ok(reply) => {
                if let Some(edited) = apply_bridge_edit(req, &reply, true) {
                    *req = edited;
                }
                ProxyAction::Continue
            }
            Err(_) => ProxyAction::Continue, // degrade to pass-through
        }
    }

    fn handle_response_received(&self, svc: &crate::ext_host::HttpService, method: &str, path: &str, resp: &mut Vec<u8>) -> ProxyAction {
        if self.dead.load(Ordering::Relaxed) {
            return ProxyAction::Continue;
        }
        let (headers, body) = split_headers_body(resp);
        let (version, status, reason) = response_status_line(resp);
        // The request's service (a response has no Host header of its own).
        let (host, port, secure) = (svc.host.clone(), svc.port, svc.secure);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let msg = serde_json::json!({
            "type": "response",
            "id": id,
            "method": method,
            "path": path,
            "headers": headers.iter().map(|(k, v)| [k, v]).collect::<Vec<_>>(),
            "body": body,
            "host": host,
            "port": port,
            "secure": secure,
            "httpVersion": version,
            "status": status,
            "reason": reason,
        });
        match self.exchange(&msg.to_string(), Some(id), HOOK_TIMEOUT) {
            Ok(reply) if reply.get("action").and_then(|a| a.as_str()) == Some("drop") => {
                ProxyAction::Drop
            }
            Ok(reply) => {
                if let Some(edited) = apply_bridge_edit(resp, &reply, false) {
                    *resp = edited;
                }
                ProxyAction::Continue
            }
            Err(_) => ProxyAction::Continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Second review, finding 11: an extension's body edit leaves a message
    /// with consistent framing.
    #[test]
    fn bridge_body_edits_reframe_the_message() {
        let orig = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX: 1\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let reply = serde_json::json!({"edited": true, "httpVersion": "HTTP/1.1", "status": 200, "reason": "OK", "body": "hello", "headers": [["Transfer-Encoding", "chunked"], ["X", "1"]]});
        let out = String::from_utf8(apply_bridge_edit(orig, &reply, false).unwrap()).unwrap();
        assert_eq!(out, "HTTP/1.1 200 OK\r\nX: 1\r\nContent-Length: 5\r\n\r\nhello");
        let post = b"POST /a HTTP/1.1\r\nHost: h\r\n\r\n";
        let reply = serde_json::json!({"edited": true, "method": "POST", "path": "/a", "httpVersion": "HTTP/1.1", "body": "x=1", "headers": [["Host", "h"]]});
        let out = String::from_utf8(apply_bridge_edit(post, &reply, true).unwrap()).unwrap();
        assert!(out.ends_with("Host: h\r\nContent-Length: 3\r\n\r\nx=1"), "{out}");
    }

    #[test]
    fn http_service_origin_omits_default_ports() {
        assert_eq!(HttpService::new("h", 443, true).origin(), "https://h");
        assert_eq!(HttpService::new("h", 8443, true).origin(), "https://h:8443");
        assert_eq!(HttpService::new("h", 80, false).origin(), "http://h");
    }

    /// An extension that drops every request and counts invocations.
    struct DropExtension;
    impl ProxyHooks for DropExtension {
        fn extension_name(&self) -> &str {
            "Dropper"
        }
        fn handle_request_received(&self, _svc: &crate::ext_host::HttpService, _: &str, _: &str, _: &mut Vec<u8>) -> ProxyAction {
            ProxyAction::Drop
        }
    }

    /// Records request method/path so the test can prove invocation order.
    struct EchoExtension {
        name: String,
    }
    impl ProxyHooks for EchoExtension {
        fn extension_name(&self) -> &str {
            &self.name
        }
        fn handle_request_received(&self, _svc: &crate::ext_host::HttpService, method: &str, path: &str, req: &mut Vec<u8>) -> ProxyAction {
            req.extend_from_slice(format!("|{method}{path}").as_bytes());
            ProxyAction::Continue
        }
    }

    #[test]
    fn empty_host_lets_everything_through() {
        let host = ExtensionHost::default();
        let mut req = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        assert!(host.run_request_hooks(&crate::ext_host::HttpService::new("qa.test", 80, false), "GET", "/", &mut req));
        assert!(host.run_response_hooks(&crate::ext_host::HttpService::new("qa.test", 80, false), "GET", "/", &mut req));
    }

    #[test]
    fn drop_stops_the_chain_and_later_extensions_do_not_run() {
        let host = ExtensionHost {
            not_loaded: Vec::new(),
            extensions: vec![
                LoadedExtension { enabled: true, hooks: Arc::new(DropExtension), source: None },
                LoadedExtension { enabled: true, hooks: Arc::new(EchoExtension { name: "Second".into() }), source: None },
            ],
        };
        let mut req = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        assert!(!host.run_request_hooks(&crate::ext_host::HttpService::new("qa.test", 80, false), "GET", "/", &mut req));
        assert!(!req.windows(5).any(|w| w == b"|GET/"), "the extension after the Drop never ran");
    }

    #[test]
    fn disabled_extensions_are_skipped() {
        let host = ExtensionHost {
            not_loaded: Vec::new(),
            extensions: vec![
                LoadedExtension { enabled: false, hooks: Arc::new(DropExtension), source: None },
                LoadedExtension { enabled: true, hooks: Arc::new(EchoExtension { name: "Echo".into() }), source: None },
            ],
        };
        let mut req = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        assert!(host.run_request_hooks(&crate::ext_host::HttpService::new("qa.test", 80, false), "GET", "/", &mut req), "the disabled Dropper is skipped");
        assert!(req.windows(5).any(|w| w == b"|GET/"), "the enabled Echo ran and edited the message");
    }

    #[test]
    fn example_extension_adds_its_header() {
        let host = ExtensionHost {
            not_loaded: Vec::new(),
            extensions: vec![LoadedExtension {
                enabled: true,
                hooks: Arc::new(ExampleHeaderExtension),
                source: None,
            }],
        };
        let mut req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        assert!(host.run_request_hooks(&crate::ext_host::HttpService::new("qa.test", 80, false), "GET", "/", &mut req));
        let text = String::from_utf8_lossy(&req);
        assert!(text.contains("X-WebProbe-Extension: example"));
    }

    /// Wave 30: a real Montoya .jar extension runs through the sidecar JVM.
    /// Skipped when the local prerequisites (java, Burp jar, demo-ext.jar)
    /// are absent so the suite stays green on machines without Burp.
    #[test]
    fn java_sidecar_runs_a_real_montoya_extension() {
        let jar = concat!(env!("CARGO_MANIFEST_DIR"), "/../sidecar/demo-ext/demo-ext.jar");
        if !std::path::Path::new(&JavaSidecar::burp_jar()).exists()
            || !std::path::Path::new(jar).exists()
        {
            eprintln!("skipping: sidecar prerequisites missing (Burp jar or demo-ext.jar)");
            return;
        }
        let sidecar = match JavaSidecar::spawn(jar) {
            Ok(s) => s,
            Err(e) if e.contains("java launch failed") => {
                eprintln!("skipping: no java toolchain ({e})");
                return;
            }
            Err(e) => panic!("sidecar spawn failed: {e}"),
        };
        assert_eq!(sidecar.extension_name(), "Montoya bridge (demo-ext.jar)");
        let host = ExtensionHost {
            not_loaded: Vec::new(),
            extensions: vec![LoadedExtension { enabled: true, hooks: Arc::new(sidecar), source: None }],
        };
        // The demo extension drops any path containing "/admin-drop".
        let mut req = b"GET /admin-drop/panel HTTP/1.1\r\nHost: qa.test\r\n\r\n".to_vec();
        assert!(!host.run_request_hooks(&crate::ext_host::HttpService::new("qa.test", 80, false), "GET", "/admin-drop/panel", &mut req));
        // Everything else continues, edited by the extension (withAddedHeader).
        let mut req = b"GET http://qa.test/normal HTTP/1.1\r\nHost: qa.test\r\n\r\n".to_vec();
        assert!(host.run_request_hooks(&crate::ext_host::HttpService::new("qa.test", 80, false), "GET", "/normal", &mut req));
        let text = String::from_utf8_lossy(&req);
        assert!(text.starts_with("GET http://qa.test/normal HTTP/1.1\r\n"), "target kept: {text}");
        assert!(text.contains("\r\nX-Montoya-Demo: 1\r\n"), "{text}");
        // Response hooks run and edit too.
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello".to_vec();
        assert!(host.run_response_hooks(&crate::ext_host::HttpService::new("qa.test", 80, false), "GET", "/normal", &mut resp));
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n") && text.contains("X-Montoya-Seen: 1") && text.ends_with("\r\n\r\nhello"), "{text}");
    }

    /// Rebuilding an edited message keeps binary bodies byte for byte and
    /// restamps Content-Length only when the body changed.
    #[test]
    fn bridge_edits_rebuild_messages() {
        let orig = b"POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\n\xff\x00\x01".to_vec();
        let reply = serde_json::json!({"edited": true, "method": "POST", "path": "/up", "httpVersion": "HTTP/1.1",
            "body": String::from_utf8_lossy(&orig[orig.len() - 3..]), "headers": [["Host", "h"], ["Content-Length", "3"], ["X-A", "1"]]});
        let out = apply_bridge_edit(&orig, &reply, true).unwrap();
        assert!(out.ends_with(b"X-A: 1\r\n\r\n\xff\x00\x01"), "{:?}", String::from_utf8_lossy(&out));
        let reply = serde_json::json!({"edited": true, "method": "PUT", "path": "/other", "httpVersion": "HTTP/1.1",
            "body": "longer body", "headers": [["Host", "h"], ["Content-Length", "3"]]});
        let out = String::from_utf8(apply_bridge_edit(&orig, &reply, true).unwrap()).unwrap();
        assert_eq!(out, "PUT /other HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\nlonger body");
        assert!(apply_bridge_edit(&orig, &serde_json::json!({"action": "continue"}), true).is_none());
    }

    /// Header/body parsing for the sidecar protocol (pure Rust, no JVM).
    #[test]
    fn split_headers_body_parses_request_and_response_shapes() {
        let (hs, body) = split_headers_body(b"GET /x HTTP/1.1\r\nHost: a.test\r\nX-One: 1\r\n\r\npayload");
        assert_eq!(hs, vec![("Host".into(), "a.test".into()), ("X-One".into(), "1".into())]);
        assert_eq!(body, "payload");
        let (ver, status, reason) = response_status_line(b"HTTP/1.1 404 Not Found\r\nX: y\r\n\r\nz");
        assert_eq!((ver.as_str(), status, reason.as_str()), ("HTTP/1.1", 404, "Not Found"));
        // Bodyless message and LF-only tolerance.
        let (hs, body) = split_headers_body(b"GET / HTTP/1.1\r\nHost: b\r\n");
        assert_eq!(hs.len(), 1);
        assert_eq!(body, "");
    }
}
