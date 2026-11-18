// Montoya-shaped extension host.
// Path A (2026-11-15): Burp extensions are in-process plugins that hook the
// message pipeline through the Montoya API (ProxyRequestHandler /
// ProxyResponseHandler). WebProbe is a self-contained Rust binary, so the
// same hook surface is expressed as Rust traits and runs in-process.
// Path B: real Burp Montoya .jar extensions load through a sidecar JVM
// bridge (sidecar/MontoyaBridge.java and the files beside it, Java's
// multi-file source launcher) that runs the extension against the Montoya
// API jar the resource resolver finds and speaks JSON lines over
// stdin/stdout.

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
    /// The request hook with the exchange's annotations (Montoya notes and
    /// highlight), which the extension may change. Defaults to
    /// [`ProxyHooks::handle_request_received`].
    fn handle_request(&self, svc: &crate::ext_host::HttpService, method: &str, path: &str, req: &mut Vec<u8>, _ann: &mut Annotations) -> ProxyAction {
        self.handle_request_received(svc, method, path, req)
    }
    /// The response hook with the request that was sent and the exchange's
    /// annotations. Defaults to [`ProxyHooks::handle_response_received`].
    fn handle_response(&self, svc: &crate::ext_host::HttpService, method: &str, path: &str, _req: &[u8], resp: &mut Vec<u8>, _ann: &mut Annotations) -> ProxyAction {
        self.handle_response_received(svc, method, path, resp)
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

/// Montoya annotations of one exchange: the comment and highlight Proxy
/// history shows. `highlight` indexes Burp's colours in menu order (Red,
/// Orange, Yellow, Green, Cyan, Blue, Pink, Magenta, Gray).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Annotations {
    pub notes: String,
    pub highlight: Option<u8>,
}

/// Montoya `HighlightColor` names, in the order of [`Annotations::highlight`].
pub const HIGHLIGHT_COLOURS: [&str; 9] = ["RED", "ORANGE", "YELLOW", "GREEN", "CYAN", "BLUE", "PINK", "MAGENTA", "GRAY"];

impl Annotations {
    /// The Montoya colour name, if highlighted.
    pub fn colour_name(&self) -> Option<&'static str> {
        self.highlight.and_then(|i| HIGHLIGHT_COLOURS.get(i as usize).copied())
    }

    /// Set the highlight from a Montoya colour name (None / NONE clears it).
    pub fn set_colour(&mut self, name: Option<&str>) {
        self.highlight = name.and_then(|n| HIGHLIGHT_COLOURS.iter().position(|c| c.eq_ignore_ascii_case(n))).map(|i| i as u8);
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
    run_request_hooks_annotated(exts, svc, method, path, req, &mut Annotations::default())
}

/// Run response hooks in order; false when one dropped the message.
pub fn run_response_hooks(exts: &[Arc<dyn ProxyHooks>], svc: &HttpService, method: &str, path: &str, resp: &mut Vec<u8>) -> bool {
    run_response_hooks_annotated(exts, svc, method, path, &[], resp, &mut Annotations::default())
}

/// [`run_request_hooks`] with the exchange's annotations.
pub fn run_request_hooks_annotated(exts: &[Arc<dyn ProxyHooks>], svc: &HttpService, method: &str, path: &str, req: &mut Vec<u8>, ann: &mut Annotations) -> bool {
    exts.iter().all(|e| !matches!(e.handle_request(svc, method, path, req, ann), ProxyAction::Drop))
}

/// [`run_response_hooks`] with the request that was sent and the
/// exchange's annotations.
pub fn run_response_hooks_annotated(exts: &[Arc<dyn ProxyHooks>], svc: &HttpService, method: &str, path: &str, req: &[u8], resp: &mut Vec<u8>, ann: &mut Annotations) -> bool {
    exts.iter().all(|e| !matches!(e.handle_response(svc, method, path, req, resp, ann), ProxyAction::Drop))
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

/// How long a Montoya handler may take on one message before the bridge is
/// stopped (its hooks then pass everything through).
const HOOK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// What a bridged extension may ask of WebProbe: `Http.sendRequest`
/// (through WebProbe's sender, so upstream proxy and session settings
/// apply) and `Logging.raise*Event` (the event log).
pub struct HostLink {
    pub send: Box<dyn Fn(&HttpService, &[u8]) -> Result<Vec<u8>, String> + Send + Sync>,
    pub event: Box<dyn Fn(&str, &str) + Send + Sync>,
}

impl HostLink {
    /// The link to a running WebProbe: sends with [`crate::net::send_raw`] /
    /// `send_tls_raw`, events to the event log. Holds the engine weakly (the
    /// engine owns its extensions).
    pub fn to_shared(shared: &Arc<crate::net::Shared>) -> Arc<HostLink> {
        let (a, b) = (Arc::downgrade(shared), Arc::downgrade(shared));
        Arc::new(HostLink {
            send: Box::new(move |svc, req| {
                let shared = a.upgrade().ok_or("WebProbe is shutting down")?;
                let up = if svc.secure { crate::net::send_tls_raw(&shared, &svc.host, svc.port, req) } else { crate::net::send_raw(&shared, &svc.host, svc.port, req) };
                up.resp.ok_or_else(|| up.error.unwrap_or_else(|| "no response".into()))
            }),
            event: Box::new(move |level, msg| {
                if let Some(shared) = b.upgrade() {
                    shared.log(&format!("Extension event ({level}): {msg}"));
                }
            }),
        })
    }
}

/// A Burp Montoya .jar extension running in a sidecar JVM
/// (`sidecar/MontoyaBridge.java` and the files beside it). See the bridge
/// for what is bridged; everything else fails inside the JVM with
/// "<Interface>.<method> is not supported by WebProbe" on the extension's
/// error output, shown in the Errors pane. If the sidecar dies, hooks
/// degrade to pass-through instead of breaking the proxy.
pub struct JavaSidecar {
    name: String,
    child: Mutex<Option<Child>>,
    /// Lines to the bridge, written by a writer thread: a bridge that stops
    /// reading must not block a proxy thread on a full pipe.
    to_bridge: Mutex<Option<std::sync::mpsc::Sender<String>>>,
    /// Replies from the bridge, read by a reader thread, so a reply can be
    /// waited for with a deadline. sendRequest calls and events are handled
    /// by the reader thread itself.
    from_bridge: Mutex<std::sync::mpsc::Receiver<String>>,
    io_lock: Mutex<()>,
    next_id: AtomicU64,
    dead: AtomicBool,
    /// JVM stderr (the extension's output and errors) and bridge errors,
    /// last 200 lines, for the Errors pane.
    errors: Arc<Mutex<std::collections::VecDeque<String>>>,
}

fn push_line(errors: &Mutex<std::collections::VecDeque<String>>, line: String) {
    let mut e = errors.lock().unwrap();
    if e.len() >= 200 {
        e.pop_front();
    }
    e.push_back(line);
}

impl JavaSidecar {
    /// Launch without a host link (sendRequest fails, events go only to
    /// the Errors pane).
    pub fn spawn(ext_jar: &str) -> Result<JavaSidecar, String> {
        Self::spawn_with(ext_jar, None)
    }

    /// Launches the sidecar JVM and waits for it to load the extension
    /// (the ping reply only comes back after `initialize()` completed).
    pub fn spawn_with(ext_jar: &str, link: Option<Arc<HostLink>>) -> Result<JavaSidecar, String> {
        // The Montoya API classes come from the jar the resolver finds; the
        // bridge is WebProbe's own source, embedded and written out.
        let java = crate::paths::java().map_err(|m| m.to_string())?;
        let api_jar = crate::paths::montoya_jar().map_err(|m| m.to_string())?;
        let bridge = crate::paths::montoya_bridge_source().map_err(|e| format!("could not write the Montoya bridge source: {e}"))?;
        if !std::path::Path::new(ext_jar).exists() {
            return Err(format!("Extension jar not found: {ext_jar}"));
        }
        let mut child = Command::new(java)
            // Extension tabs are not shown (yet); Swing still builds them.
            .arg("-Djava.awt.headless=true")
            .arg("-cp")
            .arg(&api_jar)
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
                    push_line(&errors, line);
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
        {
            let (errors, back) = (Arc::clone(&errors), to_bridge.clone());
            std::thread::spawn(move || {
                for line in stdout.lines().map_while(Result::ok) {
                    let msg: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
                    match msg.get("type").and_then(|t| t.as_str()) {
                        Some("send") => serve_send(&msg, link.clone(), back.clone()),
                        Some("event") => {
                            let (level, text) = (msg["level"].as_str().unwrap_or("info"), msg["message"].as_str().unwrap_or(""));
                            push_line(&errors, format!("[event {level}] {text}"));
                            if let Some(l) = &link {
                                (l.event)(level, text);
                            }
                        }
                        _ => {
                            if reader_tx.send(line).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
        let file_label = std::path::Path::new(ext_jar)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut sidecar = JavaSidecar {
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
        match sidecar.ping() {
            Ok(name) if !name.is_empty() => sidecar.name = format!("{name} ({file_label})"),
            Ok(_) => {}
            Err(e) => {
                // The JVM's own words are the useful part of a load failure.
                std::thread::sleep(std::time::Duration::from_millis(200));
                let tail: Vec<String> = sidecar.errors.lock().unwrap().iter().rev().take(5).rev().cloned().collect();
                return Err(if tail.is_empty() { e } else { format!("{e}; {}", tail.join(" | ")) });
            }
        }
        Ok(sidecar)
    }

    /// The name the extension gave itself (`extension().setName`).
    fn ping(&self) -> Result<String, String> {
        // The first ping waits for the JVM to compile the bridge and run the
        // extension's initialize(): about 20 s on an idle machine, over 60 s
        // under a build. Generous, but bounded.
        let reply = self.exchange(r#"{"type":"ping"}"#, None, std::time::Duration::from_secs(180))?;
        match reply.get("type").and_then(|v| v.as_str()) {
            Some("pong") => Ok(reply.get("name").and_then(|n| n.as_str()).unwrap_or_default().to_string()),
            other => Err(format!("unexpected ping reply: {other:?}")),
        }
    }

    /// Unload the extension: its unloading handlers run, then the JVM
    /// exits (killed after 5 s).
    pub fn unload(&self) {
        if let Some(tx) = self.to_bridge.lock().unwrap().take() {
            let _ = tx.send(r#"{"type":"shutdown"}"#.into());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            let exited = self.child.lock().unwrap().as_mut().is_none_or(|c| c.try_wait().map(|s| s.is_some()).unwrap_or(true));
            if exited {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // Let the stderr reader take the last lines.
        std::thread::sleep(std::time::Duration::from_millis(200));
        self.dead.store(true, Ordering::Relaxed);
        self.kill();
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

    /// One message through the extension's handlers: the verdict, with
    /// `msg` replaced when a handler edited it and `ann` updated.
    fn run(&self, kind: &str, svc: &HttpService, msg: &mut Vec<u8>, req: Option<&[u8]>, ann: &mut Annotations) -> ProxyAction {
        if self.dead.load(Ordering::Relaxed) {
            return ProxyAction::Continue;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut line = serde_json::json!({
            "type": kind,
            "id": id,
            "raw": crate::util::b64_encode(msg),
            "host": svc.host,
            "port": svc.port,
            "secure": svc.secure,
            "tool": "Proxy",
            "notes": ann.notes,
            "highlight": ann.colour_name(),
        });
        if let Some(r) = req {
            line["request"] = serde_json::Value::String(crate::util::b64_encode(r));
        }
        match self.exchange(&line.to_string(), Some(id), HOOK_TIMEOUT) {
            Ok(reply) => {
                if let Some(n) = reply.get("notes").and_then(|n| n.as_str()) {
                    ann.notes = n.to_string();
                }
                ann.set_colour(reply.get("highlight").and_then(|h| h.as_str()));
                if reply.get("action").and_then(|a| a.as_str()) == Some("drop") {
                    return ProxyAction::Drop;
                }
                if let Some(raw) = reply.get("raw").and_then(|r| r.as_str()).and_then(|r| crate::util::b64_decode(r).ok()) {
                    *msg = raw;
                }
                ProxyAction::Continue
            }
            Err(_) => ProxyAction::Continue, // degrade to pass-through
        }
    }
}

/// Answer one `Http.sendRequest` from the bridge on its own thread (the
/// extension may be waiting inside a handler).
fn serve_send(msg: &serde_json::Value, link: Option<Arc<HostLink>>, back: std::sync::mpsc::Sender<String>) {
    let sid = msg.get("sid").and_then(|v| v.as_u64()).unwrap_or(0);
    let svc = HttpService::new(msg["host"].as_str().unwrap_or(""), msg["port"].as_u64().unwrap_or(80) as u16, msg["secure"].as_bool().unwrap_or(false));
    let raw = msg["raw"].as_str().and_then(|r| crate::util::b64_decode(r).ok()).unwrap_or_default();
    std::thread::spawn(move || {
        let result = match &link {
            Some(l) => (l.send)(&svc, &raw),
            None => Err("this extension host has no HTTP sender".into()),
        };
        let reply = match result {
            Ok(resp) => serde_json::json!({"type": "sent", "sid": sid, "raw": crate::util::b64_encode(&resp)}),
            Err(e) => serde_json::json!({"type": "sent", "sid": sid, "error": e}),
        };
        let _ = back.send(reply.to_string());
    });
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
        "Montoya HTTP + Proxy handlers (sidecar JVM)"
    }

    fn errors(&self) -> Vec<String> {
        self.errors.lock().unwrap().iter().cloned().collect()
    }

    fn healthy(&self) -> bool {
        !self.dead.load(Ordering::Relaxed)
    }

    fn handle_request_received(&self, svc: &crate::ext_host::HttpService, method: &str, path: &str, req: &mut Vec<u8>) -> ProxyAction {
        self.handle_request(svc, method, path, req, &mut Annotations::default())
    }

    fn handle_response_received(&self, svc: &crate::ext_host::HttpService, method: &str, path: &str, resp: &mut Vec<u8>) -> ProxyAction {
        self.handle_response(svc, method, path, &[], resp, &mut Annotations::default())
    }

    fn handle_request(&self, svc: &crate::ext_host::HttpService, _method: &str, _path: &str, req: &mut Vec<u8>, ann: &mut Annotations) -> ProxyAction {
        self.run("request", svc, req, None, ann)
    }

    fn handle_response(&self, svc: &crate::ext_host::HttpService, _method: &str, _path: &str, req: &[u8], resp: &mut Vec<u8>, ann: &mut Annotations) -> ProxyAction {
        self.run("response", svc, resp, Some(req), ann)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        if crate::paths::montoya_jar().is_err()
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

    /// Compile one of `sidecar/stage-tests` into a fresh class directory
    /// with its BurpExtension service entry; None (test skipped) without a
    /// JDK or a Montoya API jar.
    fn stage_extension(name: &str) -> Option<std::path::PathBuf> {
        let api = crate::paths::montoya_jar().ok()?;
        let java = crate::paths::java().ok()?;
        let javac = [java.with_file_name("javac"), std::fs::canonicalize(&java).ok()?.with_file_name("javac")].into_iter().find(|p| p.is_file())?;
        let dir = std::env::temp_dir().join(format!("wp-stage-{name}-{}-{}", std::process::id(), crate::util::now_secs()));
        std::fs::create_dir_all(dir.join("META-INF/services")).ok()?;
        std::fs::write(dir.join("META-INF/services/burp.api.montoya.BurpExtension"), format!("{name}\n")).ok()?;
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/../sidecar/stage-tests/").to_string() + name + ".java";
        let ok = Command::new(javac).arg("-nowarn").arg("-cp").arg(&api).arg("-d").arg(&dir).arg(src).status().ok()?.success();
        assert!(ok, "javac failed on {name}");
        Some(dir)
    }

    /// R-03 stage 1: setName, the unloading handler, every logging()
    /// channel, burpSuite(), and Unsupported for what is not bridged.
    #[test]
    fn stage1_extension_loads_logs_and_unloads() {
        let Some(dir) = stage_extension("Stage1Extension") else {
            eprintln!("skipping: no JDK or Montoya API jar");
            return;
        };
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = Arc::clone(&events);
        let link = Arc::new(HostLink { send: Box::new(|_, _| Err("unused".into())), event: Box::new(move |l, m| seen.lock().unwrap().push(format!("{l}: {m}"))) });
        let sc = JavaSidecar::spawn_with(dir.to_str().unwrap(), Some(link)).expect("stage 1 loads");
        let dir_name = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(sc.extension_name(), format!("Stage One ({dir_name})"));
        sc.unload();
        let log = sc.errors();
        for want in [
            format!("[out] filename={dir_name} bapp=false"),
            "[error] an error line".into(),
            "[out] via output stream".into(),
            "[out] version=WebProbe edition=COMMUNITY_EDITION".into(),
            "[out] state=PAUSED args=0".into(),
            "[out] caught: MontoyaApi.persistence is not supported by WebProbe".into(),
            "[out] caught: BurpSuite.exportProjectOptionsAsJson is not supported by WebProbe".into(),
            "[event info] stage1 event".into(),
            "[out] stage1 unloaded".into(),
        ] {
            assert!(log.contains(&want), "missing {want:?} in {log:#?}");
        }
        assert_eq!(log.iter().filter(|l| *l == "[error] MontoyaApi.persistence is not supported by WebProbe").count(), 1, "reported once");
        assert!(events.lock().unwrap().contains(&"info: stage1 event".to_string()));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// R-03 stage 2: an HTTP handler that edits and annotates requests,
    /// round-trips Http.sendRequest through WebProbe's sender to a loopback
    /// responder, and edits responses; the annotations reach the history
    /// entry.
    #[test]
    fn stage2_http_handler_edits_annotates_and_sends() {
        let Some(dir) = stage_extension("Stage2Extension") else {
            eprintln!("skipping: no JDK or Montoya API jar");
            return;
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match std::io::Read::read(&mut s, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong");
            }
        });
        let shared = crate::net::Shared::new();
        let sc = JavaSidecar::spawn_with(dir.to_str().unwrap(), Some(HostLink::to_shared(&shared))).expect("stage 2 loads");
        let exts: Vec<Arc<dyn ProxyHooks>> = vec![Arc::new(sc)];
        let svc = HttpService::new("qa.test", 80, false);
        let mut ann = Annotations::default();
        let mut req = format!("GET /a?body=x HTTP/1.1\r\nHost: qa.test\r\nX-Target-Port: {port}\r\n\r\n").into_bytes();
        assert!(run_request_hooks_annotated(&exts, &svc, "GET", "/a?body=x", &mut req, &mut ann));
        let text = String::from_utf8_lossy(&req).into_owned();
        assert!(text.starts_with("GET /a?body=x HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("\r\nX-Stage2: Proxy GET /a\r\n") && text.contains("\r\nX-Sent: 200 pong\r\n"), "{text}");
        assert!(!text.contains("X-Target-Port"), "{text}");
        assert!(text.ends_with("Content-Length: 8\r\n\r\nedited=x"), "withBody keeps Content-Length right: {text}");
        assert_eq!(ann, Annotations { notes: "seen by stage2".into(), highlight: Some(4) }, "CYAN");
        let mut resp = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\n\r\nok".to_vec();
        assert!(run_response_hooks_annotated(&exts, &svc, "GET", "/a?body=x", &req, &mut resp, &mut ann));
        assert_eq!(String::from_utf8_lossy(&resp), "HTTP/1.1 200 OK\r\nServer: stage2 saw /a?body=x\r\nContent-Length: 2\r\n\r\nok");
        assert_eq!(ann.notes, "seen by stage2; response 200");
        // As Proxy history shows it.
        let mut e = crate::net::HistEntry { note: Some("upstream note".into()), ..Default::default() };
        crate::net::annotate(&mut e, &ann);
        assert_eq!((e.note.as_deref(), e.highlight), (Some("upstream note; seen by stage2; response 200"), Some(4)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn annotation_colours_follow_burps_order() {
        let mut a = Annotations::default();
        a.set_colour(Some("magenta"));
        assert_eq!((a.highlight, a.colour_name()), (Some(7), Some("MAGENTA")));
        a.set_colour(Some("NONE"));
        assert_eq!(a.highlight, None);
        a.set_colour(None);
        assert_eq!(a.colour_name(), None);
    }

}
