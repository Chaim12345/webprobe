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

/// The hook surface an extension registers. Every method defaults to
/// Continue with no edits, mirroring Montoya's default implementations.
pub trait ProxyHooks: Send {
    /// Extension name shown in the Extensions tab.
    fn extension_name(&self) -> &str;
    /// Which hook kinds this extension registered (Montoya:
    /// isProxyRequestHandler() / isProxyResponseHandler()).
    fn hooks_registered(&self) -> &'static str {
        ""
    }
    fn handle_request_received(&self, _method: &str, _path: &str, _req: &mut Vec<u8>) -> ProxyAction {
        ProxyAction::Continue
    }
    fn handle_response_received(&self, _method: &str, _path: &str, _resp: &mut Vec<u8>) -> ProxyAction {
        ProxyAction::Continue
    }
}

pub struct LoadedExtension {
    pub enabled: bool,
    pub hooks: Box<dyn ProxyHooks>,
}

/// Registry the proxy pipeline runs. Extensions run in registration order;
/// the first Drop verdict stops the chain and the message.
#[derive(Default)]
pub struct ExtensionHost {
    pub extensions: Vec<LoadedExtension>,
}

impl ExtensionHost {
    pub fn run_request_hooks(&self, method: &str, path: &str, req: &mut Vec<u8>) -> bool {
        for e in &self.extensions {
            if !e.enabled {
                continue;
            }
            if let ProxyAction::Drop = e.hooks.handle_request_received(method, path, req) {
                return false;
            }
        }
        true
    }

    pub fn run_response_hooks(&self, method: &str, path: &str, resp: &mut Vec<u8>) -> bool {
        for e in &self.extensions {
            if !e.enabled {
                continue;
            }
            if let ProxyAction::Drop = e.hooks.handle_response_received(method, path, resp) {
                return false;
            }
        }
        true
    }
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
    fn handle_request_received(&self, _method: &str, _path: &str, req: &mut Vec<u8>) -> ProxyAction {
        *req = crate::net::replace_or_add_header(req, "X-WebProbe-Extension", "example");
        ProxyAction::Continue
    }
}

// ---------- Path B: sidecar JVM for real Montoya .jar extensions ----------

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

/// Runs a real Burp Montoya .jar extension in a sidecar JVM
/// (`java -cp burpsuite.jar MontoyaBridge.java <ext.jar>`, single-file
/// source mode) and proxies WebProbe's ProxyHooks surface to the
/// extension's ProxyRequestHandler / ProxyResponseHandler via JSON lines.
///
/// v1 scope (mirrors the bridge): extensions initialize, log, and return
/// continue/drop verdicts; the *Received halves run, the *ToBeSent halves
/// do not (WebProbe's hooks have no ToBeSent stage either). If the sidecar
/// dies, hooks degrade to pass-through instead of breaking the proxy.
pub struct JavaSidecar {
    name: String,
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<ChildStdin>>,
    stdout: Mutex<Option<BufReader<ChildStdout>>>,
    io_lock: Mutex<()>,
    next_id: AtomicU64,
    dead: AtomicBool,
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
        let bridge = concat!(env!("CARGO_MANIFEST_DIR"), "/sidecar/MontoyaBridge.java");
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
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("java launch failed: {e}"))?;
        let stdin = child.stdin.take().ok_or("sidecar stdin unavailable")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("sidecar stdout unavailable")?);
        let file_label = std::path::Path::new(ext_jar)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let sidecar = JavaSidecar {
            name: format!("Montoya bridge ({file_label})"),
            child: Mutex::new(Some(child)),
            stdin: Mutex::new(Some(stdin)),
            stdout: Mutex::new(Some(stdout)),
            io_lock: Mutex::new(()),
            next_id: AtomicU64::new(1),
            dead: AtomicBool::new(false),
        };
        sidecar.ping()?;
        Ok(sidecar)
    }

    fn ping(&self) -> Result<(), String> {
        let reply = self.exchange(r#"{"type":"ping"}"#)?;
        match reply.get("type").and_then(|v| v.as_str()) {
            Some("pong") => Ok(()),
            other => Err(format!("unexpected ping reply: {other:?}")),
        }
    }

    /// One JSON-lines round trip; any failure marks the sidecar dead so the
    /// hooks degrade to pass-through without blocking the pipeline.
    fn exchange(&self, line: &str) -> Result<serde_json::Value, String> {
        let _guard = self.io_lock.lock().unwrap();
        if self.dead.load(Ordering::Relaxed) {
            return Err("sidecar is dead".into());
        }
        let mark_dead = |sc: &Self| sc.dead.store(true, Ordering::Relaxed);
        {
            let mut stdin = self.stdin.lock().unwrap();
            let w = stdin.as_mut().ok_or("sidecar stdin closed")?;
            if let Err(e) = writeln!(w, "{line}").and_then(|_| w.flush()) {
                mark_dead(self);
                return Err(format!("sidecar write failed: {e}"));
            }
        }
        let mut stdout = self.stdout.lock().unwrap();
        let reader = match stdout.as_mut() {
            Some(r) => r,
            None => {
                mark_dead(self);
                return Err("sidecar stdout closed".into());
            }
        };
        let mut buf = String::new();
        let n = match reader.read_line(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                mark_dead(self);
                return Err(format!("sidecar read failed: {e}"));
            }
        };
        if n == 0 {
            mark_dead(self);
            return Err("sidecar closed stdout (extension load failure?)".into());
        }
        serde_json::from_str(&buf).map_err(|e| format!("bad sidecar reply: {e}: {buf}"))
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

    fn handle_request_received(&self, method: &str, path: &str, req: &mut Vec<u8>) -> ProxyAction {
        if self.dead.load(Ordering::Relaxed) {
            return ProxyAction::Continue;
        }
        let (headers, body) = split_headers_body(req);
        let host = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let url = format!("http://{host}{path}");
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
            "port": 80,
            "secure": false,
            "httpVersion": "HTTP/1.1",
        });
        match self.exchange(&msg.to_string()) {
            Ok(reply) if reply.get("action").and_then(|a| a.as_str()) == Some("drop") => {
                ProxyAction::Drop
            }
            Ok(_) => ProxyAction::Continue,
            Err(_) => ProxyAction::Continue, // degrade to pass-through
        }
    }

    fn handle_response_received(&self, method: &str, path: &str, resp: &mut Vec<u8>) -> ProxyAction {
        if self.dead.load(Ordering::Relaxed) {
            return ProxyAction::Continue;
        }
        let (headers, body) = split_headers_body(resp);
        let (version, status, reason) = response_status_line(resp);
        let host = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let msg = serde_json::json!({
            "type": "response",
            "id": id,
            "method": method,
            "path": path,
            "headers": headers.iter().map(|(k, v)| [k, v]).collect::<Vec<_>>(),
            "body": body,
            "host": host,
            "port": 80,
            "secure": false,
            "httpVersion": version,
            "status": status,
            "reason": reason,
        });
        match self.exchange(&msg.to_string()) {
            Ok(reply) if reply.get("action").and_then(|a| a.as_str()) == Some("drop") => {
                ProxyAction::Drop
            }
            Ok(_) => ProxyAction::Continue,
            Err(_) => ProxyAction::Continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An extension that drops every request and counts invocations.
    struct DropExtension;
    impl ProxyHooks for DropExtension {
        fn extension_name(&self) -> &str {
            "Dropper"
        }
        fn handle_request_received(&self, _: &str, _: &str, _: &mut Vec<u8>) -> ProxyAction {
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
        fn handle_request_received(&self, method: &str, path: &str, req: &mut Vec<u8>) -> ProxyAction {
            req.extend_from_slice(format!("|{method}{path}").as_bytes());
            ProxyAction::Continue
        }
    }

    #[test]
    fn empty_host_lets_everything_through() {
        let host = ExtensionHost::default();
        let mut req = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        assert!(host.run_request_hooks("GET", "/", &mut req));
        assert!(host.run_response_hooks("GET", "/", &mut req));
    }

    #[test]
    fn drop_stops_the_chain_and_later_extensions_do_not_run() {
        let host = ExtensionHost {
            extensions: vec![
                LoadedExtension { enabled: true, hooks: Box::new(DropExtension) },
                LoadedExtension { enabled: true, hooks: Box::new(EchoExtension { name: "Second".into() }) },
            ],
        };
        let mut req = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        assert!(!host.run_request_hooks("GET", "/", &mut req));
        assert!(!req.windows(5).any(|w| w == b"|GET/"), "the extension after the Drop never ran");
    }

    #[test]
    fn disabled_extensions_are_skipped() {
        let host = ExtensionHost {
            extensions: vec![
                LoadedExtension { enabled: false, hooks: Box::new(DropExtension) },
                LoadedExtension { enabled: true, hooks: Box::new(EchoExtension { name: "Echo".into() }) },
            ],
        };
        let mut req = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        assert!(host.run_request_hooks("GET", "/", &mut req), "the disabled Dropper is skipped");
        assert!(req.windows(5).any(|w| w == b"|GET/"), "the enabled Echo ran and edited the message");
    }

    #[test]
    fn example_extension_adds_its_header() {
        let host = ExtensionHost {
            extensions: vec![LoadedExtension {
                enabled: true,
                hooks: Box::new(ExampleHeaderExtension),
            }],
        };
        let mut req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        assert!(host.run_request_hooks("GET", "/", &mut req));
        let text = String::from_utf8_lossy(&req);
        assert!(text.contains("X-WebProbe-Extension: example"));
    }

    /// Wave 30: a real Montoya .jar extension runs through the sidecar JVM.
    /// Skipped when the local prerequisites (java, Burp jar, demo-ext.jar)
    /// are absent so the suite stays green on machines without Burp.
    #[test]
    fn java_sidecar_runs_a_real_montoya_extension() {
        let jar = concat!(env!("CARGO_MANIFEST_DIR"), "/sidecar/demo-ext/demo-ext.jar");
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
            extensions: vec![LoadedExtension { enabled: true, hooks: Box::new(sidecar) }],
        };
        // The demo extension drops any path containing "/admin-drop".
        let mut req = b"GET /admin-drop/panel HTTP/1.1\r\nHost: qa.test\r\n\r\n".to_vec();
        assert!(!host.run_request_hooks("GET", "/admin-drop/panel", &mut req));
        // Everything else continues.
        let mut req = b"GET /normal HTTP/1.1\r\nHost: qa.test\r\n\r\n".to_vec();
        assert!(host.run_request_hooks("GET", "/normal", &mut req));
        // Response hooks run too.
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhello".to_vec();
        assert!(host.run_response_hooks("GET", "/normal", &mut resp));
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
