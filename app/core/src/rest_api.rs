//! R-15: Burp's REST API (resources/Documentation/rest-api): POST
//! `/v0.1/scan` starts a crawl-and-audit of the given URLs, GET
//! `/v0.1/scan/{task_id}` reports the task status and the issues it has
//! found so far, and GET `/v0.1/knowledge_base/issue_definitions` lists
//! the issue types WebProbe knows.
//!
//! The listener comes from `user_options.misc.api` (see
//! `burp_config::ApiConfig`): Burp's defaults are loopback only
//! (127.0.0.1), port 1337, and an API key required. Unless
//! `insecure_mode` is set the base path carries the key, like Burp:
//! `/{key}/v0.1/scan`. The key is never written to any log or response.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::burp_config::ApiConfig;
use crate::net;
use crate::scan;

/// One issue definition for GET `/v0.1/knowledge_base/issue_definitions`.
/// Carried as plain data so the core crate does not depend on
/// webprobe-report (which is downstream of core); callers convert from
/// `webprobe_report::report::KnowledgeBase`
/// (`KnowledgeBase::rest_api_definitions`).
#[derive(Clone, Debug, Default)]
pub struct IssueDefinition {
    pub type_index: u64,
    pub name: String,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub references: Option<String>,
    pub vulnerability_classifications: Option<String>,
}

/// One scan task started over the API.
struct ApiTask {
    /// `running`, `succeeded` or `failed` (Burp's scan_status words).
    status: String,
    /// shared.issues is append-only: this task's issues start here.
    first_issue: usize,
    /// Set when the task finishes: issues appended later are not its own.
    end_issue: Option<usize>,
    /// Hosts of the URLs the task was asked to scan (lowercase). The issue
    /// list is process-wide; while the task runs, only issues on these hosts
    /// are reported as its findings.
    hosts: Vec<String>,
}

/// The host of a URL or of an issue's host field (scheme, port, path and
/// userinfo removed), lowercase.
fn host_only(s: &str) -> String {
    let rest = s.split_once("://").map_or(s, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };
    host.to_ascii_lowercase()
}

struct ApiState {
    tasks: Vec<ApiTask>,
}

const MAX_API_CLIENTS: usize = 32;
const MAX_API_TASKS: usize = 256;
const MAX_SCAN_URLS: usize = 1024;
const MAX_SCAN_URL_LENGTH: usize = 8192;

#[derive(Debug, PartialEq, Eq)]
enum TaskAdmissionError {
    ScanAlreadyRunning,
    HistoryFull,
}

fn reserve_task(
    state: &mut ApiState,
    first_issue: usize,
    hosts: Vec<String>,
) -> Result<usize, TaskAdmissionError> {
    if state.tasks.iter().any(|task| task.status == "running") {
        return Err(TaskAdmissionError::ScanAlreadyRunning);
    }
    if state.tasks.len() >= MAX_API_TASKS {
        return Err(TaskAdmissionError::HistoryFull);
    }
    let id = state.tasks.len();
    state.tasks.push(ApiTask {
        status: "running".to_string(),
        first_issue,
        end_issue: None,
        hosts,
    });
    Ok(id)
}

fn listen_address(api: &ApiConfig) -> Result<SocketAddr, String> {
    let (mode, default_host) = match api.listen_mode.as_str() {
        "loopback_only" => ("loopback_only", "127.0.0.1"),
        "all_interfaces" => ("all_interfaces", "0.0.0.0"),
        other => {
            return Err(format!(
                "user_options.misc.api listen_mode `{other}` is not supported"
            ));
        }
    };
    let host = api.address.as_deref().unwrap_or(default_host);
    let addresses = (host, api.port)
        .to_socket_addrs()
        .map_err(|e| format!("REST API cannot resolve {host}: {e}"))?;
    let address = if mode == "loopback_only" {
        addresses.into_iter().find(|addr| addr.ip().is_loopback())
    } else {
        addresses.into_iter().next()
    };
    address.ok_or_else(|| {
        if mode == "loopback_only" {
            format!("REST API loopback_only address {host} does not resolve to a loopback IP")
        } else {
            format!("REST API address {host} did not resolve")
        }
    })
}

fn acquire_client_slot(active: &AtomicUsize) -> bool {
    let mut count = active.load(Ordering::Acquire);
    loop {
        if count >= MAX_API_CLIENTS {
            return false;
        }
        match active.compare_exchange_weak(count, count + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(current) => count = current,
        }
    }
}

struct ClientSlot(Arc<AtomicUsize>);

impl Drop for ClientSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Start the REST API from the user options. Returns the actual bound socket
/// address so callers do not guess the interface from listen_mode.
/// Refuses to start without a key on a non-loopback address, whatever
/// insecure_mode says, and when a key is required but none is configured: Burp
/// shows the generated key in its UI; a headless process has nowhere safe
/// to show it, and the key is never logged.
pub fn start(
    shared: &Arc<net::Shared>,
    api: &ApiConfig,
    issue_definitions: Vec<IssueDefinition>,
) -> Result<SocketAddr, String> {
    if !api.insecure_mode && api.keys.is_empty() {
        return Err(
            "user_options.misc.api is enabled with no keys and insecure_mode false; refusing to start without an API key"
                .to_string(),
        );
    }
    let address = listen_address(api)?;
    let listener = TcpListener::bind(address)
        .map_err(|e| format!("REST API cannot listen on {address}: {e}"))?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    // Decided on the actual socket, including an address override. An
    // options file (imported in the UI or given at startup) must not be able
    // to open a scan-control endpoint to the network with no credential.
    // insecure_mode skips the key check on every request, so it is refused
    // too, even when keys are configured.
    if (api.insecure_mode || api.keys.is_empty()) && !bound.ip().is_loopback() {
        return Err(format!(
            "REST API refused: {bound} is not a loopback address and requests would not be authenticated (insecure_mode is on or no API key is configured); turn insecure_mode off and add a key, or listen on loopback"
        ));
    }
    let state = Arc::new(Mutex::new(ApiState { tasks: Vec::new() }));
    let shared = shared.clone();
    let api = api.clone();
    let defs = Arc::new(issue_definitions);
    let active_clients = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        // Keep idle/slow clients from blocking the accept loop, but bound the
        // number of client threads so unauthenticated sockets cannot exhaust it.
        for stream in listener.incoming().flatten() {
            if !acquire_client_slot(&active_clients) {
                drop(stream);
                continue;
            }
            let (shared, state, api, defs) = (
                shared.clone(),
                Arc::clone(&state),
                api.clone(),
                Arc::clone(&defs),
            );
            let slot = Arc::clone(&active_clients);
            std::thread::spawn(move || {
                let _slot = ClientSlot(slot);
                handle(stream, &shared, &state, &api, &defs);
            });
        }
    });
    Ok(bound)
}

fn handle(
    mut stream: std::net::TcpStream,
    shared: &Arc<net::Shared>,
    state: &Arc<Mutex<ApiState>>,
    api: &ApiConfig,
    defs: &[IssueDefinition],
) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
    let Some((method, path, body)) = read_request(&mut stream) else {
        return;
    };
    let Some(rest) = authorized(api, &path) else {
        // The error never echoes the attempted path: it may carry a key.
        return respond(
            &mut stream,
            403,
            "Forbidden",
            json!({"error": "a valid API key is required"}),
        );
    };
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    match (method.as_str(), segments.as_slice()) {
        ("POST", ["v0.1", "scan"]) => start_scan(&mut stream, shared, state, &body),
        ("GET", ["v0.1", "scan", id]) => scan_status(&mut stream, shared, state, id),
        ("GET", ["v0.1", "knowledge_base", "issue_definitions"]) => {
            respond(&mut stream, 200, "OK", issue_definitions(defs))
        }
        _ => respond(
            &mut stream,
            404,
            "Not Found",
            json!({"error": "unknown endpoint"}),
        ),
    }
}

/// The key is a path prefix (Burp's API style). Returns the path without
/// the key prefix when authorized. With insecure_mode every path passes.
fn authorized(api: &ApiConfig, path: &str) -> Option<String> {
    if api.insecure_mode {
        return Some(path.to_string());
    }
    for key in &api.keys {
        let with_slash = format!("/{key}/");
        if let Some(rest) = path.strip_prefix(&with_slash) {
            return Some(format!("/{rest}"));
        }
        if path == format!("/{key}") {
            return Some("/".to_string());
        }
    }
    None
}

fn start_scan(
    stream: &mut std::net::TcpStream,
    shared: &Arc<net::Shared>,
    state: &Arc<Mutex<ApiState>>,
    body: &[u8],
) {
    let parsed: Result<Value, _> = serde_json::from_slice(body);
    let urls: Vec<String> = parsed
        .ok()
        .and_then(|v| {
            v.get("urls")?.as_array().map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
        })
        .unwrap_or_default();
    if urls.is_empty() {
        return respond(
            stream,
            400,
            "Bad Request",
            json!({"error": "a non-empty `urls` array is required"}),
        );
    }
    if urls.len() > MAX_SCAN_URLS || urls.iter().any(|url| url.len() > MAX_SCAN_URL_LENGTH) {
        return respond(
            stream,
            413,
            "Payload Too Large",
            json!({
                "error": format!(
                    "scan accepts at most {MAX_SCAN_URLS} URLs, each no longer than {MAX_SCAN_URL_LENGTH} bytes"
                )
            }),
        );
    }
    let first_issue = shared.issues.lock().unwrap().len();
    let id = {
        let mut st = state.lock().unwrap();
        let mut hosts: Vec<String> = urls.iter().map(|u| host_only(u)).collect();
        hosts.sort();
        hosts.dedup();
        match reserve_task(&mut st, first_issue, hosts) {
            Ok(id) => id,
            Err(TaskAdmissionError::ScanAlreadyRunning) => {
                return respond(
                    stream,
                    409,
                    "Conflict",
                    json!({"error": "a scan is already running"}),
                );
            }
            Err(TaskAdmissionError::HistoryFull) => {
                return respond(
                    stream,
                    429,
                    "Too Many Requests",
                    json!({"error": "scan task history is full; restart webprobe to clear it"}),
                );
            }
        }
    };
    let shared2 = shared.clone();
    let state2 = state.clone();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scan::crawl_and_audit(&shared2, &urls, true);
            shared2.scan.wait_idle(None);
        }));
        let end_issue = shared2.issues.lock().unwrap().len();
        let mut st = state2.lock().unwrap();
        st.tasks[id].end_issue = Some(end_issue);
        st.tasks[id].status = if result.is_ok() {
            "succeeded".to_string()
        } else {
            "failed".to_string()
        };
    });
    // Burp answers 201 with the task id in the Location header.
    let body = json!({"task_id": id.to_string()}).to_string();
    let head = format!(
        "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\nlocation: /v0.1/scan/{id}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

fn scan_status(
    stream: &mut std::net::TcpStream,
    shared: &Arc<net::Shared>,
    state: &Arc<Mutex<ApiState>>,
    id: &str,
) {
    let Ok(n) = id.parse::<usize>() else {
        return respond(stream, 404, "Not Found", json!({"error": "unknown task"}));
    };
    let st = state.lock().unwrap();
    let Some(task) = st.tasks.get(n) else {
        return respond(stream, 404, "Not Found", json!({"error": "unknown task"}));
    };
    let status = task.status.clone();
    let first_issue = task.first_issue;
    let end_issue = task.end_issue;
    let hosts = task.hosts.clone();
    drop(st);
    let events: Vec<Value> = {
        let issues = shared.issues.lock().unwrap();
        let end = end_issue.map_or(issues.len(), |end| end.min(issues.len()));
        let start = first_issue.min(end);
        issues[start..end]
            .iter()
            .enumerate()
            // Issues on other hosts come from other activity (live proxy
            // audit, manual findings) that shares the process-wide list.
            .filter(|(_, issue)| hosts.contains(&host_only(&issue.host)))
            // The position in the append-only list: stable across polls.
            .map(|(i, issue)| {
                json!({"serial_number": start + i, "type": "issue_found", "issue": issue_json(issue)})
            })
            .collect()
    };
    respond(
        stream,
        200,
        "OK",
        json!({"task_id": n.to_string(), "scan_status": status, "issue_events": events}),
    )
}

/// Burp's issue object (legacy /v0.1 shape): the name, the capitalized
/// severity and confidence, host, path and the numeric type index.
fn issue_json(i: &scan::ScanIssue) -> Value {
    let severity = match i.sev.as_str() {
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Information",
    };
    json!({
        "confidence": i.confidence,
        "host": i.host,
        "name": i.name,
        "path": i.path,
        "severity": severity,
        "type_index": i.type_id,
    })
}

/// GET /v0.1/knowledge_base/issue_definitions: Burp returns one entry per
/// issue type. Sorted by name for a stable response.
fn issue_definitions(defs: &[IssueDefinition]) -> Value {
    let mut entries: Vec<&IssueDefinition> = defs.iter().collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Value::Array(
        entries
            .into_iter()
            .map(|e| {
                json!({
                    "name": e.name,
                    "type_index": e.type_index,
                    "description": e.description,
                    "remediation": e.remediation,
                    "references": e.references,
                    "vulnerability_classifications": e.vulnerability_classifications,
                })
            })
            .collect(),
    )
}

fn respond(stream: &mut std::net::TcpStream, code: u16, reason: &str, body: Value) {
    let body = body.to_string();
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

/// Read one HTTP/1.1 request: request line, headers, Content-Length body.
/// Chunked bodies are not part of Burp's simple client contract; a client
/// sending one gets no response (the connection closes on the timeout).
fn read_request(stream: &mut std::net::TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let mut parts = lines.next()?.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let content_length = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    // a client may claim any length; the API's payloads are scan configs
    // and keys, so anything past this is an error, not a bigger buffer
    const MAX_BODY: usize = 8 * 1024 * 1024;
    if content_length > MAX_BODY {
        return None;
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Some((method, path, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::burp_config::ApiConfig;

    fn test_defs() -> Vec<IssueDefinition> {
        vec![IssueDefinition {
            type_index: 0x0010_0200,
            name: "SQL injection".to_string(),
            description: Some("bg".to_string()),
            ..Default::default()
        }]
    }

    fn start_test_server(api: &ApiConfig) -> (Arc<net::Shared>, u16) {
        let shared = net::Shared::new();
        let address = start(&shared, api, test_defs()).unwrap();
        (shared, address.port())
    }

    /// One raw request; returns (status code, body as JSON).
    fn request(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, Value) {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let body = body.unwrap_or_default();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).unwrap();
        let text = String::from_utf8_lossy(&resp).to_string();
        let code: u16 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
        let json: Value = serde_json::from_str(text.split("\r\n\r\n").nth(1).unwrap_or("{}"))
            .unwrap_or(Value::Null);
        (code, json)
    }

    #[test]
    fn loopback_only_rejects_non_loopback_address_overrides() {
        let mut api = keyed_api();
        api.listen_mode = "loopback_only".to_string();
        api.address = Some("0.0.0.0".to_string());
        assert!(listen_address(&api).is_err());
        api.address = Some("192.0.2.10".to_string());
        assert!(listen_address(&api).is_err());
        api.address = Some("127.0.0.1".to_string());
        assert!(listen_address(&api).unwrap().ip().is_loopback());
    }

    #[test]
    fn api_client_slots_and_scan_tasks_are_bounded() {
        let active = AtomicUsize::new(0);
        for _ in 0..MAX_API_CLIENTS {
            assert!(acquire_client_slot(&active));
        }
        assert!(!acquire_client_slot(&active));
        active.fetch_sub(1, Ordering::AcqRel);
        assert!(acquire_client_slot(&active));

        let mut state = ApiState { tasks: Vec::new() };
        assert_eq!(reserve_task(&mut state, 0, Vec::new()), Ok(0));
        assert_eq!(
            reserve_task(&mut state, 0, Vec::new()),
            Err(TaskAdmissionError::ScanAlreadyRunning)
        );
        state.tasks[0].status = "succeeded".to_string();
        for _ in 1..MAX_API_TASKS {
            assert!(reserve_task(&mut state, 0, Vec::new()).is_ok());
            let last = state.tasks.last_mut().unwrap();
            last.status = "succeeded".to_string();
        }
        assert_eq!(
            reserve_task(&mut state, 0, Vec::new()),
            Err(TaskAdmissionError::HistoryFull)
        );
    }

    #[test]
    fn idle_client_does_not_stall_other_requests() {
        let api = keyed_api();
        let (_shared, port) = start_test_server(&api);
        let key = api.keys[0].clone();
        // first client connects and sends nothing: before per-connection
        // threads, everyone else queued behind its read timeout
        let _idle = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let started = std::time::Instant::now();
        let (code, _) = request(
            port,
            "GET",
            &format!("/{key}/v0.1/knowledge_base/issue_definitions"),
            None,
        );
        assert_eq!(code, 200);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "request stalled behind the idle client"
        );
    }

    #[test]
    fn oversized_declared_body_is_rejected_without_buffering() {
        let api = keyed_api();
        let (_shared, port) = start_test_server(&api);
        let key = api.keys[0].clone();
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        // claims 64 MB, sends none: the server must close, not buffer
        let req = format!(
            "POST /{key}/v0.1/scan HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 67108864\r\nconnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut resp = Vec::new();
        let n = s.read_to_end(&mut resp).unwrap();
        assert_eq!(
            n, 0,
            "oversized body should end the connection, got a response"
        );
    }

    fn keyed_api() -> ApiConfig {
        ApiConfig {
            enabled: true,
            port: 0,
            insecure_mode: false,
            keys: vec!["test-key".to_string()],
            ..Default::default()
        }
    }

    /// A key is required: no key and a wrong key both get 403, the right
    /// key gets through. The error never echoes the attempted path.
    #[test]
    fn api_key_is_required() {
        let (_shared, port) = start_test_server(&keyed_api());
        let (code, body) = request(port, "GET", "/v0.1/knowledge_base/issue_definitions", None);
        assert_eq!(code, 403);
        assert!(!body.to_string().contains("test-key"));
        let (code, _) = request(
            port,
            "GET",
            "/wrong-key/v0.1/knowledge_base/issue_definitions",
            None,
        );
        assert_eq!(code, 403);
        let (code, _) = request(
            port,
            "GET",
            "/test-key/v0.1/knowledge_base/issue_definitions",
            None,
        );
        assert_eq!(code, 200);
    }

    /// The API refuses to start when a key is required but none is
    /// configured.
    #[test]
    fn refuses_to_start_keyless() {
        let shared = net::Shared::new();
        let api = ApiConfig {
            enabled: true,
            port: 0,
            insecure_mode: false,
            keys: vec![],
            ..Default::default()
        };
        assert!(start(&shared, &api, test_defs()).is_err());
        let api = ApiConfig {
            enabled: true,
            port: 0,
            insecure_mode: true,
            keys: vec![],
            ..Default::default()
        };
        assert!(start(&shared, &api, test_defs()).is_ok());
    }

    /// The knowledge base lists issue definitions, sorted by name.
    #[test]
    fn knowledge_base_lists_issue_definitions() {
        let (_shared, port) = start_test_server(&keyed_api());
        let (code, body) = request(
            port,
            "GET",
            "/test-key/v0.1/knowledge_base/issue_definitions",
            None,
        );
        assert_eq!(code, 200);
        let defs = body.as_array().unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0]["name"], "SQL injection");
        assert_eq!(defs[0]["type_index"], json!(0x0010_0200u64));
    }

    /// POST /v0.1/scan against a loopback lab: 201 with a task id, the
    /// task reaches a terminal status, and issue_events is an array.
    #[test]
    fn scan_start_status_and_issues() {
        // Lab: one page, nothing interesting; the scan just has to run.
        let lab = TcpListener::bind("127.0.0.1:0").unwrap();
        let lab_port = lab.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in lab.incoming().flatten() {
                let mut s = s;
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 45\r\nconnection: close\r\n\r\n<html><body><p>lab</p></body></html>",
                );
            }
        });
        let (shared, port) = start_test_server(&keyed_api());
        let (code, body) = request(
            port,
            "POST",
            "/test-key/v0.1/scan",
            Some(&format!("{{\"urls\":[\"http://127.0.0.1:{lab_port}/\"]}}")),
        );
        assert_eq!(code, 201, "{body}");
        let task_id = body["task_id"].as_str().unwrap().to_string();
        let mut status = String::new();
        for _ in 0..240 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let (code, body) =
                request(port, "GET", &format!("/test-key/v0.1/scan/{task_id}"), None);
            assert_eq!(code, 200);
            status = body["scan_status"].as_str().unwrap().to_string();
            if status != "running" {
                assert!(body["issue_events"].is_array());
                break;
            }
        }
        assert_eq!(status, "succeeded", "scan did not finish");
        let _ = shared;
    }

    /// Unknown endpoints and tasks are 404; a bad scan body is 400.
    #[test]
    fn error_statuses() {
        let (_shared, port) = start_test_server(&keyed_api());
        let (code, _) = request(port, "GET", "/test-key/v0.1/nope", None);
        assert_eq!(code, 404);
        let (code, _) = request(port, "GET", "/test-key/v0.1/scan/9", None);
        assert_eq!(code, 404);
        let (code, _) = request(port, "POST", "/test-key/v0.1/scan", Some("{}"));
        assert_eq!(code, 400);
    }
}
