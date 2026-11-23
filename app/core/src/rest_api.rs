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
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

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
}

struct ApiState {
    tasks: Vec<ApiTask>,
}

/// Start the REST API from the user options. Returns the bound port.
/// Refuses to start when a key is required but none is configured: Burp
/// shows the generated key in its UI; a headless process has nowhere safe
/// to show it, and the key is never logged.
pub fn start(
    shared: &Arc<net::Shared>,
    api: &ApiConfig,
    issue_definitions: Vec<IssueDefinition>,
) -> Result<u16, String> {
    if !api.insecure_mode && api.keys.is_empty() {
        return Err(
            "user_options.misc.api is enabled with no keys and insecure_mode false; refusing to start without an API key"
                .to_string(),
        );
    }
    if api.listen_mode == "all_interfaces" && api.insecure_mode {
        // headless has no settings UI to notice this in: say it on stderr
        eprintln!(
            "webprobe: REST API listens on all interfaces with insecure_mode (no API key); any host that can reach the port can drive it"
        );
    }
    let host = match api.listen_mode.as_str() {
        "loopback_only" => api.address.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
        "all_interfaces" => api.address.clone().unwrap_or_else(|| "0.0.0.0".to_string()),
        other => {
            return Err(format!(
                "user_options.misc.api listen_mode `{other}` is not supported"
            ));
        }
    };
    let listener = TcpListener::bind((host.as_str(), api.port))
        .map_err(|e| format!("REST API cannot listen on {host}:{}: {e}", api.port))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let state = Arc::new(Mutex::new(ApiState { tasks: Vec::new() }));
    let shared = shared.clone();
    let api = api.clone();
    let defs = Arc::new(issue_definitions);
    std::thread::spawn(move || {
        // one thread per client: an idle or slow client must not stall the
        // others behind its read timeout
        for stream in listener.incoming().flatten() {
            let (shared, state, api, defs) = (
                shared.clone(),
                Arc::clone(&state),
                api.clone(),
                Arc::clone(&defs),
            );
            std::thread::spawn(move || handle(stream, &shared, &state, &api, &defs));
        }
    });
    Ok(port)
}

fn handle(
    mut stream: std::net::TcpStream,
    shared: &Arc<net::Shared>,
    state: &Arc<Mutex<ApiState>>,
    api: &ApiConfig,
    defs: &[IssueDefinition],
) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
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
    let first_issue = shared.issues.lock().unwrap().len();
    let id = {
        let mut st = state.lock().unwrap();
        st.tasks.push(ApiTask {
            status: "running".to_string(),
            first_issue,
        });
        st.tasks.len() - 1
    };
    let shared2 = shared.clone();
    let state2 = state.clone();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scan::crawl_and_audit(&shared2, &urls, true);
            shared2.scan.wait_idle(None);
        }));
        let mut st = state2.lock().unwrap();
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
        return respond(
            stream,
            404,
            "Not Found",
            json!({"error": "unknown task"}),
        );
    };
    let st = state.lock().unwrap();
    let Some(task) = st.tasks.get(n) else {
        return respond(
            stream,
            404,
            "Not Found",
            json!({"error": "unknown task"}),
        );
    };
    let status = task.status.clone();
    let first_issue = task.first_issue;
    drop(st);
    let events: Vec<Value> = {
        let issues = shared.issues.lock().unwrap();
        issues[first_issue.min(issues.len())..]
            .iter()
            .enumerate()
            .map(|(i, issue)| {
                json!({"serial_number": i, "type": "issue_found", "issue": issue_json(issue)})
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
        let port = start(&shared, api, test_defs()).unwrap();
        (shared, port)
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
        let json: Value =
            serde_json::from_str(text.split("\r\n\r\n").nth(1).unwrap_or("{}")).unwrap_or(Value::Null);
        (code, json)
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
            "POST /burp/scans?{key} HTTP/1.1\r\nhost: x\r\ncontent-length: 67108864\r\nconnection: close\r\n\r\n"
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
            Some(&format!(
                "{{\"urls\":[\"http://127.0.0.1:{lab_port}/\"]}}"
            )),
        );
        assert_eq!(code, 201, "{body}");
        let task_id = body["task_id"].as_str().unwrap().to_string();
        let mut status = String::new();
        for _ in 0..240 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let (code, body) = request(port, "GET", &format!("/test-key/v0.1/scan/{task_id}"), None);
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
