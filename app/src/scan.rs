// Scanner: live passive checks + light active scans, mirroring the original's
// defaults from burpsuite.jar resources/Preferences (MECHANICS.md, Scanner section).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::net::{self, HistEntry, Shared};
use crate::util;

/// AuditDefaults.json misc_insertion_point_options.max_insertion_points_per_base_request
pub const MAX_INSERTION_POINTS: usize = 30;
/// CrawlDefaults.json crawl_limits.maximum_unique_locations
pub const CRAWL_MAX_UNIQUE_LOCATIONS: usize = 1500;

const ERROR_SIGNATURES: [(&str, &str); 7] = [
    ("SQL syntax", "SQL error message in response"),
    ("SQLite3::", "SQLite error message in response"),
    ("ORA-", "Oracle database error message in response"),
    ("PHP Warning", "PHP runtime warning in response"),
    ("System.Exception", "Server exception message in response"),
    ("Stack Trace", "Stack trace disclosed in response"),
    ("Warning: mysql_", "MySQL warning in response"),
];

const SECRET_KEYWORDS: [(&str, &str); 6] = [
    ("password", "Possible credential reference in HTML comment"),
    ("passwd", "Possible credential reference in HTML comment"),
    ("secret", "Possible secret reference in HTML comment"),
    ("api_key", "Possible API key reference in HTML comment"),
    ("apikey", "Possible API key reference in HTML comment"),
    ("TODO:", "Developer note in HTML comment"),
];

#[derive(Clone)]
pub struct ScanIssue {
    pub id: u64,
    pub sev: String, // high | medium | low | info (DarkTheme.json ui.issue colors)
    pub name: String,
    pub host: String,
    pub path: String,
    pub detail: String,
}

fn mk(sev: &str, name: &str, e: &HistEntry, detail: impl Into<String>) -> ScanIssue {
    ScanIssue {
        id: 0, // assigned by add_issues
        sev: sev.to_string(),
        name: name.into(),
        host: e.host.clone(),
        path: e.path.clone(),
        detail: detail.into(),
    }
}

pub fn add_issues(shared: &Shared, mut issues: Vec<ScanIssue>) {
    if issues.is_empty() {
        return;
    }
    let mut iss = shared.issues.lock().unwrap();
    let incoming = issues.len();
    for (i, issue) in issues.iter_mut().enumerate() {
        issue.id = shared.next_id.fetch_add(1, Ordering::SeqCst);
        if iss.len() + incoming - i > 500 {
            iss.remove(0);
        }
        iss.push(issue.clone());
    }
    shared.log(&format!("Scanner reported {} issue(s)", issues.len()));
}

/// Passive issues consolidated like the original (AuditDefaults.json
/// scanner.audit_optimization.consolidate_passive_issues = true, and
/// ConsolidationAction.KEEP_EXISTING for duplicates): the first instance of an
/// issue with the same severity + name + service + base URL is kept.
pub fn add_passive_issues(shared: &Shared, mut issues: Vec<ScanIssue>) {
    if issues.is_empty() {
        return;
    }
    let mut iss = shared.issues.lock().unwrap();
    let key = |i: &ScanIssue| format!("{}|{}|{}|{}", i.sev, i.name, i.host, i.path);
    let mut seen = std::collections::BTreeSet::new();
    issues.retain(|i| seen.insert(key(i)));
    let mut known: std::collections::BTreeSet<String> =
        iss.iter().map(&key).collect();
    issues.retain(|i| known.insert(key(i)));
    let incoming = issues.len();
    for (i, issue) in issues.iter_mut().enumerate() {
        issue.id = shared.next_id.fetch_add(1, Ordering::SeqCst);
        if iss.len() + incoming - i > 500 {
            iss.remove(0);
        }
        iss.push(issue.clone());
    }
    if incoming > 0 {
        shared.log(&format!("Scanner reported {} new issue(s) ({} consolidated)", issues.len(), incoming - issues.len()));
    }
}

/// Passive audit of one stored message (run for every proxied exchange when enabled).
pub fn passive_check(e: &HistEntry) -> Vec<ScanIssue> {
    let mut v: Vec<ScanIssue> = Vec::new();
    let Some(resp) = &e.resp_raw else { return v };
    let p = util::parse_http(resp);
    let ok_status = p.status.starts_with('2') || p.status.starts_with('3');
    if ok_status {
        if util::get_header(&p.headers, "Strict-Transport-Security").is_none() {
            v.push(mk("info", "Missing security header: Strict-Transport-Security", e,
                "No HSTS policy announced on an origin that returned a successful response."));
        }
        if util::get_header(&p.headers, "Content-Security-Policy").is_none() {
            v.push(mk("low", "Missing security header: Content-Security-Policy", e,
                "No CSP set, so injected scripts are not restricted by a content policy."));
        }
        if util::get_header(&p.headers, "X-Frame-Options").is_none() {
            v.push(mk("low", "Missing security header: X-Frame-Options / frame-ancestors", e,
                "The response may be framed by another site (clickjacking risk)."));
        }
        if util::get_header(&p.headers, "X-Content-Type-Options").is_none() {
            v.push(mk("info", "Missing security header: X-Content-Type-Options", e,
                "No nosniff directive; browsers may guess the content type."));
        }
        if let Some(server) = util::get_header(&p.headers, "Server") {
            let discloses = server.contains('/') || !server.split_whitespace().skip(1).next().unwrap_or("").is_empty();
            if discloses {
                v.push(mk("info", "Server version disclosure", e, format!("Server header: {server}")));
            }
        }
        // cookies lacking flags (all Set-Cookie values; repeated headers included)
        for (k, val) in &p.headers {
            if k.eq_ignore_ascii_case("Set-Cookie") {
                let lower = val.to_ascii_lowercase();
                if !lower.contains("httponly") {
                    v.push(mk("info", "Cookie without HttpOnly flag", e, val.clone()));
                }
                if !lower.contains("secure") {
                    v.push(mk("low", "Cookie without Secure flag", e, val.clone()));
                }
            }
        }
    }
    // error signatures in the response body
    let body = &resp[p.head_len.min(resp.len())..];
    for (sig, name) in ERROR_SIGNATURES {
        if body.windows(sig.len()).any(|w| w.eq_ignore_ascii_case(sig.as_bytes())) {
            v.push(mk("medium", name, e, format!("Signature matched: {sig}")));
        }
    }
    // secrets in HTML comments
    let text = String::from_utf8_lossy(body);
    let mut start = 0;
    while let Some(copen) = text[start..].find("<!--") {
        let cstart = start + copen + 4;
        let Some(cend) = text[cstart..].find("-->") else { break };
        let comment = &text[cstart..cstart + cend];
        for (kw, name) in SECRET_KEYWORDS {
            if comment.to_ascii_lowercase().contains(&kw.to_ascii_lowercase()) {
                v.push(mk("info", name, e, comment.trim().chars().take(120).collect::<String>()));
            }
        }
        start = cstart + cend + 3;
    }
    v
}

pub fn query_params(path: &str) -> Vec<(String, String)> {
    let q = path.split('?').nth(1).unwrap_or("");
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let mut it = kv.splitn(2, '=');
            (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string())
        })
        .take(MAX_INSERTION_POINTS)
        .collect()
}

/// Light active scan of a stored request: one URL parameter at a time,
/// SQL-error and reflection probes (scan_type_light_active, AuditDefaults.json).
pub fn start_active_scan(shared: Arc<Shared>, entry: HistEntry) {
    if shared.scan_busy.load(Ordering::SeqCst) {
        shared.log("Scanner: a scan is already running");
        return;
    }
    let req = String::from_utf8_lossy(&entry.req_raw).into_owned();
    let parts = util::parse_http(&entry.req_raw);
    let host_header = util::get_header(&parts.headers, "Host").unwrap_or_default();
    if host_header.is_empty() {
        shared.log("Scanner: selected request has no Host header");
        return;
    }
    let (host, port) = net::split_h_p(&host_header, entry.port);
    let params = query_params(&parts.path);
    if params.is_empty() {
        shared.log("Scanner: no query parameters to audit (URL params only, max 30 per request)");
        return;
    }
    let total = params.len() * 2; // two probes per insertion point
    shared.scan_total.store(total, Ordering::SeqCst);
    shared.scan_done.store(0, Ordering::SeqCst);
    shared.scan_stop.store(false, Ordering::SeqCst);
    shared.scan_busy.store(true, Ordering::SeqCst);
    shared.log(&format!("Scanner: active scan started ({} insertion point(s), light active checks)", params.len()));

    std::thread::spawn(move || {
        for (idx, (name, value)) in params.iter().enumerate() {
            if shared.scan_stop.load(Ordering::SeqCst) {
                break;
            }
            // SQL error probe: append ' to the raw value
            let sql_path = replace_param(&parts.path, name, &format!("{value}'"));
            let xss_marker = format!("wb{idx:03}scan");
            let xss_path = replace_param(&parts.path, name, &format!("{value}{}{xss_marker}{}", "'\"<", ">"));
            for (probe, path_probe) in [("sql", sql_path), ("reflect", xss_path)] {
                if shared.scan_stop.load(Ordering::SeqCst) {
                    break;
                }
                let new_req = rebuild_with_path(&req, &path_probe);
                let up = if entry.https {
                    net::send_tls_raw(&shared, &host, port, new_req.as_bytes())
                } else {
                    net::send_raw(&shared, &host, port, new_req.as_bytes())
                };
                if let Some(resp) = &up.resp {
                    let mut issues = Vec::new();
                    let rp = util::parse_http(resp);
                    let body = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
                    if probe == "sql" {
                        for (sig, name2) in ERROR_SIGNATURES.iter().take(3) {
                            if body.contains(sig) {
                                issues.push(mk(
                                    "high",
                                    &format!("Active probe: {name2} (parameter {name})"),
                                    &entry,
                                    format!("Payload appended a quote to {name}; the response matched: {sig}"),
                                ));
                                break;
                            }
                        }
                    } else if unencoded_reflection(&body, &xss_marker) {
                        issues.push(mk(
                            "medium",
                            &format!("Active probe: value of {name} is reflected unencoded"),
                            &entry,
                            format!("Marker {} echoed back in the response body.", xss_marker),
                        ));
                    }
                    add_issues(&shared, issues);
                }
                shared.scan_done.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        shared.scan_busy.store(false, Ordering::SeqCst);
        shared.log("Scanner: active scan finished");
        let found = shared.issues.lock().map(|i| i.len()).unwrap_or(0);
        crate::feedback::toast(
            crate::feedback::Level::Success,
            format!("Active scan finished — {found} issue(s) in the report"),
        );
    });
}

/// True when the injected marker (and the raw quote/angle brackets around it)
/// come back in the response without HTML/URL encoding.
fn unencoded_reflection(body: &str, marker: &str) -> bool {
    if !body.contains(marker) {
        return false;
    }
    // the probe payload ends with `'"<` — if that exact sequence survives,
    // nothing was encoded on the way back.
    body.contains(&format!("{marker}'\"<"))
}

fn replace_param(path: &str, name: &str, new_value: &str) -> String {
    let Some(qpos) = path.find('?') else { return path.to_string() };
    let (base, query) = path.split_at(qpos);
    let query = &query[1..];
    let parts: Vec<String> = query
        .split('&')
        .map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next().unwrap_or("");
            if k == name {
                format!("{}={}", k, new_value)
            } else {
                kv.to_string()
            }
        })
        .collect();
    format!("{base}?{}", parts.join("&"))
}

fn rebuild_with_path(req: &str, new_path: &str) -> String {
    let mut lines = req.lines();
    let first = lines.next().unwrap_or_default();
    let mut it = first.split_whitespace();
    let method = it.next().unwrap_or("GET");
    let _ = it.next();
    let ver = it.next().unwrap_or("HTTP/1.1");
    let mut out = String::new();
    out.push_str(&format!("{method} {new_path} {ver}\r\n"));
    for line in lines {
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !out.ends_with("\r\n\r\n") {
        out.push_str("\r\n");
    }
    out
}
