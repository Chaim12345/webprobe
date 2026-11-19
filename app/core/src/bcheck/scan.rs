//! Wiring of BCheck definitions into the scanner: passive (`given response`)
//! checks run from the passive pass, request/host/path/insertion-point
//! checks from the active scan. Issues report as Burp's "BCheck generated
//! issue" type.

use std::time::Duration;

use super::exec::{Collaborator, Exchange, RequestData, ResponseData};
use std::sync::Arc;
use super::runner::{run_definition, InsertionPoint as BcheckIp, Transport};
use super::{parse, Definition, GivenMode, InsertionPointKind};
use crate::net::{HistEntry, Shared};
use crate::scan::{ScanEvidence, ScanIssue};
use crate::scan::checks::ScanCtx;
use crate::scan::insertion::{InsertionPoint, IpKind};
use crate::util;

/// Parse and validate the configured definitions, logging failures once per
/// scan (Burp refuses invalid BChecks at import time; the UI validates at
/// load, so a failure here means the config was edited by hand).
fn configured_defs(shared: &Shared) -> Vec<Definition> {
    let sources = shared.scan_config.lock().unwrap().bchecks.clone();
    let mut defs = Vec::new();
    for src in &sources {
        match parse(src) {
            Ok(d) => defs.push(d),
            Err(errs) => {
                let summary = errs
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                shared.log(&format!("Scanner: BCheck skipped, invalid definition: {summary}"));
            }
        }
    }
    defs
}

/// The base exchange of an active scan: the audited request and its
/// baseline response.
fn ctx_exchange(cx: &ScanCtx) -> Exchange {
    let scheme = if cx.entry.https { "https" } else { "http" };
    let body = cx.req.as_bytes()[cx.parts.head_len.min(cx.req.len())..].to_vec();
    Exchange {
        request: RequestData {
            method: cx.parts.method.clone(),
            url: format!("{scheme}://{}{}", cx.host_hdr, cx.parts.path),
            http_version: cx
                .parts
                .first
                .split_whitespace()
                .last()
                .unwrap_or("HTTP/1.1")
                .to_string(),
            headers: cx.parts.headers.clone(),
            body: String::from_utf8_lossy(&body).into_owned(),
        },
        response: parse_response(&cx.baseline.raw).unwrap_or(ResponseData {
            status_code: 0,
            http_version: String::new(),
            headers: Vec::new(),
            body: String::new(),
        }),
    }
}

/// The exchange of a history item (passive path).
fn entry_exchange(e: &HistEntry) -> Option<Exchange> {
    let req_raw: &[u8] = &e.req_raw;
    let parts = util::parse_http(req_raw);
    let host_hdr = util::get_header(&parts.headers, "Host").unwrap_or_default();
    let scheme = if e.https { "https" } else { "http" };
    let resp_raw: &[u8] = e.resp_raw.as_deref()?;
    Some(Exchange {
        request: RequestData {
            method: parts.method.clone(),
            url: format!("{scheme}://{host_hdr}{}", parts.path),
            http_version: parts
                .first
                .split_whitespace()
                .last()
                .unwrap_or("HTTP/1.1")
                .to_string(),
            headers: parts.headers.clone(),
            body: String::from_utf8_lossy(&req_raw[parts.head_len.min(req_raw.len())..]).into_owned(),
        },
        response: parse_response(resp_raw)?,
    })
}

fn parse_response(raw: &[u8]) -> Option<ResponseData> {
    if raw.is_empty() {
        return None;
    }
    let parts = util::parse_http(raw);
    let status_code: u16 = parts.status.trim().parse().unwrap_or(0);
    Some(ResponseData {
        status_code,
        http_version: parts
            .first
            .split_whitespace()
            .next()
            .unwrap_or("HTTP/1.1")
            .to_string(),
        headers: parts.headers.clone(),
        body: String::from_utf8_lossy(&raw[parts.head_len.min(raw.len())..]).into_owned(),
    })
}

/// Active-scan transport: requests go through the scan's single choke point
/// (`ScanCtx::send`), so stored-input observation and cancellation apply.
struct CxTransport<'a> {
    cx: &'a ScanCtx,
}

impl Transport for CxTransport<'_> {
    fn send(&self, req: &RequestData) -> Result<ResponseData, String> {
        if self.cx.stopped() {
            return Err("scan stopped".to_string());
        }
        let raw = req.raw();
        let resp = self.cx.send(raw.as_bytes()).ok_or("no response")?;
        parse_response(&resp).ok_or_else(|| "unparseable response".to_string())
    }
}

/// Collaborator over the scan's payload pool and the recorded interactions.
struct ScanCollab {
    shared: Arc<Shared>,
    tokens: Vec<String>,
    /// Interaction ids already counted by an earlier condition in this
    /// check run. Burp's own Log4Shell example only works when each
    /// `... interactions` condition sees interactions not already counted
    /// (its second `if not(dns interactions)` must not re-see the first
    /// payload's DNS lookup), so conditions consume what they observe.
    counted: std::collections::HashSet<u64>,
}

impl Collaborator for ScanCollab {
    fn generate_address(&mut self) -> Result<String, String> {
        let ids = self.shared.oob.take(1, Duration::from_millis(1500));
        match ids.into_iter().next() {
            Some((token, dns)) => {
                self.tokens.push(token);
                Ok(dns)
            }
            None => Err("no Collaborator payloads available".to_string()),
        }
    }

    fn has_interaction(&mut self, kind: super::InteractionKind) -> bool {
        let observed = self.shared.oob.observed_for(&self.tokens);
        let mut found = false;
        for i in observed {
            if self.counted.contains(&i.id) {
                continue;
            }
            let k = i.kind();
            let matches = match kind {
                super::InteractionKind::Any => true,
                super::InteractionKind::Dns => k == crate::collaborator::InteractionKind::Dns,
                super::InteractionKind::Http => k == crate::collaborator::InteractionKind::Http,
                super::InteractionKind::Smtp => k == crate::collaborator::InteractionKind::Smtp,
            };
            if matches {
                self.counted.insert(i.id);
                found = true;
            }
        }
        found
    }
}

/// Convert a runner issue to a scan issue on the audited entry.
fn to_scan_issue(i: super::runner::Issue, e: &HistEntry, evidence: Vec<ScanEvidence>) -> ScanIssue {
    let confidence = match i.confidence.to_ascii_lowercase().as_str() {
        "certain" => "Certain",
        "firm" => "Firm",
        _ => "Tentative",
    };
    ScanIssue {
        id: 0, // assigned by add_issues
        sev: i.severity.to_ascii_lowercase(),
        name: i.name.clone(),
        host: e.host.clone(),
        path: e.path.split('?').next().unwrap_or("").to_string(),
        detail: format!(
            "<b>{}</b> (BCheck)<br><br>{}{}{}",
            i.name,
            i.detail,
            if i.remediation.is_empty() { String::new() } else { format!("<br><br><b>Remediation:</b> {}", i.remediation) },
            String::new()
        ),
        false_positive: false,
        confidence: confidence.to_string(),
        ts: util::now_secs(),
        // Burp reports every BCheck issue under its generated type.
        type_id: 0x09000000,
        evidence,
        ident: String::new(),
    }
}

/// The bcheck insertion-point kinds a definition wants, mapped onto the
/// scan's insertion-point kinds it runs for.
fn ip_kind_matches(want: &[InsertionPointKind], ip: &InsertionPoint) -> bool {
    want.iter().any(|w| {
        matches!(
            (w, &ip.kind),
            (InsertionPointKind::Any, IpKind::Query)
                | (InsertionPointKind::Any, IpKind::Header)
                | (InsertionPointKind::Any, IpKind::Body)
                | (InsertionPointKind::Any, IpKind::EntireBody)
                | (InsertionPointKind::Any, IpKind::Cookie)
                | (InsertionPointKind::Query, IpKind::Query)
                | (InsertionPointKind::Header, IpKind::Header)
                | (InsertionPointKind::Body, IpKind::Body)
                | (InsertionPointKind::Body, IpKind::EntireBody)
                | (InsertionPointKind::Cookie, IpKind::Cookie)
        )
    })
}

fn to_bcheck_ip(ip: &InsertionPoint) -> Option<BcheckIp> {
    let kind = match &ip.kind {
        IpKind::Query => InsertionPointKind::Query,
        IpKind::Header => InsertionPointKind::Header,
        IpKind::Cookie => InsertionPointKind::Cookie,
        IpKind::Body => InsertionPointKind::Body,
        IpKind::EntireBody => InsertionPointKind::Body,
        // Nested/structured points (JSON, multipart, XML, path segments,
        // parameter names, Base64) have no name+value placement in the
        // BCheck model; Burp runs insertion-point BChecks on them, but the
        // payload application is offset-based there. Skipped for now.
        _ => return None,
    };
    Some(BcheckIp { kind, name: ip.name.clone(), base_value: ip.decoded_value() })
}

/// Run the configured BChecks for one audited request in an active scan:
/// request / host / path / insertion-point modes. `given response` checks
/// are passive and run from the passive pass.
pub(crate) fn run_bcheck_checks(cx: &ScanCtx, points: &[InsertionPoint]) {
    let defs = configured_defs(&cx.shared);
    if defs.is_empty() || cx.stopped() {
        return;
    }
    let base = ctx_exchange(cx);
    let transport = CxTransport { cx };
    for def in &defs {
        if cx.stopped() {
            break;
        }
        match &def.given {
            GivenMode::Response => {}
            GivenMode::Request => {
                run_active_def(cx, def, &base, None, &transport);
            }
            GivenMode::Host => {
                let key = format!("H|{}|{}", cx.host, cx.port);
                if claim_once(&cx.shared, &def.metadata.name, &key) {
                    run_active_def(cx, def, &base, None, &transport);
                }
            }
            GivenMode::Path => {
                let key = format!(
                    "P|{}|{}|{}",
                    cx.host,
                    cx.port,
                    cx.parts.path.split('?').next().unwrap_or("")
                );
                if claim_once(&cx.shared, &def.metadata.name, &key) {
                    run_active_def(cx, def, &base, None, &transport);
                }
            }
            GivenMode::InsertionPoints(want) => {
                for ip in points {
                    if cx.stopped() {
                        break;
                    }
                    if !ip_kind_matches(want, ip) {
                        continue;
                    }
                    let Some(bip) = to_bcheck_ip(ip) else { continue };
                    run_active_def(cx, def, &base, Some(&bip), &transport);
                }
            }
        }
    }
}

fn run_active_def(
    cx: &ScanCtx,
    def: &Definition,
    base: &Exchange,
    ip: Option<&BcheckIp>,
    transport: &dyn Transport,
) {
    let collab = ScanCollab { shared: Arc::clone(&cx.shared), tokens: Vec::new(), counted: std::collections::HashSet::new() };
    match run_definition(def, base, ip, transport, Some(Box::new(collab))) {
        Ok(issues) => {
            let evidence = vec![ScanEvidence::new(
                cx.req.as_bytes(),
                cx.baseline.resp.as_deref(),
            )];
            let converted: Vec<ScanIssue> = issues
                .into_iter()
                .map(|i| to_scan_issue(i, &cx.entry, evidence.clone()))
                .collect();
            if !converted.is_empty() {
                // BCheck issue names are the check's own (not KB names), so
                // they bypass the built-in name gate the way extensions do.
                crate::scan::add_issues(&cx.shared, converted);
            }
        }
        Err(e) => {
            cx.shared.log(&format!(
                "Scanner: BCheck `{}` failed: {e}",
                def.metadata.name
            ));
        }
    }
}

/// Host and path checks run once per scan, not once per audited request
/// (Burp's per-host / per-path semantics); the scan claim resets the set.
fn claim_once(shared: &Shared, check: &str, key: &str) -> bool {
    shared
        .bcheck_ran
        .lock()
        .unwrap()
        .insert(format!("{check}|{key}"))
}

/// Passive pass: `given response` definitions over the audited exchange.
/// Returns issues to merge into the passive result.
pub(crate) fn bcheck_passive_issues(shared: &Shared, e: &HistEntry) -> Vec<ScanIssue> {
    let defs = configured_defs(shared);
    if defs.is_empty() {
        return Vec::new();
    }
    let Some(exchange) = entry_exchange(e) else { return Vec::new() };
    let mut out = Vec::new();
    for def in &defs {
        if !matches!(def.given, GivenMode::Response) {
            continue;
        }
        // Passive checks never send; a transport that always fails keeps a
        // stray (invalid) definition from doing anything.
        let transport = |_: &RequestData| -> Result<ResponseData, String> {
            Err("passive checks cannot send requests".to_string())
        };
        match run_definition(def, &exchange, None, &transport, None) {
            Ok(issues) => {
                let evidence = vec![ScanEvidence::new(&e.req_raw, e.resp_raw.as_deref())];
                out.extend(
                    issues
                        .into_iter()
                        .map(|i| to_scan_issue(i, e, evidence.clone())),
                );
            }
            Err(err) => {
                shared.log(&format!(
                    "Scanner: BCheck `{}` failed: {err}",
                    def.metadata.name
                ));
            }
        }
    }
    out
}

/// Reset the per-scan host/path claim set (called when a scan claims the
/// scanner).
pub(crate) fn reset_scan_state(shared: &Shared) {
    shared.bcheck_ran.lock().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn response_parse_reads_status_headers_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hi</html>";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status_code, 200);
        assert_eq!(r.http_version, "HTTP/1.1");
        assert!(r.headers.iter().any(|(k, v)| k == "Content-Type" && v == "text/html"));
        assert_eq!(r.body, "<html>hi</html>");
        assert!(parse_response(b"").is_none());
    }

    #[test]
    fn claim_once_dedups_per_check_and_key() {
        let shared = Shared::new();
        assert!(claim_once(&shared, "c", "k"));
        assert!(!claim_once(&shared, "c", "k"));
        assert!(claim_once(&shared, "c", "k2"));
        assert!(claim_once(&shared, "c2", "k"));
        reset_scan_state(&shared);
        assert!(claim_once(&shared, "c", "k"));
    }

    // ------------------------------------------------------------------
    // Acceptance: Burp's seven worked-example BChecks against a live lab.
    // ------------------------------------------------------------------

    fn lab_serve(
        handler: impl Fn(&str, &str, &str) -> String + Send + Sync + 'static,
    ) -> u16 {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let handler = std::sync::Arc::new(handler);
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let handler = handler.clone();
                std::thread::spawn(move || {
                    let mut s = s;
                    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                    let mut raw = Vec::new();
                    let mut buf = [0u8; 8192];
                    loop {
                        let n = s.read(&mut buf).unwrap_or(0);
                        raw.extend_from_slice(&buf[..n]);
                        let done = String::from_utf8_lossy(&raw).find("\r\n\r\n").is_some_and(|h| {
                            let cl = String::from_utf8_lossy(&raw[..h])
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            raw.len() >= h + 4 + cl
                        });
                        if n == 0 || done {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&raw).to_string();
                    let (head, _) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                    let method = head.split_whitespace().next().unwrap_or("").to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let _ = s.write_all(handler(&method, &path, &text).as_bytes());
                });
            }
        });
        port
    }

    fn http(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    }

    fn http_status(status: u16, body: &str) -> String {
        format!(
            "HTTP/1.1 {status} X\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    }

    /// Scan one request against the lab with the given BChecks loaded and
    /// every built-in check disabled; return (name, severity, confidence).
    fn scan_with_bchecks(
        port: u16,
        bchecks: &[&str],
        req_raw: String,
        path: &str,
    ) -> (Arc<Shared>, Vec<(String, String, String)>) {
        let shared = crate::net::Shared::new();
        let mut cfg = crate::scan_config::ScanConfig::default();
        for (id, ..) in crate::scan::check_catalogue() {
            cfg.disabled_checks.insert(id.into());
        }
        cfg.bchecks = bchecks.iter().map(|s| s.to_string()).collect();
        *shared.scan_config.lock().unwrap() = cfg;
        let mut e = crate::net::HistEntry {
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            path: path.into(),
            ..Default::default()
        };
        e.req_raw = req_raw.into_bytes().into();
        crate::scan::start_active_scan(shared.clone(), e, &[], &[]);
        let t0 = std::time::Instant::now();
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!shared.scan.is_busy(), "scan did not finish");
        let issues = shared.issues.lock().unwrap();
        let names = issues
            .iter()
            .map(|i| (i.name.clone(), i.sev.clone(), i.confidence.clone()))
            .collect();
        drop(issues);
        (shared, names)
    }

    const HOST_BC: &str = include_str!("../../tests/fixtures/bchecks/host.bcheck");
    const PATH_BC: &str = include_str!("../../tests/fixtures/bchecks/path.bcheck");
    const PASSIVE_BC: &str = include_str!("../../tests/fixtures/bchecks/passive.bcheck");
    const INSERTION_BC: &str = include_str!("../../tests/fixtures/bchecks/insertion-point.bcheck");
    const COLLAB_BC: &str = include_str!("../../tests/fixtures/bchecks/collaborator.bcheck");
    const LOG4SHELL_BC: &str = include_str!("../../tests/fixtures/bchecks/log4shell.bcheck");
    const SSPP_BC: &str = include_str!("../../tests/fixtures/bchecks/sspp.bcheck");

    #[test]
    fn burp_host_example_finds_the_exposed_git_directory() {
        let port = lab_serve(|_m, path, _raw| {
            if path == "/.git/config" {
                http("[core]\n\trepositoryformatversion = 0\n")
            } else {
                http_status(404, "nope")
            }
        });
        let req = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let (_shared, issues) = scan_with_bchecks(port, &[HOST_BC], req, "/");
        assert_eq!(
            issues,
            vec![("Host-level".to_string(), "info".to_string(), "Certain".to_string())]
        );
    }

    #[test]
    fn burp_path_example_finds_the_backup_file() {
        let port = lab_serve(|_m, path, _raw| {
            if path == "/page.bak" {
                http("backup-contents")
            } else if path == "/page" {
                http("normal page")
            } else {
                http_status(404, "nope")
            }
        });
        let req = format!("GET /page HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let (_shared, issues) = scan_with_bchecks(port, &[PATH_BC], req, "/page");
        assert_eq!(
            issues,
            vec![("Path-level".to_string(), "info".to_string(), "Firm".to_string())]
        );
    }

    #[test]
    fn burp_passive_example_flags_the_leaked_aws_key() {
        // Passive runs from the passive pass, not the active scan.
        let shared = crate::net::Shared::new();
        shared.scan_config.lock().unwrap().bchecks = vec![PASSIVE_BC.to_string()];
        let req = b"GET / HTTP/1.1\r\nHost: lab.local\r\n\r\n".to_vec();
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\n\r\nkey: AKIAIOSFODNN7EXAMPLE".to_vec();
        let mut e = crate::net::HistEntry { host: "lab.local".into(), path: "/".into(), ..Default::default() };
        e.req_raw = req.into();
        e.resp_raw = Some(resp.into());
        let issues = crate::scan::passive_check_for(&shared, &e);
        assert!(
            issues.iter().any(|i| i.name == "Response-level (passive) check"
                && i.sev == "high"
                && i.confidence == "Firm"),
            "issues: {:?}",
            issues.iter().map(|i| &i.name).collect::<Vec<_>>()
        );
        // a clean response stays quiet
        let resp2 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let mut e2 = crate::net::HistEntry { host: "lab.local".into(), path: "/".into(), ..Default::default() };
        e2.req_raw = b"GET / HTTP/1.1\r\nHost: lab.local\r\n\r\n".to_vec().into();
        e2.resp_raw = Some(resp2.into());
        let issues2 = crate::scan::passive_check_for(&shared, &e2);
        assert!(!issues2.iter().any(|i| i.name == "Response-level (passive) check"));
    }

    #[test]
    fn burp_insertion_point_example_flags_input_transformation() {
        let port = lab_serve(|_m, path, _raw| {
            if path.contains("{{1337*1337}}") || path.contains("%7B%7B1337*1337%7D%7D") {
                // the second form is the URL-encoded payload Burp sends;
                // a real application decodes the parameter value
                http("result: 1787569")
            } else {
                http("result: ")
            }
        });
        let req = format!("GET /calc?n=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let (_shared, issues) = scan_with_bchecks(port, &[INSERTION_BC], req, "/calc?n=1");
        assert!(
            issues.contains(&("Insertion-point-level".to_string(), "high".to_string(), "Tentative".to_string())),
            "issues: {issues:?}"
        );
    }

    fn stock_and_observe(shared: &Shared, kinds: &[&str]) {
        shared.oob.stock(vec![("tok1".to_string(), "t1.oast.test".to_string())]);
        shared.oob.stock(vec![("tok2".to_string(), "t2.oast.test".to_string())]);
        shared.oob.stock(vec![("tok3".to_string(), "t3.oast.test".to_string())]);
        shared.oob.stock(vec![("tok4".to_string(), "t4.oast.test".to_string())]);
        let mut interactions = Vec::new();
        for (i, kind) in kinds.iter().enumerate() {
            let detail = match *kind {
                "dns" => crate::collaborator::InteractionDetail::Dns(crate::collaborator::DnsInteraction {
                    qname: "t.oast.test".into(),
                    qtype: 1,
                    raw_query: Vec::new(),
                }),
                "http" => crate::collaborator::InteractionDetail::Http(crate::collaborator::HttpInteraction {
                    method: "GET".into(),
                    target: "/".into(),
                    version: "HTTP/1.1".into(),
                    headers: Vec::new(),
                    body: Vec::new(),
                }),
                _ => continue,
            };
            // the pool hands out tokens from the end: tok4 is drawn first
            interactions.push(crate::collaborator::Interaction {
                id: (i + 1) as u64,
                at: 0,
                source: "192.0.2.1".into(),
                token: Some(format!("tok{}", 4 - i)),
                detail,
            });
        }
        shared.oob.observe(&interactions);
    }

    #[test]
    fn burp_collaborator_example_reports_blind_ssrf() {
        let port = lab_serve(|_m, _path, _raw| http("ok"));
        let req_t = format!("GET /a HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        // the "target" fetched the collaborator URL: an HTTP interaction
        // arrives for the generated payload
        let shared = crate::net::Shared::new();
        let mut cfg = crate::scan_config::ScanConfig::default();
        for (id, ..) in crate::scan::check_catalogue() {
            cfg.disabled_checks.insert(id.into());
        }
        cfg.bchecks = vec![COLLAB_BC.to_string()];
        *shared.scan_config.lock().unwrap() = cfg;
        stock_and_observe(&shared, &["http"]);
        let mut e = crate::net::HistEntry {
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            path: "/a".into(),
            ..Default::default()
        };
        e.req_raw = req_t.into_bytes().into();
        crate::scan::start_active_scan(shared.clone(), e, &[], &[]);
        let t0 = std::time::Instant::now();
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let issues = shared.issues.lock().unwrap();
        assert!(
            issues.iter().any(|i| i.name == "Request-level collaborator-based check"
                && i.sev == "high"
                && i.confidence == "Firm"),
            "issues: {:?}",
            issues.iter().map(|i| &i.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn burp_log4shell_example_reports_only_with_a_first_payload_interaction() {
        // The lab answers everything 200; the Collaborator sees a DNS
        // interaction for the first payload only (the app resolved the LDAP
        // host, the invalid `jmdi:lxap` scheme never reaches DNS).
        let port = lab_serve(|_m, _path, _raw| http("ok"));
        let shared = crate::net::Shared::new();
        let mut cfg = crate::scan_config::ScanConfig::default();
        for (id, ..) in crate::scan::check_catalogue() {
            cfg.disabled_checks.insert(id.into());
        }
        cfg.bchecks = vec![LOG4SHELL_BC.to_string()];
        *shared.scan_config.lock().unwrap() = cfg;
        stock_and_observe(&shared, &["dns"]);
        let req_t = format!("POST /login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 3\r\n\r\nabc");
        let mut e = crate::net::HistEntry {
            method: "POST".into(),
            host: "127.0.0.1".into(),
            port,
            path: "/login".into(),
            ..Default::default()
        };
        e.req_raw = req_t.into_bytes().into();
        crate::scan::start_active_scan(shared.clone(), e, &[], &[]);
        let t0 = std::time::Instant::now();
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!shared.scan.is_busy(), "scan did not finish");
        let issues = shared.issues.lock().unwrap();
        assert!(
            issues.iter().any(|i| i.name == "Log4Shell check"
                && i.sev == "high"
                && i.confidence == "Firm"),
            "issues: {:?}",
            issues.iter().map(|i| &i.name).collect::<Vec<_>>()
        );
        drop(issues);

        // Without any interaction, the check stays quiet.
        let shared2 = crate::net::Shared::new();
        let mut cfg2 = crate::scan_config::ScanConfig::default();
        for (id, ..) in crate::scan::check_catalogue() {
            cfg2.disabled_checks.insert(id.into());
        }
        cfg2.bchecks = vec![LOG4SHELL_BC.to_string()];
        *shared2.scan_config.lock().unwrap() = cfg2;
        stock_and_observe(&shared2, &[]);
        let req_t2 = format!("POST /login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 3\r\n\r\nabc");
        let mut e2 = crate::net::HistEntry {
            method: "POST".into(),
            host: "127.0.0.1".into(),
            port,
            path: "/login".into(),
            ..Default::default()
        };
        e2.req_raw = req_t2.into_bytes().into();
        crate::scan::start_active_scan(shared2.clone(), e2, &[], &[]);
        let t0 = std::time::Instant::now();
        while shared2.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let issues2 = shared2.issues.lock().unwrap();
        assert!(
            !issues2.iter().any(|i| i.name == "Log4Shell check"),
            "issues: {:?}",
            issues2.iter().map(|i| &i.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn burp_sspp_example_reports_server_side_prototype_pollution() {
        let polluted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let p2 = polluted.clone();
        let port = lab_serve(move |method, _path, raw| {
            let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
            if method == "POST" {
                if body.contains("\"status\":510") || body.contains("\"status\": 510") {
                    p2.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                if body.contains("\"status\":0") {
                    p2.store(false, std::sync::atomic::Ordering::SeqCst);
                }
                if body == "{,}" && p2.load(std::sync::atomic::Ordering::SeqCst) {
                    return http_status(510, "{\"statusCode\":510}");
                }
            }
            http("{}")
        });
        let base_body = "{\"a\":1}";
        let req = format!(
            "POST /merge HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            base_body.len(),
            base_body
        );
        let (_shared, issues) = scan_with_bchecks(port, &[SSPP_BC], req, "/merge");
        assert!(
            issues.iter().any(|i| i.0 == "Server-side prototype pollution"
                && i.1 == "high"
                && i.2 == "Firm"),
            "issues: {issues:?}"
        );
    }
}
