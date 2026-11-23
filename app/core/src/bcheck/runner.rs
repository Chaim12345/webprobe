//! BCheck runner: executes a parsed definition against one base exchange,
//! producing issues. Given-mode iteration over audited traffic and scan
//! pipeline wiring land in the next slice.

use super::exec::{
    Collaborator, Context, Exchange, ExecError, RequestData, ResponseData, apply_mod,
    eval_condition, resolve_value,
};
use super::{Definition, GivenMode, InsertionPointKind, Stmt, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    pub name: String,
    pub severity: String,
    pub confidence: String,
    pub detail: String,
    pub remediation: String,
}

/// An insertion point the check runs against.
#[derive(Debug, Clone, PartialEq)]
pub struct InsertionPoint {
    pub kind: InsertionPointKind,
    /// Parameter / header / cookie name; unused for whole-body points.
    pub name: String,
    pub base_value: String,
}

/// Sends a built request and returns the response.
pub trait Transport {
    fn send(&self, req: &RequestData) -> Result<ResponseData, String>;
}

impl<F> Transport for F
where
    F: Fn(&RequestData) -> Result<ResponseData, String>,
{
    fn send(&self, req: &RequestData) -> Result<ResponseData, String> {
        self(req)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, ExecError> {
    Err(ExecError(msg.into()))
}

/// Run a definition once per `run for each` value tuple against the base
/// exchange. `base` is the request/response pair Burp calls `base`; for
/// passive checks it is the audited pair.
pub fn run_definition(
    def: &Definition,
    base: &Exchange,
    ip: Option<&InsertionPoint>,
    transport: &dyn Transport,
    collaborator: Option<Box<dyn Collaborator>>,
) -> Result<Vec<Issue>, ExecError> {
    // Expand run-for-each: each declared variable contributes its value list;
    // multiple variables iterate as a cartesian product (Burp re-runs the
    // whole check per combination).
    let tuples = expand_tuples(def)?;
    let mut issues = Vec::new();
    let mut collab = collaborator;
    for tuple in tuples {
        let mut cx = Context::new(base.clone());
        if let Some(ip) = ip {
            cx.insertion_point_base_value = Some(ip.base_value.clone());
        }
        cx.collaborator = collab.take();
        for (name, value) in &tuple {
            let v = resolve_value(&mut cx, value)?;
            cx.vars.insert(name.clone(), v);
        }
        for decl in &def.define {
            let v = resolve_value(&mut cx, &decl.values[0])?;
            cx.vars.insert(decl.name.clone(), v);
        }
        exec_block(def, &mut cx, base, ip, transport, &mut issues, &def.body)?;
        collab = cx.collaborator.take();
    }
    Ok(issues)
}

/// Defensive ceiling on `run for each` expansion (not a documented Burp
/// limit): every combination fires real requests, so an unbounded product
/// would turn a bad check into a self-inflicted load test.
const MAX_RUN_FOR_EACH: usize = 1024;

fn expand_tuples(def: &Definition) -> Result<Vec<Vec<(String, Value)>>, ExecError> {
    let mut tuples: Vec<Vec<(String, Value)>> = vec![Vec::new()];
    for decl in &def.run_for_each {
        if tuples.len().saturating_mul(decl.values.len().max(1)) > MAX_RUN_FOR_EACH {
            return Err(ExecError(format!(
                "`run for each` expands past {MAX_RUN_FOR_EACH} combinations"
            )));
        }
        let mut next = Vec::new();
        for t in &tuples {
            for v in &decl.values {
                let mut t2 = t.clone();
                t2.push((decl.name.clone(), v.clone()));
                next.push(t2);
            }
        }
        tuples = next;
    }
    Ok(tuples)
}

/// Execute a statement block; returns `true` when a terminating
/// `report issue` fired, matching Burp's stop-on-report semantics.
fn exec_block(
    def: &Definition,
    cx: &mut Context,
    base: &Exchange,
    ip: Option<&InsertionPoint>,
    transport: &dyn Transport,
    issues: &mut Vec<Issue>,
    stmts: &[Stmt],
) -> Result<bool, ExecError> {
    for stmt in stmts {
        match stmt {
            Stmt::SendRequest {
                name, raw, mods, ..
            } => {
                let req = match raw {
                    Some(v) => {
                        let text = resolve_value(cx, v)?;
                        parse_raw_request(&text, &base.request)?
                    }
                    None => {
                        let mut req = base.request.clone();
                        for m in mods {
                            apply_mod(cx, &mut req, m)?;
                        }
                        req
                    }
                };
                cx.requests_sent += 1;
                if cx.requests_sent > super::exec::MAX_REQUESTS_PER_RUN {
                    return Err(ExecError(format!(
                        "definition sent more than {} requests in one run",
                        super::exec::MAX_REQUESTS_PER_RUN
                    )));
                }
                let resp = transport.send(&req).map_err(ExecError)?;
                cx.record(
                    name.as_deref(),
                    Exchange {
                        request: req,
                        response: resp,
                    },
                );
            }
            Stmt::SendPayload { name, ops, .. } => {
                let ip = ip
                    .ok_or_else(|| ExecError("`send payload` without an insertion point".into()))?;
                // Burp builds one payload set per `send payload`: appending
                // ops accumulate onto the running value and a replacing op
                // resets it, so earlier ops are not lost when several appear
                // in one block.
                let mut cur = ip.base_value.clone();
                for (mode, value) in ops {
                    let payload = resolve_value(cx, value)?;
                    cur = match mode {
                        ModModeShim::Append => format!("{cur}{payload}"),
                        ModModeShim::Replace => payload,
                        ModModeShim::Remove => {
                            return Err(ExecError(
                                "`removing` is not valid in `send payload`".into(),
                            ));
                        }
                    };
                }
                let mut req = base.request.clone();
                apply_payload(&mut req, ip, &cur)?;
                cx.requests_sent += 1;
                if cx.requests_sent > super::exec::MAX_REQUESTS_PER_RUN {
                    return Err(ExecError(format!(
                        "definition sent more than {} requests in one run",
                        super::exec::MAX_REQUESTS_PER_RUN
                    )));
                }
                let resp = transport.send(&req).map_err(ExecError)?;
                cx.record(
                    name.as_deref(),
                    Exchange {
                        request: req,
                        response: resp,
                    },
                );
            }
            Stmt::ReportIssue {
                and_continue,
                fields,
            } => {
                let name = match &fields.name {
                    Some(v) => resolve_value(cx, v)?,
                    None => def.metadata.name.clone(),
                };
                issues.push(Issue {
                    name,
                    severity: resolve_value(cx, &fields.severity)?,
                    confidence: resolve_value(cx, &fields.confidence)?,
                    detail: match &fields.detail {
                        Some(v) => resolve_value(cx, v)?,
                        None => String::new(),
                    },
                    remediation: match &fields.remediation {
                        Some(v) => resolve_value(cx, v)?,
                        None => String::new(),
                    },
                });
                if !and_continue {
                    return Ok(true);
                }
            }
            Stmt::If { arms } => {
                for (cond, body) in arms {
                    let fire = match cond {
                        Some(c) => eval_condition(cx, c)?,
                        None => true,
                    };
                    if fire {
                        if exec_block(def, cx, base, ip, transport, issues, body)? {
                            return Ok(true);
                        }
                        break;
                    }
                }
            }
        }
    }
    Ok(false)
}

/// Parse a raw HTTP request block, taking scheme/authority from the base
/// request when the target is origin-form.
fn parse_raw_request(text: &str, base: &RequestData) -> Result<RequestData, ExecError> {
    let normalized = text.replace("\r\n", "\n");
    let (head, body) = match normalized.split_once("\n\n") {
        Some((h, b)) => (h, b.to_string()),
        None => (normalized.as_str(), String::new()),
    };
    let mut lines = head.lines();
    let start = lines
        .next()
        .ok_or_else(|| ExecError("empty raw request".into()))?;
    let mut parts = start.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let http_version = parts.next().unwrap_or("HTTP/1.1").to_string();
    if method.is_empty() || target.is_empty() {
        return err("bad raw request start line");
    }
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target
    } else {
        // Origin-form target: the authority is the raw request's own Host
        // header when it has one (Burp sends it there), else the base
        // request's; the scheme always comes from the base request.
        let scheme = base
            .url
            .find("://")
            .map(|i| &base.url[..i])
            .unwrap_or("http");
        let host_header = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str());
        let authority = match host_header {
            Some(h) => h.to_string(),
            None => {
                let rest = base
                    .url
                    .find("://")
                    .map(|i| &base.url[i + 3..])
                    .unwrap_or(base.url.as_str());
                let end = rest.find(['/', '?']).unwrap_or(rest.len());
                rest[..end].to_string()
            }
        };
        let path = if target.starts_with('/') {
            target.clone()
        } else {
            format!("/{target}")
        };
        format!("{scheme}://{}{}", authority.trim_end_matches('/'), path)
    };
    Ok(RequestData {
        method,
        url,
        http_version,
        headers,
        body,
    })
}

/// Apply the computed payload value at the insertion point, per Burp's
/// `send payload` semantics. Only concrete kinds reach here (the scan
/// wiring maps `Any` onto the audited point's real kind); anything else is
/// a wiring bug, not a reason to guess a placement.
fn apply_payload(
    req: &mut RequestData,
    ip: &InsertionPoint,
    combined: &str,
) -> Result<(), ExecError> {
    match ip.kind {
        InsertionPointKind::Query => {
            set_query_param(req, &ip.name, combined);
        }
        InsertionPointKind::Header => {
            set_header(req, &ip.name, combined);
        }
        InsertionPointKind::Cookie => {
            set_cookie(req, &ip.name, combined);
        }
        InsertionPointKind::Body => {
            req.body = combined.to_string();
        }
        InsertionPointKind::Any => {
            return Err(ExecError(
                "`send payload` needs a concrete insertion-point kind".into(),
            ));
        }
    }
    Ok(())
}

use super::ModMode as ModModeShim;

fn set_header(req: &mut RequestData, name: &str, value: &str) {
    if let Some(h) = req
        .headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
    {
        h.1 = value.to_string();
    } else {
        req.headers.push((name.to_string(), value.to_string()));
    }
}

fn set_cookie(req: &mut RequestData, name: &str, value: &str) {
    let mut found = false;
    for h in req
        .headers
        .iter_mut()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Cookie"))
    {
        let mut pairs: Vec<(String, String)> =
            h.1.split(';')
                .map(|p| {
                    let p = p.trim();
                    match p.split_once('=') {
                        Some((k, v)) => (k.to_string(), v.to_string()),
                        None => (p.to_string(), String::new()),
                    }
                })
                .collect();
        if let Some(pair) = pairs.iter_mut().find(|(k, _)| k == name) {
            pair.1 = value.to_string();
        } else {
            pairs.push((name.to_string(), value.to_string()));
        }
        h.1 = pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        found = true;
    }
    if !found {
        req.headers
            .push(("Cookie".to_string(), format!("{name}={value}")));
    }
}

fn set_query_param(req: &mut RequestData, name: &str, value: &str) {
    let url = req.url.clone();
    let (path, query) = {
        let after = match url.find("://") {
            Some(i) => {
                let rest = &url[i + 3..];
                match rest.find('/') {
                    Some(j) => &url[i + 3 + j..],
                    None => "/",
                }
            }
            None => url.as_str(),
        };
        match after.find('?') {
            Some(i) => (after[..i].to_string(), after[i + 1..].to_string()),
            None => (after.to_string(), String::new()),
        }
    };
    let mut pairs: Vec<(String, String)> = if query.is_empty() {
        Vec::new()
    } else {
        query
            .split('&')
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (p.to_string(), String::new()),
            })
            .collect()
    };
    if let Some(pair) = pairs.iter_mut().find(|(k, _)| k == name) {
        pair.1 = value.to_string();
    } else {
        pairs.push((name.to_string(), value.to_string()));
    }
    let new_query = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let prefix = match url.find("://") {
        Some(i) => {
            let rest = &url[i + 3..];
            match rest.find('/') {
                Some(j) => &url[..i + 3 + j],
                None => url.as_str(),
            }
        }
        None => "",
    };
    req.url = if new_query.is_empty() {
        format!("{prefix}{path}")
    } else {
        format!("{prefix}{path}?{new_query}")
    };
}

/// The given modes a definition declares decide where the scan pipeline
/// calls the runner; this helper exposes that mapping for the wiring slice.
pub fn needs_insertion_points(def: &Definition) -> bool {
    def.given.is_insertion_point()
}

pub fn given_mode(def: &Definition) -> &GivenMode {
    &def.given
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bcheck::{InteractionKind, parse};
    use std::sync::Mutex;

    struct Lab {
        sent: Mutex<Vec<RequestData>>,
        responder: Box<dyn Fn(&RequestData) -> ResponseData + Send>,
    }
    impl Transport for Lab {
        fn send(&self, req: &RequestData) -> Result<ResponseData, String> {
            self.sent.lock().unwrap().push(req.clone());
            Ok((self.responder)(req))
        }
    }

    fn base(url: &str, body: &str, status: u16) -> Exchange {
        Exchange {
            request: RequestData {
                method: "GET".into(),
                url: url.into(),
                http_version: "HTTP/1.1".into(),
                headers: vec![
                    ("Host".into(), "lab.local".into()),
                    ("Cookie".into(), "sid=1".into()),
                ],
                body: String::new(),
            },
            response: ResponseData {
                status_code: status,
                http_version: "HTTP/1.1".into(),
                headers: vec![],
                body: body.into(),
            },
        }
    }

    fn ok200(_req: &RequestData) -> ResponseData {
        ResponseData {
            status_code: 200,
            http_version: "HTTP/1.1".into(),
            headers: vec![],
            body: String::new(),
        }
    }

    #[test]
    fn host_example_reports_only_when_git_config_found() {
        let def = match parse(include_str!("../../tests/fixtures/bchecks/host.bcheck")) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        // lab serves [core] only at /.git/config
        let lab = Lab {
            sent: Mutex::new(Vec::new()),
            responder: Box::new(|req: &RequestData| ResponseData {
                body: if req.url.ends_with("/.git/config") {
                    "[core]\n".into()
                } else {
                    String::new()
                },
                ..ok200(req)
            }),
        };
        let b = base("http://lab.local/", "", 200);
        let issues = run_definition(&def, &b, None, &lab, None).unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].name, "Host-level");
        assert_eq!(issues[0].severity, "info");
        assert_eq!(issues[0].confidence, "certain");
        assert!(issues[0].detail.contains("/.git/config"));
        // both run-for-each paths were probed
        let sent = lab.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert!(sent.iter().any(|r| r.url.ends_with("/.git/config~")));
    }

    #[test]
    fn host_example_stays_quiet_without_core() {
        let def = match parse(include_str!("../../tests/fixtures/bchecks/host.bcheck")) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let lab = Lab {
            sent: Mutex::new(Vec::new()),
            responder: Box::new(ok200),
        };
        let b = base("http://lab.local/", "", 200);
        assert!(
            run_definition(&def, &b, None, &lab, None)
                .unwrap()
                .is_empty()
        );
    }

    struct Collab {
        kinds: std::collections::HashSet<InteractionKind>,
    }
    impl Collaborator for Collab {
        fn generate_address(&mut self) -> Result<String, String> {
            Ok("xyz.oast.test".into())
        }
        fn has_interaction(&self, kind: InteractionKind) -> bool {
            match kind {
                InteractionKind::Any => !self.kinds.is_empty(),
                other => self.kinds.contains(&other),
            }
        }
    }

    #[test]
    fn collaborator_example_reports_on_http_interaction_only() {
        let def = match parse(include_str!(
            "../../tests/fixtures/bchecks/collaborator.bcheck"
        )) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let lab = Lab {
            sent: Mutex::new(Vec::new()),
            responder: Box::new(ok200),
        };
        let b = base("http://lab.local/a", "", 200);
        let issues = run_definition(
            &def,
            &b,
            None,
            &lab,
            Some(Box::new(Collab {
                kinds: [InteractionKind::Http].into_iter().collect(),
            })),
        )
        .unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, "high");
        // the probe request carried the collaborator referer
        let sent = lab.sent.lock().unwrap();
        assert!(
            sent[0]
                .headers
                .iter()
                .any(|(k, v)| k == "Referer" && v == "xyz.oast.test")
        );

        let lab2 = Lab {
            sent: Mutex::new(Vec::new()),
            responder: Box::new(ok200),
        };
        let issues2 = run_definition(
            &def,
            &b,
            None,
            &lab2,
            Some(Box::new(Collab {
                kinds: std::collections::HashSet::new(),
            })),
        )
        .unwrap();
        assert!(issues2.is_empty());
    }

    #[test]
    fn insertion_point_example_skips_when_answer_already_present() {
        let def = match parse(include_str!(
            "../../tests/fixtures/bchecks/insertion-point.bcheck"
        )) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let lab = Lab {
            sent: Mutex::new(Vec::new()),
            responder: Box::new(ok200),
        };
        let b = base("http://lab.local/calc?n=1", "1787569", 200);
        let ip = InsertionPoint {
            kind: InsertionPointKind::Query,
            name: "n".into(),
            base_value: "1".into(),
        };
        let issues = run_definition(&def, &b, Some(&ip), &lab, None).unwrap();
        assert!(issues.is_empty());
        assert!(
            lab.sent.lock().unwrap().is_empty(),
            "no probe should be sent"
        );
    }

    #[test]
    fn insertion_point_example_reports_on_transformation() {
        let def = match parse(include_str!(
            "../../tests/fixtures/bchecks/insertion-point.bcheck"
        )) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let lab = Lab {
            sent: Mutex::new(Vec::new()),
            responder: Box::new(|_req| ResponseData {
                body: "result: 1787569".into(),
                ..ok200(_req)
            }),
        };
        let b = base("http://lab.local/calc?n=1", "result: ", 200);
        let ip = InsertionPoint {
            kind: InsertionPointKind::Query,
            name: "n".into(),
            base_value: "1".into(),
        };
        let issues = run_definition(&def, &b, Some(&ip), &lab, None).unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, "high");
        assert_eq!(issues[0].confidence, "tentative");
        // payload was appended to the base value
        let sent = lab.sent.lock().unwrap();
        assert!(
            sent[0].url.contains("n=1{{1337*1337}}"),
            "url: {}",
            sent[0].url
        );
    }

    #[test]
    fn report_issue_terminates_unless_and_continue() {
        let src = "metadata:\n language: v2-beta\n name: \"t\"\ngiven host then\n report issue:\n  severity: info\n  confidence: certain\n report issue:\n  name: \"second\"\n  severity: low\n  confidence: firm\n";
        let def = match parse(src) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let lab = Lab {
            sent: Mutex::new(Vec::new()),
            responder: Box::new(ok200),
        };
        let b = base("http://lab.local/", "", 200);
        let issues = run_definition(&def, &b, None, &lab, None).unwrap();
        assert_eq!(issues.len(), 1, "first report issue terminates the check");
        assert_eq!(issues[0].name, "t", "name falls back to metadata");

        let src2 = "metadata:\n language: v2-beta\n name: \"t\"\ngiven host then\n report issue and continue:\n  severity: info\n  confidence: certain\n report issue:\n  name: \"second\"\n  severity: low\n  confidence: firm\n";
        let def2 = match parse(src2) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let issues2 = run_definition(&def2, &b, None, &lab, None).unwrap();
        assert_eq!(issues2.len(), 2);
        assert_eq!(issues2[1].name, "second");
    }

    #[test]
    fn raw_requests_are_parsed_and_sent() {
        let src = "metadata:\n language: v2-beta\n name: \"t\"\ngiven host then\n send request called probe:\n  \"GET /raw-path?x=1 HTTP/1.1\nHost: lab.local\nX-Test: yes\n\nbody-text\"\n if \"hit\" in {probe.response.body} then\n  report issue:\n   severity: low\n   confidence: firm\n end if\n";
        let def = match parse(src) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let lab = Lab {
            sent: Mutex::new(Vec::new()),
            responder: Box::new(|_req| ResponseData {
                body: "hit".into(),
                ..ok200(_req)
            }),
        };
        let b = base("https://lab.local:9443/base", "", 200);
        let issues = run_definition(&def, &b, None, &lab, None).unwrap();
        assert_eq!(issues.len(), 1);
        let sent = lab.sent.lock().unwrap();
        assert_eq!(sent[0].method, "GET");
        // the raw request's own Host header wins over the base authority
        assert_eq!(sent[0].url, "https://lab.local/raw-path?x=1");
        assert!(
            sent[0]
                .headers
                .iter()
                .any(|(k, v)| k == "X-Test" && v == "yes")
        );
        assert_eq!(sent[0].body, "body-text");
    }

    #[test]
    fn raw_request_without_host_header_uses_the_base_authority() {
        let src = "metadata:\n language: v2-beta\n name: \"t\"\ngiven host then\n send request called probe:\n  \"GET /p HTTP/1.1\nX-Test: yes\"\n report issue and continue:\n  severity: low\n  confidence: firm\n";
        let def = match parse(src) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let lab = Lab {
            sent: Mutex::new(Vec::new()),
            responder: Box::new(ok200),
        };
        let b = base("https://lab.local:9443/base", "", 200);
        let _ = run_definition(&def, &b, None, &lab, None).unwrap();
        let sent = lab.sent.lock().unwrap();
        assert_eq!(sent[0].url, "https://lab.local:9443/p");
    }

    #[test]
    fn send_payload_appends_accumulate_and_replacing_resets() {
        let src = "metadata:\n language: v2-beta\n name: \"t\"\ngiven insertion point then\n send payload:\n  appending: \"A\"\n  appending: \"B\"\n send payload:\n  appending: \"C\"\n  replacing: \"D\"\n report issue and continue:\n  severity: low\n  confidence: firm\n";
        let def = match parse(src) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        let lab = Lab {
            sent: Mutex::new(Vec::new()),
            responder: Box::new(ok200),
        };
        let b = base("https://lab.local/?q=base", "", 200);
        let ip = super::InsertionPoint {
            kind: super::super::InsertionPointKind::Query,
            name: "q".into(),
            base_value: "base".into(),
        };
        let _ = run_definition(&def, &b, Some(&ip), &lab, None).unwrap();
        let sent = lab.sent.lock().unwrap();
        assert!(
            sent[0].url.contains("q=baseAB"),
            "appends accumulate: {}",
            sent[0].url
        );
        assert!(
            sent[1].url.contains("q=D"),
            "replacing resets the running value: {}",
            sent[1].url
        );
    }

    #[test]
    fn path_example_reports_backup_with_garbage_control() {
        let def = match parse(include_str!("../../tests/fixtures/bchecks/path.bcheck")) {
            Ok(d) => d,
            Err(e) => panic!("{e:?}"),
        };
        // lab: /page.bak returns the backup (differs from garbage 404s)
        let lab = Lab {
            sent: Mutex::new(Vec::new()),
            responder: Box::new(|req: &RequestData| {
                if req.url.ends_with("/page.bak") {
                    ResponseData {
                        status_code: 200,
                        http_version: "HTTP/1.1".into(),
                        headers: vec![],
                        body: "backup-contents".into(),
                    }
                } else {
                    ResponseData {
                        status_code: 404,
                        http_version: "HTTP/1.1".into(),
                        headers: vec![],
                        body: "nope".into(),
                    }
                }
            }),
        };
        let b = base("http://lab.local/page", "normal page", 200);
        let issues = run_definition(&def, &b, None, &lab, None).unwrap();
        assert_eq!(issues.len(), 1, "issues: {issues:?}");
        assert_eq!(issues[0].name, "Path-level");
        assert!(issues[0].detail.contains("/page.bak"));
    }
}
