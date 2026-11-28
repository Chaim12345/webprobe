use super::*;

// ---------------------------------------------------------------- request checks

/// The group of Burp per-request / per-host checks ported in burp_checks.rs
/// (CORS, path-relative style sheet import, TRACE, OpenAPI). It used to be
/// one function behind a single stop test.
pub const BURP_GROUP: &str = "burp-request";
/// Host-level probes: TRACE echo and OPTIONS (SCANNER_ACTIVE_CHECKS_SERVER_LEVEL_ISSUES).
pub const SERVER_GROUP: &str = "server-level";

pub fn origin_of(cx: &ScanCtx) -> (String, crate::burp_checks::Origin) {
    let scheme = if cx.entry.https { "https" } else { "http" };
    let default_port = if cx.entry.https { 443 } else { 80 };
    let own = crate::burp_checks::Origin::parse(&if cx.port == default_port {
        format!("{scheme}://{}", cx.host)
    } else {
        format!("{scheme}://{}:{}", cx.host, cx.port)
    });
    (scheme.to_string(), own)
}

/// One send of the Burp request group; counts toward progress per request.
pub fn burp_send(cx: &ScanCtx, raw: &[u8]) -> Option<Vec<u8>> {
    let resp = cx.send(raw);
    bump_progress(&cx.shared);
    resp
}

/// CORS (per request), burp_checks::run_cors_check.
pub(crate) struct Cors;

impl RequestCheck for Cors {
    fn id(&self) -> &'static str {
        "active.cors"
    }
    fn issue(&self) -> &'static str {
        "Cross-origin resource sharing"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        use crate::burp_checks as bc;
        let (_, own) = origin_of(cx);
        let req = &cx.req;
        let mut issues = Vec::new();
        let found = bc::run_cors_check(
            req.as_bytes(),
            &cx.baseline.raw,
            cx.entry.https,
            own,
            &mut bc::ThreadRand,
            |origin| {
                let probe = crate::util::replace_or_add_header(req.as_bytes(), "Origin", origin);
                let resp = burp_send(cx, &probe)?;
                Some((probe, resp))
            },
        );
        for f in &found {
            let mut i = mk(
                f.kind.severity(f.flags),
                f.kind.kb_name(),
                &cx.entry,
                bc::cors_detail(f),
            );
            i.confidence = "Certain".into();
            issues
                .push(i.with_evidence(vec![ScanEvidence::new(&f.request, Some(&f.response[..]))]));
        }
        cx.report(issues);
    }
}

/// Path-relative style sheet import (per request), evaluated on the base
/// response.
pub(crate) struct PathRelativeStyleSheet;

impl RequestCheck for PathRelativeStyleSheet {
    fn id(&self) -> &'static str {
        "active.path-relative-style-sheet-import"
    }
    fn issue(&self) -> &'static str {
        "Path-relative style sheet import"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        if let Some((flags, hrefs)) = crate::burp_checks::prssi(&cx.baseline.raw) {
            let mut i = mk(
                "info",
                "Path-relative style sheet import",
                &cx.entry,
                crate::burp_checks::prssi_detail(flags, &hrefs),
            );
            i.confidence = "Tentative".into();
            cx.report(vec![i.with_evidence(vec![ScanEvidence::new(
                cx.req.as_bytes(),
                cx.baseline.resp.as_deref(),
            )])]);
        }
    }
}

/// HTTP TRACE method is enabled (burp.Zs6x), once per host.
pub(crate) struct TraceEnabled;

impl RequestCheck for TraceEnabled {
    fn id(&self) -> &'static str {
        "active.http-trace-enabled"
    }
    fn issue(&self) -> &'static str {
        "HTTP TRACE method is enabled"
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        use crate::burp_checks as bc;
        let (scheme, _) = origin_of(cx);
        let trace_key = format!("trace|{scheme}://{}:{}", cx.host, cx.port);
        if cx.state().openapi_hosts.lock().insert(trace_key) && !cx.stopped() {
            let token: String = {
                use rand::Rng;
                let mut g = rand::thread_rng();
                (0..10)
                    .map(|_| (b'a' + g.gen_range(0..26)) as char)
                    .collect()
            };
            let probe = bc::trace_probe(cx.req.as_bytes(), &token);
            if let Some(resp) = burp_send(cx, &probe)
                && bc::trace_hit(&resp, &token)
            {
                let mut e = cx.entry.clone();
                e.path = "/".into();
                let mut i = mk(
                    "info",
                    "HTTP TRACE method is enabled",
                    &e,
                    format!(
                        "The TRACE method is enabled on this server: the request's Cookie value {token} was echoed back in the response."
                    ),
                );
                i.confidence = "Certain".into();
                cx.report(vec![
                    i.with_evidence(vec![ScanEvidence::new(&probe, Some(&resp[..]))]),
                ]);
            }
        }
    }
}

/// OpenAPI definition found (active scan check), once per host and speed (a
/// later Thorough scan probes the extra paths).
pub(crate) struct OpenApiDefinition;

impl RequestCheck for OpenApiDefinition {
    fn id(&self) -> &'static str {
        "active.openapi-definition"
    }
    fn issue(&self) -> &'static str {
        "OpenAPI definition found (active scan check)"
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        use crate::burp_checks as bc;
        let (scheme, _) = origin_of(cx);
        let thorough = cx.settings.speed >= ScanSpeed::Thorough;
        let key = format!("{scheme}://{}:{}|{}", cx.host, cx.port, thorough);
        if cx.state().openapi_hosts.lock().insert(key) {
            let host_hdr = util::get_header(&util::parse_http(cx.req.as_bytes()).headers, "Host")
                .unwrap_or_else(|| cx.host.to_string());
            let mut found = Vec::new();
            for path in bc::openapi_paths(thorough) {
                if cx.stopped() {
                    break;
                }
                let probe = format!(
                    "GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                );
                if let Some(resp) = burp_send(cx, probe.as_bytes()) {
                    let hit = if path == bc::SWAGGER_UI_INIT {
                        bc::openapi_in_swagger_init(&resp)
                    } else {
                        bc::openapi_in_response(&resp)
                    };
                    if hit {
                        found.push((path, ScanEvidence::new(probe.as_bytes(), Some(&resp[..]))));
                    }
                }
                cx.pace(20);
            }
            let issues = found
                .into_iter()
                .map(|(path, ev)| {
                    let mut e = cx.entry.clone();
                    e.path = path.to_string();
                    let mut i = mk(
                        "info",
                        "OpenAPI definition found (active scan check)",
                        &e,
                        format!("An OpenAPI definition was found at {path}."),
                    );
                    i.confidence = "Certain".into();
                    i.with_evidence(vec![ev])
                })
                .collect();
            cx.report(issues);
        }
    }
}

/// The React2Shell signature: status 500 plus the specific flight-protocol
/// marker. Burp's generic `Error`+`digest` word pair is deliberately not
/// used here: it fires on ordinary error pages.
fn nextjs_or_rsc_baseline(raw: &[u8]) -> bool {
    let parsed = util::parse_http(raw);
    let ct = util::get_header(&parsed.headers, "Content-Type").unwrap_or_default();
    let powered = util::get_header(&parsed.headers, "X-Powered-By").unwrap_or_default();
    let body = String::from_utf8_lossy(&raw[parsed.head_len.min(raw.len())..]);
    ct.to_ascii_lowercase().contains("text/x-component")
        || powered.eq_ignore_ascii_case("Next.js")
        || body.contains("__NEXT_DATA__")
        || body.contains("/_next/")
}

pub(crate) fn react2shell_hit(status: &str, body: &str) -> bool {
    status == "500" && body.contains("E{\"digest\"")
}

/// Flash / Silverlight cross-domain policy (per host), burp.Zm24 + burp.Zbtu:
/// the policy file is fetched once per host and the allowed domains analysed
/// (burp.Zudv / burp.Zebv). One code path; the kind picks the path, the
/// element and the issue name. Bounded: one GET per host and policy file.
pub(crate) struct CrossDomainPolicy {
    pub kind: crate::burp_checks::CrossDomainKind,
}

impl CrossDomainPolicy {
    fn path(&self) -> &'static str {
        match self.kind {
            crate::burp_checks::CrossDomainKind::Flash => "/crossdomain.xml",
            crate::burp_checks::CrossDomainKind::Silverlight => "/clientaccesspolicy.xml",
        }
    }
}

impl RequestCheck for CrossDomainPolicy {
    fn id(&self) -> &'static str {
        match self.kind {
            crate::burp_checks::CrossDomainKind::Flash => "active.flash-cross-domain-policy",
            crate::burp_checks::CrossDomainKind::Silverlight => {
                "active.silverlight-cross-domain-policy"
            }
        }
    }
    fn issue(&self) -> &'static str {
        match self.kind {
            crate::burp_checks::CrossDomainKind::Flash => "Flash cross-domain policy",
            crate::burp_checks::CrossDomainKind::Silverlight => "Silverlight cross-domain policy",
        }
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        let (scheme, _) = origin_of(cx);
        // Once per scheme/host/port and policy file per run: a fetched
        // policy (found or clean) stays claimed; a failed fetch releases
        // the claim so a later item of the same host can retry.
        let key = format!("{scheme}://{}:{}|xdp|{}", cx.host, cx.port, self.path());
        if !cx.state().crossdomain_hosts.lock().insert(key.clone()) || cx.stopped() {
            return;
        }
        let probe = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            self.path(),
            server_host_hdr(cx)
        );
        // One send, no resend on a lost response.
        let Some(resp) = burp_send(cx, probe.as_bytes()) else {
            cx.state().crossdomain_hosts.lock().remove(&key);
            return;
        };
        let found = crate::burp_checks::crossdomain_findings(&resp, &cx.host, self.kind);
        if found.is_empty() {
            return;
        }
        let mut e = cx.entry.clone();
        e.path = self.path().to_string();
        let mut i = mk(
            "high",
            self.issue(),
            &e,
            format!(
                "The cross-domain policy at {} allows access from {}: the policy trusts content served from outside this application's control.",
                self.path(),
                found.join(", ")
            ),
        );
        i.confidence = "Certain".into();
        cx.report(vec![i.with_evidence(vec![ScanEvidence::new(
            probe.as_bytes(),
            Some(&resp[..]),
        )])]);
    }
}

pub fn server_host_hdr(cx: &ScanCtx) -> String {
    util::get_header(&cx.parts.headers, "Host")
        .unwrap_or_else(|| format!("{}:{}", cx.host, cx.port))
}

/// TRACE echoing the request back (cross-site tracing), per request.
pub(crate) struct ServerTrace;

impl RequestCheck for ServerTrace {
    fn id(&self) -> &'static str {
        "active.server-trace-echo"
    }
    fn issue(&self) -> &'static str {
        "Active probe: TRACE method enabled (cross-site tracing)"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn group(&self) -> Option<&'static str> {
        Some(SERVER_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        let host_hdr = server_host_hdr(cx);
        let trace_req = format!(
            "TRACE {p} HTTP/1.1\r\nHost: {host_hdr}\r\nMax-Forwards: 0\r\nConnection: close\r\n\r\n",
            p = cx.parts.path
        );
        if let Some(resp) = &cx.send(trace_req.as_bytes()) {
            let rp = util::parse_http(resp);
            let rbody = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
            let status = rp.first.split_whitespace().nth(1).unwrap_or("").to_string();
            if is_trace_hit(&status, &rbody, &cx.parts.path) {
                cx.report(vec![mk(
                    "medium",
                    "Active probe: TRACE method enabled (cross-site tracing)",
                    &cx.entry,
                    "A TRACE request was answered with the request line and headers echoed back verbatim.",
                )
                .with_evidence(vec![ScanEvidence::new(trace_req.as_bytes(), Some(&resp[..]))])]);
            }
        }
        cx.progress();
        cx.pace(50);
    }
}

/// OPTIONS advertising risky write methods, per request.
pub(crate) struct ServerOptions;

impl RequestCheck for ServerOptions {
    fn id(&self) -> &'static str {
        "active.server-options-methods"
    }
    fn issue(&self) -> &'static str {
        "Active probe: permissive HTTP methods advertised via OPTIONS"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn group(&self) -> Option<&'static str> {
        Some(SERVER_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        let host_hdr = server_host_hdr(cx);
        let options_req = format!(
            "OPTIONS {p} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n",
            p = cx.parts.path
        );
        if let Some(resp) = &cx.send(options_req.as_bytes()) {
            let rp = util::parse_http(resp);
            let status = rp.first.split_whitespace().nth(1).unwrap_or("").to_string();
            let allow = util::get_header(&rp.headers, "Allow");
            let risky = risky_methods_allowed(&status, allow.as_deref());
            if !risky.is_empty() {
                cx.report(vec![
                    mk(
                        "low",
                        "Active probe: permissive HTTP methods advertised via OPTIONS",
                        &cx.entry,
                        format!("Allow advertises risky methods: {}.", risky.join(", ")),
                    )
                    .with_evidence(vec![ScanEvidence::new(
                        options_req.as_bytes(),
                        Some(&resp[..]),
                    )]),
                ]);
            }
        }
        cx.progress();
        cx.pace(50);
    }
}

/// HEADER_MANIPULATION: does the app reflect an attacker-set header value?
/// (SCANNER_ACTIVE_CHECKS_HEADER_MANIPULATION)
pub(crate) struct HeaderManipulation;

impl RequestCheck for HeaderManipulation {
    fn id(&self) -> &'static str {
        "active.header-manipulation"
    }
    fn issue(&self) -> &'static str {
        "Active probe: attacker-set header value reflected (header manipulation)"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        const FIP_MARKER: &str = "wb-fip-marker";
        if cx.stopped() {
            return;
        }
        let manip =
            crate::util::replace_or_add_header(cx.req.as_bytes(), "X-Forwarded-For", FIP_MARKER);
        if let Some(resp) = &cx.send(&manip) {
            let rp = util::parse_http(resp);
            let rbody = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
            if is_header_manipulation_hit(&rbody, &rp.headers, FIP_MARKER) {
                cx.report(vec![
                    mk(
                        "low",
                        "Active probe: attacker-set header value reflected (header manipulation)",
                        &cx.entry,
                        format!(
                            "The response echoes the {FIP_MARKER} value sent in X-Forwarded-For."
                        ),
                    )
                    .with_evidence(vec![ScanEvidence::new(&manip, Some(&resp[..]))]),
                ]);
            }
        }
        cx.progress();
        cx.pace(50);
    }
}

pub fn request_body(cx: &ScanCtx) -> &str {
    &cx.req[cx.parts.head_len.min(cx.req.len())..]
}

pub fn request_ct(cx: &ScanCtx) -> String {
    util::get_header(&cx.parts.headers, "Content-Type").unwrap_or_default()
}

/// XML external entity file read (SCANNER_ACTIVE_CHECKS_XML_INJECTION),
/// Burp's own flow (burp.Zge7): DOCTYPE with a random `xxe?????` entity,
/// the reference placed after an element value, win.ini then passwd, each
/// confirmed by its `X` negative control. XML request bodies only.
pub(crate) struct XxeFileRead;

impl RequestCheck for XxeFileRead {
    fn id(&self) -> &'static str {
        "active.xxe-file-read"
    }
    fn issue(&self) -> &'static str {
        "XML external entity injection"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        let req_ct = request_ct(cx);
        let req_body = request_body(cx);
        let is_xml = req_ct.to_ascii_lowercase().contains("xml")
            || req_body.trim_start().starts_with("<?xml");
        if !is_xml || cx.stopped() {
            return;
        }
        use rand::Rng;
        let entity: String = {
            let mut rng = rand::thread_rng();
            format!(
                "xxe{}",
                (0..5)
                    .map(|_| rng.gen_range(b'a'..=b'z') as char)
                    .collect::<String>()
            )
        };
        let rec = Recorder::default();
        let send = |body: &str| -> Option<String> {
            let mut xxe_req = cx.req.as_bytes().to_vec();
            xxe_req.truncate(cx.parts.head_len.min(cx.req.len()));
            xxe_req.extend_from_slice(body.as_bytes());
            let xxe_req = crate::util::replace_or_add_header(
                &xxe_req,
                "Content-Length",
                &body.len().to_string(),
            );
            let resp = rec.send(cx, body, &xxe_req)?;
            let rp = util::parse_http(&resp);
            Some(String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]).into_owned())
        };
        if let Some(hit) = run_xxe_check(req_body, &cx.baseline.body, &entity, send) {
            cx.report(vec![mk_burp(
                "XML external entity injection",
                "high",
                "Firm",
                &cx.entry,
                "(XML body)",
                format!(
                    "External entity {entity} expanded {} content into the response (markers: {}); the non-existent-file control did not.",
                    hit.file,
                    hit.markers.join(", ")
                ),
            )
            .with_evidence(evidence([rec.last(&hit.payload), rec.next_after(&hit.payload)]))]);
        }
        cx.progress();
        cx.pace(50);
    }
}

/// Rebuild a request whose head is `head` (the base request up to the
/// header/body split) around a raw XML probe `body`: any Content-Encoding
/// and Transfer-Encoding the original carried are dropped (the probe is
/// raw bytes) and Content-Length is set to the body's exact length, so the
/// result is always validly framed.
pub(crate) fn xml_body_request(head: &[u8], body: &str) -> Vec<u8> {
    let req = crate::util::remove_header(head, "Content-Encoding");
    let req = crate::util::remove_header(&req, "Transfer-Encoding");
    let mut req =
        crate::util::replace_or_add_header(&req, "Content-Length", &body.len().to_string());
    req.extend_from_slice(body.as_bytes());
    req
}

/// XML entity expansion (burp.Zgij), Burp's two scopes folded into the
/// request check: the per-request XML base (burp.Ze3z) and the per-insertion
/// points (burp.Zin9) are the element-value points of `xxe_points`. A
/// quadratic DOCTYPE with random entity names and seed, depth 2 confirmed by
/// depth 3; the exponentially repeated seed in the response is the evidence.
/// XML request bodies only. Budgets: at most 2 sends per value point, the
/// points themselves capped by `xxe_points` (10); the expansion asked of the
/// parser is finite and tiny (an 8-byte seed doubled 3 times = 64 bytes),
/// internal general entities only - no external entities, no parameter
/// entities, no external DTD, no timing. A lost response is never resent.
pub(crate) struct XmlEntityExpansion;

impl RequestCheck for XmlEntityExpansion {
    fn id(&self) -> &'static str {
        "active.xml-entity-expansion"
    }
    fn issue(&self) -> &'static str {
        "XML entity expansion"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        let req_ct = request_ct(cx);
        let req_body = request_body(cx);
        let is_xml = req_ct.to_ascii_lowercase().contains("xml")
            || req_body.trim_start().starts_with("<?xml");
        if !is_xml || cx.stopped() {
            return;
        }
        let (name, seed) = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let mut t = |n: usize| {
                (0..n)
                    .map(|_| rng.gen_range(b'a'..=b'z') as char)
                    .collect::<String>()
            };
            (format!("xee{}", t(5)), t(8))
        };
        let rec = Recorder::default();
        let send = |body: &str| -> Option<String> {
            let mut head = cx.req.as_bytes().to_vec();
            head.truncate(cx.parts.head_len.min(cx.req.len()));
            let req = xml_body_request(&head, body);
            let resp = rec.send(cx, body, &req)?;
            let rp = util::parse_http(&resp);
            Some(String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]).into_owned())
        };
        if let Some((probe, _resp)) = run_entity_expansion_check(req_body, &name, &seed, send) {
            cx.report(
                vec![mk_burp(
                    "XML entity expansion",
                    "medium",
                    "Firm",
                    &cx.entry,
                    "(XML body)",
                    "The parser expanded a quadratic DOCTYPE: the random seed came back repeated 4 times at depth 2 and 8 times at the depth-3 confirmation. Only expansion reflected in the response is detected; a parser that expands without reflecting (the blind case) is not.".to_string(),
                )
                .with_evidence(evidence([rec.last(&probe)]))],
            );
        }
        cx.progress();
        cx.pace(50);
    }
}

/// CSRF: replay the state-changing request with its anti-CSRF token
/// parameters removed (SCANNER_ACTIVE_CHECKS_CSRF). Burp builds the attack
/// request by dropping the token parameters (burp.Zg8w.ZU/Zi), re-sends it,
/// and reports when the stripped request still succeeds (burp.Zg8u.Zw).
/// WebProbe mirrors that shape: applicability from burp.Zm9o.ZP, the
/// token-name tables from burp.Zg8w, and the success test from burp.Zg8u.ZN.
pub(crate) struct CsrfTokenNotEnforced;

impl RequestCheck for CsrfTokenNotEnforced {
    fn id(&self) -> &'static str {
        "active.csrf"
    }
    fn issue(&self) -> &'static str {
        "Cross-site request forgery"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        let (req, parts) = (&cx.req, &cx.parts);
        let req_ct = request_ct(cx);
        let req_body = request_body(cx);
        if !csrf_applicable(&parts.method, &req_ct, &parts.headers)
            || !req_ct
                .to_ascii_lowercase()
                .contains("x-www-form-urlencoded")
            || req_body.trim().is_empty()
            || cx.stopped()
        {
            return;
        }
        let req_body_str = req_body.to_string();
        let (stripped, removed) = strip_csrf_params(&req_body_str);
        if removed.is_empty() {
            return;
        }
        let mut csrf_reported = false;
        // Variant 1: remove the token parameters entirely (Zg8w.ZU).
        {
            let mut csrf_req = req.as_bytes()[..parts.head_len.min(req.len())].to_vec();
            csrf_req.extend_from_slice(stripped.as_bytes());
            // The body length changed, so the header must be restamped
            // or the server reads a truncated/oversized body.
            let csrf_req = crate::util::replace_or_add_header(
                &csrf_req,
                "Content-Length",
                &stripped.len().to_string(),
            );
            if let Some(resp) = &cx.send(&csrf_req) {
                let rp = util::parse_http(resp);
                let probe_status = rp.first.split_whitespace().nth(1).unwrap_or("").to_string();
                let baseline_status = base_status(&cx.baseline.resp).unwrap_or_default();
                let location = util::get_header(&rp.headers, "Location").unwrap_or_default();
                if is_csrf_hit(&baseline_status, &probe_status, &location, &parts.path) {
                    csrf_reported = true;
                    cx.report(vec![mk_burp(
                        "Cross-site request forgery",
                        "medium",
                        "Firm",
                        &cx.entry,
                        &removed.join(", "),
                        format!(
                            "The request succeeded after removing the token parameter(s) {}: the server accepted a state-changing request without them.",
                            removed.join(", ")
                        ),
                    )
                    .with_evidence(vec![ScanEvidence::new(&csrf_req, Some(&resp[..]))])]);
                }
            }
            cx.progress();
            cx.pace(50);
        }
        // Variant 2 (burp.Zwfm: "the request is successful if these
        // parameters are assigned empty values"): keep the token
        // parameters but blank their values. Some stacks only check
        // presence, which this defeats.
        if !csrf_reported && !cx.stopped() {
            let (blanked, blanked_names) = blank_csrf_params(&req_body_str);
            if !blanked_names.is_empty() {
                let mut csrf_req = req.as_bytes()[..parts.head_len.min(req.len())].to_vec();
                csrf_req.extend_from_slice(blanked.as_bytes());
                let csrf_req = crate::util::replace_or_add_header(
                    &csrf_req,
                    "Content-Length",
                    &blanked.len().to_string(),
                );
                if let Some(resp) = &cx.send(&csrf_req) {
                    let rp = util::parse_http(resp);
                    let probe_status = rp.first.split_whitespace().nth(1).unwrap_or("").to_string();
                    let baseline_status = base_status(&cx.baseline.resp).unwrap_or_default();
                    let location = util::get_header(&rp.headers, "Location").unwrap_or_default();
                    if is_csrf_hit(&baseline_status, &probe_status, &location, &parts.path) {
                        csrf_reported = true;
                        cx.report(vec![mk_burp(
                            "Cross-site request forgery",
                            "medium",
                            "Firm",
                            &cx.entry,
                            &blanked_names.join(", "),
                            format!(
                                "The request succeeded with the token parameter(s) {} assigned empty values: the server only checks that the fields are present.",
                                blanked_names.join(", ")
                            ),
                        )
                        .with_evidence(vec![ScanEvidence::new(&csrf_req, Some(&resp[..]))])]);
                    }
                }
                cx.progress();
                cx.pace(50);
            }
        }
        // Variant 3 (burp.Zwfm: "the values of these parameters do
        // not change if the submitting form is reloaded without
        // supplying any cookies. Hence, the parameters are probably
        // not being used as anti-CSRF tokens"): re-fetch the form
        // page with no Cookie header and compare the freshly rendered
        // token values against the ones the original request sent.
        if !csrf_reported && !cx.stopped() {
            if let Some(static_hit) =
                csrf_static_token_hit(&|raw: &[u8]| cx.send(raw), &cx.host, parts, &req_body_str)
            {
                cx.report(vec![mk_burp(
                    "Cross-site request forgery",
                    "medium",
                    "Firm",
                    &cx.entry,
                    &static_hit.param,
                    format!(
                        "The form was reloaded without any cookies and parameter {} still carried the value the original request used ({:?}): the token is static, so an attacker can read it once and replay it.",
                        static_hit.param, static_hit.value
                    ),
                )
                .with_evidence(vec![static_hit.exchange])]);
            }
            cx.progress();
        }
    }
}
/// Robots.txt file (per host), burp.Zut6's robots half: fetch /robots.txt
/// over HTTP/1.1 with Connection: close and report only a 200 whose body
/// carries both robots markers `user-agent:` and `allow:` (Zut6.java:64-72,
/// 110-121). Burp's accepted content-type set is stripped from the readable
/// source; an HTML body (a soft-404 page) is rejected instead.
pub(crate) struct RobotsTxt;

impl RequestCheck for RobotsTxt {
    fn id(&self) -> &'static str {
        "active.robots-txt"
    }
    fn issue(&self) -> &'static str {
        "Robots.txt file"
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        let (scheme, _) = origin_of(cx);
        let key = format!("{scheme}://{}:{}|robots", cx.host, cx.port);
        if cx.stopped() {
            return;
        }
        let claim = match cx.host_scope.acquire(key) {
            crate::host_probe_state::Acquire::Acquired(c) => c,
            crate::host_probe_state::Acquire::Complete => return,
            crate::host_probe_state::Acquire::Suppressed => {
                cx.shared.log(
                    "Host probe incomplete/deferred: an attempt already owns this logical run",
                );
                return;
            }
            crate::host_probe_state::Acquire::Capacity => {
                cx.shared.log("Host probe incomplete/deferred: bounded claim capacity exhausted; no request sent");
                return;
            }
        };
        let probe = format!(
            "GET /robots.txt HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            server_host_hdr(cx)
        );
        let Some(resp) = burp_send(cx, probe.as_bytes()) else {
            cx.shared
                .log("Host probe incomplete: transport failed; no same-run retry");
            return;
        };
        let Some(assessed) = super::host_response::assess(&resp, "GET") else {
            cx.shared
                .log("Host probe incomplete: no valid final response head; no same-run retry");
            return;
        };
        let complete = assessed.complete;
        if complete {
            claim.complete();
        } else {
            cx.shared
                .log("Host probe incomplete body: later explicit scan may retry, never this run");
        }
        let status = assessed.status.to_string();
        let body = String::from_utf8_lossy(&assessed.body).to_ascii_lowercase();
        let ctype = assessed.content_type.to_ascii_lowercase();
        let looks_html = ctype.contains("html")
            || body.trim_start().starts_with("<!doctype html")
            || body.trim_start().starts_with("<html");
        if status != "200"
            || looks_html
            || !body.contains("user-agent:")
            || !body.contains("allow:")
        {
            return;
        }
        let mut e = cx.entry.clone();
        e.method = "GET".into();
        e.path = "/robots.txt".to_string();
        let mut i = mk("info", self.issue(), &e, "The site publishes a /robots.txt file. Its entries may reveal paths the site does not want indexed.".to_string());
        if !complete {
            i.detail.push_str(" The response body is incomplete; this positive is based only on the received decoded prefix.");
        }
        i.confidence = "Certain".into();
        cx.report(vec![i.with_evidence(vec![ScanEvidence::new(
            probe.as_bytes(),
            Some(&resp[..]),
        )])]);
    }
}

/// React Server Components RCE, React2Shell (per host), burp.Zgn0: one POST
/// to / with random Next-Action and X-Nextjs-Request-Id values,
/// Next-Router-State-Tree: [""] and a multipart body (part 1 `{}`, part 0
/// `["$1:a:a"]`; Zgn0.java:53-80). A report needs status 500 and the flight
/// error digest marker (Zgn0.java:83-98; the stripped field-to-literal
/// assignments read as `E{"digest"`). Burp's generic `Error`+`digest` pair
/// is deliberately not used: it fires on ordinary error pages.
/// Only runs after a Next.js/RSC baseline fingerprint. Sends one synthetic
/// POST / per host, even if the audited path differs. This is a tentative
/// signature, not confirmation of exploitable code execution.
pub(crate) struct React2Shell;

impl RequestCheck for React2Shell {
    fn id(&self) -> &'static str {
        "active.react2shell"
    }
    fn issue(&self) -> &'static str {
        "React Server Components remote code execution (React2Shell)"
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped() || !cx.runs(self.issue()) || !nextjs_or_rsc_baseline(&cx.baseline.raw) {
            return;
        }
        let (scheme, _) = origin_of(cx);
        let key = format!("{scheme}://{}:{}|react2shell", cx.host, cx.port);
        if cx.stopped() {
            return;
        }
        let claim = match cx.host_scope.acquire(key) {
            crate::host_probe_state::Acquire::Acquired(c) => c,
            crate::host_probe_state::Acquire::Complete => return,
            crate::host_probe_state::Acquire::Suppressed => {
                cx.shared.log(
                    "Host probe incomplete/deferred: an attempt already owns this logical run",
                );
                return;
            }
            crate::host_probe_state::Acquire::Capacity => {
                cx.shared.log("Host probe incomplete/deferred: bounded claim capacity exhausted; no request sent");
                return;
            }
        };
        let (action, req_id, boundary) = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let mut t = |n: usize| {
                (0..n)
                    .map(|_| format!("{:x}", rng.gen_range(0..16u8)))
                    .collect::<String>()
            };
            (t(32), t(32), format!("----WebProbeBoundary{}", t(16)))
        };
        let body = format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n{{}}\r\n--{b}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n[\"$1:a:a\"]\r\n--{b}--\r\n",
            b = boundary
        );
        let probe = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nNext-Action: {action}\r\nX-Nextjs-Request-Id: {req_id}\r\nNext-Router-State-Tree: [\"\"]\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            server_host_hdr(cx),
            body.len()
        );
        let Some(resp) = burp_send(cx, probe.as_bytes()) else {
            cx.shared
                .log("Host probe incomplete: transport failed; no same-run retry");
            return;
        };
        let Some(assessed) = super::host_response::assess(&resp, "POST") else {
            cx.shared
                .log("Host probe incomplete: no valid final response head; no same-run retry");
            return;
        };
        let complete = assessed.complete;
        if complete {
            claim.complete();
        } else {
            cx.shared
                .log("Host probe incomplete body: later explicit scan may retry, never this run");
        }
        let status = assessed.status.to_string();
        let text = String::from_utf8_lossy(&assessed.body);
        if !react2shell_hit(&status, &text) {
            return;
        }
        let mut e = cx.entry.clone();
        e.method = "POST".into();
        e.path = "/".into();
        let mut i = mk(
            "high",
            self.issue(),
            &e,
            "The server answered the React Server Components probe with status 500 and a flight-protocol error digest, the React2Shell signature (CVE-2025-55182 class).".to_string(),
        );
        if !complete {
            i.detail.push_str(" The response body is incomplete; this positive is based only on the received decoded prefix.");
        }
        i.confidence = "Tentative".into();
        cx.report(vec![i.with_evidence(vec![ScanEvidence::new(
            probe.as_bytes(),
            Some(&resp[..]),
        )])]);
    }
}

/// TLS certificate (per host), burp.Zut6's TLS half (G.13, KB 01000100):
/// the chain captured on the host's TLS handshake is analyzed for
/// hostname mismatch, validity dates and trust. Registered alongside
/// Robots (Zcug.java:96-116); Burp reports through the shared
/// Robots/TLS exchange, WebProbe captures with a recording verifier.
pub(crate) struct TlsCertificate;

/// What one TLS capture attempt produced.
enum TlsAttempt {
    /// The chain was captured; analyze it.
    Done(crate::tls_cert::TlsCapture),
    /// The transport came up but no TLS handshake happened (transient or a
    /// plain-HTTP service): the dedupe key is released so a later pass of
    /// the same run retries instead of silencing the host's TLS check.
    Retry,
    /// The configured route itself failed. The key stays claimed: a route
    /// failure is configuration-level, and re-dialling a broken route every
    /// pass would stall the run on the route's own connect timeouts. The
    /// diagnostic is logged once, the check fails closed for this run.
    RouteFailed(String),
}

/// Claim the per-run dedupe key for a host's TLS check, then capture.
/// `None` only when the key was already claimed. A `Retry` outcome
/// releases the key again; `Done` and `RouteFailed` keep it.
fn claim_and_capture(
    seen: &crate::sync::Mutex<std::collections::HashSet<String>>,
    key: String,
    capture: impl FnOnce() -> TlsAttempt,
) -> Option<TlsAttempt> {
    if !seen.lock().insert(key.clone()) {
        return None;
    }
    let cap = capture();
    if matches!(cap, TlsAttempt::Retry) {
        seen.lock().remove(&key);
    }
    Some(cap)
}

impl RequestCheck for TlsCertificate {
    fn id(&self) -> &'static str {
        "active.tls-certificate"
    }
    fn issue(&self) -> &'static str {
        "TLS certificate"
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    fn run(&self, cx: &ScanCtx) {
        let (scheme, _) = origin_of(cx);
        if scheme != "https" {
            return;
        }
        let key = format!("https://{}:{}|tls-cert", cx.host, cx.port);
        if cx.stopped() {
            return;
        }
        // The configured upstream route is a network/privacy boundary: the
        // capture follows it, and a failed route fails closed (logged, not
        // retried this run) rather than falling back to a direct connection.
        let route = cx.shared.upstream_for(&cx.host);
        let roots = cx.shared.tls_roots.lock().clone();
        let Some(attempt) =
            claim_and_capture(
                &cx.state().openapi_hosts,
                key,
                || match crate::tls_cert::capture(
                    &cx.host,
                    cx.port,
                    &route,
                    &roots,
                    std::time::Duration::from_secs(10),
                ) {
                    Ok(Some(cap)) => TlsAttempt::Done(cap),
                    Ok(None) => TlsAttempt::Retry,
                    Err(reason) => TlsAttempt::RouteFailed(reason),
                },
            )
        else {
            return;
        };
        let cap = match attempt {
            TlsAttempt::Done(cap) => cap,
            TlsAttempt::Retry => return,
            TlsAttempt::RouteFailed(reason) => {
                cx.shared.log(&format!(
                    "TLS certificate check: no result for {}:{} - {reason} (route {:?}); not retried this run",
                    cx.host,
                    cx.port,
                    route.kind,
                ));
                return;
            }
        };
        let flags = crate::tls_cert::analyze(&cap, &cx.host, std::time::SystemTime::now());
        if flags.is_empty() {
            if cap.error_kind == Some(crate::tls_cert::VerifyKind::Inconclusive) {
                cx.shared.log(&format!(
                    "TLS certificate check: verification inconclusive for {}:{}: {}",
                    cx.host,
                    cx.port,
                    cap.verify_error.as_deref().unwrap_or("unknown error"),
                ));
            }
            return;
        }
        use crate::tls_cert::CertFlag as F;
        let mut problems = Vec::new();
        if flags.contains(&F::HostnameMismatch) {
            problems.push("is not valid for this hostname");
        }
        if flags.contains(&F::Untrusted) {
            problems.push("is not issued by a trusted authority");
        }
        if flags.contains(&F::NotYetValid) {
            problems.push("is not yet valid");
        }
        if flags.contains(&F::Expired) {
            problems.push("has expired");
        }
        if flags.contains(&F::ValidityUnknown) {
            problems.push("is outside its validity period (a certificate in the chain could not be identified as expired or not yet valid)");
        }
        let summary = crate::tls_cert::leaf_summary(&cap);
        let error = cap
            .verify_error
            .as_deref()
            .map(|e| format!(" Verification failed: {e}."))
            .unwrap_or_default();
        let desc = format!(
            "{} The certificate {}.{error} Clients cannot rely on the server's identity or on the protection of data in transit.",
            summary,
            problems.join(" and ")
        );
        let e = cx.entry.clone();
        let mut i = mk(crate::tls_cert::severity(&flags), self.issue(), &e, desc);
        i.confidence = "Certain".into();
        cx.report(vec![i]);
    }
}

#[cfg(test)]
mod tls_dedupe_tests {
    use super::*;
    use crate::sync::Mutex;
    use crate::tls_cert::TlsCapture;
    use std::collections::HashSet;

    fn cap() -> TlsCapture {
        TlsCapture {
            chain: Vec::new(),
            verify_error: None,
            error_kind: None,
        }
    }

    #[test]
    fn failed_capture_releases_the_key_so_the_host_is_retried() {
        let seen = Mutex::new(HashSet::new());
        let key = "https://h:443|tls-cert".to_string();
        let mut attempts = 0;
        assert!(matches!(
            claim_and_capture(&seen, key.clone(), || {
                attempts += 1;
                TlsAttempt::Retry
            }),
            Some(TlsAttempt::Retry)
        ));
        assert!(seen.lock().is_empty(), "key released on failure");
        assert!(matches!(
            claim_and_capture(&seen, key.clone(), || {
                attempts += 1;
                TlsAttempt::Done(cap())
            }),
            Some(TlsAttempt::Done(_))
        ));
        assert_eq!(attempts, 2, "the second pass retried the capture");
    }

    #[test]
    fn successful_capture_keeps_the_key_and_a_repeat_does_not_capture() {
        let seen = Mutex::new(HashSet::new());
        let key = "https://h:443|tls-cert".to_string();
        assert!(matches!(
            claim_and_capture(&seen, key.clone(), || TlsAttempt::Done(cap())),
            Some(TlsAttempt::Done(_))
        ));
        let mut called = false;
        assert!(
            claim_and_capture(&seen, key, || {
                called = true;
                TlsAttempt::Done(cap())
            })
            .is_none()
        );
        assert!(!called, "an already-claimed host is not captured again");
    }

    #[test]
    fn a_route_failure_keeps_the_key_and_is_not_retried() {
        let seen = Mutex::new(HashSet::new());
        let key = "https://h:443|tls-cert".to_string();
        assert!(matches!(
            claim_and_capture(&seen, key.clone(), || {
                TlsAttempt::RouteFailed("HTTP CONNECT rejected with status 403".into())
            }),
            Some(TlsAttempt::RouteFailed(_))
        ));
        assert!(
            seen.lock().contains(&key),
            "route failure is terminal for the run: key stays claimed"
        );
        let mut called = false;
        assert!(
            claim_and_capture(&seen, key, || {
                called = true;
                TlsAttempt::Retry
            })
            .is_none()
        );
        assert!(!called, "a failed route is not re-dialed on every pass");
    }
}
