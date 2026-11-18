// Active-scan check interface and registry.
//
// `start_active_scan` (scan.rs) is a short driver: it fetches the baseline,
// builds a `ScanCtx`, runs every `PointCheck` of `POINT_CHECKS` on each
// insertion point and then every `RequestCheck` of `REQUEST_CHECKS` once.
// Burp models the same split: insertion-point checks (burp.Zi6p, Zp3a, ...)
// versus per-request and per-host checks (burp.Zs6x TRACE, the APH_ OpenAPI
// checks).
//
// Each check wraps one of the pure `run_*_check(value, baseline, ..., send)`
// functions in scan.rs / active_checks.rs / xss.rs / burp_checks.rs without
// changing them. The bodies below are the blocks that used to sit inline in
// `start_active_scan`, in the same order and under the same conditions: the
// order matters because later checks see the state earlier ones leave
// (`sqli_reported`, the stored-echo markers, the Collaborator slots used) and
// it decides which of two duplicate issues is reported first.
//
// New in the move: every reporting check attaches the exchange(s) that
// confirmed it (`ScanIssue::evidence`) through a `Recorder` that wraps the
// check's own send closure.

use std::cell::RefCell;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::*;

// ---------------------------------------------------------------- context

/// The scan settings a check may read (Settings > Scanner).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Settings {
    pub speed: ScanSpeed,
    pub accuracy: crate::variations::Accuracy,
}

/// The base request's own response, fetched once before any check runs.
pub(crate) struct Baseline {
    /// The response, None when the target did not answer.
    pub resp: Option<Vec<u8>>,
    /// `resp` or empty.
    pub raw: Vec<u8>,
    /// The response body (after the header block), lossy UTF-8.
    pub body: String,
}

/// Count one finished scan request. The planned total is an estimate (it
/// predates several check families), so it is raised whenever the count
/// passes it: the UI never shows more done than total.
pub(crate) fn bump_progress(shared: &Shared) {
    let done = shared.scan.done.fetch_add(1, Ordering::SeqCst) + 1;
    shared.scan.total.fetch_max(done, Ordering::SeqCst);
}

/// Everything a check needs about the scan, shared by all checks.
pub(crate) struct ScanCtx {
    pub shared: Arc<Shared>,
    pub entry: HistEntry,
    /// The base request, lossy UTF-8.
    pub req: String,
    pub parts: util::HttpParts,
    /// Connection target.
    pub host: String,
    pub port: u16,
    /// The base request's Host header ("" when absent).
    pub host_hdr: String,
    pub settings: Settings,
    pub baseline: Baseline,
    /// Collaborator payloads (slot, id, payload), see `oob_slots`.
    pub oob: Vec<(String, String, String)>,
    /// Collaborator ids for the SMTP header injection check.
    pub smtp: Vec<SmtpOob>,
    /// Safe requests the stored XSS check replays after injecting.
    pub retrieval_reqs: Vec<String>,
}

impl ScanCtx {
    /// Fetch the baseline and assemble the context. Runs on the scan thread.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        shared: Arc<Shared>,
        entry: HistEntry,
        req: String,
        parts: util::HttpParts,
        host: String,
        port: u16,
        settings: Settings,
        oob: Vec<(String, String, String)>,
        smtp: Vec<SmtpOob>,
    ) -> ScanCtx {
        // The baseline request runs here, not on the caller's (UI) thread: a
        // slow or dead target used to freeze the window for the full read
        // timeout before the scan even started.
        let base_up = if entry.https {
            net::send_tls_raw(&shared, &host, port, req.as_bytes())
        } else {
            net::send_raw(&shared, &host, port, req.as_bytes())
        };
        let raw = base_up.resp.clone().unwrap_or_default();
        let body = base_up
            .resp
            .as_ref()
            .map(|r| {
                let p = util::parse_http(r);
                String::from_utf8_lossy(&r[p.head_len.min(r.len())..]).into_owned()
            })
            .unwrap_or_default();
        bump_progress(&shared);
        let baseline = Baseline { resp: base_up.resp, raw, body };
        let retrieval_reqs = stored_retrieval_requests(&shared, &entry, &req, &baseline.raw);
        let host_hdr = util::get_header(&parts.headers, "Host").unwrap_or_default();
        ScanCtx { shared, entry, req, parts, host, port, host_hdr, settings, baseline, oob, smtp, retrieval_reqs }
    }

    pub(crate) fn stopped(&self) -> bool {
        self.shared.scan.stop.load(Ordering::SeqCst)
    }

    /// One request to the scan target, plain or TLS.
    pub(crate) fn send(&self, raw: &[u8]) -> Option<Vec<u8>> {
        send_one(&self.shared, self.entry.https, &self.host, self.port, raw)
    }

    /// Whether a check reporting `issue` runs: Burp's issue types always,
    /// WebProbe's own probes only with "WebProbe extra checks" on, so a
    /// default scan sends only the traffic Burp's scan would.
    pub(crate) fn runs(&self, issue: &str) -> bool {
        is_burp_issue(issue) || self.shared.extra_checks.load(Ordering::SeqCst)
    }

    /// Report what a check proved (ids are assigned by the Issues list). Issue types Burp does not have (the
    /// WebProbe-only probes) stay hidden unless Settings > Scanner >
    /// "WebProbe extra checks" is on, the same rule as passive issues, so the
    /// default issue list is the one Burp would produce.
    pub(crate) fn report(&self, mut issues: Vec<ScanIssue>) {
        if !self.shared.extra_checks.load(Ordering::SeqCst) {
            issues.retain(|i| is_burp_issue(&i.name));
        }
        add_issues(&self.shared, issues);
    }

    /// One unit of the progress bar.
    pub(crate) fn progress(&self) {
        bump_progress(&self.shared);
    }

    /// The fixed pause some probes leave after themselves.
    pub(crate) fn pace(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// Scan-wide state that checks share across insertion points.
#[derive(Default)]
pub(crate) struct ScanState {
    /// Markers injected so far, for the stored-echo pass: a marker that
    /// survives into a later response was persisted server-side
    /// (STORED_INPUT / STORED_XSS / STORED_DOM).
    pub stored_markers: Vec<(String, String)>,
    /// Collaborator payloads already embedded (each slot is used once).
    pub oob_used: Vec<usize>,
}

/// One insertion point being audited, with the state its checks share.
pub(crate) struct PointRun<'a> {
    pub idx: usize,
    pub ip: &'a InsertionPoint,
    /// One SQL injection issue per insertion point: once the error-based
    /// test reports, the boolean test is not run.
    pub sqli_reported: bool,
}

// ---------------------------------------------------------------- evidence

/// Records every exchange a check sends, keyed by the payload it was built
/// from, so the confirming exchange(s) can be attached to the issue.
#[derive(Default)]
pub(crate) struct Recorder {
    log: RefCell<Vec<(String, ScanEvidence)>>,
}

impl Recorder {
    /// Send `raw` for `key` and keep a bounded copy of the exchange.
    pub(crate) fn send(&self, cx: &ScanCtx, key: &str, raw: &[u8]) -> Option<Vec<u8>> {
        let resp = cx.send(raw);
        self.note(key, raw, resp.as_deref());
        resp
    }

    /// Keep an exchange sent by other means.
    pub(crate) fn note(&self, key: &str, raw: &[u8], resp: Option<&[u8]>) {
        self.log.borrow_mut().push((key.to_string(), ScanEvidence::new(raw, resp)));
    }

    fn last_index(&self, key: &str) -> Option<usize> {
        self.log.borrow().iter().rposition(|(k, _)| k == key)
    }

    /// The latest exchange sent for `key`.
    pub(crate) fn last(&self, key: &str) -> Option<ScanEvidence> {
        let i = self.last_index(key)?;
        self.log.borrow().get(i).map(|(_, e)| e.clone())
    }

    /// The exchange sent right after the latest one for `key` (a negative
    /// control or a retrieval request).
    pub(crate) fn next_after(&self, key: &str) -> Option<ScanEvidence> {
        let i = self.last_index(key)?;
        self.log.borrow().get(i + 1).map(|(_, e)| e.clone())
    }

    /// The latest exchange for `key` and every exchange after it.
    pub(crate) fn from_last(&self, key: &str) -> Vec<ScanEvidence> {
        let Some(i) = self.last_index(key) else { return Vec::new() };
        self.log.borrow()[i..].iter().map(|(_, e)| e.clone()).collect()
    }
}

fn evidence(items: impl IntoIterator<Item = Option<ScanEvidence>>) -> Vec<ScanEvidence> {
    items.into_iter().flatten().collect()
}

// ---------------------------------------------------------------- interface

/// An active check that runs once per insertion point.
pub(crate) trait PointCheck: Sync {
    /// Stable identifier (exports, tests, future per-check settings).
    /// Check metadata: no runtime reader yet, only the registry tests.
    #[cfg_attr(not(test), allow(dead_code))]
    fn id(&self) -> &'static str;
    /// The issue it reports: Burp's KnowledgeBase name where the check is a
    /// Burp port, otherwise WebProbe's own wording (some WebProbe issues add
    /// the parameter name to it).
    #[cfg_attr(not(test), allow(dead_code))]
    fn issue(&self) -> &'static str;
    /// The insertion-point kinds it applies to: the point-type rules of the
    /// Burp check's applicability test (`Zuit.Zh`). Every implementation
    /// matches every kind explicitly, so a new kind needs a decision.
    fn applies_to(&self, kind: &IpKind) -> bool;
    /// Whether the check is a server-side injection check, which Burp skips
    /// on the skip_server_side_injection_for_parameters list (its `Zh`
    /// calls `Zgx0.Zr`; [`InsertionPoint::skips_server_side`]).
    fn server_side(&self) -> bool;
    /// Audit one insertion point. Reports through `cx.report`.
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun);
}

/// How often a request-level check runs. Check metadata: the once-per-host
/// bookkeeping itself stays inside those checks (`openapi_hosts`).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Once per audited request.
    Request,
    /// Once per host (and session, see `reset_openapi_hosts`).
    Host,
}

/// An active check that runs once per request (or per host), after the
/// insertion-point checks.
pub(crate) trait RequestCheck: Sync {
    /// As [`PointCheck::id`].
    #[cfg_attr(not(test), allow(dead_code))]
    fn id(&self) -> &'static str;
    /// As [`PointCheck::issue`].
    #[cfg_attr(not(test), allow(dead_code))]
    fn issue(&self) -> &'static str;
    #[cfg_attr(not(test), allow(dead_code))]
    fn scope(&self) -> Scope;
    /// Checks in the same group share one stop gate: the group runs when the
    /// scan was not stopped as its first member was reached, and every member
    /// then runs (a member may still look at the stop flag itself). Checks
    /// without a group test the stop flag in `run`.
    fn group(&self) -> Option<&'static str> {
        None
    }
    fn run(&self, cx: &ScanCtx);
}

/// Insertion-point checks, in run order.
pub(crate) static POINT_CHECKS: &[&dyn PointCheck] = &[
    &LightProbes,
    &ExternalInteraction,
    &OsCommandInjection,
    &PathTraversal,
    &LinkManipulation,
    &FilePathManipulation,
    &SsiInjection,
    &TemplateInjection,
    &ReflectedXss,
    &StoredXss,
    &ClientTemplateInjection,
    &PhpCodeInjection,
    &InputReflected,
    &HeaderInjection,
    &OpenRedirect,
    &SqlErrorInjection,
    &SqlBooleanInjection,
    &XmlInjectionOob,
    &XmlInjectionError,
    &LdapInjection,
    &SmtpHeaderInjection,
    &StoredEcho,
];

/// Request-level and host-level checks, in run order.
pub(crate) static REQUEST_CHECKS: &[&dyn RequestCheck] = &[
    &Cors,
    &PathRelativeStyleSheet,
    &TraceEnabled,
    &OpenApiDefinition,
    &ServerTrace,
    &ServerOptions,
    &HeaderManipulation,
    &XxeFileRead,
    &CsrfTokenNotEnforced,
];

/// Whether `check` audits `ip` under `config`: the point type suits it,
/// it is switched on, and a server-side check leaves the points on Burp's
/// skip_server_side_injection_for_parameters list alone.
pub(crate) fn check_applies(check: &dyn PointCheck, ip: &InsertionPoint, config: &crate::scan_config::ScanConfig) -> bool {
    check.applies_to(&ip.kind) && config.check_enabled(check.id()) && !(check.server_side() && ip.skips_server_side())
}

/// The insertion-point phase: every point in order, every applicable check
/// in registry order. Stops at the next point once the scan is stopped.
pub(crate) fn run_point_checks(cx: &ScanCtx, points: &[InsertionPoint]) {
    let mut st = ScanState::default();
    let config = cx.shared.scan_config.lock().unwrap().clone();
    for (idx, ip) in points.iter().enumerate() {
        if cx.stopped() {
            break;
        }
        let mut pt = PointRun { idx, ip, sqli_reported: false };
        for check in POINT_CHECKS {
            if check_applies(*check, ip, &config) && cx.runs(check.issue()) {
                check.run(cx, &mut st, &mut pt);
            }
        }
    }
}

/// The request phase: every request-level check once, honouring groups.
pub(crate) fn run_request_checks(cx: &ScanCtx) {
    let mut open: Vec<(&'static str, bool)> = Vec::new();
    let config = cx.shared.scan_config.lock().unwrap().clone();
    for check in REQUEST_CHECKS {
        if !config.check_enabled(check.id()) || !cx.runs(check.issue()) {
            continue;
        }
        if let Some(g) = check.group() {
            let gate = match open.iter().find(|(name, _)| *name == g) {
                Some((_, o)) => *o,
                None => {
                    let o = !cx.stopped();
                    open.push((g, o));
                    o
                }
            };
            if !gate {
                continue;
            }
        }
        check.run(cx);
    }
}

// ---------------------------------------------------------------- point checks

/// SCANNER_ACTIVE_CHECKS_EXTERNAL_INTERACTION: the Collaborator payload
/// replaces the value, and the id is registered so
/// `scan::match_oob_interactions` raises "External service interaction
/// (DNS)" / "(HTTP)" when the Collaborator logs an interaction for it. Runs
/// only when the scan has Collaborator ids.
pub(crate) struct ExternalInteraction;

impl PointCheck for ExternalInteraction {
    fn id(&self) -> &'static str {
        "active.external-interaction"
    }
    fn issue(&self) -> &'static str {
        "External service interaction (DNS)"
    }
    /// burp.Zxfo.Zh (Collaborator payload in the value: external interaction / out-of-band resource load): via Zibp.ZU not on parameter names; server-side. Burp also skips URL path folders and one header whose name is encrypted in the jar; WebProbe's existing kinds are unchanged.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            // Zibp.ZU: not on added parameter names (Zewr.ZY).
            IpKind::ParamName(_) => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun) {
        let (idx, ip) = (pt.idx, pt.ip);
        let Some((_, token, domain)) = oob_slot(&cx.oob, idx, &ip.name, "ext", &mut st.oob_used) else { return };
        if cx.stopped() {
            return;
        }
        let new_req = inject(&cx.req, ip, domain);
        let resp = cx.send(new_req.as_bytes());
        let issue = mk(
            "medium",
            &format!("Out-of-band payload embedded via parameter {}", ip.name),
            &cx.entry,
            format!("Collaborator token {token} replaced the value; confirmed when an interaction is observed."),
        )
        .with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), resp.as_deref())]);
        cx.shared.oob.register(token.clone(), None, issue);
        cx.progress();
        cx.pace(50);
    }
}

/// WebProbe's own reflected-DOM canary (Burp finds DOM issues by analysing
/// JavaScript, which is not this): a plain canary reflected unencoded into
/// script data or an attribute value of an HTML response. Also seeds the
/// stored-echo markers. A WebProbe extra check, off by default.
pub(crate) struct LightProbes;

impl PointCheck for LightProbes {
    fn id(&self) -> &'static str {
        "active.light-probes"
    }
    fn issue(&self) -> &'static str {
        "Active probe: DOM-based cross-site scripting (reflected)"
    }
    /// WebProbe's own probe (no Burp class): every kind; not a server-side check.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun) {
        let (idx, ip) = (pt.idx, pt.ip);
        if cx.stopped() {
            return;
        }
        let dom_canary = format!("wb{idx:03}dom");
        st.stored_markers.push((ip.name.clone(), dom_canary.clone()));
        let new_req = inject(&cx.req, ip, &format!("{}{dom_canary}", ip.value));
        if let Some(resp) = cx.send(new_req.as_bytes()) {
            let rp = util::parse_http(&resp);
            let body = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
            let ct = util::get_header(&rp.headers, "Content-Type").unwrap_or_default();
            if ct.to_ascii_lowercase().contains("html") && is_reflected_dom_hit(&body, &dom_canary) {
                cx.report(vec![mk(
                    "high",
                    &format!("Active probe: DOM-based cross-site scripting (reflected) via parameter {}", ip.name),
                    &cx.entry,
                    format!("Canary {dom_canary} is reflected unencoded into script data or an attribute value, a context DOM sinks can reach."),
                )
                .with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), Some(&resp[..]))])]);
            }
        }
        cx.progress();
        cx.pace(50);
    }
}

/// OS command injection, Burp's Collaborator flow (burp.Zc99 payloads,
/// burp.Zfw7 verdict). Each `nslookup -q=cname` payload carries its own
/// Collaborator id; a DNS CNAME lookup of that id (burp.Zing.ZR) raises "OS
/// command injection", high and firm (burp.Zwvy.ZR: Zrh confidence 2,
/// severity 4). Burp's other flow (burp.Zxom, `ping` delays) is timing-based
/// and not ported. Runs only when the scan has Collaborator ids.
pub(crate) struct OsCommandInjection;

impl PointCheck for OsCommandInjection {
    fn id(&self) -> &'static str {
        "active.os-command-injection"
    }
    fn issue(&self) -> &'static str {
        "OS command injection"
    }
    /// burp.Zx8l.Zh: every kind but the parameter names; server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            // burp.Zx8l.Zh: never on added parameter names (Zxt3.ZD).
            IpKind::ParamName(_) => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun) {
        let (idx, ip) = (pt.idx, pt.ip);
        let mut ids = std::collections::HashMap::new();
        let payloads = active_checks::os_cmd_payloads(cx.settings.speed, |slot| {
            let (_, token, domain) = oob_slot(&cx.oob, idx, &ip.name, slot, &mut st.oob_used)?;
            ids.insert(slot.to_string(), token.clone());
            Some(domain.clone())
        });
        for (slot, payload, append) in payloads {
            if cx.stopped() {
                break;
            }
            let value = if append { format!("{}{payload}", ip.value) } else { payload.clone() };
            let new_req = inject_payload(&cx.req, ip, &value);
            // Through the scan's own sender: it honours pause and the
            // resource pool, as every other check does.
            let resp = cx.send(new_req.as_bytes());
            let token = ids[slot].clone();
            let issue = mk_point(
                "OS command injection",
                "high",
                "Firm",
                &cx.entry,
                ip,
                format!(
                    "The payload {payload} was {} the {}. The application performed a DNS lookup of type CNAME for the Collaborator id {token}, indicating that the injected command was executed.",
                    if append { "appended to" } else { "submitted as" },
                    ip.describe()
                ),
            )
            .with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), resp.as_deref())]);
            cx.shared.oob.register(token, Some("CNAME"), issue);
            cx.progress();
            cx.pace(50);
        }
    }
}

/// FILE_PATH_TRAVERSAL, Burp's own flow (burp.Zp3a).
pub(crate) struct PathTraversal;

impl PointCheck for PathTraversal {
    fn id(&self) -> &'static str {
        "active.file-path-traversal"
    }
    fn issue(&self) -> &'static str {
        "File path traversal"
    }
    /// burp.Zp3a.Zh -> Zibp.ZZ: not on parameter names (nor headers in Burp; WebProbe's header points keep the check, unchanged); server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            // Zibp.ZZ: not on parameter names (Zewr.ZY cases 1-3).
            IpKind::ParamName(_) => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<String> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, &payload);
            let resp = rec.send(cx, payload, new_req.as_bytes())?;
            let rp = util::parse_http(&resp);
            Some(String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]).into_owned())
        };
        if let Some(hit) = run_traversal_check(&ip.value, &cx.baseline.body, cx.settings.speed, send) {
            let control = traversal_control(&hit.payload);
            cx.report(vec![mk_point(
                "File path traversal",
                "high",
                "Firm",
                &cx.entry,
                ip,
                format!(
                    "Payload {:?} returned {} content (markers: {}); the negative control ({:?}) did not.",
                    encode_query_payload(&hit.payload),
                    hit.file,
                    hit.markers.join(", "),
                    encode_query_payload(&control),
                ),
            )
            .with_evidence(evidence([rec.last(&hit.payload), rec.last(&control)]))]);
        }
        cx.progress();
    }
}

/// Link manipulation (reflected) (burp.Zb_5).
pub(crate) struct LinkManipulation;

impl PointCheck for LinkManipulation {
    fn id(&self) -> &'static str {
        "active.link-manipulation"
    }
    fn issue(&self) -> &'static str {
        "Link manipulation (reflected)"
    }
    /// burp.Zb_5 has no applicability test: every kind; not server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, &payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = run_link_manip_check(&ip.value, send) {
            cx.report(vec![mk_point(
                "Link manipulation (reflected)",
                "info",
                "Firm",
                &cx.entry,
                ip,
                format!("Injected URL {:?} became a link/redirect target: {:?}.", hit.payload, hit.target),
            )
            .with_evidence(evidence([rec.last(&hit.payload)]))]);
        }
        cx.progress();
    }
}

/// File path manipulation (burp.Zsl1).
pub(crate) struct FilePathManipulation;

impl PointCheck for FilePathManipulation {
    fn id(&self) -> &'static str {
        "active.file-path-manipulation"
    }
    fn issue(&self) -> &'static str {
        "File path manipulation"
    }
    /// Part of burp.Zp3a (Zsl1): Zibp.ZZ rules as PathTraversal; server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            // Zibp.ZZ: not on parameter names.
            IpKind::ParamName(_) => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() || cx.baseline.raw.is_empty() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, &payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = run_file_path_manip_check(&ip.value, &cx.baseline.raw, cx.settings.accuracy, send) {
            cx.report(vec![mk_point(
                "File path manipulation",
                "high",
                "Firm",
                &cx.entry,
                ip,
                format!("Same-file paths like {:?} and bogus paths like {:?} gave consistently different responses: the parameter selects a file (attributes: {:?}).", hit.valid, hit.invalid, hit.attributes),
            )
            .with_evidence(evidence([rec.last(&hit.valid), rec.last(&hit.invalid)]))]);
        }
        cx.progress();
    }
}

/// Server-side includes injection (burp.Zexx).
pub(crate) struct SsiInjection;

impl PointCheck for SsiInjection {
    fn id(&self) -> &'static str {
        "active.ssi-injection"
    }
    fn issue(&self) -> &'static str {
        "SSI injection"
    }
    /// burp.Zexx.Zh: every new kind (Burp excludes URL path folders and the User-Agent / Referer headers; WebProbe's existing kinds are unchanged); server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<String> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, &payload);
            let resp = rec.send(cx, payload, new_req.as_bytes())?;
            let rp = util::parse_http(&resp);
            Some(String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]).into_owned())
        };
        if let Some(hit) = run_ssi_check(&ip.value, send) {
            cx.report(vec![mk_point(
                "SSI injection",
                "high",
                "Firm",
                &cx.entry,
                ip,
                format!("SSI directives {:?} were processed by the server.", hit.payload),
            )
            .with_evidence(evidence([rec.last(&format!("{}{}", ip.value, hit.payload))]))]);
        }
        cx.progress();
    }
}

/// Server-side template / code injection (burp.Zi6p.Znq).
pub(crate) struct TemplateInjection;

impl PointCheck for TemplateInjection {
    fn id(&self) -> &'static str {
        "active.server-side-template-injection"
    }
    fn issue(&self) -> &'static str {
        "Server-side template injection"
    }
    /// burp.Zi6p.Zh: every kind, server-side (ZA.Zn(Zr)).
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<String> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, &payload);
            let resp = rec.send(cx, payload, new_req.as_bytes())?;
            let rp = util::parse_http(&resp);
            Some(String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]).into_owned())
        };
        if let Some(hit) = run_ssti_check(&ip.value, send) {
            cx.report(vec![mk_point(
                "Server-side template injection",
                "high",
                "Tentative",
                &cx.entry,
                ip,
                format!("Template expression {:?} ({}) was evaluated by the server.", hit.payload, hit.engine),
            )
            .with_evidence(evidence([rec.last(&format!("{}{}", ip.value, hit.payload))]))]);
        }
        cx.progress();
    }
}

/// Reflected XSS, Burp's breakout engine (burp.Zi6p).
pub(crate) struct ReflectedXss;

impl PointCheck for ReflectedXss {
    fn id(&self) -> &'static str {
        "active.xss-reflected"
    }
    fn issue(&self) -> &'static str {
        "Cross-site scripting (reflected)"
    }
    /// burp.Zi6p.Zh: every kind, server-side: Burp's XSS engine also skips the server-side skip list.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, &payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = crate::xss::run_xss_check(&ip.value, send) {
            cx.report(vec![mk_point(
                "Cross-site scripting (reflected)",
                reflected_xss_severity(&ip.kind),
                "Certain",
                &cx.entry,
                ip,
                format!("Payload {:?} broke out of reflection context {} and executed.", hit.payload, hit.context),
            )
            .with_evidence(evidence([rec.last(&hit.payload)]))]);
        }
        cx.progress();
    }
}

/// Cross-site scripting (stored), burp.Zi6p.ZZ.
pub(crate) struct StoredXss;

impl PointCheck for StoredXss {
    fn id(&self) -> &'static str {
        "active.xss-stored"
    }
    fn issue(&self) -> &'static str {
        "Cross-site scripting (stored)"
    }
    /// burp.Zi6p.Zh (stored half Zi6p.ZZ): every kind, server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() || cx.retrieval_reqs.is_empty() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            rec.send(cx, payload, inject_payload(&cx.req, ip, &payload).as_bytes())
        };
        let retrieve = |i: usize| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            rec.send(cx, "", cx.retrieval_reqs.get(i)?.as_bytes())
        };
        if let Some(hit) = active_checks::run_stored_xss_check(&ip.value, cx.retrieval_reqs.len(), send, retrieve) {
            let later = cx.retrieval_reqs[hit.retrieval].lines().next().unwrap_or("").to_string();
            cx.report(vec![mk_point(
                "Cross-site scripting (stored)",
                "high",
                "Certain",
                &cx.entry,
                ip,
                format!(
                    "Payload {:?} submitted in the {} was stored and returned unencoded (context {}) in the response to the later request {later:?}.",
                    hit.payload,
                    ip.describe_short(false),
                    hit.context
                ),
            )
            .with_evidence(evidence([rec.last(&hit.payload), rec.next_after(&hit.payload)]))]);
        }
        cx.progress();
    }
}

/// Client-side template injection, burp.Zrmh.
pub(crate) struct ClientTemplateInjection;

impl PointCheck for ClientTemplateInjection {
    fn id(&self) -> &'static str {
        "active.client-side-template-injection"
    }
    fn issue(&self) -> &'static str {
        "Client-side template injection"
    }
    /// burp.Zrmh has no applicability test: every kind; not server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            rec.send(cx, payload, inject_payload(&cx.req, ip, &payload).as_bytes())
        };
        // Version banner lookup (burp.Zr54.ZK): same-origin scripts only.
        let fetch_script = |src: &str| -> Option<Vec<u8>> {
            let path = same_origin_path(src, cx.entry.https, &cx.host_hdr, &cx.parts.path)?;
            cx.send(get_request_like(&cx.req, &path).as_bytes())
        };
        if let Some(hit) = active_checks::run_csti_check(&ip.value, send, fetch_script) {
            cx.report(vec![mk_point(
                "Client-side template injection",
                "high",
                hit.confidence(),
                &cx.entry,
                ip,
                format!(
                    "The template expression {} submitted as {:?} was returned unencoded ({:?}) inside an AngularJS ng-app scope.{}",
                    active_checks::CSTI_EXPR,
                    hit.payload,
                    hit.reflection,
                    hit.angular_version.as_deref().map(|v| format!(" The page loads {v}.")).unwrap_or_default()
                ),
            )
            .with_evidence(evidence([rec.last(&hit.payload)]))]);
        }
        cx.progress();
    }
}

/// PHP code injection, echo-based (burp.Zsn3 -> Zgeo.Zv -> Zxvv), on
/// file-upload points only (Zcgg.Zw: the multipart parts that carry a
/// filename). Burp's timing half of Zsn3 (Zwj_) is not ported.
pub(crate) struct PhpCodeInjection;

impl PointCheck for PhpCodeInjection {
    fn id(&self) -> &'static str {
        "active.php-code-injection"
    }
    fn issue(&self) -> &'static str {
        "PHP code injection"
    }
    /// burp.Zsn3 (echo half) on file-upload parts only (Zcgg.Zw); server-side
    /// (Zsn3.Zh: Zg.Zn(ZS)).
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Multipart { filename, .. } => filename.is_some(),
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => false,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        let ip = pt.ip;
        let IpKind::Multipart { index, filename: Some(orig) } = &ip.kind else { return };
        if cx.stopped() {
            return;
        }
        let token = active_checks::rnd_id(20);
        let rec = Recorder::default();
        let send = |fname: &str, ct: &str, content: &str| -> Option<Vec<u8>> {
            rec.send(cx, fname, with_multipart_part(&cx.req, *index, content, Some(fname), Some(ct)).as_bytes())
        };
        let follow = |loc: &str| -> Option<Vec<u8>> {
            let path = same_origin_path(loc, cx.entry.https, &cx.host_hdr, &cx.parts.path)?;
            rec.send(cx, "", get_request_like(&cx.req, &path).as_bytes())
        };
        if let Some(hit) = active_checks::run_php_echo_check(orig, &token, send, follow) {
            let mut ev = rec.from_last(&hit.filename);
            ev.truncate(hit.hop + 1);
            cx.report(vec![mk_point(
                "PHP code injection",
                "high",
                "Certain",
                &cx.entry,
                ip,
                format!(
                    "A file named {:?} was uploaded with the content {:?}. The response{} contained {}, the result of the evaluated expression, so the server executed the uploaded PHP code.",
                    hit.filename,
                    hit.payload,
                    if hit.hop > 0 { format!(" after {} redirect(s)", hit.hop) } else { String::new() },
                    hit.expected
                ),
            )
            .with_evidence(ev)]);
        }
        cx.progress();
    }
}

/// Input returned in response (reflected), burp.Zr02: a random marker
/// replacing, then appended to, the value (Zwe8.PLAIN_REFLECTION_TYPES);
/// reported as information with certain confidence when it comes back.
pub(crate) struct InputReflected;

impl PointCheck for InputReflected {
    fn id(&self) -> &'static str {
        "active.input-returned-reflected"
    }
    fn issue(&self) -> &'static str {
        "Input returned in response (reflected)"
    }
    /// burp.Zr02 has no applicability test: every kind; not server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let value = &ip.value;
        for append in [false, true] {
            let marker: String = {
                use rand::Rng;
                let mut g = rand::thread_rng();
                (0..10).map(|_| (b'a' + g.gen_range(0..26)) as char).collect()
            };
            let v = if append { format!("{value}{marker}") } else { marker.clone() };
            let new_req = inject_payload(&cx.req, ip, &v);
            let resp = cx.send(new_req.as_bytes());
            // Anywhere in the response, headers included: on a fresh
            // project Burp reports lab /redirect, whose value comes
            // back only in Location (scan 5, 2026-11-16). The earlier
            // "body only" reading (fnd_56) came from a reused project,
            // where the REST API lists only issues new to the project.
            let reflected = resp.as_ref().is_some_and(|r| r.windows(marker.len()).any(|w| w == marker.as_bytes()));
            if reflected {
                // Burp's own sentence with its point wording (burp.Zsg0.ZD;
                // live 52685 on Juice Shop: "The value of the URL path
                // filename is copied into the application's response.").
                let mut issue = mk("info", "Input returned in response (reflected)", &cx.entry, format!("The {} is copied into the application's response.", ip.describe()));
                issue.confidence = "Certain".into();
                cx.report(vec![issue.with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), resp.as_deref())])]);
                break;
            }
        }
        cx.progress();
    }
}

/// HTTP response header injection, Burp's own flow (burp.Zwi).
pub(crate) struct HeaderInjection;

impl PointCheck for HeaderInjection {
    fn id(&self) -> &'static str {
        "active.http-response-header-injection"
    }
    fn issue(&self) -> &'static str {
        "HTTP response header injection"
    }
    /// burp.Zwi has no applicability test: every kind; not server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, &payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = run_header_injection_check(&ip.value, send) {
            cx.report(vec![mk_point(
                "HTTP response header injection",
                "high",
                "Certain",
                &cx.entry,
                ip,
                format!("Payload {:?} produced the response header line {:?}.", hit.payload, hit.injected_line),
            )
            .with_evidence(evidence([rec.last(&hit.payload)]))]);
        }
        cx.progress();
    }
}

/// Open redirection, Burp's own flow (burp.Zuag).
pub(crate) struct OpenRedirect;

impl PointCheck for OpenRedirect {
    fn id(&self) -> &'static str {
        "active.open-redirection"
    }
    fn issue(&self) -> &'static str {
        "Open redirection (reflected)"
    }
    /// burp.Zuag has no applicability test: every kind; not server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, &payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = run_open_redirect_check(&ip.value, cx.settings.speed, send) {
            cx.report(vec![mk_point(
                "Open redirection (reflected)",
                "low",
                "Certain",
                &cx.entry,
                ip,
                format!("Payload {:?} made the response redirect to {:?}.", hit.payload, hit.target),
            )
            .with_evidence(evidence([rec.last(&hit.payload)]))]);
        }
        cx.progress();
    }
}

/// Error-based SQL injection, Burp's own flow (burp.Zppj.ZE). One SQL
/// injection issue per insertion point: once this reports, the boolean test
/// is not run (live 52685, lab /user: only the "general error" issue).
/// Its send closure does not look at the stop flag (unchanged).
pub(crate) struct SqlErrorInjection;

impl PointCheck for SqlErrorInjection {
    fn id(&self) -> &'static str {
        "active.sql-injection-error"
    }
    fn issue(&self) -> &'static str {
        "SQL injection"
    }
    /// burp.Zg_c / Zppj: no point-type rule; Zppj returns before probing a point on the server-side skip list.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<String> {
            let new_req = inject_payload(&cx.req, ip, &payload);
            let resp = rec.send(cx, payload, new_req.as_bytes())?;
            Some(String::from_utf8_lossy(&resp).into_owned())
        };
        let baseline_full = String::from_utf8_lossy(&cx.baseline.raw).into_owned();
        if let Some(hit) = run_sql_error_check(&ip.value, &baseline_full, cx.settings.speed, send) {
            // burp.Zh6 issue text: flag 32 (database error) / 64 (general error).
            let general = hit.database == "General";
            // The point as Burp names it (burp.Zsg0.Zj): "<b>q</b> parameter",
            // "<b>sid</b> cookie", "request body", ...
            let text = format!(
                "The {} appears to be vulnerable to SQL injection attacks. A single quote was submitted in the {}, and a {} error message was returned.{} You should review the contents of the error message, and the application's handling of other input, to confirm whether a vulnerability is present.",
                ip.describe_short(true),
                ip.describe_short(false),
                if general { "general" } else { "database" },
                // Only a confirmed hit saw the balanced probe come back clean.
                if hit.confirmed { " Two single quotes were then submitted and the error message disappeared." } else { "" }
            );
            let mut i = mk("high", "SQL injection", &cx.entry, text);
            i.confidence = if general { "Tentative".into() } else if hit.confirmed { "Certain".into() } else { "Firm".into() };
            cx.report(vec![i.with_evidence(evidence([rec.last(&hit.payload), rec.next_after(&hit.payload)]))]);
            pt.sqli_reported = true;
        }
        cx.progress();
    }
}

/// Boolean SQL injection, Burp's own payloads (burp.Zppj). Skipped (one
/// progress unit) when the error-based check already reported this point.
pub(crate) struct SqlBooleanInjection;

impl PointCheck for SqlBooleanInjection {
    fn id(&self) -> &'static str {
        "active.sql-injection-boolean"
    }
    fn issue(&self) -> &'static str {
        "SQL injection"
    }
    /// burp.Zg_c / Zppj: as SqlErrorInjection.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if pt.sqli_reported {
            cx.progress();
            return;
        }
        if cx.stopped() || cx.baseline.raw.is_empty() {
            return;
        }
        let ip = pt.ip;
        let accuracy = cx.settings.accuracy;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, &payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = run_sql_boolean_check(&ip.value, &cx.baseline.raw, cx.settings.speed, accuracy, send) {
            cx.report(vec![mk_point(
                "SQL injection",
                "high",
                "Tentative",
                &cx.entry,
                ip,
                format!(
                    "True condition {:?} and false condition {:?} produced consistently different responses over {} rounds (attributes: {:?}).",
                    hit.positive,
                    hit.negative,
                    accuracy.rounds(),
                    hit.attributes
                ),
            )
            .with_evidence(evidence([rec.last(&hit.positive), rec.last(&hit.negative)]))]);
        }
        cx.progress();
    }
}

/// XML injection, Collaborator half of burp.Zp7s (Zsrh over Ze_f then
/// Zbiw); Zp7s.Zw runs it before the error-based half. Each id is
/// registered so the UI matcher raises "XML injection" (medium, certain:
/// Zc3f -> Zuzl -> Zp9s.ZC) on its DNS interaction.
pub(crate) struct XmlInjectionOob;

impl PointCheck for XmlInjectionOob {
    fn id(&self) -> &'static str {
        "active.xml-injection-collaborator"
    }
    fn issue(&self) -> &'static str {
        "XML injection"
    }
    /// burp.Zp7s.Zh: not on headers or parameter names; server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            // burp.Zp7s.Zh: Zxmw.Zl lists HEADER and the parameter-name kinds.
            IpKind::Header
            | IpKind::ParamName(_) => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun) {
        let (idx, ip) = (pt.idx, pt.ip);
        let name = &ip.name;
        let xsd = oob_slot(&cx.oob, idx, name, "xsd", &mut st.oob_used).map(|(_, t, h)| (t.clone(), h.clone()));
        let xi = oob_slot(&cx.oob, idx, name, "xi", &mut st.oob_used).map(|(_, t, h)| (t.clone(), h.clone()));
        if (xsd.is_some() || xi.is_some()) && !cx.stopped() {
            let rec = Recorder::default();
            let send = |payload: &str| -> Option<Vec<u8>> { rec.send(cx, payload, inject_payload(&cx.req, ip, &payload).as_bytes()) };
            let sent = active_checks::run_xml_oob_check(
                &ip.kind,
                &ip.value,
                xsd.as_ref().map(|(t, h)| (t.as_str(), h.as_str())),
                xi.as_ref().map(|(t, h)| (t.as_str(), h.as_str())),
                send,
            );
            for (token, payload) in sent {
                let issue = mk_point(
                    "XML injection",
                    "medium",
                    "Certain",
                    &cx.entry,
                    ip,
                    format!("The payload {payload} replaced the value; an XML parser that resolves it contacts the Collaborator id {token}."),
                )
                .with_evidence(evidence([rec.last(&payload)]));
                cx.shared.oob.register(token, Some("DNS"), issue);
            }
            cx.progress();
        }
    }
}

/// XML injection, error-based half of burp.Zp7s. Zp7s.Zh refuses HTTP header
/// points (Zxmw.Zl: HEADER and the parameter-name kinds).
pub(crate) struct XmlInjectionError;

impl PointCheck for XmlInjectionError {
    fn id(&self) -> &'static str {
        "active.xml-injection-error"
    }
    fn issue(&self) -> &'static str {
        "XML injection"
    }
    /// burp.Zp7s.Zh: not on headers or parameter names (Zxmw.Zl); server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            // Zxmw.Zl: HEADER and the parameter-name kinds.
            IpKind::Header
            | IpKind::ParamName(_) => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() || cx.baseline.raw.is_empty() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send_payload = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, &payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        let send_base = || -> Option<Vec<u8>> { cx.send(cx.req.as_bytes()) };
        if let Some(markers) = run_xml_injection_check(&ip.value, &cx.baseline.raw, xml_injection_rounds(cx.settings.accuracy), send_payload, send_base) {
            cx.report(vec![mk_point(
                "XML injection",
                "medium",
                "Tentative",
                &cx.entry,
                ip,
                format!("The {} appears to be vulnerable to XML injection. The payload {XML_INJECTION_PAYLOAD} was appended to the value and XML/SOAP markers that were not in the original response appeared: {}.", ip.describe_short(false), markers.join(", ")),
            )
            .with_evidence(evidence([rec.last(&format!("{}{XML_INJECTION_PAYLOAD}", ip.value))]))]);
        }
        cx.progress();
    }
}

/// LDAP injection, Burp's own check (burp.Zwkf + Zmaq).
pub(crate) struct LdapInjection;

impl PointCheck for LdapInjection {
    fn id(&self) -> &'static str {
        "active.ldap-injection"
    }
    fn issue(&self) -> &'static str {
        "LDAP injection"
    }
    /// burp.Zwkf.Zh: no point-type rule; server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() || cx.baseline.raw.is_empty() {
            return;
        }
        let ip = pt.ip;
        let accuracy = cx.settings.accuracy;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, &payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = run_ldap_check(&ip.value, &cx.baseline.raw, cx.settings.speed, accuracy, send) {
            cx.report(vec![mk_point(
                "LDAP injection",
                "high",
                "Firm",
                &cx.entry,
                ip,
                format!(
                    "Always-true filter {:?} and always-false filter {:?} produced consistently different responses over {} rounds (attributes: {:?}).",
                    hit.positive,
                    hit.negative,
                    accuracy.rounds(),
                    hit.attributes
                ),
            )
            .with_evidence(evidence([rec.last(&hit.positive), rec.last(&hit.negative)]))]);
        }
        cx.progress();
    }
}

/// SMTP header injection, Burp's own check (burp.Zgcg/Zrok): two payloads
/// per parameter, each with its own Collaborator id; the response is not
/// inspected, an SMTP interaction for the id raises the issue
/// (scan::match_oob_interactions, kind SMTP).
pub(crate) struct SmtpHeaderInjection;

impl PointCheck for SmtpHeaderInjection {
    fn id(&self) -> &'static str {
        "active.smtp-header-injection"
    }
    fn issue(&self) -> &'static str {
        "SMTP header injection"
    }
    /// burp.Zgcg.Zh: every new kind (Burp excludes URL path folders and User-Agent / Referer; existing kinds unchanged); server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        let ip = pt.ip;
        let (name, value) = (&ip.name, &ip.value);
        let Some(plan) = cx.smtp.iter().find(|p| &p.param == name) else { return };
        for (enclosed, (token, collab_host)) in [(false, &plan.simple), (true, &plan.enclosed)] {
            if cx.stopped() {
                break;
            }
            let (r3, r1) = {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let mut pick = |n: usize| (0..n).map(|_| rng.gen_range(b'a'..=b'z') as char).collect::<String>();
                (pick(3), pick(1))
            };
            let payload = smtp_payload(value, enclosed, collab_host, &r3, &r1);
            let new_req = inject_payload(&cx.req, ip, &payload);
            let resp = cx.send(new_req.as_bytes());
            let issue = mk_point(
                "SMTP header injection",
                "medium",
                "Certain",
                &cx.entry,
                ip,
                format!("Payload appended a BCC header to user@{collab_host}; awaiting an SMTP interaction for id {token}."),
            )
            .with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), resp.as_deref())]);
            cx.shared.oob.register(token.clone(), Some("SMTP"), issue);
        }
    }
}

/// Stored-echo pass (SCANNER_ACTIVE_CHECKS_STORED_INPUT / STORED_XSS /
/// STORED_DOM). Burp detects the stored variants by revisiting pages after
/// injection. Light-weight equivalent: once a point's probes are done,
/// re-fetch the original URL and classify any surviving marker of this or
/// any earlier point. A marker in a later response to the original URL was
/// persisted server-side and echoed where the attacker does not control the
/// input.
pub(crate) struct StoredEcho;

impl PointCheck for StoredEcho {
    fn id(&self) -> &'static str {
        "active.stored-echo"
    }
    fn issue(&self) -> &'static str {
        "Active probe: value of parameter appears stored"
    }
    /// WebProbe's own pass (no Burp class): every kind; not server-side.
    fn applies_to(&self, kind: &IpKind) -> bool {
        match kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, _pt: &mut PointRun) {
        if st.stored_markers.is_empty() || cx.stopped() {
            return;
        }
        let re_req = rebuild_with_path(&cx.req, &cx.parts.path);
        let resp = cx.send(re_req.as_bytes());
        if let Some(resp) = &resp {
            let rp = util::parse_http(resp);
            let rbody = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
            let ev = ScanEvidence::new(re_req.as_bytes(), Some(&resp[..]));
            let mut issues = Vec::new();
            for (pname, marker) in &st.stored_markers {
                if let Some(kind) = stored_echo_hit(&rbody, marker) {
                    let (sev, title, detail) = match kind {
                        // Only plain canaries are tracked here: one
                        // inside a script tag is a stored DOM context,
                        // not proof of XSS (that is the breakout-based
                        // "Cross-site scripting (stored)" check).
                        "xss" | "dom" => (
                            "high",
                            format!("Active probe: stored DOM-based cross-site scripting via parameter {pname}"),
                            format!("Canary {marker} injected earlier is now reflected into script data or an attribute value of the original URL's response."),
                        ),
                        _ => (
                            "medium",
                            format!("Active probe: value of parameter {pname} appears stored"),
                            format!("Marker {marker} injected earlier shows up in a later response to the original URL (STORED_INPUT)."),
                        ),
                    };
                    issues.push(mk(sev, &title, &cx.entry, detail).with_evidence(vec![ev.clone()]));
                }
            }
            cx.report(issues);
        }
        cx.progress();
        cx.pace(50);
    }
}

// ---------------------------------------------------------------- request checks

/// The group of Burp per-request / per-host checks ported in burp_checks.rs
/// (CORS, path-relative style sheet import, TRACE, OpenAPI). It used to be
/// one function behind a single stop test.
const BURP_GROUP: &str = "burp-request";
/// Host-level probes: TRACE echo and OPTIONS (SCANNER_ACTIVE_CHECKS_SERVER_LEVEL_ISSUES).
const SERVER_GROUP: &str = "server-level";

fn origin_of(cx: &ScanCtx) -> (String, crate::burp_checks::Origin) {
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
fn burp_send(cx: &ScanCtx, raw: &[u8]) -> Option<Vec<u8>> {
    let up = if cx.entry.https {
        net::send_tls_raw(&cx.shared, &cx.host, cx.port, raw)
    } else {
        net::send_raw(&cx.shared, &cx.host, cx.port, raw)
    };
    bump_progress(&cx.shared);
    up.resp
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
        let found = bc::run_cors_check(req.as_bytes(), &cx.baseline.raw, cx.entry.https, own, &mut bc::ThreadRand, |origin| {
            let probe = net::replace_or_add_header(req.as_bytes(), "Origin", origin);
            let resp = burp_send(cx, &probe)?;
            Some((probe, resp))
        });
        for f in &found {
            let mut i = mk(f.kind.severity(f.flags), f.kind.kb_name(), &cx.entry, bc::cors_detail(f));
            i.confidence = "Certain".into();
            issues.push(i.with_evidence(vec![ScanEvidence::new(&f.request, Some(&f.response[..]))]));
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
            let mut i = mk("info", "Path-relative style sheet import", &cx.entry, crate::burp_checks::prssi_detail(flags, &hrefs));
            i.confidence = "Tentative".into();
            cx.report(vec![i.with_evidence(vec![ScanEvidence::new(cx.req.as_bytes(), cx.baseline.resp.as_deref())])]);
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
        if openapi_hosts().lock().unwrap().insert(trace_key) && !cx.stopped() {
            let token: String = {
                use rand::Rng;
                let mut g = rand::thread_rng();
                (0..10).map(|_| (b'a' + g.gen_range(0..26)) as char).collect()
            };
            let probe = bc::trace_probe(cx.req.as_bytes(), &token);
            if let Some(resp) = burp_send(cx, &probe) {
                if bc::trace_hit(&resp, &token) {
                    let mut e = cx.entry.clone();
                    e.path = "/".into();
                    let mut i = mk(
                        "info",
                        "HTTP TRACE method is enabled",
                        &e,
                        format!("The TRACE method is enabled on this server: the request's Cookie value {token} was echoed back in the response."),
                    );
                    i.confidence = "Certain".into();
                    cx.report(vec![i.with_evidence(vec![ScanEvidence::new(&probe, Some(&resp[..]))])]);
                }
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
        if openapi_hosts().lock().unwrap().insert(key) {
            let host_hdr = util::get_header(&util::parse_http(cx.req.as_bytes()).headers, "Host").unwrap_or_else(|| cx.host.to_string());
            let mut found = Vec::new();
            for path in bc::openapi_paths(thorough) {
                if cx.stopped() {
                    break;
                }
                let probe = format!("GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\nAccept: */*\r\nConnection: close\r\n\r\n");
                if let Some(resp) = burp_send(cx, probe.as_bytes()) {
                    let hit = if path == bc::SWAGGER_UI_INIT { bc::openapi_in_swagger_init(&resp) } else { bc::openapi_in_response(&resp) };
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

fn server_host_hdr(cx: &ScanCtx) -> String {
    util::get_header(&cx.parts.headers, "Host").unwrap_or_else(|| format!("{}:{}", cx.host, cx.port))
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
                cx.report(vec![mk(
                    "low",
                    "Active probe: permissive HTTP methods advertised via OPTIONS",
                    &cx.entry,
                    format!("Allow advertises risky methods: {}.", risky.join(", ")),
                )
                .with_evidence(vec![ScanEvidence::new(options_req.as_bytes(), Some(&resp[..]))])]);
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
        let manip = net::replace_or_add_header(cx.req.as_bytes(), "X-Forwarded-For", FIP_MARKER);
        if let Some(resp) = &cx.send(&manip) {
            let rp = util::parse_http(resp);
            let rbody = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
            if is_header_manipulation_hit(&rbody, &rp.headers, FIP_MARKER) {
                cx.report(vec![mk(
                    "low",
                    "Active probe: attacker-set header value reflected (header manipulation)",
                    &cx.entry,
                    format!("The response echoes the {FIP_MARKER} value sent in X-Forwarded-For."),
                )
                .with_evidence(vec![ScanEvidence::new(&manip, Some(&resp[..]))])]);
            }
        }
        cx.progress();
        cx.pace(50);
    }
}

fn request_body(cx: &ScanCtx) -> &str {
    &cx.req[cx.parts.head_len.min(cx.req.len())..]
}

fn request_ct(cx: &ScanCtx) -> String {
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
        let is_xml = req_ct.to_ascii_lowercase().contains("xml") || req_body.trim_start().starts_with("<?xml");
        if !is_xml || cx.stopped() {
            return;
        }
        use rand::Rng;
        let entity: String = {
            let mut rng = rand::thread_rng();
            format!("xxe{}", (0..5).map(|_| rng.gen_range(b'a'..=b'z') as char).collect::<String>())
        };
        let rec = Recorder::default();
        let send = |body: &str| -> Option<String> {
            let mut xxe_req = cx.req.as_bytes().to_vec();
            xxe_req.truncate(cx.parts.head_len.min(cx.req.len()));
            xxe_req.extend_from_slice(body.as_bytes());
            let xxe_req = net::replace_or_add_header(&xxe_req, "Content-Length", &body.len().to_string());
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
        if !(csrf_applicable(&parts.method, &req_ct, &parts.headers)
            && req_ct.to_ascii_lowercase().contains("x-www-form-urlencoded")
            && !req_body.trim().is_empty()
            && !cx.stopped())
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
            let csrf_req = net::replace_or_add_header(&csrf_req, "Content-Length", &stripped.len().to_string());
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
                let csrf_req = net::replace_or_add_header(&csrf_req, "Content-Length", &blanked.len().to_string());
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
            if let Some(static_hit) = csrf_static_token_hit(&cx.shared, cx.entry.https, &cx.host, cx.port, parts, &req_body_str) {
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

// ---------------------------------------------------------------- issue types

/// Burp's numeric issue type for every name in kb_issue_names.txt, from the
/// `typeIndex` field of Burp's KnowledgeBase (resources/KnowledgeBase/Issues
/// /*.json of build 52685; the file-name prefix is the same number in hex
/// except for two entries, where the JSON field wins).
pub(crate) const KB_ISSUE_TYPES: &[(&str, u64)] = &[
    ("ASP.NET ViewState without MAC enabled", 0x00400600),
    ("ASP.NET debugging enabled", 0x00100800),
    ("ASP.NET tracing enabled", 0x00100280),
    ("Ajax request header manipulation (DOM-based)", 0x00500c00),
    ("Ajax request header manipulation (reflected DOM-based)", 0x00500c01),
    ("Ajax request header manipulation (stored DOM-based)", 0x00500c02),
    ("BCheck generated issue", 0x09000000),
    ("Backup file", 0x006000d8),
    ("Bambda generated issue", 0x09000000),
    ("Base64-encoded data in parameter", 0x00700200),
    ("Broken access control", 0x00100850),
    ("Browser cross-site scripting filter disabled", 0x005009b0),
    ("CSS injection (reflected)", 0x00501300),
    ("CSS injection (stored)", 0x00501301),
    ("Cacheable HTTPS response", 0x00700100),
    ("Cleartext submission of password", 0x00300100),
    ("Client-side HTTP parameter pollution (reflected)", 0x00501400),
    ("Client-side HTTP parameter pollution (stored)", 0x00501401),
    ("Client-side JSON injection (DOM-based)", 0x00200370),
    ("Client-side JSON injection (reflected DOM-based)", 0x00200371),
    ("Client-side JSON injection (stored DOM-based)", 0x00200372),
    ("Client-side SQL injection (DOM-based)", 0x00200330),
    ("Client-side SQL injection (reflected DOM-based)", 0x00200331),
    ("Client-side SQL injection (stored DOM-based)", 0x00200332),
    ("Client-side XPath injection (DOM-based)", 0x00200360),
    ("Client-side XPath injection (reflected DOM-based)", 0x00200361),
    ("Client-side XPath injection (stored DOM-based)", 0x00200362),
    ("Client-side desync", 0x00200141),
    ("Client-side prototype pollution", 0x00200316),
    ("Client-side template injection", 0x00200308),
    ("Content security policy: allowlisted script resources", 0x00200503),
    ("Content security policy: allows clickjacking", 0x00200507),
    ("Content security policy: allows form hijacking", 0x00200508),
    ("Content security policy: allows untrusted script execution", 0x00200504),
    ("Content security policy: allows untrusted style execution", 0x00200505),
    ("Content security policy: malformed syntax", 0x00200506),
    ("Content security policy: not enforced", 0x00200509),
    ("Content type incorrectly stated", 0x00800400),
    ("Content type is not specified", 0x00800500),
    ("Cookie manipulation (DOM-based)", 0x00500b00),
    ("Cookie manipulation (reflected DOM-based)", 0x00500b01),
    ("Cookie manipulation (stored DOM-based)", 0x00500b02),
    ("Cookie scoped to parent domain", 0x00500300),
    ("Cookie without HttpOnly flag set", 0x00500600),
    ("Credit card numbers disclosed", 0x00600500),
    ("Cross-domain POST", 0x00400500),
    ("Cross-domain Referer leakage", 0x00500400),
    ("Cross-domain script include", 0x00500500),
    ("Cross-origin resource sharing", 0x00200600),
    ("Cross-origin resource sharing: all subdomains trusted", 0x00200603),
    ("Cross-origin resource sharing: arbitrary origin trusted", 0x00200601),
    ("Cross-origin resource sharing: unencrypted origin trusted", 0x00200602),
    ("Cross-site request forgery", 0x00200700),
    ("Cross-site scripting (DOM-based)", 0x00200310),
    ("Cross-site scripting (reflected DOM-based)", 0x00200311),
    ("Cross-site scripting (reflected)", 0x00200300),
    ("Cross-site scripting (stored DOM-based)", 0x00200312),
    ("Cross-site scripting (stored)", 0x00200100),
    ("DOM data manipulation (DOM-based)", 0x00501200),
    ("DOM data manipulation (reflected DOM-based)", 0x00501201),
    ("DOM data manipulation (stored DOM-based)", 0x00501202),
    ("Database connection string disclosed", 0x00600080),
    ("Denial of service (DOM-based)", 0x00500d00),
    ("Denial of service (reflected DOM-based)", 0x00500d01),
    ("Denial of service (stored DOM-based)", 0x00500d02),
    ("Directory listing", 0x00600100),
    ("Document domain manipulation (DOM-based)", 0x00501100),
    ("Document domain manipulation (reflected DOM-based)", 0x00501101),
    ("Document domain manipulation (stored DOM-based)", 0x00501102),
    ("Duplicate cookies set", 0x00400a00),
    ("Email addresses disclosed", 0x00600200),
    ("Expression Language injection", 0x00100f20),
    ("Extension generated issue", 0x08000000),
    ("External service interaction (DNS)", 0x00300200),
    ("External service interaction (HTTP)", 0x00300210),
    ("External service interaction (SMTP)", 0x00300220),
    ("File path manipulation", 0x00100b00),
    ("File path traversal", 0x00100300),
    ("File upload functionality", 0x00500980),
    ("Flash cross-domain policy", 0x00200400),
    ("Form action hijacking (reflected)", 0x00501500),
    ("Form action hijacking (stored)", 0x00501501),
    ("Frameable response (potential Clickjacking)", 0x005009a0),
    ("GraphQL content type not validated", 0x00200514),
    ("GraphQL endpoint discovered", 0x00200511),
    ("GraphQL endpoint found", 0x00200510),
    ("GraphQL introspection enabled", 0x00200512),
    ("GraphQL suggestions enabled", 0x00200513),
    ("HTML does not specify charset", 0x00800200),
    ("HTML uses unrecognized charset", 0x00800300),
    ("HTML5 storage manipulation (DOM-based)", 0x00500f00),
    ("HTML5 storage manipulation (reflected DOM-based)", 0x00500f01),
    ("HTML5 storage manipulation (stored DOM-based)", 0x00500f02),
    ("HTML5 web message manipulation (DOM-based)", 0x00500e00),
    ("HTML5 web message manipulation (reflected DOM-based)", 0x00500e01),
    ("HTML5 web message manipulation (stored DOM-based)", 0x00500e02),
    ("HTTP PUT method is enabled", 0x00100900),
    ("HTTP TRACE method is enabled", 0x00500a00),
    ("HTTP request smuggling", 0x00200140),
    ("HTTP response header injection", 0x00200200),
    ("Hidden HTTP 2", 0x01000500),
    ("Input returned in response (reflected)", 0x00400c00),
    ("Input returned in response (stored)", 0x00400b00),
    ("JWT arbitrary jku header supported", 0x00200904),
    ("JWT arbitrary x5u header supported", 0x00200905),
    ("JWT none algorithm supported", 0x00200901),
    ("JWT private key disclosed", 0x00600800),
    ("JWT self-signed JWK header supported", 0x00200902),
    ("JWT signature not verified", 0x00200900),
    ("JWT weak HMAC secret", 0x00200903),
    ("JavaScript injection (DOM-based)", 0x00200320),
    ("JavaScript injection (reflected DOM-based)", 0x00200321),
    ("JavaScript injection (stored DOM-based)", 0x00200322),
    ("Json Web Key Set disclosed", 0x00600700),
    ("LDAP injection", 0x00100500),
    ("Link manipulation (DOM-based)", 0x00501000),
    ("Link manipulation (reflected DOM-based)", 0x00501001),
    ("Link manipulation (reflected)", 0x00501003),
    ("Link manipulation (stored DOM-based)", 0x00501002),
    ("Link manipulation (stored)", 0x00501004),
    ("Local file path manipulation (DOM-based)", 0x00200350),
    ("Local file path manipulation (reflected DOM-based)", 0x00200351),
    ("Local file path manipulation (stored DOM-based)", 0x00200352),
    ("Long redirection response", 0x00400800),
    ("Manually generated issue", 0x08008000),
    ("Mixed content", 0x01000400),
    ("Multiple content types specified", 0x00800100),
    ("OS command injection", 0x00100100),
    ("Open redirection (DOM-based)", 0x00500110),
    ("Open redirection (reflected DOM-based)", 0x00500111),
    ("Open redirection (reflected)", 0x00500100),
    ("Open redirection (stored DOM-based)", 0x00500112),
    ("Open redirection (stored)", 0x00500101),
    ("OpenAPI definition found (active scan check)", 0x00600900),
    ("OpenAPI definition found (passive scan check)", 0x00600901),
    ("Out-of-band resource load (HTTP)", 0x00100a00),
    ("PHP code injection", 0x00100c00),
    ("Password field with autocomplete enabled", 0x00500800),
    ("Password returned in URL query string", 0x00400400),
    ("Password returned in later response", 0x00400200),
    ("Password submitted using GET method", 0x00400300),
    ("Password value set in cookie", 0x00500900),
    ("Path-relative style sheet import", 0x00200328),
    ("Perl code injection", 0x00100e00),
    ("Private IP addresses disclosed", 0x00600300),
    ("Private key disclosed", 0x00600550),
    ("Python code injection", 0x00100f10),
    ("React Server Components remote code execution (React2Shell)", 0x00100e00),
    ("Referer-dependent response", 0x00400100),
    ("Request URL override", 0x00400f00),
    ("Robots.txt file", 0x00600600),
    ("Ruby code injection", 0x00100f00),
    ("SMTP header injection", 0x00200800),
    ("SQL injection", 0x00100200),
    ("SQL injection (second order)", 0x00100210),
    ("SQL statement in request parameter", 0x00400480),
    ("SSI injection", 0x00101100),
    ("Serialized object in HTTP message", 0x00400900),
    ("Server-side JavaScript code injection", 0x00100d00),
    ("Server-side template injection", 0x00101080),
    ("Session token in URL", 0x00500700),
    ("Silverlight cross-domain policy", 0x00200500),
    ("Social security numbers disclosed", 0x00600400),
    ("Source code disclosure", 0x006000b0),
    ("Spoofable client IP address", 0x00400110),
    ("Strict transport security not enforced", 0x01000300),
    ("Suspicious input transformation (reflected)", 0x00400d00),
    ("Suspicious input transformation (stored)", 0x00400e00),
    ("TLS certificate", 0x01000100),
    ("TLS cookie without secure flag set", 0x00500200),
    ("Unencrypted communications", 0x01000200),
    ("Unidentified code injection", 0x00101000),
    ("User agent-dependent response", 0x00400120),
    ("Vulnerable JavaScript dependency", 0x00500080),
    ("Web cache deception", 0x00200650),
    ("Web cache poisoning", 0x00200180),
    ("WebSocket URL poisoning (DOM-based)", 0x00200340),
    ("WebSocket URL poisoning (reflected DOM-based)", 0x00200341),
    ("WebSocket URL poisoning (stored DOM-based)", 0x00200342),
    ("XML entity expansion", 0x00400700),
    ("XML external entity injection", 0x00100400),
    ("XML injection", 0x00100700),
    ("XPath injection", 0x00100600),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The registries are the run order; reordering changes which duplicate
    /// is reported first and must be deliberate.
    #[test]
    fn registry_order_is_pinned() {
        let points: Vec<&str> = POINT_CHECKS.iter().map(|c| c.id()).collect();
        assert_eq!(
            points,
            [
                "active.light-probes",
                "active.external-interaction",
                "active.os-command-injection",
                "active.file-path-traversal",
                "active.link-manipulation",
                "active.file-path-manipulation",
                "active.ssi-injection",
                "active.server-side-template-injection",
                "active.xss-reflected",
                "active.xss-stored",
                "active.client-side-template-injection",
                "active.php-code-injection",
                "active.input-returned-reflected",
                "active.http-response-header-injection",
                "active.open-redirection",
                "active.sql-injection-error",
                "active.sql-injection-boolean",
                "active.xml-injection-collaborator",
                "active.xml-injection-error",
                "active.ldap-injection",
                "active.smtp-header-injection",
                "active.stored-echo",
            ]
        );
        let requests: Vec<(&str, Scope, Option<&str>)> = REQUEST_CHECKS.iter().map(|c| (c.id(), c.scope(), c.group())).collect();
        assert_eq!(
            requests,
            [
                ("active.cors", Scope::Request, Some(BURP_GROUP)),
                ("active.path-relative-style-sheet-import", Scope::Request, Some(BURP_GROUP)),
                ("active.http-trace-enabled", Scope::Host, Some(BURP_GROUP)),
                ("active.openapi-definition", Scope::Host, Some(BURP_GROUP)),
                ("active.server-trace-echo", Scope::Request, Some(SERVER_GROUP)),
                ("active.server-options-methods", Scope::Request, Some(SERVER_GROUP)),
                ("active.header-manipulation", Scope::Request, None),
                ("active.xxe-file-read", Scope::Request, None),
                ("active.csrf", Scope::Request, None),
            ]
        );
        let mut ids: Vec<&str> = points.iter().copied().chain(requests.iter().map(|r| r.0)).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), POINT_CHECKS.len() + REQUEST_CHECKS.len(), "ids must be unique");
    }

    /// A check that ports a Burp check names Burp's issue, so its issues
    /// get Burp's type id; WebProbe's own probes name theirs and get 0.
    #[test]
    fn check_issue_names_resolve_to_burp_types() {
        let own = ["active.light-probes", "active.stored-echo", "active.server-trace-echo", "active.server-options-methods", "active.header-manipulation"];
        let issues = POINT_CHECKS.iter().map(|c| (c.id(), c.issue())).chain(REQUEST_CHECKS.iter().map(|c| (c.id(), c.issue())));
        for (id, issue) in issues {
            assert_eq!(issue_type_id(issue) == 0, own.contains(&id), "{id}: {issue}");
        }
    }

    #[test]
    fn every_burp_issue_name_has_a_type() {
        for name in KB_ISSUE_NAMES.lines() {
            assert_ne!(issue_type_id(name), 0, "{name}");
        }
        assert_eq!(KB_ISSUE_TYPES.len(), KB_ISSUE_NAMES.lines().count());
        assert_eq!(issue_type_id("SQL injection"), 0x0010_0200);
        assert_eq!(issue_type_id("External service interaction (DNS)"), 3_146_240);
        assert_eq!(issue_type_id("Active probe: TRACE method enabled (cross-site tracing)"), 0);
        use crate::burp_checks::CorsKind;
        for k in [CorsKind::Generic, CorsKind::Arbitrary, CorsKind::Subdomains, CorsKind::Unencrypted] {
            assert_ne!(issue_type_id(k.kb_name()), 0, "{}", k.kb_name());
        }
    }

    #[test]
    fn kind_applicability() {
        let multipart_file = IpKind::Multipart { index: 0, filename: Some("a.txt".into()) };
        let multipart_plain = IpKind::Multipart { index: 0, filename: None };
        assert!(PhpCodeInjection.applies_to(&multipart_file));
        assert!(!PhpCodeInjection.applies_to(&multipart_plain));
        assert!(!PhpCodeInjection.applies_to(&IpKind::Query));
        assert!(!XmlInjectionError.applies_to(&IpKind::Header));
        assert!(XmlInjectionError.applies_to(&IpKind::Cookie));
    }

    #[test]
    fn recorder_picks_probe_and_control() {
        let r = Recorder::default();
        r.note("a", b"GET /a", Some(&b"HTTP/1.1 200 OK\r\n\r\nA"[..]));
        r.note("b", b"GET /b", Some(&b"HTTP/1.1 200 OK\r\n\r\nB"[..]));
        r.note("a", b"GET /a2", None);
        r.note("c", b"GET /c", Some(&b"HTTP/1.1 404 Not Found\r\n\r\n"[..]));
        assert_eq!(&*r.last("a").unwrap().request, b"GET /a2");
        assert_eq!(&*r.next_after("a").unwrap().request, b"GET /c");
        assert!(r.next_after("c").is_none());
        assert!(r.last("zz").is_none());
        assert_eq!(r.from_last("b").len(), 3);
    }
}
