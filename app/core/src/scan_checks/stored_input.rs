use crate::diagnostics::Field;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::*;

// ---------------------------------------------------------------- stored input (D-10)

/// Check id of the stored-input probe and its issue (burp.Zwp0 stage A2,
/// burp.Zpwn), for the scan configuration.
pub(crate) const STORED_INPUT_ID: &str = "active.input-returned-stored";
pub(crate) const STORED_INPUT_ISSUE: &str = "Input returned in response (stored)";
/// Redirects followed by the stored-input probe and the stored stage.
pub const STORED_MAX_REDIRECTS: usize = 5;

/// burp.Zwp0 stage A2 / burp.Zuvm.ZO: every point gets its token in place
/// of the value (STORED_DATA_REPLACE through burp.Zx2y, redirects
/// followed); the responses go through [`ScanCtx::send`] like all others.
/// Runs before the point checks, as stage A2 precedes Burp's audit stage.
pub(crate) fn run_stored_seeding(cx: &ScanCtx, points: &[InsertionPoint]) {
    if !cx.stored_report || !cx.runs(STORED_INPUT_ISSUE) {
        return;
    }
    for ip in points {
        if cx.stopped() {
            break;
        }
        let token = cx.shared.stored.token(cx.item, ip);
        let req = inject_payload(&cx.req, ip, &token);
        let chain = cx.send_following(&req);
        if let Some((r, resp)) = chain.first() {
            cx.shared
                .stored
                .note_injection(&token, r.as_bytes(), resp.as_deref());
        }
        cx.progress();
    }
}

/// burp.Zwfa (INPUT_RETRIEVAL_STORED) with burp.Zmkj's evidence: the
/// injection exchange, then the retrieval exchange; information, certain.
pub(crate) fn stored_input_issue(
    pair: &crate::stored::Pair,
    retrieval_req: &[u8],
    retrieval_resp: &[u8],
) -> ScanIssue {
    let mut i = mk(
        "info",
        STORED_INPUT_ISSUE,
        &pair.item.entry,
        format!(
            "The {} submitted to the URL {} is copied into the response for the URL {}.<br><br>Burp has captured the first observed location where this stored input is returned. There might be other locations within the application where the same input is returned. To identify all such locations, perform a full crawl of the application and then do a global search for the highlighted value.",
            pair.point.describe_bold(),
            util::html_encode(&pair.item.url()),
            util::html_encode(&pair.retrieval.url())
        ),
    );
    i.confidence = "Certain".into();
    let injection = ScanEvidence::new(&pair.injection.0, pair.injection.1.as_deref());
    i.with_evidence(vec![
        injection,
        ScanEvidence::new(retrieval_req, Some(retrieval_resp)),
    ])
}

/// A check of stage A4 (burp.Zwp6): it runs once per recorded pair.
pub(crate) trait StoredCheck: Sync {
    fn id(&self) -> &'static str;
    fn issue(&self) -> &'static str;
    /// The registration record every check kind exposes (AR-10 / F14).
    fn meta(&self) -> CheckMeta {
        CheckMeta::identified(self.id(), self.issue())
    }
    fn applies_to(&self, ip: &InsertionPoint) -> bool;
    fn server_side(&self) -> bool;
    fn run(&self, cx: &PairCtx);
}

/// Open redirection (stored), burp.Zuag in the stored stage: burp.Zcug
/// registers the same check class for OPEN_REDIRECTION_STORED, and its
/// factory burp.Zezc makes the stored variant Medium, Certain. Each payload
/// of the reflected check goes to the pair's injection request; the
/// redirect test reads the direct response to the retrieval request
/// replayed after it (not the page a same-origin redirect leads to). As
/// for the other stored checks, only a GET or HEAD retrieval is replayed.
pub(crate) struct OpenRedirectionStored;

impl StoredCheck for OpenRedirectionStored {
    fn id(&self) -> &'static str {
        "active.open-redirection-stored"
    }
    fn issue(&self) -> &'static str {
        "Open redirection (stored)"
    }
    /// As the reflected check (burp.Zuag has no applicability test).
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        OpenRedirect.applies_to(ip)
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &PairCtx) {
        if cx.stopped() || !cx.retrieval_is_safe() {
            return;
        }
        let pair = &cx.pair;
        let ip = &pair.point;
        let log: std::cell::RefCell<Vec<ScanEvidence>> = std::cell::RefCell::new(Vec::new());
        let record = |exchange: Option<(String, Option<Vec<u8>>)>| -> Option<Vec<u8>> {
            let (req, resp) = exchange?;
            log.borrow_mut()
                .push(cx.record_exchange(req.as_bytes(), resp.as_deref())?);
            resp
        };
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let injected = inject_payload(&pair.item.req, ip, payload);
            record(cx.send_following(&pair.item, &injected).into_iter().last())?;
            if cx.stopped() {
                return None;
            }
            let chain = cx.send_following(&pair.retrieval, &pair.retrieval.req);
            record(chain.into_iter().next())
        };
        let speed = ScanSpeed::from_u8(cx.shared.scan_speed.load(Ordering::SeqCst));
        if let Some(hit) = run_open_redirect_check(&ip.value, speed, send) {
            let log = log.borrow();
            let ev: Vec<ScanEvidence> = log.iter().rev().take(2).rev().cloned().collect();
            cx.report(vec![
                mk_point(
                    self.issue(),
                    "medium",
                    "Certain",
                    &pair.item.entry,
                    ip,
                    format!(
                        "Payload {:?}, submitted in the {} in a previous request, was stored and made the response to the later request {:?} ({}) redirect to {:?}.",
                        hit.payload,
                        ip.describe_short(false),
                        pair.retrieval.req.lines().next().unwrap_or(""),
                        pair.retrieval.url(),
                        hit.target
                    ),
                )
                .with_evidence(ev),
            ]);
        }
        cx.progress();
    }
}

/// SQL injection (second order), burp.Zg_c in the stored stage: burp.Zcug
/// registers the SQL check for SQL_INJECTION_2ND_ORDER and burp.Zppj picks
/// the type by context (Zcrn.ZL). This is the error-based half
/// (burp.Zppj.ZE): the quote series goes to the pair's injection request
/// and the error test reads the response to the retrieval request replayed
/// after each, against the retrieval response as it was before. Severity
/// and confidence as in the reflected check. The boolean, time-based and
/// Collaborator variants are not ported for stored input. Only a GET or
/// HEAD retrieval is replayed.
pub(crate) struct SqlInjectionSecondOrder;

impl StoredCheck for SqlInjectionSecondOrder {
    fn id(&self) -> &'static str {
        "active.sql-injection-second-order"
    }
    fn issue(&self) -> &'static str {
        "SQL injection (second order)"
    }
    /// As the reflected check (burp.Zg_c / Zppj have no point-type rule).
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        SqlErrorInjection.applies_to(ip)
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &PairCtx) {
        if cx.stopped() || !cx.retrieval_is_safe() {
            return;
        }
        let pair = &cx.pair;
        let ip = &pair.point;
        let log: std::cell::RefCell<Vec<ScanEvidence>> = std::cell::RefCell::new(Vec::new());
        let retrieve = |keep: bool| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let chain = cx.send_following(&pair.retrieval, &pair.retrieval.req);
            let (req, resp) = chain.into_iter().last()?;
            if keep {
                log.borrow_mut()
                    .push(cx.record_exchange(req.as_bytes(), resp.as_deref())?);
            }
            resp
        };
        let Some(baseline) = retrieve(false) else {
            return;
        };
        let baseline = String::from_utf8_lossy(&baseline).into_owned();
        let send = |payload: &str| -> Option<String> {
            if cx.stopped() {
                return None;
            }
            let injected = inject_payload(&pair.item.req, ip, payload);
            let (req, resp) = cx
                .send_following(&pair.item, &injected)
                .into_iter()
                .last()?;
            log.borrow_mut()
                .push(cx.record_exchange(req.as_bytes(), resp.as_deref())?);
            resp?;
            Some(String::from_utf8_lossy(&retrieve(true)?).into_owned())
        };
        let speed = ScanSpeed::from_u8(cx.shared.scan_speed.load(Ordering::SeqCst));
        if let Some(hit) = run_sql_error_check(&ip.value, &baseline, speed, send) {
            let general = hit.database == "General";
            let text = format!(
                "The {} appears to be vulnerable to second-order SQL injection attacks. A single quote was submitted in the {} in a previous request, and a {} error message was returned in the response to the later request {:?} ({}).{} You should review the contents of the error message, and the application's handling of other input, to confirm whether a vulnerability is present.",
                ip.describe_short(true),
                ip.describe_short(false),
                if general { "general" } else { "database" },
                pair.retrieval.req.lines().next().unwrap_or(""),
                pair.retrieval.url(),
                if hit.confirmed {
                    " Two single quotes were then submitted and the error message disappeared."
                } else {
                    ""
                }
            );
            let confidence = if general {
                "Tentative"
            } else if hit.confirmed {
                "Certain"
            } else {
                "Firm"
            };
            // The first quote's injection and retrieval, the two exchanges
            // the hit rests on.
            let ev: Vec<ScanEvidence> = log.borrow().iter().take(2).cloned().collect();
            cx.report(vec![
                mk_point(self.issue(), "high", confidence, &pair.item.entry, ip, text)
                    .with_evidence(ev),
            ]);
        }
        cx.progress();
    }
}

/// Suspicious input transformation (stored), burp.Zeo6 in the stored stage
/// (burp.Zcug registers it for SUSPICIOUS_INPUT_TRANSFORMATION_STORED) with
/// burp.Zc6w's issue: each probe of [`run_input_transformation_check`],
/// the plain reflection gate included, goes to the pair's injection
/// request, and the response to the retrieval request replayed after it is
/// searched. Information, firm; the injection and retrieval exchanges as
/// evidence. Only a GET or HEAD retrieval is replayed.
pub(crate) struct SuspiciousInputTransformationStored;

impl StoredCheck for SuspiciousInputTransformationStored {
    fn id(&self) -> &'static str {
        "active.suspicious-input-transformation-stored"
    }
    fn issue(&self) -> &'static str {
        "Suspicious input transformation (stored)"
    }
    /// As the reflected check (burp.Zeo6.Zh).
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        SuspiciousInputTransformation.applies_to(ip)
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &PairCtx) {
        if cx.stopped() || !cx.retrieval_is_safe() {
            return;
        }
        let pair = &cx.pair;
        let ip = &pair.point;
        type Logged = (String, ScanEvidence, ScanEvidence);
        let log: std::cell::RefCell<Vec<Logged>> = std::cell::RefCell::new(Vec::new());
        let send = |payload: &str, append: bool| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let injected = transformation_request(&pair.item.req, ip, payload, append)?;
            let (req, resp) = cx
                .send_following(&pair.item, &injected)
                .into_iter()
                .last()?;
            let injection = cx.record_exchange(req.as_bytes(), resp.as_deref())?;
            if cx.stopped() {
                return None;
            }
            let (req, resp) = cx
                .send_following(&pair.retrieval, &pair.retrieval.req)
                .into_iter()
                .next()?;
            let retrieval = cx.record_exchange(req.as_bytes(), resp.as_deref())?;
            log.borrow_mut()
                .push((payload.to_string(), injection, retrieval));
            resp
        };
        let hits = run_input_transformation_check(
            transformation_appends(ip),
            webprobe_support::util::rnd_id,
            send,
        );
        let log = log.into_inner();
        let (injection_url, retrieval_url) = (pair.item.url(), pair.retrieval.url());
        let issues: Vec<ScanIssue> = hits
            .into_iter()
            .map(|h| {
                let mut i = mk(
                    "info",
                    self.issue(),
                    &pair.item.entry,
                    transformation_detail(
                        h.variant,
                        &ip.describe_bold(),
                        &ip.describe_short(false),
                        Some((&injection_url, &retrieval_url)),
                        &h.payload,
                        &h.reflection,
                    ),
                );
                i.confidence = "Firm".into();
                let ev = log.iter().rev().find(|(p, ..)| *p == h.payload);
                i.with_evidence(
                    ev.map(|(_, inj, ret)| vec![inj.clone(), ret.clone()])
                        .unwrap_or_default(),
                )
            })
            .collect();
        cx.report(issues);
        cx.progress();
    }
}

/// Stage A4 checks, in run order.
pub(crate) static STORED_CHECKS: &[&dyn StoredCheck] = &[
    &StoredXss,
    &LinkManipulationStored,
    &CssInjectionStored,
    &HppStored,
    &FormActionHijackingStored,
    &OpenRedirectionStored,
    &SqlInjectionSecondOrder,
    &SuspiciousInputTransformationStored,
];

/// One pair being audited in stage A4.
pub(crate) struct PairCtx {
    pub shared: Arc<Shared>,
    pub pair: crate::stored::Pair,
    g11_hit: std::cell::Cell<bool>,
    #[cfg(test)]
    incomplete: std::cell::Cell<bool>,
    #[cfg(test)]
    partial: std::cell::Cell<bool>,
}

impl PairCtx {
    pub(crate) fn new(shared: Arc<Shared>, pair: crate::stored::Pair) -> Self {
        Self {
            shared,
            pair,
            g11_hit: std::cell::Cell::new(false),
            #[cfg(test)]
            incomplete: std::cell::Cell::new(false),
            #[cfg(test)]
            partial: std::cell::Cell::new(false),
        }
    }

    pub(crate) fn g11_allowed(&self) -> bool {
        !self.g11_hit.get() && self.retrieval_is_safe()
    }

    /// Whether the retrieval request may be replayed after each payload:
    /// only a GET or a HEAD is.
    pub(crate) fn retrieval_is_safe(&self) -> bool {
        let method = self
            .pair
            .retrieval
            .req
            .split_whitespace()
            .next()
            .unwrap_or("");
        method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
    }

    pub(crate) fn note_g11_hit(&self) {
        self.g11_hit.set(true);
    }

    pub(crate) fn stopped(&self) -> bool {
        #[cfg(test)]
        if crate::scan_lifecycle::captured().is_some_and(|c| c.validate(&self.shared).is_err()) {
            return true;
        }
        self.shared.scan.stop.load(Ordering::SeqCst)
    }

    /// One request to `item`'s service and its same-origin redirects; each
    /// request counts toward progress. Stage A4 does not look for new
    /// stored input (burp.Zpqv senders are not detectors).
    pub(crate) fn send_following(
        &self,
        item: &crate::stored::Item,
        raw: &str,
    ) -> Vec<(String, Option<Vec<u8>>)> {
        let mut out = Vec::new();
        let mut req = raw.to_string();
        let host_hdr = util::get_header(&util::parse_http(item.req.as_bytes()).headers, "Host")
            .unwrap_or_default();
        for _ in 0..=STORED_MAX_REDIRECTS {
            if self.stopped() {
                break;
            }
            #[cfg(test)]
            let resp = match crate::scan_lifecycle::captured() {
                Some(crate::scan_lifecycle::ExecutionContext::Budgeted(p)) => {
                    use crate::net::scanner_io::{ExchangeStatus, send_budgeted};
                    let outcome = send_budgeted(
                        &self.shared,
                        &p,
                        item.https,
                        &item.host,
                        item.port,
                        req.as_bytes(),
                    );
                    if outcome.status == ExchangeStatus::Complete {
                        Some(outcome.response)
                    } else {
                        self.incomplete.set(true);
                        // Only a strict valid final identity response's payload
                        // prefix may reach positive-only stored detectors. No
                        // redirect or completed-negative claim follows partial.
                        let raw = outcome.response;
                        let method = req.split_whitespace().next().unwrap_or("");
                        let headers =
                            util::find_head_end(&raw).map(|end| util::parse_http(&raw[..end]));
                        let qualified = headers.is_some_and(|h| {
                            !h.headers
                                .iter()
                                .any(|(name, _)| name.eq_ignore_ascii_case("Transfer-Encoding"))
                        }) && host_response::assess(&raw, method)
                            .is_some_and(|a| a.status >= 200 && !a.body.is_empty())
                            && !raw.starts_with(b"HTTP/1.1 1")
                            && !raw.starts_with(b"HTTP/1.0 1");
                        if qualified {
                            self.partial.set(true);
                            Some(raw)
                        } else {
                            None
                        }
                    }
                }
                _ => send_one(
                    &self.shared,
                    item.https,
                    &item.host,
                    item.port,
                    req.as_bytes(),
                ),
            };
            #[cfg(not(test))]
            let resp = send_one(
                &self.shared,
                item.https,
                &item.host,
                item.port,
                req.as_bytes(),
            );
            bump_progress(&self.shared);
            let next = resp
                .as_deref()
                .and_then(active_checks::redirect_location)
                .and_then(|l| {
                    same_origin_path(
                        &l,
                        item.https,
                        &host_hdr,
                        &util::parse_http(req.as_bytes()).path,
                    )
                })
                .map(|p| get_request_like(&item.req, &p));
            out.push((req, resp));
            #[cfg(test)]
            if self.incomplete.get() {
                break;
            }
            match next {
                Some(n) => req = n,
                None => break,
            }
        }
        out
    }

    /// Temporary evidence copy admission precedes the bounded Arc copies.
    /// Retained proven issue accounting is separate, at report time.
    pub(crate) fn record_exchange(
        &self,
        request: &[u8],
        response: Option<&[u8]>,
    ) -> Option<ScanEvidence> {
        #[cfg(test)]
        if let Some(crate::scan_lifecycle::ExecutionContext::Budgeted(p)) =
            crate::scan_lifecycle::captured()
        {
            let cap = webprobe_support::issues::EVIDENCE_MAX_BYTES;
            let bytes = std::mem::size_of::<ScanEvidence>()
                .checked_add(request.len().min(cap))?
                .checked_add(response.map_or(0, |r| r.len().min(cap)))?;
            if p.ledger().retain_input(bytes as u64).is_err() {
                self.incomplete.set(true);
                return None;
            }
        }
        Some(ScanEvidence::new(request, response))
    }

    pub(crate) fn report(&self, mut issues: Vec<ScanIssue>) {
        if !self.shared.extra_checks.load(Ordering::SeqCst) {
            issues.retain(|i| is_burp_issue(&i.name));
        }
        {
            let cfg_slot = crate::scan_config::shared_config(&self.shared);
            let config = cfg_slot.lock().unwrap();
            issues.retain(|i| config.issue_allowed(&i.name, true));
        }
        #[cfg(test)]
        if self.partial.get() {
            for issue in &mut issues {
                issue.detail.push_str("<p>Incomplete exchange: this finding uses only the received prefix of a strictly validated final identity response. The full response was not received or assessed; no complete-negative result is implied.</p>");
                issue.confidence = "Tentative".into();
            }
        }
        #[cfg(test)]
        if let Some(crate::scan_lifecycle::ExecutionContext::Budgeted(p)) =
            crate::scan_lifecycle::captured()
        {
            issues.retain(|issue| {
                let bytes = [
                    issue.sev.len(),
                    issue.name.len(),
                    issue.host.len(),
                    issue.path.len(),
                    issue.detail.len(),
                    issue.confidence.len(),
                    issue.ident.len(),
                ]
                .into_iter()
                .try_fold(std::mem::size_of::<ScanIssue>(), usize::checked_add)
                .and_then(|n| {
                    issue.evidence.iter().try_fold(n, |n, e| {
                        n.checked_add(std::mem::size_of::<ScanEvidence>())?
                            .checked_add(e.request.len())?
                            .checked_add(e.response.as_ref().map_or(0, |r| r.len()))
                    })
                });
                match bytes {
                    Some(n) => p.ledger().retain_proven(n as u64).is_ok(),
                    None => {
                        p.mark_incomplete();
                        false
                    }
                }
            });
        }
        add_issues(&self.shared, issues);
    }

    pub(crate) fn progress(&self) {
        bump_progress(&self.shared);
    }
}

/// Stage A4 (burp.Zwp6 / Zh7d): every stored check on every recorded pair,
/// in the order the pairs were found. Stops at the next pair (and inside a
/// check, at the next send) once the scan is stopped.
pub(crate) fn run_stored_stage(shared: &Arc<Shared>) {
    let pairs = shared.stored.pairs();
    if pairs.is_empty() {
        return;
    }
    let config = crate::scan_config::shared_config(shared)
        .lock()
        .unwrap()
        .clone();
    shared.event(
        crate::diagnostics::Level::Info,
        "scan.stored.started",
        "Scanner: stored input stage",
        &[Field::Count("pairs", pairs.len() as u64)],
    );
    for pair in pairs {
        if shared.scan.stop.load(Ordering::SeqCst) {
            break;
        }
        let cx = PairCtx::new(shared.clone(), pair.clone());
        for check in STORED_CHECKS {
            let runs = (is_burp_issue(check.issue()) || shared.extra_checks.load(Ordering::SeqCst))
                && config.issue_allowed(check.issue(), true);
            if runs
                && check.applies_to(&pair.point)
                && config.check_enabled(check.id())
                && !(check.server_side() && pair.point.skips_server_side())
            {
                check.run(&cx);
            }
        }
    }
}

/// Experimental real A4 registry path. Explicit limits/permit only, no legacy
/// fallback. Network accounting/deadline integration remains a separate gate.
#[cfg(test)]
#[expect(
    dead_code,
    reason = "experimental A4 registry path, not wired to a production caller yet"
)]
pub(crate) fn run_stored_stage_budgeted(
    shared: &Arc<Shared>,
    permit: &crate::scan_lifecycle::BudgetedExecution,
    max_pairs: usize,
    max_pair_bytes: usize,
) -> crate::scan_lifecycle::Finish {
    use crate::scan_budget::Resource;
    use crate::scan_lifecycle::{ExecutionContext, Finish, captured};
    if max_pairs == 0
        || max_pairs > 65536
        || max_pair_bytes == 0
        || max_pair_bytes > 64 * 1024 * 1024
        || permit.validate_shared(shared).is_err()
    {
        return Finish::Incomplete;
    }
    let Some(ExecutionContext::Budgeted(inherited)) = captured() else {
        return Finish::Incomplete;
    };
    if !std::ptr::eq(inherited.ledger(), permit.ledger())
        || !Arc::ptr_eq(inherited.owner(), permit.owner())
    {
        return Finish::Incomplete;
    }
    // Only the fixed registry selection crosses the configuration lock.
    // Do not clone arbitrary project sets/strings into the bounded stage.
    let enabled: [bool; 5] = {
        let config_slot = crate::scan_config::shared_config(shared);
        let config = config_slot.lock().unwrap();
        std::array::from_fn(|i| {
            config.issue_allowed(STORED_CHECKS[i].issue(), true)
                && config.check_enabled(STORED_CHECKS[i].id())
        })
    };
    let mut incomplete = false;
    for index in 0..max_pairs {
        if permit.validate_shared(shared).is_err() || permit.ledger().reserve(&[]).is_err() {
            return Finish::Incomplete;
        }
        if !shared.stored.has_pair(index) {
            return if incomplete {
                Finish::Incomplete
            } else {
                Finish::Complete
            };
        }
        if permit.ledger().reserve(&[(Resource::Record, 1)]).is_err() {
            return Finish::Incomplete;
        }
        let pair = shared.stored.pair_bounded(index, max_pair_bytes, |bytes| {
            permit
                .ledger()
                .reserve(&[(Resource::Input, bytes as u64)])
                .is_ok()
        });
        let pair = match pair {
            Ok(Some(p)) => p,
            Ok(None) => {
                return if incomplete {
                    Finish::Incomplete
                } else {
                    Finish::Complete
                };
            }
            Err(()) => {
                incomplete = true;
                continue;
            }
        };
        let cx = PairCtx::new(shared.clone(), pair);
        for (check, enabled) in STORED_CHECKS.iter().zip(enabled) {
            if permit.validate_shared(shared).is_err() || permit.ledger().reserve(&[]).is_err() {
                return Finish::Incomplete;
            }
            if (is_burp_issue(check.issue()) || shared.extra_checks.load(Ordering::SeqCst))
                && enabled
                && check.applies_to(&cx.pair.point)
                && !(check.server_side() && cx.pair.point.skips_server_side())
            {
                check.run(&cx);
                if cx.incomplete.get() {
                    incomplete = true;
                }
            }
        }
    }
    if incomplete || shared.stored.has_pair(max_pairs) {
        Finish::Incomplete
    } else {
        Finish::Complete
    }
}
