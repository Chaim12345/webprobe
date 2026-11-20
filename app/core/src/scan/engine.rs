// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;
use crate::diagnostics::{Field, Level};

/// AuditDefaults.json misc_insertion_point_options.max_insertion_points_per_base_request
pub const MAX_INSERTION_POINTS: usize = 30;

/// CrawlDefaults.json crawl_limits.maximum_unique_locations
pub const CRAWL_MAX_UNIQUE_LOCATIONS: usize = 1500;

/// Active scan of a stored request. Builds the insertion points under the
/// scan configuration (Burp's builder, vetoes and cap, see [`audit_points`]),
/// then on a
/// worker thread fetches the baseline and runs the check registries of
/// [`checks`]: every insertion-point check on every point, in registry
/// order, then the per-request and per-host checks once.
///
/// `oob` carries one Collaborator payload per slot of [`oob_slots`]
/// (slot, token, payload): the payload replaces the value and the
/// interaction itself is detected asynchronously by
/// [`match_oob_interactions`] against `Shared::oob_pending`. Burp family:
/// SCANNER_ACTIVE_CHECKS_EXTERNAL_INTERACTION.
///
/// `smtp` carries, per parameter, the two Collaborator ids for Burp's SMTP
/// header injection check (simple and `>`-enclosed payloads, burp.Zrok).
/// It is empty unless a public Collaborator (interactsh) is active, as Burp
/// runs the check only with Collaborator enabled (burp.Zgcg.Zw: Za.Ze()).
pub fn start_active_scan(
    shared: Arc<Shared>,
    entry: HistEntry,
    oob: &[(String, String, String)],
    smtp: &[SmtpOob],
) {
    if shared.scan.is_busy() {
        shared.event(
            Level::Warn,
            "scan.busy",
            "Scanner: a scan is already running",
            &[],
        );
        return;
    }
    let req = String::from_utf8_lossy(&entry.req_raw).into_owned();
    let parts = util::parse_http(&entry.req_raw);
    let host_header = util::get_header(&parts.headers, "Host").unwrap_or_default();
    if host_header.is_empty() {
        shared.event(
            Level::Warn,
            "scan.missing_host",
            "Scanner: selected request has no Host header",
            &[],
        );
        return;
    }
    let (host, port) = net::split_h_p(&host_header, entry.port);
    let config = crate::scan_config::shared_config(&shared)
        .lock()
        .unwrap()
        .clone();
    let points: Vec<InsertionPoint> = audit_points(&req, &config);
    if points.is_empty() {
        // Burp still runs its per-request and per-host checks (CORS,
        // path-relative style sheets, OpenAPI discovery) on such requests.
        shared.event(
            Level::Info,
            "scan.no_points",
            "Scanner: running per-request and per-host checks only",
            &[],
        );
    }
    // Claim the scanner before touching its progress: a refused second
    // scan must not reset the running one's counters.
    let Some(guard) = crate::scan_run::try_claim(&shared.scan) else {
        shared.event(
            Level::Warn,
            "scan.busy",
            "Scanner: a scan is already running",
            &[],
        );
        return;
    };
    // The stored-input store lives for one scan run: this scan, or the
    // batch (task, crawl) it belongs to.
    if !shared.stored.in_batch() {
        shared.stored.clear();
    }
    let item = shared.stored.add_item(crate::stored::Item {
        entry: entry.clone(),
        req: req.clone(),
        host: host.clone(),
        port,
        https: entry.https,
    });
    shared.scan.total.store(
        planned_progress(&entry, points.len(), oob.len()),
        Ordering::SeqCst,
    );
    shared.scan.done.store(0, Ordering::SeqCst);
    shared.scan.stop.store(false, Ordering::SeqCst);
    shared.scan.direct.store(
        shared.scan.running_task.load(Ordering::SeqCst) == 0,
        Ordering::SeqCst,
    );
    shared.event(
        Level::Info,
        "scan.started",
        "Scanner: active scan started",
        &[Field::Count("insertion_points", points.len() as u64)],
    );

    let settings = checks::Settings {
        speed: ScanSpeed::from_u8(shared.scan_speed.load(Ordering::SeqCst)),
        accuracy: crate::variations::Accuracy::from_u8(shared.scan_accuracy.load(Ordering::SeqCst)),
    };
    let (oob, smtp) = (oob.to_vec(), smtp.to_vec());
    // Async Phase 1 (issue #42): the scan body is one engine task on the
    // runtime; the blocking checks (extension hooks included) run in
    // `spawn_blocking`. Abort cannot interrupt a started blocking body;
    // its cooperative stop checks end it after in-flight calls return.
    let flag = shared.clone();
    crate::rt::engine().spawn_engine(
        "scan",
        move || flag.scan.stop.load(Ordering::SeqCst),
        move || {
            let _tool = crate::net::tool_scope("Scanner");
            // The guard releases the scanner however this thread ends: a
            // panicking check used to leave it claimed, so every later scan was
            // refused and the task runner waited forever.
            let _guard = guard;
            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let cx = checks::ScanCtx::start(
                    shared.clone(),
                    entry,
                    req,
                    parts,
                    host,
                    port,
                    settings,
                    oob,
                    smtp,
                    item,
                );
                checks::run_stored_seeding(&cx, &points);
                checks::run_point_checks(&cx, &points);
                checks::run_request_checks(&cx);
                checks::run_extension_checks(&cx, &points);
                // A scan on its own runs stage A4 now; a batch runs it once its
                // last item is done (`run_stored_stage_claimed`).
                if !shared.stored.in_batch() {
                    checks::run_stored_stage(&shared);
                }
            }));
            if run.is_err() {
                shared.event(
                    Level::Error,
                    "scan.failed",
                    "Scanner: the scan stopped on an internal error",
                    &[],
                );
                crate::notice::toast(
                    crate::notice::Level::Error,
                    "Active scan stopped on an internal error. See the diagnostic event code.",
                );
                return;
            }
            drop(_guard);
            let shared = &shared;
            shared.event(
                Level::Info,
                "scan.finished",
                "Scanner: active scan finished",
                &[],
            );
            let found = shared.issues.lock().map(|i| i.len()).unwrap_or(0);
            crate::notice::toast(
                crate::notice::Level::Success,
                format!("Active scan finished — {found} issue(s) in the report"),
            );
        },
    );
}

/// The progress bar's total for a scan: fifteen probes per insertion point,
/// one baseline, one oob probe per payload, the scan-level probes, the
/// stored-echo pass, up to eight CORS origins and the per-host OpenAPI
/// paths, plus up to three CSRF variants (remove / empty / static token)
/// when the request qualifies. An estimate; checks advance it as they go.
pub fn planned_progress(entry: &HistEntry, points: usize, oob: usize) -> usize {
    let total = points * 16 + 1 + oob + 5 + 8 + crate::burp_checks::openapi_paths(false).len();
    let csrf_parts = util::parse_http(&entry.req_raw);
    let csrf_ct = util::get_header(&csrf_parts.headers, "Content-Type").unwrap_or_default();
    let csrf_body =
        String::from_utf8_lossy(&entry.req_raw[csrf_parts.head_len.min(entry.req_raw.len())..])
            .into_owned();
    let csrf_total = if csrf_applicable(&csrf_parts.method, &csrf_ct, &csrf_parts.headers)
        && csrf_ct
            .to_ascii_lowercase()
            .contains("x-www-form-urlencoded")
        && !csrf_body.trim().is_empty()
        && !strip_csrf_params(&csrf_body).1.is_empty()
    {
        3
    } else {
        0
    };
    total + csrf_total
}

/// The raw header lines of a response (status line excluded), split on CR,
/// LF or CRLF, so a bare CR or LF injected by the probe is visible too.
/// Burp's "Crawl and audit": crawl from each start URL, then audit every
/// auditable item found (passive checks, then the active scan), one at a
/// time. Blocks until done; call from a worker thread.
/// Actively audit these items one after another on a background thread
/// (Burp's "Actively scan this host / branch"). Stops when the scan is
/// stopped; draws Collaborator payloads from the pool like Crawl & Audit.
pub fn audit_entries(shared: Arc<Shared>, entries: Vec<HistEntry>) {
    // Queued as a Dashboard task: it runs after any scan already queued and
    // can be paused, resumed and cancelled there.
    let name = match entries.as_slice() {
        [one] => format!("Active scan of {}{}", net::history_host(one), one.path),
        many => format!("Active scan of {} items", many.len()),
    };
    crate::tasks::enqueue(&shared, name, crate::tasks::TaskKind::Audit(entries));
}

/// One pre-minted Collaborator payload per out-of-band slot of this request,
/// taken from the pool (a front end with a Collaborator stocks it; a headless
/// run has none). When the pool runs short the remaining slots get none and
/// the scan log says so: those out-of-band checks are skipped, not silently.
pub fn pooled_oob(shared: &Shared, req_raw: &[u8]) -> Vec<(String, String, String)> {
    let slots = oob_slots(shared, req_raw);
    if slots.is_empty() {
        return Vec::new();
    }
    // Wake the front end now so it stocks the pool on its next frame.
    shared.wake();
    let ids = shared
        .oob
        .take(slots.len(), std::time::Duration::from_millis(1500));
    if ids.len() < slots.len() && !ids.is_empty() {
        shared.event(
            Level::Warn,
            "scan.oob.shortage",
            "Scanner: Collaborator pool is short; probes skipped",
            &[
                Field::Count("available", ids.len() as u64),
                Field::Count("wanted", slots.len() as u64),
                Field::Count("skipped", (slots.len() - ids.len()) as u64),
            ],
        );
    }
    slots
        .into_iter()
        .zip(ids)
        .map(|(slot, (token, dns))| (slot, token, dns))
        .collect()
}

/// Stage A4 for a batch whose items are all audited: wait for the last
/// item's scan, claim the scanner for the stage (stop, pause and progress
/// work as in any scan) and run the stored checks over the batch's pairs.
pub fn run_stored_stage_claimed(shared: &Arc<Shared>) {
    shared.scan.wait_idle(None);
    if shared.stored.pairs().is_empty() {
        return;
    }
    let Some(guard) = crate::scan_run::try_claim(&shared.scan) else {
        return;
    };
    shared.scan.done.store(0, Ordering::SeqCst);
    shared
        .scan
        .total
        .store(shared.stored.pairs().len() * 30, Ordering::SeqCst);
    let _tool = crate::net::tool_scope("Scanner");
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        checks::run_stored_stage(shared)
    }));
    if run.is_err() {
        shared.event(
            Level::Error,
            "scan.stored.failed",
            "Scanner: stored input stage stopped on an internal error",
            &[],
        );
    }
    drop(guard);
}

/// Holds the stored-input store open across a batch's items and runs stage
/// A4 when the batch ends, however it ends. A batch inside another (a crawl
/// run as a task) leaves both to the outer one.
pub struct StoredBatch {
    shared: Arc<Shared>,
    opened: bool,
}

impl StoredBatch {
    pub fn open(shared: &Arc<Shared>) -> StoredBatch {
        StoredBatch {
            shared: shared.clone(),
            opened: shared.stored.open_batch(),
        }
    }
}

impl Drop for StoredBatch {
    fn drop(&mut self) {
        if self.opened {
            run_stored_stage_claimed(&self.shared);
            self.shared.stored.close_batch();
        }
    }
}

pub fn crawl_and_audit(shared: &Arc<Shared>, start_urls: &[String], audit_only: bool) {
    let _stored = StoredBatch::open(shared);
    let _tool = crate::net::tool_scope("Scanner");
    // Ask the UI thread for Collaborator payloads for the whole run, so the
    // out-of-band checks work here as they do for a scan started on one item.
    struct Wanted<'a>(&'a Shared);
    impl Drop for Wanted<'_> {
        fn drop(&mut self) {
            self.0.oob.want(false);
        }
    }
    shared.oob.want(true);
    let _wanted = Wanted(shared);
    // Fresh dedup sets for this run (reset by construction, #38).
    *shared.scan_state.lock().unwrap() = Arc::new(webprobe_support::dedup::ScanDedup::default());
    for url in start_urls {
        let mut items = if audit_only {
            crate::crawl::crawl_single(shared, url)
        } else {
            crate::crawl::crawl(shared, url)
        };
        // Browser-driven crawl (Burp's crawler drives Chromium): picks up
        // client-side routes and the API calls pages make; each observed
        // same-origin request is re-issued as a crawl item.
        let engine = crate::scan_config::shared_config(shared)
            .lock()
            .unwrap()
            .crawl
            .engine
            .clone();
        if !audit_only && !engine.is_empty() && !engine.eq_ignore_ascii_case("chromium") {
            // Another headless engine (headless.rs): render through the
            // proxy, then fetch each page it found as a crawl item.
            let js_crawl = crate::scan::browser_crawl()
                .and_then(|bc| (bc.js_crawl)(&engine, shared, url).map(|r| (bc, r)));
            match js_crawl {
                Some((_, Ok(urls))) => {
                    shared.event(
                        Level::Info,
                        "crawl.engine.finished",
                        "Headless crawl finished",
                        &[Field::Count("pages", urls.len() as u64)],
                    );
                    let mut keys: std::collections::BTreeSet<String> = items
                        .iter()
                        .map(|e| format!("{} {}", e.method, crate::crawl::location_key(&e.path)))
                        .collect();
                    for u in urls {
                        for it in crate::crawl::crawl_single(shared, &u) {
                            if keys.insert(format!(
                                "{} {}",
                                it.method,
                                crate::crawl::location_key(&it.path)
                            )) {
                                items.push(it);
                            }
                        }
                    }
                }
                Some((_, Err(_))) => shared.event(
                    Level::Error,
                    "crawl.engine.failed",
                    "Headless crawl unavailable; static crawl only",
                    &[],
                ),
                None => shared.event(
                    Level::Warn,
                    "crawl.engine.missing",
                    "Headless engine not installed; static crawl only",
                    &[],
                ),
            }
        } else if !audit_only {
            match crate::crawl::browser_crawl(shared, url) {
                Ok(mut seen) => {
                    shared.event(
                        Level::Info,
                        "crawl.browser.finished",
                        "Browser crawl finished",
                        &[Field::Count("requests", seen.len() as u64)],
                    );
                    // Per location, prefer an exchange whose response the
                    // browser itself received (what Burp audits passively): a
                    // replay of a stateful request, such as a socket.io poll
                    // with a stale sid, gets a different answer.
                    seen.sort_by_key(|r| r.resp_head.is_none() || r.resp_body.is_none());
                    let mut keys: std::collections::BTreeSet<String> = items
                        .iter()
                        .map(|e| format!("{} {}", e.method, crate::crawl::location_key(&e.path)))
                        .collect();
                    // Only the start origin is crawled and audited, whatever
                    // the browser was led to request.
                    let start = crate::crawl::origin_of(url).unwrap_or_default();
                    for r in seen
                        .into_iter()
                        .filter(|r| crate::crawl::same_origin(&r.url, &start))
                    {
                        let path = r
                            .url
                            .split_once("://")
                            .and_then(|(_, x)| x.find('/').map(|i| x[i..].to_string()))
                            .unwrap_or_else(|| "/".into());
                        let path = path.split('#').next().unwrap_or("/").to_string();
                        if keys.insert(format!(
                            "{} {}",
                            r.method,
                            crate::crawl::location_key(&path)
                        )) {
                            items.push(crate::crawl::replay_seen(shared, &r));
                        }
                    }
                }
                Err(_) => shared.event(
                    Level::Error,
                    "crawl.browser.failed",
                    "Browser crawl unavailable; static crawl only",
                    &[],
                ),
            }
        }
        shared.event(
            Level::Info,
            "crawl.finished",
            "Crawl finished",
            &[Field::Count("items", items.len() as u64)],
        );
        shared.add_crawl_items(items.iter().cloned());
        let static_refs = crate::crawl::static_reference_corpus(&items);
        for e in items.into_iter().filter(|e| {
            crate::crawl::auditable(e) || crate::crawl::referenced_static(e, &static_refs)
        }) {
            if shared.scan.stop.load(Ordering::SeqCst) {
                return;
            }
            add_passive_issues(shared, passive_check_for(shared, &e));
            let oob = pooled_oob(shared, &e.req_raw);
            start_active_scan(shared.clone(), e, &oob, &[]);
            // start_active_scan claims the scanner before it returns.
            shared.scan.wait_idle(None);
        }
    }
    shared.event(
        Level::Info,
        "scan.crawl.finished",
        "Crawl and audit finished",
        &[],
    );
}
