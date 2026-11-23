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
    let Some((guard, host_scope)) = crate::host_probe_state::admit(&shared) else {
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
                    host_scope,
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
                format!("Active scan finished. The report now holds {found} issue(s) in total"),
            );
        },
    );
}

/// Required-Limits synchronous engine adapter for isolated lifecycle fixtures.
/// No production caller or default policy selects it. Returns the exact
/// finalization obligation to the caller rather than hiding A4 in Drop.
#[cfg(test)]
pub(crate) struct ExperimentalEngine {
    shared: Arc<Shared>,
    coordinator: Arc<crate::scan_lifecycle::Coordinator>,
}
#[cfg(test)]
impl ExperimentalEngine {
    pub fn new(
        shared: Arc<Shared>,
        limits: crate::scan_budget::Limits,
    ) -> Result<Self, crate::scan_lifecycle::AdmissionError> {
        let coordinator = crate::scan_lifecycle::Coordinator::new(shared.clone(), limits)?;
        Ok(Self {
            shared,
            coordinator,
        })
    }
    pub fn open(
        &self,
    ) -> Result<crate::scan_lifecycle::Batch, crate::scan_lifecycle::AdmissionError> {
        self.coordinator.open()
    }
    pub fn audit(
        &self,
        entry: HistEntry,
    ) -> Result<crate::scan_lifecycle::Handoff, crate::scan_lifecycle::AdmissionError> {
        use crate::scan_lifecycle::{AdmissionError, ExecutionContext};
        let shared = &self.shared;
        let parts = util::parse_http(&entry.req_raw);
        let host_header = util::get_header(&parts.headers, "Host")
            .filter(|h| !h.is_empty())
            .ok_or(AdmissionError::InvalidLimits)?;
        let (host, port) = net::split_h_p(&host_header, entry.port);
        let req = String::from_utf8_lossy(&entry.req_raw).into_owned();
        let (a, legacy, item) = self.coordinator.admit(crate::stored::Item {
            entry: entry.clone(),
            req: req.clone(),
            host: host.clone(),
            port,
            https: entry.https,
        })?;
        // Admission succeeds before changing the accepted run's UI flags.
        shared.scan.stop.store(false, Ordering::SeqCst);
        shared.scan.done.store(0, Ordering::SeqCst);
        let context = ExecutionContext::Legacy(legacy.clone());
        let _expected = net::scanner_io::ExpectedScanner.install();
        let installed = context.enter(shared)?;
        let _tool = net::tool_scope("Scanner");
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let config = crate::scan_config::shared_config(shared)
                .lock()
                .unwrap()
                .clone();
            let points = audit_points(&req, &config);
            let settings = checks::Settings {
                speed: ScanSpeed::from_u8(shared.scan_speed.load(Ordering::SeqCst)),
                accuracy: crate::variations::Accuracy::from_u8(
                    shared.scan_accuracy.load(Ordering::SeqCst),
                ),
            };
            let cx = checks::ScanCtx::start(
                shared.clone(),
                entry,
                req,
                parts,
                host,
                port,
                settings,
                Vec::new(),
                Vec::new(),
                item,
                legacy.owner,
            );
            checks::run_stored_seeding(&cx, &points);
            checks::run_point_checks(&cx, &points);
            checks::run_request_checks(&cx);
            checks::run_extension_checks(&cx, &points);
        }));
        drop(installed);
        if run.is_err() {
            drop(a);
            return Err(AdmissionError::Internal);
        }
        a.complete()
    }
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
    host_owner: crate::host_probe_state::BatchOwner,
}

impl StoredBatch {
    pub fn open(shared: &Arc<Shared>) -> StoredBatch {
        Self::open_with(shared, false)
    }
    fn open_with(shared: &Arc<Shared>, fresh_crawl: bool) -> StoredBatch {
        let host_owner = crate::host_probe_state::open_batch(shared, fresh_crawl);
        StoredBatch {
            host_owner,
            shared: shared.clone(),
            opened: shared.stored.open_batch(),
        }
    }
}

// ================= G.11 reflected manipulation contexts (burp.Zb_5 / Zcpt) =================

/// Where in a response a probe reflection landed: the subset of burp.Zcpt's
/// context identification the G.11 families select on (Zbf4.java:25-35
/// preserves the same contexts in the report).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum G11Context {
    /// Inside the value of `attr` on `tag`; `attrs` carries every
    /// attribute of that tag (names lowercased).
    Attr {
        tag: String,
        attr: String,
        attrs: Vec<(String, String)>,
    },
    /// Text inside a <style> element.
    StyleText,
    /// Text inside a <script> element.
    JsText,
    /// In the response head (a header value).
    Head,
    /// Anything else (HTML text, comments, tag names).
    Other,
}

impl G11Context {
    /// The report's context wording (burp.Zbf4).
    pub(crate) fn describe(&self) -> String {
        match self {
            G11Context::Attr { tag, attr, .. } => {
                format!("the {attr} attribute of a <{tag}> element")
            }
            G11Context::StyleText => "a <style> element".to_string(),
            G11Context::JsText => "a JavaScript string".to_string(),
            G11Context::Head => "a response header".to_string(),
            G11Context::Other => "the response body".to_string(),
        }
    }
}

/// HTML elements with no end tag; they are never pushed onto the
/// open-tag stack.
const VOID_TAGS: [&str; 14] = [
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// The context of one body position: the open-tag stack at `pos`, and an
/// attribute match when `pos` is inside a quoted or unquoted value.
fn g11_body_context(body: &str, pos: usize) -> G11Context {
    let b = body.as_bytes();
    let mut open: Vec<String> = Vec::new();
    let mut i = 0;
    while i < pos && i < b.len() {
        // Raw-text elements: everything up to their close tag is text,
        // never markup, so a '<' in script or style text is not a tag.
        if let Some(top) = open.last() {
            if top == "script" || top == "style" {
                let close = format!("</{top}");
                match body[i..].to_ascii_lowercase().find(&close) {
                    // Already at the close tag: parse it normally below.
                    Some(0) => {}
                    // Re-check the loop condition: the jump may pass pos.
                    Some(rel) => {
                        i += rel;
                        continue;
                    }
                    None => break,
                }
            }
        }
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if body[i..].starts_with("<!--") {
            i = body[i + 4..]
                .find("-->")
                .map(|x| x + i + 7)
                .unwrap_or(b.len());
            continue;
        }
        let gt_scan = &body[i..];
        let mut gt = b.len();
        // A tag's '>' can hide inside a quoted attribute value.
        let mut q: Option<u8> = None;
        for (off, ch) in gt_scan.bytes().enumerate().skip(1) {
            match (q, ch) {
                (None, b'"') => q = Some(b'"'),
                (None, b'\'') => q = Some(b'\''),
                (Some(qc), c) if c == qc => q = None,
                (None, b'>') => {
                    gt = i + off;
                    break;
                }
                _ => {}
            }
        }
        if gt == b.len() {
            break;
        }
        let closing = body.get(i + 1..i + 2) == Some("/");
        let name_start = i + 1 + usize::from(closing);
        let name_len = body[name_start..gt]
            .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
            .unwrap_or(gt - name_start);
        let tag = body[name_start..name_start + name_len].to_ascii_lowercase();
        // Walk the attributes in one pass, then match the position: the
        // Attr result must carry the tag's full attribute list whichever
        // order they appear in.
        let mut j = name_start + name_len;
        let mut spans: Vec<(String, usize, usize)> = Vec::new();
        while j < gt {
            while j < gt && (b[j].is_ascii_whitespace() || b[j] == b'/') {
                j += 1;
            }
            let ns = j;
            while j < gt && !b[j].is_ascii_whitespace() && b[j] != b'=' && b[j] != b'/' {
                j += 1;
            }
            let name = body[ns..j].to_ascii_lowercase();
            while j < gt && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < gt && b[j] == b'=' {
                j += 1;
                while j < gt && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                let (vs, ve) = if j < gt && (b[j] == b'"' || b[j] == b'\'') {
                    let qc = b[j];
                    let vs = j + 1;
                    let mut ve = vs;
                    // HTML attribute values have no escape mechanism: the
                    // next matching quote closes the value, backslash or
                    // not.
                    while ve < gt && b[ve] != qc {
                        ve += 1;
                    }
                    j = (ve + 1).min(gt);
                    (vs, ve)
                } else {
                    let vs = j;
                    while j < gt && !b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    (vs, j)
                };
                if !name.is_empty() {
                    spans.push((name, vs, ve));
                }
            } else if !name.is_empty() {
                spans.push((name, 0, 0));
            }
        }
        if let Some((name, _, _)) = spans.iter().find(|(_, vs, ve)| pos >= *vs && pos < *ve) {
            let attrs = spans
                .iter()
                .map(|(k, vs, ve)| (k.clone(), body[*vs..*ve].to_string()))
                .collect();
            return G11Context::Attr {
                tag,
                attr: name.clone(),
                attrs,
            };
        }
        if closing {
            if let Some(k) = open.iter().rposition(|t| *t == tag) {
                open.truncate(k);
            }
        } else if !tag.is_empty()
            && !VOID_TAGS.contains(&tag.as_str())
            && !body[i..gt].trim_end().ends_with('/')
        {
            open.push(tag);
        }
        i = gt + 1;
    }
    if open.iter().any(|t| t == "style") {
        G11Context::StyleText
    } else if open.iter().any(|t| t == "script") {
        G11Context::JsText
    } else {
        G11Context::Other
    }
}

/// Classify at most 32 occurrences of `probe` (burp.Zcpt).
/// Each body classification scans its prefix, so bound target-controlled work.
/// Later reflections may be missed rather than allowing quadratic amplification.
pub(crate) fn g11_contexts(resp: &[u8], probe: &str) -> Vec<G11Context> {
    if probe.is_empty() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(resp);
    // Locate the head/body split in the lossy string, not the raw bytes:
    // invalid UTF-8 before it would otherwise shift every body offset.
    // Both the CRLF and the LF-only form split the head, as
    // util::find_head_end does.
    let head_end = text
        .find("\r\n\r\n")
        .map(|x| x + 4)
        .or_else(|| text.find("\n\n").map(|x| x + 2))
        .unwrap_or(0);
    let mut out = Vec::new();
    let mut start = 0;
    while out.len() < 32 && start + probe.len() <= text.len() {
        let Some(at) = text[start..].find(probe).map(|p| p + start) else {
            break;
        };
        out.push(if at < head_end {
            G11Context::Head
        } else {
            g11_body_context(&text[head_end..], at - head_end)
        });
        start = at + probe.len();
    }
    out
}

fn g11_token(n: usize) -> String {
    use rand::Rng;
    let mut g = rand::thread_rng();
    (0..n)
        .map(|_| (b'a' + g.gen_range(0..26)) as char)
        .collect()
}

/// The CSS injection probe: one plain token (burp.Zw0x; the CSS-specific
/// payload literal is stripped, not established).
pub(crate) fn g11_css_probes() -> Vec<String> {
    vec![g11_token(8)]
}

/// The HPP probe pair (burp.Zpy1): `<random3>&<random3>`; the stripped
/// static suffix and the '?' prefix are not established and omitted.
pub(crate) fn g11_hpp_probes() -> Vec<String> {
    vec![format!("{}&{}", g11_token(3), g11_token(3))]
}

/// The form action probe: a random URL (burp.Zc51).
pub(crate) fn g11_form_action_probes() -> Vec<String> {
    vec![format!("https://{}.example/{}", g11_token(8), g11_token(6))]
}

/// The link manipulation probes (burp.Zpyp.java:13-33, established
/// literals): one random host/path under each of the four scheme prefixes.
pub(crate) fn g11_link_probes() -> Vec<String> {
    let url = format!("{}.example/{}", g11_token(8), g11_token(6));
    ["http://", "https://", "//", "\\/"]
        .iter()
        .map(|p| format!("{p}{url}"))
        .collect()
}

/// The CSS family's reflection-context selector (burp.Zw0x; the decoded
/// applicable map's link/rel/stylesheet entries).
pub(crate) fn g11_css_match(c: &G11Context) -> bool {
    match c {
        G11Context::StyleText => true,
        G11Context::Attr { attr, .. } if attr == "style" => true,
        G11Context::Attr { tag, attr, attrs } if tag == "link" && attr == "href" => {
            // rel is a space-separated token list: an exact token match,
            // not a substring ("preload-stylesheet" is not a stylesheet).
            attrs.iter().any(|(k, v)| {
                k == "rel"
                    && v.to_ascii_lowercase()
                        .split_whitespace()
                        .any(|t| t == "stylesheet")
            })
        }
        _ => false,
    }
}

/// The HPP family's selector (burp.Zpy2's transformed-reflection match):
/// an attribute value, a JavaScript string or a response header.
pub(crate) fn g11_hpp_match(c: &G11Context) -> bool {
    // Attribute hits only count on URL-bearing attributes: a parameter
    // pair in a URL is what client-side navigation reads.
    match c {
        G11Context::Attr { attr, .. } => {
            matches!(attr.as_str(), "href" | "src" | "action" | "formaction")
        }
        G11Context::JsText | G11Context::Head => true,
        _ => false,
    }
}

/// The form action family's selector (burp.Zc51): a <form>'s action or
/// any element's formaction attribute.
pub(crate) fn g11_form_action_match(c: &G11Context) -> bool {
    matches!(c, G11Context::Attr { tag, attr, .. } if (tag == "form" && attr == "action") || attr == "formaction")
}

/// Stored G.11 rounds (burp.Zpqv): each probe goes to the pair's
/// injection item, the retrieval item's own request is replayed after it,
/// and `hit` classifies the retrieval response. Returns the first
/// matching (probe, description).
pub(crate) fn run_g11_stored<S, R, H>(
    probes: &[String],
    mut send: S,
    mut retrieve: R,
    hit: H,
) -> Option<(String, String)>
where
    S: FnMut(&str) -> Option<Vec<u8>>,
    R: FnMut() -> Option<Vec<u8>>,
    H: Fn(&[u8], &str) -> Option<String>,
{
    for p in probes {
        // A failed send or retrieval skips that probe, not the rest: one
        // transient failure must not suppress the other probes' hits.
        if send(p).is_none() {
            continue;
        }
        let Some(resp) = retrieve() else { continue };
        if let Some(what) = hit(&resp, p) {
            return Some((p.clone(), what));
        }
    }
    None
}

/// Stored link manipulation's hit (burp.Ze20 with Zpy2's transformed
/// reflection): the injected URL must come back as a link or redirect
/// target of the retrieval response.
pub(crate) fn g11_link_stored_hit(resp: &[u8], probe: &str) -> Option<String> {
    let target = crate::crawl::link_targets(resp)
        .into_iter()
        .find(|t| t.contains(probe))?;
    Some(format!("the link/redirect target {target:?}"))
}

/// The stored CSS/HPP/form-action hit: the probe's reflection context in
/// the retrieval response, per the family's selector.
pub(crate) fn g11_stored_context_hit(
    resp: &[u8],
    probe: &str,
    matches: impl Fn(&G11Context) -> bool,
) -> Option<String> {
    g11_contexts(resp, probe)
        .into_iter()
        .find(|c| matches(c))
        .map(|c| c.describe())
}

/// CSS injection (reflected), burp.Zb_5's selector -> Zw0x (KB 00501300):
/// a token injected at the point must reflect in a CSS position: <style>
/// text, a style attribute, or the href of a <link rel=stylesheet>. The
/// CSS-specific payload literal (Zi9s initializer) and the full
/// applicable-tag map are stripped from the jar (not established), so the
/// probe is a plain token and detection is purely contextual; REPLACE
/// mode only (Burp also tries APPEND).
/// Returns (payload, context description, response).
pub(crate) fn run_css_reflected<F: FnMut(&str) -> Option<Vec<u8>>>(
    mut send: F,
) -> Option<(String, String, Vec<u8>)> {
    let token = g11_css_probes().remove(0);
    let resp = send(&token)?;
    let cx = g11_contexts(&resp, &token)
        .into_iter()
        .find(g11_css_match)?;
    Some((token, cx.describe(), resp))
}

/// Client-side HTTP parameter pollution (reflected), burp.Zb_5 -> Zi4q
/// (KB 00501400): burp.Zpy1 builds `<random3>&<random3><suffix>`,
/// optionally prefixed by '?'; the static suffix is stripped from the jar
/// (not established), so WebProbe's probe is `<random3>&<random3>` with
/// no suffix and no '?' prefix. Reported when the pair reflects in an
/// HTML attribute value, a JavaScript string or a response header — the
/// contexts client-side code reads query parameters from (Zpy2's
/// transformed-reflection match is verbatim here; transformations are
/// not established). REPLACE mode only.
pub(crate) fn run_hpp_reflected<F: FnMut(&str) -> Option<Vec<u8>>>(
    mut send: F,
) -> Option<(String, String, Vec<u8>)> {
    let probe = g11_hpp_probes().remove(0);
    let resp = send(&probe)?;
    let cx = g11_contexts(&resp, &probe)
        .into_iter()
        .find(g11_hpp_match)?;
    Some((probe, cx.describe(), resp))
}

/// Form action hijacking (reflected), burp.Zb_5 -> Zc51 (KB 00501500):
/// an injected URL must reflect as a form submission target — the action
/// of a <form> or any element's formaction attribute (the Zi9s map's
/// decoded form/action/input entries; the full map is not established).
/// REPLACE mode only.
pub(crate) fn run_form_action_reflected<F: FnMut(&str) -> Option<Vec<u8>>>(
    mut send: F,
) -> Option<(String, String, Vec<u8>)> {
    let probe = g11_form_action_probes().remove(0);
    let resp = send(&probe)?;
    let cx = g11_contexts(&resp, &probe)
        .into_iter()
        .find(g11_form_action_match)?;
    Some((probe, cx.describe(), resp))
}

impl Drop for StoredBatch {
    fn drop(&mut self) {
        // Host scope stays open through the stored stage; only its owner closes it.
        if self.opened {
            run_stored_stage_claimed(&self.shared);
            self.shared.stored.close_batch();
        }
        crate::host_probe_state::close_batch(&self.shared, &self.host_owner);
    }
}

pub fn crawl_and_audit(shared: &Arc<Shared>, start_urls: &[String], audit_only: bool) {
    let _stored = StoredBatch::open_with(shared, true);
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
    // Scope and dedup publication is atomic at batch admission above.
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

#[cfg(test)]
mod g11_tests {
    use super::*;

    fn resp(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn stored_rounds_continue_after_send_and_retrieval_failures() {
        let probes: Vec<String> = ["send-fails", "retrieve-fails", "hit"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let mut retrieved = 0;
        let hit = run_g11_stored(
            &probes,
            |p| {
                if p == "send-fails" {
                    None
                } else {
                    Some(vec![])
                }
            },
            || {
                retrieved += 1;
                if retrieved == 1 {
                    None
                } else {
                    Some(resp("<style>hit</style>"))
                }
            },
            |r, p| g11_stored_context_hit(r, p, g11_css_match),
        );
        assert_eq!(retrieved, 2);
        assert_eq!(hit.unwrap().0, "hit");
    }

    #[test]
    fn stylesheet_selector_requires_an_exact_rel_token() {
        for (rel, expected) in [
            ("preload-stylesheet", false),
            ("stylesheet-extra", false),
            ("alternate STYLESHEET", true),
        ] {
            let response = resp(&format!("<link rel='{rel}' href='PROBEBODY'>"));
            let hit = g11_stored_context_hit(&response, "PROBEBODY", g11_css_match);
            assert_eq!(hit.is_some(), expected, "{rel}");
        }
    }

    #[test]
    fn link_probes_cover_the_four_zpyp_prefixes() {
        let probes = g11_link_probes();
        assert_eq!(probes.len(), 4);
        assert!(probes[0].starts_with("http://"), "{}", probes[0]);
        assert!(probes[1].starts_with("https://"), "{}", probes[1]);
        assert!(
            probes[2].starts_with("//") && !probes[2].starts_with("///"),
            "{}",
            probes[2]
        );
        assert!(probes[3].starts_with('\\'), "{}", probes[3]);
        // The same random host/path under each prefix.
        let tail = probes[0].trim_start_matches("http://").to_string();
        for p in &probes[1..] {
            assert!(p.ends_with(&tail), "{p}");
        }
    }

    #[test]
    fn stored_rounds_inject_then_retrieve_and_classify() {
        // A probe returned in <style> text is a stored CSS hit; the
        // injection went out first.
        let mut sent = Vec::new();
        let hit = run_g11_stored(
            &["tokaaaaa".to_string()],
            |p: &str| {
                sent.push(p.to_string());
                Some(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec())
            },
            || Some(resp("<style>body{color:tokaaaaa}</style>")),
            |r: &[u8], p: &str| g11_stored_context_hit(r, p, g11_css_match),
        );
        assert_eq!(sent, ["tokaaaaa"]);
        let (p, what) = hit.expect("stored css hit");
        assert_eq!(
            (p.as_str(), what.as_str()),
            ("tokaaaaa", "a <style> element")
        );
        // Plain body text is not a CSS position.
        let none = run_g11_stored(
            &["tokbbbbb".to_string()],
            |_: &str| Some(vec![]),
            || Some(resp("<p>tokbbbbb</p>")),
            |r: &[u8], p: &str| g11_stored_context_hit(r, p, g11_css_match),
        );
        assert!(none.is_none());
        // The stored HPP probe in a URL-bearing attribute value.
        let hit = run_g11_stored(
            &["abc&def".to_string()],
            |_: &str| Some(vec![]),
            || Some(resp("<a href=\"/go?next=abc&def\">y</a>")),
            |r: &[u8], p: &str| g11_stored_context_hit(r, p, g11_hpp_match),
        );
        assert!(hit.is_some());
        // A non-URL attribute is not a client-side navigation context.
        let hit = run_g11_stored(
            &["abc&def".to_string()],
            |_: &str| Some(vec![]),
            || Some(resp("<div data-x=\"abc&def\">y</div>")),
            |r: &[u8], p: &str| g11_stored_context_hit(r, p, g11_hpp_match),
        );
        assert!(hit.is_none(), "non-URL attribute must not flag: {hit:?}");
        // Stored link manipulation: the injected URL as a link target.
        let hit = run_g11_stored(
            &["http://tokcccc.example/dddddd".to_string()],
            |_: &str| Some(vec![]),
            || Some(resp("<a href=\"http://tokcccc.example/dddddd\">x</a>")),
            g11_link_stored_hit,
        );
        assert!(hit.unwrap().1.contains("link/redirect target"));
        // Form action: formaction on a button.
        let hit = run_g11_stored(
            &["https://tokeeee.example/ffffff".to_string()],
            |_: &str| Some(vec![]),
            || {
                Some(resp(
                    "<button formaction=\"https://tokeeee.example/ffffff\">go</button>",
                ))
            },
            |r: &[u8], p: &str| g11_stored_context_hit(r, p, g11_form_action_match),
        );
        assert!(hit.is_some());
        // A retrieval failure abandons the family.
        let none = run_g11_stored(
            &["t".to_string()],
            |_: &str| Some(vec![]),
            || None,
            g11_link_stored_hit,
        );
        assert!(none.is_none());
    }

    #[test]
    fn many_reflections_have_bounded_classification_work() {
        let response = resp(&"<p>PROBEBODY</p>".repeat(20_000));
        let start = std::time::Instant::now();
        let contexts = g11_contexts(&response, "PROBEBODY");
        assert_eq!(contexts.len(), 32);
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        assert!(g11_contexts(&response, "").is_empty());
    }

    #[test]
    fn contexts_cover_style_attr_script_and_head() {
        let r = resp("<html><style>body{color:PROBEBODY}</style></html>");
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::StyleText]);
        let r = resp("<div style=\"background:PROBEBODY\">x</div>");
        assert!(
            matches!(g11_contexts(&r, "PROBEBODY").as_slice(), [G11Context::Attr { tag, attr, .. }] if tag == "div" && attr == "style")
        );
        let r = resp("<script>var x = 'PROBEBODY';</script>");
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::JsText]);
        // A reflection in the response head.
        let r =
            b"HTTP/1.1 302 Found\r\nLocation: https://x/PROBEBODY\r\nContent-Length: 2\r\n\r\nok"
                .to_vec();
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::Head]);
        // Plain body text is Other; rel before href and href before rel both match.
        let r = resp("<p>PROBEBODY</p>");
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::Other]);
        let r = resp("<link href=\"/x?c=PROBEBODY\" rel=\"stylesheet\">");
        assert!(
            matches!(g11_contexts(&r, "PROBEBODY").as_slice(), [G11Context::Attr { tag, attr, attrs }] if tag == "link" && attr == "href" && attrs.iter().any(|(k, _)| k == "rel"))
        );
    }

    #[test]
    fn contexts_survive_script_text_void_tags_and_invalid_utf8() {
        // A '<' inside script text is not a tag; the probe stays JsText.
        let r = resp("<script>if (a<b) { x = 'PROBEBODY'; }</script><p>y</p>");
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::JsText]);
        // A probe after a script close tag parses normally (regression:
        // landing exactly on the close tag must not spin).
        let r = resp("<script>var a=1;</script><p>PROBEBODY</p>");
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::Other]);
        // Void elements never open, so text after <br>/<img> is Other.
        let r = resp("<div><br><img src=x>PROBEBODY</div>");
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::Other]);
        // Invalid UTF-8 in a header must not shift the head/body split:
        // a header reflection still classifies as Head.
        let raw = b"HTTP/1.1 302 Found\r\nX-Loc: \xff\xfe/PROBEBODY\r\nContent-Length: 2\r\n\r\nok"
            .to_vec();
        assert_eq!(g11_contexts(&raw, "PROBEBODY"), vec![G11Context::Head]);
        // HTML attribute values have no escape mechanism: a backslash
        // does not keep the value open, so the probe after the closing
        // quote is plain text.
        let r = resp("<a title=\"x \\\" PROBEBODY\">y</a>");
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::Other]);
        // An LF-only head/body split still classifies header reflections.
        let raw = b"HTTP/1.1 302 Found\nLocation: https://x/PROBEBODY\n\nok".to_vec();
        assert_eq!(g11_contexts(&raw, "PROBEBODY"), vec![G11Context::Head]);
    }

    #[test]
    fn css_reflected_only_in_css_positions() {
        let hit = run_css_reflected(|p| Some(resp(&format!("<style>body{{color:{p}}}</style>"))));
        assert!(hit.is_some());
        let hit = run_css_reflected(|p| Some(resp(&format!("<p>{p}</p>"))));
        assert!(hit.is_none());
        let hit = run_css_reflected(|p| Some(resp(&format!("<div style=\"x:{p}\">y</div>"))));
        assert!(hit.is_some());
        let hit = run_css_reflected(|p| {
            Some(resp(&format!(
                "<link rel=\"stylesheet\" href=\"/x?c={p}\">"
            )))
        });
        assert!(hit.is_some());
    }

    #[test]
    fn hpp_reflected_in_url_attr_js_and_header_only() {
        let hit = run_hpp_reflected(|p| Some(resp(&format!("<a href=\"/go?next={p}\">x</a>"))));
        assert!(hit.is_some());
        // A non-URL attribute is not a client-side navigation context.
        let hit = run_hpp_reflected(|p| Some(resp(&format!("<div data-x=\"{p}\">x</div>"))));
        assert!(hit.is_none(), "non-URL attribute must not flag: {hit:?}");
        let hit = run_hpp_reflected(|p| Some(resp(&format!("<p>{p}</p>"))));
        assert!(hit.is_none());
        let hit = run_hpp_reflected(|p| {
            Some(
                format!("HTTP/1.1 302 Found\r\nLocation: /next?{p}\r\nContent-Length: 2\r\n\r\nok")
                    .into_bytes(),
            )
        });
        assert!(hit.is_some());
    }

    #[test]
    fn form_action_reflected_on_submission_targets() {
        let hit = run_form_action_reflected(|p| {
            Some(resp(&format!(
                "<form action=\"{p}\"><input type=\"text\"></form>"
            )))
        });
        assert!(hit.is_some());
        let hit = run_form_action_reflected(|p| {
            Some(resp(&format!("<button formaction=\"{p}\">go</button>")))
        });
        assert!(hit.is_some());
        let hit = run_form_action_reflected(|p| Some(resp(&format!("<a href=\"{p}\">x</a>"))));
        assert!(hit.is_none());
    }
}
