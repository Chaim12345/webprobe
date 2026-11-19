// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

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
    let config = shared.scan_config.lock().unwrap().clone();
    let points: Vec<InsertionPoint> = audit_points(&req, &config);
    if points.is_empty() {
        // Burp still runs its per-request and per-host checks (CORS,
        // path-relative style sheets, OpenAPI discovery) on such requests.
        shared.log("Scanner: no query parameters; running per-request and per-host checks only");
    }
    // Claim the scanner before touching its progress: a refused second
    // scan must not reset the running one's counters.
    let Some(guard) = crate::scan_run::try_claim(&shared) else {
        shared.log("Scanner: a scan is already running");
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
    shared.log(&format!(
        "Scanner: active scan started ({} insertion point(s), light active checks)",
        points.len()
    ));

    let settings = checks::Settings {
        speed: ScanSpeed::from_u8(shared.scan_speed.load(Ordering::SeqCst)),
        accuracy: crate::variations::Accuracy::from_u8(shared.scan_accuracy.load(Ordering::SeqCst)),
    };
    let (oob, smtp) = (oob.to_vec(), smtp.to_vec());
    crate::util::spawn_contained("scan", move || {
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
        if let Err(e) = run {
            let why = e
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            shared.log(&format!(
                "Scanner: the scan stopped on an internal error: {why}"
            ));
            crate::notice::toast(
                crate::notice::Level::Error,
                format!("Active scan stopped on an internal error: {why}"),
            );
            return;
        }
        drop(_guard);
        let shared = &shared;
        shared.log("Scanner: active scan finished");
        let found = shared.issues.lock().map(|i| i.len()).unwrap_or(0);
        crate::notice::toast(
            crate::notice::Level::Success,
            format!("Active scan finished — {found} issue(s) in the report"),
        );
    });
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
        shared.log(&format!(
            "Scanner: only {} of {} Collaborator ids available; {} out-of-band probe(s) skipped",
            ids.len(),
            slots.len(),
            slots.len() - ids.len()
        ));
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
    let Some(guard) = crate::scan_run::try_claim(shared) else {
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
        shared.log("Scanner: the stored input stage stopped on an internal error");
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


// ================= G.11 reflected manipulation contexts (burp.Zb_5 / Zcpt) =================

/// Where in a response a probe reflection landed: the subset of burp.Zcpt's
/// context identification the G.11 families select on (Zbf4.java:25-35
/// preserves the same contexts in the report).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum G11Context {
    /// Inside the value of `attr` on `tag`; `attrs` carries every
    /// attribute of that tag (names lowercased).
    Attr { tag: String, attr: String, attrs: Vec<(String, String)> },
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
            G11Context::Attr { tag, attr, .. } => format!("the {attr} attribute of a <{tag}> element"),
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
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
    "source", "track", "wbr",
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
            i = body[i + 4..].find("-->").map(|x| x + i + 7).unwrap_or(b.len());
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
        let name_len = body[name_start..gt].find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>').unwrap_or(gt - name_start);
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
        if let Some((name, vs, ve)) = spans.iter().find(|(_, vs, ve)| pos >= *vs && pos < *ve) {
            let attrs = spans.iter().map(|(k, vs, ve)| (k.clone(), body[*vs..*ve].to_string())).collect();
            return G11Context::Attr { tag, attr: name.clone(), attrs };
        }
        if closing {
            if let Some(k) = open.iter().rposition(|t| *t == tag) {
                open.truncate(k);
            }
        } else if !tag.is_empty() && !VOID_TAGS.contains(&tag.as_str()) && !body[i..gt].trim_end().ends_with('/') {
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

/// Every occurrence of `probe` in `resp`, classified (burp.Zcpt).
pub(crate) fn g11_contexts(resp: &[u8], probe: &str) -> Vec<G11Context> {
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
    while start + probe.len() <= text.len() {
        let Some(at) = text[start..].find(probe).map(|p| p + start) else { break };
        out.push(if at < head_end { G11Context::Head } else { g11_body_context(&text[head_end..], at - head_end) });
        start = at + probe.len();
    }
    out
}

fn g11_token(n: usize) -> String {
    use rand::Rng;
    let mut g = rand::thread_rng();
    (0..n).map(|_| (b'a' + g.gen_range(0..26)) as char).collect()
}

/// CSS injection (reflected), burp.Zb_5's selector -> Zw0x (KB 00501300):
/// a token injected at the point must reflect in a CSS position: <style>
/// text, a style attribute, or the href of a <link rel=stylesheet>. The
/// CSS-specific payload literal (Zi9s initializer) and the full
/// applicable-tag map are stripped from the jar (not established), so the
/// probe is a plain token and detection is purely contextual; REPLACE
/// mode only (Burp also tries APPEND).
/// Returns (payload, context description, response).
pub(crate) fn run_css_reflected<F: FnMut(&str) -> Option<Vec<u8>>>(mut send: F) -> Option<(String, String, Vec<u8>)> {
    let token = g11_token(8);
    let resp = send(&token)?;
    let cx = g11_contexts(&resp, &token).into_iter().find(|c| match c {
        G11Context::StyleText => true,
        G11Context::Attr { attr, .. } if attr == "style" => true,
        G11Context::Attr { tag, attr, attrs } if tag == "link" && attr == "href" => attrs.iter().any(|(k, v)| k == "rel" && v.to_ascii_lowercase().contains("stylesheet")),
        _ => false,
    })?;
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
pub(crate) fn run_hpp_reflected<F: FnMut(&str) -> Option<Vec<u8>>>(mut send: F) -> Option<(String, String, Vec<u8>)> {
    let probe = format!("{}&{}", g11_token(3), g11_token(3));
    let resp = send(&probe)?;
    // Attribute hits only count on URL-bearing attributes: a parameter
    // pair reflected into a URL is what client-side navigation reads.
    let cx = g11_contexts(&resp, &probe).into_iter().find(|c| match c {
        G11Context::Attr { attr, .. } => matches!(attr.as_str(), "href" | "src" | "action" | "formaction"),
        G11Context::JsText | G11Context::Head => true,
        _ => false,
    })?;
    Some((probe, cx.describe(), resp))
}

/// Form action hijacking (reflected), burp.Zb_5 -> Zc51 (KB 00501500):
/// an injected URL must reflect as a form submission target — the action
/// of a <form> or any element's formaction attribute (the Zi9s map's
/// decoded form/action/input entries; the full map is not established).
/// REPLACE mode only.
pub(crate) fn run_form_action_reflected<F: FnMut(&str) -> Option<Vec<u8>>>(mut send: F) -> Option<(String, String, Vec<u8>)> {
    let probe = format!("https://{}.example/{}", g11_token(8), g11_token(6));
    let resp = send(&probe)?;
    let cx = g11_contexts(&resp, &probe).into_iter().find(|c| match c {
        G11Context::Attr { tag, attr, .. } => (tag == "form" && attr == "action") || attr == "formaction",
        _ => false,
    })?;
    Some((probe, cx.describe(), resp))
}

#[cfg(test)]
mod g11_tests {
    use super::*;

    fn resp(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    #[test]
    fn contexts_cover_style_attr_script_and_head() {
        let r = resp("<html><style>body{color:PROBEBODY}</style></html>");
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::StyleText]);
        let r = resp("<div style=\"background:PROBEBODY\">x</div>");
        assert!(matches!(g11_contexts(&r, "PROBEBODY").as_slice(), [G11Context::Attr { tag, attr, .. }] if tag == "div" && attr == "style"));
        let r = resp("<script>var x = 'PROBEBODY';</script>");
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::JsText]);
        // A reflection in the response head.
        let r = b"HTTP/1.1 302 Found\r\nLocation: https://x/PROBEBODY\r\nContent-Length: 2\r\n\r\nok".to_vec();
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::Head]);
        // Plain body text is Other; rel before href and href before rel both match.
        let r = resp("<p>PROBEBODY</p>");
        assert_eq!(g11_contexts(&r, "PROBEBODY"), vec![G11Context::Other]);
        let r = resp("<link href=\"/x?c=PROBEBODY\" rel=\"stylesheet\">");
        assert!(matches!(g11_contexts(&r, "PROBEBODY").as_slice(), [G11Context::Attr { tag, attr, attrs }] if tag == "link" && attr == "href" && attrs.iter().any(|(k, _)| k == "rel")));
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
        let raw = b"HTTP/1.1 302 Found\r\nX-Loc: \xff\xfe/PROBEBODY\r\nContent-Length: 2\r\n\r\nok".to_vec();
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
        let hit = run_css_reflected(|p| Some(resp(&format!("<link rel=\"stylesheet\" href=\"/x?c={p}\">"))));
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
        let hit = run_hpp_reflected(|p| Some(format!("HTTP/1.1 302 Found\r\nLocation: /next?{p}\r\nContent-Length: 2\r\n\r\nok").into_bytes()));
        assert!(hit.is_some());
    }

    #[test]
    fn form_action_reflected_on_submission_targets() {
        let hit = run_form_action_reflected(|p| Some(resp(&format!("<form action=\"{p}\"><input type=\"text\"></form>"))));
        assert!(hit.is_some());
        let hit = run_form_action_reflected(|p| Some(resp(&format!("<button formaction=\"{p}\">go</button>"))));
        assert!(hit.is_some());
        let hit = run_form_action_reflected(|p| Some(resp(&format!("<a href=\"{p}\">x</a>"))));
        assert!(hit.is_none());
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
    reset_openapi_hosts();
    for url in start_urls {
        let mut items = if audit_only {
            crate::crawl::crawl_single(shared, url)
        } else {
            crate::crawl::crawl(shared, url)
        };
        // Browser-driven crawl (Burp's crawler drives Chromium): picks up
        // client-side routes and the API calls pages make; each observed
        // same-origin request is re-issued as a crawl item.
        let engine = shared.scan_config.lock().unwrap().crawl.engine.clone();
        if !audit_only && !engine.is_empty() && !engine.eq_ignore_ascii_case("chromium") {
            // Another headless engine (headless.rs): render through the
            // proxy, then fetch each page it found as a crawl item.
            match crate::headless::pick(Some(&engine)) {
                Some(eng) => match crate::headless::js_crawl(eng.as_ref(), shared, url) {
                    Ok(urls) => {
                        shared.log(&format!(
                            "{} crawl of {url}: {} page(s)",
                            eng.name(),
                            urls.len()
                        ));
                        let mut keys: std::collections::BTreeSet<String> = items
                            .iter()
                            .map(|e| {
                                format!("{} {}", e.method, crate::crawl::location_key(&e.path))
                            })
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
                    Err(e) => shared.log(&format!(
                        "{} crawl unavailable ({e}); static crawl only",
                        eng.name()
                    )),
                },
                None => shared.log(&format!(
                    "Headless engine {engine} is not installed; static crawl only"
                )),
            }
        } else if !audit_only {
            match crate::crawl::browser_crawl(shared, url) {
                Ok(mut seen) => {
                    shared.log(&format!(
                        "Browser crawl of {url}: {} request(s) observed",
                        seen.len()
                    ));
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
                Err(e) => shared.log(&format!(
                    "Browser crawl unavailable ({e}); static crawl only"
                )),
            }
        }
        shared.log(&format!("Crawl of {url}: {} item(s)", items.len()));
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
    shared.log("Crawl and audit finished");
}
