// Dynamic DOM analysis, R-13 option (b): the runtime lives in
// crate::crawl (dom_analysis_probe + DomRoute); this module owns the
// family checks that consume its hits. Moved out of graphql.rs on
// 2026-11-23 (pure move) so the DOM lane has one home.

use super::*;

pub(crate) const DOM_XSS_SINKS: &[&str] = &[
    "document.write",
    "document.writeln",
    "element.innerHTML",
    "element.outerHTML",
    "element.insertAdjacentHTML",
    "element.setAttribute.onclick",
    "jQuery.html",
    "jQuery.append",
    "jQuery.prepend",
    "jQuery.before",
    "jQuery.after",
    "jQuery.wrap",
    "jQuery.replaceWith",
    "jQuery.parseHTML",
];
pub(crate) const DOM_JS_INJECTION_SINKS: &[&str] = &[
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "jQuery.globalEval",
];
pub(crate) const DOM_OPEN_REDIRECTION_SINKS: &[&str] = &["window.open"];
pub(crate) const DOM_DATA_MANIPULATION_SINKS: &[&str] = &[
    "element.textContent",
    "element.innerText",
    "input.value",
    "document.title",
    "window.name",
    "history.pushState",
    "history.replaceState",
    "script.text",
    "anchor.target",
    "element.setAttribute.action",
    "element.setAttribute.src",
    "element.setAttribute.data",
    "element.setAttribute.formaction",
];
pub(crate) const DOM_LINK_MANIPULATION_SINKS: &[&str] = &[
    "form.action",
    "anchor.href",
    "button.formaction",
    "input.formaction",
    "element.setAttribute.href",
    "jQuery.attr.href",
    "jQuery.prop.href",
    "jQuery.attr.action",
    "jQuery.prop.action",
];
pub(crate) const DOM_WEBSOCKET_POISONING_SINKS: &[&str] = &["websocket"];
pub(crate) const DOM_DOS_SINKS: &[&str] = &["RegExp"];
pub(crate) const DOM_AJAX_HEADER_SINKS: &[&str] =
    &["xhr.setRequestHeader.name", "xhr.setRequestHeader.value"];
pub(crate) const DOM_STORAGE_MANIPULATION_SINKS: &[&str] = &[
    "localStorage.setItem.name",
    "localStorage.setItem.value",
    "sessionStorage.setItem.name",
    "sessionStorage.setItem.value",
];
pub(crate) const DOM_JSON_INJECTION_SINKS: &[&str] = &["JSON.parse"];
pub(crate) const DOM_XPATH_INJECTION_SINKS: &[&str] = &["document.evaluate"];
pub(crate) const DOM_DOCUMENT_DOMAIN_SINKS: &[&str] = &["document.domain"];
pub(crate) const DOM_COOKIE_MANIPULATION_SINKS: &[&str] = &["document.cookie"];
pub(crate) const DOM_WEB_MESSAGE_SINKS: &[&str] = &["postMessage"];

/// Addition-only Object.prototype evidence. Stored pollution is not covered.
pub(crate) const DOM_PROTOTYPE_POLLUTION_SINKS: &[&str] = &["Object.prototype"];

/// Only dedicated URL-part tokens plus new own-key evidence are admitted.
/// Reflection into a DOM sink is not pollution; stored pollution and overwrites
/// of existing prototype properties are outside this milestone.
pub(crate) struct DomPrototypePollution;
impl RequestCheck for DomPrototypePollution {
    fn id(&self) -> &'static str {
        "active.dom-prototype-pollution"
    }
    fn issue(&self) -> &'static str {
        "Client-side prototype pollution"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn group(&self) -> Option<&'static str> {
        Some(BURP_GROUP)
    }
    // This check sends only through dom_analysis_hits, which after stop
    // reads existing cache cells only and never initializes a miss.
    fn consumes_cached_dom_after_stop(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx) {
        if !cx.runs(self.issue()) {
            return;
        }
        let outcome = dom_analysis_hits(cx);
        let mut seen = std::collections::HashSet::new();
        for hit in &outcome.hits {
            if !DOM_PROTOTYPE_POLLUTION_SINKS.contains(&hit.sink.as_str())
                || !matches!(
                    hit.source.as_str(),
                    "location.hash" | "location.search" | "location.hash+location.search"
                )
                || (!outcome.stored.is_empty() && hit.sink_value.contains(&outcome.stored))
                || !seen.insert((hit.sink.as_str(), hit.source.as_str()))
            {
                continue;
            }
            let source = match hit.source.as_str() {
                "location.hash+location.search" => "location.hash and location.search",
                s => s,
            };
            let mut issue = mk("info", self.issue(), &cx.entry, format!(
                "The application may be vulnerable to client-side prototype pollution. Data is read from <b>{}</b> and a new own property was observed on <b>Object.prototype</b>.<br><br>The source value <b>{}</b> reached the prototype as <b>{}</b>.<br><br>Addition-only evidence: existing-property overwrites and stored pollution are not covered.",
                util::html_encode(source), util::html_encode(&hit.source_value), util::html_encode(&hit.sink_value)));
            if !outcome.complete {
                issue.detail.push_str(&format!("<br><br>DOM operation incomplete: {}. This finding retains independently observed evidence only.", util::html_encode(&outcome.diagnostic)));
            }
            issue.confidence = if hit.source == "location.hash" {
                "Firm"
            } else {
                "Tentative"
            }
            .into();
            cx.report(vec![issue]);
        }
    }
}

/// A GET over the audited session (cookie/session headers of the template
/// request, minus framing and hop-by-hop fields): the stored submission
/// carries the same identity as the audited
/// request, like the browser probe's forwarded requests.
fn authed_get(cx: &ScanCtx, path_query: &str) -> Vec<u8> {
    let mut raw = format!("GET {path_query} HTTP/1.1\r\nHost: {}\r\n", cx.host_hdr);
    let connection = cx
        .parts
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>()
        .join(",");
    for (k, v) in &cx.parts.headers {
        if crate::crawl::dom_safe_header(k, v, &connection) {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    raw.push_str("Connection: close\r\nAccept-Encoding: identity\r\n\r\n");
    raw.into_bytes()
}

/// Only self-delimited complete final responses acknowledge a submission.
/// The transport's Option<Vec<u8>> does not prove clean EOF, so an EOF-
/// delimited response is conservatively unknown, never replayed.
fn dom_submission_acknowledged(response: &[u8]) -> bool {
    crate::crawl::dom_complete_final_response(response)
}

#[test]
fn dom_submission_requires_complete_final_response_head() {
    for raw in [
        b"".as_slice(),
        b"HTTP/1.1 200",
        b"HTTP/1.1 100 Continue\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
        b"HTTP/1.1 200 OK\r\n\r\nunknown EOF",
    ] {
        assert!(!dom_submission_acknowledged(raw), "{raw:?}");
    }
    for raw in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".as_slice(),
        b"HTTP/1.1 204 No Content\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
    ] {
        assert!(dom_submission_acknowledged(raw), "{raw:?}");
    }
}

/// Dynamic DOM analysis, R-13 option (b) (burp.Zel5's runAnalysis shape;
/// the injected script body is not established, so WebProbe's
/// instrumentation is its own): each HTML page is opened once in a
/// headless browser carrying the fragment and query probe payloads (the
/// location.hash and location.search sources), the wrapped sinks are
/// the families of burp.Zcwh's dynamic decoder (docs/specs/R-13), and a
/// probe token reaching a sink is reported under the sink's family. One
/// browser run per URL serves every family check; hits are kept only on
/// the probed origin (the browser's own chrome-error pages run the
/// wrapped sinks too) and merged per sink, variant and source.
/// Skipped when no Chromium is available.
/// Results belong to the current run's ScanDedup. A per-URL OnceLock
/// shares one browser probe across the fourteen families and concurrent
/// callers. The cached outcome also carries the reflected query token
/// and the stored token: burp.Zf24's REFLECTED and STORED variants are
/// per HIT (see dom_family_check!), so the tokens must be cached with
/// the hits.
pub(crate) fn dom_analysis_hits(cx: &ScanCtx) -> webprobe_support::dedup::DomProbeOutcome {
    // Only GET history can be navigated faithfully as a browser GET.
    if !matches!(cx.req.split_whitespace().next(), Some("GET")) {
        return Default::default();
    }
    // Dynamic analysis runs on pages: the baseline must be HTML.
    let rp = util::parse_http(&cx.baseline.raw);
    let ct = util::get_header(&rp.headers, "Content-Type").unwrap_or_default();
    if !ct.to_ascii_lowercase().contains("html") {
        return Default::default();
    }
    // No dynamic source can run in a page with no script, inline handler
    // or javascript: URL. Avoid launching Chromium for inert HTML.
    static EXECUTABLE_HTML: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    if !EXECUTABLE_HTML
        .get_or_init(|| regex::Regex::new(r"(?i)<script\b|\bon[a-z]+\s*=|javascript:").unwrap())
        .is_match(&cx.baseline.body)
    {
        return Default::default();
    }
    let scheme = if cx.entry.https { "https" } else { "http" };
    let default = if cx.entry.https { 443 } else { 80 };
    let port = if cx.port == default {
        String::new()
    } else {
        format!(":{}", cx.port)
    };
    let path = cx.parts.path.split('#').next().unwrap_or("/");
    if !path.starts_with('/') || path.starts_with("//") {
        return Default::default();
    }
    let host = if cx.host.contains(':') {
        format!("[{}]", cx.host)
    } else {
        cx.host.clone()
    };
    let url = format!("{scheme}://{host}{port}{path}");
    let state = cx.state();
    // Cancellation is cache-only: never create or initialize a cell.
    if cx.stopped() {
        return state
            .dom_hits
            .lock()
            .unwrap()
            .get(&url)
            .and_then(|cell| cell.get())
            .cloned()
            .unwrap_or_default();
    }
    let cell = state
        .dom_hits
        .lock()
        .unwrap()
        .entry(url.clone())
        .or_default()
        .clone();
    cell.get_or_init(|| {
        if cx.stopped() {
            return Default::default();
        }
        // Two distinct run-owned tokens: the query-string payload
        // (tok_s) and the fragment payload (tok_h) ride the SAME single
        // navigation, so one probe covers both URL-part sources with no
        // extra browser run. The instrumentation attributes a hit by
        // which token the evidence contains; a transformed value that
        // loses the tokens is conservatively not reported.
        let tok_s = format!("wp{}", rnd_letters(10));
        let tok_h = format!("wp{}", rnd_letters(10));
        let canary = format!("__proto__[{tok_h}]={tok_h}");
        let sep = if url.contains('?') { "&" } else { "?" };
        let probe_url = format!("{url}{sep}__proto__[{tok_s}]={tok_s}");
        let origin = crate::crawl::origin_of(&probe_url).unwrap_or_default();
        // The stored-DOM variant (burp.Zf24's STORED; Zhp's template: the
        // value "submitted to the URL ... is copied into a JavaScript string
        // literal" of a later response): submit a distinct stored token with
        // the request first; a sink hit holding it was embedded by the app,
        // not read from this navigation's URL. Each URL gets its own token
        // (the probe cache is keyed by URL), so a stored hit is attributed to
        // THIS page's submission.
        //
        // Side effect, inherent to stored-variant detection: this GET with
        // the stored payload reaches every scanned HTML page in the audited
        // request's session, and an application may persist the value (logs,
        // search history, comments). The token is a random inert string and
        // the check runs only as part of the active scan.
        let tok_st = format!("wp{}", rnd_letters(10));
        let sep0 = if path.contains('?') { "&" } else { "?" };
        let submit = authed_get(cx, &format!("{path}{sep0}__proto__[{tok_st}]={tok_st}"));
        let probe = crate::crawl::dom_analysis_probe(
            &cx.shared,
            &probe_url,
            &canary,
            &cx.req,
            &cx.host,
            cx.port,
            cx.entry.https,
            &tok_st,
            || {
                crate::tasks::wait_while_paused(&cx.shared);
                if cx.stopped() {
                    return Err("scan stopped before stored submission".into());
                }
                let response = cx.send(&submit);
                let confirmed = response
                    .as_ref()
                    .is_some_and(|r| dom_submission_acknowledged(r));
                if confirmed {
                    Ok(())
                } else {
                    Err(
                        "stored submission outcome unknown; not retried; DOM operation stopped"
                            .into(),
                    )
                }
            },
        );
        if let Err(e) = &probe {
            cx.shared.scan.record_dom(crate::scan_run::DomScanRecord {
                url: url.chars().take(500).collect(),
                complete: false,
                cancelled: cx.stopped(),
                proven_hits: Vec::new(),
                diagnostic: e.chars().take(500).collect(),
            });
            // A crashed/timed-out probe is not a clean bill of health: say so
            // in the scan log (the cached empty hit set only avoids
            // re-probing this URL for every family check in this run).
            cx.shared
                .log(&format!("DOM analysis probe failed for {url}: {e}"));
        }
        let Ok(probe) = probe else {
            return Default::default();
        };
        // Only the exact navigation response fulfilled to Chromium is evidence.
        // Script-text co-occurrence is not a proven string-literal data flow.
        cx.shared.scan.record_dom(crate::scan_run::DomScanRecord {
            url: url.chars().take(500).collect(),
            complete: probe.complete,
            cancelled: probe.cancelled,
            proven_hits: probe.hits.clone(),
            diagnostic: probe.diagnostic.clone(),
        });
        let reflected = probe
            .document_response
            .as_ref()
            .is_some_and(|r| {
                crate::scan::g11_contexts(r, &tok_s)
                    .iter()
                    .any(|c| matches!(c, crate::scan::G11Context::JsText))
            })
            .then_some(tok_s);
        let hits = probe
            .hits
            .into_iter()
            .filter(|h| crate::crawl::same_origin(&h.page_url, &origin))
            .collect();
        webprobe_support::dedup::DomProbeOutcome {
            hits,
            reflected,
            stored: tok_st,
            complete: probe.complete,
            cancelled: probe.cancelled,
            diagnostic: probe.diagnostic,
        }
    })
    .clone()
}

/// One DOM family check: the sinks of one burp.Zcwh family, the issues it
/// reports (base DOM-based plus burp.Zf24's REFLECTED and STORED variants,
/// attributed per hit) and the check metadata. The dynamic hits come from
/// the shared probe cache.
macro_rules! dom_family_check {
    ($name:ident, $id:literal, $issue:literal, $reflected_issue:literal, $stored_issue:literal, $severity:literal, $confidence:literal, $family:literal, $sinks:expr, $doc:literal) => {
        #[doc = $doc]
        pub(crate) struct $name;

        impl RequestCheck for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn issue(&self) -> &'static str {
                $issue
            }
            fn scope(&self) -> Scope {
                Scope::Request
            }
            fn group(&self) -> Option<&'static str> {
                Some(BURP_GROUP)
            }
            fn consumes_cached_dom_after_stop(&self) -> bool { true }
            fn run(&self, cx: &ScanCtx) {
                if !cx.runs(self.issue()) {
                    return;
                }
                let webprobe_support::dedup::DomProbeOutcome {
                    hits,
                    reflected: reflected_token,
                    stored: stored_token,
                    complete,
                    diagnostic,
                    ..
                } = dom_analysis_hits(cx);
                let mut seen: std::collections::HashSet<(&str, &str, &str)> = std::collections::HashSet::new();
                for hit in hits.iter().filter(|h| $sinks.contains(&h.sink.as_str())) {
                    // burp.Zf24.Zw: a hit holding the stored token was
                    // embedded by the application from an earlier request
                    // (the stored variant); otherwise a hit whose sink
                    // value carries the query token the server echoed
                    // into this response's script text makes the
                    // reflected variant (per hit, not per page).
                    let (issue, detail) = if !stored_token.is_empty() && hit.sink_value.contains(&stored_token) {
                        (
                            $stored_issue,
                            format!(
                                "The application may be vulnerable to stored {}. A probe token submitted in an earlier request was later observed at <b>{}</b>. This suggests persistence but does not establish the storage mechanism or a JavaScript string-literal origin.<br><br>The stored value <b>{}</b> reached the sink as <b>{}</b>.",
                                $family,
                                util::html_encode(&hit.sink),
                                util::html_encode(&hit.source_value),
                                util::html_encode(&hit.sink_value)
                            ),
                        )
                    } else if reflected_token.as_deref().is_some_and(|qt| hit.sink_value.contains(qt)) {
                        (
                            $reflected_issue,
                            format!(
                                "The application may be vulnerable to reflected {}. The query probe token appeared in script text of the navigation response fulfilled to the browser and was also observed at <b>{}</b>. These observations do not prove that the sink value came from that script text or from a JavaScript string literal.<br><br>The source value <b>{}</b> reached the sink as <b>{}</b>.",
                                $family,
                                util::html_encode(&hit.sink),
                                util::html_encode(&hit.source_value),
                                util::html_encode(&hit.sink_value)
                            ),
                        )
                    } else {
                        let provenance_note = match hit.source.as_str() {
                            "location.hash" => "location.hash",
                            "location.search" => "location.search",
                            "location.hash+location.search" => "location.hash and location.search",
                            _ => "the URL (query or fragment; part not attributable)",
                        };
                        (
                            $issue,
                            format!(
                                "The application may be vulnerable to {}. Data is read from <b>{}</b> and passed to <b>{}</b>.<br><br>The source value <b>{}</b> reached the sink as <b>{}</b>.",
                                $family,
                                util::html_encode(provenance_note),
                                util::html_encode(&hit.sink),
                                util::html_encode(&hit.source_value),
                                util::html_encode(&hit.sink_value)
                            ),
                        )
                    };
                    if !seen.insert((hit.sink.as_str(), issue, hit.source.as_str())) { continue; }
                    let detail=if complete { detail } else { format!("{}<br><br>DOM operation incomplete: {}. This finding retains independently observed evidence only.",detail,util::html_encode(&diagnostic)) };
                    let mut i = mk($severity, issue, &cx.entry, detail);
                    // burp.Zwf8's confidence mapping is established for a
                    // location.hash source only: a base-variant hit with
                    // hash-only provenance keeps the family confidence;
                    // everything else (search, mixed or unknown
                    // provenance, the reflected and stored variants) is
                    // reported conservatively as Tentative.
                    // burp.Zwf8.Zd: a jQuery-dependent result (flag 4) is
                    // always Tentative.
                    i.confidence = if issue == $issue
                        && hit.source == "location.hash"
                        && !hit.sink.starts_with("jQuery.")
                    {
                        $confidence.into()
                    } else {
                        "Tentative".into()
                    };
                    cx.report(vec![i]);
                }
            }
        }
    };
}

dom_family_check!(
    DomXss,
    "active.dom-xss",
    "Cross-site scripting (DOM-based)",
    "Cross-site scripting (reflected DOM-based)",
    "Cross-site scripting (stored DOM-based)",
    "high",
    "Firm",
    "DOM-based cross-site scripting",
    DOM_XSS_SINKS,
    "Cross-site scripting (DOM-based), KB 00200310, High: the HTML-writing sinks of burp.Zcwh's XSS family (first slice: document.write/writeln, inner/outerHTML, insertAdjacentHTML; jQuery groups not yet). Confidence Firm (burp.Zwf8.Zd: no Tentative rule covers a location.hash source)."
);
dom_family_check!(
    DomJsInjection,
    "active.dom-javascript-injection",
    "JavaScript injection (DOM-based)",
    "JavaScript injection (reflected DOM-based)",
    "JavaScript injection (stored DOM-based)",
    "high",
    "Firm",
    "DOM-based JavaScript injection",
    DOM_JS_INJECTION_SINKS,
    "JavaScript injection (DOM-based), KB 00200320, High: the JavaScript-execution sinks of burp.Zcwh's family (eval, Function, setTimeout/setInterval string handlers; execScript and javascript: URLs are not wrappable, not established here). Confidence Firm (burp.Zwf8.Zd)."
);
dom_family_check!(
    DomOpenRedirection,
    "active.dom-open-redirection",
    "Open redirection (DOM-based)",
    "Open redirection (reflected DOM-based)",
    "Open redirection (stored DOM-based)",
    "low",
    "Tentative",
    "DOM-based open redirection",
    DOM_OPEN_REDIRECTION_SINKS,
    "Open redirection (DOM-based), KB 00500110, Low: window.open, the only wrappable navigation sink of burp.Zcwh's family - the Location members (href, assign, replace, host, hostname, protocol) are LegacyUnforgeable in Chromium. Confidence Tentative (burp.Zwf8.Zd: every open-redirection variant is Tentative)."
);
dom_family_check!(
    DomDataManipulation,
    "active.dom-data-manipulation",
    "DOM data manipulation (DOM-based)",
    "DOM data manipulation (reflected DOM-based)",
    "DOM data manipulation (stored DOM-based)",
    "info",
    "Firm",
    "DOM-based data manipulation",
    DOM_DATA_MANIPULATION_SINKS,
    "DOM data manipulation (DOM-based), KB 00501200, Information: the UI/logic property sinks of burp.Zcwh's data-manipulation family (textContent/innerText, input.value, document.title, window.name, history pushState/replaceState, script.text, anchor.target, setAttribute action/src/data/formaction). script.textContent/innerText collapse onto the element.* sink names (the prototype setters are shared). Confidence Firm (burp.Zwf8.Zd)."
);
dom_family_check!(
    DomLinkManipulation,
    "active.dom-link-manipulation",
    "Link manipulation (DOM-based)",
    "Link manipulation (reflected DOM-based)",
    "Link manipulation (stored DOM-based)",
    "low",
    "Firm",
    "DOM-based link manipulation",
    DOM_LINK_MANIPULATION_SINKS,
    "Link manipulation (DOM-based), KB 00501000, Low: the navigation-target property sinks of burp.Zcwh's link family (form.action, anchor.href, button/input.formaction, setAttribute href; jQuery prop/attr variants not yet). Confidence Firm (burp.Zwf8.Zd)."
);
dom_family_check!(
    DomWebSocketPoisoning,
    "active.dom-websocket-poisoning",
    "WebSocket URL poisoning (DOM-based)",
    "WebSocket URL poisoning (reflected DOM-based)",
    "WebSocket URL poisoning (stored DOM-based)",
    "high",
    "Firm",
    "DOM-based WebSocket URL poisoning",
    DOM_WEBSOCKET_POISONING_SINKS,
    "WebSocket URL poisoning (DOM-based), KB 00200340, High: the WebSocket constructor (burp.Zcwh's websocket sink). Confidence Firm (burp.Zwf8.Zd)."
);
dom_family_check!(
    DomDos,
    "active.dom-dos",
    "Denial of service (DOM-based)",
    "Denial of service (reflected DOM-based)",
    "Denial of service (stored DOM-based)",
    "info",
    "Firm",
    "DOM-based denial of service",
    DOM_DOS_SINKS,
    "Denial of service (DOM-based), KB 00500d00, Information: the RegExp constructor (burp.Zcwh's literal dynamic mapping for the family). Confidence Firm (burp.Zwf8.Zd)."
);
dom_family_check!(
    DomAjaxHeader,
    "active.dom-ajax-header-manipulation",
    "Ajax request header manipulation (DOM-based)",
    "Ajax request header manipulation (reflected DOM-based)",
    "Ajax request header manipulation (stored DOM-based)",
    "low",
    "Firm",
    "DOM-based Ajax request header manipulation",
    DOM_AJAX_HEADER_SINKS,
    "Ajax request header manipulation (DOM-based), KB 00500c00, Low: XMLHttpRequest.setRequestHeader name and value. Confidence Firm (burp.Zwf8.Zd's Tentative rule covers a document.cookie source, not location.hash)."
);
dom_family_check!(
    DomStorageManipulation,
    "active.dom-storage-manipulation",
    "HTML5 storage manipulation (DOM-based)",
    "HTML5 storage manipulation (reflected DOM-based)",
    "HTML5 storage manipulation (stored DOM-based)",
    "info",
    "Firm",
    "DOM-based HTML5 storage manipulation",
    DOM_STORAGE_MANIPULATION_SINKS,
    "HTML5 storage manipulation (DOM-based), KB 00500f00, Information: the localStorage/sessionStorage setItem name and value sinks of burp.Zcwh's storage family. Confidence Firm (burp.Zwf8.Zd)."
);
dom_family_check!(
    DomJsonInjection,
    "active.dom-json-injection",
    "Client-side JSON injection (DOM-based)",
    "Client-side JSON injection (reflected DOM-based)",
    "Client-side JSON injection (stored DOM-based)",
    "low",
    "Firm",
    "DOM-based client-side JSON injection",
    DOM_JSON_INJECTION_SINKS,
    "Client-side JSON injection (DOM-based), KB 00200370, Low: JSON.parse, burp.Zcwh's client-side JSON injection sink. Confidence Firm (burp.Zwf8.Zd)."
);
dom_family_check!(
    DomXpathInjection,
    "active.dom-xpath-injection",
    "Client-side XPath injection (DOM-based)",
    "Client-side XPath injection (reflected DOM-based)",
    "Client-side XPath injection (stored DOM-based)",
    "low",
    "Firm",
    "DOM-based client-side XPath injection",
    DOM_XPATH_INJECTION_SINKS,
    "Client-side XPath injection (DOM-based), KB 00200360, Low: document.evaluate (jQuery.parseXML not yet), burp.Zcwh's XPath family. Confidence Firm (burp.Zwf8.Zd)."
);
dom_family_check!(
    DomDocumentDomain,
    "active.dom-document-domain",
    "Document domain manipulation (DOM-based)",
    "Document domain manipulation (reflected DOM-based)",
    "Document domain manipulation (stored DOM-based)",
    "medium",
    "Firm",
    "DOM-based document domain manipulation",
    DOM_DOCUMENT_DOMAIN_SINKS,
    "Document domain manipulation (DOM-based), KB 00501100, Medium: the document.domain setter (configurable in Chromium, wrapped). Confidence Firm (burp.Zwf8.Zd)."
);

dom_family_check!(
    DomCookieManipulation,
    "active.dom-cookie-manipulation",
    "Cookie manipulation (DOM-based)",
    "Cookie manipulation (reflected DOM-based)",
    "Cookie manipulation (stored DOM-based)",
    "low",
    "Firm",
    "DOM-based cookie manipulation",
    DOM_COOKIE_MANIPULATION_SINKS,
    "Cookie manipulation (DOM-based), KB 00500b00, Low: the document.cookie setter (burp.Zcwh's cookie family). Confidence Firm (burp.Zwf8.Zd)."
);

dom_family_check!(
    DomWebMessage,
    "active.dom-web-message-manipulation",
    "HTML5 web message manipulation (DOM-based)",
    "HTML5 web message manipulation (reflected DOM-based)",
    "HTML5 web message manipulation (stored DOM-based)",
    "info",
    "Firm",
    "DOM-based HTML5 web message manipulation",
    DOM_WEB_MESSAGE_SINKS,
    "HTML5 web message manipulation (DOM-based), KB 00500e00, Information: controllable data sent as a web message to another document (window.postMessage; no literal Zcwh sink mapping - the family is established by the KB resource). Confidence Firm (burp.Zwf8.Zd)."
);

/// Sink-set drift, both directions (burp.Zcwh's family tables drive the
/// reports): drift between the JS wrappers and the Rust checks would
/// silently drop or orphan hits.
#[test]
fn dom_sink_sets_match_the_instrumentation() {
    let families: &[&[&str]] = &[
        DOM_XSS_SINKS,
        DOM_JS_INJECTION_SINKS,
        DOM_OPEN_REDIRECTION_SINKS,
        DOM_DATA_MANIPULATION_SINKS,
        DOM_LINK_MANIPULATION_SINKS,
        DOM_WEBSOCKET_POISONING_SINKS,
        DOM_DOS_SINKS,
        DOM_AJAX_HEADER_SINKS,
        DOM_STORAGE_MANIPULATION_SINKS,
        DOM_JSON_INJECTION_SINKS,
        DOM_XPATH_INJECTION_SINKS,
        DOM_DOCUMENT_DOMAIN_SINKS,
        DOM_COOKIE_MANIPULATION_SINKS,
        DOM_WEB_MESSAGE_SINKS,
        DOM_PROTOTYPE_POLLUTION_SINKS,
    ];
    let mut rust: Vec<&str> = families.iter().flat_map(|f| f.iter().copied()).collect();
    rust.sort_unstable();
    rust.dedup();
    let js = crate::crawl::DOM_INSTRUMENT_JS;
    let mut js_sinks: Vec<&str> = Vec::new();
    let mut rest = js;
    while let Some(i) = rest.find("record(\"") {
        let after = &rest[i + 8..];
        let end = after.find('"').expect("record literal");
        js_sinks.push(&after[..end]);
        rest = &after[end..];
    }
    // wrapSetter takes the sink name as its third argument.
    let mut rest = js;
    while let Some(i) = rest.find("wrapSetter(") {
        let after = &rest[i + 11..];
        let end = after.find(')').expect("wrapSetter call");
        if let Some(q) = after[..end].rfind('"') {
            let before = &after[..q];
            let start = before.rfind('"').expect("wrapSetter sink literal");
            js_sinks.push(&before[start + 1..]);
        }
        rest = &after[end..];
    }
    js_sinks.sort_unstable();
    js_sinks.dedup();
    // Three wrapper groups build sink names at runtime
    // (element.setAttribute.<name>, history.<method>, jQuery.<method>):
    // the extraction sees only the literal prefix.
    let (mut js_dyn, mut js_lit): (Vec<&str>, Vec<&str>) =
        js_sinks.into_iter().partition(|s| s.ends_with('.'));
    js_dyn.sort_unstable();
    js_dyn.dedup();
    assert_eq!(
        js_dyn,
        ["element.setAttribute.", "history.", "jQuery."],
        "dynamic sink-name prefixes"
    );
    js_lit.sort_unstable();
    js_lit.dedup();
    // Literal record calls that share a dynamic prefix (the jQuery block
    // wraps a few methods explicitly) are covered by the prefix wrapper.
    js_lit.retain(|s| !js_dyn.iter().any(|p| s.starts_with(p)));
    let mut expected: Vec<&str> = rust
        .iter()
        .copied()
        .filter(|s| !js_dyn.iter().any(|p| s.starts_with(p)))
        .collect();
    expected.extend(["storage.setItem.name", "storage.setItem.value"]);
    expected.sort_unstable();
    assert_eq!(js_lit, expected, "instrumentation vs family sink drift");
}

/// Every declared family sink is actually wrapped somewhere in the
/// instrumentation source (the literal-name convention above).
#[test]
fn dom_family_sinks_are_wrapped() {
    let dynamic = ["element.setAttribute.", "history.", "jQuery."];
    for (family, sinks) in [
        ("xss", DOM_XSS_SINKS),
        ("js-injection", DOM_JS_INJECTION_SINKS),
        ("open-redirection", DOM_OPEN_REDIRECTION_SINKS),
        ("data-manipulation", DOM_DATA_MANIPULATION_SINKS),
        ("link-manipulation", DOM_LINK_MANIPULATION_SINKS),
        ("websocket-poisoning", DOM_WEBSOCKET_POISONING_SINKS),
        ("dos", DOM_DOS_SINKS),
        ("ajax-header", DOM_AJAX_HEADER_SINKS),
        ("storage", DOM_STORAGE_MANIPULATION_SINKS),
        ("json", DOM_JSON_INJECTION_SINKS),
        ("xpath", DOM_XPATH_INJECTION_SINKS),
        ("document-domain", DOM_DOCUMENT_DOMAIN_SINKS),
        ("cookie", DOM_COOKIE_MANIPULATION_SINKS),
        ("web-message", DOM_WEB_MESSAGE_SINKS),
        ("prototype-pollution", DOM_PROTOTYPE_POLLUTION_SINKS),
    ] {
        for sink in sinks {
            // Dynamic-name sinks are pinned by the prefix assertion in
            // dom_sink_sets_match_the_instrumentation plus the live labs.
            if dynamic.iter().any(|p| sink.starts_with(p)) {
                continue;
            }
            let js = crate::crawl::DOM_INSTRUMENT_JS;
            assert!(
                js.contains(&format!("record(\"{sink}\"")) || js.contains(&format!("\"{sink}\")")),
                "{family} sink {sink} not wrapped"
            );
        }
    }
}

/// Token drift: the instrumentation keeps both token placeholders and
/// the provenance labels the Rust side reasons about, and
/// dom_instrument_js substitutes them distinctly.
#[test]
fn dom_probe_tokens_are_distinct_and_substituted() {
    let js = crate::crawl::DOM_INSTRUMENT_JS;
    for needle in [
        "%CANARY%",
        "%CANARY2%",
        "location.hash",
        "location.search",
        "location.hash+location.search",
        "unknown",
    ] {
        assert!(js.contains(needle), "instrumentation lost {needle}");
    }
    let out = crate::crawl::dom_instrument_js(
        "http://h/p?__proto__[wpSs]=wpSs",
        "__proto__[wpHh]=wpHh",
        "",
    );
    assert!(!out.contains("%CANARY%") && !out.contains("%CANARY2%"));
    assert!(out.contains("wpSs") && out.contains("wpHh"));
    // A probe URL without a query payload falls back to one token, which
    // the instrumentation reads as unattributable provenance.
    let legacy = crate::crawl::dom_instrument_js("http://h/p", "wpT0k", "");
    assert!(
        legacy.contains("var QTOKEN = \"wpT0k\";") && legacy.contains("var CANARY = \"wpT0k\";")
    );
}

#[test]
fn dom_cancelled_dispatch_preserves_cross_family_cached_findings_without_egress() {
    use std::sync::atomic::Ordering;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let shared = crate::net::Shared::new();
    let raw = format!("GET /cached HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let baseline =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>void 0</script>".to_vec();
    let cx = ScanCtx {
        shared: shared.clone(),
        entry: HistEntry {
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            path: "/cached".into(),
            ..Default::default()
        },
        req: raw.clone(),
        parts: util::parse_http(raw.as_bytes()),
        host: "127.0.0.1".into(),
        port,
        host_hdr: format!("127.0.0.1:{port}"),
        settings: Settings {
            speed: ScanSpeed::from_u8(0),
            accuracy: crate::variations::Accuracy::from_u8(0),
        },
        baseline: Baseline {
            resp: Some(baseline.clone()),
            raw: baseline,
            body: "<script>void 0</script>".into(),
        },
        oob: vec![],
        smtp: vec![],
        item: 0,
        stored_report: false,
    };
    let url = format!("http://127.0.0.1:{port}/cached");
    let hits = ["document.write", "document.cookie"]
        .into_iter()
        .map(|sink| crate::crawl::DomHit {
            source: "location.hash".into(),
            sink: sink.into(),
            source_value: "proven".into(),
            sink_value: "proven".into(),
            page_url: url.clone(),
        })
        .collect::<Vec<_>>();
    // Deterministic production merge sequence: confirmed snapshot, a shorter
    // successful snapshot, then an empty successful evaluation, then stop.
    let mut retained = Vec::new();
    let origin = crate::crawl::origin_of(&url).unwrap();
    crate::crawl::dom_merge_confirmed_hits(
        &mut retained,
        hits.clone(),
        &origin,
        "proven",
        "query",
        "stored",
    );
    crate::crawl::dom_merge_confirmed_hits(
        &mut retained,
        [hits[0].clone()],
        &origin,
        "proven",
        "query",
        "stored",
    );
    crate::crawl::dom_merge_confirmed_hits(
        &mut retained,
        Vec::new(),
        &origin,
        "proven",
        "query",
        "stored",
    );
    assert_eq!(retained.len(), 2);
    let outcome = webprobe_support::dedup::DomProbeOutcome {
        hits: retained,
        reflected: None,
        stored: "stored".into(),
        complete: false,
        cancelled: true,
        diagnostic: "cancelled after confirmed snapshot".into(),
    };
    let cell = std::sync::OnceLock::new();
    cell.set(outcome).unwrap();
    cx.state()
        .dom_hits
        .lock()
        .unwrap()
        .insert(url.clone(), std::sync::Arc::new(cell));
    shared.scan.record_dom(crate::scan_run::DomScanRecord {
        url,
        complete: false,
        cancelled: true,
        proven_hits: hits,
        diagnostic: "cancelled".into(),
    });
    let mut config = crate::scan_config::ScanConfig::default();
    for (id, ..) in crate::scan::check_catalogue() {
        if !["active.dom-xss", "active.dom-cookie-manipulation"].contains(&id) {
            config.disabled_checks.insert(id.into());
        }
    }
    *crate::scan_config::shared_config(&shared).lock().unwrap() = config;
    shared.scan.stop.store(true, Ordering::SeqCst);
    run_request_checks(&cx);
    let issues = shared.issues.lock().unwrap();
    for name in [
        "Cross-site scripting (DOM-based)",
        "Cookie manipulation (DOM-based)",
    ] {
        assert!(
            issues
                .iter()
                .any(|i| i.name == name && i.detail.contains("incomplete")),
            "missing {name}"
        );
    }
    assert_eq!(
        shared.scan.dom_outcomes.lock().unwrap()[0]
            .proven_hits
            .len(),
        2
    );
    assert!(
        listener.accept().is_err(),
        "cache-only dispatch must not send"
    );
    cx.state().dom_hits.lock().unwrap().clear();
    assert!(dom_analysis_hits(&cx).hits.is_empty());
    assert!(
        cx.state().dom_hits.lock().unwrap().is_empty(),
        "stopped cache miss must not initialize a cell"
    );
    assert!(listener.accept().is_err());
}

#[test]
fn dom_cancelled_dispatch_preserves_pollution_and_other_families_without_egress() {
    use std::sync::atomic::Ordering;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let shared = crate::net::Shared::new();
    let raw = format!("GET /cached HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let baseline =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>void 0</script>".to_vec();
    let cx = ScanCtx {
        shared: shared.clone(),
        entry: HistEntry {
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            path: "/cached".into(),
            ..Default::default()
        },
        req: raw.clone(),
        parts: util::parse_http(raw.as_bytes()),
        host: "127.0.0.1".into(),
        port,
        host_hdr: format!("127.0.0.1:{port}"),
        settings: Settings {
            speed: ScanSpeed::from_u8(0),
            accuracy: crate::variations::Accuracy::from_u8(0),
        },
        baseline: Baseline {
            resp: Some(baseline.clone()),
            raw: baseline,
            body: "<script>void 0</script>".into(),
        },
        oob: vec![],
        smtp: vec![],
        item: 0,
        stored_report: false,
    };
    let url = format!("http://127.0.0.1:{port}/cached");
    let hits = ["document.write", "document.cookie", "Object.prototype"]
        .into_iter()
        .map(|sink| crate::crawl::DomHit {
            source: "location.hash".into(),
            sink: sink.into(),
            source_value: "proven".into(),
            sink_value: "proven".into(),
            page_url: url.clone(),
        })
        .collect::<Vec<_>>();
    let outcome = webprobe_support::dedup::DomProbeOutcome {
        hits: hits.clone(),
        reflected: None,
        stored: "stored".into(),
        complete: false,
        cancelled: true,
        diagnostic: "cancelled after confirmed snapshot".into(),
    };
    let cell = std::sync::OnceLock::new();
    cell.set(outcome).unwrap();
    cx.state()
        .dom_hits
        .lock()
        .unwrap()
        .insert(url.clone(), std::sync::Arc::new(cell));
    shared.scan.record_dom(crate::scan_run::DomScanRecord {
        url,
        complete: false,
        cancelled: true,
        proven_hits: hits,
        diagnostic: "cancelled".into(),
    });
    let mut config = crate::scan_config::ScanConfig::default();
    for (id, ..) in crate::scan::check_catalogue() {
        if ![
            "active.dom-xss",
            "active.dom-cookie-manipulation",
            "active.dom-prototype-pollution",
        ]
        .contains(&id)
        {
            config.disabled_checks.insert(id.into());
        }
    }
    *crate::scan_config::shared_config(&shared).lock().unwrap() = config;
    shared.scan.stop.store(true, Ordering::SeqCst);
    run_request_checks(&cx);
    let issues = shared.issues.lock().unwrap();
    for name in [
        "Cross-site scripting (DOM-based)",
        "Cookie manipulation (DOM-based)",
        "Client-side prototype pollution",
    ] {
        assert!(
            issues
                .iter()
                .any(|i| i.name == name && i.detail.contains("incomplete")),
            "missing {name}"
        );
    }
    assert_eq!(
        shared.scan.dom_outcomes.lock().unwrap()[0]
            .proven_hits
            .len(),
        3
    );
    assert!(
        listener.accept().is_err(),
        "cache-only dispatch must not send"
    );
    cx.state().dom_hits.lock().unwrap().clear();
    assert!(dom_analysis_hits(&cx).hits.is_empty());
    assert!(
        cx.state().dom_hits.lock().unwrap().is_empty(),
        "stopped cache miss must not initialize a cell"
    );
    assert!(listener.accept().is_err());
}

#[test]
fn dom_first_cancel_barrier_blocks_later_cors_direct_and_proxy() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};
    for proxy in [false, true] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let shared = crate::net::Shared::new();
        if proxy {
            *shared.upstream.lock().unwrap() = crate::upstream::UpstreamConfig {
                kind: crate::upstream::UpstreamKind::Http,
                host: "127.0.0.1".into(),
                port: port.to_string(),
                ..Default::default()
            };
        }
        let raw = format!("GET /cached HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let baseline =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>void 0</script>".to_vec();
        let cx = ScanCtx {
            shared: shared.clone(),
            entry: HistEntry {
                method: "GET".into(),
                host: "127.0.0.1".into(),
                port,
                path: "/cached".into(),
                ..Default::default()
            },
            req: raw.clone(),
            parts: util::parse_http(raw.as_bytes()),
            host: "127.0.0.1".into(),
            port,
            host_hdr: format!("127.0.0.1:{port}"),
            settings: Settings {
                speed: ScanSpeed::from_u8(0),
                accuracy: crate::variations::Accuracy::from_u8(0),
            },
            baseline: Baseline {
                resp: Some(baseline.clone()),
                raw: baseline,
                body: "<script>void 0</script>".into(),
            },
            oob: vec![],
            smtp: vec![],
            item: 0,
            stored_report: false,
        };
        let url = format!("http://127.0.0.1:{port}/cached");

        let captured = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let capture = captured.clone();
        let server = std::thread::spawn(move || {
            while capture.lock().unwrap().len() < 2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut b = [0; 4096];
                while let Ok(n) = stream.read(&mut b) {
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&b[..n]);
                    if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                if bytes.is_empty() {
                    continue;
                }
                capture
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&bytes).into_owned());
                let body="<html><head><link rel='icon' href='data:,'></head><script>document.write(location.hash);document.cookie='x='+location.hash;</script></html>";
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
            listener
        });
        let observed = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        shared.tool_state.insert(crate::crawl::DomSnapshotBarrier {
            observed: observed.clone(),
            resume: resume.clone(),
            used: Arc::new(AtomicBool::new(false)),
        });
        let stop = shared.clone();
        let controller = std::thread::spawn(move || {
            observed.wait();
            stop.scan.stop.store(true, Ordering::SeqCst);
            resume.wait();
        });
        let mut config = crate::scan_config::ScanConfig::default();
        for (id, ..) in crate::scan::check_catalogue() {
            if ![
                "active.dom-xss",
                "active.dom-cookie-manipulation",
                "active.cors",
            ]
            .contains(&id)
            {
                config.disabled_checks.insert(id.into());
            }
        }
        *crate::scan_config::shared_config(&shared).lock().unwrap() = config;
        run_request_checks(&cx);
        controller.join().unwrap();
        let listener = server.join().unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = captured.lock().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "submission + navigation only: {requests:?}"
        );
        assert!(
            !requests
                .iter()
                .any(|r| r.to_ascii_lowercase().contains("\r\norigin:")),
            "no CORS after cancellation"
        );
        while let Ok((mut stream, _)) = listener.accept() {
            stream.set_nonblocking(true).unwrap();
            let mut b = [0; 1];
            assert_ne!(
                stream.read(&mut b).unwrap_or(0),
                1,
                "new post-stop wire request"
            );
        }
        let issues = shared.issues.lock().unwrap();
        for name in [
            "Cross-site scripting (DOM-based)",
            "Cookie manipulation (DOM-based)",
        ] {
            assert!(
                issues
                    .iter()
                    .any(|i| i.name == name && i.detail.contains("incomplete")),
                "missing {name}"
            );
        }
        assert!(shared
            .scan
            .dom_outcomes
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.cancelled && !r.complete && r.proven_hits.len() >= 2));
        assert!(
            cx.state()
                .dom_hits
                .lock()
                .unwrap()
                .get(&url)
                .unwrap()
                .get()
                .unwrap()
                .cancelled
        );
        // Explicit bypass paths also deny a fresh send after stop.
        assert!(burp_send(&cx, b"GET /bypass HTTP/1.1\r\nHost: h\r\n\r\n").is_none());
        assert!(cx
            .send(b"GET /context HTTP/1.1\r\nHost: h\r\n\r\n")
            .is_none());
        assert!(listener.accept().is_err());
    }
}
