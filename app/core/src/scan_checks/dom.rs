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
];
pub(crate) const DOM_JS_INJECTION_SINKS: &[&str] =
    &["eval", "Function", "setTimeout", "setInterval"];
pub(crate) const DOM_OPEN_REDIRECTION_SINKS: &[&str] = &["window.open"];
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

/// Dynamic DOM analysis, R-13 option (b) (burp.Zel5's runAnalysis shape;
/// the injected script body is not established, so WebProbe's
/// instrumentation is its own): each HTML page is opened once in a
/// headless browser with a canary in location.hash, the wrapped sinks are
/// the families of burp.Zcwh's dynamic decoder (docs/specs/R-13), and a
/// canary reaching a sink is reported under the sink's family. One
/// browser run per URL serves every family check; hits are kept only on
/// the probed origin (the browser's own chrome-error pages run the
/// wrapped sinks too) and merged per sink (burp.Zwf8.identityOf).
/// Skipped when no Chromium is available.
/// Results belong to the current run's ScanDedup. A per-URL OnceLock
/// shares one browser probe across the eight families and concurrent callers.
fn dom_analysis_hits(cx: &ScanCtx) -> Vec<crate::crawl::DomHit> {
    // Only GET history can be navigated faithfully as a browser GET.
    if !matches!(cx.req.split_whitespace().next(), Some("GET")) {
        return Vec::new();
    }
    // Dynamic analysis runs on pages: the baseline must be HTML.
    let rp = util::parse_http(&cx.baseline.raw);
    let ct = util::get_header(&rp.headers, "Content-Type").unwrap_or_default();
    if !ct.to_ascii_lowercase().contains("html") {
        return Vec::new();
    }
    // No dynamic source can run in a page with no script, inline handler
    // or javascript: URL. Avoid launching Chromium for inert HTML.
    static EXECUTABLE_HTML: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    if !EXECUTABLE_HTML
        .get_or_init(|| regex::Regex::new(r"(?i)<script\b|\bon[a-z]+\s*=|javascript:").unwrap())
        .is_match(&cx.baseline.body)
    {
        return Vec::new();
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
        return Vec::new();
    }
    let host = if cx.host.contains(':') {
        format!("[{}]", cx.host)
    } else {
        cx.host.clone()
    };
    let url = format!("{scheme}://{host}{port}{path}");
    let state = cx.state();
    let cell = state
        .dom_hits
        .lock()
        .unwrap()
        .entry(url.clone())
        .or_default()
        .clone();
    cell.get_or_init(|| {
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
        crate::crawl::dom_analysis_probe(
            &cx.shared,
            &probe_url,
            &canary,
            &cx.req,
            &cx.host,
            cx.port,
            cx.entry.https,
        )
        .unwrap_or_default()
        .into_iter()
        .filter(|h| crate::crawl::same_origin(&h.page_url, &origin))
        .collect()
    })
    .clone()
}

/// One DOM family check: the sinks of one burp.Zcwh family, the issue it
/// maps to, and burp.Zwf8's severity/confidence for it.
macro_rules! dom_family_check {
    ($name:ident, $id:literal, $issue:literal, $severity:literal, $confidence:literal, $family:literal, $sinks:expr, $doc:literal) => {
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
            fn run(&self, cx: &ScanCtx) {
                if cx.stopped() || !cx.runs(self.issue()) {
                    return;
                }
                let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
                for hit in dom_analysis_hits(cx).iter().filter(|h| $sinks.contains(&h.sink.as_str())) {
                    if !seen.insert(hit.sink.as_str()) {
                        continue;
                    }
                    let provenance_note = match hit.source.as_str() {
                        "location.hash" => "location.hash",
                        "location.search" => "location.search",
                        "location.hash+location.search" => "location.hash and location.search",
                        _ => "the URL (query or fragment; part not attributable)",
                    };
                    let mut i = mk(
                        $severity,
                        self.issue(),
                        &cx.entry,
                        format!(
                            "The application may be vulnerable to {}. Data is read from <b>{}</b> and passed to <b>{}</b>.<br><br>The source value <b>{}</b> reached the sink as <b>{}</b>.",
                            $family,
                            util::html_encode(provenance_note),
                            util::html_encode(&hit.sink),
                            util::html_encode(&hit.source_value),
                            util::html_encode(&hit.sink_value)
                        ),
                    );
                    // burp.Zwf8's confidence mapping is established for a
                    // location.hash source only. Search-only, mixed or
                    // unattributable provenance is reported conservatively
                    // as Tentative rather than inheriting it.
                    i.confidence = if hit.source == "location.hash" {
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
    "low",
    "Tentative",
    "DOM-based open redirection",
    DOM_OPEN_REDIRECTION_SINKS,
    "Open redirection (DOM-based), KB 00500110, Low: window.open, the only wrappable navigation sink of burp.Zcwh's family - the Location members (href, assign, replace, host, hostname, protocol) are LegacyUnforgeable in Chromium. Confidence Tentative (burp.Zwf8.Zd: every open-redirection variant is Tentative)."
);
dom_family_check!(
    DomStorageManipulation,
    "active.dom-storage-manipulation",
    "HTML5 storage manipulation (DOM-based)",
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
    "low",
    "Firm",
    "DOM-based cookie manipulation",
    DOM_COOKIE_MANIPULATION_SINKS,
    "Cookie manipulation (DOM-based), KB 00500b00, Low: the document.cookie setter (burp.Zcwh's cookie family). Confidence Firm (burp.Zwf8.Zd)."
);

/// The instrumentation's literal sink names must equal the union of the
/// family tables (plus the generic-storage fallback, which no family
/// reports): drift between the JS wrappers and the Rust checks would
/// silently drop or orphan hits.
#[test]
fn dom_sink_sets_match_the_instrumentation() {
    let families: &[&[&str]] = &[
        DOM_XSS_SINKS,
        DOM_JS_INJECTION_SINKS,
        DOM_OPEN_REDIRECTION_SINKS,
        DOM_STORAGE_MANIPULATION_SINKS,
        DOM_JSON_INJECTION_SINKS,
        DOM_XPATH_INJECTION_SINKS,
        DOM_DOCUMENT_DOMAIN_SINKS,
        DOM_COOKIE_MANIPULATION_SINKS,
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
    js_sinks.sort_unstable();
    js_sinks.dedup();
    let mut expected = rust.clone();
    expected.extend(["storage.setItem.name", "storage.setItem.value"]);
    expected.sort_unstable();
    assert_eq!(js_sinks, expected, "instrumentation vs family sink drift");
}

/// Every declared family sink is actually wrapped somewhere in the
/// instrumentation source (the literal-name convention above).
#[test]
fn dom_family_sinks_are_wrapped() {
    for (family, sinks) in [
        ("xss", DOM_XSS_SINKS),
        ("js-injection", DOM_JS_INJECTION_SINKS),
        ("open-redirection", DOM_OPEN_REDIRECTION_SINKS),
        ("storage", DOM_STORAGE_MANIPULATION_SINKS),
        ("json", DOM_JSON_INJECTION_SINKS),
        ("xpath", DOM_XPATH_INJECTION_SINKS),
        ("document-domain", DOM_DOCUMENT_DOMAIN_SINKS),
        ("cookie", DOM_COOKIE_MANIPULATION_SINKS),
    ] {
        for sink in sinks {
            assert!(
                crate::crawl::DOM_INSTRUMENT_JS.contains(&format!("record(\"{sink}\"")),
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
    let out =
        crate::crawl::dom_instrument_js("http://h/p?__proto__[wpSs]=wpSs", "__proto__[wpHh]=wpHh");
    assert!(!out.contains("%CANARY%") && !out.contains("%CANARY2%"));
    assert!(out.contains("wpSs") && out.contains("wpHh"));
    // A probe URL without a query payload falls back to one token, which
    // the instrumentation reads as unattributable provenance.
    let legacy = crate::crawl::dom_instrument_js("http://h/p", "wpT0k");
    assert!(
        legacy.contains("var QTOKEN = \"wpT0k\";") && legacy.contains("var CANARY = \"wpT0k\";")
    );
}
