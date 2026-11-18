// Passive checks (R-04): one registered unit per check, like the active
// registries (`checks::POINT_CHECKS` / `REQUEST_CHECKS`). Each unit has a
// stable id (scan configuration, catalogue), the issue it reports and a run
// function over one request/response pair. The units of the former
// `scan::passive_issues` keep their code and their order, so a response
// raises the same issues as before; Burp ports added in R-04 follow them.
//
// The checks that have no Burp issue type (the 18 WebProbe-only ones) are
// registered too and stay hidden unless "WebProbe extra checks" is on
// (`scan::add_passive_issues`).

use super::*;

/// One response being checked, with what every unit needs computed once.
pub(crate) struct PassiveCtx<'a> {
    pub e: &'a HistEntry,
    pub resp: &'a [u8],
    pub p: util::HttpParts,
    pub req: util::HttpParts,
    pub ok_status: bool,
    pub ct: String,
    /// The first [`MAX_BODY_SCAN`] bytes of the body.
    pub body: &'a [u8],
    pub binary: bool,
    pub html: bool,
    pub text: String,
    pub low: String,
}

impl<'a> PassiveCtx<'a> {
    fn new(e: &'a HistEntry, resp: &'a [u8]) -> Self {
        let p = util::parse_http(resp);
        let req = util::parse_http(&e.req_raw);
        let ok_status = p.status.starts_with('2') || p.status.starts_with('3');
        let ct = util::get_header(&p.headers, "Content-Type").unwrap_or_default();
        let body = body_slice(resp, p.head_len);
        let binary = is_binary(&ct, body);
        let html = is_document(&ct) && !binary;
        let text = if binary { String::new() } else { String::from_utf8_lossy(body).into_owned() };
        let low = text.to_ascii_lowercase();
        PassiveCtx { e, resp, p, req, ok_status, ct, body, binary, html, text, low }
    }
}

/// A registered passive check.
pub(crate) struct PassiveCheck {
    /// Stable id (scan configuration, catalogue, tests).
    pub id: &'static str,
    /// The issue it reports (Burp's KnowledgeBase name where it is a Burp
    /// port; the units that report several names give the family).
    pub issue: &'static str,
    pub run: fn(&PassiveCtx, &mut Vec<ScanIssue>),
}

macro_rules! unit {
    ($c:expr, $run:expr) => {
        PassiveCheck { id: $c.id, issue: $c.name, run: $run }
    };
}

/// Every passive check, in run (and report) order.
pub(crate) static PASSIVE_CHECKS: &[PassiveCheck] = &[
    unit!(CH_CSRF, csrf_form_token),
    unit!(CH_CT_MISSING, |cx, v| mime(cx, v, CH_CT_MISSING)),
    unit!(CH_CT_MULTI, |cx, v| mime(cx, v, CH_CT_MULTI)),
    unit!(CH_HTML_NO_CHARSET, |cx, v| mime(cx, v, CH_HTML_NO_CHARSET)),
    unit!(CH_HTML_BAD_CHARSET, |cx, v| mime(cx, v, CH_HTML_BAD_CHARSET)),
    unit!(CH_OPENAPI_PASSIVE, openapi),
    unit!(CH_CLEARTEXT, unencrypted),
    unit!(CH_FRAME, frameable),
    unit!(CH_HSTS, hsts),
    unit!(CH_CSP, csp_missing),
    unit!(CH_XCTO, xcto),
    unit!(CH_REFERRER, referrer_policy),
    unit!(CH_PERMISSIONS, permissions_policy),
    unit!(CH_SERVER, server_version),
    unit!(CH_XPB, x_powered_by),
    unit!(CH_ASPNET, aspnet_version),
    unit!(CH_COOKIE_SECURE, |cx, v| cookie_flags(cx, v, CH_COOKIE_SECURE)),
    unit!(CH_COOKIE_HTTPONLY, |cx, v| cookie_flags(cx, v, CH_COOKIE_HTTPONLY)),
    unit!(CH_COOKIE_SAMESITE, |cx, v| cookie_flags(cx, v, CH_COOKIE_SAMESITE)),
    unit!(CH_COOKIE_SAMESITE_NONE, |cx, v| cookie_flags(cx, v, CH_COOKIE_SAMESITE_NONE)),
    unit!(CH_CORS_WILDCARD_CREDS, |cx, v| cors(cx, v, CH_CORS_WILDCARD_CREDS)),
    unit!(CH_CORS_WILDCARD, |cx, v| cors(cx, v, CH_CORS_WILDCARD)),
    unit!(CH_CORS_NULL, |cx, v| cors(cx, v, CH_CORS_NULL)),
    unit!(CH_CORS_CREDS, |cx, v| cors(cx, v, CH_CORS_CREDS)),
    unit!(CH_CORS_REFLECT, |cx, v| cors(cx, v, CH_CORS_REFLECT)),
    unit!(CH_REDIRECT_COOKIE, redirect_cookie),
    unit!(CH_CACHE, cacheable_https),
    PassiveCheck { id: "passive.error-signatures", issue: "Error message or stack trace in response (WebProbe)", run: error_signatures },
    PassiveCheck { id: "passive.html-comment-secrets", issue: "Secret reference in HTML comment (WebProbe)", run: comment_secrets },
    unit!(CH_GIT, git_exposed),
    unit!(CH_ENV, env_exposed),
    unit!(CH_DIR_LISTING, directory_listing),
    unit!(CH_ROBOTS, robots),
    unit!(CH_EMAIL, |cx, v| disclosure(cx, v, CH_EMAIL)),
    unit!(CH_PRIVATE_IP, |cx, v| disclosure(cx, v, CH_PRIVATE_IP)),
    unit!(CH_CREDIT_CARD, |cx, v| disclosure(cx, v, CH_CREDIT_CARD)),
    unit!(CH_MIXED, mixed_content),
    unit!(CH_LOGIN_HTTP, cleartext_password),
    unit!(CH_AUTOCOMPLETE, password_autocomplete),
    // R-04: Burp ports.
    unit!(crate::scan::csp::CSP_NOT_ENFORCED, crate::scan::csp::run_not_enforced),
    unit!(crate::scan::csp::CSP_UNTRUSTED_SCRIPTS, crate::scan::csp::run_untrusted_scripts),
    unit!(crate::scan::csp::CSP_UNTRUSTED_STYLES, crate::scan::csp::run_untrusted_styles),
    unit!(crate::scan::csp::CSP_ALLOWLISTED_SCRIPTS, crate::scan::csp::run_allowlisted_scripts),
    unit!(crate::scan::csp::CSP_CLICKJACKING, crate::scan::csp::run_clickjacking),
    unit!(crate::scan::csp::CSP_FORM_HIJACKING, crate::scan::csp::run_form_hijacking),
    unit!(crate::scan::csp::CSP_MALFORMED, crate::scan::csp::run_malformed),
    unit!(CH_PASSWORD_GET, password_get),
    unit!(CH_PRIVATE_KEY, private_key),
    unit!(CH_SSN, ssn),
    unit!(crate::scan::retirejs::CH_VULNERABLE_JS, crate::scan::retirejs::run),
];

/// Run every check `enabled` lets through on one exchange.
pub(crate) fn run_passive(e: &HistEntry, enabled: &dyn Fn(&str) -> bool) -> Vec<ScanIssue> {
    let mut v: Vec<ScanIssue> = Vec::new();
    let Some(resp) = &e.resp_raw else { return v };
    let cx = PassiveCtx::new(e, resp);
    for c in PASSIVE_CHECKS {
        if enabled(c.id) {
            (c.run)(&cx, &mut v);
        }
    }
    v
}

// ---------------------------------------------------------------- units

/// burp.Zgo1 (PASSWORD_SUBMITTED_USING_GET_METHOD): Certain, Low (Zrh
/// bytes 3 / 2).
pub(crate) const CH_PASSWORD_GET: CheckDef = CheckDef { id: "passive.password-get", name: "Password submitted using GET method", sev: "low", confidence: "Certain" };

/// One form of an HTML page: method, action, and its named password fields.
struct Form {
    method_get: bool,
    action: String,
    passwords: Vec<String>,
}

/// The value of attribute `name` in a lowercase start tag `low_tag`, read
/// from the same span of the original-case `tag`.
pub(crate) fn attr(low_tag: &str, tag: &str, name: &str) -> Option<String> {
    let mut from = 0;
    while let Some(i) = low_tag[from..].find(name) {
        let at = from + i;
        let before_ok = at == 0 || low_tag.as_bytes()[at - 1].is_ascii_whitespace();
        let rest_low = low_tag[at + name.len()..].trim_start();
        if before_ok && rest_low.starts_with('=') {
            let start = low_tag.len() - rest_low.len() + 1;
            let rest = tag[start..].trim_start();
            let q = rest.chars().next()?;
            return Some(if q == '"' || q == '\'' {
                rest[1..].find(q).map(|e| rest[1..1 + e].to_string()).unwrap_or_else(|| rest[1..].to_string())
            } else {
                rest.split(|c: char| c.is_whitespace() || c == '>').next().unwrap_or("").to_string()
            });
        }
        from = at + name.len();
    }
    None
}

/// The forms of a page (burp.Zem): a form runs to its `</form>` (or the
/// next form); its inputs of type password with a name are its password
/// fields (burp.Zxro.Zt: Zbmj.PASSWORD with a name). No method means GET.
fn forms(text: &str, low: &str) -> Vec<Form> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(off) = low[i..].find("<form") {
        let start = i + off;
        let tag_end = low[start..].find('>').map(|e| start + e + 1).unwrap_or(low.len());
        let next_form = low[tag_end..].find("<form").map(|e| tag_end + e).unwrap_or(low.len());
        let end = low[tag_end..].find("</form").map(|e| tag_end + e).unwrap_or(low.len()).min(next_form);
        let (low_tag, tag) = (&low[start..tag_end], &text[start..tag_end]);
        let method_get = attr(low_tag, tag, "method").is_none_or(|m| m.trim().eq_ignore_ascii_case("get"));
        let action = attr(low_tag, tag, "action").unwrap_or_default();
        let mut passwords = Vec::new();
        let (body_low, body) = (&low[tag_end..end], &text[tag_end..end]);
        let mut j = 0;
        while let Some(o) = body_low[j..].find("<input") {
            let s = j + o;
            let e = body_low[s..].find('>').map(|x| s + x + 1).unwrap_or(body_low.len());
            let (lt, t) = (&body_low[s..e], &body[s..e]);
            if attr(lt, t, "type").is_some_and(|ty| ty.trim().eq_ignore_ascii_case("password")) {
                if let Some(n) = attr(lt, t, "name") {
                    passwords.push(n);
                }
            }
            j = e;
        }
        out.push(Form { method_get, action, passwords });
        i = end.max(tag_end);
    }
    out
}

/// The page's URL and a form action resolved against it.
pub(crate) fn page_url(e: &HistEntry) -> String {
    let scheme = if e.https { "https" } else { "http" };
    let default = if e.https { 443 } else { 80 };
    let host = if e.port == default || e.port == 0 { e.host.clone() } else { format!("{}:{}", e.host, e.port) };
    if e.path.contains("://") {
        e.path.clone()
    } else {
        format!("{scheme}://{host}{}", e.path)
    }
}

fn resolve(base: &str, action: &str) -> String {
    let a = action.trim();
    if a.is_empty() {
        return base.to_string();
    }
    if a.contains("://") {
        return a.to_string();
    }
    let (origin, path) = match base.split_once("://").and_then(|(s, r)| r.find('/').map(|i| (format!("{s}://{}", &r[..i]), &r[i..]))) {
        Some((o, p)) => (o, p.to_string()),
        None => (base.to_string(), "/".to_string()),
    };
    if let Some(rest) = a.strip_prefix("//") {
        let scheme = base.split("://").next().unwrap_or("http");
        return format!("{scheme}://{rest}");
    }
    if a.starts_with('/') {
        return format!("{origin}{a}");
    }
    let path = path.split(['?', '#']).next().unwrap_or("/");
    let dir = &path[..path.rfind('/').map(|i| i + 1).unwrap_or(0)];
    format!("{origin}{}{a}", if dir.is_empty() { "/" } else { dir })
}

/// burp.Zum_ (PRIVATE_KEY_DISCLOSED): Certain, Info.
pub(crate) const CH_PRIVATE_KEY: CheckDef = CheckDef { id: "passive.private-key-disclosed", name: "Private key disclosed", sev: "info", confidence: "Certain" };
/// burp.Zcuc (SOCIAL_SECURITY_NUMBERS_DISCLOSED): Tentative, Info.
pub(crate) const CH_SSN: CheckDef = CheckDef { id: "passive.ssn-disclosed", name: "Social security numbers disclosed", sev: "info", confidence: "Tentative" };

/// Case-insensitive search for lowercase `needle` in `hay[from..to]`.
fn find_ci(hay: &[u8], needle: &[u8], from: usize, to: usize) -> Option<usize> {
    let to = to.min(hay.len());
    if from >= to || to - from < needle.len() {
        return None;
    }
    (from..=to - needle.len()).find(|&i| hay[i..i + needle.len()].iter().zip(needle).all(|(a, b)| a.to_ascii_lowercase() == *b))
}

/// burp.Zsdw.ZT: the words of a marker in order, the first anywhere from
/// `from`, each next one starting within 20 + its length of the previous
/// one's start. Returns (start of the first word, end of the last).
fn pem_marker(hay: &[u8], words: &[&[u8]], from: usize) -> Option<(usize, usize)> {
    let first = find_ci(hay, words[0], from, hay.len())?;
    let mut at = first;
    for w in &words[1..] {
        at = find_ci(hay, w, at, at + 20 + w.len())?;
    }
    Some((first, at + words[words.len() - 1].len()))
}

/// burp.Zhj.ZU: `hay[a..b]` is all base64 characters, with `=` only in the
/// last two places.
fn base64_run(hay: &[u8], a: usize, b: usize) -> bool {
    (a..b).all(|i| {
        let c = hay[i];
        !(c == b'=' && i + 2 < b) && (c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
    })
}

/// burp.Zsdw.Zd + ZU: the base64 runs longer than 20 between the markers
/// add up to at least 200 characters.
fn pem_body(hay: &[u8], mut a: usize, b: usize) -> bool {
    while a < b && !(hay[a].is_ascii_alphabetic() || hay[a] == b'/' || hay[a] == b'+') {
        a += 1;
    }
    let mut total = 0;
    while a < b {
        let mut z = a;
        loop {
            z += 1;
            if !(z < b && base64_run(hay, a, z)) {
                break;
            }
        }
        if z - a > 20 {
            total += z - 1 - a;
        }
        a = z;
    }
    total >= 200
}

/// Private key disclosed (burp.Zsdw.ZS, text burp.Zwuv): a BEGIN … PRIVATE
/// … KEY marker, then an END … PRIVATE … KEY marker, with at least 200
/// base64 characters between them. Burp stops at the first marker it
/// cannot complete.
fn private_key(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let hay = &cx.resp[..cx.resp.len().min(cx.p.head_len + MAX_BODY_SCAN)];
    let mut at = 0;
    let mut found = false;
    while at < hay.len() {
        let Some((_, begin_end)) = pem_marker(hay, &[b"begin", b"private", b"key"], at) else { break };
        let Some((end_start, end_end)) = pem_marker(hay, &[b"end", b"private", b"key"], begin_end) else { break };
        found |= pem_body(hay, begin_end, end_start);
        at = end_end;
    }
    if found {
        v.push(mk_check(CH_PRIVATE_KEY, cx.e, "The response appears to contain a cryptographic private key."));
    }
}

/// burp.Zi9q.Zx: social security numbers `ddd-dd-dddd` (or with spaces),
/// starting after a non-alphanumeric character, not followed by one, the
/// two separators equal, not part of a longer separated chain, area 1..899
/// but not 666, group and serial not zero, and not the 078-05-1120 sample.
fn find_ssns(b: &[u8]) -> Vec<String> {
    let n = b.len();
    let digit = |i: usize| i < n && b[i].is_ascii_digit();
    let sep = |i: usize| i < n && (b[i] == b' ' || b[i] == b'-');
    let num = |a: usize, l: usize| std::str::from_utf8(&b[a..a + l]).ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let mut out: Vec<String> = Vec::new();
    let mut boundary = true;
    let mut i = 0;
    while i + 10 < n {
        let c = b[i];
        if boundary && c.is_ascii_digit() {
            // ddd?dd?dddd, the separators at offsets 3 and 6.
            let mut j = i;
            let mut whole = true;
            for k in 1..11 {
                j = i + k;
                if !(if k == 3 || k == 6 { sep(j) } else { digit(j) }) {
                    whole = false;
                    break;
                }
            }
            if whole {
                j = i + 11;
                let s = b[i + 3];
                let ok = (j == n || !b[j].is_ascii_alphanumeric())
                    && b[i + 6] == s
                    && !(i > 2 && b[i - 1] == s && b[i - 2].is_ascii_digit())
                    && !(n > i + 12 && b[i + 11] == s && b[i + 12].is_ascii_digit())
                    && {
                        let (area, group, serial) = (num(i, 3), num(i + 4, 2), num(i + 7, 4));
                        area > 0 && area < 900 && area != 666 && group > 0 && serial > 0 && (area, group, serial) != (78, 5, 1120)
                    };
                if ok {
                    let v = String::from_utf8_lossy(&b[i..j]).into_owned();
                    if !out.contains(&v) {
                        out.push(v);
                    }
                }
            }
            boundary = false;
            i = j;
            continue;
        }
        boundary = !c.is_ascii_alphanumeric();
        i += 1;
    }
    out
}

/// Social security numbers disclosed (burp.Zbdp, text burp.Zwvk): the
/// body is searched. Burp raises one issue per number; here one issue per
/// response lists them all, as the other disclosure checks do.
fn ssn(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let found = find_ssns(cx.body);
    if found.is_empty() {
        return;
    }
    let mut t = String::from("The following social security ");
    t.push_str(if found.len() == 1 { "number was" } else { "numbers were" });
    t.push_str(" disclosed in the response:<ul>");
    for s in &found {
        t.push_str(&format!("<li>{}</li>", util::html_encode(s)));
    }
    t.push_str("</ul>");
    v.push(mk_check(CH_SSN, cx.e, t));
}

/// Password submitted using GET method (burp.Zxro.ZQ, text burp.Zwun): a
/// form with named password fields that submits with GET; one issue per
/// form.
fn password_get(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if !cx.html {
        return;
    }
    let base = page_url(cx.e);
    for f in forms(&cx.text, &cx.low) {
        if !f.method_get || f.passwords.is_empty() {
            continue;
        }
        let mut t = String::from("The page contains a form with the following action URL, which is submitted using the GET method:<ul><li>");
        t.push_str(&util::html_encode(&resolve(&base, &f.action)));
        t.push_str("</li></ul>The form contains the following password ");
        t.push_str(if f.passwords.len() == 1 { "field" } else { "fields" });
        t.push_str(":<ul>");
        let mut seen: Vec<&String> = Vec::new();
        for p in &f.passwords {
            if !seen.contains(&p) {
                seen.push(p);
                t.push_str(&format!("<li>{}</li>", util::html_encode(p)));
            }
        }
        t.push_str("</ul>");
        v.push(mk_check(CH_PASSWORD_GET, cx.e, t));
    }
}

/// CSRF: a password-bearing POST form without an anti-CSRF token field
/// (burp.Zbjf SCANNER_ACTIVE_CHECKS_CSRF; passive variant of the family).
fn csrf_form_token(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let e = cx.e;
    let req_body = String::from_utf8_lossy(body_slice(&e.req_raw, cx.req.head_len.min(e.req_raw.len()))).to_lowercase();
    let method_post = cx.req.first.trim_start().to_ascii_uppercase().starts_with("POST");
    if method_post && req_body.contains("password") {
        let has_token = ["csrf", "token", "nonce", "authenticity"].iter().any(|t| req_body.contains(t));
        if !has_token {
            v.push(mk_check(CH_CSRF, e, "POST body carries a password field but no anti-CSRF token field name (csrf/token/nonce/authenticity)."));
        }
    }
}

/// Content type / charset (burp.Zf9p, PPR_MisstatedMimeType): skipped for
/// redirects; known charsets are Zf9p.ZY (runtime-dumped). One unit per
/// issue, each in mime_issues' own order.
fn mime(cx: &PassiveCtx, v: &mut Vec<ScanIssue>, which: CheckDef) {
    for i in mime_issues(cx.resp).into_iter().filter(|i| i.id == which.id) {
        let mut issue = mk_check(i, cx.e, match i.id {
            "passive.html-no-charset" => "The response states the content type as HTML but does not specify a character set.",
            "passive.html-unrecognized-charset" => "The response specifies a character set that is not a recognized standard one.",
            "passive.content-type-missing" => "The response does not contain a Content-Type header.",
            _ => "The response contains multiple Content-Type statements.",
        });
        issue.confidence = "Certain".into();
        v.push(issue);
    }
}

/// OpenAPI definition found (passive scan check), burp.Zge_.
fn openapi(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let e = cx.e;
    let path = e.path.split_once("://").and_then(|(_, r)| r.find('/').map(|i| r[i..].to_string())).unwrap_or_else(|| e.path.clone());
    if crate::burp_checks::openapi_passive(&path, cx.resp) {
        v.push(mk_check(CH_OPENAPI_PASSIVE, e, "The response contains an OpenAPI definition."));
    }
}

/// Unencrypted communications (Burp KB): the response was served over plain
/// HTTP, so all of it is interceptable. Burp raises this once per host,
/// against the root path.
fn unencrypted(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if !cx.e.https {
        let mut i = mk_check(CH_CLEARTEXT, cx.e, "The site communicates over plain HTTP; traffic can be read or modified in transit.");
        i.path = "/".into();
        v.push(i);
    }
}

/// Frameable response (burp.Zm7y.ZL, issue burp.Zpe_: info / firm): a GET
/// answered with a non-redirect, sniffed-HTML page that carries at least
/// one URL-bearing element (burp.Zeyc) and no X-Frame-Options DENY or
/// SAMEORIGIN. A CSP frame-ancestors policy does not suppress it.
fn frameable(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    let get = cx.req.first.trim_start().to_ascii_uppercase().starts_with("GET ");
    let redirect = cx.p.status.starts_with('3');
    let xfo = util::get_header(&cx.p.headers, "X-Frame-Options").unwrap_or_default();
    let blocked = xfo.trim().eq_ignore_ascii_case("deny") || xfo.trim().eq_ignore_ascii_case("sameorigin");
    if get && !redirect && cx.html && !blocked && !burp_sniff_unknown(cx.resp, cx.p.head_len) && has_url_element(&cx.low) {
        v.push(mk_check(CH_FRAME, cx.e, "The response may be framed by another site (clickjacking risk)."));
    }
}

/// HSTS only means anything over HTTPS.
fn hsts(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.ok_status && cx.e.https && !has_header(&cx.p.headers, "Strict-Transport-Security") {
        v.push(mk_check(CH_HSTS, cx.e, "No HSTS policy on an HTTPS response; downgrade and cookie-stripping attacks stay possible."));
    }
}

fn csp_missing(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.ok_status && cx.html && util::get_header(&cx.p.headers, "Content-Security-Policy").unwrap_or_default().is_empty() {
        v.push(mk_check(CH_CSP, cx.e, "No Content-Security-Policy, so injected scripts are not restricted by a content policy."));
    }
}

fn xcto(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.ok_status && cx.html && !has_header(&cx.p.headers, "X-Content-Type-Options") {
        v.push(mk_check(CH_XCTO, cx.e, "No nosniff directive; browsers may guess the content type."));
    }
}

fn referrer_policy(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.ok_status && cx.html && !has_header(&cx.p.headers, "Referrer-Policy") {
        v.push(mk_check(CH_REFERRER, cx.e, "No Referrer-Policy, so URLs (possibly with tokens) leak in the Referer header."));
    }
}

fn permissions_policy(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.ok_status && cx.html && !has_header(&cx.p.headers, "Permissions-Policy") && !has_header(&cx.p.headers, "Feature-Policy") {
        v.push(mk_check(CH_PERMISSIONS, cx.e, "No Permissions-Policy; powerful browser features are left enabled for embedded content."));
    }
}

fn server_version(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if !(cx.ok_status && cx.html) {
        return;
    }
    if let Some(server) = util::get_header(&cx.p.headers, "Server") {
        let discloses = server.contains('/') || !server.split_whitespace().nth(1).unwrap_or("").is_empty();
        if discloses {
            v.push(mk_check(CH_SERVER, cx.e, format!("Server header: {server}")));
        }
    }
}

fn x_powered_by(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.ok_status && cx.html {
        if let Some(xpb) = util::get_header(&cx.p.headers, "X-Powered-By") {
            v.push(mk_check(CH_XPB, cx.e, format!("X-Powered-By header: {xpb}")));
        }
    }
}

fn aspnet_version(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if !(cx.ok_status && cx.html) {
        return;
    }
    for h in ["X-AspNet-Version", "X-AspNetMvc-Version"] {
        if let Some(val) = util::get_header(&cx.p.headers, h) {
            v.push(mk_check(CH_ASPNET, cx.e, format!("{h} header: {val}")));
        }
    }
}

/// Cookies lacking flags (all Set-Cookie values; repeated headers included);
/// one unit per flag.
fn cookie_flags(cx: &PassiveCtx, v: &mut Vec<ScanIssue>, which: CheckDef) {
    if !cx.ok_status {
        return;
    }
    let e = cx.e;
    for (k, val) in &cx.p.headers {
        if !k.eq_ignore_ascii_case("Set-Cookie") {
            continue;
        }
        let c = parse_cookie(val);
        let secure = has_flag(&c.attrs, "secure");
        let hit = match which.id {
            "passive.cookie-secure-missing" => e.https && !secure,
            "passive.cookie-httponly-missing" => looks_session_cookie(c.name, c.value) && !has_flag(&c.attrs, "httponly"),
            "passive.cookie-samesite-missing" => attr_value(&c.attrs, "samesite").is_none(),
            _ => attr_value(&c.attrs, "samesite") == Some("none") && !secure,
        };
        if hit {
            v.push(mk_check(which, e, val.clone()));
        }
    }
}

/// CORS: compare the response against the Origin that was actually sent.
/// The five outcomes are exclusive; one unit per outcome.
fn cors(cx: &PassiveCtx, v: &mut Vec<ScanIssue>, which: CheckDef) {
    if !cx.ok_status {
        return;
    }
    let p = &cx.p;
    let acao = util::get_header(&p.headers, "Access-Control-Allow-Origin").unwrap_or_default();
    let acac = util::get_header(&p.headers, "Access-Control-Allow-Credentials").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let found: Option<(CheckDef, String)> = if acao == "*" && acac {
        Some((CH_CORS_WILDCARD_CREDS, "Access-Control-Allow-Origin: * with credentials (browsers reject it, but the policy is broken).".into()))
    } else if acao == "*" {
        Some((CH_CORS_WILDCARD, "Access-Control-Allow-Origin: * lets any site read the response.".into()))
    } else if acao.eq_ignore_ascii_case("null") {
        Some((CH_CORS_NULL, "Access-Control-Allow-Origin: null trusts sandboxed/data: origins.".into()))
    } else if let Some(origin) = util::get_header(&cx.req.headers, "Origin") {
        if !acao.is_empty() && acao.eq_ignore_ascii_case(&origin) {
            if acac {
                Some((CH_CORS_CREDS, format!("Access-Control-Allow-Origin reflects {origin} and allows credentials.")))
            } else {
                Some((CH_CORS_REFLECT, format!("Access-Control-Allow-Origin reflects the caller-supplied origin {origin}.")))
            }
        } else {
            None
        }
    } else {
        None
    };
    if let Some((c, detail)) = found {
        if c.id == which.id {
            v.push(mk_check(c, cx.e, detail));
        }
    }
}

/// A redirect that hands a session cookie to a different host.
fn redirect_cookie(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if !(cx.ok_status && cx.p.status.starts_with('3')) {
        return;
    }
    if let Some(loc) = util::get_header(&cx.p.headers, "Location") {
        let same_host = location_host(&loc).map(|h| h == cx.e.host.to_ascii_lowercase()).unwrap_or(true);
        let session_cookie = cx.p.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie")).any(|(_, val)| {
            let c = parse_cookie(val);
            looks_session_cookie(c.name, c.value)
        });
        if !same_host && session_cookie {
            v.push(mk_check(CH_REDIRECT_COOKIE, cx.e, format!("302 to {loc} sets a session cookie that is not scoped to the target host.")));
        }
    }
}

/// Sensitive HTTPS response that a shared cache may store.
fn cacheable_https(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if !(cx.ok_status && cx.e.https) {
        return;
    }
    let cc = util::get_header(&cx.p.headers, "Cache-Control").unwrap_or_default().to_ascii_lowercase();
    let set_cookie = cx.p.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"));
    let low = &cx.low;
    let sensitive = set_cookie || low.contains("\"token\"") || low.contains("password") || low.contains("api_key");
    let cacheable = cc.is_empty() || (cc.contains("public") && !cc.contains("no-store"));
    if sensitive && cacheable {
        v.push(mk_check(CH_CACHE, cx.e, "Sensitive HTTPS response without Cache-Control: no-store/private."));
    }
}

/// Error / stack-trace signatures in the response body (WebProbe's own).
fn error_signatures(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.binary {
        return;
    }
    for (sig, name) in ERROR_SIGNATURES {
        if cx.body.windows(sig.len()).any(|w| w.eq_ignore_ascii_case(sig.as_bytes())) {
            v.push(mk("medium", name, cx.e, format!("Signature matched: {sig}")));
        }
    }
}

/// Secrets in HTML comments (WebProbe's own).
fn comment_secrets(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.binary {
        return;
    }
    let text = &cx.text;
    let mut start = 0;
    while let Some(copen) = text[start..].find("<!--") {
        let cstart = start + copen + 4;
        let Some(cend) = text[cstart..].find("-->") else { break };
        let comment = &text[cstart..cstart + cend];
        for (kw, name) in SECRET_KEYWORDS {
            if comment.to_ascii_lowercase().contains(&kw.to_ascii_lowercase()) {
                v.push(mk("info", name, cx.e, comment.trim().chars().take(120).collect::<String>()));
            }
        }
        start = cstart + cend + 3;
    }
}

fn git_exposed(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.binary || !cx.ok_status {
        return;
    }
    let path = cx.e.path.to_ascii_lowercase();
    if (path.contains("/.git/") || path.ends_with("/.git")) && (cx.text.contains("[core]") || cx.text.contains("ref: refs/")) {
        v.push(mk_check(CH_GIT, cx.e, "Git metadata served by the web root (repository layout and history are exposed)."));
    }
}

fn env_exposed(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.binary || !cx.ok_status {
        return;
    }
    let path = cx.e.path.to_ascii_lowercase();
    let env_path = path.ends_with("/.env") || path.contains("/.env?");
    let t = &cx.text;
    if env_path && (t.contains("APP_KEY=") || t.contains("DB_PASSWORD=") || t.contains("SECRET_KEY=")) {
        v.push(mk_check(CH_ENV, cx.e, "Environment file served by the web root (secrets and credentials are exposed)."));
    }
}

fn directory_listing(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.binary || !cx.ok_status {
        return;
    }
    let low = &cx.low;
    if cx.html && (low.contains("<title>index of") || low.contains("<h1>index of") || low.contains("directory listing for")) {
        v.push(mk_check(CH_DIR_LISTING, cx.e, "The server returns a directory index instead of refusing the request."));
    }
}

fn robots(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if cx.binary || !cx.ok_status {
        return;
    }
    if cx.e.path.to_ascii_lowercase().ends_with("/robots.txt") {
        v.push(mk_check(CH_ROBOTS, cx.e, "robots.txt is reachable; its Disallow entries map the hidden parts of the site."));
    }
}

/// The text the information-disclosure checks search: the body, or only
/// the headers when Burp's sniffer finds the body unknown (burp.Zbz9).
pub(crate) fn disclosure_text(cx: &PassiveCtx) -> Option<String> {
    if cx.binary || cx.text.is_empty() {
        return None;
    }
    if burp_sniff_unknown(cx.resp, cx.p.head_len) {
        Some(String::from_utf8_lossy(&cx.resp[..cx.p.head_len.min(cx.resp.len())]).into_owned())
    } else {
        Some(cx.text.clone())
    }
}

fn disclosure(cx: &PassiveCtx, v: &mut Vec<ScanIssue>, which: CheckDef) {
    let Some(text) = disclosure_text(cx) else { return };
    let e = cx.e;
    match which.id {
        "passive.email-disclosed" => {
            if let Some(addr) = find_email_excluding(&text, &String::from_utf8_lossy(&e.req_raw)) {
                v.push(mk_check(CH_EMAIL, e, format!("Address found in the response: {addr}")));
            }
        }
        "passive.private-ip-disclosed" => {
            if let Some(ip) = find_private_ip(&text) {
                v.push(mk_check(CH_PRIVATE_IP, e, format!("Address found in the response: {ip}")));
            }
        }
        _ => {
            if let Some(card) = find_card(&text) {
                v.push(mk_check(CH_CREDIT_CARD, e, format!("Luhn-valid number found in the response: {card}")));
            }
        }
    }
}

/// Mixed content: an HTTPS document pulling subresources over HTTP.
fn mixed_content(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if !(cx.html && cx.e.https) {
        return;
    }
    let low = &cx.low;
    let mixed = ["script", "iframe", "img", "source", "video", "audio"].iter().flat_map(|t| tags(low, t)).find(|t| t.contains("http://"));
    let mixed_link = tags(low, "link").into_iter().find(|t| t.contains("stylesheet") && t.contains("http://"));
    if let Some(tag) = mixed.or(mixed_link) {
        v.push(mk_check(CH_MIXED, cx.e, format!("HTTPS page loads a subresource over HTTP: {}", tag.trim())));
    }
}

/// Login form posted in clear text.
fn cleartext_password(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if !(cx.html && has_password_input(&cx.low)) {
        return;
    }
    let forms = tags(&cx.low, "form");
    let http_action = forms.iter().find(|t| t.contains("action=\"http://") || t.contains("action='http://"));
    let relative_action = !cx.e.https && forms.iter().any(|t| !t.contains("action=\"http") && !t.contains("action='http"));
    if let Some(tag) = http_action {
        v.push(mk_check(CH_LOGIN_HTTP, cx.e, format!("Password form submits over HTTP: {}", tag.trim())));
    } else if relative_action {
        v.push(mk_check(CH_LOGIN_HTTP, cx.e, "Password form on a plain-HTTP page submits its credentials unencrypted."));
    }
}

/// Password field with autocomplete enabled.
fn password_autocomplete(cx: &PassiveCtx, v: &mut Vec<ScanIssue>) {
    if !(cx.html && has_password_input(&cx.low)) {
        return;
    }
    let weak = tags(&cx.low, "input").into_iter().find(|t| {
        (t.contains("type=\"password\"") || t.contains("type='password'"))
            && !(t.contains("autocomplete=\"off\"") || t.contains("autocomplete='off'") || t.contains("autocomplete=\"new-password\"") || t.contains("autocomplete='new-password'"))
    });
    if let Some(tag) = weak {
        v.push(mk_check(CH_AUTOCOMPLETE, cx.e, tag.trim().to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::csp;
    use crate::scan::retirejs;

    fn ex(path: &str, https: bool, headers: &str, body: &str) -> HistEntry {
        let resp = format!("HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\n\r\n{body}", body.len());
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
            req_raw: format!("GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n").into_bytes().into(),
            resp_raw: Some(resp.into_bytes().into()),
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

    const HTML: &str = "Content-Type: text/html; charset=utf-8\r\n";

    fn page(csp: &str) -> HistEntry {
        ex("/", true, &format!("{HTML}Content-Security-Policy: {csp}\r\n"), "<html><body>hi</body></html>")
    }

    /// The issues one check raises on its own.
    fn only(e: &HistEntry, c: CheckDef) -> Vec<ScanIssue> {
        run_passive(e, &|id| id == c.id)
    }

    const STRICT: &str = "default-src 'none'; script-src 'nonce-abcdefghijklmnopqrstuv'; style-src 'self'; frame-ancestors 'none'; form-action 'self'";

    #[test]
    fn registry_lists_every_passive_unit_once() {
        let cat = crate::scan::check_catalogue();
        for c in PASSIVE_CHECKS {
            assert_eq!(cat.iter().filter(|x| x.0 == c.id).count(), 1, "{}", c.id);
        }
        for id in ["passive.csp-untrusted-scripts", "passive.password-get", "passive.private-key-disclosed", "passive.ssn-disclosed", "passive.vulnerable-js-dependency"] {
            assert!(cat.iter().any(|x| x.0 == id && x.2 == "passive, per response"), "{id}");
        }
        // The Burp ports report KnowledgeBase names, so they are shown by
        // default.
        for c in [csp::CSP_NOT_ENFORCED, csp::CSP_UNTRUSTED_SCRIPTS, csp::CSP_UNTRUSTED_STYLES, csp::CSP_ALLOWLISTED_SCRIPTS, csp::CSP_CLICKJACKING, csp::CSP_FORM_HIJACKING, csp::CSP_MALFORMED, CH_PASSWORD_GET, CH_PRIVATE_KEY, CH_SSN, retirejs::CH_VULNERABLE_JS] {
            assert!(crate::scan::is_burp_issue(c.name), "{}", c.name);
        }
    }

    #[test]
    fn strict_policy_raises_no_csp_issue() {
        let e = page(STRICT);
        let names: Vec<String> = run_passive(&e, &|id| id.starts_with("passive.csp-") && id != "passive.csp-missing").into_iter().map(|i| i.name).collect();
        assert!(names.is_empty(), "{names:?}");
    }

    #[test]
    fn csp_not_enforced() {
        let e = ex("/", true, &format!("{HTML}Content-Security-Policy-Report-Only: {STRICT}\r\n"), "<html></html>");
        let v = only(&e, csp::CSP_NOT_ENFORCED);
        assert_eq!(v.len(), 1);
        assert!(v[0].detail.contains("Content-Security-Policy-Report-Only header"), "{}", v[0].detail);
        assert!(only(&page(STRICT), csp::CSP_NOT_ENFORCED).is_empty());
        // No policy at all: "header not set" covers it, not this issue.
        assert!(only(&ex("/", true, HTML, "<html></html>"), csp::CSP_NOT_ENFORCED).is_empty());
    }

    #[test]
    fn csp_untrusted_scripts() {
        let v = only(&page("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'none'"), csp::CSP_UNTRUSTED_SCRIPTS);
        assert_eq!(v.len(), 1);
        assert!(v[0].detail.contains("unsafe-inline which can allow arbitrary scripts") && v[0].detail.contains("unsafe-eval"), "{}", v[0].detail);
        let v = only(&page("script-src 'nonce-abc'"), csp::CSP_UNTRUSTED_SCRIPTS);
        assert!(v[0].detail.contains("nonce is under 8 characters"), "{}", v[0].detail);
        assert!(only(&page(STRICT), csp::CSP_UNTRUSTED_SCRIPTS).is_empty());
    }

    #[test]
    fn csp_untrusted_styles() {
        let v = only(&page("default-src 'self'; style-src 'unsafe-inline'"), csp::CSP_UNTRUSTED_STYLES);
        assert_eq!(v.len(), 1);
        assert!(v[0].detail.contains("arbitrary styles"), "{}", v[0].detail);
        assert!(only(&page(STRICT), csp::CSP_UNTRUSTED_STYLES).is_empty());
    }

    #[test]
    fn csp_allowlisted_scripts() {
        assert_eq!(only(&page("default-src 'self'; script-src https://cdn.example.net"), csp::CSP_ALLOWLISTED_SCRIPTS).len(), 1);
        assert!(only(&page(STRICT), csp::CSP_ALLOWLISTED_SCRIPTS).is_empty());
        // A global wildcard is the untrusted-scripts issue, not this one.
        assert!(only(&page("script-src *"), csp::CSP_ALLOWLISTED_SCRIPTS).is_empty());
    }

    #[test]
    fn csp_clickjacking() {
        let v = only(&page("default-src 'self'"), csp::CSP_CLICKJACKING);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].confidence, "Certain");
        assert!(v[0].detail.contains("frame-ancestors directive is not present"), "{}", v[0].detail);
        assert!(only(&page(STRICT), csp::CSP_CLICKJACKING).is_empty());
        // X-Frame-Options covers framing.
        let e = ex("/", true, &format!("{HTML}X-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'\r\n"), "<html></html>");
        assert!(only(&e, csp::CSP_CLICKJACKING).is_empty());
    }

    #[test]
    fn csp_form_hijacking() {
        assert_eq!(only(&page("script-src 'self'; frame-ancestors 'none'"), csp::CSP_FORM_HIJACKING).len(), 1);
        // Burp lets default-src stand in for form-action (Zupz.Zw).
        assert!(only(&page("default-src 'self'"), csp::CSP_FORM_HIJACKING).is_empty());
        assert_eq!(only(&page("form-action *"), csp::CSP_FORM_HIJACKING).len(), 1);
        assert!(only(&page(STRICT), csp::CSP_FORM_HIJACKING).is_empty());
    }

    #[test]
    fn csp_malformed() {
        let v = only(&page("default-src 'self'; bogus-directive x"), csp::CSP_MALFORMED);
        assert_eq!(v.len(), 1);
        assert!(v[0].detail.contains("bogus-directive"), "{}", v[0].detail);
        assert!(only(&page(STRICT), csp::CSP_MALFORMED).is_empty());
    }

    #[test]
    fn password_submitted_using_get() {
        let body = "<html><form action=\"/login\"><input type=\"text\" name=\"user\"><input type=\"password\" name=\"pw\"></form></html>";
        let v = only(&ex("/account/", false, HTML, body), CH_PASSWORD_GET);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].detail, "The page contains a form with the following action URL, which is submitted using the GET method:<ul><li>http://example.com/login</li></ul>The form contains the following password field:<ul><li>pw</li></ul>");
        let post = body.replace("<form ", "<form method=\"POST\" ");
        assert!(only(&ex("/account/", false, HTML, &post), CH_PASSWORD_GET).is_empty());
        // A password input without a name is not submitted.
        let unnamed = "<form method=get action=x><input type=password></form>";
        assert!(only(&ex("/", false, HTML, unnamed), CH_PASSWORD_GET).is_empty());
        assert_eq!(resolve("https://h/a/b?q", "c"), "https://h/a/c");
        assert_eq!(resolve("https://h/a/b", "//o/x"), "https://o/x");
    }

    fn pem(kind: &str, lines: usize) -> String {
        let line = "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n";
        format!("<pre>-----BEGIN {kind}-----\n{}-----END {kind}-----</pre>", line.repeat(lines))
    }

    #[test]
    fn private_key_disclosed() {
        let v = only(&ex("/k", true, HTML, &pem("RSA PRIVATE KEY", 4)), CH_PRIVATE_KEY);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].detail, "The response appears to contain a cryptographic private key.");
        assert_eq!((v[0].sev.as_str(), v[0].confidence.as_str()), ("info", "Certain"));
        // Under 200 base64 characters, or not a private key.
        assert!(only(&ex("/k", true, HTML, &pem("RSA PRIVATE KEY", 2)), CH_PRIVATE_KEY).is_empty());
        assert!(only(&ex("/k", true, HTML, &pem("PUBLIC KEY", 4)), CH_PRIVATE_KEY).is_empty());
    }

    #[test]
    fn social_security_numbers_disclosed() {
        let v = only(&ex("/u", true, HTML, "<p>SSN: 123-45-6789, again 123-45-6789; spouse 234 56 7890.</p>"), CH_SSN);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].detail, "The following social security numbers were disclosed in the response:<ul><li>123-45-6789</li><li>234 56 7890</li></ul>");
        for neg in ["078-05-1120", "666-12-3456", "900-12-3456", "123-00-4567", "123-45 6789", "x123-45-6789", "123-45-67890", "99-123-45-6789", "123-45-6789-12"] {
            assert!(only(&ex("/u", true, HTML, &format!("<p>{neg} </p>")), CH_SSN).is_empty(), "{neg}");
        }
    }

    const REPO: &str = r#"{
      "wpfixture": {
        "vulnerabilities": [
          {"below": "1.4.0", "identifiers": {"summary": "XSS in render", "CVE": ["CVE-2099-0001"]}, "info": ["https://example.invalid/a"]},
          {"atOrAbove": "1.2.0", "below": "1.3.5", "identifiers": {"summary": "Prototype pollution"}, "info": ["https://example.invalid/pp", "https://example.invalid/dead"]}
        ],
        "extractors": {
          "func": ["wpfixture.version"],
          "uri": ["/wpfixture/(§§version§§)/wpfixture(\\.min)?\\.js"],
          "filename": ["wpfixture-(§§version§§)(\\.min)?\\.js"],
          "filecontent": ["/\\*! wpfixture v(§§version§§)", "(?<=x)wpfixture"]
        }
      },
      "safelib": {"vulnerabilities": [], "extractors": {"filename": ["safelib-(§§version§§)\\.js"]}}
    }"#;

    fn repo() -> retirejs::Repository {
        retirejs::Repository::parse(REPO, ["https://example.invalid/dead".to_string()].into_iter().collect()).unwrap()
    }

    fn vuln_js(e: &HistEntry) -> Vec<ScanIssue> {
        let resp = e.resp_raw.clone().unwrap();
        let cx = PassiveCtx::new(e, &resp);
        let mut v = Vec::new();
        retirejs::run_with(&repo(), &cx, &mut v);
        v
    }

    const JS: &str = "Content-Type: application/javascript\r\n";

    #[test]
    fn vulnerable_js_dependency_by_url_content_and_script_tag() {
        let r = repo();
        assert_eq!(r.skipped.len(), 1, "the look-behind extractor is reported, not guessed");
        // URL extractor: 1.2.3 has both vulnerabilities.
        let v = vuln_js(&ex("/static/wpfixture/1.2.3/wpfixture.min.js", true, JS, "x"));
        assert_eq!(v.len(), 1);
        let d = &v[0].detail;
        assert!(d.starts_with("<p>We observed a vulnerable JavaScript library.</p>\n<p>We detected <strong>wpfixture</strong> version <strong>1.2.3</strong>, which has the following vulnerabilities:</p>\n<ul>\n<li>\n<a href='https://nvd.nist.gov/vuln/detail/CVE-2099-0001'>CVE-2099-0001</a>: XSS in render<br/>\n</li>\n"), "{d}");
        assert!(d.contains("<li>\nPrototype pollution<br/>\n<a href='https://example.invalid/pp'>https://example.invalid/pp</a><br/>\n</li>\n</ul><br/>\n"), "{d}");
        assert_eq!((v[0].sev.as_str(), v[0].confidence.as_str()), ("low", "Tentative"));
        // Content extractor when the URL says nothing: 1.3.9 has only the
        // first one.
        let v = vuln_js(&ex("/app/bundle.js", true, JS, "/*! wpfixture v1.3.9 */ var a;"));
        assert_eq!(v.len(), 1);
        assert!(v[0].detail.contains("version <strong>1.3.9</strong>, which has the following vulnerability:"), "{}", v[0].detail);
        // HTML page: the script tags' src.
        let v = vuln_js(&ex("/", true, HTML, "<html><script src=\"/js/wpfixture-1.0.0.js\"></script><script src='/js/safelib-0.1.js'></script></html>"));
        assert_eq!(v.len(), 1);
        assert!(v[0].detail.contains("<strong>1.0.0</strong>"));
    }

    #[test]
    fn vulnerable_js_dependency_negative() {
        // Fixed version, a library without vulnerabilities, no scripts.
        assert!(vuln_js(&ex("/static/wpfixture/1.4.0/wpfixture.js", true, JS, "x")).is_empty());
        assert!(vuln_js(&ex("/app/bundle.js", true, JS, "/*! wpfixture v2.0.0 */")).is_empty());
        assert!(vuln_js(&ex("/", true, HTML, "<script src=/js/safelib-0.1.js></script><script>var x</script>")).is_empty());
        // A library without extractors makes the repository invalid.
        assert!(retirejs::Repository::parse(r#"{"x": {"vulnerabilities": [{"below": "1"}]}}"#, Default::default()).is_err());
    }

    /// Each new check stops when the scan configuration switches it off.
    #[test]
    fn switching_a_check_off_stops_it() {
        retirejs::set_repository(repo());
        let shared = crate::net::Shared::new();
        let cases: Vec<(CheckDef, HistEntry)> = vec![
            (csp::CSP_NOT_ENFORCED, ex("/", true, &format!("{HTML}Content-Security-Policy-Report-Only: {STRICT}\r\n"), "<html></html>")),
            (csp::CSP_UNTRUSTED_SCRIPTS, page("script-src 'unsafe-inline'")),
            (csp::CSP_UNTRUSTED_STYLES, page("style-src 'unsafe-inline'")),
            (csp::CSP_ALLOWLISTED_SCRIPTS, page("script-src https://cdn.example.net")),
            (csp::CSP_CLICKJACKING, page("default-src 'self'")),
            (csp::CSP_FORM_HIJACKING, page("script-src 'self'")),
            (csp::CSP_MALFORMED, page("default-src 'self'; bogus-directive x")),
            (CH_PASSWORD_GET, ex("/", false, HTML, "<form><input type=password name=p></form>")),
            (CH_PRIVATE_KEY, ex("/k", true, HTML, &pem("PRIVATE KEY", 4))),
            (CH_SSN, ex("/u", true, HTML, "ssn 123-45-6789 ")),
            (retirejs::CH_VULNERABLE_JS, ex("/static/wpfixture/1.2.3/wpfixture.js", true, JS, "x")),
        ];
        for (c, e) in cases {
            *shared.scan_config.lock().unwrap() = Default::default();
            assert!(crate::scan::passive_check_for(&shared, &e).iter().any(|i| i.name == c.name), "{} on", c.id);
            shared.scan_config.lock().unwrap().disabled_checks.insert(c.id.to_string());
            assert!(!crate::scan::passive_check_for(&shared, &e).iter().any(|i| i.name == c.name), "{} off", c.id);
        }
        assert_eq!(crate::scan::check_note(retirejs::CH_VULNERABLE_JS.id).as_deref().map(|n| n.contains("skipped")), Some(true));
    }

    /// The real repository (`WEBPROBE_RETIREJS`), when given, loads; its
    /// unsupported extractors are listed rather than guessed at.
    #[test]
    fn real_repository_loads_when_given() {
        let Ok(path) = std::env::var("WEBPROBE_RETIREJS") else { return };
        let r = retirejs::Repository::load(std::path::Path::new(&path)).unwrap();
        eprintln!("{} libraries, skipped: {:?}", r.libs_len(), r.skipped);
        assert!(r.libs_len() > 10);
    }
}
