// Split from scan.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub(crate) where siblings across the split need access.

use super::*;

/// The first three entries are the SQL probes used by the light active scan;
/// the rest are passive stack-trace / error-message signatures.
pub const ERROR_SIGNATURES: [(&str, &str); 12] = [
    ("SQL syntax", "SQL error message in response"),
    ("SQLite3::", "SQLite error message in response"),
    ("ORA-", "Oracle database error message in response"),
    ("PHP Warning", "PHP runtime warning in response"),
    ("System.Exception", "Server exception message in response"),
    ("Stack Trace", "Stack trace disclosed in response"),
    ("Warning: mysql_", "MySQL warning in response"),
    (
        "Traceback (most recent call last)",
        "Python stack trace disclosed in response",
    ),
    ("at java.", "Java stack trace disclosed in response"),
    (
        "goroutine 1 [running]:",
        "Go stack trace disclosed in response",
    ),
    ("Fatal error:", "PHP fatal error disclosed in response"),
    ("Notice: Undefined", "PHP notice disclosed in response"),
];

pub const SECRET_KEYWORDS: [(&str, &str); 6] = [
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
#[derive(Clone, Copy, Debug)]
pub struct CheckDef {
    pub id: &'static str,
    pub name: &'static str,
    pub sev: &'static str,
    /// Burp vocabulary: Certain | Firm | Tentative.
    pub confidence: &'static str,
}

impl CheckDef {
    /// The registry metadata record (AR-10): the same identity a passive
    /// check entry exposes plus its fixed severity and confidence.
    pub fn meta(&self) -> CheckMeta {
        CheckMeta {
            id: self.id,
            issue: self.name,
            severity: Severity::parse(self.sev),
            confidence: Confidence::parse(self.confidence),
        }
    }
}

pub const CH_HSTS: CheckDef = CheckDef {
    id: "passive.hsts-missing",
    name: "Strict transport security not enforced",
    sev: "low",
    confidence: "Certain",
};

pub const CH_CLEARTEXT: CheckDef = CheckDef {
    id: "passive.unencrypted-communications",
    name: "Unencrypted communications",
    sev: "low",
    confidence: "Certain",
};

pub const CH_CSP: CheckDef = CheckDef {
    id: "passive.csp-missing",
    name: "Content security policy (CSP) header not set",
    sev: "low",
    confidence: "Certain",
};

pub const CH_FRAME: CheckDef = CheckDef {
    id: "passive.frame-ancestors-missing",
    name: "Frameable response (potential Clickjacking)",
    sev: "info",
    confidence: "Firm",
};

pub const CH_XCTO: CheckDef = CheckDef {
    id: "passive.x-content-type-options-missing",
    name: "X-Content-Type-Options header missing",
    sev: "low",
    confidence: "Certain",
};

pub const CH_REFERRER: CheckDef = CheckDef {
    id: "passive.referrer-policy-missing",
    name: "Referrer-Policy header not set",
    sev: "low",
    confidence: "Certain",
};

pub const CH_PERMISSIONS: CheckDef = CheckDef {
    id: "passive.permissions-policy-missing",
    name: "Permissions policy header not set",
    sev: "low",
    confidence: "Certain",
};

pub const CH_SERVER: CheckDef = CheckDef {
    id: "passive.server-version",
    name: "Server header discloses version",
    sev: "info",
    confidence: "Firm",
};

pub const CH_XPB: CheckDef = CheckDef {
    id: "passive.x-powered-by",
    name: "X-Powered-By header discloses technology",
    sev: "info",
    confidence: "Firm",
};

pub const CH_ASPNET: CheckDef = CheckDef {
    id: "passive.aspnet-version",
    name: "ASP.NET version disclosure",
    sev: "info",
    confidence: "Certain",
};

pub const CH_COOKIE_HTTPONLY: CheckDef = CheckDef {
    id: "passive.cookie-httponly-missing",
    name: "Cookie without HttpOnly flag set",
    sev: "low",
    confidence: "Firm",
};

pub const CH_COOKIE_SECURE: CheckDef = CheckDef {
    id: "passive.cookie-secure-missing",
    name: "TLS cookie without secure flag set",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_COOKIE_SAMESITE: CheckDef = CheckDef {
    id: "passive.cookie-samesite-missing",
    name: "Cookie without SameSite attribute",
    sev: "low",
    confidence: "Firm",
};

pub const CH_COOKIE_SAMESITE_NONE: CheckDef = CheckDef {
    id: "passive.cookie-samesite-none-insecure",
    name: "SameSite=None cookie without Secure attribute",
    sev: "low",
    confidence: "Firm",
};

pub const CH_CORS_WILDCARD: CheckDef = CheckDef {
    id: "passive.cors-wildcard-origin",
    name: "CORS misconfiguration: wildcard origin",
    sev: "low",
    confidence: "Firm",
};

pub const CH_CORS_WILDCARD_CREDS: CheckDef = CheckDef {
    id: "passive.cors-wildcard-origin-credentials",
    name: "CORS misconfiguration: wildcard origin with credentials",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_CORS_REFLECT: CheckDef = CheckDef {
    id: "passive.cors-reflected-origin",
    name: "CORS misconfiguration: arbitrary origin reflected",
    sev: "low",
    confidence: "Firm",
};

pub const CH_CORS_CREDS: CheckDef = CheckDef {
    id: "passive.cors-reflected-origin-credentials",
    name: "CORS misconfiguration: reflected origin with credentials",
    sev: "high",
    confidence: "Firm",
};

pub const CH_CORS_NULL: CheckDef = CheckDef {
    id: "passive.cors-null-origin",
    name: "CORS misconfiguration: null origin allowed",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_DIR_LISTING: CheckDef = CheckDef {
    id: "passive.directory-listing",
    name: "Directory listing",
    sev: "low",
    confidence: "Firm",
};

pub const CH_GIT: CheckDef = CheckDef {
    id: "passive.git-directory-exposed",
    name: "Exposed .git directory",
    sev: "high",
    confidence: "Certain",
};

pub const CH_ENV: CheckDef = CheckDef {
    id: "passive.env-file-exposed",
    name: "Exposed .env file",
    sev: "high",
    confidence: "Certain",
};

pub const CH_LOGIN_HTTP: CheckDef = CheckDef {
    id: "passive.login-form-http",
    name: "Cleartext submission of password",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_MIXED: CheckDef = CheckDef {
    id: "passive.mixed-content",
    name: "Mixed content",
    sev: "low",
    confidence: "Firm",
};

pub const CH_CACHE: CheckDef = CheckDef {
    id: "passive.cacheable-https-response",
    name: "Cacheable HTTPS response",
    sev: "low",
    confidence: "Tentative",
};

pub const CH_REDIRECT_COOKIE: CheckDef = CheckDef {
    id: "passive.session-cookie-cross-host-redirect",
    name: "Session cookie sent on cross-host redirect",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_AUTOCOMPLETE: CheckDef = CheckDef {
    id: "passive.password-autocomplete",
    name: "Password field with autocomplete enabled",
    sev: "low",
    confidence: "Firm",
};

pub const CH_EMAIL: CheckDef = CheckDef {
    id: "passive.email-disclosed",
    name: "Email addresses disclosed",
    sev: "info",
    confidence: "Certain",
};

pub const CH_PRIVATE_IP: CheckDef = CheckDef {
    id: "passive.private-ip-disclosed",
    name: "Private IP addresses disclosed",
    sev: "info",
    confidence: "Certain",
};

pub const CH_CREDIT_CARD: CheckDef = CheckDef {
    id: "passive.credit-card-disclosed",
    name: "Credit card numbers disclosed",
    sev: "medium",
    confidence: "Firm",
};

pub const CH_OPENAPI_PASSIVE: CheckDef = CheckDef {
    id: "passive.openapi-definition",
    name: "OpenAPI definition found (passive scan check)",
    sev: "info",
    confidence: "Certain",
};

pub const CH_HTML_NO_CHARSET: CheckDef = CheckDef {
    id: "passive.html-no-charset",
    name: "HTML does not specify charset",
    sev: "info",
    confidence: "Certain",
};

pub const CH_HTML_BAD_CHARSET: CheckDef = CheckDef {
    id: "passive.html-unrecognized-charset",
    name: "HTML uses unrecognized charset",
    sev: "info",
    confidence: "Certain",
};

pub const CH_CT_MISSING: CheckDef = CheckDef {
    id: "passive.content-type-missing",
    name: "Content type is not specified",
    sev: "info",
    confidence: "Certain",
};

pub const CH_CT_MULTI: CheckDef = CheckDef {
    id: "passive.content-type-multiple",
    name: "Multiple content types specified",
    sev: "info",
    confidence: "Certain",
};

pub const CH_ROBOTS: CheckDef = CheckDef {
    id: "passive.robots-txt",
    name: "Robots.txt file",
    sev: "info",
    confidence: "Certain",
};

pub const CH_CSRF: CheckDef = CheckDef {
    id: "passive.csrf-form-token-missing",
    name: "CSRF token missing on form with password field",
    sev: "medium",
    confidence: "Firm",
};

/// burp.Zf9p.ZY: charsets Burp recognizes.
pub const KNOWN_CHARSETS: [&str; 10] = [
    "utf-8",
    "us-ascii",
    "iso8859-1",
    "iso8859-2",
    "iso8859-15",
    "iso-8859-1",
    "iso-8859-2",
    "iso-8859-15",
    "windows-1250",
    "windows-1252",
];

/// The status code of a parsed response (0 when it cannot be read).
fn status_code(p: &util::HttpParts) -> u16 {
    p.first
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0)
}

/// burp.Zh63.Zh: the values of the response's Content-Type headers, in
/// header order.
fn content_types(p: &util::HttpParts) -> Vec<&String> {
    p.headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v)
        .collect()
}

/// burp.Zmlg.Zg: the distinct media types those values state, without
/// parameters (lowercased here).
fn content_type_essences(cts: &[&String]) -> std::collections::BTreeSet<String> {
    cts.iter()
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .collect()
}

/// burp.Zf9p: content-type and charset statements of one response.
pub fn mime_issues(resp: &[u8]) -> Vec<CheckDef> {
    let p = util::parse_http(resp);
    let status = status_code(&p);
    if (300..400).contains(&status) || status == 204 {
        return Vec::new();
    }
    let body = &resp[p.head_len.min(resp.len())..];
    let cts = content_types(&p);
    let mut out = Vec::new();
    if cts.is_empty() {
        if !body.is_empty() {
            out.push(CH_CT_MISSING);
        }
        return out;
    }
    let essences = content_type_essences(&cts);
    if essences.len() > 1 {
        out.push(CH_CT_MULTI);
    }
    if essences.iter().any(|e| e == "text/html") && !body.is_empty() {
        let mut charsets: Vec<String> = cts
            .iter()
            .flat_map(|v| v.split(';').skip(1))
            .filter_map(|p| {
                p.trim()
                    .strip_prefix("charset=")
                    .or_else(|| p.trim().strip_prefix("Charset="))
                    .map(|c| c.trim_matches('"').to_ascii_lowercase())
            })
            .collect();
        let low = String::from_utf8_lossy(&body[..body.len().min(4096)]).to_ascii_lowercase();
        if let Some(i) = low.find("<meta") {
            for tag in low[i..].split("<meta").skip(1).take(20) {
                let tag = tag.split('>').next().unwrap_or("");
                if let Some(c) = tag.split("charset=").nth(1) {
                    let c = c
                        .trim_start_matches(['"', '\''])
                        .split(['"', '\'', ' ', '/', ';'])
                        .next()
                        .unwrap_or("");
                    if !c.is_empty() {
                        charsets.push(c.to_string());
                    }
                }
            }
        }
        if charsets.is_empty() {
            out.push(CH_HTML_NO_CHARSET);
        } else if charsets
            .iter()
            .any(|c| !KNOWN_CHARSETS.contains(&c.as_str()))
        {
            out.push(CH_HTML_BAD_CHARSET);
        }
    }
    out
}

// ------------------------------------------------------------ misstated content type (burp.Zf9p)

/// burp.Zmlg type codes the content sniffing can infer (burp.Zwgu.Zy).
const JPEG: u16 = 513;
const GIF: u16 = 514;
const PNG: u16 = 515;
const BMP: u16 = 516;
const TIFF: u16 = 517;
const FLASH: u16 = 1026;
const WOFF: u16 = 1536;
const WOFF2: u16 = 1537;

/// burp.Zwgu.Zy: the leading bytes that identify a binary format. Burp's
/// TIFF entries are "IIB\0" and "MM\0B" (the format's own are "II*\0" and
/// "MM\0*"); they are kept as Burp has them.
const MAGIC: [(&[u8], u16); 10] = [
    (&[0xFF, 0xD8], JPEG),
    (b"GIF", GIF),
    (&[0x89, b'P', b'N', b'G'], PNG),
    (b"BM", BMP),
    (&[b'I', b'I', b'B', 0], TIFF),
    (&[b'M', b'M', 0, b'B'], TIFF),
    (b"FWS", FLASH),
    (b"CWS", FLASH),
    (b"wOFF", WOFF),
    (b"wOF2", WOFF2),
];

/// burp.Zh0p: the byte-order marks skipped before the content, in the
/// order they are tried.
const BOMS: [&[u8]; 5] = [
    &[0xEF, 0xBB, 0xBF],
    &[0xFE, 0xFF, 0, 0],
    &[0xFF, 0xFE, 0, 0],
    &[0xFE, 0xFF],
    &[0xFF, 0xFE],
];

/// burp.Zh63.Zh: the type code a Content-Type value states, from
/// substrings of the whole lowercased value (parameters included).
fn stated_type(value: &str) -> u16 {
    let v = value.to_lowercase();
    let has = |s: &str| v.contains(s);
    let font = has("application/font") || v.starts_with("font/");
    if has("html") && !has("application/vnd") {
        256
    } else if has("json") {
        260
    } else if has("yaml") || has("yml") {
        263
    } else if has("text/event-stream") {
        264
    } else if has("script") {
        259
    } else if has("text/css") {
        258
    } else if has("image") {
        [
            ("jpeg", JPEG),
            ("png", PNG),
            ("gif", GIF),
            ("bmp", BMP),
            ("tiff", TIFF),
            ("svg", 518),
        ]
        .iter()
        .find(|(s, _)| has(s))
        .map_or(512, |&(_, c)| c)
    } else if has("text/plain") {
        257
    } else if has("xml") {
        262
    } else if has("text/rtf") {
        261
    } else if has("sound") || has("audio") {
        768
    } else if has("video") || has("application/ogg") {
        769
    } else if has("application/x-shockwave-flash") {
        FLASH
    } else if font && has("woff2") {
        WOFF2
    } else if font && has("woff") {
        WOFF
    } else if has("application") {
        1025
    } else {
        1
    }
}

/// The binary type Burp's content sniffing (burp.Zh63.Zi, burp.Zmby.Zs)
/// finds in the body at `body_at`, if any. Only burp.Zwgu infers a binary
/// type; the sniffers after it (burp.Zxjd) infer text types or none, which
/// burp.Zmlg.ZC accepts, so they cannot raise this issue and are not ported.
fn sniff_binary(resp: &[u8], body_at: usize) -> Option<u16> {
    // burp.Zh63.Zi: only the first 10,000 bytes of the body are sniffed.
    let msg = &resp[..resp.len().min(body_at + 10_000)];
    let body = &msg[body_at.min(msg.len())..];
    // burp.Zmb7.ZW: a byte-order mark is skipped (burp.Zh0p), then control
    // bytes are counted (Zmb7.ZR on Java's signed bytes: below 32 except
    // tab, LF and CR, and every byte from 0x80).
    let skip = BOMS
        .iter()
        .find(|b| body.starts_with(b))
        .map_or(0, |b| b.len());
    let content = &body[skip..];
    let control = content
        .iter()
        .any(|&b| (b < 32 && !matches!(b, 9 | 10 | 13)) || b >= 0x80);
    // burp.Zwgu.ZW: only with a control byte and a body over 5 bytes
    // (burp.Zm5t.ZH), the format whose magic starts the content.
    if !control || body.len() <= 5 {
        return None;
    }
    let &(_, code) = MAGIC.iter().find(|(m, _)| content.starts_with(m))?;
    // Zwgu.lambda$execute$0: a JPEG must end with FF D9; the end is that of
    // the cut message, so a JPEG body over 10,000 bytes rarely passes.
    (code != JPEG || msg.ends_with(&[0xFF, 0xD9])).then_some(code)
}

/// burp.Zmlg.Ze: how the issue text names an inferred binary type.
fn inferred_name(code: u16) -> &'static str {
    match code {
        JPEG => "a JPEG image",
        GIF => "a GIF image",
        PNG => "a PNG image",
        BMP => "a BMP image",
        TIFF => "a TIFF image",
        FLASH => "a flash object",
        _ => "a WOFF font",
    }
}

/// burp.Zbt4, in its order, with the names burp.Zbt4.Zf gives them; a set
/// of browsers is a bit mask in this order.
pub(crate) const BROWSER_NAMES: [&str; 7] = [
    "Chrome",
    "Firefox",
    "Opera",
    "Internet Explorer 11",
    "Internet Explorer 11 (Compatibility Mode)",
    "Safari",
    "Edge",
];
const CHROME: u8 = 1;
const FIREFOX: u8 = 1 << 1;
const OPERA: u8 = 1 << 2;
const IE11: u8 = 1 << 3;
const IE11_COMPAT: u8 = 1 << 4;
const SAFARI: u8 = 1 << 5;
const EDGE: u8 = 1 << 6;
/// Every burp.Zbt4 browser.
pub(crate) const ALL_BROWSERS: u8 = 0x7F;

/// burp.Zuin: the browsers that render a response as HTML when the URL
/// path ends with ".html" (first) and the response sends
/// `X-Content-Type-Options: nosniff` (second), as burp.Zu4o pairs them.
type Rule = (bool, bool, u8);
/// burp.Zr1o.ZV.
const IE_EDGE: Rule = (false, false, EDGE | IE11_COMPAT | IE11);
/// burp.Zr1o.Za.
const IE_EDGE_HTML: Rule = (true, false, EDGE | IE11_COMPAT | IE11);
/// burp.Zr1o.ZP.
const IE_HTML: Rule = (true, false, IE11_COMPAT | IE11);
/// burp.Zr1o.ZL.
const OTHERS: Rule = (false, false, SAFARI | OPERA | CHROME | FIREFOX);
/// burp.Zr1o.ZR.
const OTHERS_HTML: Rule = (true, false, SAFARI | OPERA | CHROME | FIREFOX);
/// burp.Zr1o.ZW.
const FIREFOX_NOSNIFF: Rule = (false, true, FIREFOX);
/// burp.Zr1o.ZI.
const FIREFOX_NOSNIFF_HTML: Rule = (true, true, FIREFOX);
/// burp.Zr1o.Zh.
const NO_EDGE_HTML: Rule = (
    true,
    false,
    SAFARI | IE11_COMPAT | IE11 | OPERA | CHROME | FIREFOX,
);
/// burp.Zr1o.ZQ.
const EVERY: Rule = (false, false, ALL_BROWSERS);
/// burp.Zr1o.Zq.
const EVERY_HTML: Rule = (true, false, ALL_BROWSERS);
/// burp.Zr1o.ZN.
const NO_EDGE_FIREFOX_HTML: Rule = (true, false, SAFARI | IE11_COMPAT | IE11 | OPERA | CHROME);
/// burp.Zr1o.ZX: a stated type without "/".
const NO_SLASH: &[Rule] = &[OTHERS, NO_EDGE_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML];
/// burp.Zr1o.ZF: any other stated type (burp.Zx9d).
const OTHER_TYPE: &[Rule] = &[IE_HTML];

/// burp.Zr1o.Zf, filled by burp.Zxj_: the rules for a stated type Burp
/// lists. `Some(&[])` is burp.Zr1o.Ze (no browser renders it as HTML).
fn type_rules(stated: &str) -> Option<&'static [Rule]> {
    Some(match stated {
        "application/octet-stream" => &[IE_EDGE, IE_EDGE_HTML],
        "application/binary" => &[IE_HTML],
        "unknown/unknown" => &[
            (false, false, SAFARI | OPERA | CHROME),
            NO_EDGE_FIREFOX_HTML,
        ],
        "application/unknown" => &[
            (false, false, SAFARI | OPERA | CHROME),
            NO_EDGE_FIREFOX_HTML,
        ],
        "text/plain" => &[(false, false, IE11_COMPAT), (true, false, IE11_COMPAT)],
        "text/x-json" => &[IE_HTML],
        "text/json" => &[IE_HTML],
        "application/postscript" => &[IE_EDGE, IE_EDGE_HTML],
        "application/x-compressed" => &[IE_EDGE, IE_EDGE_HTML],
        "application/x-zip-compressed" => &[IE_EDGE, IE_EDGE_HTML],
        "audio/basic" => &[IE_EDGE, IE_EDGE_HTML],
        "audio/wav" => &[IE_EDGE, IE_EDGE_HTML],
        "audio/x-aiff" => &[IE_EDGE, IE_EDGE_HTML],
        "pkcs10" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "pkcs7-mime" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "pkcs7-signature" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "pkix-cert" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "pkix-crl" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "text/html" => &[
            EVERY,
            EVERY_HTML,
            (
                false,
                true,
                EDGE | SAFARI | IE11_COMPAT | IE11 | OPERA | CHROME | FIREFOX,
            ),
            (
                true,
                true,
                EDGE | SAFARI | IE11_COMPAT | IE11 | OPERA | CHROME | FIREFOX,
            ),
        ],
        "text/scriptlet" => &[IE_EDGE, IE_EDGE_HTML],
        "video/avi" => &[IE_EDGE, IE_EDGE_HTML],
        "video/mpeg" => &[IE_EDGE, IE_EDGE_HTML],
        "video/x-msvideo" => &[IE_EDGE, IE_EDGE_HTML],
        "vnd.ms-pki.certstore" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "vnd.ms-pki.pko" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "vnd.ms-pki.seccat" => &[FIREFOX_NOSNIFF_HTML, OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF],
        "vnd.ms-pki.stl" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "x-pkcs12" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "x-pkcs7-certificates" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "x-pkcs7-certreqresp" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "x-x509-ca-cert" => &[OTHERS, OTHERS_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "audio/x-m4a" => &[IE_HTML],
        "video/ogg" => &[IE_HTML],
        "audio/ogg" => &[IE_HTML],
        "video/webm" => &[IE_HTML],
        "audio/webm" => &[IE_HTML],
        "audio/flac" => &[IE_HTML],
        "application/x-chrome-extension" => &[IE_HTML],
        "multipart/related" => &[IE_HTML],
        "application/gzip" => &[IE_HTML],
        "application/font-woff" => &[IE_HTML],
        "application/x-mpegurl" => &[IE_HTML],
        "application/applefile" => &[IE_HTML],
        "application/x-macbinary" => &[IE_HTML],
        "application/compress" => &[IE_HTML],
        "application/x-fortezza-ckl" => &[IE_HTML],
        "application/x-fortezza-krl" => &[IE_HTML],
        "application/x-gunzip" => &[IE_HTML],
        "application/zip" => &[IE_HTML],
        "application/http-index-format" => &[IE_HTML],
        "application/ecmascript" => &[IE_HTML],
        "application/x-netscape-revocation" => &[IE_HTML],
        "application/x-ns-proxy-autoconfig" => &[IE_HTML],
        "application/x-javascript-config" => &[IE_HTML],
        "application/pgp" => &[IE_HTML],
        "application/x-pgp-message" => &[IE_HTML],
        "application/pre-encrypted" => &[IE_HTML],
        "application/x-uuencode" => &[IE_HTML],
        "application/x-uue" => &[IE_HTML],
        "application/uuencode" => &[IE_HTML],
        "application/uue" => &[IE_HTML],
        "application/x-x509-server-cert" => &[IE_HTML],
        "application/x-x509-email-cert" => &[IE_HTML],
        "application/x-x509-user-cert" => &[IE_HTML],
        "application/x-pkcs7-crl" => &[IE_HTML],
        "application/x-pkcs7-mime" => &[IE_HTML],
        "application/x-pkcs7-signature" => &[IE_HTML],
        "application/x-www-form-urlencoded" => &[IE_HTML],
        "application/oleobject" => &[IE_HTML],
        "application/x-oleobject" => &[IE_HTML],
        "application/java-archive" => &[IE_HTML],
        "application/marimba" => &[IE_HTML],
        "application/x-marimba" => &[IE_HTML],
        "application/x-xpinstall" => &[IE_HTML],
        "application/package" => &[IE_HTML],
        "audio/amr" => &[IE_HTML],
        "audio/x-matroska" => &[IE_HTML],
        "binary/octet-stream" => &[IE_HTML],
        "video/x-mng" => &[IE_HTML],
        "message/external-body" => &[IE_HTML],
        "message/news" => &[IE_HTML],
        "multipart/alternative" => &[IE_HTML],
        "multipart/appledouble" => &[IE_HTML],
        "multipart/digest" => &[IE_HTML],
        "multipart/form-data" => &[IE_HTML],
        "multipart/header-set" => &[IE_HTML],
        "multipart/mixed" => &[IE_EDGE_HTML, IE_EDGE],
        "multipart/parallel" => &[IE_HTML],
        "multipart/signed" => &[IE_HTML],
        "multipart/x-mixed-replace" => &[
            (
                false,
                false,
                EDGE | SAFARI | IE11_COMPAT | IE11 | OPERA | CHROME,
            ),
            (
                true,
                false,
                EDGE | SAFARI | IE11_COMPAT | IE11 | OPERA | CHROME,
            ),
            (false, true, SAFARI | OPERA | CHROME),
            (true, true, SAFARI | OPERA | CHROME),
        ],
        "multipart/byteranges" => &[IE_HTML],
        "x-sun-attachment" => &[OTHERS, NO_EDGE_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "text/enriched" => &[IE_HTML],
        "text/calendar" => &[IE_HTML],
        "text/mdl" => &[IE_HTML],
        "text/richtext" => &[IE_EDGE, IE_EDGE_HTML],
        "text/vcard" => &[IE_HTML],
        "text/jsss" => &[IE_HTML],
        "text/rdf" => &[IE_HTML],
        "text/ecmascript" => &[IE_HTML],
        "text/xsl" => &[IE_HTML],
        "text/event-stream" => &[IE_HTML],
        "text/cache-manifest" => &[
            IE_EDGE,
            IE_EDGE_HTML,
            (false, true, EDGE | IE11_COMPAT | IE11),
            (true, true, EDGE | IE11_COMPAT | IE11),
        ],
        "video/x-raw-yuv" => &[IE_HTML],
        "video/mp2t" => &[IE_HTML],
        "video/x-matroska" => &[IE_HTML],
        "application/ogg" => &[IE_HTML],
        "x-uuencode-apple-single" => &[OTHERS, NO_EDGE_HTML, FIREFOX_NOSNIFF, FIREFOX_NOSNIFF_HTML],
        "application/x-unknown-content-type" => &[
            (false, false, FIREFOX),
            (true, false, IE11_COMPAT | IE11 | FIREFOX),
            FIREFOX_NOSNIFF,
            FIREFOX_NOSNIFF_HTML,
        ],
        "application/x-vnd.mozilla.guess-from-ext" => &[IE_HTML],
        "application/x-view-source" => &[IE_HTML],
        "application/directory" => &[IE_HTML],
        "mozilla.application/cached-xul" => &[IE_HTML],
        "text/javascript" => &[],
        "application/x-javascript" => &[],
        "text/css" => &[],
        "text/xml" => &[],
        "application/fractals" => &[],
        "application/hta" => &[],
        "application/java-deployment-toolkit" => &[],
        "application/mac-binhex40" => &[],
        "application/opensearchdescription+xml" => &[],
        "application/pdf" => &[],
        "application/pkcs10" => &[],
        "application/pkcs7-mime" => &[],
        "application/pkcs7-signature" => &[],
        "application/pkix-cert" => &[],
        "application/pkix-crl" => &[],
        "application/vnd.adobe.acrobat-security-settings" => &[],
        "application/vnd.adobe.pdfxml" => &[],
        "application/vnd.adobe.pdx" => &[],
        "application/vnd.adobe.xdp+xml" => &[],
        "application/vnd.adobe.xfd+xml" => &[],
        "application/vnd.adobe.xfdf" => &[],
        "application/vnd.fdf" => &[],
        "application/vnd.ms-pki.pko" => &[],
        "application/vnd.ms-pki.seccat" => &[],
        "application/vnd.ms-pki.stl" => &[],
        "application/vnd.ms-visio.drawing" => &[],
        "application/vnd.ms-visio.drawing.macroenabled" => &[],
        "application/vnd.ms-visio.stencil" => &[],
        "application/vnd.ms-visio.stencil.macroenabled" => &[],
        "application/vnd.ms-visio.template" => &[],
        "application/vnd.ms-visio.template.macroenabled" => &[],
        "application/vnd.ms-visio.viewer" => &[],
        "application/vnd.ms-wpl" => &[],
        "application/vnd.ms-xpsdocument" => &[],
        "application/vnd.visio" => &[],
        "application/vnd.visio.webdrawing" => &[],
        "application/x-complus" => &[],
        "application/x-compress" => &[],
        "application/x-gzip" => &[],
        "application/x-informationcard" => &[],
        "application/x-java-applet" => &[],
        "application/x-java-jnlp-file" => &[],
        "application/x-jtx+xps" => &[],
        "application/x-latex" => &[],
        "application/x-mix-transfer" => &[],
        "application/x-mplayer2" => &[],
        "application/x-ms-application" => &[],
        "application/x-ms-license" => &[],
        "application/x-ms-vsto" => &[],
        "application/x-ms-wmd" => &[],
        "application/x-ms-wmz" => &[],
        "application/x-ms-xbap" => &[],
        "application/x-mswebsite" => &[],
        "application/x-pkcs12" => &[],
        "application/x-pkcs7-certificates" => &[],
        "application/x-pkcs7-certreqresp" => &[],
        "application/x-stuffit" => &[],
        "application/x-tar" => &[],
        "application/x-troff-man" => &[],
        "application/x-vnd.google.oneclickctrl.9" => &[],
        "application/x-vnd.google.update3webcontrol.3" => &[],
        "application/x-wmplayer" => &[],
        "application/x-x509-ca-cert" => &[],
        "application/xaml+xml" => &[],
        "application/xhtml+xml" => &[],
        "application/xml" => &[],
        "audio/3gpp" => &[],
        "audio/3gpp2" => &[],
        "audio/aiff" => &[],
        "audio/mid" => &[],
        "audio/midi" => &[],
        "audio/mp3" => &[],
        "audio/mp4" => &[],
        "audio/mpeg" => &[],
        "audio/mpegurl" => &[],
        "audio/mpg" => &[],
        "audio/vnd.dlna.adts" => &[],
        "audio/x-mid" => &[],
        "audio/x-midi" => &[],
        "audio/x-mp3" => &[],
        "audio/x-mpeg" => &[],
        "audio/x-mpegurl" => &[],
        "audio/x-mpg" => &[],
        "audio/x-ms-wax" => &[],
        "audio/x-ms-wma" => &[],
        "audio/x-wav" => &[],
        "message/rfc822" => &[],
        "midi/mid" => &[],
        "model/vnd.dwfx+xps" => &[],
        "model/vnd.easmx+xps" => &[],
        "model/vnd.edrwx+xps" => &[],
        "model/vnd.eprtx+xps" => &[],
        "text/vnd-ms.click2record+xml" => &[],
        "text/x-component" => &[],
        "text/x-ms-contact" => &[],
        "text/x-ms-odc" => &[],
        "text/x-scriptlet" => &[],
        "text/x-vcard" => &[],
        "video/3gpp" => &[],
        "video/3gpp2" => &[],
        "video/mp4" => &[],
        "video/mpg" => &[],
        "video/msvideo" => &[],
        "video/quicktime" => &[],
        "video/vnd.dlna.mpeg-tts" => &[],
        "video/x-mpeg" => &[],
        "video/x-mpeg2a" => &[],
        "video/x-ms-asf" => &[],
        "video/x-ms-asf-plugin" => &[],
        "video/x-ms-wm" => &[],
        "video/x-ms-wmv" => &[],
        "video/x-ms-wmx" => &[],
        "video/x-ms-wvx" => &[],
        "application/javascript" => &[],
        "application/rdf+xml" => &[],
        "application/vnd.mozilla.xul+xml" => &[],
        "application/x-shockwave-flash" => &[],
        "application/manifest+json" => &[],
        "application/xslt+xml" => &[],
        "application/mathml+xml" => &[],
        "application/atom+xml" => &[],
        "application/rss+xml" => &[],
        "application/vnd.ms-package.relationships+xml" => &[],
        "application/vnd.ms-pki.certstore" => &[],
        _ => return None,
    })
}

/// burp.Zen8.ZE: the browsers that may render a response of this stated
/// type as HTML (burp.Zsto, burp.Zr2z, burp.Zphj, burp.Z_0, burp.Za2,
/// burp.Zx9d; burp.Zss4.Zf takes the first rule matching both flags).
/// Burp's branch for no stated type (burp.Zr1o.Zl) is not needed: this
/// issue requires a Content-Type header.
fn sniffing_browsers(stated: &str, nosniff: bool, attachment: bool, html_path: bool) -> u8 {
    let t = stated.to_lowercase();
    if attachment && t.contains("json") {
        return 0;
    }
    let rules = match type_rules(&t) {
        Some(rules) => rules,
        None if !t.contains('/') => NO_SLASH,
        None if t.starts_with("image/") || t.contains("json") => return 0,
        None => OTHER_TYPE,
    };
    rules
        .iter()
        .find(|r| r.0 == html_path && r.1 == nosniff)
        .map_or(0, |r| r.2)
}

/// What burp.Zur0.ZM records for a response whose content does not match
/// its stated type.
pub(crate) struct Misstated {
    /// burp.Zmlg.ZS: the last stated type, without parameters.
    pub stated: String,
    /// burp.Zmlg.Ze of the inferred type.
    pub inferred: &'static str,
    /// burp.Zw8c.ZV: the browsers that may render it as HTML at this path.
    pub browsers: u8,
    /// burp.Zw8c.ZB: the same if the path ended with ".html".
    pub html_browsers: u8,
}

/// burp.Zf9p.ZT, CONTENT_TYPE_INCORRECTLY_STATED: not a redirect, one
/// stated type (the gates of mime_issues), content sniffed as a binary type
/// other than the stated one (`!Zmlg.ZC(inferred)` and Zf9p.ZZ), and some
/// browser that may render it as HTML (Zf9p.Zr). `path` is the request
/// path (burp.Zin1.Zh).
pub(crate) fn misstated_type(resp: &[u8], path: &str) -> Option<Misstated> {
    let p = util::parse_http(resp);
    if (300..400).contains(&status_code(&p)) {
        return None;
    }
    let cts = content_types(&p);
    if content_type_essences(&cts).len() != 1 {
        return None;
    }
    // burp.Zh63.Zf over the distinct values (a LinkedHashSet): every value
    // states a non-zero type, so the last one counts.
    let mut values: Vec<&str> = Vec::new();
    for v in &cts {
        if !values.contains(&v.trim()) {
            values.push(v.trim());
        }
    }
    let last = *values.last()?;
    let inferred = sniff_binary(resp, p.head_len.min(resp.len()))?;
    if inferred == stated_type(last) {
        return None;
    }
    let stated = last.split(';').next().unwrap_or("").trim().to_string();
    // burp.Zs65.Zt / Za: the first X-Content-Type-Options header says
    // nosniff; burp.Zs65.ZV: the first header line starting with
    // "content-disposition" contains "attachment" after those 19 characters.
    let nosniff = p
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-content-type-options"))
        .is_some_and(|(_, v)| v.trim().eq_ignore_ascii_case("nosniff"));
    let attachment = p
        .headers
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase().starts_with("content-disposition"))
        .is_some_and(|(k, v)| {
            format!("{}:{v}", &k[19..])
                .to_lowercase()
                .contains("attachment")
        });
    // burp.Zw8c.ZD: the path ends with ".html", ignoring case.
    let at_html = path.to_lowercase().ends_with(".html");
    let browsers = sniffing_browsers(&stated, nosniff, attachment, at_html);
    let html_browsers = sniffing_browsers(&stated, nosniff, attachment, true);
    (browsers != 0 || html_browsers != 0).then(|| Misstated {
        stated,
        inferred: inferred_name(inferred),
        browsers,
        html_browsers,
    })
}
