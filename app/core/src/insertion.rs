// Insertion points of the active scan, after Burp's own:
//
// * the point types (burp.Zbg8) and the wording issues use (burp.Zsg0);
// * the builder, in burp.Zuq.Zs order: entire body (Zuq.ZT), URL and body
//   parameters (Zuq.addUrlAndBodyParameterInsertionPoints), cookies (Zuq.Zy),
//   `X-*` headers (Zuq.ZP), nested points (Zuq.ZV), XML standalone tags
//   (Zuq.Za), parameter names (Zuq.Zp), User-Agent and Referer (Zuq.Zb), URL
//   path folders and filename;
// * the vetoes and the per-request cap (burp.Zwez: Zick, Zgai, Zb9c, then
//   the limit), and the server-side skip list (burp.Zgx0.Zr / Ziqf.Zr);
// * payload placement: each point type's encoder (burp.Zfw9.Zr) and, for a
//   nested point, the child's content composed into its parent with the
//   parent's encoder (burp.Ziqv.ZT).
//
// `IpKind`, `InsertionPoint`, `insertion_points`, `inject`, `inject_payload`,
// `insertion_type`, `json_leaves` and `json_set` moved here from scan.rs,
// unchanged for the kinds that existed (the builder was rewritten around
// them; `insertion_type` now returns None for nested-only kinds). The
// request helpers they call (`with_body`, `replace_param`, `with_cookie`,
// ...) stay in scan.rs.

use base64::Engine as _;

use super::*;
use crate::scan_config::ScanConfig;

/// Burp's insertion point kinds used by the active scan (burp.Zg6r / Zbg8:
/// URL parameter, body parameter, JSON value, multipart part, cookie, HTTP
/// header, URL path folder and filename, entire body, XML element and
/// attribute, added parameter name, Base64 value).
///
/// A nested point (`InsertionPoint::parent` set) reuses these kinds; its
/// offsets then index the parent's decoded, trimmed value
/// ([`InsertionPoint::nested_content`]), not the request body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IpKind {
    Query,
    Body,
    /// JSON value at a path of object keys / array indices.
    Json(Vec<String>),
    /// multipart/form-data part `index` (0-based); `filename` is set for a
    /// file-upload part (burp.Zsdt / Ziqg, the parts with a filename attribute).
    Multipart { index: usize, filename: Option<String> },
    /// A cookie in the Cookie header (Zg6r.COOKIE).
    Cookie,
    /// A request header value (Zbg8.HEADER); added when absent (Referer).
    Header,
    /// '/'-separated path segment index (Zg6r.PATH_FOLDER_PARAM).
    PathFolder(usize),
    /// '/'-separated path segment index of the last segment (PATH_FILENAME_PARAM).
    PathFilename(usize),
    /// The whole body of an XML or JSON request (Zbg8.ENTIRE_BODY, Zuq.ZT).
    EntireBody,
    /// Text of an XML element, raw range `start..end` (Zbg8.XML_PARAM from the
    /// request parser, burp.Zhjs: a text token, or the empty value between a
    /// start tag and its end tag).
    XmlParam { start: usize, end: usize },
    /// A self-closing XML element turned into `<tag>value</tag>`
    /// (Zbg8.XML_PARAM, Zuq.addStandaloneTagInsertionPoint): `close` is
    /// where `/>` starts (spaces before `/` included), `end` is just after
    /// the `>`.
    XmlTag { close: usize, end: usize },
    /// Value of an XML attribute, raw range `start..end` inside its quotes
    /// (Zbg8.XML_ATTR).
    XmlAttr { start: usize, end: usize },
    /// Name of an added `1=1` parameter (Zbg8.PARAM_NAME_*, Zuq.Zp).
    ParamName(NameSite),
    /// A Base64 (or Base64url) value decoded from its parent
    /// (Zbg8.BASE64_ENCODED / BASE64URL_ENCODED, Zuq.ZS). Always nested.
    Base64 { url: bool },
}

/// Where a parameter-name point adds its `1=1` parameter (Zuq.Zp).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NameSite {
    /// `1=1` added to the query string (PARAM_NAME_URL).
    Url,
    /// `1=1` added to a URL-encoded body (PARAM_NAME_BODY_URL_ENCODED).
    Body,
    /// A part named `1` added to a multipart body (PARAM_NAME_BODY_MULTIPART).
    Multipart,
    /// `/1` appended to a `.php` path (Zuq.addPhpFileRequestInsertionPoint,
    /// typed PARAM_NAME_URL).
    PhpPathInfo,
}

/// Burp's point type (burp.Zbg8) of a kind: what the wording (Zsg0), the
/// skip lists (burp.Zsc3.ZQ) and the encoders (burp.Zfw9) key on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PointType {
    UrlParam,
    BodyParamUrlEncoded,
    BodyParamMultipart,
    Cookie,
    XmlParam,
    XmlAttr,
    PathFolder,
    PathFilename,
    JsonParam,
    ParamNameUrl,
    ParamNameBodyUrlEncoded,
    ParamNameBodyMultipart,
    Header,
    EntireBody,
    Base64,
    Base64Url,
}

impl IpKind {
    pub(crate) fn point_type(&self) -> PointType {
        match self {
            IpKind::Query => PointType::UrlParam,
            IpKind::Body => PointType::BodyParamUrlEncoded,
            IpKind::Json(_) => PointType::JsonParam,
            IpKind::Multipart { .. } => PointType::BodyParamMultipart,
            IpKind::Cookie => PointType::Cookie,
            IpKind::Header => PointType::Header,
            IpKind::PathFolder(_) => PointType::PathFolder,
            IpKind::PathFilename(_) => PointType::PathFilename,
            IpKind::EntireBody => PointType::EntireBody,
            IpKind::XmlParam { .. } | IpKind::XmlTag { .. } => PointType::XmlParam,
            IpKind::XmlAttr { .. } => PointType::XmlAttr,
            IpKind::ParamName(NameSite::Url | NameSite::PhpPathInfo) => PointType::ParamNameUrl,
            IpKind::ParamName(NameSite::Body) => PointType::ParamNameBodyUrlEncoded,
            IpKind::ParamName(NameSite::Multipart) => PointType::ParamNameBodyMultipart,
            IpKind::Base64 { url: false } => PointType::Base64,
            IpKind::Base64 { url: true } => PointType::Base64Url,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct InsertionPoint {
    pub kind: IpKind,
    pub name: String,
    /// The base value: decoded for the kinds Burp decodes (form body, XML,
    /// Base64, nested URL parameters); a query or cookie value is kept as
    /// sent (see [`InsertionPoint::decoded_value`]).
    pub value: String,
    /// For a nested point (burp.Zhs3), the point whose decoded value holds it.
    pub parent: Option<Box<InsertionPoint>>,
}

impl InsertionPoint {
    pub(crate) fn new(kind: IpKind, name: impl Into<String>, value: impl Into<String>) -> Self {
        InsertionPoint { kind, name: name.into(), value: value.into(), parent: None }
    }

    fn nested(parent: &InsertionPoint, kind: IpKind, name: impl Into<String>, value: impl Into<String>) -> Self {
        InsertionPoint { kind, name: name.into(), value: value.into(), parent: Some(Box::new(parent.clone())) }
    }

    /// The base value as Burp's point encoder decodes it (burp.Zr4u runs
    /// the type's Zifl decoder over the raw value): a query parameter or a
    /// cookie URL-decoded, every other kind as stored.
    pub(crate) fn decoded_value(&self) -> String {
        match (&self.kind, &self.parent) {
            (IpKind::Query | IpKind::Cookie, None) => util::url_decode(&self.value),
            _ => self.value.clone(),
        }
    }

    /// The content nested points of this one index into: the decoded value,
    /// trimmed (burp.Zuq.ZV: `Zy().trim()`).
    pub(crate) fn nested_content(&self) -> String {
        self.decoded_value().trim().to_string()
    }

    /// The points from the outermost to this one (burp.Zhs3.Zn: the parent's
    /// list, then the child's).
    fn chain(&self) -> Vec<&InsertionPoint> {
        let mut v = vec![self];
        let mut cur = self;
        while let Some(p) = cur.parent.as_deref() {
            v.push(p);
            cur = p;
        }
        v.reverse();
        v
    }

    /// burp.Zsg0.ZD: "value of the q request parameter", "Base64-decoded
    /// value of the data parameter", "name of an arbitrarily supplied URL
    /// parameter", ...
    pub(crate) fn describe(&self) -> String {
        describe_chain(&self.chain(), true, false)
    }

    /// burp.Zsg0.Zj: "q parameter", "sid cookie", "request body", ...;
    /// `bold` wraps the name in `<b>` as Burp's issue texts do.
    pub(crate) fn describe_short(&self, bold: bool) -> String {
        describe_chain(&self.chain(), false, bold)
    }

    /// True when Burp's skip_server_side_injection_for_parameters list
    /// matches this point (burp.Ziqf.Zr -> Ze9d.Ze: the point's own type,
    /// name and value; ancestors are not consulted).
    pub(crate) fn skips_server_side(&self) -> bool {
        rule_hits(SKIP_SERVER_SIDE, self)
    }
}

// ---------------------------------------------------------------- wording

/// burp.Zsg0.Zy (short form) and Zsg0.ZX (`value_form`) for one point.
fn point_label(t: PointType, name: &str, value_form: bool, bold: bool) -> String {
    let n = if bold { format!("<b>{name}</b>") } else { name.to_string() };
    let named = |what: &str| if value_form { format!("value of the {n} {what}") } else { format!("{n} {what}") };
    match t {
        PointType::UrlParam | PointType::BodyParamUrlEncoded | PointType::BodyParamMultipart => {
            if value_form {
                format!("value of the {n} request parameter")
            } else {
                format!("{n} parameter")
            }
        }
        PointType::Cookie => named("cookie"),
        PointType::XmlParam => named("XML parameter"),
        PointType::XmlAttr => named("XML attribute"),
        PointType::Header => named("HTTP header"),
        PointType::JsonParam => named("JSON parameter"),
        PointType::ParamNameUrl => "name of an arbitrarily supplied URL parameter".into(),
        PointType::ParamNameBodyUrlEncoded | PointType::ParamNameBodyMultipart => "name of an arbitrarily supplied body parameter".into(),
        // Zsg0 case 13 appends the folder's name (no bold) to the label;
        // WebProbe names folders "URL path folder N" already.
        PointType::PathFolder => {
            let num = name.strip_prefix("URL path folder ").unwrap_or(name);
            if value_form {
                format!("value of the URL path folder {num}")
            } else {
                format!("URL path folder {num}")
            }
        }
        PointType::PathFilename => if value_form { "value of the URL path filename" } else { "URL path filename" }.into(),
        PointType::EntireBody => if value_form { "value of the request body" } else { "request body" }.into(),
        PointType::Base64 => "Base64-decoded value".into(),
        PointType::Base64Url => "Base64Url-decoded value".into(),
    }
}

/// burp.Zsg0.ZH: innermost point first; a Base64 level is followed by
/// " of the ", any other by " within the " (", within the " from three
/// levels on).
fn describe_chain(chain: &[&InsertionPoint], value_form: bool, bold: bool) -> String {
    let n = chain.len();
    let mut s = String::new();
    for i in (0..n).rev() {
        let t = chain[i].kind.point_type();
        s.push_str(&point_label(t, &chain[i].name, value_form && i == n - 1, bold));
        if n > 1 && i > 0 {
            if matches!(t, PointType::Base64 | PointType::Base64Url) {
                s.push_str(" of the ");
            } else {
                if n > 2 {
                    s.push(',');
                }
                s.push_str(" within the ");
            }
        }
    }
    s
}

// ---------------------------------------------------------------- skip lists

/// The `parameter` of a skip rule (burp.Zsc3.ZQ: the rule's type matched
/// against the point type; `any_parameter` matches every type).
#[derive(Clone, Copy)]
enum RuleParam {
    Any,
    Body,
    Cookie,
    XmlAttr,
}

/// `match_type` of a skip rule on the parameter name (burp.Zsc3.Ze):
/// `is` compares ignoring case; `matches_regex` runs Matcher.find() with
/// CASE_INSENSITIVE|DOTALL (burp.Zx6z, flags 34). Every shipped regex is
/// `<literal>.*`, so find() is "contains the literal, ignoring case".
#[derive(Clone, Copy)]
enum RuleMatch {
    Is(&'static str),
    Contains(&'static str),
}

/// AuditDefaults.json scanner.ignored_insertion_points.skip_all_tests_for_parameters.
const SKIP_ALL: &[(RuleParam, RuleMatch)] = &[
    (RuleParam::XmlAttr, RuleMatch::Is("version")),
    (RuleParam::XmlAttr, RuleMatch::Is("encoding")),
    (RuleParam::XmlAttr, RuleMatch::Is("standalone")),
    (RuleParam::XmlAttr, RuleMatch::Contains("xmlns")),
    (RuleParam::XmlAttr, RuleMatch::Is("xml:lang")),
    (RuleParam::XmlAttr, RuleMatch::Is("lang")),
    (RuleParam::Cookie, RuleMatch::Is("_ga")),
    (RuleParam::Cookie, RuleMatch::Is("_gid")),
    (RuleParam::Cookie, RuleMatch::Is("_gat")),
    (RuleParam::Cookie, RuleMatch::Contains("_ga_")),
    (RuleParam::Cookie, RuleMatch::Contains("_gac_")),
    (RuleParam::Cookie, RuleMatch::Contains("awsalb")),
];

/// AuditDefaults.json scanner.ignored_insertion_points.skip_server_side_injection_for_parameters.
const SKIP_SERVER_SIDE: &[(RuleParam, RuleMatch)] = &[
    (RuleParam::Cookie, RuleMatch::Contains("aspsessionid")),
    (RuleParam::Cookie, RuleMatch::Is("asp.net_sessionid")),
    (RuleParam::Body, RuleMatch::Is("__eventtarget")),
    (RuleParam::Body, RuleMatch::Is("__eventargument")),
    (RuleParam::Body, RuleMatch::Is("__viewstate")),
    (RuleParam::Body, RuleMatch::Is("__eventvalidation")),
    (RuleParam::Any, RuleMatch::Is("jsessionid")),
    (RuleParam::Cookie, RuleMatch::Is("cfid")),
    (RuleParam::Cookie, RuleMatch::Is("cftoken")),
    (RuleParam::Cookie, RuleMatch::Is("PHPSESSID")),
    (RuleParam::Cookie, RuleMatch::Is("session_id")),
];

fn rule_param_matches(param: RuleParam, t: PointType) -> bool {
    match param {
        RuleParam::Any => true,
        // burp.Zr2c: body_parameter covers URL-encoded and multipart body
        // parameters (and multipart attributes), not JSON or XML.
        RuleParam::Body => matches!(t, PointType::BodyParamUrlEncoded | PointType::BodyParamMultipart),
        RuleParam::Cookie => t == PointType::Cookie,
        RuleParam::XmlAttr => t == PointType::XmlAttr,
    }
}

fn rule_hits(rules: &[(RuleParam, RuleMatch)], p: &InsertionPoint) -> bool {
    let t = p.kind.point_type();
    rules.iter().any(|(param, m)| {
        rule_param_matches(*param, t)
            && match m {
                RuleMatch::Is(x) => p.name.eq_ignore_ascii_case(x),
                RuleMatch::Contains(x) => p.name.to_ascii_lowercase().contains(&x.to_ascii_lowercase()),
            }
    })
}

/// burp.Zb9c: the skip-all list vetoes a point when it matches the point or
/// any point it is nested in.
fn skipped_by_skip_all(p: &InsertionPoint) -> bool {
    p.chain().iter().any(|q| rule_hits(SKIP_ALL, q))
}

// ---------------------------------------------------------------- vetoes

/// The scan configuration's insertion point type of a base point
/// ([`crate::scan_config::INSERTION_TYPES`], burp.Zwez's Zick list); None
/// for kinds that only exist nested (Zick lets every nested point through).
pub(crate) fn insertion_type(kind: &IpKind) -> Option<&'static str> {
    match kind {
        IpKind::Query => Some("url"),
        IpKind::Body | IpKind::Json(_) | IpKind::Multipart { .. } | IpKind::XmlParam { .. } | IpKind::XmlTag { .. } | IpKind::XmlAttr { .. } => Some("body"),
        IpKind::Cookie => Some("cookie"),
        IpKind::Header => Some("header"),
        IpKind::PathFolder(_) => Some("folder"),
        IpKind::PathFilename(_) => Some("filename"),
        IpKind::EntireBody => Some("entire_body"),
        IpKind::ParamName(_) => Some("param_name"),
        IpKind::Base64 { .. } => None,
    }
}

/// burp.Zwez.ZV without the limit: Zick (the point type is switched off;
/// nested points are exempt), Zgai (nested points need "Use nested
/// insertion points" and an allowed parent), Zb9c (skip-all list).
fn allowed(p: &InsertionPoint, config: &ScanConfig) -> bool {
    match &p.parent {
        None => {
            if let Some(key) = insertion_type(&p.kind) {
                if !config.insertion_enabled(key) {
                    return false;
                }
            }
        }
        Some(parent) => {
            if !config.insertion_enabled(crate::scan_config::NESTED_KEY) || !allowed(parent, config) {
                return false;
            }
        }
    }
    !skipped_by_skip_all(p)
}

/// The points a scan of `req` attacks under `config`, in burp.Zuq.Zs order:
/// every point the builder makes goes through the vetoes in turn, and once
/// AuditDefaults max_insertion_points_per_base_request = 30 points are
/// accepted the rest are vetoed (burp.Zwez: the limit is the last filter and
/// counts only accepted points), so the points built last (path, then
/// User-Agent and Referer) are the first to fall off a busy request.
pub(crate) fn audit_points(req: &str, config: &ScanConfig) -> Vec<InsertionPoint> {
    let mut out = Vec::new();
    for p in build_points(req) {
        if out.len() >= MAX_INSERTION_POINTS {
            break;
        }
        if allowed(&p, config) {
            out.push(p);
        }
    }
    out
}

/// [`audit_points`] under the default scan configuration.
#[cfg(test)]
pub(crate) fn insertion_points(req: &str) -> Vec<InsertionPoint> {
    audit_points(req, &ScanConfig::default())
}

// ---------------------------------------------------------------- builder

/// The value Burp synthesises for a Referer insertion point when the request
/// has none (burp.Zuq.ZE, "addNewReferHeaderInsertionPoint").
pub(crate) const SYNTH_REFERER: &str = "https://example.com/";

/// A safety bound on the points one base point's nested walk may add
/// (Burp's walk, Zuq.ZV, has none; every level only shrinks the content,
/// so it ends, but a busy value could build thousands of points that the
/// cap of 30 would drop anyway).
const MAX_NESTED_PER_POINT: usize = 64;

/// burp.Zxb0.Zh: the first and last non-blank bytes decide: `<`..`>` is
/// XML, `{`..`}` or `[`..`]` JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sniff {
    None,
    Xml,
    Json,
}

fn sniff(s: &str) -> Sniff {
    let t = s.trim_matches(|c: char| (c as u32) <= 32);
    let b = t.as_bytes();
    if b.len() < 2 {
        return Sniff::None;
    }
    match (b[0], b[b.len() - 1]) {
        (b'<', b'>') => Sniff::Xml,
        (b'{', b'}') | (b'[', b']') => Sniff::Json,
        _ => Sniff::None,
    }
}

/// burp.Zi5p.Zx: URL-encoded content: the text up to the first `&` is
/// printable and has a non-empty name before an `=`, and so does the
/// segment after that `&` (one `&` at least).
fn looks_url_encoded(s: &str) -> bool {
    fn segment(b: &[u8]) -> (bool, Option<usize>) {
        let (mut eq, mut name) = (false, false);
        for (i, &c) in b.iter().enumerate() {
            if !(32..127).contains(&c) {
                return (false, None);
            }
            if c == b'&' {
                return (name && eq, Some(i));
            }
            if c == b'=' {
                eq = true;
            } else if !eq {
                name = true;
            }
        }
        (name && eq, None)
    }
    let b = s.as_bytes();
    match segment(b) {
        (true, Some(amp)) => segment(&b[amp + 1..]).0,
        _ => false,
    }
}

/// The body type of a request (burp.Zw2_.Zf). Decided from the
/// Content-Type, else by sniffing: Burp's own decision (burp.Zgpb) was not
/// traced, so this keeps WebProbe's earlier order (multipart, JSON, form)
/// and adds XML before the form fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
enum BodyKind {
    None,
    Form,
    Multipart(String),
    Json,
    Xml,
}

fn body_kind(ct_raw: &str, body: &str) -> BodyKind {
    if body.trim().is_empty() {
        return BodyKind::None;
    }
    if let Some(boundary) = multipart_boundary(ct_raw) {
        return BodyKind::Multipart(boundary);
    }
    let ct = ct_raw.to_ascii_lowercase();
    let sniffed = sniff(body);
    if ct.contains("json") || body.trim_start().starts_with('{') || body.trim_start().starts_with('[') {
        BodyKind::Json
    } else if ct.contains("xml") || (sniffed == Sniff::Xml && !ct.contains("x-www-form-urlencoded")) {
        BodyKind::Xml
    } else if ct.contains("x-www-form-urlencoded") || body.contains('=') {
        BodyKind::Form
    } else {
        BodyKind::None
    }
}

/// A token of the XML scanner (burp.Zbl1 token types: 0 start tag, 1 end
/// tag, 2 other, 3 text, 4 self-closing tag).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokKind {
    Start,
    End,
    Other,
    Text,
    SelfClose,
}

struct XmlAttrTok {
    name: String,
    /// Raw value range (inside the quotes).
    value: (usize, usize),
}

struct XmlTok {
    kind: TokKind,
    start: usize,
    end: usize,
    name: String,
    attrs: Vec<XmlAttrTok>,
}

/// A forgiving XML tokenizer: tags, text, and comments / CDATA /
/// declarations as "other". Slices only at ASCII delimiters.
fn xml_tokens(s: &str) -> Vec<XmlTok> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            let end = s[i..].find('<').map(|x| x + i).unwrap_or(b.len());
            out.push(XmlTok { kind: TokKind::Text, start: i, end, name: String::new(), attrs: Vec::new() });
            i = end;
            continue;
        }
        let rest = &s[i..];
        let close = |pat: &str| rest.find(pat).map(|x| i + x + pat.len());
        let other_end = if rest.starts_with("<!--") {
            Some(close("-->"))
        } else if rest.starts_with("<![CDATA[") {
            Some(close("]]>"))
        } else if rest.starts_with("<?") || rest.starts_with("<!") {
            Some(close(">"))
        } else {
            None
        };
        if let Some(end) = other_end {
            let Some(end) = end else { break };
            out.push(XmlTok { kind: TokKind::Other, start: i, end, name: String::new(), attrs: Vec::new() });
            i = end;
            continue;
        }
        // A tag: find its '>' outside quotes.
        let mut j = i + 1;
        let mut quote: Option<u8> = None;
        while j < b.len() {
            match (quote, b[j]) {
                (Some(q), c) if c == q => quote = None,
                (None, b'"' | b'\'') => quote = Some(b[j]),
                (None, b'>') => break,
                _ => {}
            }
            j += 1;
        }
        if j >= b.len() {
            break;
        }
        let end = j + 1;
        if b.get(i + 1) == Some(&b'/') {
            let name = s[i + 2..j].trim().to_string();
            out.push(XmlTok { kind: TokKind::End, start: i, end, name, attrs: Vec::new() });
            i = end;
            continue;
        }
        let self_close = b[j - 1] == b'/' && j - 1 > i;
        let inner_end = if self_close { j - 1 } else { j };
        let mut k = i + 1;
        while k < inner_end && !b[k].is_ascii_whitespace() && b[k] != b'/' {
            k += 1;
        }
        let name = s[i + 1..k].to_string();
        let mut attrs = Vec::new();
        loop {
            while k < inner_end && b[k].is_ascii_whitespace() {
                k += 1;
            }
            if k >= inner_end {
                break;
            }
            let n0 = k;
            while k < inner_end && !b[k].is_ascii_whitespace() && b[k] != b'=' {
                k += 1;
            }
            let aname = s[n0..k].to_string();
            while k < inner_end && b[k].is_ascii_whitespace() {
                k += 1;
            }
            if k >= inner_end || b[k] != b'=' {
                if k == n0 {
                    k += 1;
                }
                continue;
            }
            k += 1;
            while k < inner_end && b[k].is_ascii_whitespace() {
                k += 1;
            }
            if k >= inner_end {
                break;
            }
            let (v0, v1);
            if b[k] == b'"' || b[k] == b'\'' {
                let q = b[k];
                v0 = k + 1;
                let mut m = v0;
                while m < inner_end && b[m] != q {
                    m += 1;
                }
                v1 = m;
                k = (m + 1).min(inner_end);
            } else {
                v0 = k;
                while k < inner_end && !b[k].is_ascii_whitespace() {
                    k += 1;
                }
                v1 = k;
            }
            if !aname.is_empty() {
                attrs.push(XmlAttrTok { name: aname, value: (v0, v1) });
            }
        }
        let kind = if self_close { TokKind::SelfClose } else { TokKind::Start };
        out.push(XmlTok { kind, start: i, end, name, attrs });
        i = end;
    }
    out
}

/// XML parameters and attributes of `content` as Burp's request parser
/// yields them (burp.Zhjs, token loop at 0x6b0): every attribute of a start
/// or self-closing tag; a non-blank text token, named after the last tag
/// seen; and an empty value where an end tag directly follows a start tag.
/// Values are XML-decoded (burp.Zbk2 / Zgk9 decoders).
fn xml_points(content: &str, parent: Option<&InsertionPoint>) -> Vec<InsertionPoint> {
    let mut out = Vec::new();
    let mut last: Option<String> = None;
    let mut prev: Option<TokKind> = None;
    let mk = |kind: IpKind, name: String, value: String| match parent {
        Some(p) => InsertionPoint::nested(p, kind, name, value),
        None => InsertionPoint::new(kind, name, value),
    };
    for t in xml_tokens(content) {
        match t.kind {
            TokKind::Start | TokKind::SelfClose => {
                last = Some(t.name.clone());
                for a in &t.attrs {
                    let raw = &content[a.value.0..a.value.1];
                    out.push(mk(IpKind::XmlAttr { start: a.value.0, end: a.value.1 }, a.name.clone(), util::html_decode(raw)));
                }
            }
            TokKind::End => {
                if prev == Some(TokKind::Start) {
                    out.push(mk(IpKind::XmlParam { start: t.start, end: t.start }, last.clone().unwrap_or_default(), String::new()));
                }
            }
            TokKind::Text => {
                let raw = &content[t.start..t.end];
                if !raw.trim().is_empty() {
                    out.push(mk(IpKind::XmlParam { start: t.start, end: t.end }, last.clone().unwrap_or_default(), util::html_decode(raw)));
                }
            }
            TokKind::Other => {}
        }
        prev = Some(t.kind);
    }
    out
}

/// burp.Zuq.Za / addStandaloneTagInsertionPoint / ZN: one point per
/// self-closing element of an XML body. The `/` must be the byte before the
/// `>`; spaces (only) before it are taken in, and the payload goes between
/// the new `>` and `</tag>`.
fn standalone_tag_points(body: &str) -> Vec<InsertionPoint> {
    let b = body.as_bytes();
    let mut out = Vec::new();
    for t in xml_tokens(body) {
        if t.kind != TokKind::SelfClose || t.end < t.start + 2 || b[t.end - 2] != b'/' {
            continue;
        }
        let mut close = t.end - 2;
        while close > t.start + 1 && b[close - 1] == b' ' {
            close -= 1;
        }
        out.push(InsertionPoint::new(IpKind::XmlTag { close, end: t.end }, t.name, ""));
    }
    out
}

fn json_leaves(v: &serde_json::Value, path: &mut Vec<String>, out: &mut Vec<(Vec<String>, String)>) {
    if out.len() >= MAX_INSERTION_POINTS {
        return;
    }
    match v {
        serde_json::Value::Object(m) => {
            for (k, x) in m {
                path.push(k.clone());
                json_leaves(x, path, out);
                path.pop();
            }
        }
        serde_json::Value::Array(a) => {
            for (i, x) in a.iter().enumerate().take(5) {
                path.push(i.to_string());
                json_leaves(x, path, out);
                path.pop();
            }
        }
        serde_json::Value::String(st) => out.push((path.clone(), st.clone())),
        serde_json::Value::Number(n) => out.push((path.clone(), n.to_string())),
        serde_json::Value::Bool(b) => out.push((path.clone(), b.to_string())),
        serde_json::Value::Null => {}
    }
}

/// JSON values of `text` as points (nested under `parent` when given).
fn json_points(text: &str, parent: Option<&InsertionPoint>) -> Vec<InsertionPoint> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { return Vec::new() };
    let mut leaves = Vec::new();
    json_leaves(&v, &mut Vec::new(), &mut leaves);
    leaves
        .into_iter()
        .map(|(path, value)| {
            let name = path.last().cloned().unwrap_or_default();
            match parent {
                Some(p) => InsertionPoint::nested(p, IpKind::Json(path), name, value),
                None => InsertionPoint::new(IpKind::Json(path), name, value),
            }
        })
        .collect()
}

/// burp.Zq4.ZA (+ Zq4.Zj's length >= 4): Base64 shape over `alphabet`.
fn base64_shape(b: &[u8], alphabet: fn(u8) -> bool) -> bool {
    if b.len() < 4 || b.len() % 4 == 1 {
        return false;
    }
    let last = b[b.len() - 1];
    if if last == b'=' { b.len() % 4 != 0 } else { b[b.len() - 2] == b'=' } {
        return false;
    }
    let n = b.len() - 2;
    b.iter().enumerate().all(|(i, &c)| !(c == b'=' && i < n) && alphabet(c))
}

/// burp net.portswigger.Zyn.Za: printable ASCII, tab, CR or LF only.
fn printable(b: &[u8]) -> bool {
    b.iter().all(|&c| (c >= 32 || c == b'\n' || c == b'\r' || c == b'\t') && c < 127)
}

fn base64_engine(url: bool) -> base64::engine::GeneralPurpose {
    let cfg = base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true);
    let alphabet = if url { &base64::alphabet::URL_SAFE } else { &base64::alphabet::STANDARD };
    base64::engine::GeneralPurpose::new(alphabet, cfg)
}

/// The decoded text when `s` passes Burp's Base64 test (net.portswigger.Zq0.ZC
/// for the standard alphabet, Zan.ZG for the URL-safe one): Base64 shape,
/// and the decoded bytes printable. Zan.ZR returns the input itself when
/// the URL-safe decoder fails; WebProbe treats that as "not Base64url"
/// instead (the input would then test as Base64url again, forever).
fn base64_decoded(s: &str, url: bool) -> Option<String> {
    let alphabet: fn(u8) -> bool = if url {
        |c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'='
    } else {
        |c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'='
    };
    if !base64_shape(s.as_bytes(), alphabet) {
        return None;
    }
    let decoded = base64_engine(url).decode(s).ok()?;
    printable(&decoded).then(|| String::from_utf8_lossy(&decoded).into_owned())
}

/// The points one level inside `node`'s value (burp.Zuq.Za over
/// Zuq.ZP's content type: XML, JSON, else URL-encoded per Zi5p).
fn nested_children(node: &InsertionPoint) -> Vec<InsertionPoint> {
    let content = node.nested_content();
    match sniff(&content) {
        Sniff::Xml => xml_points(&content, Some(node)),
        Sniff::Json => json_points(&content, Some(node)),
        Sniff::None if looks_url_encoded(&content) => content
            .split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                InsertionPoint::nested(node, IpKind::Query, k, util::url_decode(v))
            })
            .collect(),
        Sniff::None => Vec::new(),
    }
}

/// burp.Zuq.ZV: a depth-first walk below one base point. Each node's
/// value is parsed as URL-encoded / XML / JSON content and its parameters
/// become points (pushed so they come out in order); a value that parses
/// as none of these is tried as Base64, then Base64url. The base point
/// itself is already in the list.
fn nested_points(base: &InsertionPoint, out: &mut Vec<InsertionPoint>) {
    let mut stack: Vec<InsertionPoint> = vec![base.clone()];
    let mut made = 0usize;
    let mut first = true;
    while let Some(node) = stack.pop() {
        if !std::mem::take(&mut first) {
            out.push(node.clone());
        }
        if made >= MAX_NESTED_PER_POINT {
            continue;
        }
        let children = nested_children(&node);
        if !children.is_empty() {
            made += children.len();
            stack.extend(children.into_iter().rev());
            continue;
        }
        let content = node.nested_content();
        for url in [false, true] {
            if let Some(decoded) = base64_decoded(&content, url) {
                made += 1;
                stack.push(InsertionPoint::nested(&node, IpKind::Base64 { url }, node.name.clone(), decoded));
                break;
            }
        }
    }
}

/// The file extension of a request path (burp.Zhem.ZLs).
fn path_extension(path: &str) -> &str {
    let p = path.split(['?', '#']).next().unwrap_or("");
    let last = p.rsplit('/').next().unwrap_or("");
    last.rfind('.').map(|i| &last[i + 1..]).unwrap_or("")
}

/// Every point burp.Zuq.Zs builds for `req`, in its order, before any veto:
/// 1. the entire body of an XML or JSON request (Zuq.ZT);
/// 2. URL parameters, then body parameters (form, multipart part, JSON
///    value, XML attribute / element) in request order (Zuq.Ze);
/// 3. cookies (Zuq.Zy); 4. every `X-*` header present (Zuq.ZP);
/// 5. nested points under each point of 2-4, base point by base point (Zuq.ZV);
/// 6. self-closing XML elements (Zuq.Za);
/// 7. parameter names: the body's (when it has URL-encoded or multipart
///    parameters), the URL's, and `/1` after a `.php` path (Zuq.Zp);
/// 8. User-Agent when present and Referer, existing or synthesised (Zuq.Zb);
/// 9. URL path folders (Zuq.ZX), 10. the URL path filename (Zuq.ZY).
///
/// Not built: Zuq.ZG's moved-parameter points (every
/// scanner.modifying_parameter_locations default is false).
fn build_points(req: &str) -> Vec<InsertionPoint> {
    let parts = util::parse_http(req.as_bytes());
    let body = req.find("\r\n\r\n").map(|i| &req[i + 4..]).unwrap_or("");
    let ct_raw = util::get_header(&parts.headers, "Content-Type").unwrap_or_default();
    let kind = body_kind(&ct_raw, body);
    let mut out: Vec<InsertionPoint> = Vec::new();
    if matches!(kind, BodyKind::Json | BodyKind::Xml) {
        out.push(InsertionPoint::new(IpKind::EntireBody, "", body));
    }
    let mut base: Vec<InsertionPoint> =
        query_params(&parts.path).into_iter().map(|(name, value)| InsertionPoint::new(IpKind::Query, name, value)).collect();
    match &kind {
        BodyKind::Multipart(boundary) => {
            for (index, p) in multipart_parts(body, boundary).into_iter().enumerate() {
                base.push(InsertionPoint::new(IpKind::Multipart { index, filename: p.filename.clone() }, p.name.clone(), &body[p.content.0..p.content.1]));
            }
        }
        BodyKind::Json => base.extend(json_points(body, None)),
        BodyKind::Xml => base.extend(xml_points(body, None)),
        BodyKind::Form => {
            for kv in body.split('&').filter(|x| !x.is_empty()) {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                base.push(InsertionPoint::new(IpKind::Body, k, util::url_decode(v)));
            }
        }
        BodyKind::None => {}
    }
    // Cookies, in header order (the skip-all list is a veto, applied later).
    for v in parts.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("Cookie")).map(|(_, v)| v) {
        for pair in v.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (n, val) = pair.split_once('=').unwrap_or((pair, ""));
            base.push(InsertionPoint::new(IpKind::Cookie, n, val));
        }
    }
    // X-* headers present in the request.
    for (k, v) in &parts.headers {
        if k.len() > 2 && k.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("x-")) {
            base.push(InsertionPoint::new(IpKind::Header, k.clone(), v.clone()));
        }
    }
    out.extend(base.iter().cloned());
    for p in &base {
        nested_points(p, &mut out);
    }
    if sniff(body) == Sniff::Xml {
        out.extend(standalone_tag_points(body));
    }
    if base.iter().any(|p| matches!(p.kind, IpKind::Body | IpKind::Multipart { .. })) {
        let site = if matches!(kind, BodyKind::Multipart(_)) { NameSite::Multipart } else { NameSite::Body };
        out.push(InsertionPoint::new(IpKind::ParamName(site), "", "1"));
    }
    out.push(InsertionPoint::new(IpKind::ParamName(NameSite::Url), "", "1"));
    if path_extension(&parts.path).eq_ignore_ascii_case("php") {
        out.push(InsertionPoint::new(IpKind::ParamName(NameSite::PhpPathInfo), "", "1"));
    }
    if let Some(ua) = util::get_header(&parts.headers, "User-Agent") {
        out.push(InsertionPoint::new(IpKind::Header, "User-Agent", ua));
    }
    let referer = util::get_header(&parts.headers, "Referer").unwrap_or_else(|| SYNTH_REFERER.to_string());
    out.push(InsertionPoint::new(IpKind::Header, "Referer", referer));
    for (label, idx, seg) in path_insertion_points(&parts.path) {
        let kind = if label == "URL path filename" { IpKind::PathFilename(idx) } else { IpKind::PathFolder(idx) };
        out.push(InsertionPoint::new(kind, label, seg));
    }
    out
}

// ---------------------------------------------------------------- encoders

/// burp.Zc1o, the URL-parameter encoder (URL / body parameters, cookies and
/// parameter names): space " # % & + , / : ; < = > ? \ ^ ` { | } and every
/// byte outside printable ASCII are percent-encoded. Its "leave as is" set
/// (Zc1o.Zr) is configuration Burp fills at runtime; WebProbe assumes it
/// empty. Used for the new point kinds and for nested content; the existing
/// kinds keep [`encode_query_payload`].
pub(crate) fn encode_url_param(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let special = matches!(
            b,
            b' ' | b'"' | b'#' | b'%' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'<' | b'=' | b'>' | b'?' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}'
        );
        if special || !(0x21..0x7f).contains(&b) {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

/// burp.Zbk2 (XML_PARAM): `<` and `&` as entities, NUL / CR / LF as
/// `&#x00;` / `&#x0d;` / `&#x0a;` (net.portswigger.Zsh.Zc).
pub(crate) fn xml_text_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '&' => out.push_str("&amp;"),
            '\0' => out.push_str("&#x00;"),
            '\r' => out.push_str("&#x0d;"),
            '\n' => out.push_str("&#x0a;"),
            c => out.push(c),
        }
    }
    out
}

/// burp.Zgk9 (XML_ATTR): also `"`, `'` and `>` (net.portswigger.Zsh.ZM).
pub(crate) fn xml_attr_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '>' => out.push_str("&gt;"),
            '<' => out.push_str("&lt;"),
            '&' => out.push_str("&amp;"),
            '\0' => out.push_str("&#x00;"),
            '\r' => out.push_str("&#x0d;"),
            '\n' => out.push_str("&#x0a;"),
            c => out.push(c),
        }
    }
    out
}

/// burp.Zr87 (multipart parameter name): `"` becomes `\"`.
fn multipart_name_escape(s: &str) -> String {
    s.replace('"', "\\\"")
}

// ---------------------------------------------------------------- placement

pub(crate) fn json_set(v: &mut serde_json::Value, path: &[String], new: serde_json::Value) {
    let Some((first, rest)) = path.split_first() else {
        *v = new;
        return;
    };
    match v {
        serde_json::Value::Object(m) => {
            if let Some(x) = m.get_mut(first) {
                json_set(x, rest, new);
            }
        }
        serde_json::Value::Array(a) => {
            if let Some(x) = first.parse::<usize>().ok().and_then(|i| a.get_mut(i)) {
                json_set(x, rest, new);
            }
        }
        _ => {}
    }
}

fn splice(s: &str, start: usize, end: usize, value: &str) -> String {
    match (s.get(..start), s.get(end..)) {
        (Some(a), Some(b)) if start <= end => format!("{a}{value}{b}"),
        _ => s.to_string(),
    }
}

/// `<tag ...` + `>value</tag>` + the rest, for a standalone tag point.
fn open_tag(s: &str, close: usize, end: usize, name: &str, value: &str) -> String {
    match (s.get(..close), s.get(end..)) {
        (Some(a), Some(b)) if close <= end => format!("{a}>{value}</{name}>{b}"),
        _ => s.to_string(),
    }
}

/// `value` placed verbatim at a nested point inside its parent's content.
fn place_in_content(content: &str, ip: &InsertionPoint, value: &str) -> String {
    match &ip.kind {
        IpKind::Query => replace_param(&format!("?{content}"), &ip.name, value).get(1..).unwrap_or("").to_string(),
        IpKind::Json(path) => match serde_json::from_str::<serde_json::Value>(content) {
            Ok(mut v) => {
                json_set(&mut v, path, serde_json::Value::String(value.to_string()));
                v.to_string()
            }
            Err(_) => content.to_string(),
        },
        IpKind::XmlParam { start, end } | IpKind::XmlAttr { start, end } => splice(content, *start, *end, value),
        IpKind::XmlTag { close, end } => open_tag(content, *close, *end, &ip.name, value),
        // burp.Zg16 / Zmqa: the whole content, re-encoded (padded).
        IpKind::Base64 { url } => base64_engine(*url).encode(value.as_bytes()),
        // The builder never nests these kinds.
        IpKind::Body
        | IpKind::Multipart { .. }
        | IpKind::Cookie
        | IpKind::Header
        | IpKind::PathFolder(_)
        | IpKind::PathFilename(_)
        | IpKind::EntireBody
        | IpKind::ParamName(_) => content.to_string(),
    }
}

/// The request with `content` as the new value of `parent`, encoded the
/// way the parent's own encoder encodes a payload (burp.Ziqv.ZT: the child
/// builds its content, the parent places it with flag 0, replace).
fn compose_into_parent(req: &str, parent: &InsertionPoint, content: &str) -> String {
    match &parent.kind {
        IpKind::Query | IpKind::Body | IpKind::Cookie => inject(req, parent, &encode_url_param(content)),
        // inject() URL-decodes a header value; encode it so it decodes back.
        IpKind::Header => inject(req, parent, &encode_url_param(content)),
        IpKind::XmlParam { .. } | IpKind::XmlTag { .. } => inject(req, parent, &xml_text_escape(content)),
        IpKind::XmlAttr { .. } => inject(req, parent, &xml_attr_escape(content)),
        // JSON escapes on its own; multipart is raw (burp.Zaa); a Base64
        // parent encodes its whole content.
        IpKind::Json(_) | IpKind::Multipart { .. } | IpKind::Base64 { .. } => inject(req, parent, content),
        // Not parents in Burp's builder (no nested pass over them).
        IpKind::PathFolder(_) | IpKind::PathFilename(_) | IpKind::EntireBody | IpKind::ParamName(_) => inject(req, parent, content),
    }
}

/// The request with `payload` placed at the insertion point, encoded for
/// that kind of point: URL-encoded in the query, form body, cookie and
/// header values; as written inside a JSON string, a multipart part and a
/// path segment, which escape it their own way. A payload that is itself
/// percent-encoded (a `%2f` traversal variant) therefore reaches a JSON
/// value as written; it used to be URL-decoded into `/`. The new kinds use
/// Burp's encoders (burp.Zfw9.Zr): the entire body raw, XML escaped, a
/// parameter name URL-encoded (multipart: `"` escaped). A nested point's
/// payload is encoded for its own kind, then the parent's content is
/// encoded for the parent (burp.Ziqv.ZT).
pub(crate) fn inject_payload(req: &str, ip: &InsertionPoint, payload: &str) -> String {
    if ip.parent.is_some() {
        let encoded = match &ip.kind {
            IpKind::Query => encode_url_param(payload),
            IpKind::XmlParam { .. } | IpKind::XmlTag { .. } => xml_text_escape(payload),
            IpKind::XmlAttr { .. } => xml_attr_escape(payload),
            IpKind::Json(_) | IpKind::Base64 { .. } => payload.to_string(),
            IpKind::Body
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::ParamName(_) => payload.to_string(),
        };
        return inject(req, ip, &encoded);
    }
    match &ip.kind {
        IpKind::Json(_) | IpKind::Multipart { .. } | IpKind::PathFolder(_) | IpKind::PathFilename(_) => inject(req, ip, payload),
        IpKind::Query | IpKind::Body | IpKind::Cookie | IpKind::Header => inject(req, ip, &encode_query_payload(payload)),
        IpKind::EntireBody | IpKind::Base64 { .. } => inject(req, ip, payload),
        IpKind::XmlParam { .. } | IpKind::XmlTag { .. } => inject(req, ip, &xml_text_escape(payload)),
        IpKind::XmlAttr { .. } => inject(req, ip, &xml_attr_escape(payload)),
        IpKind::ParamName(NameSite::Multipart) => inject(req, ip, &multipart_name_escape(payload)),
        IpKind::ParamName(NameSite::Url | NameSite::Body | NameSite::PhpPathInfo) => inject(req, ip, &encode_url_param(payload)),
    }
}

/// The request with `value` placed verbatim at the insertion point (already
/// encoded for it; see [`inject_payload`]). For a nested point, `value` goes
/// verbatim into the parent's content, which is then encoded for the parent.
pub(crate) fn inject(req: &str, ip: &InsertionPoint, value: &str) -> String {
    if let Some(parent) = &ip.parent {
        let content = place_in_content(&parent.nested_content(), ip, value);
        return compose_into_parent(req, parent, &content);
    }
    let encoded = value;
    let parts = util::parse_http(req.as_bytes());
    let body = req.find("\r\n\r\n").map(|i| &req[i + 4..]).unwrap_or("");
    match &ip.kind {
        IpKind::Query => rebuild_with_path(req, &replace_param(&parts.path, &ip.name, encoded)),
        IpKind::Body => {
            let new: Vec<String> = body
                .split('&')
                .map(|kv| {
                    let k = kv.split('=').next().unwrap_or("");
                    if k == ip.name { format!("{k}={encoded}") } else { kv.to_string() }
                })
                .collect();
            with_body(req, &new.join("&"))
        }
        IpKind::Json(path) => {
            let Ok(mut v) = serde_json::from_str::<serde_json::Value>(body) else { return req.to_string() };
            json_set(&mut v, path, serde_json::Value::String(encoded.to_string()));
            with_body(req, &v.to_string())
        }
        // Multipart content is sent raw, like a browser would.
        IpKind::Multipart { index, .. } => with_multipart_part(req, *index, encoded, None, None),
        IpKind::Cookie => with_cookie(req, &ip.name, &cookie_value(encoded)),
        IpKind::Header => String::from_utf8_lossy(&net::replace_or_add_header(req.as_bytes(), &ip.name, &header_value(encoded))).into_owned(),
        IpKind::PathFolder(idx) | IpKind::PathFilename(idx) => {
            // with_path_segment escapes what would leave the segment.
            rebuild_with_path(req, &with_path_segment(&parts.path, *idx, encoded))
        }
        IpKind::EntireBody => with_body(req, encoded),
        IpKind::XmlParam { start, end } | IpKind::XmlAttr { start, end } => with_body(req, &splice(body, *start, *end, encoded)),
        IpKind::XmlTag { close, end } => with_body(req, &open_tag(body, *close, *end, &ip.name, encoded)),
        // Zuq.addNewParameterNameInsertionPoint: the request with a `1=1`
        // parameter added; the point is that parameter's name.
        IpKind::ParamName(NameSite::Url) => {
            let sep = match parts.path.split_once('?') {
                None => "?",
                Some((_, q)) if q.is_empty() || q.ends_with('&') => "",
                Some(_) => "&",
            };
            rebuild_with_path(req, &format!("{}{sep}{encoded}=1", parts.path))
        }
        IpKind::ParamName(NameSite::Body) => {
            let sep = if body.is_empty() || body.ends_with('&') { "" } else { "&" };
            with_body(req, &format!("{body}{sep}{encoded}=1"))
        }
        IpKind::ParamName(NameSite::Multipart) => {
            let ct = util::get_header(&parts.headers, "Content-Type").unwrap_or_default();
            let Some(boundary) = multipart_boundary(&ct) else { return req.to_string() };
            let part = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{encoded}\"\r\n\r\n1\r\n");
            let closing = format!("--{boundary}--");
            let new_body = match body.rfind(&closing) {
                Some(i) => format!("{}{part}{}", &body[..i], &body[i..]),
                None => format!("{body}{part}"),
            };
            with_body(req, &new_body)
        }
        // Zuq.addPhpFileRequestInsertionPoint: `<path>/1`, the `1` replaced.
        IpKind::ParamName(NameSite::PhpPathInfo) => {
            let (p, q) = match parts.path.split_once('?') {
                Some((p, q)) => (p, Some(q)),
                None => (parts.path.as_str(), None),
            };
            let new_path = match q {
                Some(q) => format!("{p}/{encoded}?{q}"),
                None => format!("{p}/{encoded}"),
            };
            rebuild_with_path(req, &new_path)
        }
        // A Base64 point always has a parent (handled above).
        IpKind::Base64 { .. } => req.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::checks::{self as ck, check_applies};

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    fn body_of(req: &str) -> &str {
        req.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("")
    }

    fn summary(pts: &[InsertionPoint]) -> Vec<(PointType, String, String)> {
        pts.iter().map(|p| (p.kind.point_type(), p.name.clone(), p.value.clone())).collect()
    }

    #[test]
    // JSON values come in serde_json's key order (sorted: `n` before `q`),
    // as before D-11, not in request order as Burp's parser gives them.
    fn json_body_gets_the_entire_body_point_first_then_the_build_order() {
        let body = r#"{"q":"a","n":5}"#;
        let req = format!("POST /api/find?x=1 HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nCookie: sid=abc\r\nX-Trace: t1\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let pts = insertion_points(&req);
        let got: Vec<(PointType, &str)> = pts.iter().map(|p| (p.kind.point_type(), p.name.as_str())).collect();
        assert_eq!(
            got,
            vec![
                (PointType::EntireBody, ""),
                (PointType::UrlParam, "x"),
                (PointType::JsonParam, "n"),
                (PointType::JsonParam, "q"),
                (PointType::Cookie, "sid"),
                (PointType::Header, "X-Trace"),
                (PointType::ParamNameUrl, ""),
                (PointType::Header, "Referer"),
                (PointType::PathFolder, "URL path folder 1"),
                (PointType::PathFilename, "URL path filename"),
            ]
        );
        assert_eq!(pts[0].value, body);
        // The entire body is replaced raw (burp.Zaa) and Content-Length follows.
        let r = inject_payload(&req, &pts[0], "{\"q\":\"'\"}");
        assert_eq!(body_of(&r), "{\"q\":\"'\"}");
        assert!(r.contains("Content-Length: 9\r\n"), "{r}");
        // A form body has no entire-body point (Zuq.ZT: XML and JSON only).
        let form = "POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1";
        assert!(!insertion_points(form).iter().any(|p| p.kind == IpKind::EntireBody));
    }

    #[test]
    fn the_cap_counts_accepted_points_after_the_vetoes() {
        // 29 URL parameters, five skip-listed cookies, then a real cookie:
        // the vetoed cookies do not count, so the 30th point is `real`.
        let q: Vec<String> = (0..29).map(|i| format!("p{i}=v")).collect();
        let req = format!("GET /a?{} HTTP/1.1\r\nHost: h\r\nCookie: _ga=1; _GID=2; x_ga_y=3; AWSALBCORS=4; _gat=5; real=6\r\n\r\n", q.join("&"));
        let pts = insertion_points(&req);
        assert_eq!(pts.len(), MAX_INSERTION_POINTS);
        assert_eq!((pts[29].kind.clone(), pts[29].name.as_str()), (IpKind::Cookie, "real"));
    }

    #[test]
    fn base64_heuristic_follows_zq4() {
        // Positive: padded, unpadded (length % 4 == 2 or 3).
        assert_eq!(base64_decoded(&b64("a=1&b=2"), false).as_deref(), Some("a=1&b=2"));
        assert_eq!(base64_decoded("Zm9vYg", false).as_deref(), Some("foob"));
        assert_eq!(base64_decoded("Zm9vYmE", false).as_deref(), Some("fooba"));
        // Negative, one rule each: shorter than 4; length % 4 == 1; a final
        // '=' with length % 4 != 0; '=' second to last without a final '=';
        // '=' before the last two places; a byte outside the alphabet;
        // decoded bytes that are not printable.
        assert_eq!(base64_decoded("Zm8", false), None);
        assert_eq!(base64_decoded("Zm9vY", false), None);
        assert_eq!(base64_decoded("Zm9vYg=", false), None);
        assert_eq!(base64_decoded("Zm9vY=g", false), None);
        assert_eq!(base64_decoded("Zm=vYmFy", false), None);
        assert_eq!(base64_decoded("Zm9v YmFy", false), None);
        assert_eq!(base64_decoded("/w==", false), None, "0xff is not printable");
        assert_eq!(base64_decoded("test", false), None, "decodes to binary");
        // URL-safe alphabet only through the Base64url test (Zan.ZG).
        let url = base64::engine::general_purpose::URL_SAFE.encode("<?>~~");
        assert!(url.contains('-') || url.contains('_'), "{url}");
        assert_eq!(base64_decoded(&url, false), None);
        assert_eq!(base64_decoded(&url, true).as_deref(), Some("<?>~~"));
    }

    #[test]
    fn nested_base64_then_url_encoded_points_round_trip() {
        let inner = b64("a=1&b=2");
        let req = format!("GET /p?data={} HTTP/1.1\r\nHost: h\r\n\r\n", inner.replace('=', "%3D"));
        let pts = insertion_points(&req);
        let i = pts.iter().position(|p| p.name == "data" && p.kind == IpKind::Query).unwrap();
        // Directly after the base points: the Base64 value, then a and b.
        assert_eq!(
            summary(&pts[i + 1..i + 4]),
            vec![
                (PointType::Base64, "data".into(), "a=1&b=2".into()),
                (PointType::UrlParam, "a".into(), "1".into()),
                (PointType::UrlParam, "b".into(), "2".into()),
            ]
        );
        let (b64pt, a) = (&pts[i + 1], &pts[i + 2]);
        assert_eq!(b64pt.describe(), "Base64-decoded value of the data parameter");
        assert_eq!(a.describe(), "value of the a request parameter, within the Base64-decoded value of the data parameter");
        // payload -> URL-encoded inside the content -> Base64 -> URL-encoded
        // in the query (burp.Ziqv.ZT).
        let r = inject_payload(&req, a, "x'&y");
        let path = r.split_whitespace().nth(1).unwrap();
        let sent = util::url_decode(path.split_once("data=").unwrap().1);
        let decoded = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(sent).unwrap()).unwrap();
        assert_eq!(decoded, "a=x'%26y&b=2");
        assert_eq!(util::url_decode(decoded.split('&').next().unwrap().strip_prefix("a=").unwrap()), "x'&y");
        // The Base64 point itself: the payload replaces the decoded text.
        let r = inject_payload(&req, b64pt, "<p>");
        let sent = util::url_decode(r.split_whitespace().nth(1).unwrap().split_once("data=").unwrap().1);
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(sent).unwrap(), b"<p>");
    }

    #[test]
    fn nested_points_compose_through_every_parent_encoder() {
        // b64("a=1&b=2") in a cookie, an X- header, a JSON string, an XML
        // element and a multipart part; the nested `a` gets a payload and
        // the parent's value must decode back to it (burp.Ziqv.ZT).
        let v = b64("a=1&b=2");
        let json = format!("{{\"t\":\"{v}\"}}");
        let xml = format!("<r><t>{v}</t></r>");
        let mp = format!("--B\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\n{v}\r\n--B--\r\n");
        let cases: Vec<(String, Box<dyn Fn(&str) -> String>)> = vec![
            (format!("GET / HTTP/1.1\r\nHost: h\r\nCookie: t={v}\r\n\r\n"), Box::new(|r: &str| util::url_decode(r.split("Cookie: t=").nth(1).unwrap().split("\r\n").next().unwrap()))),
            (format!("GET / HTTP/1.1\r\nHost: h\r\nX-T: {v}\r\n\r\n"), Box::new(|r: &str| r.split("X-T: ").nth(1).unwrap().split("\r\n").next().unwrap().to_string())),
            (format!("POST / HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{json}"), Box::new(|r: &str| serde_json::from_str::<serde_json::Value>(body_of(r)).unwrap()["t"].as_str().unwrap().to_string())),
            (format!("POST / HTTP/1.1\r\nHost: h\r\nContent-Type: text/xml\r\n\r\n{xml}"), Box::new(|r: &str| util::html_decode(body_of(r).split("<t>").nth(1).unwrap().split("</t>").next().unwrap()))),
            (format!("POST / HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=B\r\n\r\n{mp}"), Box::new(|r: &str| body_of(r).split("\r\n\r\n").nth(1).unwrap().split("\r\n").next().unwrap().to_string())),
        ];
        for (req, value_of) in cases {
            let pts = insertion_points(&req);
            let a = pts.iter().find(|p| p.name == "a" && p.parent.is_some()).unwrap_or_else(|| panic!("no nested a in {req}"));
            let r = inject_payload(&req, a, "x'&<y>");
            let sent = value_of(&r);
            let decoded = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(&sent).unwrap()).unwrap();
            let got = decoded.split('&').next().unwrap().strip_prefix("a=").unwrap();
            assert_eq!(util::url_decode(got), "x'&<y>", "{req}");
            assert!(decoded.ends_with("&b=2"), "{decoded}");
        }
    }

    #[test]
    fn nested_json_in_a_form_value_and_quoting() {
        let body = format!("q={}&n=7", encode_url_param("{\"k\":\"v\",\"m\":3}"));
        let req = format!("POST /s HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let pts = insertion_points(&req);
        let k = pts.iter().find(|p| p.name == "k").expect("nested k");
        assert!(k.parent.is_some() && matches!(k.kind, IpKind::Json(_)));
        assert_eq!(k.describe(), "value of the k JSON parameter within the q parameter");
        // The unquoted number becomes a quoted string, as Zuq.Zm rewrites it.
        let m = pts.iter().find(|p| p.name == "m").unwrap();
        let r = inject_payload(&req, m, "1'");
        let q = body_of(&r).split('&').next().unwrap().strip_prefix("q=").unwrap();
        let v: serde_json::Value = serde_json::from_str(&util::url_decode(q)).unwrap();
        assert_eq!((v["k"].as_str(), v["m"].as_str()), (Some("v"), Some("1'")));
        assert!(body_of(&r).ends_with("&n=7"));
    }

    #[test]
    fn xml_body_parameters_attributes_and_standalone_tags() {
        let body = "<?xml version=\"1.0\"?><r id=\"7\" xmlns:a=\"urn:x\"><name>bob &amp; co</name><e></e><b/><c x='1' /></r>";
        let req = format!("POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let pts = insertion_points(&req);
        let got: Vec<(PointType, &str, &str)> = pts.iter().take(7).map(|p| (p.kind.point_type(), p.name.as_str(), p.value.as_str())).collect();
        assert_eq!(
            got,
            vec![
                (PointType::EntireBody, "", body),
                // xmlns:a is on the skip-all list (xmlns.*).
                (PointType::XmlAttr, "id", "7"),
                (PointType::XmlParam, "name", "bob & co"),
                (PointType::XmlParam, "e", ""),
                (PointType::XmlAttr, "x", "1"),
                // Standalone tags come after the nested pass (Zuq.Za).
                (PointType::XmlParam, "b", ""),
                (PointType::XmlParam, "c", ""),
            ]
        );
        // Element text is XML-escaped (burp.Zbk2), attributes too (Zgk9).
        let r = inject_payload(&req, &pts[2], "<s>&\"");
        assert!(body_of(&r).contains("<name>&lt;s>&amp;\"</name>"), "{r}");
        let r = inject_payload(&req, &pts[1], "\"'<");
        assert!(body_of(&r).contains("id=\"&quot;&apos;&lt;\""), "{r}");
        // The empty element gets its value between the tags.
        assert!(body_of(&inject_payload(&req, &pts[3], "z")).contains("<e>z</e>"));
        // Standalone tags: `<b/>` and `<c x='1' />` open up.
        assert!(body_of(&inject_payload(&req, &pts[5], "P")).contains("<b>P</b><c"));
        assert!(body_of(&inject_payload(&req, &pts[6], "P")).contains("<c x='1'>P</c></r>"));
    }

    #[test]
    fn standalone_tag_spec_example() {
        let body = "<a><b/></a>";
        let req = format!("POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let tag = insertion_points(&req).into_iter().find(|p| matches!(p.kind, IpKind::XmlTag { .. })).unwrap();
        assert_eq!((tag.name.as_str(), tag.value.as_str()), ("b", ""));
        assert_eq!(body_of(&inject(&req, &tag, "PAYLOAD")), "<a><b>PAYLOAD</b></a>");
        assert_eq!(tag.describe(), "value of the b XML parameter");
    }

    #[test]
    fn parameter_name_points() {
        let names = |req: &str| -> Vec<IpKind> { insertion_points(req).into_iter().filter(|p| matches!(p.kind, IpKind::ParamName(_))).map(|p| p.kind).collect() };
        // GET: the URL name only; `1=1` is added and its name replaced.
        let get = "GET /s?q=1 HTTP/1.1\r\nHost: h\r\n\r\n";
        assert_eq!(names(get), vec![IpKind::ParamName(NameSite::Url)]);
        let p = insertion_points(get).into_iter().find(|p| p.kind == IpKind::ParamName(NameSite::Url)).unwrap();
        assert_eq!((p.name.as_str(), p.value.as_str()), ("", "1"));
        assert!(inject_payload(get, &p, "a b=").starts_with("GET /s?q=1&a%20b%3D=1 HTTP/1.1\r\n"));
        assert!(inject(&get.replace("?q=1", ""), &p, "z").starts_with("GET /s?z=1 HTTP/1.1\r\n"));
        assert_eq!(p.describe(), "name of an arbitrarily supplied URL parameter");
        // POST form: the body name first, then the URL name.
        let form = "POST /f HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=1";
        assert_eq!(names(form), vec![IpKind::ParamName(NameSite::Body), IpKind::ParamName(NameSite::Url)]);
        let p = insertion_points(form).into_iter().find(|p| p.kind == IpKind::ParamName(NameSite::Body)).unwrap();
        let r = inject_payload(form, &p, "x'");
        assert_eq!(body_of(&r), "a=1&x'=1");
        assert!(r.contains("Content-Length: 8\r\n"));
        assert_eq!(p.describe(), "name of an arbitrarily supplied body parameter");
        // POST multipart: a part named by the payload, `"` escaped (burp.Zr87).
        let mp = "--B\r\nContent-Disposition: form-data; name=\"t\"\r\n\r\nhi\r\n--B--\r\n";
        let req = format!("POST /u HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=B\r\nContent-Length: {}\r\n\r\n{mp}", mp.len());
        assert_eq!(names(&req), vec![IpKind::ParamName(NameSite::Multipart), IpKind::ParamName(NameSite::Url)]);
        let p = insertion_points(&req).into_iter().find(|p| p.kind == IpKind::ParamName(NameSite::Multipart)).unwrap();
        let r = inject_payload(&req, &p, "a\"b");
        assert!(body_of(&r).ends_with("hi\r\n--B\r\nContent-Disposition: form-data; name=\"a\\\"b\"\r\n\r\n1\r\n--B--\r\n"), "{r}");
        // A .php path also gets `/1` path info (typed as a URL parameter name).
        let php = "GET /app/index.PHP?x=1 HTTP/1.1\r\nHost: h\r\n\r\n";
        assert_eq!(names(php), vec![IpKind::ParamName(NameSite::Url), IpKind::ParamName(NameSite::PhpPathInfo)]);
        let p = insertion_points(php).into_iter().find(|p| p.kind == IpKind::ParamName(NameSite::PhpPathInfo)).unwrap();
        assert!(inject_payload(php, &p, "../x").starts_with("GET /app/index.PHP/..%2Fx?x=1 HTTP/1.1\r\n"));
    }

    #[test]
    fn vetoes_follow_zwez() {
        let inner = b64("a=1&b=2");
        let req = format!("GET /p?data={inner} HTTP/1.1\r\nHost: h\r\nCookie: _ga={inner}\r\n\r\n");
        let all = insertion_points(&req);
        // The skip-listed cookie takes its nested points with it (Zb9c).
        assert!(all.iter().all(|p| p.chain().iter().all(|q| q.name != "_ga")));
        assert!(all.iter().any(|p| p.kind == IpKind::Base64 { url: false }));
        // Nested points off: no Base64 / nested points.
        let mut cfg = ScanConfig::default();
        cfg.disabled_insertion.insert(crate::scan_config::NESTED_KEY.into());
        assert!(audit_points(&req, &cfg).iter().all(|p| p.parent.is_none()));
        // URL parameters off: the parameter and everything nested in it go
        // (Zgai checks the parent), the nested toggle notwithstanding.
        let mut cfg = ScanConfig::default();
        cfg.disabled_insertion.insert("url".into());
        let pts = audit_points(&req, &cfg);
        assert!(pts.iter().all(|p| p.kind != IpKind::Query && p.parent.is_none()), "{:?}", summary(&pts));
        // The new types have their own switches.
        let mut cfg = ScanConfig::default();
        cfg.disabled_insertion.insert("param_name".into());
        assert!(!audit_points(&req, &cfg).iter().any(|p| matches!(p.kind, IpKind::ParamName(_))));
        // A configuration saved before D-11 (no new keys) has them on.
        let old = ScanConfig { disabled_insertion: ["header".to_string()].into_iter().collect(), ..Default::default() };
        let pts = audit_points(&req, &old);
        assert!(pts.iter().any(|p| matches!(p.kind, IpKind::ParamName(_))) && pts.iter().any(|p| p.parent.is_some()));
    }

    #[test]
    fn server_side_skip_list_gates_server_side_checks_only() {
        let sid = b64("user=1&r=2");
        let req = format!("GET /p HTTP/1.1\r\nHost: h\r\nCookie: PHPSESSID=abc123; JSESSIONID=x9; theme={sid}\r\n\r\n");
        let pts = insertion_points(&req);
        let cfg = ScanConfig::default();
        let php = pts.iter().find(|p| p.name == "PHPSESSID").unwrap();
        assert!(php.skips_server_side(), "cookie PHPSESSID, matched ignoring case as Burp's `is` rules do");
        // burp.Zi6p (XSS and template injection), Zppj, Zx8l, Zp3a, Zxfo,
        // Zwkf, Zp7s, Zexx, Zgcg are server-side: none runs on PHPSESSID.
        for check in [&ck::ReflectedXss as &dyn ck::PointCheck, &ck::StoredXss, &ck::TemplateInjection, &ck::SqlErrorInjection, &ck::SqlBooleanInjection, &ck::OsCommandInjection, &ck::PathTraversal, &ck::FilePathManipulation, &ck::ExternalInteraction, &ck::LdapInjection, &ck::XmlInjectionError, &ck::SsiInjection, &ck::SmtpHeaderInjection] {
            assert!(!check_applies(check, php, &cfg), "{} runs on PHPSESSID", check.id());
        }
        // The checks with no Zgx0.Zr test still run (Zr02, Zb_5, Zuag, Zwi, Zrmh).
        for check in [&ck::InputReflected as &dyn ck::PointCheck, &ck::LinkManipulation, &ck::OpenRedirect, &ck::HeaderInjection, &ck::ClientTemplateInjection] {
            assert!(check_applies(check, php, &cfg), "{} skipped on PHPSESSID", check.id());
        }
        // `jsessionid` is an any_parameter rule; an ordinary cookie is not listed.
        assert!(pts.iter().find(|p| p.name == "JSESSIONID").unwrap().skips_server_side());
        let theme = pts.iter().find(|p| p.name == "theme" && p.parent.is_none()).unwrap();
        assert!(!theme.skips_server_side() && check_applies(&ck::SqlErrorInjection, theme, &cfg));
        // Only the point itself is matched (Ziqf.Zr): a Base64 value under a
        // listed cookie is a BASE64 point, which the cookie rule does not cover.
        let req = format!("GET /p HTTP/1.1\r\nHost: h\r\nCookie: PHPSESSID={sid}\r\n\r\n");
        let pts = insertion_points(&req);
        let nested = pts.iter().find(|p| p.kind == IpKind::Base64 { url: false }).unwrap();
        assert!(!nested.skips_server_side());
        assert!(check_applies(&ck::SqlErrorInjection, nested, &cfg));
        // Body rules cover form parameters, not JSON ones.
        let form = "POST / HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n__VIEWSTATE=x";
        assert!(insertion_points(form).iter().find(|p| p.name == "__VIEWSTATE").unwrap().skips_server_side());
        let json = "POST / HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"__viewstate\":\"x\"}";
        assert!(!insertion_points(json).iter().find(|p| p.name == "__viewstate").unwrap().skips_server_side());
    }

    #[test]
    fn point_types_decide_per_check() {
        let cfg = ScanConfig::default();
        let name = InsertionPoint::new(IpKind::ParamName(NameSite::Url), "", "1");
        let body = InsertionPoint::new(IpKind::EntireBody, "", "{}");
        // burp.Zx8l / Zibp.ZU / Zibp.ZZ / Zp7s refuse parameter names.
        for check in [&ck::OsCommandInjection as &dyn ck::PointCheck, &ck::ExternalInteraction, &ck::PathTraversal, &ck::FilePathManipulation, &ck::XmlInjectionError, &ck::XmlInjectionOob] {
            assert!(!check_applies(check, &name, &cfg), "{}", check.id());
            assert!(check_applies(check, &body, &cfg), "{}", check.id());
        }
        // Checks without a type rule take every kind.
        for check in [&ck::ReflectedXss as &dyn ck::PointCheck, &ck::SqlErrorInjection, &ck::SsiInjection, &ck::InputReflected] {
            assert!(check_applies(check, &name, &cfg) && check_applies(check, &body, &cfg), "{}", check.id());
        }
        // PHP code injection stays on file-upload parts.
        assert!(!check_applies(&ck::PhpCodeInjection, &body, &cfg));
    }

    #[test]
    fn wording_follows_zsg0() {
        let pt = |kind: IpKind, name: &str| InsertionPoint::new(kind, name, "v");
        assert_eq!(pt(IpKind::Query, "q").describe(), "value of the q request parameter");
        assert_eq!(pt(IpKind::Query, "q").describe_short(true), "<b>q</b> parameter");
        assert_eq!(pt(IpKind::Cookie, "sid").describe(), "value of the sid cookie");
        assert_eq!(pt(IpKind::Header, "User-Agent").describe_short(false), "User-Agent HTTP header");
        assert_eq!(pt(IpKind::Json(vec!["k".into()]), "k").describe(), "value of the k JSON parameter");
        assert_eq!(pt(IpKind::XmlAttr { start: 0, end: 0 }, "id").describe(), "value of the id XML attribute");
        assert_eq!(pt(IpKind::EntireBody, "").describe(), "value of the request body");
        assert_eq!(pt(IpKind::EntireBody, "").describe_short(false), "request body");
        assert_eq!(pt(IpKind::ParamName(NameSite::Multipart), "").describe(), "name of an arbitrarily supplied body parameter");
        assert_eq!(pt(IpKind::PathFolder(0), "URL path folder 1").describe(), "value of the URL path folder 1");
        assert_eq!(pt(IpKind::PathFilename(1), "URL path filename").describe(), "value of the URL path filename");
        // Two levels: " within the " (or " of the " after a Base64 level).
        let parent = pt(IpKind::Cookie, "c");
        let child = InsertionPoint::nested(&parent, IpKind::Query, "a", "1");
        assert_eq!(child.describe(), "value of the a request parameter within the c cookie");
        let b = InsertionPoint::nested(&parent, IpKind::Base64 { url: true }, "c", "x");
        assert_eq!(b.describe_short(false), "Base64Url-decoded value of the c cookie");
    }

    #[test]
    fn hostile_xml_and_nesting_never_panic() {
        for body in ["<", "<a", "<a b=\"", "<a b='x' c", "</", "<!--", "<![CDATA[x", "<a/><b / ><é x=\"é\"/>", "<a>é</a", "<>", "< / >"] {
            let req = format!("POST / HTTP/1.1\r\nHost: h\r\nContent-Type: text/xml\r\n\r\n{body}");
            for p in insertion_points(&req) {
                let _ = inject_payload(&req, &p, "<x>");
            }
        }
        // Base64 of Base64 of ...: the walk ends and stays bounded.
        let mut v = "a=1&b=2".to_string();
        for _ in 0..12 {
            v = b64(&v);
        }
        let req = format!("GET /?d={v} HTTP/1.1\r\nHost: h\r\n\r\n");
        let pts = insertion_points(&req);
        assert!(pts.len() <= MAX_INSERTION_POINTS && pts.iter().filter(|p| p.parent.is_some()).count() >= 12);
        for p in &pts {
            let _ = inject_payload(&req, p, "'");
        }
    }

    #[test]
    fn collaborator_slots_follow_the_scan_points() {
        // With URL parameters off, slot #k must name the scan's point k: the
        // dropped query parameter shifts every later point down by one.
        let req = b"GET /p?q=1 HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut cfg = ScanConfig::default();
        cfg.disabled_insertion.insert("url".into());
        let pts = audit_points(&String::from_utf8_lossy(req), &cfg);
        assert_eq!((pts[0].kind.clone(), pts[0].name.as_str()), (IpKind::ParamName(NameSite::Url), ""));
        let slots = crate::scan::slots_for(req, crate::scan::ScanSpeed::Normal, &cfg);
        assert!(!slots.iter().any(|s| s.starts_with("#0:")), "no out-of-band check runs on the name point: {slots:?}");
        assert_eq!(pts[1].name, "Referer");
        assert!(slots.contains(&"#1:ext".to_string()), "{slots:?}");
    }
}
