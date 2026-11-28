use std::cell::RefCell;

use super::*;

// ---------------------------------------------------------------- GraphQL

/// How a GraphQL request carries its query (burp.Zcsb styles).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GqlStyle {
    /// POST, `{"query": ...}`, `application/json; charset=utf-8`.
    Json,
    /// GET with a `query` URL parameter, no Content-Type.
    Get,
    /// POST, `query=...` as `application/x-www-form-urlencoded`.
    Form,
}

/// The GraphQL query of a request (burp.Zeuo.ZH): a JSON body's "query"
/// string, else a `query` URL or form parameter; with its style.
pub(crate) fn graphql_query(req: &[u8]) -> Option<(String, GqlStyle)> {
    let p = util::parse_http(req);
    let body = &req[p.head_len.min(req.len())..];
    if let Ok(serde_json::Value::Object(m)) = serde_json::from_slice::<serde_json::Value>(body)
        && let Some(q) = m.get("query").and_then(|q| q.as_str())
    {
        return Some((q.to_string(), GqlStyle::Json));
    }
    let param = |text: &str| {
        text.split('&').find_map(|kv| {
            kv.split_once('=')
                .filter(|(k, _)| *k == "query")
                .map(|(_, v)| util::url_decode(&v.replace('+', " ")))
        })
    };
    if let Some(q) = p.path.split_once('?').and_then(|(_, q)| param(q)) {
        return Some((q, GqlStyle::Get));
    }
    param(&String::from_utf8_lossy(body)).map(|q| (q, GqlStyle::Form))
}

/// A GraphQL response (burp.Zeuo.Ze): a JSON object with "data" or "errors".
pub(crate) fn graphql_response(resp: &[u8]) -> Option<serde_json::Map<String, serde_json::Value>> {
    let (_, body) = status_body(resp);
    match serde_json::from_slice::<serde_json::Value>(body).ok()? {
        serde_json::Value::Object(m) if m.contains_key("data") || m.contains_key("errors") => {
            Some(m)
        }
        _ => None,
    }
}

/// burp.Zeuo.Za: `data.__schema` with at least one introspection field.
pub(crate) fn has_introspection(m: &serde_json::Map<String, serde_json::Value>) -> bool {
    m.get("data")
        .and_then(|d| d.get("__schema"))
        .and_then(|s| s.as_object())
        .is_some_and(|s| {
            [
                "queryType",
                "mutationType",
                "subscriptionType",
                "types",
                "directives",
            ]
            .iter()
            .any(|k| s.contains_key(*k))
        })
}

/// The base request rewritten to send `query` in `style` to the same path.
pub fn graphql_request(cx: &ScanCtx, query: &str, style: GqlStyle) -> Vec<u8> {
    let path = cx.entry.path.split('?').next().unwrap_or("/").to_string();
    graphql_request_to(cx, &path, query, style)
}

/// A request sending `query` in `style` to `path` on the scanned host.
pub fn graphql_request_to(cx: &ScanCtx, path: &str, query: &str, style: GqlStyle) -> Vec<u8> {
    match style {
        GqlStyle::Json => host_request(
            cx,
            "POST",
            path,
            &[("Content-Type", "application/json; charset=utf-8")],
            serde_json::json!({ "query": query }).to_string().as_bytes(),
        ),
        GqlStyle::Get => host_request(
            cx,
            "GET",
            &format!(
                "{path}?query={}",
                crate::scan::insertion::encode_url_param(query)
            ),
            &[],
            b"",
        ),
        GqlStyle::Form => host_request(
            cx,
            "POST",
            path,
            &[("Content-Type", "application/x-www-form-urlencoded")],
            format!("query={}", crate::scan::insertion::encode_url_param(query)).as_bytes(),
        ),
    }
}

/// The existing exchange, when it is GraphQL (query in the request and a
/// GraphQL response), with the query style.
pub fn graphql_exchange(cx: &ScanCtx) -> Option<GqlStyle> {
    let (_, style) = graphql_query(cx.req.as_bytes())?;
    graphql_response(&cx.baseline.raw)?;
    Some(style)
}

pub fn graphql_issue(cx: &ScanCtx, name: &str, detail: String, ev: Vec<ScanEvidence>) -> ScanIssue {
    // Zmzr / Zgg2 / Zgck: Low, Certain.
    let mut i = mk("low", name, &cx.entry, detail).with_evidence(ev);
    i.confidence = "Certain".into();
    i
}

/// The paths Burp probes for a GraphQL endpoint (burp.Zeuo.Zc, decoded).
pub(crate) const GRAPHQL_PATHS: [&str; 13] = [
    "/graphql",
    "/api",
    "/api/graphql",
    "/graphql/api",
    "/graphql/graphql",
    "/v1/api",
    "/v1/api/graphql",
    "/api/v1",
    "/api/graphql/v1",
    "/v1/graphql/api",
    "/graphql/api/v1",
    "/v1/graphql",
    "/graphql/v1",
];

/// GraphQL endpoint discovered, burp.Zmzj (per host): `query{__typename}`
/// sent to each path of Zeuo.Zc as GET, JSON POST and form POST; every
/// path with a GraphQL answer is reported with its successful exchanges
/// (Zb9m.ZA: Information, Certain). Burp's exact variant list (Zmzj.Za)
/// is only known from its decoded literals (GET, POST, the JSON
/// content type).
pub(crate) struct GraphqlEndpointDiscovered;

impl RequestCheck for GraphqlEndpointDiscovered {
    fn id(&self) -> &'static str {
        "active.graphql-endpoint-discovered"
    }
    fn issue(&self) -> &'static str {
        "GraphQL endpoint discovered"
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn run(&self, cx: &ScanCtx) {
        let (scheme, _) = origin_of(cx);
        if cx.stopped()
            || !cx.runs(self.issue())
            || !cx
                .state()
                .openapi_hosts
                .lock()
                .insert(format!("graphql|{scheme}://{}:{}", cx.host, cx.port))
        {
            return;
        }
        for path in GRAPHQL_PATHS {
            let mut ok = Vec::new();
            for style in [GqlStyle::Get, GqlStyle::Json, GqlStyle::Form] {
                if cx.stopped() {
                    return;
                }
                let req = graphql_request_to(cx, path, "query{__typename}", style);
                let Some(resp) = burp_send(cx, &req) else {
                    continue;
                };
                if graphql_response(&resp).is_some() {
                    ok.push(ScanEvidence::new(&req, Some(&resp)));
                }
            }
            if !ok.is_empty() {
                let mut e = cx.entry.clone();
                e.path = path.to_string();
                let mut i = mk(
                    "info",
                    self.issue(),
                    &e,
                    format!(
                        "A GraphQL endpoint was found at <b>{}</b>: it answered a GraphQL query.",
                        util::html_encode(path)
                    ),
                )
                .with_evidence(ok);
                i.confidence = "Certain".into();
                cx.report(vec![i]);
            }
        }
    }
}

/// GraphQL introspection enabled, burp.Zgd9 (per request): the existing
/// response already shows the schema, or the introspection query
/// (burp.Zuj2.ZQ, the standard one) returns `data.__schema`.
pub(crate) struct GraphqlIntrospection;

/// The standard GraphQL introspection query (Burp sends the same one).
pub(crate) const INTROSPECTION_QUERY: &str = "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }";

impl RequestCheck for GraphqlIntrospection {
    fn id(&self) -> &'static str {
        "active.graphql-introspection"
    }
    fn issue(&self) -> &'static str {
        "GraphQL introspection enabled"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped() || !cx.runs(self.issue()) {
            return;
        }
        let Some(style) = graphql_exchange(cx) else {
            return;
        };
        let detail =
            "The GraphQL endpoint answers introspection queries, which disclose its whole schema."
                .to_string();
        if graphql_response(&cx.baseline.raw).is_some_and(|m| has_introspection(&m)) {
            cx.report(vec![graphql_issue(
                cx,
                self.issue(),
                detail,
                vec![ScanEvidence::new(cx.req.as_bytes(), Some(&cx.baseline.raw))],
            )]);
            return;
        }
        let req = graphql_request(cx, INTROSPECTION_QUERY, style);
        let Some(resp) = burp_send(cx, &req) else {
            return;
        };
        if graphql_response(&resp).is_some_and(|m| has_introspection(&m)) {
            cx.report(vec![graphql_issue(
                cx,
                self.issue(),
                detail,
                vec![ScanEvidence::new(&req, Some(&resp))],
            )]);
        }
    }
}

/// GraphQL suggestions enabled, burp.Zbop (per request): `query{__type}`
/// answered by a GraphQL response holding "must have a selection of
/// subfields. Did you mean".
pub(crate) struct GraphqlSuggestions;

impl RequestCheck for GraphqlSuggestions {
    fn id(&self) -> &'static str {
        "active.graphql-suggestions"
    }
    fn issue(&self) -> &'static str {
        "GraphQL suggestions enabled"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped() || !cx.runs(self.issue()) {
            return;
        }
        let Some(style) = graphql_exchange(cx) else {
            return;
        };
        let req = graphql_request(cx, "query{__type}", style);
        let Some(resp) = burp_send(cx, &req) else {
            return;
        };
        if graphql_response(&resp).is_some()
            && find_sub(
                status_body(&resp).1,
                b"must have a selection of subfields. Did you mean",
            )
        {
            cx.report(vec![graphql_issue(cx, self.issue(), "The GraphQL endpoint suggests field names in its error messages, which can disclose its schema even with introspection disabled.".into(), vec![ScanEvidence::new(&req, Some(&resp))])]);
        }
    }
}

/// GraphQL content type not validated, burp.Zx85 (per request): the query
/// sent as a GET parameter (for a POST request) and as a URL-encoded form
/// body; a variant that gets a GraphQL response is confirmed with
/// `query{__typename}` (its answer must carry data.__typename) and the
/// first variant's exchange is reported.
pub(crate) struct GraphqlContentType;

impl RequestCheck for GraphqlContentType {
    fn id(&self) -> &'static str {
        "active.graphql-content-type"
    }
    fn issue(&self) -> &'static str {
        "GraphQL content type not validated"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped() || !cx.runs(self.issue()) {
            return;
        }
        let Some(_) = graphql_exchange(cx) else {
            return;
        };
        let Some((query, style)) = graphql_query(cx.req.as_bytes()) else {
            return;
        };
        let post = util::parse_http(cx.req.as_bytes())
            .method
            .eq_ignore_ascii_case("POST");
        let mut styles = Vec::new();
        if post && style != GqlStyle::Get {
            styles.push(GqlStyle::Get);
        }
        if style != GqlStyle::Form {
            styles.push(GqlStyle::Form);
        }
        for s in styles {
            if cx.stopped() {
                return;
            }
            let req = graphql_request(cx, &query, s);
            let Some(resp) = burp_send(cx, &req) else {
                continue;
            };
            if graphql_response(&resp).is_none() {
                continue;
            }
            let confirm = graphql_request(cx, "query{__typename}", s);
            let Some(cr) = burp_send(cx, &confirm) else {
                continue;
            };
            if graphql_response(&cr)
                .is_some_and(|m| m.get("data").and_then(|d| d.get("__typename")).is_some())
            {
                let how = if s == GqlStyle::Get {
                    "as a GET request with the query in the URL"
                } else {
                    "as a POST request with a URL-encoded body (application/x-www-form-urlencoded)"
                };
                cx.report(vec![graphql_issue(cx, self.issue(), format!("The GraphQL endpoint also accepted the query sent {how}, so it does not validate the request's content type; this can make cross-site request forgery possible."), vec![ScanEvidence::new(&req, Some(&resp))])]);
                return;
            }
        }
    }
}

/// The request without header `name` (any case).
pub fn without_header(raw: &[u8], name: &str) -> Vec<u8> {
    let Some(end) = util::find_head_end(raw) else {
        return raw.to_vec();
    };
    let head = String::from_utf8_lossy(&raw[..end]);
    let mut out = String::new();
    for (i, line) in head.split("\r\n").enumerate() {
        if i > 0
            && line
                .split_once(':')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        {
            continue;
        }
        if line.is_empty() {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut v = out.into_bytes();
    v.extend_from_slice(&raw[end..]);
    v
}

/// Spoofable client IP address, response-diffing half of Burp's check
/// (burp.Zxlc over Zxld / Zmaq, APR_XForwardedDependentResponse, per
/// request): the request without X-Forwarded-For and the request with
/// `X-Forwarded-For: 127.0.0.1` are sent alternately for the accuracy's
/// rounds; reported when their responses stay distinguishable (the base
/// response counts with the "without" side). Zf9t.ZV: Information;
/// confidence Firm or Tentative by Zex1.Zg (not established: Tentative
/// here). Burp's detail text for this variant was not recovered. The
/// Collaborator half (burp.Zc7h, Zwv9 text) is not ported.
pub(crate) struct SpoofableClientIp;

impl RequestCheck for SpoofableClientIp {
    fn id(&self) -> &'static str {
        "active.spoofable-client-ip"
    }
    fn issue(&self) -> &'static str {
        "Spoofable client IP address"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped() || !cx.runs(self.issue()) || cx.baseline.raw.is_empty() {
            return;
        }
        let without = without_header(cx.req.as_bytes(), "X-Forwarded-For");
        let with = crate::util::replace_or_add_header(&without, "X-Forwarded-For", "127.0.0.1");
        let fp = crate::variations::fingerprint;
        let (Some(a0), Some(b0)) = (burp_send(cx, &without), burp_send(cx, &with)) else {
            return;
        };
        let mut c = crate::variations::Comparator::new(&fp(&a0), &fp(&b0));
        c.add_a(&fp(&cx.baseline.raw));
        if !c.distinguishable() {
            return;
        }
        let (mut last_a, mut last_b) = (a0, b0);
        for _ in 1..cx.settings.accuracy.rounds() {
            if cx.stopped() {
                return;
            }
            let (Some(a), Some(b)) = (burp_send(cx, &without), burp_send(cx, &with)) else {
                return;
            };
            c.add_a(&fp(&a));
            c.add_b(&fp(&b));
            if !c.distinguishable() {
                return;
            }
            (last_a, last_b) = (a, b);
        }
        let mut i = mk(
            "info",
            self.issue(),
            &cx.entry,
            format!("It may be possible for clients to spoof their IP address using the X-Forwarded-For HTTP header.<br><br>The response changed consistently when the header <b>X-Forwarded-For: 127.0.0.1</b> was added to the request (attributes: {:?}).", c.attributes()),
        )
        .with_evidence(vec![ScanEvidence::new(&without, Some(&last_a)), ScanEvidence::new(&with, Some(&last_b))]);
        i.confidence = "Tentative".into();
        cx.report(vec![i]);
    }
}

/// Remove `authorization`, `cookie` and `x-*` headers — except
/// `x-requested-with` — from a raw request (burp.Zii_.java:25-64),
/// returning the rewritten request and the names removed.
/// Bare-LF headers are not stripped; this helper expects CRLF.
fn strip_auth_headers(raw: &[u8]) -> (Vec<u8>, Vec<String>) {
    let Some(end) = util::find_head_end(raw) else {
        return (raw.to_vec(), Vec::new());
    };
    let head = String::from_utf8_lossy(&raw[..end]);
    let mut out = String::new();
    let mut removed = Vec::new();
    for (i, line) in head.split("\r\n").enumerate() {
        if line.is_empty() {
            continue;
        }
        if i > 0
            && let Some((k, _)) = line.split_once(':')
        {
            let k = k.trim();
            let drop = k.eq_ignore_ascii_case("authorization")
                || k.eq_ignore_ascii_case("cookie")
                || (k.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("x-"))
                    && !k.eq_ignore_ascii_case("x-requested-with"));
            if drop {
                removed.push(k.to_string());
                continue;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut v = out.into_bytes();
    v.extend_from_slice(&raw[end..]);
    (v, removed)
}

/// Total JSON nodes in a body (0 when the body is not JSON): Burp's
/// equivalence metric counts parsed nodes either way (Zcxn.java:74-92).
fn json_node_count(body: &[u8]) -> i64 {
    fn count(v: &serde_json::Value) -> i64 {
        1 + match v {
            serde_json::Value::Array(a) => a.iter().map(count).sum(),
            serde_json::Value::Object(m) => m.values().map(count).sum(),
            _ => 0,
        }
    }
    serde_json::from_slice::<serde_json::Value>(body)
        .map(|v| count(&v))
        .unwrap_or(0)
}

/// The text of the first <title> element, trimmed ("" when none).
fn page_title(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_lowercase();
    let Some(s) = lower.find("<title") else {
        return String::new();
    };
    let Some(gt) = lower[s..].find('>') else {
        return String::new();
    };
    let start = s + gt + 1;
    let Some(e) = lower[start..].find("</title") else {
        return String::new();
    };
    text[start..start + e].trim().to_string()
}

/// Burp's broken-access-control equivalence (Zcxn.java:74-92,117-123):
/// same status, same JSON node count, and — for an HTML reference — the
/// same page title, otherwise the same line count.
fn bac_equivalent(reference: &[u8], candidate: &[u8]) -> bool {
    let pa = util::parse_http(reference);
    let pb = util::parse_http(candidate);
    let status_a = pa.first.split_whitespace().nth(1).unwrap_or("");
    let status_b = pb.first.split_whitespace().nth(1).unwrap_or("");
    if status_a != status_b {
        return false;
    }
    let body_a = &reference[pa.head_len.min(reference.len())..];
    let body_b = &candidate[pb.head_len.min(candidate.len())..];
    if json_node_count(body_a) != json_node_count(body_b) {
        return false;
    }
    let html = util::get_header(&pa.headers, "Content-Type")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("html");
    if html {
        page_title(body_a) == page_title(body_b)
    } else {
        body_a.iter().filter(|b| **b == b'\n').count()
            == body_b.iter().filter(|b| **b == b'\n').count()
    }
}

/// Broken access control, the established core of burp.Zcxn
/// (APR_BrokenAccessControl, in-session per request, KB 00100850):
/// the request with a fresh random URL parameter, and the same request
/// with authorization/cookie/x-* headers removed (x-requested-with kept,
/// Zii_.java:25-64), are sent for eight rounds; reported when every
/// round's responses stay equivalent — removing the session changed
/// nothing. Zr0k.java:20-59 builds the issue with both exchanges.
/// Information (KB); confidence not established: Tentative here.
/// Guards WebProbe adds because Burp's own preconditions are stripped:
/// the base response must be 2xx (a request the session already fails
/// proves nothing) and some header must actually be removed.
/// Not established and omitted: the accepted content-type set ZP, the
/// minimize-false-negatives / false-positive-reduction configuration
/// gating, and the Zbwz browser/session verdicts.
pub(crate) struct BrokenAccessControl;

impl RequestCheck for BrokenAccessControl {
    fn id(&self) -> &'static str {
        "active.broken-access-control"
    }
    fn issue(&self) -> &'static str {
        "Broken access control"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped() || !cx.runs(self.issue()) || cx.baseline.raw.is_empty() {
            return;
        }
        // Replay GET only. HEAD has no body for equivalence checks, and
        // POST or other methods could repeat application side effects.
        let method = cx.req.split_whitespace().next().unwrap_or("");
        if !method.eq_ignore_ascii_case("GET") {
            return;
        }
        let base = util::parse_http(&cx.baseline.raw);
        let status: u16 = base
            .first
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status) {
            return;
        }
        let mut pair = None;
        let mut removed_names = Vec::new();
        for round in 0..8 {
            if cx.stopped() {
                return;
            }
            let marker = rnd_letters(8);
            let full = super::cache::with_query_param(cx.req.as_bytes(), &marker, &marker);
            let (stripped, removed) = strip_auth_headers(&full);
            if removed.is_empty() {
                return;
            }
            let (Some(a), Some(b)) = (burp_send(cx, &full), burp_send(cx, &stripped)) else {
                return;
            };
            if !bac_equivalent(&a, &b) {
                return;
            }
            if round == 0 {
                pair = Some((full, stripped, a, b));
                removed_names = removed;
            }
        }
        let Some((full, stripped, a, b)) = pair else {
            return;
        };
        let mut i = mk(
            "info",
            self.issue(),
            &cx.entry,
            format!("The application appears not to enforce access control on this request.<br><br>Removing the session material (<b>{}</b>) left the response equivalent to the authenticated response over eight rounds (status, page title / line count and JSON structure), so the resource appears to be reachable without authentication.", removed_names.join(", ")),
        )
        .with_evidence(vec![ScanEvidence::new(&full, Some(&a)), ScanEvidence::new(&stripped, Some(&b))]);
        i.confidence = "Tentative".into();
        cx.report(vec![i]);
    }
}

/// burp.Zxly.java:34-45: does this User-Agent look mobile?
pub(crate) fn ua_looks_mobile(ua: &str) -> bool {
    let ua = ua.to_ascii_lowercase();
    [
        "iphone",
        "android",
        "blackberry",
        "htc",
        "symbian",
        "nokia",
        "samsung",
        "mot",
        "sonyericsson",
    ]
    .iter()
    .any(|t| ua.contains(t))
}

/// burp.Zxly.java:29-46: the swapped User-Agent - a desktop request gets the
/// iPhone string, a mobile request the IE9 string.
pub(crate) fn ua_variant(existing: Option<&str>) -> &'static str {
    match existing {
        Some(ua) if ua_looks_mobile(ua) => {
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
        }
        _ => {
            "Mozilla/5.0 (iPhone; CPU iPhone OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B176 Safari/7534.48.3"
        }
    }
}

/// Referer-dependent and User agent-dependent response (per request),
/// burp.Zxlg / burp.Zxly over the shared burp.Zxld/Zmaq comparison, the
/// same shape as `SpoofableClientIp`: the request with the header swapped
/// must stay distinguishable from the base request for the accuracy's
/// rounds (4/6/10 - Zxld's counts). burp.Zg4d's removal variant is the
/// base request itself when the header is absent. Bounded: two sends per
/// round, no other traffic.
pub(crate) struct HeaderDependent {
    pub user_agent: bool,
}

impl RequestCheck for HeaderDependent {
    fn id(&self) -> &'static str {
        if self.user_agent {
            "active.user-agent-dependent-response"
        } else {
            "active.referer-dependent-response"
        }
    }
    fn issue(&self) -> &'static str {
        if self.user_agent {
            "User agent-dependent response"
        } else {
            "Referer-dependent response"
        }
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped() || !cx.runs(self.issue()) || cx.baseline.raw.is_empty() {
            return;
        }
        let (header, swapped) = if self.user_agent {
            let existing = util::get_header(&cx.parts.headers, "User-Agent");
            ("User-Agent", ua_variant(existing.as_deref()).to_string())
        } else {
            // burp.Zxlg's static replacement is stripped from the readable
            // source; its fragments are "http://" and ".com/". Any foreign
            // origin serves the differential.
            ("Referer", "http://www.google.com/".to_string())
        };
        let base = cx.req.as_bytes().to_vec();
        let changed = crate::util::replace_or_add_header(&base, header, &swapped);
        let fp = crate::variations::fingerprint;
        let (Some(a0), Some(b0)) = (burp_send(cx, &base), burp_send(cx, &changed)) else {
            return;
        };
        let mut c = crate::variations::Comparator::new(&fp(&a0), &fp(&b0));
        c.add_a(&fp(&cx.baseline.raw));
        if !c.distinguishable() {
            return;
        }
        let (mut last_a, mut last_b) = (a0, b0);
        for _ in 1..cx.settings.accuracy.rounds() {
            if cx.stopped() {
                return;
            }
            let (Some(a), Some(b)) = (burp_send(cx, &base), burp_send(cx, &changed)) else {
                return;
            };
            c.add_a(&fp(&a));
            c.add_b(&fp(&b));
            if !c.distinguishable() {
                return;
            }
            (last_a, last_b) = (a, b);
        }
        let mut i = mk(
            "info",
            self.issue(),
            &cx.entry,
            format!("The response changed consistently when the header <b>{header}</b> was swapped for <b>{swapped}</b> (attributes: {:?}).", c.attributes()),
        )
        .with_evidence(vec![
            ScanEvidence::new(&base, Some(&last_a)),
            ScanEvidence::new(&changed, Some(&last_b)),
        ]);
        i.confidence = "Tentative".into();
        cx.report(vec![i]);
    }
}

/// The backup-file names Burp tries for a file name (`stem` + `ext`, the
/// extension with its dot), from the decoded literals of its four
/// mutation families: burp.Zxc6 (prefixes), Zxfn (suffixes before the
/// extension), Zsro (JSP extension swaps) and Zem7 / Zu7n ("~" appended).
/// Spaces are sent as %20, as Burp's literals have them. Burp's generic
/// extension list (Zebr.ZD) is stripped and not included.
pub(crate) fn backup_names(stem: &str, ext: &str) -> Vec<String> {
    let mut out = Vec::new();
    for p in [
        "bak_",
        "backup_",
        "old_",
        "Copy%20of%20",
        "Copy%20(2)%20of%20",
        "Copy%20of%20Copy%20of%20",
    ] {
        out.push(format!("{p}{stem}{ext}"));
    }
    for sfx in [
        "_bak",
        "_backup",
        "_old",
        "%20(copy)",
        "%20(2nd%20copy)",
        "%20(3rd%20copy)",
        "%20(4th%20copy)",
        "%20(third%20copy)",
        "%20(fourth%20copy)",
        "%20(another%20copy)",
        "%20-%20Copy",
        "%20-%20Copy%20(2)",
        "%20-%20Copy%20-%20Copy",
    ] {
        out.push(format!("{stem}{sfx}{ext}"));
    }
    if ext.eq_ignore_ascii_case(".jsp") {
        for x in [".jspa", ".jspx", ".jspf"] {
            out.push(format!("{stem}{x}"));
        }
    }
    out.push(format!("{stem}{ext}~"));
    out
}

/// Backup file (burp.Zbdu over Zem7 / Zsro / Zxc6 / Zxfn, per URL): each
/// backup name of the request's file is requested next to it; a candidate
/// answered below 400 is compared with the same mutation of a random name
/// (Burp's control), twice; reported when the two stay distinguishable.
/// Zebr.ZW: Information, Certain; both exchanges as evidence. Burp's
/// detail text was not recovered.
pub(crate) struct BackupFile;

impl RequestCheck for BackupFile {
    fn id(&self) -> &'static str {
        "active.backup-file"
    }
    fn issue(&self) -> &'static str {
        "Backup file"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped() || !cx.runs(self.issue()) {
            return;
        }
        let path = cx.entry.path.split('?').next().unwrap_or("/").to_string();
        let Some(slash) = path.rfind('/') else { return };
        let (dir, file) = (&path[..slash + 1], &path[slash + 1..]);
        if file.is_empty()
            || !cx
                .state()
                .openapi_hosts
                .lock()
                .insert(format!("backup|{}:{}{path}", cx.host, cx.port))
        {
            return;
        }
        let (stem, ext) = match file.rfind('.') {
            Some(d) if d > 0 => (&file[..d], &file[d..]),
            _ => (file, ""),
        };
        let random = rnd_letters(10);
        let fp = crate::variations::fingerprint;
        for (k, name) in backup_names(stem, ext).into_iter().enumerate() {
            if cx.stopped() {
                return;
            }
            let req = host_request(cx, "GET", &format!("{dir}{name}"), &[], b"");
            let Some(resp) = burp_send(cx, &req) else {
                continue;
            };
            if status_body(&resp).0 >= 400 {
                continue;
            }
            let control_name = backup_names(&random, ext)
                .into_iter()
                .nth(k)
                .unwrap_or_default();
            let control = host_request(cx, "GET", &format!("{dir}{control_name}"), &[], b"");
            let Some(cresp) = burp_send(cx, &control) else {
                continue;
            };
            let mut c = crate::variations::Comparator::new(&fp(&resp), &fp(&cresp));
            if !c.distinguishable() {
                continue;
            }
            let (Some(again), Some(cagain)) = (burp_send(cx, &req), burp_send(cx, &control)) else {
                continue;
            };
            c.add_a(&fp(&again));
            c.add_b(&fp(&cagain));
            if !c.distinguishable() {
                continue;
            }
            let mut e = cx.entry.clone();
            e.path = format!("{dir}{name}");
            let mut i = mk("info", self.issue(), &e, format!("A backup copy of <b>{}</b> appears to be available at <b>{}</b>: it answered differently from a request for a file that does not exist ({}).", util::html_encode(file), util::html_encode(&format!("{dir}{name}")), util::html_encode(&control_name)))
                .with_evidence(vec![ScanEvidence::new(&req, Some(&resp)), ScanEvidence::new(&control, Some(&cresp))]);
            i.confidence = "Certain".into();
            cx.report(vec![i]);
            return;
        }
    }
}

/// WebProbe's own reflected-DOM canary (Burp finds DOM issues by analysing
/// JavaScript, which is not this): a plain canary reflected unencoded into
/// script data or an attribute value of an HTML response. Also seeds the
/// stored-echo markers. A WebProbe extra check, off by default.
pub(crate) struct LightProbes;

impl PointCheck for LightProbes {
    fn id(&self) -> &'static str {
        "active.light-probes"
    }
    fn issue(&self) -> &'static str {
        "Active probe: DOM-based cross-site scripting (reflected)"
    }
    /// WebProbe's own probe (no Burp class): every kind; not a server-side check.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun) {
        let (idx, ip) = (pt.idx, pt.ip);
        if cx.stopped() {
            return;
        }
        let dom_canary = format!("wb{idx:03}dom");
        st.stored_markers
            .push((ip.name.clone(), dom_canary.clone()));
        let new_req = inject(&cx.req, ip, &format!("{}{dom_canary}", ip.value));
        if let Some(resp) = cx.send(new_req.as_bytes()) {
            let rp = util::parse_http(&resp);
            let body = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
            let ct = util::get_header(&rp.headers, "Content-Type").unwrap_or_default();
            if ct.to_ascii_lowercase().contains("html") && is_reflected_dom_hit(&body, &dom_canary)
            {
                cx.report(vec![mk(
                    "high",
                    &format!("Active probe: DOM-based cross-site scripting (reflected) via parameter {}", ip.name),
                    &cx.entry,
                    format!("Canary {dom_canary} is reflected unencoded into script data or an attribute value, a context DOM sinks can reach."),
                )
                .with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), Some(&resp[..]))])]);
            }
        }
        cx.progress();
        cx.pace(50);
    }
}

/// OS command injection, Burp's Collaborator flow (burp.Zc99 payloads,
/// burp.Zfw7 verdict). Each `nslookup -q=cname` payload carries its own
/// Collaborator id; a DNS CNAME lookup of that id (burp.Zing.ZR) raises "OS
/// command injection", high and firm (burp.Zwvy.ZR: Zrh confidence 2,
/// severity 4). Burp's other flow (burp.Zxom, `ping` delays) is timing-based
/// and not ported. Runs only when the scan has Collaborator ids.
pub(crate) struct OsCommandInjection;

impl PointCheck for OsCommandInjection {
    fn id(&self) -> &'static str {
        "active.os-command-injection"
    }
    fn issue(&self) -> &'static str {
        "OS command injection"
    }
    /// burp.Zx8l.Zh: never on added parameter names (Zxt3.ZD), nor on a value `true` / `false` (any case). Server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::ParamName(_) => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => !is_bool_word(&ip.decoded_value()),
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun) {
        let (idx, ip) = (pt.idx, pt.ip);
        let mut ids = std::collections::HashMap::new();
        let payloads = active_checks::os_cmd_payloads(cx.settings.speed, |slot| {
            let (_, token, domain) = oob_slot(&cx.oob, idx, &ip.name, slot, &mut st.oob_used)?;
            ids.insert(slot.to_string(), token.clone());
            Some(domain.clone())
        });
        for (slot, payload, append) in payloads {
            if cx.stopped() {
                break;
            }
            let value = if append {
                format!("{}{payload}", ip.value)
            } else {
                payload.clone()
            };
            let new_req = inject_payload(&cx.req, ip, &value);
            // Through the scan's own sender: it honours pause and the
            // resource pool, as every other check does.
            let resp = cx.send(new_req.as_bytes());
            let token = ids[slot].clone();
            let issue = mk_point(
                "OS command injection",
                "high",
                "Firm",
                &cx.entry,
                ip,
                format!(
                    "The payload {payload} was {} the {}. The application performed a DNS lookup of type CNAME for the Collaborator id {token}, indicating that the injected command was executed.",
                    if append { "appended to" } else { "submitted as" },
                    ip.describe()
                ),
            )
            .with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), resp.as_deref())]);
            // burp.Zez7.Ze (NSLOOKUP_PAYLOAD) wording for an External service
            // interaction this id may raise instead (burp.Zfw7.Zr).
            let delivery = crate::oob::delivery_sentence(
                "The nslookup shell command",
                &payload,
                &ip.describe_short(true),
                ". This payload is designed to trigger a CNAME DNS lookup if the application is vulnerable to OS command injection.",
            );
            cx.shared
                .oob
                .register_delivered(token, Some("CNAME"), issue, delivery);
            cx.progress();
            cx.pace(50);
        }
    }
}

/// FILE_PATH_TRAVERSAL, Burp's own flow (burp.Zp3a).
pub(crate) struct PathTraversal;

impl PointCheck for PathTraversal {
    fn id(&self) -> &'static str {
        "active.file-path-traversal"
    }
    fn issue(&self) -> &'static str {
        "File path traversal"
    }
    /// burp.Zp3a.Zh -> Zibp.ZZ: not on parameter names or HTTP headers (Zewr.ZY cases 1-4); server-side. Zibp.Zo's value rules are not ported (it depends on Zp3a's own flag and the point's ZO(), not established).
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::ParamName(_) | IpKind::Header => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<String> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, payload);
            let resp = rec.send(cx, payload, new_req.as_bytes())?;
            let rp = util::parse_http(&resp);
            Some(String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]).into_owned())
        };
        if let Some(hit) =
            run_traversal_check(&ip.value, &cx.baseline.body, cx.settings.speed, send)
        {
            let control = traversal_control(&hit.payload);
            cx.report(vec![mk_point(
                "File path traversal",
                "high",
                "Firm",
                &cx.entry,
                ip,
                format!(
                    "Payload {:?} returned {} content (markers: {}); the negative control ({:?}) did not.",
                    encode_query_payload(&hit.payload),
                    hit.file,
                    hit.markers.join(", "),
                    encode_query_payload(&control),
                ),
            )
            .with_evidence(evidence([rec.last(&hit.payload), rec.last(&control)]))]);
        }
        cx.progress();
    }
}

/// Link manipulation (reflected) (burp.Zb_5).
pub(crate) struct LinkManipulation;

impl PointCheck for LinkManipulation {
    fn id(&self) -> &'static str {
        "active.link-manipulation"
    }
    fn issue(&self) -> &'static str {
        "Link manipulation (reflected)"
    }
    /// burp.Zb_5 has no applicability test: every kind; not server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = run_link_manip_check(&ip.value, send) {
            cx.report(vec![
                mk_point(
                    "Link manipulation (reflected)",
                    "info",
                    "Firm",
                    &cx.entry,
                    ip,
                    format!(
                        "Injected URL {:?} became a link/redirect target: {:?}.",
                        hit.payload, hit.target
                    ),
                )
                .with_evidence(evidence([rec.last(&hit.payload)])),
            ]);
        }
        cx.progress();
    }
}

/// The G.11 reflected families share burp.Zb_5's applicability (every
/// insertion-point kind, not server-side) and differ only in probe and
/// reflection context; the impls below are that shape three times.
macro_rules! g11_reflected_check {
    ($name:ident, $id:literal, $issue:literal, $severity:literal, $runner:path, $doc:literal) => {
        #[doc = $doc]
        pub(crate) struct $name;

        impl PointCheck for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn issue(&self) -> &'static str {
                $issue
            }
            fn applies_to(&self, ip: &InsertionPoint) -> bool {
                match &ip.kind {
                    IpKind::Query
                    | IpKind::Body
                    | IpKind::Json(_)
                    | IpKind::Multipart { .. }
                    | IpKind::Cookie
                    | IpKind::Header
                    | IpKind::PathFolder(_)
                    | IpKind::PathFilename(_)
                    | IpKind::EntireBody
                    | IpKind::XmlParam { .. }
                    | IpKind::XmlTag { .. }
                    | IpKind::XmlAttr { .. }
                    | IpKind::ParamName(_)
                    | IpKind::Base64 { .. } => true,
                }
            }
            fn server_side(&self) -> bool {
                false
            }
            fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
                if cx.stopped() {
                    return;
                }
                let ip = pt.ip;
                let rec = Recorder::default();
                let send = |payload: &str| -> Option<Vec<u8>> {
                    if cx.stopped() {
                        return None;
                    }
                    let new_req = inject_payload(&cx.req, ip, &payload);
                    rec.send(cx, payload, new_req.as_bytes())
                };
                if let Some((payload, context, _resp)) = $runner(send) {
                    cx.report(vec![
                        mk_point(
                            $issue,
                            $severity,
                            "Tentative",
                            &cx.entry,
                            ip,
                            format!(
                                "The injected value <b>{}</b> was reflected in {}.",
                                util::html_encode(&payload),
                                context
                            ),
                        )
                        .with_evidence(evidence([rec.last(&payload)])),
                    ]);
                }
                cx.progress();
            }
        }
    };
}

g11_reflected_check!(
    CssInjectionReflected,
    "active.css-injection",
    "CSS injection (reflected)",
    "medium",
    crate::scan::run_css_reflected,
    "CSS injection (reflected), burp.Zb_5 -> Zw0x, KB 00501300: the probe must reflect in a CSS position (<style> text, a style attribute, a <link rel=stylesheet> href). Burp's payload literal and applicable-tag map are stripped (not established): plain token, contextual detection, REPLACE only. Severity Medium (KB); confidence not established: Tentative (a single contextual reflection, no breakout confirmation)."
);
g11_reflected_check!(
    HppReflected,
    "active.client-side-hpp",
    "Client-side HTTP parameter pollution (reflected)",
    "low",
    crate::scan::run_hpp_reflected,
    "Client-side HTTP parameter pollution (reflected), burp.Zb_5 -> Zi4q, KB 00501400: a `<random3>&<random3>` pair (the stripped suffix is omitted, not established) must reflect in a URL-bearing attribute (href/src/action/formaction), JavaScript string or response header. Severity Low (KB); confidence not established: Tentative (a single contextual reflection, no confirmation probe)."
);
g11_reflected_check!(
    FormActionHijacking,
    "active.form-action-hijacking",
    "Form action hijacking (reflected)",
    "medium",
    crate::scan::run_form_action_reflected,
    "Form action hijacking (reflected), burp.Zb_5 -> Zc51, KB 00501500: an injected URL must reflect as a form's action or an element's formaction. Severity Medium (KB); confidence not established: Tentative (single request, no confirmation)."
);

/// File path manipulation (burp.Zsl1).
pub(crate) struct FilePathManipulation;

impl PointCheck for FilePathManipulation {
    fn id(&self) -> &'static str {
        "active.file-path-manipulation"
    }
    fn issue(&self) -> &'static str {
        "File path manipulation"
    }
    /// Part of burp.Zp3a (Zsl1): Zibp.ZZ type rules as PathTraversal, and
    /// Zp3a.Zw runs it only off URL path points (`!Zibp.ZR(point)`) and on a
    /// value that is not an http(s) URL (`!Zp3a.ZG()`); server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::ParamName(_)
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_) => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => {
                let v = ip.decoded_value().to_ascii_lowercase();
                !v.starts_with("http:") && !v.starts_with("https:")
            }
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() || cx.baseline.raw.is_empty() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let mut send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) =
            run_file_path_manip_check(&ip.value, &cx.baseline.raw, cx.settings.accuracy, &mut send)
        {
            // burp.Zsl1.java:111-128,179-203: demonstrate impact by pulling
            // one of Burp's known files from the selected directory.
            let known = known_file_follow_up(&ip.value, &cx.baseline.raw, &mut send);
            let detail = match &known {
                Some(k) => format!(
                    "Same-file paths like {:?} and bogus paths like {:?} gave consistently different responses: the parameter selects a file (attributes: {:?}). The known file {} was retrieved with {:?} (marker {:?}, absent from the {:?} control).",
                    hit.valid, hit.invalid, hit.attributes, k.file, k.payload, k.marker, k.control
                ),
                None => format!(
                    "Same-file paths like {:?} and bogus paths like {:?} gave consistently different responses: the parameter selects a file (attributes: {:?}).",
                    hit.valid, hit.invalid, hit.attributes
                ),
            };
            let mut ev = vec![rec.last(&hit.valid), rec.last(&hit.invalid)];
            if let Some(k) = &known {
                ev.push(rec.last(&k.payload));
                ev.push(rec.last(&k.control));
            }
            cx.report(vec![
                mk_point(
                    "File path manipulation",
                    "high",
                    "Firm",
                    &cx.entry,
                    ip,
                    detail,
                )
                .with_evidence(evidence(ev)),
            ]);
        }
        cx.progress();
    }
}

/// Server-side includes injection (burp.Zexx).
pub(crate) struct SsiInjection;

impl PointCheck for SsiInjection {
    fn id(&self) -> &'static str {
        "active.ssi-injection"
    }
    fn issue(&self) -> &'static str {
        "SSI injection"
    }
    /// burp.Zexx.Zh (Zmw7.Zk): not on URL path folders, nor on the User-Agent and Referer headers (names compared lower-cased); server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::PathFolder(_) => false,
            IpKind::Header => {
                !ip.name.eq_ignore_ascii_case("user-agent")
                    && !ip.name.eq_ignore_ascii_case("referer")
            }
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<String> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, payload);
            let resp = rec.send(cx, payload, new_req.as_bytes())?;
            let rp = util::parse_http(&resp);
            Some(String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]).into_owned())
        };
        if let Some(hit) = run_ssi_check(&ip.value, send) {
            cx.report(vec![
                mk_point(
                    "SSI injection",
                    "high",
                    "Firm",
                    &cx.entry,
                    ip,
                    format!(
                        "SSI directives {:?} were processed by the server.",
                        hit.payload
                    ),
                )
                .with_evidence(evidence([
                    rec.last(&format!("{}{}", ip.value, hit.payload))
                ])),
            ]);
        }
        cx.progress();
    }
}

/// Server-side template / code injection (burp.Zi6p.Znq).
pub(crate) struct TemplateInjection;

impl PointCheck for TemplateInjection {
    fn id(&self) -> &'static str {
        "active.server-side-template-injection"
    }
    fn issue(&self) -> &'static str {
        "Server-side template injection"
    }
    /// burp.Zi6p.Zh: every kind, server-side (ZA.Zn(Zr)).
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<String> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, payload);
            let resp = rec.send(cx, payload, new_req.as_bytes())?;
            let rp = util::parse_http(&resp);
            Some(String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]).into_owned())
        };
        if let Some(hit) = run_ssti_check(&ip.value, send) {
            cx.report(vec![
                mk_point(
                    "Server-side template injection",
                    "high",
                    "Tentative",
                    &cx.entry,
                    ip,
                    format!(
                        "Template expression {:?} ({}) was evaluated by the server.",
                        hit.payload, hit.engine
                    ),
                )
                .with_evidence(evidence([
                    rec.last(&format!("{}{}", ip.value, hit.payload))
                ])),
            ]);
        }
        cx.progress();
    }
}

/// Reflected XSS, Burp's breakout engine (burp.Zi6p).
pub(crate) struct ReflectedXss;

impl PointCheck for ReflectedXss {
    fn id(&self) -> &'static str {
        "active.xss-reflected"
    }
    fn issue(&self) -> &'static str {
        "Cross-site scripting (reflected)"
    }
    /// burp.Zi6p.Zh: every kind, server-side: Burp's XSS engine also skips the server-side skip list.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = crate::xss::run_xss_check(&ip.value, send) {
            cx.report(vec![
                mk_point(
                    "Cross-site scripting (reflected)",
                    reflected_xss_severity(&ip.kind),
                    "Certain",
                    &cx.entry,
                    ip,
                    format!(
                        "Payload {:?} broke out of reflection context {} and executed.",
                        hit.payload, hit.context
                    ),
                )
                .with_evidence(evidence([rec.last(&hit.payload)])),
            ]);
        }
        cx.progress();
    }
}

/// Cross-site scripting (stored), burp.Zi6p.ZZ.
pub(crate) struct StoredXss;

impl StoredCheck for StoredXss {
    fn id(&self) -> &'static str {
        "active.xss-stored"
    }
    fn issue(&self) -> &'static str {
        "Cross-site scripting (stored)"
    }
    /// burp.Zi6p.Zh (stored half Zi6p.ZZ): every kind, server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    /// burp.Zi6p.Zw -> ZZ in stored mode (the Zehl is a burp.Zpqv): the
    /// breakout engine, each payload sent to the injection item and the
    /// retrieval item's own request replayed after it (burp.Zpqv.Z_).
    fn run(&self, cx: &PairCtx) {
        let pair = &cx.pair;
        let ip = &pair.point;
        let log: RefCell<Vec<(String, ScanEvidence)>> = RefCell::new(Vec::new());
        let last = |chain: Vec<(String, Option<Vec<u8>>)>, key: &str| -> Option<Vec<u8>> {
            let (req, resp) = chain.into_iter().last()?;
            log.borrow_mut().push((
                key.to_string(),
                cx.record_exchange(req.as_bytes(), resp.as_deref())?,
            ));
            resp
        };
        let send = |payload: &str| -> Option<Vec<u8>> {
            last(
                cx.send_following(&pair.item, &inject_payload(&pair.item.req, ip, payload)),
                payload,
            )
        };
        let retrieve = |_: usize| -> Option<Vec<u8>> {
            last(cx.send_following(&pair.retrieval, &pair.retrieval.req), "")
        };
        if let Some(hit) = active_checks::run_stored_xss_check(&ip.value, 1, send, retrieve) {
            let log = log.borrow();
            let at = log.iter().rposition(|(k, _)| *k == hit.payload);
            let ev: Vec<ScanEvidence> = at
                .map(|i| {
                    log[i..(i + 2).min(log.len())]
                        .iter()
                        .map(|(_, e)| e.clone())
                        .collect()
                })
                .unwrap_or_default();
            let retrieval = pair.retrieval.req.lines().next().unwrap_or("").to_string();
            cx.report(vec![mk_point(
                "Cross-site scripting (stored)",
                "high",
                "Certain",
                &pair.item.entry,
                ip,
                format!(
                    "Payload {:?} submitted in the {} was stored and returned unencoded (context {}) in the response to the later request {retrieval:?} ({}).",
                    hit.payload,
                    ip.describe_short(false),
                    hit.context,
                    pair.retrieval.url()
                ),
            )
            .with_evidence(ev)]);
        }
        cx.progress();
    }
}

/// The G.11 stored families share burp.Zb_5's stored half (the Ze20 /
/// Zw0x / Zi4q / Zc51 selectors through the stored registry): every
/// insertion-point kind, and not server-side, matching their reflected
/// halves. Each probe is sent to the pair's injection item and the
/// retrieval item's own request is replayed after it (burp.Zpqv.Z_).
/// Stored G.11 checks submit their probes into the live application
/// (comment fields, profiles and the like), as every stored-input
/// scanner does; the probes are inert tokens and URLs, but operators
/// should expect them to persist where the application stores input.
/// No cleanup is attempted. Only GET/HEAD retrieval is replayed, and a
/// first G.11 hit stops later G.11 families for this pair.
macro_rules! g11_stored_check {
    ($name:ident, $id:literal, $issue:literal, $severity:literal, $confidence:literal, $probes:expr, $hit:expr, $doc:literal) => {
        #[doc = $doc]
        pub(crate) struct $name;

        impl StoredCheck for $name {
            fn id(&self) -> &'static str {
                $id
            }
            fn issue(&self) -> &'static str {
                $issue
            }
            /// burp.Zb_5's stored half has no applicability test: every kind.
            fn applies_to(&self, ip: &InsertionPoint) -> bool {
                match &ip.kind {
                    IpKind::Query
                    | IpKind::Body
                    | IpKind::Json(_)
                    | IpKind::Multipart { .. }
                    | IpKind::Cookie
                    | IpKind::Header
                    | IpKind::PathFolder(_)
                    | IpKind::PathFilename(_)
                    | IpKind::EntireBody
                    | IpKind::XmlParam { .. }
                    | IpKind::XmlTag { .. }
                    | IpKind::XmlAttr { .. }
                    | IpKind::ParamName(_)
                    | IpKind::Base64 { .. } => true,
                }
            }
            fn server_side(&self) -> bool {
                false
            }
            fn run(&self, cx: &PairCtx) {
                if cx.stopped() || !cx.g11_allowed() {
                    return;
                }
                let pair = &cx.pair;
                let ip = &pair.point;
                let log: RefCell<Vec<ScanEvidence>> = RefCell::new(Vec::new());
                let send = |payload: &str| -> Option<Vec<u8>> {
                    if cx.stopped() {
                        return None;
                    }
                    let chain = cx.send_following(&pair.item, &inject_payload(&pair.item.req, ip, payload));
                    let (req, resp) = chain.into_iter().last()?;
                    log.borrow_mut().push(cx.record_exchange(req.as_bytes(), resp.as_deref())?);
                    resp
                };
                let retrieve = || -> Option<Vec<u8>> {
                    if cx.stopped() {
                        return None;
                    }
                    let chain = cx.send_following(&pair.retrieval, &pair.retrieval.req);
                    let (req, resp) = chain.into_iter().last()?;
                    log.borrow_mut().push(cx.record_exchange(req.as_bytes(), resp.as_deref())?);
                    resp
                };
                if let Some((probe, what)) = crate::scan::run_g11_stored(&$probes, send, retrieve, $hit) {
                    cx.note_g11_hit();
                    let log = log.borrow();
                    let ev: Vec<ScanEvidence> = log.iter().rev().take(2).rev().cloned().collect();
                    cx.report(vec![mk_point(
                        $issue,
                        $severity,
                        $confidence,
                        &pair.item.entry,
                        ip,
                        format!(
                            "The value <b>{}</b>, submitted in the {} in a previous request, was stored and returned in {} in the response to the later request {:?} ({}).",
                            util::html_encode(&probe),
                            ip.describe_short(false),
                            what,
                            pair.retrieval.req.lines().next().unwrap_or(""),
                            pair.retrieval.url()
                        ),
                    )
                    .with_evidence(ev)]);
                }
                cx.progress();
            }
        }
    };
}

g11_stored_check!(
    LinkManipulationStored,
    "active.link-manipulation-stored",
    "Link manipulation (stored)",
    "info",
    "Firm",
    crate::scan::g11_link_probes(),
    crate::scan::g11_link_stored_hit,
    "Link manipulation (stored), burp.Zb_5 -> Ze20, KB 00501004: the Zpyp probes (random host/path under http://, https://, //, \\/ - established literals) must come back as a link or redirect target of the retrieval response. Severity Information (KB); confidence not established: Firm."
);
g11_stored_check!(
    CssInjectionStored,
    "active.css-injection-stored",
    "CSS injection (stored)",
    "medium",
    "Tentative",
    crate::scan::g11_css_probes(),
    |resp: &[u8], probe: &str| crate::scan::g11_stored_context_hit(
        resp,
        probe,
        crate::scan::g11_css_match
    ),
    "CSS injection (stored), burp.Zb_5 -> Zw0x, KB 00501301: the token probe must be returned in a CSS position (<style> text, a style attribute, a <link rel=stylesheet> href) of the retrieval response. Severity Medium (KB); confidence not established: Tentative (retrieval proves storage, not breakout)."
);
g11_stored_check!(
    HppStored,
    "active.client-side-hpp-stored",
    "Client-side HTTP parameter pollution (stored)",
    "low",
    "Tentative",
    crate::scan::g11_hpp_probes(),
    |resp: &[u8], probe: &str| crate::scan::g11_stored_context_hit(
        resp,
        probe,
        crate::scan::g11_hpp_match
    ),
    "Client-side HTTP parameter pollution (stored), burp.Zb_5 -> Zi4q, KB 00501401: the `<random3>&<random3>` probe (the stripped suffix is omitted, not established) must be returned in a URL-bearing attribute (href/src/action/formaction), JavaScript string or response header of the retrieval response. Severity Low (KB); confidence not established: Tentative (retrieval proves storage, not exploitability)."
);
g11_stored_check!(
    FormActionHijackingStored,
    "active.form-action-hijacking-stored",
    "Form action hijacking (stored)",
    "medium",
    "Tentative",
    crate::scan::g11_form_action_probes(),
    |resp: &[u8], probe: &str| crate::scan::g11_stored_context_hit(
        resp,
        probe,
        crate::scan::g11_form_action_match
    ),
    "Form action hijacking (stored), burp.Zb_5 -> Zc51, KB 00501501: the injected URL must be returned as a form's action or an element's formaction in the retrieval response. Severity Medium (KB); confidence not established: Tentative (retrieval proves storage, not exploitability)."
);

/// Client-side template injection, burp.Zrmh.
pub(crate) struct ClientTemplateInjection;

impl PointCheck for ClientTemplateInjection {
    fn id(&self) -> &'static str {
        "active.client-side-template-injection"
    }
    fn issue(&self) -> &'static str {
        "Client-side template injection"
    }
    /// burp.Zrmh has no applicability test: every kind; not server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            rec.send(cx, payload, inject_payload(&cx.req, ip, payload).as_bytes())
        };
        // Version banner lookup (burp.Zr54.ZK): same-origin scripts only.
        let fetch_script = |src: &str| -> Option<Vec<u8>> {
            let path = same_origin_path(src, cx.entry.https, &cx.host_hdr, &cx.parts.path)?;
            cx.send(get_request_like(&cx.req, &path).as_bytes())
        };
        if let Some(hit) = active_checks::run_csti_check(&ip.value, send, fetch_script) {
            cx.report(vec![mk_point(
                "Client-side template injection",
                "high",
                hit.confidence(),
                &cx.entry,
                ip,
                format!(
                    "The template expression {} submitted as {:?} was returned unencoded ({:?}) inside an AngularJS ng-app scope.{}",
                    active_checks::CSTI_EXPR,
                    hit.payload,
                    hit.reflection,
                    hit.angular_version.as_deref().map(|v| format!(" The page loads {v}.")).unwrap_or_default()
                ),
            )
            .with_evidence(evidence([rec.last(&hit.payload)]))]);
        }
        cx.progress();
    }
}

/// PHP code injection, echo-based (burp.Zsn3 -> Zgeo.Zv -> Zxvv), on
/// file-upload points only (Zcgg.Zw: the multipart parts that carry a
/// filename). Burp's timing half of Zsn3 (Zwj_) is not ported.
pub(crate) struct PhpCodeInjection;

impl PointCheck for PhpCodeInjection {
    fn id(&self) -> &'static str {
        "active.php-code-injection"
    }
    fn issue(&self) -> &'static str {
        "PHP code injection"
    }
    /// burp.Zsn3 (echo half) on file-upload parts only (Zcgg.Zw); server-side
    /// (Zsn3.Zh: Zg.Zn(ZS)).
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Multipart { filename, .. } => filename.is_some(),
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => false,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun) {
        let (idx, ip) = (pt.idx, pt.ip);
        let IpKind::Multipart {
            index,
            filename: Some(orig),
        } = &ip.kind
        else {
            return;
        };
        if cx.stopped() {
            return;
        }
        let token = active_checks::rnd_id(20);
        // The Collaborator half (burp.Zxvv.ZQ): the same uploaded file also
        // resolves a Collaborator name, when the scan has an id for it.
        let collab = oob_slot(&cx.oob, idx, &ip.name, "php", &mut st.oob_used)
            .map(|(_, t, d)| (t.clone(), active_checks::php_collaborator_host(t, d)));
        let rec = Recorder::default();
        let send = |fname: &str, ct: &str, content: &str| -> Option<Vec<u8>> {
            rec.send(
                cx,
                fname,
                with_multipart_part(&cx.req, *index, content, Some(fname), Some(ct)).as_bytes(),
            )
        };
        let follow = |loc: &str| -> Option<Vec<u8>> {
            let path = same_origin_path(loc, cx.entry.https, &cx.host_hdr, &cx.parts.path)?;
            rec.send(cx, "", get_request_like(&cx.req, &path).as_bytes())
        };
        let hit = active_checks::run_php_echo_check(
            orig,
            &token,
            collab.as_ref().map(|(_, h)| h.as_str()),
            send,
            follow,
        );
        if hit.is_none()
            && let Some((id, host)) = &collab
        {
            // Raised when the id sees a DNS lookup (burp.Zxvv.ZR).
            let filename = active_checks::php_upload_filename(orig, &token);
            let issue = mk_point(
                    "PHP code injection",
                    "high",
                    "Certain",
                    &cx.entry,
                    ip,
                    format!(
                        "A file named {filename:?} was uploaded with PHP code that calls gethostbyname(\"{host}\"). The application performed a DNS lookup of the Collaborator id {id}, so the server executed the uploaded PHP code."
                    ),
                )
                .with_evidence(rec.since_last(&filename).into_iter().take(1).collect());
            cx.shared.oob.register(id.clone(), Some("DNS"), issue);
        }
        if let Some(hit) = hit {
            let mut ev = rec.since_last(&hit.filename);
            ev.truncate(hit.hop + 1);
            cx.report(vec![mk_point(
                "PHP code injection",
                "high",
                "Certain",
                &cx.entry,
                ip,
                format!(
                    "A file named {:?} was uploaded with the content {:?}. The response{} contained {}, the result of the evaluated expression, so the server executed the uploaded PHP code.",
                    hit.filename,
                    hit.payload,
                    if hit.hop > 0 { format!(" after {} redirect(s)", hit.hop) } else { String::new() },
                    hit.expected
                ),
            )
            .with_evidence(ev)]);
        }
        cx.progress();
    }
}

/// Input returned in response (reflected), burp.Zr02: a random marker
/// replacing, then appended to, the value (Zwe8.PLAIN_REFLECTION_TYPES);
/// reported as information with certain confidence when it comes back.
pub(crate) struct InputReflected;

impl PointCheck for InputReflected {
    fn id(&self) -> &'static str {
        "active.input-returned-reflected"
    }
    fn issue(&self) -> &'static str {
        "Input returned in response (reflected)"
    }
    /// burp.Zr02 has no applicability test: every kind; not server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let value = &ip.value;
        for append in [false, true] {
            let marker: String = {
                use rand::Rng;
                let mut g = rand::thread_rng();
                (0..10)
                    .map(|_| (b'a' + g.gen_range(0..26)) as char)
                    .collect()
            };
            let v = if append {
                format!("{value}{marker}")
            } else {
                marker.clone()
            };
            let new_req = inject_payload(&cx.req, ip, &v);
            let resp = cx.send(new_req.as_bytes());
            // Anywhere in the response, headers included: on a fresh
            // project Burp reports lab /redirect, whose value comes
            // back only in Location (scan 5, 2026-11-16). The earlier
            // "body only" reading (fnd_56) came from a reused project,
            // where the REST API lists only issues new to the project.
            let reflected = resp
                .as_ref()
                .is_some_and(|r| r.windows(marker.len()).any(|w| w == marker.as_bytes()));
            if reflected {
                // Burp's own sentence with its point wording (burp.Zsg0.ZD;
                // live 52685 on Juice Shop: "The value of the URL path
                // filename is copied into the application's response.").
                let mut issue = mk(
                    "info",
                    "Input returned in response (reflected)",
                    &cx.entry,
                    format!(
                        "The {} is copied into the application's response.",
                        ip.describe_bold()
                    ),
                );
                issue.confidence = "Certain".into();
                cx.report(vec![issue.with_evidence(vec![ScanEvidence::new(
                    new_req.as_bytes(),
                    resp.as_deref(),
                )])]);
                break;
            }
        }
        cx.progress();
    }
}

/// HTTP response header injection, Burp's own flow (burp.Zwi).
pub(crate) struct HeaderInjection;

impl PointCheck for HeaderInjection {
    fn id(&self) -> &'static str {
        "active.http-response-header-injection"
    }
    fn issue(&self) -> &'static str {
        "HTTP response header injection"
    }
    /// burp.Zwi has no applicability test: every kind; not server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = run_header_injection_check(&ip.value, send) {
            cx.report(vec![
                mk_point(
                    "HTTP response header injection",
                    "high",
                    "Certain",
                    &cx.entry,
                    ip,
                    format!(
                        "Payload {:?} produced the response header line {:?}.",
                        hit.payload, hit.injected_line
                    ),
                )
                .with_evidence(evidence([rec.last(&hit.payload)])),
            ]);
        }
        cx.progress();
    }
}

/// Open redirection, Burp's own flow (burp.Zuag).
pub(crate) struct OpenRedirect;

impl PointCheck for OpenRedirect {
    fn id(&self) -> &'static str {
        "active.open-redirection"
    }
    fn issue(&self) -> &'static str {
        "Open redirection (reflected)"
    }
    /// burp.Zuag has no applicability test: every kind; not server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = run_open_redirect_check(&ip.value, cx.settings.speed, send) {
            cx.report(vec![
                mk_point(
                    "Open redirection (reflected)",
                    "low",
                    "Certain",
                    &cx.entry,
                    ip,
                    format!(
                        "Payload {:?} made the response redirect to {:?}.",
                        hit.payload, hit.target
                    ),
                )
                .with_evidence(evidence([rec.last(&hit.payload)])),
            ]);
        }
        cx.progress();
    }
}

/// Error-based SQL injection, Burp's own flow (burp.Zppj.ZE). One SQL
/// injection issue per insertion point: once this reports, the boolean test
/// is not run (live 52685, lab /user: only the "general error" issue).
/// Its send closure does not look at the stop flag (unchanged).
pub(crate) struct SqlErrorInjection;

impl PointCheck for SqlErrorInjection {
    fn id(&self) -> &'static str {
        "active.sql-injection-error"
    }
    fn issue(&self) -> &'static str {
        "SQL injection"
    }
    /// burp.Zg_c / Zppj: no point-type rule; Zppj returns before probing a point on the server-side skip list.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<String> {
            let new_req = inject_payload(&cx.req, ip, payload);
            let resp = rec.send(cx, payload, new_req.as_bytes())?;
            Some(String::from_utf8_lossy(&resp).into_owned())
        };
        let baseline_full = String::from_utf8_lossy(&cx.baseline.raw).into_owned();
        if let Some(hit) = run_sql_error_check(&ip.value, &baseline_full, cx.settings.speed, send) {
            // burp.Zh6 issue text: flag 32 (database error) / 64 (general error).
            let general = hit.database == "General";
            // The point as Burp names it (burp.Zsg0.Zj): "<b>q</b> parameter",
            // "<b>sid</b> cookie", "request body", ...
            let text = format!(
                "The {} appears to be vulnerable to SQL injection attacks. A single quote was submitted in the {}, and a {} error message was returned.{} You should review the contents of the error message, and the application's handling of other input, to confirm whether a vulnerability is present.",
                ip.describe_short(true),
                ip.describe_short(false),
                if general { "general" } else { "database" },
                // Only a confirmed hit saw the balanced probe come back clean.
                if hit.confirmed {
                    " Two single quotes were then submitted and the error message disappeared."
                } else {
                    ""
                }
            );
            let mut i = mk("high", "SQL injection", &cx.entry, text);
            i.confidence = if general {
                "Tentative".into()
            } else if hit.confirmed {
                "Certain".into()
            } else {
                "Firm".into()
            };
            cx.report(vec![i.with_evidence(evidence([
                rec.last(&hit.payload),
                rec.next_after(&hit.payload),
            ]))]);
            pt.sqli_reported = true;
        }
        cx.progress();
    }
}

/// Boolean SQL injection, Burp's own payloads (burp.Zppj). Skipped (one
/// progress unit) when the error-based check already reported this point.
pub(crate) struct SqlBooleanInjection;

impl PointCheck for SqlBooleanInjection {
    fn id(&self) -> &'static str {
        "active.sql-injection-boolean"
    }
    fn issue(&self) -> &'static str {
        "SQL injection"
    }
    /// burp.Zg_c / Zppj: as SqlErrorInjection.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if pt.sqli_reported {
            cx.progress();
            return;
        }
        if cx.stopped() || cx.baseline.raw.is_empty() {
            return;
        }
        let ip = pt.ip;
        let accuracy = cx.settings.accuracy;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = run_sql_boolean_check(
            &ip.value,
            &cx.baseline.raw,
            cx.settings.speed,
            accuracy,
            send,
        ) {
            cx.report(vec![mk_point(
                "SQL injection",
                "high",
                "Tentative",
                &cx.entry,
                ip,
                format!(
                    "True condition {:?} and false condition {:?} produced consistently different responses over {} rounds (attributes: {:?}).",
                    hit.positive,
                    hit.negative,
                    accuracy.rounds(),
                    hit.attributes
                ),
            )
            .with_evidence(evidence([rec.last(&hit.positive), rec.last(&hit.negative)]))]);
        }
        cx.progress();
    }
}

/// XML injection, Collaborator half of burp.Zp7s (Zsrh over Ze_f then
/// Zbiw); Zp7s.Zw runs it before the error-based half. Each id is
/// registered so the UI matcher raises "XML injection" (medium, certain:
/// Zc3f -> Zuzl -> Zp9s.ZC) on its DNS interaction.
pub(crate) struct XmlInjectionOob;

impl PointCheck for XmlInjectionOob {
    fn id(&self) -> &'static str {
        "active.xml-injection-collaborator"
    }
    fn issue(&self) -> &'static str {
        "XML injection"
    }
    /// burp.Zp7s.Zh: not on headers or parameter names; server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            // burp.Zp7s.Zh: Zxmw.Zl lists HEADER and the parameter-name kinds.
            IpKind::Header | IpKind::ParamName(_) => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun) {
        let (idx, ip) = (pt.idx, pt.ip);
        let name = &ip.name;
        let xsd = oob_slot(&cx.oob, idx, name, "xsd", &mut st.oob_used)
            .map(|(_, t, h)| (t.clone(), h.clone()));
        let xi = oob_slot(&cx.oob, idx, name, "xi", &mut st.oob_used)
            .map(|(_, t, h)| (t.clone(), h.clone()));
        if (xsd.is_some() || xi.is_some()) && !cx.stopped() {
            let rec = Recorder::default();
            let send = |payload: &str| -> Option<Vec<u8>> {
                rec.send(cx, payload, inject_payload(&cx.req, ip, payload).as_bytes())
            };
            let sent = active_checks::run_xml_oob_check(
                &ip.kind,
                &ip.value,
                xsd.as_ref().map(|(t, h)| (t.as_str(), h.as_str())),
                xi.as_ref().map(|(t, h)| (t.as_str(), h.as_str())),
                send,
            );
            for (token, payload) in sent {
                let issue = mk_point(
                    "XML injection",
                    "medium",
                    "Certain",
                    &cx.entry,
                    ip,
                    format!("The payload {payload} replaced the value; an XML parser that resolves it contacts the Collaborator id {token}."),
                )
                .with_evidence(evidence([rec.last(&payload)]));
                cx.shared.oob.register(token, Some("DNS"), issue);
            }
            cx.progress();
        }
    }
}

/// XML injection, error-based half of burp.Zp7s. Zp7s.Zh refuses HTTP header
/// points (Zxmw.Zl: HEADER and the parameter-name kinds).
pub(crate) struct XmlInjectionError;

impl PointCheck for XmlInjectionError {
    fn id(&self) -> &'static str {
        "active.xml-injection-error"
    }
    fn issue(&self) -> &'static str {
        "XML injection"
    }
    /// burp.Zp7s.Zh: not on headers or parameter names (Zxmw.Zl); server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            // Zxmw.Zl: HEADER and the parameter-name kinds.
            IpKind::Header | IpKind::ParamName(_) => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() || cx.baseline.raw.is_empty() {
            return;
        }
        let ip = pt.ip;
        let rec = Recorder::default();
        let send_payload = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        let send_base = || -> Option<Vec<u8>> { cx.send(cx.req.as_bytes()) };
        if let Some(markers) = run_xml_injection_check(
            &ip.value,
            &cx.baseline.raw,
            xml_injection_rounds(cx.settings.accuracy),
            send_payload,
            send_base,
        ) {
            cx.report(vec![mk_point(
                "XML injection",
                "medium",
                "Tentative",
                &cx.entry,
                ip,
                format!("The {} appears to be vulnerable to XML injection. The payload {XML_INJECTION_PAYLOAD} was appended to the value and XML/SOAP markers that were not in the original response appeared: {}.", ip.describe_short(false), markers.join(", ")),
            )
            .with_evidence(evidence([rec.last(&format!("{}{XML_INJECTION_PAYLOAD}", ip.value))]))]);
        }
        cx.progress();
    }
}

/// LDAP injection, Burp's own check (burp.Zwkf + Zmaq).
pub(crate) struct LdapInjection;

impl PointCheck for LdapInjection {
    fn id(&self) -> &'static str {
        "active.ldap-injection"
    }
    fn issue(&self) -> &'static str {
        "LDAP injection"
    }
    /// burp.Zwkf.Zh: no point-type rule; server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() || cx.baseline.raw.is_empty() {
            return;
        }
        let ip = pt.ip;
        let accuracy = cx.settings.accuracy;
        let rec = Recorder::default();
        let send = |payload: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let new_req = inject_payload(&cx.req, ip, payload);
            rec.send(cx, payload, new_req.as_bytes())
        };
        if let Some(hit) = run_ldap_check(
            &ip.value,
            &cx.baseline.raw,
            cx.settings.speed,
            accuracy,
            send,
        ) {
            cx.report(vec![mk_point(
                "LDAP injection",
                "high",
                "Firm",
                &cx.entry,
                ip,
                format!(
                    "Always-true filter {:?} and always-false filter {:?} produced consistently different responses over {} rounds (attributes: {:?}).",
                    hit.positive,
                    hit.negative,
                    accuracy.rounds(),
                    hit.attributes
                ),
            )
            .with_evidence(evidence([rec.last(&hit.positive), rec.last(&hit.negative)]))]);
        }
        cx.progress();
    }
}

/// SMTP header injection, Burp's own check (burp.Zgcg/Zrok): two payloads
/// per parameter, each with its own Collaborator id; the response is not
/// inspected, an SMTP interaction for the id raises the issue
/// (scan::match_oob_interactions, kind SMTP).
pub(crate) struct SmtpHeaderInjection;

impl PointCheck for SmtpHeaderInjection {
    fn id(&self) -> &'static str {
        "active.smtp-header-injection"
    }
    fn issue(&self) -> &'static str {
        "SMTP header injection"
    }
    /// burp.Zgcg.Zh (Zw5k.Zy): not on URL path folders, nor on the User-Agent and Referer headers (names compared lower-cased); server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::PathFolder(_) => false,
            IpKind::Header => {
                !ip.name.eq_ignore_ascii_case("user-agent")
                    && !ip.name.eq_ignore_ascii_case("referer")
            }
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        let ip = pt.ip;
        let (name, value) = (&ip.name, &ip.value);
        let Some(plan) = cx.smtp.iter().find(|p| &p.param == name) else {
            return;
        };
        for (enclosed, (token, collab_host)) in [(false, &plan.simple), (true, &plan.enclosed)] {
            if cx.stopped() {
                break;
            }
            let (r3, r1) = {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let mut pick = |n: usize| {
                    (0..n)
                        .map(|_| rng.gen_range(b'a'..=b'z') as char)
                        .collect::<String>()
                };
                (pick(3), pick(1))
            };
            let payload = smtp_payload(value, enclosed, collab_host, &r3, &r1);
            let new_req = inject_payload(&cx.req, ip, &payload);
            let resp = cx.send(new_req.as_bytes());
            let issue = mk_point(
                "SMTP header injection",
                "medium",
                "Certain",
                &cx.entry,
                ip,
                format!("Payload appended a BCC header to user@{collab_host}; awaiting an SMTP interaction for id {token}."),
            )
            .with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), resp.as_deref())]);
            cx.shared.oob.register(token.clone(), Some("SMTP"), issue);
        }
    }
}

/// Stored-echo pass (SCANNER_ACTIVE_CHECKS_STORED_INPUT / STORED_XSS /
/// STORED_DOM). Burp detects the stored variants by revisiting pages after
/// injection. Light-weight equivalent: once a point's probes are done,
/// re-fetch the original URL and classify any surviving marker of this or
/// any earlier point. A marker in a later response to the original URL was
/// persisted server-side and echoed where the attacker does not control the
/// input.
pub(crate) struct StoredEcho;

impl PointCheck for StoredEcho {
    fn id(&self) -> &'static str {
        "active.stored-echo"
    }
    fn issue(&self) -> &'static str {
        "Active probe: value of parameter appears stored"
    }
    /// WebProbe's own pass (no Burp class): every kind; not server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFolder(_)
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(_)
            | IpKind::Base64 { .. } => true,
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, _pt: &mut PointRun) {
        if st.stored_markers.is_empty() || cx.stopped() {
            return;
        }
        let re_req = rebuild_with_path(&cx.req, &cx.parts.path);
        let resp = cx.send(re_req.as_bytes());
        if let Some(resp) = &resp {
            let rp = util::parse_http(resp);
            let rbody = String::from_utf8_lossy(&resp[rp.head_len.min(resp.len())..]);
            let ev = ScanEvidence::new(re_req.as_bytes(), Some(&resp[..]));
            let mut issues = Vec::new();
            for (pname, marker) in &st.stored_markers {
                if let Some(kind) = stored_echo_hit(&rbody, marker) {
                    let (sev, title, detail) = match kind {
                        // Only plain canaries are tracked here: one
                        // inside a script tag is a stored DOM context,
                        // not proof of XSS (that is the breakout-based
                        // "Cross-site scripting (stored)" check).
                        "xss" | "dom" => (
                            "high",
                            format!(
                                "Active probe: stored DOM-based cross-site scripting via parameter {pname}"
                            ),
                            format!(
                                "Canary {marker} injected earlier is now reflected into script data or an attribute value of the original URL's response."
                            ),
                        ),
                        _ => (
                            "medium",
                            format!("Active probe: value of parameter {pname} appears stored"),
                            format!(
                                "Marker {marker} injected earlier shows up in a later response to the original URL (STORED_INPUT)."
                            ),
                        ),
                    };
                    issues.push(mk(sev, &title, &cx.entry, detail).with_evidence(vec![ev.clone()]));
                }
            }
            cx.report(issues);
        }
        cx.progress();
        cx.pace(50);
    }
}

#[cfg(test)]
mod bac_helper_tests {
    use super::*;

    #[test]
    fn strip_auth_headers_handles_non_ascii_names_without_panicking() {
        let raw = "GET / HTTP/1.1\r\nHost: h\r\n�name: v\r\néname: v\r\nCookie: s\r\n\r\n";
        let (out, removed) = strip_auth_headers(raw.as_bytes());
        assert_eq!(removed, ["Cookie"]);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("�name: v"));
        assert!(out.contains("éname: v"));
    }

    #[test]
    fn strip_auth_headers_drops_cookie_authorization_and_x_headers_only() {
        let raw = b"POST /a?b=1 HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\nAuthorization: Bearer t\r\nX-Csrf: c\r\nX-Requested-With: XMLHttpRequest\r\nAccept: */*\r\nContent-Length: 3\r\n\r\nabc";
        let (out, removed) = strip_auth_headers(raw);
        assert_eq!(removed, ["Cookie", "Authorization", "X-Csrf"]);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("X-Requested-With: XMLHttpRequest\r\n"));
        assert!(text.contains("Host: h\r\n") && text.contains("Accept: */*\r\n"));
        assert!(!text.to_lowercase().contains("cookie"));
        assert!(text.ends_with("\r\n\r\nabc"), "body kept: {text:?}");
    }

    #[test]
    fn marker_then_strip_keeps_query_body_and_request_line_for_get_and_post() {
        use super::super::cache::with_query_param;
        let get = b"GET /p HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\n\r\n";
        let (s, r) = strip_auth_headers(&with_query_param(get, "mk", "mk"));
        assert_eq!(r, ["Cookie"]);
        assert!(
            String::from_utf8(s)
                .unwrap()
                .starts_with("GET /p?mk=mk HTTP/1.1\r\n")
        );
        let post = b"POST /p?x=1 HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\nContent-Length: 2\r\n\r\nhi";
        let (s, _) = strip_auth_headers(&with_query_param(post, "mk", "mk"));
        let s = String::from_utf8(s).unwrap();
        assert!(s.starts_with("POST /p?x=1&mk=mk HTTP/1.1\r\n"));
        assert!(s.ends_with("\r\n\r\nhi"));
        let trailing = b"GET /p? HTTP/1.1\r\nHost: h\r\n\r\n";
        assert!(
            String::from_utf8(with_query_param(trailing, "mk", "mk"))
                .unwrap()
                .starts_with("GET /p?mk=mk HTTP/1.1")
        );
    }

    #[test]
    fn json_node_count_and_page_title_follow_the_equivalence_metric() {
        assert_eq!(json_node_count(br#"{"a":[1,2],"b":{"c":null}}"#), 6);
        assert_eq!(json_node_count(b"<html>"), 0);
        assert_eq!(
            page_title(b"<HTML><head><TITLE> Acct </TITLE></head>"),
            "Acct"
        );
        assert_eq!(page_title(b"no title here"), "");
    }
}
