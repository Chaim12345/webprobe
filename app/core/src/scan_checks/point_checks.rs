use super::*;

// ---------------------------------------------------------------- point checks

/// SCANNER_ACTIVE_CHECKS_EXTERNAL_INTERACTION: the Collaborator payload
/// replaces the value, and the id is registered so
/// `scan::match_oob_interactions` raises "External service interaction
/// (DNS)" / "(HTTP)" when the Collaborator logs an interaction for it. Runs
/// only when the scan has Collaborator ids.
pub(crate) struct ExternalInteraction;

impl PointCheck for ExternalInteraction {
    fn id(&self) -> &'static str {
        "active.external-interaction"
    }
    fn issue(&self) -> &'static str {
        "External service interaction (DNS)"
    }
    /// burp.Zxfo.Zh (a Collaborator URL in the value: External service interaction / Out-of-band resource load): not on URL path folders nor the User-Agent header; then Zibp.ZU: not on parameter names, nor on a value `true` / `false` (any case) or holding U+0002. Server-side.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::PathFolder(_) | IpKind::ParamName(_) => false,
            IpKind::Header => {
                !ip.name.eq_ignore_ascii_case("user-agent") && zibp_zu_value_ok(&ip.decoded_value())
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
            | IpKind::Base64 { .. } => zibp_zu_value_ok(&ip.decoded_value()),
        }
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun) {
        let (idx, ip) = (pt.idx, pt.ip);
        let value = ip.decoded_value();
        // burp.Zxfo.doCheck: one request per burp.Zbxl.Zu variant, each with
        // a Collaborator id of its own.
        for (k, variant) in ext_variants(ip, cx.settings.speed).into_iter().enumerate() {
            let Some((_, token, domain)) =
                oob_slot(&cx.oob, idx, &ip.name, &ext_slot(k), &mut st.oob_used)
            else {
                continue;
            };
            if cx.stopped() {
                return;
            }
            let shown = crate::url_payloads::payload(&value, variant, domain);
            let new_req = inject(&cx.req, ip, &shown);
            let resp = cx.send(new_req.as_bytes());
            let issue = mk(
                "medium",
                &format!("Out-of-band payload embedded via parameter {}", ip.name),
                &cx.entry,
                format!("Collaborator token {token} replaced the value; confirmed when an interaction is observed."),
            )
            .with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), resp.as_deref())]);
            // burp.Zez7.Ze (URL payload) wording for the issue the interaction raises.
            let point = ip.describe_short(true);
            let delivery = crate::oob::delivery_sentence("The payload", &shown, &point, ".");
            cx.shared
                .oob
                .register_delivered(token.clone(), None, issue, delivery);
            // burp.Zxfo.lambda$doCheck$0: the response itself may carry what the
            // Collaborator served for this id (Ze2n.Zt): the server fetched the
            // URL and returned its content in-band.
            if let Some(r) = resp.as_deref()
                && inband_hit(r, token)
            {
                cx.report(vec![oob_resource_load_issue(
                    &cx.entry,
                    &crate::oob::delivery_sentence("The payload", &shown, &point, ""),
                    &new_req,
                    r,
                )]);
            }
            cx.progress();
            cx.pace(50);
        }
    }
}

/// burp.Zbxl.Zu's URL payload variants for the point (burp.Zxfo: the
/// audit thoroughness, Thorough when the base value looks like a URL,
/// Zibp.ZN). Slot allocation and the check both use this, so they agree.
pub(crate) fn ext_variants(
    ip: &InsertionPoint,
    speed: ScanSpeed,
) -> Vec<crate::url_payloads::UrlVariant> {
    let value = ip.decoded_value();
    let thorough = speed == ScanSpeed::Thorough || crate::url_payloads::looks_like_url(&value);
    crate::url_payloads::variants(&value, thorough)
}

/// The Collaborator slot of variant `k`: "ext" for the first (also keyed
/// by parameter name in older callers), "ext1".. for the rest.
pub(crate) fn ext_slot(k: usize) -> String {
    if k == 0 {
        "ext".to_string()
    } else {
        format!("ext{k}")
    }
}

/// Burp's active JWT check (burp.Zu4y over Zs_2 / Zi8s / Zs83, registered
/// for five issues at Zcug.java:210-216): on an insertion point whose value
/// is a JWT, first make sure the application checks the token at all (a
/// control token with a blanked payload must answer differently from the
/// original, Zu4y.Zx), then try each attack: a corrupted signature, the
/// "none" algorithm, a self-signed key in "jwk". An attack is reported when,
/// over the accuracy's rounds, its responses (and the original's, sent
/// alternately) stay on the original's side of the original-vs-control
/// difference (Zs_2.Zk with Zsnr.Zt). "jku" and "x5u" pointing at a
/// Collaborator URL are reported when the server fetches them.
pub(crate) struct JwtAttacks;

impl PointCheck for JwtAttacks {
    fn id(&self) -> &'static str {
        "active.jwt"
    }
    fn issue(&self) -> &'static str {
        "JWT signature not verified"
    }
    /// Zu4y.Zh: any insertion point whose value parses as a JWT.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        match &ip.kind {
            IpKind::ParamName(_) | IpKind::PathFolder(_) => false,
            IpKind::Query
            | IpKind::Body
            | IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::Cookie
            | IpKind::Header
            | IpKind::PathFilename(_)
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::Base64 { .. } => {
                let v = ip.decoded_value();
                let v = v.trim();
                crate::jwt::Jwt::parse(v.strip_prefix("Bearer ").unwrap_or(v)).is_some()
            }
        }
    }
    fn server_side(&self) -> bool {
        false
    }
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun) {
        let ip = pt.ip;
        let value = ip.decoded_value();
        let bearer = value.trim().starts_with("Bearer ");
        let Some(token) =
            crate::jwt::Jwt::parse(value.trim().strip_prefix("Bearer ").unwrap_or(value.trim()))
        else {
            cx.progress();
            return;
        };
        if cx.stopped() || cx.baseline.raw.is_empty() {
            cx.progress();
            return;
        }
        let rec = Recorder::default();
        let send = |t: &str| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let v = if bearer {
                format!("Bearer {t}")
            } else {
                t.to_string()
            };
            rec.send(cx, t, inject_payload(&cx.req, ip, &v).as_bytes())
        };
        let base = crate::variations::fingerprint(&cx.baseline.raw);
        // Zu4y.Zx: the control token must be told apart from the original.
        let control = crate::jwt::control_token(&token);
        let Some(control_resp) = send(&control) else {
            cx.progress();
            return;
        };
        let control_fp = crate::variations::fingerprint(&control_resp);
        if !crate::variations::Comparator::new(&base, &control_fp).distinguishable() {
            cx.progress();
            return;
        }
        let rounds = cx.settings.accuracy.rounds();
        let accepted = |attack: &str| -> bool {
            let mut c = crate::variations::Comparator::new(&base, &control_fp);
            for _ in 0..rounds {
                let Some(a) = send(attack) else { return false };
                c.add_a(&crate::variations::fingerprint(&a));
                if !c.distinguishable() {
                    return false;
                }
                let Some(o) = send(&token.raw) else {
                    return false;
                };
                c.add_a(&crate::variations::fingerprint(&o));
                if !c.distinguishable() {
                    return false;
                }
            }
            true
        };
        let place = ip.describe_short(true);
        // Zwfx.Zf detail texts; Zmir.ZL: High, Tentative (Zs_2.java:48).
        let attacks: Vec<(&str, Vec<String>, String)> = vec![
            (
                "JWT signature not verified",
                vec![crate::jwt::corrupt_signature(&token)],
                format!(
                    "The signature of the JWT within the {place} does not appear to be verified correctly by the application."
                ),
            ),
            (
                "JWT none algorithm supported",
                crate::jwt::none_variants(&token),
                format!(
                    "The JWT within the {place} appears to be trusted by the application even when using the \"none\" algorithm with an empty signature."
                ),
            ),
            (
                "JWT self-signed JWK header supported",
                crate::jwt::jwk_variant(&token).into_iter().collect(),
                format!(
                    "The JWT within the {place} appears to use an arbitrary key embedded in the \"jwk\" header to validate the token."
                ),
            ),
        ];
        for (name, variants, detail) in attacks {
            if !cx.runs(name)
                || !crate::scan_config::shared_config(&cx.shared)
                    .lock()
                    .unwrap()
                    .check_enabled(&jwt_issue_id(name))
            {
                continue;
            }
            if let Some(v) = variants.iter().find(|v| accepted(v)) {
                cx.report(vec![
                    mk_point(name, "high", "Tentative", &cx.entry, ip, detail).with_evidence(
                        evidence([rec.last(v), rec.last(&token.raw), rec.last(&control)]),
                    ),
                ]);
            }
        }
        // Zs83: jku / x5u at a Collaborator URL; Zmir.Zl: High, Certain,
        // raised when the interaction arrives.
        for (header, name, what) in [
            ("jku", "JWT arbitrary jku header supported", "a public key"),
            (
                "x5u",
                "JWT arbitrary x5u header supported",
                "a public key certificate",
            ),
        ] {
            if cx.stopped()
                || !cx.runs(name)
                || !crate::scan_config::shared_config(&cx.shared)
                    .lock()
                    .unwrap()
                    .check_enabled(&jwt_issue_id(name))
            {
                continue;
            }
            let Some((_, oob_token, domain)) =
                oob_slot(&cx.oob, pt.idx, &ip.name, header, &mut st.oob_used)
            else {
                continue;
            };
            let attack =
                crate::jwt::header_url_variant(&token, header, &format!("https://{domain}/"));
            let v = if bearer {
                format!("Bearer {attack}")
            } else {
                attack.clone()
            };
            let new_req = inject_payload(&cx.req, ip, &v);
            let resp = cx.send(new_req.as_bytes());
            let mut issue = mk_point(
                name,
                "high",
                "Certain",
                &cx.entry,
                ip,
                format!("The application appears to trust the \"{header}\" header of the JWT found in the {place}. It fetched {what} from an arbitrary URL provided in this header and attempted to use it to verify the signature."),
            )
            .with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), resp.as_deref())]);
            issue.name = name.into();
            let delivery = crate::oob::delivery_sentence("The JWT", domain, &place, ".");
            cx.shared
                .oob
                .register_delivered(oob_token.clone(), Some("HTTP"), issue, delivery);
        }
        cx.progress();
    }
}

/// Each JWT issue can be switched off on its own in the scan configuration.
pub fn jwt_issue_id(name: &str) -> String {
    format!("active.jwt.{}", name.to_ascii_lowercase().replace(' ', "-"))
}

pub fn rnd_letters(n: usize) -> String {
    use rand::Rng;
    let mut g = rand::thread_rng();
    (0..n)
        .map(|_| (b'a' + g.gen_range(0..26)) as char)
        .collect()
}

/// A request to `path` on the scanned host with `method`, the base
/// request's headers (no body, no cookies of framing), plus `extra`
/// headers and `body`.
pub fn host_request(
    cx: &ScanCtx,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let parts = util::parse_http(cx.req.as_bytes());
    let mut out = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in &parts.headers {
        if matches!(
            k.to_ascii_lowercase().as_str(),
            "content-length" | "content-type" | "transfer-encoding"
        ) {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() || method == "PUT" || method == "POST" {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("\r\n");
    let mut v = out.into_bytes();
    v.extend_from_slice(body);
    v
}

/// The response's status code and body.
pub fn status_body(resp: &[u8]) -> (u16, &[u8]) {
    let p = util::parse_http(resp);
    let st = p
        .status
        .split_whitespace()
        .next()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (st, &resp[p.head_len.min(resp.len())..])
}

/// Expression Language injection, burp.Zbhh (selected by Znq for
/// EXPRESSION_LANGUAGE_ENGINE_INJECTION inside Zi6p): the value is
/// followed by `${"z<a>z".toString().replace("<a>", "<b>")}` between two
/// random delimiters; reported when the response holds the evaluated
/// `<d1>z<b>z<d2>` (Ziqe.ZT). Zelb: High, Certain; detail burp.Zwfo.
pub(crate) struct ExpressionLanguageInjection;

impl PointCheck for ExpressionLanguageInjection {
    fn id(&self) -> &'static str {
        "active.expression-language-injection"
    }
    fn issue(&self) -> &'static str {
        "Expression Language injection"
    }
    /// burp.Zi6p.Zh: every kind, server-side.
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
        let (d1, d2) = (rnd_letters(6), rnd_letters(6));
        let (mut a, mut b) = (rnd_letters(5), rnd_letters(5));
        while a == b {
            a = rnd_letters(5);
            b = rnd_letters(5);
        }
        let (payload, expected) = el_probe(&d1, &d2, &a, &b);
        let full = format!("{}{payload}", ip.value);
        let new_req = inject_payload(&cx.req, ip, &full);
        if let Some(resp) = cx.send(new_req.as_bytes()) {
            let (_, body) = status_body(&resp);
            if find_sub(body, expected.as_bytes()) {
                let detail = format!(
                    "The {} appears to be vulnerable to Expression Language injection attacks. <br><br>The payload <b>{}</b> was submitted in the {}. This payload contains an Expression Language statement.<br><br>The server response contained the string <b>{}</b>. This indicates that the injected statement was executed.",
                    ip.describe_short(true),
                    util::html_encode(&payload),
                    ip.describe_short(false),
                    util::html_encode(&expected)
                );
                cx.report(vec![
                    mk_point(
                        "Expression Language injection",
                        "high",
                        "Certain",
                        &cx.entry,
                        ip,
                        detail,
                    )
                    .with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), Some(&resp))]),
                ]);
            }
        }
        cx.progress();
    }
}

/// burp.Zbhh: the payload and the string its evaluation produces.
pub(crate) fn el_probe(d1: &str, d2: &str, a: &str, b: &str) -> (String, String) {
    (
        format!("{d1}${{\"z{a}z\".toString().replace(\"{a}\", \"{b}\")}}{d2}"),
        format!("{d1}z{b}z{d2}"),
    )
}

pub(crate) fn xpath_boolean_pairs(value: &str) -> Vec<(String, String)> {
    vec![
        (
            format!("{value} and true()"),
            format!("{value} and false()"),
        ),
        (
            format!("{value} and not(false())"),
            format!("{value} and not(true())"),
        ),
        (
            format!("{value}' and true() and 'x'='x"),
            format!("{value}' and false() and 'x'='y"),
        ),
        (
            format!("{value}\" and true() and \"x\"=\"x"),
            format!("{value}\" and false() and \"x\"=\"y"),
        ),
    ]
}

pub fn strip_reflection(response: &[u8], payload: &str) -> Vec<u8> {
    fn strip(response: &[u8], needle: &[u8]) -> Vec<u8> {
        if needle.is_empty() {
            return response.to_vec();
        }
        let mut out = Vec::with_capacity(response.len());
        let mut rest = response;
        while let Some(index) = rest.windows(needle.len()).position(|w| w == needle) {
            out.extend_from_slice(&rest[..index]);
            rest = &rest[index + needle.len()..];
        }
        out.extend_from_slice(rest);
        out
    }
    let plain = strip(response, payload.as_bytes());
    let stripped = strip(&plain, util::html_encode(payload).as_bytes());
    let parts = util::parse_http(&stripped);
    if util::get_header(&parts.headers, "Content-Length").is_none() {
        return stripped;
    }
    let body = &stripped[parts.head_len..];
    let mut out = format!("{}\r\n", parts.first).into_bytes();
    for (name, value) in &parts.headers {
        if name.eq_ignore_ascii_case("Content-Length") {
            out.extend_from_slice(format!("{name}: {}\r\n", body.len()).as_bytes());
        } else {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

pub fn xpath_boolean_detection(
    baseline: &[u8],
    accuracy: crate::variations::Accuracy,
    value: &str,
    send: impl Fn(&str) -> Option<Vec<u8>>,
) -> Option<(String, String, Vec<crate::variations::Attr>)> {
    let clean_baseline = strip_reflection(baseline, value);
    for (positive, negative) in xpath_boolean_pairs(value) {
        let mut positive_send =
            || send(&positive).map(|response| strip_reflection(&response, &positive));
        let mut negative_send =
            || send(&negative).map(|response| strip_reflection(&response, &negative));
        if let Some(attributes) = crate::variations::differential(
            Some(&clean_baseline),
            accuracy,
            &mut positive_send,
            &mut negative_send,
        ) {
            return Some((positive, negative, attributes));
        }
    }
    None
}

pub fn find_sub(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && hay.len() >= needle.len()
        && hay.windows(needle.len()).any(|w| w == needle)
}

/// XPath error signatures of burp.Ze2s (decoded strings), with the API
/// each suggests (Zwvf.ZK: 1 ASP.NET, 2 Java). The grouping by API is
/// WebProbe's reading of the vendor names; Burp's index tables are stripped.
pub(crate) const XPATH_ERRORS: [(&str, u8); 11] = [
    ("System.Xml.XPath", 1),
    ("MS.Internal.Xml.XPath", 1),
    ("has an invalid token", 1),
    ("This is an unclosed string", 1),
    ("A location path was expected", 1),
    ("javax.xml.xpath.XPathExpressionException", 2),
    ("com.sun.org.apache.xpath.internal.compiler.XPathParser", 2),
    ("javax.xml.transform.TransformerException", 2),
    ("misquoted literal", 2),
    ("Extra illegal tokens", 2),
    ("Expression must evaluate to a node-set", 2),
];

/// The first XPath error signature in `body` the baseline does not have.
pub(crate) fn xpath_error_in(body: &[u8], baseline: &[u8]) -> Option<(&'static str, u8)> {
    XPATH_ERRORS
        .iter()
        .copied()
        .find(|(sig, _)| find_sub(body, sig.as_bytes()) && !find_sub(baseline, sig.as_bytes()))
}

/// XPath injection, error-based half of burp.Zppj / Zxp6 (shared engine
/// Zg_c with SQL injection): a quote appended to the value, then a double
/// quote; reported when an XPath error message appears that the base
/// response lacks. Zs76.Zs: High, Firm; detail burp.Zwvf. The boolean half
/// uses Zuuv-style true()/false() pairs with the response-variation engine.
pub(crate) struct XPathInjection;

impl PointCheck for XPathInjection {
    fn id(&self) -> &'static str {
        "active.xpath-injection"
    }
    fn issue(&self) -> &'static str {
        "XPath injection"
    }
    /// burp.Zg_c: as the SQL injection checks.
    fn applies_to(&self, ip: &InsertionPoint) -> bool {
        SqlErrorInjection.applies_to(ip)
    }
    fn server_side(&self) -> bool {
        true
    }
    fn run(&self, cx: &ScanCtx, _st: &mut ScanState, pt: &mut PointRun) {
        if cx.stopped() || cx.baseline.raw.is_empty() {
            cx.progress();
            return;
        }
        let ip = pt.ip;
        let (_, base_body) = status_body(&cx.baseline.raw);
        let mut reported = false;
        for quote in ["'", "\""] {
            if cx.stopped() {
                break;
            }
            let payload = format!("{}{quote}", ip.value);
            let new_req = inject_payload(&cx.req, ip, &payload);
            let Some(resp) = cx.send(new_req.as_bytes()) else {
                continue;
            };
            let (_, body) = status_body(&resp);
            if let Some((_, api)) = xpath_error_in(body, base_body) {
                let mut detail = format!(
                    "The {} appears to be vulnerable to XPath injection attacks. The payload <b>{}</b> was submitted in the {}, and an XPath error message was returned. You should review the contents of the error message, and the application's handling of other input, to confirm whether a vulnerability is present.",
                    ip.describe_short(true),
                    util::html_encode(quote),
                    ip.describe_short(false)
                );
                detail.push_str(if api == 1 {
                    "<br><br>The application appears to be using the ASP.NET XPath APIs."
                } else {
                    "<br><br>The application appears to be using the Java XPath APIs."
                });
                cx.report(vec![
                    mk_point("XPath injection", "high", "Firm", &cx.entry, ip, detail)
                        .with_evidence(vec![ScanEvidence::new(new_req.as_bytes(), Some(&resp))]),
                ]);
                reported = true;
                break;
            }
        }
        if !reported && !cx.stopped() {
            let accuracy = cx.settings.accuracy;
            let rec = Recorder::default();
            let send = |payload: &str| {
                if cx.stopped() {
                    return None;
                }
                let req = inject_payload(&cx.req, ip, payload);
                rec.send(cx, payload, req.as_bytes())
            };
            if let Some((positive, negative, attributes)) =
                xpath_boolean_detection(&cx.baseline.raw, accuracy, &ip.value, send)
            {
                cx.report(vec![mk_point(
                    "XPath injection",
                    "high",
                    "Tentative",
                    &cx.entry,
                    ip,
                    format!("True condition {positive:?} and false condition {negative:?} produced consistently different responses (attributes: {attributes:?})."),
                ).with_evidence(evidence([rec.last(&positive), rec.last(&negative)]))]);
            }
        }
        cx.progress();
    }
}

/// HTTP PUT method is enabled, burp.Zu8k (APH_HttpPutEnabled, per host):
/// PUT a file with a marker; a non-2xx answer ends the check; then GET it
/// and report when the marker comes back (Zu8k.java:42-88; Zxhh builds the
/// issue). Burp's path and marker constants are stripped (not
/// established): WebProbe PUTs a random .txt name in the request's
/// directory with a random marker. Severity / confidence from the KB
/// typical values (not established from Zxhh).
pub(crate) struct HttpPutEnabled;

impl RequestCheck for HttpPutEnabled {
    fn id(&self) -> &'static str {
        "active.http-put-enabled"
    }
    fn issue(&self) -> &'static str {
        "HTTP PUT method is enabled"
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
                .unwrap()
                .insert(format!("put|{scheme}://{}:{}", cx.host, cx.port))
        {
            return;
        }
        let dir = {
            let p = cx.entry.path.split('?').next().unwrap_or("/");
            p[..p.rfind('/').map(|i| i + 1).unwrap_or(1).min(p.len())].to_string()
        };
        let path = format!(
            "{}{}.txt",
            if dir.is_empty() { "/" } else { &dir },
            rnd_letters(10)
        );
        let marker = rnd_letters(16);
        let put = host_request(
            cx,
            "PUT",
            &path,
            &[("Content-Type", "text/plain")],
            marker.as_bytes(),
        );
        let Some(r1) = burp_send(cx, &put) else {
            return;
        };
        if !(200..300).contains(&status_body(&r1).0) {
            return;
        }
        let get = host_request(cx, "GET", &path, &[], b"");
        let Some(r2) = burp_send(cx, &get) else {
            return;
        };
        if find_sub(status_body(&r2).1, marker.as_bytes()) {
            let mut e = cx.entry.clone();
            e.path = path.clone();
            let i = mk(
                "high",
                "HTTP PUT method is enabled",
                &e,
                format!(
                    "The server allowed a file to be created with PUT: the file {} was uploaded and its contents were then retrieved.",
                    util::html_encode(&path)
                ),
            );
            let mut i = i.with_evidence(vec![
                ScanEvidence::new(&put, Some(&r1)),
                ScanEvidence::new(&get, Some(&r2)),
            ]);
            i.confidence = "Certain".into();
            cx.report(vec![i]);
        }
    }
}

/// burp.Zh7b.ZA: the paths probed for a JWK Set, in Burp's order.
pub(crate) const JWK_SET_PATHS: [&str; 8] = [
    "/oauth2/v1/keys",
    "/jwks.json",
    "/.well-known/jwks.json",
    "/.well-known/jwks_uri",
    "/.well-known/openid-configuration/jwks",
    "/openid/connect/jwks.json",
    "/oauth/discovery/keys",
    "/id/keys",
];

/// burp.Zwws.Zp and burp.Zw8f.ZO: whether `body` is a JWK Set (a JSON
/// object whose `keys` array holds at least one object with a string
/// `kty`) and, if so, the private key material in it: the string members
/// `d p q dp dq qi` and the strings of the `oth` array for RSA, `k` for
/// oct, `d` for EC and OKP. An element of `keys` that is not an object
/// ends the reading, as it does in Burp. `None`: not a JWK Set.
pub(crate) fn jwk_set_private_material(body: &[u8]) -> Option<Vec<String>> {
    let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    let mut keys = Vec::new();
    for item in doc.as_object()?.get("keys")?.as_array()? {
        let Some(key) = item.as_object() else { break };
        if key.get("kty").is_some_and(serde_json::Value::is_string) {
            keys.push(key);
        }
    }
    if keys.is_empty() {
        return None;
    }
    let mut private = Vec::new();
    for key in keys {
        let kty = key["kty"].as_str().unwrap_or_default();
        let members: &[&str] = match kty {
            "RSA" => &["d", "p", "q", "dp", "dq", "qi"],
            "oct" => &["k"],
            "EC" | "OKP" => &["d"],
            _ => &[],
        };
        private.extend(
            members
                .iter()
                .filter_map(|m| key.get(*m)?.as_str())
                .map(str::to_string),
        );
        if kty == "RSA"
            && let Some(other) = key.get("oth").and_then(serde_json::Value::as_array)
        {
            private.extend(other.iter().filter_map(|v| v.as_str()).map(str::to_string));
        }
    }
    Some(private)
}

/// JSON Web Key Set disclosed, burp.Zh7b (per host, not at the fast audit
/// speed): GET each of [`JWK_SET_PATHS`]; a body that is a JWK Set is
/// reported at that path (burp.Zbfr). Factory burp.Zmir.ZJ: Certain, and
/// High when the set holds private key material, else Information. Text
/// burp.Zwf3.
pub(crate) struct JwkSetDisclosed;

impl RequestCheck for JwkSetDisclosed {
    fn id(&self) -> &'static str {
        "active.jwk-set-disclosed"
    }
    fn issue(&self) -> &'static str {
        "Json Web Key Set disclosed"
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn run(&self, cx: &ScanCtx) {
        let (scheme, _) = origin_of(cx);
        if cx.stopped()
            || !cx.runs(self.issue())
            || matches!(cx.settings.speed, ScanSpeed::Fast)
            || !cx
                .state()
                .openapi_hosts
                .lock()
                .unwrap()
                .insert(format!("jwks|{scheme}://{}:{}", cx.host, cx.port))
        {
            return;
        }
        for path in JWK_SET_PATHS {
            if cx.stopped() {
                return;
            }
            let req = host_request(cx, "GET", path, &[], b"");
            let Some(resp) = burp_send(cx, &req) else {
                continue;
            };
            let Some(private) = jwk_set_private_material(status_body(&resp).1) else {
                continue;
            };
            let (sev, detail) = if private.is_empty() {
                (
                    "info",
                    "The application publicly exposes a JSON Web Key (JWK) Set. Although no private keys have been found in the JWK set, exposed public key components can also be useful for attackers.",
                )
            } else {
                (
                    "high",
                    "The application publicly exposes a JSON Web Key (JWK) Set that contains private keys. These could be used by an attacker to generate arbitrary valid JWTs.",
                )
            };
            let mut e = cx.entry.clone();
            e.path = path.into();
            let mut i = mk(sev, self.issue(), &e, detail)
                .with_evidence(vec![ScanEvidence::new(&req, Some(&resp))]);
            i.confidence = "Certain".into();
            cx.report(vec![i]);
        }
    }
}

/// Hidden HTTP 2, burp.Zpfw.Zw (APH_HiddenHttp2, per host): on an HTTPS
/// target only (Zp42.ZLX), the base request is sent again with
/// Zwk0.FORCE_HTTP2_NON_POOLED: ALPN offers only `h2`, and the request
/// goes out over HTTP/2 on a fresh connection whatever ALPN selected. A
/// response with a non-zero status raises the issue (Zpfw.Zd) at the base
/// request. An I/O failure ends the check without an issue. Factory
/// burp.Zhhg.Zf: Information, Certain, no detail map; text burp.Zwfq.
///
/// Burp skips a host that an ordinary connection negotiated `h2` with by
/// ALPN within the DNS resolution timeout (burp.Zhx5.ZS, recorded by
/// burp.Zpf9.Zq). WebProbe keeps no such record: the probe's own handshake
/// stands in for it, and a host whose ALPN selected `h2` is not reported.
/// Burp also returns, logging Zm8i.H2_DISABLED, when the project option
/// project_options.http.http2.enable_http2 is off (Zps6.ZUp). WebProbe's
/// upstream connections always offer HTTP/2, so that option gates only
/// this check (`scan_config::shared_config().http.http2_enabled`).
/// After reporting, Zpfw.Zd marks the host in the scan task (Zggr.Z_o),
/// which only the request smuggling check reads (burp.Zg3d.Zn, to pick its
/// HTTP/2 techniques); WebProbe has no such check, so nothing is marked.
pub(crate) struct HiddenHttp2;

impl RequestCheck for HiddenHttp2 {
    fn id(&self) -> &'static str {
        "active.hidden-http2"
    }
    fn issue(&self) -> &'static str {
        "Hidden HTTP 2"
    }
    fn scope(&self) -> Scope {
        Scope::Host
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped()
            || !cx.runs(self.issue())
            || !cx.http2_enabled
            || !cx.entry.https
            || !cx
                .state()
                .openapi_hosts
                .lock()
                .unwrap()
                .insert(format!("hidden-h2|https://{}:{}", cx.host, cx.port))
        {
            return;
        }
        let resp = {
            let _forced = crate::net::http2_scope(crate::net::Http2Choice {
                want_h2: Some(true),
                strip_connection: true,
                force_h2: true,
            });
            burp_send(cx, cx.req.as_bytes())
                .filter(|_| crate::net::last_protocol() == crate::net::HTTP2_WITHOUT_ALPN)
        };
        let Some(resp) = resp else {
            return;
        };
        if status_body(&resp).0 == 0 {
            return;
        }
        let mut i = mk(
            "info",
            self.issue(),
            &cx.entry,
            "The server did not list <b>h2</b> in the ALPN field during the TLS handshake. However, when a HTTP/2 request was sent over the TLS connection, a HTTP/2 response was received. This indicates that the server does support HTTP/2, despite not advertising it.",
        )
        .with_evidence(vec![ScanEvidence::new(cx.req.as_bytes(), Some(&resp))]);
        i.confidence = "Certain".into();
        cx.report(vec![i]);
    }
}

/// ASP.NET tracing enabled, burp.Ze3_ (per host): GET /trace.axd; a 200
/// whose HTML has `<span class="tracecontent">` (Zsqx.Zh). Zr17.Zv case 1:
/// High, Certain; detail burp.Zwjg ("application" level).
pub(crate) struct AspNetTracing;

impl RequestCheck for AspNetTracing {
    fn id(&self) -> &'static str {
        "active.aspnet-tracing"
    }
    fn issue(&self) -> &'static str {
        "ASP.NET tracing enabled"
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
                .unwrap()
                .insert(format!("trace.axd|{scheme}://{}:{}", cx.host, cx.port))
        {
            return;
        }
        let req = host_request(cx, "GET", "/trace.axd", &[], b"");
        let Some(resp) = burp_send(cx, &req) else {
            return;
        };
        let (st, body) = status_body(&resp);
        if st == 200 && has_tracecontent_span(body) {
            let mut e = cx.entry.clone();
            e.path = "/trace.axd".into();
            let mut i = mk(
                "high",
                "ASP.NET tracing enabled",
                &e,
                "ASP.NET tracing appears to be enabled at the application level.",
            )
            .with_evidence(vec![ScanEvidence::new(&req, Some(&resp))]);
            i.confidence = "Certain".into();
            cx.report(vec![i]);
        }
    }
}

/// A `span` element whose class is exactly `tracecontent` (Zsqx).
pub(crate) fn has_tracecontent_span(body: &[u8]) -> bool {
    let low = String::from_utf8_lossy(body).to_ascii_lowercase();
    let mut at = 0;
    while let Some(i) = low[at..].find("<span").map(|i| at + i) {
        let end = low[i..].find('>').map(|e| i + e).unwrap_or(low.len());
        let tag = &low[i..end];
        if let Some(c) = tag.find("class=") {
            let v = tag[c + 6..].trim_start_matches(['"', '\'']);
            let v = v.split(['"', '\'', ' ', '>']).next().unwrap_or("");
            if v == "tracecontent" {
                return true;
            }
        }
        at = end.max(i + 1);
    }
    false
}

/// ASP.NET debugging enabled, burp.Zihl (per host): `DEBUG /Default.aspx`
/// with `Command: start-debug`; a 401 holding "Debug access denied to
/// '/Default.aspx'." (Zuv4 case 2: Information, Firm) or a 500 holding
/// "DebugSessionID corrupted or not provided." (case 1: Medium, Firm).
/// Detail burp.Zwjd.
pub(crate) struct AspNetDebugging;

impl RequestCheck for AspNetDebugging {
    fn id(&self) -> &'static str {
        "active.aspnet-debugging"
    }
    fn issue(&self) -> &'static str {
        "ASP.NET debugging enabled"
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
                .unwrap()
                .insert(format!("aspdebug|{scheme}://{}:{}", cx.host, cx.port))
        {
            return;
        }
        let req = host_request(
            cx,
            "DEBUG",
            "/Default.aspx",
            &[("Command", "start-debug")],
            b"",
        );
        let Some(resp) = burp_send(cx, &req) else {
            return;
        };
        let (st, body) = status_body(&resp);
        let verdict = match st {
            500 if find_sub(body, b"DebugSessionID corrupted or not provided.") => Some((
                "medium",
                "The user context used to scan the application appears to be permitted to perform debugging, so this is potentially an important issue.",
            )),
            401 if find_sub(body, b"Debug access denied to '/Default.aspx'.") => Some((
                "info",
                "The user context used to scan the application does not appear to be permitted to perform debugging, so this is not an immediately exploitable issue. However, if you were able to obtain or guess appropriate platform-level credentials, you may be able to perform debugging.",
            )),
            _ => None,
        };
        if let Some((sev, more)) = verdict {
            let mut e = cx.entry.clone();
            e.path = "/Default.aspx".into();
            let mut i = mk(
                sev,
                "ASP.NET debugging enabled",
                &e,
                format!("ASP.NET debugging is enabled on the server. {more}"),
            )
            .with_evidence(vec![ScanEvidence::new(&req, Some(&resp))]);
            i.confidence = "Firm".into();
            cx.report(vec![i]);
        }
    }
}

// ---------------------------------------------------------------- suspicious input transformation

/// burp.Zc1o (URL / body parameters, cookies, parameter names) and, with
/// `slash` false, burp.Zpap (URL path folder and filename; it leaves `/`
/// alone): the bytes of `s` (ISO-8859-1, wider characters as UTF-8) with
/// space " # % & + , / : ; < = > ? \ ^ { | }, the backquote and every byte outside
/// 0x20..0x7e percent-encoded in lower-case hex (net.portswigger.Zsh.ZY).
/// The "leave as is" sets (Zc1o.Zr, Zpap.ZC) are runtime configuration,
/// assumed empty as in [`encode_url_param`].
fn burp_url_encode(s: &str, slash: bool) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    let mut push = |b: u8| {
        let special = matches!(
            b,
            b' ' | b'"'
                | b'#'
                | b'%'
                | b'&'
                | b'+'
                | b','
                | b':'
                | b';'
                | b'<'
                | b'='
                | b'>'
                | b'?'
                | b'\\'
                | b'^'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
        ) || (slash && b == b'/');
        if special || !(0x20..0x7f).contains(&b) {
            out.push_str(&format!("%{b:02x}"));
        } else {
            out.push(b as char);
        }
    };
    for c in s.chars() {
        if (c as u32) <= 0xff {
            push(c as u32 as u8);
        } else {
            let mut buf = [0u8; 4];
            for &b in c.encode_utf8(&mut buf).as_bytes() {
                push(b);
            }
        }
    }
    out
}

/// The request for one payload of the suspicious input transformation
/// check, the payload in place of the value or after it (`append`), as
/// Burp's point encoder for the kind writes it (burp.Zfw9.Zr): burp.Zc1o
/// for query and body parameters, cookies and URL / body parameter names,
/// burp.Zpap for path segments, so `%41` arrives as `%2541` and the raw
/// bytes [0xc1][0x81] as `%c1%81`; a header value as written (burp.Zex2).
/// The other kinds go through [`inject_payload`], which builds the request
/// as a UTF-8 string: a payload with bytes above 0x7f cannot be placed there
/// byte for byte, so None (that probe is not sent for those kinds).
pub(crate) fn transformation_request(
    req: &str,
    ip: &InsertionPoint,
    payload: &str,
    append: bool,
) -> Option<String> {
    use crate::scan::insertion::NameSite;
    if ip.parent.is_none() {
        let url = |base: &str, slash: bool| {
            let p = burp_url_encode(payload, slash);
            if append { format!("{base}{p}") } else { p }
        };
        match &ip.kind {
            // A query or cookie value is kept as sent, already encoded.
            IpKind::Query | IpKind::Cookie => return Some(inject(req, ip, &url(&ip.value, true))),
            // A form body value is kept decoded.
            IpKind::Body => {
                return Some(inject(
                    req,
                    ip,
                    &url(&burp_url_encode(&ip.value, true), true),
                ));
            }
            IpKind::ParamName(NameSite::Url | NameSite::Body | NameSite::PhpPathInfo) => {
                return Some(inject(req, ip, &url("", true)));
            }
            IpKind::PathFolder(_) | IpKind::PathFilename(_) => {
                return Some(inject(req, ip, &url(&ip.value, false)));
            }
            // [`inject`] URL-decodes a header value: a '%' is sent as "%25".
            IpKind::Header => {
                let v = if append {
                    format!("{}{payload}", ip.value)
                } else {
                    payload.to_string()
                };
                return v
                    .is_ascii()
                    .then(|| inject(req, ip, &v.replace('%', "%25")));
            }
            IpKind::Json(_)
            | IpKind::Multipart { .. }
            | IpKind::EntireBody
            | IpKind::XmlParam { .. }
            | IpKind::XmlTag { .. }
            | IpKind::XmlAttr { .. }
            | IpKind::ParamName(NameSite::Multipart)
            | IpKind::Base64 { .. } => {}
        }
    }
    let v = if append {
        format!("{}{payload}", ip.value)
    } else {
        payload.to_string()
    };
    v.is_ascii().then(|| inject_payload(req, ip, &v))
}

/// burp.Zm3o.ZK: the payload is also appended to the value when the value
/// is not empty and the point is not a parameter name.
pub(crate) fn transformation_appends(ip: &InsertionPoint) -> bool {
    !ip.value.is_empty() && !matches!(ip.kind, IpKind::ParamName(_))
}

/// Suspicious input transformation (reflected), burp.Zeo6 in the audit
/// stage (burp.Zcug registers it for SUSPICIOUS_INPUT_TRANSFORMATION_
/// REFLECTED) with burp.Zppb's issue: the probes of
/// [`run_input_transformation_check`] against the point, one issue per
/// variant found, information, firm (burp.Zwvh.Zm: `new Zrh(type, variant,
/// 0, .., (byte) 2, (byte) 1, ..)`), the probe's exchange as evidence.
/// Burp shares the plain reflection probe with Input returned in response
/// (reflected) (burp.Zw7s); this check sends its own.
pub(crate) struct SuspiciousInputTransformation;

impl PointCheck for SuspiciousInputTransformation {
    fn id(&self) -> &'static str {
        "active.suspicious-input-transformation"
    }
    fn issue(&self) -> &'static str {
        "Suspicious input transformation (reflected)"
    }
    /// burp.Zeo6.Zh is only `Zgx0.Zn` (not on the server-side skip list):
    /// every kind.
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
        let log: std::cell::RefCell<Vec<(String, ScanEvidence)>> =
            std::cell::RefCell::new(Vec::new());
        let send = |payload: &str, append: bool| -> Option<Vec<u8>> {
            if cx.stopped() {
                return None;
            }
            let req = transformation_request(&cx.req, ip, payload, append)?;
            let resp = cx.send(req.as_bytes());
            log.borrow_mut().push((
                payload.to_string(),
                ScanEvidence::new(req.as_bytes(), resp.as_deref()),
            ));
            resp
        };
        let hits = run_input_transformation_check(
            transformation_appends(ip),
            webprobe_support::util::rnd_id,
            send,
        );
        let log = log.into_inner();
        let issues: Vec<ScanIssue> = hits
            .into_iter()
            .map(|h| {
                let mut i = mk(
                    "info",
                    self.issue(),
                    &cx.entry,
                    transformation_detail(
                        h.variant,
                        &ip.describe_bold(),
                        &ip.describe_short(false),
                        None,
                        &h.payload,
                        &h.reflection,
                    ),
                );
                i.confidence = "Firm".into();
                let ev = log.iter().rev().find(|(p, _)| *p == h.payload);
                i.with_evidence(ev.map(|(_, e)| e.clone()).into_iter().collect())
            })
            .collect();
        cx.report(issues);
        cx.progress();
    }
}
