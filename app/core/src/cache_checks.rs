//! Web cache poisoning and deception probes (R-10), using in-band canaries
//! and clean retrieval rather than response timing.

use super::*;

fn contains(resp: &[u8], canary: &str) -> bool {
    find_sub(resp, canary.as_bytes())
}

fn cacheable(resp: &[u8]) -> bool {
    let parts = util::parse_http(resp);
    let control = util::get_header(&parts.headers, "Cache-Control")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ["max-age", "s-maxage", "immutable", "public", "private"]
        .iter()
        .any(|token| control.contains(token))
    {
        return true;
    }
    if util::get_header(&parts.headers, "Age").is_some_and(|v| v.trim().parse::<u64>().is_ok()) {
        return true;
    }
    [
        "X-Cache",
        "CF-Cache-Status",
        "CDN-Cache-Status",
        "X-CDN-Cache-Status",
    ]
    .iter()
    .any(|name| {
        util::get_header(&parts.headers, name).is_some_and(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "hit" | "hit from cloudfront" | "cached"
            )
        })
    })
}

/// Prime with a canary-bearing header and retrieve the original request
/// without it. A cache-busted control must not contain the canary.
fn poisoning_attempt(
    base: &[u8],
    header: &str,
    value: &str,
    control_path: &str,
    send: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<(Vec<u8>, Vec<ScanEvidence>)> {
    let canary = value;
    let poison = net::replace_or_add_header(base, header, value);
    let first = send(&poison)?;
    if !contains(&first, canary) {
        return None;
    }
    let _prime = send(&poison)?;
    let clean = send(base)?;
    if !contains(&clean, canary) {
        return None;
    }
    let control_req = host_request_raw(base, control_path);
    let control = send(&control_req)?;
    if contains(&control, canary) {
        return None;
    }
    Some((
        poison,
        vec![
            ScanEvidence::new(base, Some(&first)),
            ScanEvidence::new(base, Some(&clean)),
            ScanEvidence::new(&control_req, Some(&control)),
        ],
    ))
}

/// Preserve the base request while replacing its target with a GET path.
fn host_request_raw(base: &[u8], path: &str) -> Vec<u8> {
    let parts = util::parse_http(base);
    let mut out = format!("GET {path} HTTP/1.1\r\n");
    for (name, value) in &parts.headers {
        if !matches!(
            name.to_ascii_lowercase().as_str(),
            "content-length" | "content-type" | "transfer-encoding"
        ) {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Repeat the dynamic baseline and a static-looking path. The bodies and
/// status must stay at the baseline while a cacheability signal appears.
fn deception_attempt(
    base_req: &[u8],
    base_resp: &[u8],
    method: &str,
    attack_path: &str,
    send: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<Vec<ScanEvidence>> {
    if cacheable(base_resp) || status_body(base_resp).0 != 200 {
        return None;
    }
    let (_, base_body) = status_body(base_resp);
    for _ in 0..2 {
        let resp = send(base_req)?;
        let (status, body) = status_body(&resp);
        if status != 200 || body != base_body {
            return None;
        }
    }
    let attack = host_request_raw(base_req, attack_path);
    let method_attack = if method.eq_ignore_ascii_case("GET") {
        attack
    } else {
        let mut head = attack;
        head[..4].copy_from_slice(b"HEAD");
        head
    };
    let mut evidence = Vec::new();
    let mut saw_cache = false;
    for _ in 0..3 {
        let resp = send(&method_attack)?;
        let (status, body) = status_body(&resp);
        if status != 200 || body != base_body {
            return None;
        }
        saw_cache |= cacheable(&resp);
        evidence.push(ScanEvidence::new(&method_attack, Some(&resp)));
    }
    saw_cache.then_some(evidence)
}

pub(crate) struct WebCachePoisoning;

impl RequestCheck for WebCachePoisoning {
    fn id(&self) -> &'static str {
        "active.web-cache-poisoning"
    }
    fn issue(&self) -> &'static str {
        "Web cache poisoning"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped() || cx.baseline.raw.is_empty() || !cx.runs(self.issue()) {
            return;
        }
        let marker = rnd_letters(12).to_ascii_lowercase();
        let path = cx.entry.path.split('?').next().unwrap_or("/");
        let control = format!("{path}?webprobe-cache-control={marker}");
        let variants = [
            ("X-Original-URL", format!("/{marker}/index.html")),
            ("X-Rewrite-URL", format!("/{marker}/index.html")),
            ("X-Forwarded-Host", format!("{marker}.example")),
            ("X-Host", format!("{marker}.example")),
            ("X-Forwarded-Server", format!("{marker}.example")),
        ];
        for (header, value) in variants {
            if cx.stopped() {
                return;
            }
            let mut send = |raw: &[u8]| burp_send(cx, raw);
            if let Some((probe, evidence)) =
                poisoning_attempt(cx.req.as_bytes(), header, &value, &control, &mut send)
            {
                let mut issue = mk(
                    "high",
                    self.issue(),
                    &cx.entry,
                    format!(
                        "The <b>{header}</b> header is not part of the cache key. A canary supplied through it appeared in a later retrieval without that header, while a cache-busted control stayed clean."
                    ),
                );
                issue.confidence = "Certain".into();
                let mut evidence = evidence;
                if let Some(first) = evidence.first_mut() {
                    first.request = probe.into();
                }
                cx.report(vec![issue.with_evidence(evidence)]);
                return;
            }
        }
    }
}

pub(crate) struct WebCacheDeception;

impl RequestCheck for WebCacheDeception {
    fn id(&self) -> &'static str {
        "active.web-cache-deception"
    }
    fn issue(&self) -> &'static str {
        "Web cache deception"
    }
    fn scope(&self) -> Scope {
        Scope::Request
    }
    fn run(&self, cx: &ScanCtx) {
        if cx.stopped()
            || cx.baseline.raw.is_empty()
            || !cx.runs(self.issue())
            || !matches!(
                cx.entry.method.to_ascii_uppercase().as_str(),
                "GET" | "HEAD"
            )
        {
            return;
        }
        let marker = rnd_letters(6).to_ascii_lowercase();
        let (path, query) = cx
            .entry
            .path
            .split_once('?')
            .map_or((cx.entry.path.as_str(), ""), |(p, q)| (p, q));
        for delimiter in ["/", "%2F", "%3F", "%23", "%00", "%20", "%0A", "%0D%0A"] {
            if cx.stopped() {
                return;
            }
            let attack = format!(
                "{path}{delimiter}{marker}.css{}",
                if query.is_empty() {
                    String::new()
                } else {
                    format!("?{query}")
                }
            );
            let mut send = |raw: &[u8]| burp_send(cx, raw);
            if let Some(evidence) = deception_attempt(
                cx.req.as_bytes(),
                &cx.baseline.raw,
                &cx.entry.method,
                &attack,
                &mut send,
            ) {
                let mut issue = mk(
                    "medium",
                    self.issue(),
                    &cx.entry,
                    format!(
                        "A static-looking path variant <b>{}</b> returned the dynamic response with cacheability evidence, while the original response was not cacheable.",
                        util::html_encode(&attack)
                    ),
                );
                issue.confidence = "Certain".into();
                cx.report(vec![issue.with_evidence(evidence)]);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(body: &str, cache: bool) -> Vec<u8> {
        let control = if cache {
            "Cache-Control: public, max-age=60\r\n"
        } else {
            ""
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{control}Content-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    #[test]
    fn poisoning_requires_clean_retrieval_and_an_independent_control() {
        let base = b"GET /account HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut send = |req: &[u8]| {
            let text = String::from_utf8_lossy(req);
            if text.contains("webprobe-cache-control") {
                Some(resp("control", false))
            } else if text.contains("X-Forwarded-Host:") || text.starts_with("GET /account") {
                Some(resp("cached-canary.example", false))
            } else {
                Some(resp("ordinary", false))
            }
        };
        let hit = poisoning_attempt(
            base,
            "X-Forwarded-Host",
            "canary.example",
            "/account?webprobe-cache-control=x",
            &mut send,
        );
        assert!(hit.is_some());
        let mut negative = |_req: &[u8]| Some(resp("ordinary", false));
        assert!(
            poisoning_attempt(
                base,
                "X-Host",
                "canary.example",
                "/account?webprobe-cache-control=x",
                &mut negative
            )
            .is_none()
        );
    }

    #[test]
    fn deception_requires_cache_evidence_on_the_static_variant() {
        let base = b"GET /account HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let base_resp = resp("private account", false);
        let mut cached = |req: &[u8]| {
            let cached = String::from_utf8_lossy(req).contains(".css");
            Some(resp("private account", cached))
        };
        assert!(
            deception_attempt(base, &base_resp, "GET", "/account/abcdef.css", &mut cached)
                .is_some()
        );
        let mut dynamic = |_req: &[u8]| Some(resp("private account", false));
        assert!(
            deception_attempt(base, &base_resp, "GET", "/account/abcdef.css", &mut dynamic)
                .is_none()
        );
        let already_cached = resp("private account", true);
        assert!(
            deception_attempt(
                base,
                &already_cached,
                "GET",
                "/account/abcdef.css",
                &mut dynamic
            )
            .is_none()
        );
    }
}
