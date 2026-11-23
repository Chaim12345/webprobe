// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// Sends a raw HTTP/1.1 request through the configured upstream route and reads
/// the whole response. Framing decides where the response ends, and the
/// connection is pooled per host when keep-alive is enabled
/// (ProjectDefaults.json http.http1.enable_keep_alive, default false).
pub fn send_raw(shared: &Shared, host: &str, port: u16, request: &[u8]) -> Upstream {
    send_raw_with(shared, host, port, request, None)
}

/// [`send_raw`] with a response sink (streaming responses, R-06); without
/// one, the tool on this thread gets Burp's "other tools" handling: a
/// streaming response is cut after its head.
pub fn send_raw_with(
    shared: &Shared,
    host: &str,
    port: u16,
    request: &[u8],
    sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
) -> Upstream {
    let request = jar_request(shared, host, false, request);
    let request = match session_request(shared, port, false, request) {
        Ok(request) => request,
        Err(error) => {
            return Upstream {
                resp: None,
                error: Some(error),
            }
        }
    };
    let mut tool_sink = tool_sink(shared, host, port, false, &request);
    let up = match (sink, tool_sink.as_mut()) {
        (Some(s), _) => send_from(shared, host, port, &request, Some(s)),
        (None, Some(t)) => send_from(shared, host, port, &request, Some(t)),
        (None, None) => send_from(shared, host, port, &request, None),
    };
    jar_response(shared, host, &request, &up);
    session_after(shared, host);
    log_tool_exchange(shared, host, port, false, &request, &up);
    up
}

/// The full URL of a request sent to host:port (for the streaming rule).
pub(crate) fn request_url(host: &str, port: u16, https: bool, request: &[u8]) -> String {
    let parts = util::parse_http(request);
    history_host(&HistEntry {
        host: host.to_string(),
        port,
        https,
        ..Default::default()
    }) + &path_of(&parts)
}

pub fn send_from(
    shared: &Shared,
    host: &str,
    port: u16,
    req: &[u8],
    sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
) -> Upstream {
    let t0 = std::time::Instant::now();
    let r = send_inner(shared, host, port, req, sink);
    // Opt-in timing diagnostics, never raw request lines or error strings.
    if std::env::var_os("WB_TRACE").is_some() && t0.elapsed().as_millis() > 2000 {
        tracing::debug!(target: "webprobe", event_code = "net.upstream.slow",
            elapsed_ms = t0.elapsed().as_millis() as u64, failed = r.is_err(),
            "Slow upstream exchange (request and error text omitted)");
    }
    match r {
        Ok(resp) => Upstream {
            resp: Some(resp),
            error: None,
        },
        Err(e) => Upstream {
            resp: None,
            error: Some(e),
        },
    }
}

// Resolve a host with the suite's DNS timeout (ProjectDefaults.json: domain_name_resolution_timeout).
pub use webprobe_support::dns::resolve;
