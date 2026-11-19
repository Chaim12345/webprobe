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
    let request = session_request(shared, port, false, request);
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
    // Debug aid: WB_TRACE=1 prints every upstream exchange slower than 2 s.
    if std::env::var_os("WB_TRACE").is_some() && t0.elapsed().as_millis() > 2000 {
        let first = req
            .split(|b| *b == b'\n')
            .next()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .unwrap_or_default();
        eprintln!(
            "TRACE slow {} ms {first} -> {:?}",
            t0.elapsed().as_millis(),
            r.as_ref().err()
        );
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

/// Resolve a host with the suite's DNS timeout (ProjectDefaults.json: domain_name_resolution_timeout).
pub fn resolve(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<Vec<std::net::SocketAddr>, String> {
    use std::net::ToSocketAddrs;
    let display = host.to_string();
    let (tx, rx) = mpsc::sync_channel::<Result<Vec<std::net::SocketAddr>, String>>(1);
    let host = host.to_string();
    crate::util::spawn_contained("net", move || {
        let r = match (host.as_str(), port).to_socket_addrs() {
            Ok(it) => Ok(it.collect::<Vec<std::net::SocketAddr>>()),
            Err(e) => Err(format!("dns {host}: {e}")),
        };
        let _ = tx.send(r);
    });
    rx.recv_timeout(Duration::from_millis(timeout_ms))
        .map_err(|_| format!("dns {display}: timed out after {timeout_ms} ms"))?
}
