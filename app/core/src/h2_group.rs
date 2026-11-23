//! R-12 "Send group in sequence (single connection)" over HTTP/2: one TLS
//! connection, one preface, then the group's requests on client streams
//! 1, 3, 5... in tab order (burp.Zx_o over the group's shared h2
//! connection). HTTP/1 groups and per-connection sending live in
//! `send_group`; only the h2 group transports are here.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::h2::{self, Conn};
use crate::net::{Shared, UpstreamConn};
use crate::send_group::{self, GroupItem, GroupResult, SequenceEnd};

/// Send every item over one h2 connection, in order. Opens the connection
/// on the first item's target (single-connection groups pass validation
/// only when every item shares it).
pub fn run_single_connection(
    shared: &Shared,
    items: &[GroupItem],
    cancel: &AtomicBool,
    mut on_result: impl FnMut(usize, GroupResult),
) -> SequenceEnd {
    let Some(first) = items.first() else { return SequenceEnd::Completed };
    let _tool = crate::net::tool_scope("Repeater");
    let conn = match send_group::open_conn(shared, &first.host, first.port, first.https, true) {
        Ok(c) => c,
        Err(e) => {
            on_result(0, send_group::finish_item(shared, first, &first.request, Err(e), None));
            return SequenceEnd::Cancelled(0);
        }
    };
    let UpstreamConn::Tls(_) = conn else {
        // h2 without TLS (h2c) is not a Repeater group case.
        on_result(
            0,
            send_group::finish_item(shared, first, &first.request, Err("h2 group over cleartext is not supported".into()), None),
        );
        return SequenceEnd::Cancelled(0);
    };
    let mut conn = Conn::new(conn);
    for (n, item) in items.iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            return SequenceEnd::Cancelled(n);
        }
        let t0 = std::time::Instant::now();
        let (req, hook) = send_group::hooked(shared, item);
        let outcome = crate::h2::request_from_raw(&req, "https")
            .ok_or_else(|| "h2: request without Host header".to_string())
            .and_then(|h2req| conn.exchange(&h2req, None).map_err(|e| e.message()));
        let unknown = outcome.as_ref().err().is_some_and(|e| send_group::unknown_host(e));
        let mut r = send_group::finish_item(shared, item, &req, outcome.map(|r| (r, None)), hook);
        r.elapsed_ms = t0.elapsed().as_millis();
        on_result(n, r);
        if unknown {
            return SequenceEnd::UnknownHost(n);
        }
    }
    SequenceEnd::Completed
}

/// R-12 "Send group in parallel" over HTTP/2 — Burp's single-packet
/// attack (burp.Zglm): one connection, one preface, every stream's
/// frames in a single write, then the responses pumped together. The
/// arrival numbering follows the first response frame per stream.
pub fn run_parallel_single_packet(
    shared: &Shared,
    items: &[GroupItem],
    cancel: &AtomicBool,
    mut on_result: impl FnMut(usize, GroupResult),
) -> SequenceEnd {
    use std::io::Write as _;
    let Some(first) = items.first() else { return SequenceEnd::Completed };
    if cancel.load(Ordering::SeqCst) {
        return SequenceEnd::Cancelled(0);
    }
    let _tool = crate::net::tool_scope("Repeater");
    let total = items.len();
    // Transform every request first (cookie jar, session rules — the same
    // two steps send_group::hooked applies) so the whole burst can go out
    // in one write.
    let mut requests = Vec::with_capacity(total);
    let mut hooks = Vec::with_capacity(total);
    for item in items {
        let (req, hook) = send_group::hooked(shared, item);
        requests.push(req);
        hooks.push(hook);
    }
    // Validate the whole group before connecting: the burst precedes any
    // WINDOW_UPDATE, so it must fit in the peer's initial connection
    // window, and every request must parse.
    let prepared = (|| -> Result<Vec<h2::H2Request>, String> {
        let mut reqs = Vec::with_capacity(total);
        for req in &requests {
            reqs.push(h2::request_from_raw(req, "https").ok_or_else(|| "h2: request without Host header".to_string())?);
        }
        h2::check_burst_window(reqs.iter().map(|r| r.body.len()))?;
        Ok(reqs)
    })();
    let reqs = match prepared {
        Ok(r) => r,
        Err(e) => {
            for (n, item) in items.iter().enumerate() {
                let req = std::mem::take(&mut requests[n]);
                let hook = hooks[n].take();
                on_result(n, send_group::finish_item(shared, item, &req, Err(e.clone()), hook));
            }
            return SequenceEnd::Completed;
        }
    };
    let run = send_group::open_conn(shared, &first.host, first.port, first.https, true)
        .and_then(|conn| {
            let mut conn = Conn::new(conn);
            let burst = conn.burst_frames(&reqs).map_err(|e| e.message())?;
            // The single packet: every stream's request in one write.
            conn.get_mut().write_all(&burst).and_then(|()| conn.get_mut().flush()).map_err(|e| format!("write: {e}"))?;
            let arrival = conn.pump_all().map_err(|e| e.message())?;
            let mut responses = Vec::with_capacity(total);
            for sid in (0..total).map(|n| 2 * n as u32 + 1) {
                responses.push(conn.finish_stream(sid).map_err(|e| e.message()));
            }
            Ok((arrival, responses))
        });
    let (arrival, responses) = match run {
        Ok(ok) => ok,
        Err(e) => {
            for (n, item) in items.iter().enumerate() {
                let req = std::mem::take(&mut requests[n]);
                let hook = hooks[n].take();
                on_result(n, send_group::finish_item(shared, item, &req, Err(e.clone()), hook));
            }
            return SequenceEnd::Completed;
        }
    };
    for (n, item) in items.iter().enumerate() {
        let sid = 2 * n as u32 + 1;
        let at = arrival.iter().position(|s| *s == sid).map(|p| (p + 1, total));
        let req = std::mem::take(&mut requests[n]);
        let hook = hooks[n].take();
        let outcome = responses[n].clone().map(|r| (r, at));
        on_result(n, send_group::finish_item(shared, item, &req, outcome, hook));
    }
    SequenceEnd::Completed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Barrier};

    /// R-12 over HTTP/2, the single-packet attack: the whole group goes
    /// out on ONE connection at once. The lab answers each request only
    /// once ALL of them have arrived (a barrier per request): a client
    /// that sent the group one request at a time, waiting for each
    /// response, would deadlock against the barrier and time out instead
    /// of passing.
    #[test]
    fn parallel_single_packet_one_connection_all_at_once() {
        const N: usize = 6;
        let mut shared = Shared::new();
        // Trust the lab's CA for the upstream side (the pattern of
        // net::tests::tls_alpn_h2_roundtrip).
        let mut roots = rustls::RootCertStore::empty();
        roots.add(shared.mitm.ca_der()).unwrap();
        let mut cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        Arc::get_mut(&mut shared).unwrap().tls_upstream = Arc::new(cfg);
        let server_config = shared.mitm.server_config_with_alpn("localhost", vec![b"h2".to_vec()]).unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let gate = Arc::new(Barrier::new(N));
        let server = std::thread::spawn(move || {
            // ONE connection is all the lab serves; a second would hang.
            let (s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(60))).ok();
            let conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, s);
            tls.conn.complete_io(&mut tls.sock).ok();
            assert_eq!(tls.conn.alpn_protocol(), Some(b"h2".as_slice()), "the group must negotiate h2");
            let handler: crate::h2_server::Handler = Arc::new(move |raw, mut out| {
                let path = String::from_utf8_lossy(&raw).lines().next().unwrap_or("").split(' ').nth(1).unwrap_or("").to_string();
                // Answer only once every request is in.
                gate.wait();
                let _ = out.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{path}", path.len()).as_bytes());
            });
            crate::h2_server::serve(&mut tls, handler);
        });
        let items: Vec<GroupItem> = (0..N).map(|i| GroupItem {
            tab: i as u64,
            host: "localhost".into(),
            port,
            https: true,
            request: format!("GET /r{i} HTTP/1.1\r\nHost: localhost\r\n\r\n").into_bytes(),
            http2: true,
            websocket: false,
        }).collect();
        let cancel = AtomicBool::new(false);
        let got = Arc::new(std::sync::Mutex::new(Vec::new()));
        let keep = got.clone();
        let end = send_group::run_parallel(&shared, &items, &cancel, move |n, r| keep.lock().unwrap().push((n, r)));
        assert_eq!(end, SequenceEnd::Completed);
        server.join().unwrap();
        let got = got.lock().unwrap();
        assert_eq!(got.len(), N);
        for (n, r) in got.iter() {
            let body = String::from_utf8_lossy(r.response.as_deref().unwrap_or_else(|| panic!("tab {n}: {:?}", r.error))).rsplit("\r\n\r\n").next().unwrap_or("").to_string();
            assert_eq!(body, format!("/r{n}"), "stream {n} got its own response");
        }
        let mut arrivals: Vec<usize> = got.iter().map(|(_, r)| r.arrival.map(|(a, _)| a).unwrap_or(0)).collect();
        arrivals.sort_unstable();
        assert_eq!(arrivals, (1..=N).collect::<Vec<_>>(), "every stream has its arrival number");
        assert!(got.iter().all(|(_, r)| r.arrival.is_some_and(|(_, total)| total == N)));
    }
}
