//! R-12 "Send group in sequence (single connection)" over HTTP/2: one TLS
//! connection, one preface, then the group's requests on client streams
//! 1, 3, 5... in tab order (burp.Zx_o over the group's shared h2
//! connection). HTTP/1 groups and per-connection sending live in
//! `send_group`; only the h2 single-connection walk is here.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::h2;
use crate::net::Shared;
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
    let Some(first) = items.first() else {
        return SequenceEnd::Completed;
    };
    let mut conn = match send_group::open_conn(shared, first) {
        Ok(c) => c,
        Err(e) => {
            let up = crate::net::Upstream {
                resp: None,
                error: Some(e),
            };
            on_result(0, GroupResult::from_up(Vec::new(), up, "HTTP/2", 0));
            return SequenceEnd::Cancelled(0);
        }
    };
    if let Err(e) = h2::send_preface(&mut conn) {
        let up = crate::net::Upstream {
            resp: None,
            error: Some(e),
        };
        on_result(0, GroupResult::from_up(Vec::new(), up, "HTTP/2", 0));
        return SequenceEnd::Cancelled(0);
    }
    for (n, item) in items.iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            return SequenceEnd::Cancelled(n);
        }
        let sid = 2 * n as u32 + 1;
        let t0 = std::time::Instant::now();
        let (sent, up) = send_group::hooked(shared, item, |request| {
            let req = h2::request_from_raw(request, "https")
                .ok_or_else(|| "the request is not a valid HTTP request".to_string())?;
            h2::exchange_on(&mut conn, sid, &req, None)
        });
        let stop = up.error.as_deref().is_some_and(send_group::unknown_host);
        on_result(
            n,
            GroupResult::from_up(sent, up, "HTTP/2", t0.elapsed().as_millis()),
        );
        if stop {
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
    let Some(first) = items.first() else {
        return SequenceEnd::Completed;
    };
    if cancel.load(Ordering::SeqCst) {
        return SequenceEnd::Cancelled(0);
    }
    // Transform every request first (cookie jar, session rules — the same
    // two steps send_group::hooked applies) so the whole burst can go out
    // in one write.
    let mut requests = Vec::with_capacity(items.len());
    for item in items {
        let request = crate::net::jar_request(shared, &item.host, item.https, &item.request);
        requests
            .push(crate::net::session_request(shared, item.port, item.https, request).into_owned());
    }
    let (sent_all, up_all) = match send_group::open_conn(shared, first).and_then(|mut conn| {
        // Validate the whole group's DATA before connecting: the
        // burst precedes any WINDOW_UPDATE, so it must fit in the
        // peer's initial connection window.
        let mut reqs = Vec::with_capacity(requests.len());
        for request in &requests {
            reqs.push(
                h2::request_from_raw(request, "https")
                    .ok_or_else(|| "the request is not a valid HTTP request".to_string())?,
            );
        }
        h2::check_burst_window(reqs.iter().map(|r| r.body.len()))?;
        h2::send_preface(&mut conn)?;
        let mut burst = Vec::new();
        for (n, req) in reqs.iter().enumerate() {
            let sid = 2 * n as u32 + 1;
            burst.extend(h2::request_frames(sid, req)?);
        }
        // The single packet: every stream's request in one write.
        conn.write_all(&burst).map_err(|e| format!("write: {e}"))?;
        conn.flush().ok();
        let mut rxs: Vec<h2::Rx> = (0..items.len())
            .map(|n| h2::Rx::new(2 * n as u32 + 1))
            .collect();
        let arrival = h2::pump_all(&mut conn, &mut rxs)?;
        Ok::<_, String>((arrival, rxs))
    }) {
        Ok(ok) => ok,
        Err(e) => {
            for (n, item) in items.iter().enumerate() {
                let up = crate::net::Upstream {
                    resp: None,
                    error: Some(e.clone()),
                };
                let request = std::mem::take(&mut requests[n]);
                finish_item(
                    shared,
                    item,
                    request,
                    up,
                    "HTTP/2",
                    0,
                    None,
                    items.len(),
                    n,
                    &mut on_result,
                );
            }
            return SequenceEnd::Completed;
        }
    };
    let (arrival, mut rxs) = (sent_all, up_all);
    for (n, item) in items.iter().enumerate() {
        let sid = 2 * n as u32 + 1;
        let pos = rxs
            .iter()
            .position(|rx| rx.sid() == sid)
            .expect("one Rx per stream");
        let rx = rxs.swap_remove(pos);
        let up = match rx.finish() {
            Ok(resp) => crate::net::Upstream {
                resp: Some(resp),
                error: None,
            },
            Err(e) => crate::net::Upstream {
                resp: None,
                error: Some(e),
            },
        };
        let at = arrival.iter().position(|s| *s == sid).map(|p| p + 1);
        let request = std::mem::take(&mut requests[n]);
        finish_item(
            shared,
            item,
            request,
            up,
            "HTTP/2",
            0,
            at,
            items.len(),
            n,
            &mut on_result,
        );
    }
    SequenceEnd::Completed
}

/// The per-item bookkeeping send_group::hooked does after a response:
/// cookie jar, session rules, tool log, and the result callback.
#[allow(clippy::too_many_arguments)] // one per send-group result channel
fn finish_item(
    shared: &Shared,
    item: &GroupItem,
    request: Vec<u8>,
    up: crate::net::Upstream,
    protocol: &'static str,
    elapsed_ms: u128,
    arrival: Option<usize>,
    total: usize,
    n: usize,
    on_result: &mut impl FnMut(usize, GroupResult),
) {
    crate::net::jar_response(shared, &item.host, &request, &up);
    crate::net::session_after(shared, &item.host);
    crate::net::log_tool_exchange(shared, &item.host, item.port, item.https, &request, &up);
    let mut r = GroupResult::from_up(request, up, protocol, elapsed_ms);
    r.arrival = arrival.map(|a| (a, total));
    on_result(n, r);
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
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        Arc::get_mut(&mut shared).unwrap().tls_upstream = Arc::new(cfg);
        let server_config = shared
            .mitm
            .server_config_with_alpn("localhost", vec![b"h2".to_vec()])
            .unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let gate = Arc::new(Barrier::new(N));
        let server = std::thread::spawn(move || {
            // ONE connection is all the lab serves; a second would hang.
            let (s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(60)))
                .ok();
            let conn = rustls::ServerConnection::new(server_config).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, s);
            tls.conn.complete_io(&mut tls.sock).ok();
            assert_eq!(
                tls.conn.alpn_protocol(),
                Some(b"h2".as_slice()),
                "the group must negotiate h2"
            );
            let handler: crate::h2_server::Handler = Arc::new(move |raw, mut out| {
                let path = String::from_utf8_lossy(&raw)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .split(' ')
                    .nth(1)
                    .unwrap_or("")
                    .to_string();
                // Answer only once every request is in.
                gate.wait();
                let _ = out.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{path}",
                        path.len()
                    )
                    .as_bytes(),
                );
            });
            crate::h2_server::serve(&mut tls, handler);
        });
        let items: Vec<GroupItem> = (0..N)
            .map(|i| GroupItem {
                tab: i as u64,
                host: "localhost".into(),
                port,
                https: true,
                request: format!("GET /r{i} HTTP/1.1\r\nHost: localhost\r\n\r\n").into_bytes(),
                http2: true,
                websocket: false,
            })
            .collect();
        let cancel = AtomicBool::new(false);
        let got = Arc::new(std::sync::Mutex::new(Vec::new()));
        let keep = got.clone();
        let end = send_group::run_parallel(&shared, &items, &cancel, move |n, r| {
            keep.lock().unwrap().push((n, r))
        });
        assert_eq!(end, SequenceEnd::Completed);
        server.join().unwrap();
        let got = got.lock().unwrap();
        assert_eq!(got.len(), N);
        for (n, r) in got.iter() {
            let body = String::from_utf8_lossy(
                r.response
                    .as_deref()
                    .unwrap_or_else(|| panic!("tab {n}: {:?}", r.error)),
            )
            .rsplit("\r\n\r\n")
            .next()
            .unwrap_or("")
            .to_string();
            assert_eq!(body, format!("/r{n}"), "stream {n} got its own response");
        }
        let mut arrivals: Vec<usize> = got
            .iter()
            .map(|(_, r)| r.arrival.map(|(a, _)| a).unwrap_or(0))
            .collect();
        arrivals.sort_unstable();
        assert_eq!(
            arrivals,
            (1..=N).collect::<Vec<_>>(),
            "every stream has its arrival number"
        );
        assert!(got
            .iter()
            .all(|(_, r)| r.arrival.is_some_and(|(_, total)| total == N)));
    }
}
