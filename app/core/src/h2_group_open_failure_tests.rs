//! Initial HTTP/2 group failure classification and hook/cancellation contracts.
use super::*;
use crate::net;
use crate::send_group::run_sequence;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

fn items(port: u16) -> Vec<GroupItem> {
    (0..3)
        .map(|n| GroupItem {
            tab: n,
            host: "127.0.0.1".into(),
            port,
            https: true,
            http2: true,
            websocket: false,
            request: format!("GET /{n} HTTP/1.1\r\nHost: localhost\r\n\r\n").into_bytes(),
        })
        .collect()
}
fn read_head(r: &mut impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0];
    while !out.ends_with(b"\r\n\r\n") {
        if r.read(&mut b).unwrap_or(0) == 0 {
            break;
        }
        out.push(b[0]);
        assert!(out.len() < 8192);
    }
    out
}

#[test]
fn refused_h2_open_reports_each_position_without_cancel_or_reconnect() {
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = dead.local_addr().unwrap().port();
    drop(dead);
    let shared = Shared::new();
    let mut got = Vec::new();
    assert_eq!(
        run_sequence(
            &shared,
            &items(port),
            true,
            &AtomicBool::new(false),
            |n, r| got.push((n, r))
        ),
        SequenceEnd::Completed
    );
    assert_eq!(
        got.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(got[0].1.error.as_deref().unwrap().contains("connect"));
    assert!(got[1..].iter().all(|(_, r)| r
        .error
        .as_deref()
        .unwrap()
        .contains("unavailable after an open error")));
    assert!(got.iter().all(|(_, r)| r.response.is_none()));
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 1);
}

#[test]
fn alpn_refusal_reports_all_positions_but_no_application_bytes_or_reconnect() {
    let mut shared = Shared::new();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(shared.mitm.ca_der()).unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::get_mut(&mut shared).unwrap().tls_upstream = Arc::new(config);
    let cfg = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"http/1.1".to_vec()])
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), s);
        let mut application = [0; 24];
        assert_eq!(tls.read(&mut application).unwrap_or(0), 0);
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    });
    let mut batch = items(port);
    for item in &mut batch {
        item.host = "localhost".into();
    }
    let mut got = Vec::new();
    assert_eq!(
        run_sequence(&shared, &batch, true, &AtomicBool::new(false), |n, r| got
            .push((n, r))),
        SequenceEnd::Completed
    );
    assert_eq!(got.len(), 3);
    assert!(got.iter().all(|(_, r)| r.error.is_some()));
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 1);
    server.join().unwrap();
}

#[test]
fn initial_h2_dns_failure_is_unknown_host_and_stops_at_first_position() {
    let shared = Shared::new();
    let mut batch = items(443);
    for item in &mut batch {
        item.host = "no-such-host.invalid".into();
    }
    let mut got = Vec::new();
    assert_eq!(
        run_sequence(&shared, &batch, true, &AtomicBool::new(false), |n, r| got
            .push((n, r))),
        SequenceEnd::UnknownHost(0)
    );
    assert_eq!(got.len(), 1);
    assert!(got[0].1.error.as_deref().unwrap().starts_with("dns "));
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 1);
}

#[test]
fn callback_stop_after_failed_open_prevents_later_callbacks_and_configured_hooks() {
    for stop in [false, true] {
        let shared = Shared::new();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let expected = if stop { 1 } else { 3 };
        let server = std::thread::spawn(move || {
            for _ in 0..expected {
                let (mut s, _) = l.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                assert!(read_head(&mut s).starts_with(b"GET /hook HTTP/1.1"));
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .unwrap();
            }
            l.set_nonblocking(true).unwrap();
            assert_eq!(
                l.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        });
        shared.macros.lock().unwrap().push(net::Macro {
            name: "after".into(),
            request: format!("GET /hook HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        });
        shared.session_rules.lock().unwrap().push(net::SessionRule {
            action: "post-request macro".into(),
            value: "after".into(),
            tools: vec!["Repeater".into()],
            ..net::SessionRule::new()
        });
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let failed_port = dead.local_addr().unwrap().port();
        drop(dead);
        let cancel = AtomicBool::new(false);
        let mut got = Vec::new();
        let end = run_sequence(&shared, &items(failed_port), true, &cancel, |n, r| {
            got.push((n, r));
            if stop {
                cancel.store(true, Ordering::SeqCst);
            }
        });
        assert_eq!(
            end,
            if stop {
                SequenceEnd::Cancelled(1)
            } else {
                SequenceEnd::Completed
            }
        );
        assert_eq!(got.len(), expected);
        assert!(got[0].1.error.is_some());
        // One failed group attempt plus exactly the configured hook connections.
        assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 1 + expected);
        server.join().unwrap();
    }
}
