//! Regression coverage for source #7 behavior lost during the parity port.
use super::*;
use crate::sync::Mutex;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

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
fn request(port: u16) -> GroupItem {
    GroupItem {
        tab: 1,
        host: "localhost".into(),
        port,
        https: false,
        request: b"GET http://localhost/resource HTTP/2\r\nHost: localhost\r\n\r\n".to_vec(),
        http2: false,
        websocket: false,
    }
}
fn trusted() -> Arc<Shared> {
    let mut shared = Shared::new();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(shared.mitm.ca_der()).unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::get_mut(&mut shared).unwrap().tls_upstream = Arc::new(config);
    shared
}

#[test]
fn source_http_proxy_uses_absolute_form_without_connect_for_both_h1_modes() {
    for parallel in [false, true] {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = l.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let req = read_head(&mut socket);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            req
        });
        let shared = Shared::new();
        *shared.upstream.lock() = crate::upstream::UpstreamConfig {
            kind: crate::upstream::UpstreamKind::Http,
            host: "127.0.0.1".into(),
            port: port.to_string(),
            ..Default::default()
        };
        let mut item = request(8081);
        item.host = "target.invalid".into();
        item.request = b"GET /resource HTTP/2\r\nHost: target.invalid:8081\r\n\r\n".to_vec();
        let got = Mutex::new(Vec::new());
        let cancel = AtomicBool::new(false);
        if parallel {
            run_parallel(&shared, &[item], &cancel, |_, r| got.lock().push(r));
        } else {
            run_sequence(&shared, &[item], false, &cancel, |_, r| got.lock().push(r));
        }
        assert!(got.lock()[0].error.is_none());
        assert!(
            server
                .join()
                .unwrap()
                .starts_with(b"GET http://target.invalid:8081/resource HTTP/1.1\r\n")
        );
        assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn source_direct_wire_normalizes_absolute_uri_and_cleartext_h2_display() {
    let shared = Shared::new();
    let mut item = request(80);
    item.http2 = true;
    assert!(http1_wire(&shared, &item, &item.request).starts_with(b"GET /resource HTTP/1.1\r\n"));
}

#[test]
fn source_tls_pins_h1_and_refuses_unnegotiated_h2_before_request_bytes() {
    for h2 in [false, true] {
        let shared = trusted();
        let cfg = shared
            .mitm
            .server_config_with_alpn("localhost", vec![b"http/1.1".to_vec()])
            .unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), s);
            let handshake = tls.conn.complete_io(&mut tls.sock);
            if !h2 {
                handshake.unwrap();
                assert_eq!(tls.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
                assert!(read_head(&mut tls).starts_with(b"GET /resource HTTP/1.1"));
                tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
            } else {
                // A TLS alert or an EOF is acceptable; application bytes are not.
                let mut b = [0; 24];
                assert_eq!(tls.read(&mut b).unwrap_or(0), 0);
            }
        });
        let mut item = request(port);
        item.https = true;
        item.http2 = h2;
        let mut got = Vec::new();
        run_sequence(&shared, &[item], false, &AtomicBool::new(false), |_, r| {
            got.push(r)
        });
        assert_eq!(got[0].error.is_some(), h2);
        server.join().unwrap();
    }
}

#[test]
fn source_tls_h1_last_byte_waits_for_every_prefix() {
    const N: usize = 4;
    let shared = trusted();
    let cfg = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"http/1.1".to_vec()])
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = events.clone();
    let server = std::thread::spawn(move || {
        let gate = Arc::new(Barrier::new(N));
        let mut workers = Vec::new();
        for index in 0..N {
            let (s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
            let (cfg, gate, seen) = (cfg.clone(), gate.clone(), seen.clone());
            workers.push(std::thread::spawn(move || {
                if index == N - 1 {
                    // Withhold the last TLS handshake. Other clients cannot
                    // release their barrier before the first prefixes are checked.
                    let start = std::time::Instant::now();
                    while seen.lock().len() < N - 1 {
                        assert!(start.elapsed() < Duration::from_secs(3));
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                let mut tls =
                    rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), s);
                let mut prefix = Vec::new();
                let mut byte = [0];
                while !prefix.ends_with(b"\r\n\r") {
                    tls.read_exact(&mut byte).unwrap();
                    prefix.push(byte[0]);
                }
                // Inspect TLS plaintext before the server gate: a whole-request
                // client must fail, even if the server delays reading its tail.
                if index < N - 1 {
                    tls.sock
                        .set_read_timeout(Some(Duration::from_millis(80)))
                        .unwrap();
                    let e = tls
                        .read(&mut byte)
                        .expect_err("last byte arrived before prefix release");
                    assert!(matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ));
                    tls.sock
                        .set_read_timeout(Some(Duration::from_secs(4)))
                        .unwrap();
                }
                seen.lock().push("prefix");
                gate.wait();
                tls.read_exact(&mut byte).unwrap();
                assert_eq!(byte, [b'\n']);
                seen.lock().push("last");
                tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    });
    let items: Vec<_> = (0..N)
        .map(|_| {
            let mut r = request(port);
            r.https = true;
            r
        })
        .collect();
    let got = Mutex::new(Vec::new());
    run_parallel(&shared, &items, &AtomicBool::new(false), |_, r| {
        got.lock().push(r)
    });
    assert!(got.lock().iter().all(|r| r.error.is_none()));
    server.join().unwrap();
    let ev = events.lock();
    assert_eq!(ev.len(), N * 2);
    assert!(ev[..N].iter().all(|e| *e == "prefix"));
}

#[test]
fn source_cancel_before_first_item_has_no_connection_or_callback() {
    for h2 in [false, true] {
        let shared = Shared::new();
        let mut item = request(9);
        item.https = h2;
        item.http2 = h2;
        let cancel = AtomicBool::new(true);
        assert_eq!(
            run_sequence(&shared, &[item], true, &cancel, |_, _| panic!(
                "cancelled item reported"
            )),
            SequenceEnd::Cancelled(0)
        );
        assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn source_closed_single_connection_is_not_used_for_another_request() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        read_head(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut b = [0];
        assert_eq!(
            s.read(&mut b).unwrap_or(0),
            0,
            "no second request on closed group connection"
        );
    });
    let shared = Shared::new();
    let a = request(port);
    let mut got = Vec::new();
    run_sequence(
        &shared,
        &[a.clone(), a],
        true,
        &AtomicBool::new(false),
        |_, r| got.push(r),
    );
    assert!(got[0].error.is_none());
    assert!(
        got[1]
            .error
            .as_deref()
            .unwrap()
            .contains("closed the group's connection")
    );
    server.join().unwrap();
}

#[test]
fn source_error_path_runs_post_request_macro_once_and_logs_error() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        read_head(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    let shared = Shared::new();
    shared.macros.lock().push(net::Macro {
        name: "after".into(),
        request: format!("GET /after HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    });
    shared.session_rules.lock().push(net::SessionRule {
        action: "post-request macro".into(),
        value: "after".into(),
        tools: vec!["Repeater".into()],
        ..net::SessionRule::new()
    });
    let _tool = net::tool_scope("Repeater");
    let item = request(9);
    let r = finish_item(
        &shared,
        &item,
        &item.request,
        Err("fixture failure".into()),
        None,
    );
    assert_eq!(r.error.as_deref(), Some("fixture failure"));
    server.join().unwrap();
    assert!(
        shared
            .events
            .lock()
            .iter()
            .any(|e| e.contains("post-request macro after: ok"))
    );
}

#[test]
fn source_session_failure_is_not_silently_replaced_by_original_request() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        read_head(&mut s);
    });
    let shared = Shared::new();
    shared.session_rules.lock().push(net::SessionRule {
        action: "check session".into(),
        tools: vec!["Repeater".into()],
        ..net::SessionRule::new()
    });
    let item = request(port);
    let mut got = Vec::new();
    run_sequence(&shared, &[item], false, &AtomicBool::new(false), |_, r| {
        got.push(r)
    });
    server.join().unwrap();
    assert!(
        got[0]
            .error
            .as_deref()
            .unwrap()
            .contains("session validation")
    );
    // Only the failed session probe opened a socket, not a second original send.
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 1);
}

#[test]
fn source_registry_import_validation_and_settings_export_invariants() {
    let mut order = vec![1, 2, 3];
    let mut groups = Vec::new();
    create_group(&mut groups, &mut order, 10, " g ", 255, &[2]);
    assert_eq!(groups[0].colour, 0);
    add_to_group(&mut groups, &mut order, 999, 2);
    assert_eq!(
        groups[0].tabs,
        vec![2],
        "invalid target cannot eject a member"
    );
    add_to_group(&mut groups, &mut order, 10, 99);
    assert_eq!(order, vec![1, 2, 3], "unknown tab cannot be invented");
    let saved = vec![
        crate::project::ProjectRepeaterGroup {
            name: "a".into(),
            colour: 255,
            tabs: vec![0],
        },
        crate::project::ProjectRepeaterGroup {
            name: "b".into(),
            colour: 1,
            tabs: vec![0, 1, 99],
        },
        crate::project::ProjectRepeaterGroup {
            name: " ".into(),
            colour: 2,
            tabs: vec![2],
        },
    ];
    let mut id = 0;
    let loaded = from_project(&saved, &order, || {
        id += 1;
        id
    });
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[1].tabs, vec![2]);
    let mut a = request(80);
    let mut b = a.clone();
    b.host = "LOCALHOST".into();
    assert!(validate(GroupMode::SingleConnection, &[a.clone(), b], false).is_empty());
    a.host = " ".into();
    assert_eq!(
        validate(GroupMode::Separate, &[a], false),
        vec![Problem::TargetMissing]
    );
    let data = crate::project::ProjectData {
        repeater_groups: saved,
        ..Default::default()
    };
    assert!(
        crate::project::settings_only(&data)
            .repeater_groups
            .is_empty()
    );
}

include!("send_group_route_tests.rs");

#[test]
fn exchange_error_retires_group_socket_without_second_send_or_reconnect() {
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabc".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nXYZ\r\n".as_slice(),
    ] {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = l.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert!(read_head(&mut socket).starts_with(b"GET /resource HTTP/1.1"));
            socket.write_all(response).unwrap();
            // End the response without completing its declared framing while
            // leaving the server read side available to detect another send.
            socket.shutdown(std::net::Shutdown::Write).unwrap();
            let mut second = Vec::new();
            socket.read_to_end(&mut second).unwrap();
            assert!(
                second.is_empty(),
                "second request followed a failed exchange"
            );
            l.set_nonblocking(true).unwrap();
            assert_eq!(
                l.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "single-connection group must not reconnect"
            );
        });
        let shared = Shared::new();
        let first = request(port);
        let mut got = Vec::new();
        assert_eq!(
            run_sequence(
                &shared,
                &[first.clone(), first],
                true,
                &AtomicBool::new(false),
                |n, r| got.push((n, r))
            ),
            SequenceEnd::Completed
        );
        assert_eq!(got.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![0, 1]);
        assert!(
            got[0].1.response.is_some(),
            "parity codec preserves partial bytes"
        );
        assert!(
            got[1]
                .1
                .error
                .as_deref()
                .unwrap()
                .contains("closed the group's connection")
        );
        assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 1);
        server.join().unwrap();
    }
}

#[test]
fn singleton_readd_is_idempotent_and_import_deduplicates_within_group() {
    let mut groups = vec![RepGroup {
        id: 9,
        name: "only".into(),
        colour: 2,
        tabs: vec![1],
    }];
    let mut order = vec![1, 2];
    add_to_group(&mut groups, &mut order, 9, 1);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].tabs, vec![1]);
    assert_eq!(order, vec![1, 2]);
    let saved = vec![crate::project::ProjectRepeaterGroup {
        name: "saved".into(),
        colour: 3,
        tabs: vec![0, 0, 1, 1],
    }];
    let loaded = from_project(&saved, &order, || 10);
    assert_eq!(loaded[0].tabs, vec![1, 2]);
}

#[test]
fn timed_out_partial_response_poisons_socket_and_next_item_cannot_write_or_reconnect() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        read_head(&mut s);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc")
            .unwrap();
        // Keep the incomplete response open until client retirement. A second
        // request would appear here; retiring the socket produces EOF.
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        l.set_nonblocking(true).unwrap();
        assert_eq!(
            l.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    });
    let shared = Shared::new();
    let item = request(port);
    let socket = open_conn(&shared, &item.host, item.port, false, false).unwrap();
    if let UpstreamConn::Plain(tcp) = &socket {
        tcp.set_read_timeout(Some(Duration::from_millis(80)))
            .unwrap();
    }
    let mut connection = Some(Ok(socket));
    let wire = http1_wire(&shared, &item, &item.request);
    let first = exchange_single(&mut connection, &shared, &item, &wire).unwrap_err();
    assert!(first.starts_with("read:"), "{first}");
    assert!(connection.as_ref().unwrap().is_err());
    let second = exchange_single(&mut connection, &shared, &item, &wire).unwrap_err();
    assert!(second.contains("unavailable after an exchange error"));
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 1);
    server.join().unwrap();
}
