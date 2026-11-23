use super::*;

#[test]
fn scanner_initial_stop_blocks_all_bypass_entries_without_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let shared = Shared::new();
    shared.scan.stop.store(true, Ordering::SeqCst);
    let raw = format!("GET /initial HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    assert!(crate::scan::send_one(&shared, false, "127.0.0.1", port, raw.as_bytes()).is_none());
    let _scanner = tool_scope("Scanner");
    assert!(send_raw(&shared, "127.0.0.1", port, raw.as_bytes())
        .resp
        .is_none());
    assert!(send_from(&shared, "127.0.0.1", port, raw.as_bytes(), None)
        .resp
        .is_none());
    assert!(send_inner(&shared, "127.0.0.1", port, raw.as_bytes(), None).is_err());
    assert!(send_tls_raw(&shared, "127.0.0.1", port, raw.as_bytes())
        .resp
        .is_none());
    assert!(send_tls_inner(&shared, "127.0.0.1", port, raw.as_bytes(), None).is_err());
    assert!(listener.accept().is_err());
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 0);
}

#[test]
fn scanner_stop_between_multiprobes_denies_next_but_not_other_tools() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let shared = Shared::new();
    let stop = shared.clone();
    let received = Arc::new(std::sync::Barrier::new(2));
    let barrier = received.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut raw = Vec::new();
        let mut b = [0; 4096];
        while let Ok(n) = stream.read(&mut b) {
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&b[..n]);
            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        stop.scan.stop.store(true, Ordering::SeqCst);
        barrier.wait();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
        listener
    });
    let raw = format!("GET /first HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let client = shared.clone();
    let first = std::thread::spawn(move || {
        crate::scan::send_one(&client, false, "127.0.0.1", port, raw.as_bytes())
    });
    received.wait();
    assert!(
        first.join().unwrap().is_some(),
        "already admitted response may finish"
    );
    let listener = server.join().unwrap();
    listener.set_nonblocking(true).unwrap();
    assert!(crate::scan::send_one(
        &shared,
        false,
        "127.0.0.1",
        port,
        b"GET /second HTTP/1.1\r\nHost: h\r\n\r\n"
    )
    .is_none());
    assert!(listener.accept().is_err(), "no second attempt");
    let _repeater = tool_scope("Repeater");
    assert!(
        scanner_send_admission(&shared).is_ok(),
        "scanner stop must not stop other tools"
    );
}

#[test]
fn scanner_noncancel_direct_and_proxy_positive_control() {
    for proxy in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let shared = Shared::new();
        if proxy {
            *shared.upstream.lock().unwrap() = crate::upstream::UpstreamConfig {
                kind: crate::upstream::UpstreamKind::Http,
                host: "127.0.0.1".into(),
                port: port.to_string(),
                ..Default::default()
            };
        }
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut raw = [0; 4096];
            let n = s.read(&mut raw).unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            String::from_utf8_lossy(&raw[..n]).into_owned()
        });
        assert!(crate::scan::send_one(
            &shared,
            false,
            "127.0.0.1",
            port,
            b"GET /positive HTTP/1.1\r\nHost: h\r\n\r\n"
        )
        .is_some());
        let wire = server.join().unwrap();
        assert!(wire.contains("/positive"));
        if proxy {
            assert!(wire.starts_with("GET http://"));
        }
    }
}
