#[test]
fn source_tls_proxy_tunnels_then_sends_origin_form() {
    let shared = trusted();
    let cfg = shared
        .mitm
        .server_config_with_alpn("localhost", vec![b"http/1.1".to_vec()])
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
        assert!(read_head(&mut s).starts_with(b"CONNECT localhost:8443 HTTP/1.1\r\n"));
        s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), s);
        let req = read_head(&mut tls);
        assert!(req.starts_with(b"GET /resource HTTP/1.1\r\n"));
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    *shared.upstream.lock() = crate::upstream::UpstreamConfig {
        kind: crate::upstream::UpstreamKind::Http,
        host: "127.0.0.1".into(),
        port: port.to_string(),
        ..Default::default()
    };
    let mut item = request(8443);
    item.https = true;
    let mut got = Vec::new();
    run_sequence(&shared, &[item], false, &AtomicBool::new(false), |_, r| {
        got.push(r)
    });
    assert!(got[0].error.is_none(), "{:?}", got[0].error);
    server.join().unwrap();
}

#[test]
fn source_socks_route_preserves_remote_target_and_origin_form() {
    let shared = Shared::new();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
        let mut greeting = [0; 2];
        s.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting[0], 5);
        let mut methods = vec![0; greeting[1] as usize];
        s.read_exact(&mut methods).unwrap();
        s.write_all(&[5, 0]).unwrap();
        let mut head = [0; 4];
        s.read_exact(&mut head).unwrap();
        assert_eq!(head, [5, 1, 0, 3]);
        let mut len = [0];
        s.read_exact(&mut len).unwrap();
        let mut host = vec![0; len[0] as usize];
        s.read_exact(&mut host).unwrap();
        assert_eq!(host, b"target.invalid");
        let mut port = [0; 2];
        s.read_exact(&mut port).unwrap();
        assert_eq!(u16::from_be_bytes(port), 8081);
        s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80]).unwrap();
        assert!(read_head(&mut s).starts_with(b"GET /resource HTTP/1.1\r\n"));
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    *shared.upstream.lock() = crate::upstream::UpstreamConfig {
        kind: crate::upstream::UpstreamKind::Socks5,
        host: "127.0.0.1".into(),
        port: port.to_string(),
        ..Default::default()
    };
    let mut item = request(8081);
    item.host = "target.invalid".into();
    item.request =
        b"GET http://target.invalid:8081/resource HTTP/2\r\nHost: target.invalid:8081\r\n\r\n"
            .to_vec();
    let mut got = Vec::new();
    run_sequence(&shared, &[item], false, &AtomicBool::new(false), |_, r| {
        got.push(r)
    });
    assert!(got[0].error.is_none(), "{:?}", got[0].error);
    server.join().unwrap();
}
