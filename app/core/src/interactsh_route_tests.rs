//! Route-regression fixtures for the Collaborator (interactsh) egress item.
//!
//! Hand-off from the independent fixtures lane (PM request, 2026-11-23).
//! These pin the egress contract that the interactsh upstream-routing fix
//! implements; they do not implement any of that fix themselves:
//!   * registration, polling and deregistration use ONLY the selected
//!     upstream route (`crate::upstream::UpstreamConfig`);
//!   * a direct route reaches the control server directly;
//!   * an HTTP / SOCKS5 route carries the control-server connect through
//!     the proxy and never touches the control server directly;
//!   * a failing route fails the operation - there is no silent direct
//!     fallback;
//!   * the endpoint override (`host:port`, optionally `https://` with a
//!     trailing slash) is the authority the route connects to.
//!
//! Routing is observed at the TCP level with loopback fakes, so the
//! assertions hold before TLS trust enters (the session verifies against
//! the public roots, which a loopback fake cannot satisfy). Full protocol
//! round trips stay covered by the ignored live tests in `interactsh.rs`.
//!
//! Seam these fixtures are written against (the routing fix's announced
//! interface): `Session::register_with(server, token, route:
//! &UpstreamConfig)` with the session carrying `route` into poll and
//! deregister via `crate::upstream::connect_tls_target`.

use super::*;
use crate::upstream::{UpstreamConfig, UpstreamKind};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

const TLS_HANDSHAKE: u8 = 0x16;

/// A loopback listener that records the first bytes of every accepted
/// connection and then drops it. `hits` yields one entry per connection.
struct FakeEndpoint {
    port: u16,
    hits: mpsc::Receiver<Vec<u8>>,
}

fn first_bytes(mut s: TcpStream, n: usize) -> Vec<u8> {
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = vec![0u8; n];
    let mut read = 0;
    while read < n {
        match s.read(&mut buf[read..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => read += k,
        }
    }
    buf.truncate(read);
    buf
}

fn fake_endpoint() -> FakeEndpoint {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        while let Ok((s, _)) = listener.accept() {
            let _ = tx.send(first_bytes(s, 5));
        }
    });
    FakeEndpoint { port, hits: rx }
}

/// A loopback HTTP CONNECT proxy: accepts one connection, records the
/// CONNECT head, answers 200, records the tunnelled TLS ClientHello's first
/// bytes, and drops. `served` yields `(connect_head, client_hello)`.
struct FakeHttpProxy {
    port: u16,
    served: mpsc::Receiver<(String, Vec<u8>)>,
}

fn fake_http_connect_proxy() -> FakeHttpProxy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = listener.accept() {
            s.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if s.read_exact(&mut byte).is_err() {
                    break;
                }
                head.push(byte[0]);
                if head.len() > 64 * 1024 {
                    break;
                }
            }
            if s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
            {
                continue;
            }
            let hello = first_bytes(s, 5);
            let _ = tx.send((String::from_utf8_lossy(&head).into_owned(), hello));
        }
    });
    FakeHttpProxy { port, served: rx }
}

/// A loopback SOCKS5 proxy (no auth): accepts one connection, answers the
/// greeting, records the CONNECT request bytes, answers success, records
/// the tunnelled TLS ClientHello's first bytes, and drops.
struct FakeSocksProxy {
    port: u16,
    served: mpsc::Receiver<(Vec<u8>, Vec<u8>)>,
}

fn fake_socks5_proxy() -> FakeSocksProxy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = listener.accept() {
            s.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut greeting = [0u8; 2];
            if s.read_exact(&mut greeting).is_err() {
                continue;
            }
            let mut methods = vec![0u8; greeting[1] as usize];
            if s.read_exact(&mut methods).is_err() {
                continue;
            }
            if s.write_all(&[5, 0]).is_err() {
                continue;
            }
            // CONNECT request: ver/cmd/rsv/atyp + addr + port (2 bytes BE).
            let mut fixed = [0u8; 4];
            if s.read_exact(&mut fixed).is_err() {
                continue;
            }
            let alen = match fixed[3] {
                1 => 4,
                4 => 16,
                3 => {
                    let mut l = [0u8; 1];
                    if s.read_exact(&mut l).is_err() {
                        continue;
                    }
                    l[0] as usize + 1
                }
                _ => break,
            };
            let mut rest = vec![0u8; alen + 2];
            if s.read_exact(&mut rest).is_err() {
                continue;
            }
            let mut request = fixed.to_vec();
            request.extend_from_slice(&rest);
            if s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
                continue;
            }
            let hello = first_bytes(s, 5);
            let _ = tx.send((request, hello));
        }
    });
    FakeSocksProxy { port, served: rx }
}

fn http_route(proxy: &FakeHttpProxy) -> UpstreamConfig {
    UpstreamConfig {
        kind: UpstreamKind::Http,
        host: "127.0.0.1".into(),
        port: proxy.port.to_string(),
        username: String::new(),
        password: String::new(),
    }
}

fn assert_no_direct_hit(endpoint: &FakeEndpoint) {
    assert!(
        endpoint
            .hits
            .recv_timeout(Duration::from_millis(500))
            .is_err(),
        "a proxied or failed route must never open a direct connection to the control server"
    );
}

/// Direct route: registration connects to the control server itself.
#[test]
fn direct_route_reaches_the_control_server() {
    let endpoint = fake_endpoint();
    let server = format!("127.0.0.1:{}", endpoint.port);
    // TLS against a loopback fake cannot verify; what this pins is WHERE
    // the connection went, and a direct route must go straight there.
    let _ = Session::register_with(&server, None, &UpstreamConfig::default());
    let hello = endpoint
        .hits
        .recv_timeout(Duration::from_secs(5))
        .expect("a direct route must connect to the control server");
    assert_eq!(
        hello.first(),
        Some(&TLS_HANDSHAKE),
        "expected a TLS ClientHello"
    );
}

/// HTTP upstream: registration CONNECTs to the control-server authority via
/// the proxy, and nothing touches the control server directly.
#[test]
fn http_proxy_route_carries_registration_and_never_goes_direct() {
    let endpoint = fake_endpoint();
    let proxy = fake_http_connect_proxy();
    let server = format!("127.0.0.1:{}", endpoint.port);
    let _ = Session::register_with(&server, None, &http_route(&proxy));
    let (head, hello) = proxy
        .served
        .recv_timeout(Duration::from_secs(5))
        .expect("an HTTP route must CONNECT through the proxy");
    assert!(
        head.starts_with(&format!("CONNECT 127.0.0.1:{}", endpoint.port)),
        "CONNECT authority must be the control server, got {head:?}"
    );
    assert_eq!(
        hello.first(),
        Some(&TLS_HANDSHAKE),
        "the tunnel must carry TLS"
    );
    assert_no_direct_hit(&endpoint);
}

/// Endpoint override: `https://host:port/` is parsed down to the same
/// authority the route CONNECTs to.
#[test]
fn endpoint_override_is_the_route_authority() {
    let endpoint = fake_endpoint();
    let proxy = fake_http_connect_proxy();
    let server = format!(" https://127.0.0.1:{}/ ", endpoint.port);
    let _ = Session::register_with(&server, None, &http_route(&proxy));
    let (head, _) = proxy
        .served
        .recv_timeout(Duration::from_secs(5))
        .expect("an HTTP route must CONNECT through the proxy");
    assert!(
        head.starts_with(&format!("CONNECT 127.0.0.1:{}", endpoint.port)),
        "the override endpoint must be the CONNECT authority, got {head:?}"
    );
    assert_no_direct_hit(&endpoint);
}

/// SOCKS5 upstream: registration negotiates the tunnel via the proxy and
/// never goes direct.
#[test]
fn socks5_proxy_route_carries_registration_and_never_goes_direct() {
    let endpoint = fake_endpoint();
    let proxy = fake_socks5_proxy();
    let route = UpstreamConfig {
        kind: UpstreamKind::Socks5,
        host: "127.0.0.1".into(),
        port: proxy.port.to_string(),
        username: String::new(),
        password: String::new(),
    };
    let server = format!("127.0.0.1:{}", endpoint.port);
    let _ = Session::register_with(&server, None, &route);
    let (request, hello) = proxy
        .served
        .recv_timeout(Duration::from_secs(5))
        .expect("a SOCKS5 route must connect through the proxy");
    // ver=5, cmd=connect, rsv=0, atyp=IPv4, 127.0.0.1, port BE.
    let port = endpoint.port.to_be_bytes();
    let want = [5, 1, 0, 1, 127, 0, 0, 1, port[0], port[1]];
    assert_eq!(
        request, want,
        "SOCKS5 CONNECT must target the control server"
    );
    assert_eq!(
        hello.first(),
        Some(&TLS_HANDSHAKE),
        "the tunnel must carry TLS"
    );
    assert_no_direct_hit(&endpoint);
}

/// A failing route fails the registration; there is no direct fallback.
#[test]
fn failed_route_never_falls_back_to_direct() {
    let endpoint = fake_endpoint();
    // A closed proxy port: bind and drop to learn a free port.
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let route = UpstreamConfig {
        kind: UpstreamKind::Http,
        host: "127.0.0.1".into(),
        port: closed.to_string(),
        username: String::new(),
        password: String::new(),
    };
    let server = format!("127.0.0.1:{}", endpoint.port);
    assert!(
        Session::register_with(&server, None, &route).is_err(),
        "registration must fail when the selected route fails"
    );
    assert_no_direct_hit(&endpoint);
}

/// Polling and deregistration travel the same selected route (a session is
/// built in-module so no TLS-verified registration is needed first).
#[test]
fn poll_and_deregister_use_the_selected_route() {
    let endpoint = fake_endpoint();
    let proxy = fake_http_connect_proxy();
    let session = Session {
        server: "127.0.0.1".into(),
        port: endpoint.port,
        cid: random_lower_alnum(CID_LEN),
        secret: random_uuid(),
        token: None,
        key: rsa::PrivateKey::new(&mut crate::tls::OsRandom, 1024).unwrap(),
        route: http_route(&proxy),
    };
    let _ = session.poll();
    session.deregister();
    for what in ["poll", "deregister"] {
        let (head, _) = proxy
            .served
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("{what} must use the selected route"));
        assert!(
            head.starts_with(&format!("CONNECT 127.0.0.1:{}", endpoint.port)),
            "{what} CONNECT authority must be the control server, got {head:?}"
        );
    }
    assert_no_direct_hit(&endpoint);
}
