//! `RequestReader`: one framed message at a time, leftovers owned by the
//! connection. Unit cases at read sizes 1/3/7/16384, then end-to-end through
//! `handle_conn` (pipelining, CONNECT with coalesced tunnel bytes, WebSocket
//! with coalesced first frame).

use crate::net::{handle_conn, ws_frame, RequestReader, Shared};
use std::io::{Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

const STEPS: [usize; 4] = [1, 3, 7, 16_384];

struct Script {
    data: Cursor<Vec<u8>>,
    step: usize,
}
impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.step);
        self.data.read(&mut buf[..n])
    }
}
fn script(wire: &[u8], step: usize) -> Script {
    Script {
        data: Cursor::new(wire.to_vec()),
        step,
    }
}

/// Every message the reader yields from `wire`, then what it still holds.
fn drain(wire: &[u8], step: usize) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut r = RequestReader::new();
    let mut s = script(wire, step);
    let mut out = Vec::new();
    loop {
        let m = r.read_next(&mut s).unwrap();
        if m.is_empty() {
            break;
        }
        out.push(m);
        if r.leftovers().is_empty() && s.data.position() as usize == wire.len() {
            break;
        }
    }
    (out, r.take_leftovers())
}

fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

const A: &[u8] = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
const B: &[u8] = b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n";
const C: &[u8] =
    b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n";
const D: &[u8] = b"POST /d HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n";

#[test]
fn pipelined_requests_come_out_one_at_a_time_in_order() {
    let wire = join(&[A, B, C, D]);
    for step in STEPS {
        let (msgs, left) = drain(&wire, step);
        assert_eq!(
            msgs,
            vec![A.to_vec(), B.to_vec(), C.to_vec(), D.to_vec()],
            "step {step}"
        );
        assert!(left.is_empty(), "step {step}");
    }
}

#[test]
fn leftovers_are_kept_exactly_between_calls() {
    let wire = join(&[A, B, C]);
    let mut r = RequestReader::new();
    let mut s = script(&wire, 16_384);
    assert_eq!(r.read_next(&mut s).unwrap(), A);
    assert_eq!(r.leftovers(), join(&[B, C]).as_slice());
    assert_eq!(r.read_next(&mut s).unwrap(), B);
    assert_eq!(r.leftovers(), C);
    assert_eq!(r.read_next(&mut s).unwrap(), C);
    assert!(r.leftovers().is_empty());
    assert!(
        r.read_next(&mut s).unwrap().is_empty(),
        "EOF, nothing buffered"
    );
}

#[test]
fn a_split_request_is_assembled_across_reads_with_the_next_one_held() {
    // First request arrives in pieces; the start of the next rides along.
    let wire = join(&[A, B]);
    for step in STEPS {
        let mut r = RequestReader::new();
        let mut s = script(&wire, step);
        assert_eq!(r.read_next(&mut s).unwrap(), A, "step {step}");
        let mut got = r.take_leftovers();
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).unwrap();
        got.extend_from_slice(&rest);
        assert_eq!(got, B, "step {step}: nothing lost or duplicated");
    }
}

#[test]
fn an_unfinished_message_at_eof_comes_back_whole() {
    for wire in [
        &b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"[..],
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
        b"GET / HTTP/1.1\r\nHost: h",
    ] {
        for step in STEPS {
            let mut r = RequestReader::new();
            assert_eq!(r.read_next(&mut script(wire, step)).unwrap(), wire);
            assert!(r.leftovers().is_empty());
        }
    }
}

#[test]
fn connect_leftovers_belong_to_the_tunnel() {
    let head = b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n";
    let hello = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03client hello bytes\r\n\r\n";
    let wire = join(&[head, hello]);
    for step in STEPS {
        let mut r = RequestReader::new();
        let mut s = script(&wire, step);
        assert_eq!(r.read_next(&mut s).unwrap(), head, "step {step}");
        // What the reader holds plus what is still on the socket is exactly
        // the tunnel bytes: none dropped, none doubled.
        let mut tunnel = r.take_leftovers();
        s.read_to_end(&mut tunnel).unwrap();
        assert_eq!(tunnel, hello, "step {step}");
    }
}

#[test]
fn upgrade_leftovers_are_the_first_frames() {
    let up = b"GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    let frame = ws_frame(0x81, b"hi", true);
    let wire = join(&[up, &frame]);
    for step in STEPS {
        let mut r = RequestReader::new();
        let mut s = script(&wire, step);
        assert_eq!(r.read_next(&mut s).unwrap(), up, "step {step}");
        let mut got = r.take_leftovers();
        s.read_to_end(&mut got).unwrap();
        assert_eq!(got, frame, "step {step}");
    }
}

#[test]
fn oversized_head_and_body_limits_still_error() {
    let mut huge = b"GET / HTTP/1.1\r\n".to_vec();
    while huge.len() <= 4 * 1024 * 1024 + 16 {
        huge.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    let mut r = RequestReader::new();
    assert!(r.read_next(&mut script(&huge, 16_384)).is_err());
    let big = b"POST / HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n";
    assert!(RequestReader::new()
        .read_next(&mut script(big, 16_384))
        .is_err());
}

// ---------------------------------------------------------- end to end

fn spawn_proxy(shared: Arc<Shared>) -> (u16, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        handle_conn(shared, s);
    });
    (port, t)
}

fn client(port: u16) -> TcpStream {
    let c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c
}

/// Read one request (head only) from an upstream-side socket.
fn read_head(s: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    while !out.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).unwrap() == 0 {
            break;
        }
        out.push(b[0]);
    }
    out
}

#[test]
fn proxy_serves_pipelined_requests_in_order_and_loses_none() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let up = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..3 {
            let (mut s, _) = upstream.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let head = read_head(&mut s);
            let path = String::from_utf8_lossy(&head)
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();
            let body = format!("reply for {path}");
            write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            seen.push(path);
        }
        seen
    });
    let shared = Shared::new();
    let (port, pt) = spawn_proxy(shared);
    let mut c = client(port);
    // Three requests in ONE write.
    let mut wire = Vec::new();
    for p in ["/one", "/two", "/three"] {
        wire.extend_from_slice(
            format!(
                "GET http://127.0.0.1:{up_port}{p} HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n\r\n"
            )
            .as_bytes(),
        );
    }
    c.write_all(&wire).unwrap();
    let mut got = Vec::new();
    c.read_to_end(&mut got).unwrap();
    pt.join().unwrap();
    let seen = up.join().unwrap();
    assert_eq!(
        seen,
        ["/one", "/two", "/three"],
        "upstream saw each request, in order"
    );
    let text = String::from_utf8_lossy(&got).to_string();
    let (i1, i2, i3) = (
        text.find("reply for /one").expect("first reply"),
        text.find("reply for /two").expect("second reply"),
        text.find("reply for /three").expect("third reply"),
    );
    assert!(i1 < i2 && i2 < i3, "{text}");
}

#[test]
fn connect_passthrough_gets_the_coalesced_tunnel_bytes_after_the_200() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let hello = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03coalesced hello\r\n\r\nmore".to_vec();
    let expect = hello.clone();
    let up = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut got = vec![0u8; expect.len()];
        s.read_exact(&mut got).unwrap();
        assert_eq!(got, expect, "tunnel bytes arrive exactly once, in order");
        s.write_all(b"pong").unwrap();
    });
    let shared = Shared::new();
    shared.tls_bypass.lock().unwrap().push("127.0.0.1".into());
    let (port, pt) = spawn_proxy(shared);
    let mut c = client(port);
    let mut wire =
        format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\n\r\n")
            .into_bytes();
    wire.extend_from_slice(&hello);
    c.write_all(&wire).unwrap();
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while !got.ends_with(b"pong") {
        if c.read(&mut b).unwrap() == 0 {
            break;
        }
        got.push(b[0]);
    }
    let text = String::from_utf8_lossy(&got).to_string();
    assert!(
        text.starts_with("HTTP/1.1 200 Connection established\r\n\r\n"),
        "{text}"
    );
    assert!(text.ends_with("pong"), "{text}");
    drop(c);
    up.join().unwrap();
    pt.join().unwrap();
}

#[test]
fn connect_that_fails_to_connect_does_not_forward_the_leftovers() {
    // Nothing listens on the target: the client gets a 502 and the
    // coalesced bytes go nowhere (they are only handed over after success).
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let shared = Shared::new();
    shared.tls_bypass.lock().unwrap().push("127.0.0.1".into());
    let (port, pt) = spawn_proxy(shared);
    let mut c = client(port);
    let mut wire =
        format!("CONNECT 127.0.0.1:{dead_port} HTTP/1.1\r\nHost: 127.0.0.1:{dead_port}\r\n\r\n")
            .into_bytes();
    wire.extend_from_slice(b"\x16\x03\x01tunnel bytes");
    c.write_all(&wire).unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    pt.join().unwrap();
    assert!(
        String::from_utf8_lossy(&got).starts_with("HTTP/1.1 502"),
        "{got:?}"
    );
}

#[test]
fn websocket_first_frame_sent_with_the_upgrade_reaches_upstream_after_the_101() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let frame = ws_frame(0x81, b"early frame", true);
    let expect = frame.clone();
    let up = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let head = read_head(&mut s);
        assert!(String::from_utf8_lossy(&head).contains("Upgrade: websocket"));
        s.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();
        let mut got = vec![0u8; expect.len()];
        s.read_exact(&mut got).unwrap();
        assert_eq!(got, expect, "the early frame, once, unchanged");
    });
    let shared = Shared::new();
    let (port, pt) = spawn_proxy(shared);
    let mut c = client(port);
    let mut wire = format!(
        "GET http://127.0.0.1:{up_port}/ws HTTP/1.1\r\nHost: 127.0.0.1:{up_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .into_bytes();
    wire.extend_from_slice(&frame);
    c.write_all(&wire).unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read(&mut b).unwrap() == 0 {
            break;
        }
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"));
    up.join().unwrap();
    drop(c);
    pt.join().unwrap();
}

#[test]
fn mitm_connect_gets_the_coalesced_client_hello_and_the_handshake_completes() {
    use rustls::pki_types::ServerName;
    let shared = Shared::new();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(shared.mitm.ca_der()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut tls =
        rustls::ClientConnection::new(Arc::new(cfg), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let mut hello = Vec::new();
    tls.write_tls(&mut hello).unwrap();
    assert!(!hello.is_empty(), "a ClientHello to coalesce");

    let (port, pt) = spawn_proxy(shared);
    let mut c = client(port);
    let mut wire = b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n".to_vec();
    wire.extend_from_slice(&hello);
    c.write_all(&wire).unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read(&mut b).unwrap() == 0 {
            break;
        }
        head.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    while tls.is_handshaking() {
        tls.complete_io(&mut c)
            .expect("handshake with the coalesced hello");
    }
    drop(c);
    pt.join().unwrap();
}
