//! AR-09: bytes, not lossy text, in tool state.
//!
//! The transport below the tool state is byte-clean; the Repeater/Intruder
//! request text is a Rust `String` produced by `String::from_utf8_lossy`
//! (`app/src/ui/actions.rs:204`), and `send_once` writes `req.as_bytes()`
//! (`app/src/repeater_ops.rs:514`). These tests prove the transport keeps
//! exact bytes and show what that conversion does to a binary body.
//!
//! Loopback only.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use webprobe_core::net::{Shared, send_raw_with};

const BODY: &[u8] = &[0x00, 0xff, 0xfe, 0x00, 0xc3, 0x28];

fn raw_request() -> Vec<u8> {
    let mut r = format!(
        "POST /ar09 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        BODY.len()
    )
    .into_bytes();
    r.extend_from_slice(BODY);
    r
}

/// Loopback origin that captures exactly what it received. `body_len` is the
/// number of body bytes the test expects on the wire, not the declared
/// Content-Length: the characterisation deliberately sends more than it
/// declares, and a short TCP read must not end the capture early.
fn capture(body_len: usize) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(h) = buf.windows(4).position(|w| w == b"\r\n\r\n")
                        && buf.len() >= h + 4 + body_len
                    {
                        break;
                    }
                }
            }
        }
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let _ = tx.send(buf);
    });
    (port, rx)
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn body_of(wire: &[u8]) -> &[u8] {
    let h = wire
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("head terminator");
    &wire[h + 4..]
}

/// Control: the real send path carries NUL and non-UTF-8 body bytes exactly.
#[test]
fn control_transport_preserves_nul_and_non_utf8_body_bytes() {
    let shared = Shared::new();
    let (port, rx) = capture(BODY.len());
    let raw = raw_request();
    let up = send_raw_with(&shared, "127.0.0.1", port, &raw, None);
    assert!(up.error.is_none(), "send error: {:?}", up.error);
    let wire = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("origin got the request");
    println!("sent     : {}", hex(&raw));
    println!("received : {}", hex(&wire));
    // The transport adds `Connection: close` to the head by design; the body
    // bytes and the declared length must be exactly what was handed in.
    assert_eq!(
        wire.len(),
        raw.len() + b"Connection: close\r\n".len(),
        "only the Connection header was added"
    );
    assert_eq!(body_of(&wire), BODY, "body bytes intact on the wire");
}

/// Characterisation of the tool-state conversion: `request_for_tools`
/// (`actions.rs:204`) stores `String::from_utf8_lossy(raw)`, and
/// `send_once` (`repeater_ops.rs:514`) sends `req.as_bytes()`. NUL survives;
/// every invalid byte becomes U+FFFD (ef bf bd) and the declared
/// Content-Length no longer matches the body actually sent.
#[test]
fn repeater_text_state_is_lossy_for_non_utf8_bodies() {
    let shared = Shared::new();
    let (port, rx) = capture(12);
    let raw = raw_request();

    // Exactly the production conversion chain for an origin-form request.
    let stored: String = String::from_utf8_lossy(&raw).into_owned();
    let sent = stored.as_bytes().to_vec();

    let up = send_raw_with(&shared, "127.0.0.1", port, &sent, None);
    assert!(up.error.is_none(), "send error: {:?}", up.error);
    let wire = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("origin got the request");

    let wire_body = body_of(&wire);
    println!("stored text body : {}", hex(wire_body));
    println!("original body    : {}", hex(BODY));
    assert_eq!(
        wire_body,
        [
            0x00, 0xef, 0xbf, 0xbd, 0xef, 0xbf, 0xbd, 0x00, 0xef, 0xbf, 0xbd, 0x28
        ],
        "lossy conversion result"
    );
    assert_eq!(wire_body.len(), 12, "6 body bytes became 12");
    assert_ne!(wire, raw, "the wire request is not the captured request");
    let declared = String::from_utf8_lossy(&wire)
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().to_string())
        })
        .unwrap();
    assert_eq!(declared, "6", "header still declares the original length");
    assert_ne!(
        declared.parse::<usize>().unwrap(),
        wire_body.len(),
        "Content-Length desync: header 6, body 12"
    );
}
