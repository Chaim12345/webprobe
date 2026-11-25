//! AR-09 app-layer: NUL and non-UTF-8 bodies through the real Repeater and
//! Intruder send paths. Loopback only.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use webprobe_core::intruder::{AttackType, SetSpec};
use webprobe_core::intruder_run::{self, AttackSettings};
use webprobe_core::net;

const BODY: &[u8] = &[0x00, 0xff, 0xfe, 0x00, 0xc3, 0x28];
const LOSSY_BODY: &[u8] = &[
    0x00, 0xef, 0xbf, 0xbd, 0xef, 0xbf, 0xbd, 0x00, 0xef, 0xbf, 0xbd, 0x28,
];

fn raw_request() -> Vec<u8> {
    let mut r = format!(
        "POST /ar09 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
        BODY.len()
    )
    .into_bytes();
    r.extend_from_slice(BODY);
    r
}

fn head_len(wire: &[u8]) -> usize {
    wire.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("head terminator")
}

fn declared_len(wire: &[u8]) -> usize {
    let head = &wire[..head_len(wire)];
    String::from_utf8_lossy(head)
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .expect("Content-Length header")
}

fn body_of(wire: &[u8]) -> &[u8] {
    &wire[head_len(wire) + 4..]
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Loopback origin capturing every request it receives.
///
/// `body_len` is the number of body bytes expected on the wire, not the
/// declared Content-Length (Repeater sends more than it declares): a short
/// TCP read must not end the capture early.
fn capture(body_len: usize) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
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
                        if buf.windows(4).any(|w| w == b"\r\n\r\n")
                            && buf.len() >= head_len(&buf) + 4 + body_len
                        {
                            break;
                        }
                    }
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = tx.send(buf);
        }
    });
    (port, rx)
}

/// The real Repeater path: `request_for_tools` -> `RepTab.request` (text) ->
/// `send_following` -> `send_once` -> `req.as_bytes()` -> socket.
#[test]
fn repeater_send_once_sends_the_lossy_body_with_a_stale_content_length() {
    let shared = net::Shared::new();
    let (port, rx) = capture(12);
    let text = crate::ui::request_for_tools(&raw_request());
    // An edit in the text editor must not change the body bytes.
    let edited = text.replacen("POST /ar09", "POST /ar09?edited=1", 1);
    let service = crate::repeater_ops::Service::new("127.0.0.1", port, false);
    let out = crate::repeater_ops::send_following(
        &shared,
        &edited,
        &service,
        crate::repeater_ops::FollowMode::Never,
        false,
        &|| false,
        &|_, _| {},
    );
    assert!(out.error.is_none(), "send error: {:?}", out.error);
    let wire = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("origin saw the Repeater request");
    println!("repeater body : {}", hex(body_of(&wire)));
    assert!(
        String::from_utf8_lossy(&wire[..head_len(&wire)]).starts_with("POST /ar09?edited=1 "),
        "the edited request line reached the wire"
    );
    assert_eq!(body_of(&wire), LOSSY_BODY, "send_once sent the lossy body");
    assert_eq!(declared_len(&wire), 6, "header keeps the captured length");
    assert_eq!(
        body_of(&wire).len(),
        12,
        "12 bytes under a 6-byte declaration"
    );
}

/// The real Intruder path: `request_for_tools` -> template text -> `start` ->
/// `execute_probe` -> `update_content_length(request.as_bytes())` -> socket.
#[test]
fn intruder_attack_sends_the_lossy_template_body() {
    let shared = net::Shared::new();
    let (port, rx) = capture(12);
    let text = crate::ui::request_for_tools(&raw_request());
    let template = text.replacen("POST /ar09", "POST /ar09§p§", 1);
    let state = intruder_run::start(
        shared.clone(),
        &template,
        AttackType::Sniper,
        vec![SetSpec::List(vec!["x".into()])],
        ("127.0.0.1".into(), port, false),
        AttackSettings::default(),
    )
    .expect("attack starts");
    let end = Instant::now() + Duration::from_secs(15);
    while state.is_running() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    state.drain_rows();
    let wire = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("origin saw the Intruder request");
    println!("intruder body : {}", hex(body_of(&wire)));
    assert_eq!(body_of(&wire), LOSSY_BODY, "Intruder sent the lossy body");
    assert_eq!(
        declared_len(&wire),
        body_of(&wire).len(),
        "Intruder restamps Content-Length to the converted length"
    );
}
