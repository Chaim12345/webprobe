//! F9: a held intercepted HTTP request must not outlive its client, and no
//! request may reach the origin after the client cancels.
//!
//! Loopback only: a real `handle_conn` proxy path, a fake origin listener and
//! a raw client socket. No remote traffic.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use webprobe_core::net::{handle_conn, intercept_release_all, Shared};

const DEADLINE: Duration = Duration::from_secs(3);

/// Fake origin: counts connections and answers one request.
fn origin() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_thread = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            hits_thread.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nupstream-ok",
            );
            let _ = stream.flush();
        }
    });
    (port, hits)
}

/// Proxy listener running the real connection handler.
fn proxy(shared: Arc<Shared>) -> (u16, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    std::thread::spawn(move || {
        while !stop_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let shared = shared.clone();
                    std::thread::spawn(move || handle_conn(shared, stream));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return,
            }
        }
    });
    (port, stop)
}

fn shared_intercepting() -> Arc<Shared> {
    let shared = Shared::new();
    shared.intercept_on.store(true, Ordering::SeqCst);
    // Empty rule table: `should_intercept` then answers true for everything.
    shared.intercept_rules.lock().unwrap().clear();
    shared
}

fn wait_queue(shared: &Shared, want: usize, deadline: Duration) -> bool {
    let end = Instant::now() + deadline;
    while Instant::now() < end {
        if shared.queue.lock().unwrap().len() == want {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    shared.queue.lock().unwrap().len() == want
}

fn request(origin_port: u16) -> Vec<u8> {
    format!(
        "GET http://127.0.0.1:{origin_port}/f9 HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

#[test]
fn control_normal_request_reaches_the_origin_and_returns() {
    let (origin_port, hits) = origin();
    let shared = Shared::new(); // interception off
    let (proxy_port, stop) = proxy(shared.clone());
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client.set_read_timeout(Some(DEADLINE)).unwrap();
    client.write_all(&request(origin_port)).unwrap();
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response);
    stop.store(true, Ordering::SeqCst);
    assert!(text.contains("200 OK"), "response: {text:?}");
    assert!(text.contains("upstream-ok"), "response: {text:?}");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "origin saw the request");
}

#[test]
#[ignore = "F9 defect: held HTTP request has no client-liveness wait; see notes/f9-intercept-disconnect.md"]
fn held_request_is_released_when_the_client_disconnects() {
    let (origin_port, hits) = origin();
    let shared = shared_intercepting();
    let (proxy_port, stop) = proxy(shared.clone());
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    client.write_all(&request(origin_port)).unwrap();
    assert!(wait_queue(&shared, 1, DEADLINE), "request was held");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing sent while held");

    let _ = client.shutdown(Shutdown::Both);
    drop(client);

    let start = Instant::now();
    let released = wait_queue(&shared, 0, DEADLINE);
    let released_after = start.elapsed();

    // If still held, forward it as the UI would, then watch the origin.
    if !released {
        intercept_release_all(&shared, false);
    }
    let end = Instant::now() + DEADLINE;
    while Instant::now() < end && hits.load(Ordering::SeqCst) == 0 {
        std::thread::sleep(Duration::from_millis(5));
    }
    let upstream_after_cancel = hits.load(Ordering::SeqCst);
    stop.store(true, Ordering::SeqCst);

    assert!(
        released && upstream_after_cancel == 0,
        "released={released} after {released_after:?} (deadline {DEADLINE:?}); \
         origin connections after cancel={upstream_after_cancel}"
    );
}
