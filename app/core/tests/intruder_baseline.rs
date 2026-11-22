//! Real loopback regression fixtures for the Burp request-0 contract in PR #112.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{atomic::Ordering, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use webprobe_core::{intruder, intruder_run as run, net};

fn wait_finished(state: &run::RunState) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while state.is_running() {
        assert!(Instant::now() < deadline, "attack did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
}

type Capture = Arc<Mutex<Vec<Vec<u8>>>>;

fn origin(count: usize, fail_first: usize) -> (u16, Capture, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let copy = seen.clone();
    let thread = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        for index in 0..count {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "missing request {index}");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept failed: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut buf = [0; 1024];
                let n = stream.read(&mut buf).unwrap();
                assert_ne!(n, 0, "request truncated");
                request.extend_from_slice(&buf[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&request[..end]);
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .map(|v| v.parse::<usize>().unwrap())
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            copy.lock().unwrap().push(request);
            if index == 0 {
                // Keep the baseline in flight. No payload may start until its
                // response completes, even with multiple available workers.
                std::thread::sleep(Duration::from_millis(80));
                assert!(
                    matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
                    "payload overtook the baseline response"
                );
            }
            if index >= fail_first {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .unwrap();
            }
        }
    });
    (port, seen, thread)
}

fn settings() -> run::AttackSettings {
    let mut settings = run::AttackSettings::default();
    settings.pool.max_concurrent = 4;
    settings.retry = run::RetryConfig {
        retries: 0,
        pause_ms: 0,
    };
    settings.grep_match.enabled = true;
    settings.grep_match.items = vec!["ok".into()];
    settings
}

#[test]
fn request_zero_precedes_all_four_payload_matrices_and_is_exported() {
    use intruder::AttackType::*;
    for (kind, positions, payload_count) in [
        (Sniper, 1, 2),
        (Sniper, 2, 4),
        (BatteringRam, 2, 2),
        (Pitchfork, 2, 2),
        (ClusterBomb, 2, 4),
    ] {
        let (port, seen, server) = origin(payload_count + 1, 0);
        // A body containing encoding-set characters must stay untouched in
        // the baseline, including header order and Content-Length spelling.
        let text = format!("POST /echo HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 7\r\nX-Keep: exact\r\nConnection: close\r\n\r\n§a&b§=§c/d§");
        let text = if positions == 1 {
            text.replace("§c/d§", "c/d")
        } else {
            text
        };
        let parsed = intruder::Template::parse(&text).unwrap();
        let sources = vec![
            intruder::PayloadSource::SimpleList {
                items: vec!["one".into(), "two".into()]
            };
            kind.sets_needed(positions)
        ];
        let specs = intruder::resolve_specs(&parsed, kind, &sources).unwrap();
        let state = run::start(
            net::Shared::new(),
            &text,
            kind,
            specs,
            ("127.0.0.1".into(), port, false),
            settings(),
        )
        .unwrap();
        wait_finished(&state);
        server.join().unwrap();
        let seen = seen.lock().unwrap();
        let mut rows = state.rows.lock().unwrap().clone();
        assert_eq!(rows[0].number, 0);
        rows.sort_by_key(|r| r.number);
        assert_eq!(rows.len(), payload_count + 1);
        assert_eq!(
            state.progress(),
            (payload_count + 1, Some(payload_count + 1))
        );
        let expected = intruder::clear_markers(&text).into_bytes();
        assert_eq!(seen[0], expected);
        assert_eq!(rows[0].request, expected);
        assert_eq!(rows[0].payloads, vec![None; positions]);
        assert_eq!(rows[0].payload_text(), "");
        for (number, row) in rows.iter().enumerate() {
            assert_eq!(row.number, number);
            if number != 0 {
                assert!(!row.payload_text().is_empty());
            }
            assert_eq!(row.status, "200");
            assert!(!row.error);
            assert_eq!(row.matches, vec![true]);
            assert!(seen.contains(&row.request));
        }
        let csv = run::results_csv(&rows, state.sets, &state.settings);
        assert!(csv.lines().nth(1).unwrap().starts_with("0,,"));
        let xml = run::results_xml(&rows, state.sets, &state.settings);
        assert!(xml.contains("<column name=\"Request\">0</column>"));
        assert_eq!(
            run::sort_order(&rows, state.sets, &state.settings, 0, true),
            (0..rows.len()).collect::<Vec<_>>()
        );
        println!("{}: origin requests={}, baseline exact=true, results=0..{}, status=200, progress={:?}, CSV/XML baseline included", kind.label(), seen.len(), payload_count, state.progress());
    }
}

#[test]
fn failed_baseline_is_reported_and_payload_still_runs_after_its_retries() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener); // Both requests fail fast with connection refused.
    let text = format!("GET /?q=§base§ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let parsed = intruder::Template::parse(&text).unwrap();
    let specs = intruder::resolve_specs(
        &parsed,
        intruder::AttackType::Sniper,
        &[intruder::PayloadSource::SimpleList {
            items: vec!["one".into()],
        }],
    )
    .unwrap();
    let mut cfg = settings();
    cfg.retry.retries = 1;
    let state = run::start(
        net::Shared::new(),
        &text,
        intruder::AttackType::Sniper,
        specs,
        ("127.0.0.1".into(), port, false),
        cfg,
    )
    .unwrap();
    wait_finished(&state);
    let rows = state.rows.lock().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[0].number, rows[0].error, rows[0].attempts),
        (0, true, 2)
    );
    assert_eq!(
        (rows[1].number, rows[1].error, rows[1].attempts),
        (1, true, 2)
    );
    assert!(String::from_utf8_lossy(&rows[0].request).starts_with("GET /?q=base "));
    assert!(String::from_utf8_lossy(&rows[1].request).starts_with("GET /?q=one "));
    assert_eq!(state.progress(), (2, Some(2)));
}

#[test]
fn stop_during_baseline_does_not_launch_payloads() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 2048];
        assert!(stream.read(&mut request).unwrap() > 0);
        arrived_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    });
    let text = format!("GET /?q=§base§ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let parsed = intruder::Template::parse(&text).unwrap();
    let specs = intruder::resolve_specs(
        &parsed,
        intruder::AttackType::Sniper,
        &[intruder::PayloadSource::SimpleList {
            items: vec!["one".into(), "two".into()],
        }],
    )
    .unwrap();
    let state = run::start(
        net::Shared::new(),
        &text,
        intruder::AttackType::Sniper,
        specs,
        ("127.0.0.1".into(), port, false),
        settings(),
    )
    .unwrap();
    arrived_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    state.stop.store(true, Ordering::SeqCst);
    release_tx.send(()).unwrap();
    wait_finished(&state);
    server.join().unwrap();
    assert_eq!(state.progress(), (1, Some(3)));
    let rows = state.rows.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].number, 0);
}
