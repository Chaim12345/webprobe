//! Real transport fixtures for the experimental inherited-only net seam.
//! Production lifecycle and transport accounting remain unwired.
use super::*;
use crate::scan_lifecycle::{Coordinator, ExecutionContext, Finish, Handoff};
pub(super) fn limits() -> crate::scan_budget::Limits {
    crate::scan_budget::Limits {
        duration: Duration::from_secs(10),
        http_attempts: 100,
        connection_attempts: 100,
        outgoing: 65536,
        response: 65536,
        decompressed: 65536,
        inputs: 65536,
        evidence: 65536,
        evidence_records: 100,
        records: 100,
    }
}
pub(super) fn accept(l: &TcpListener) -> TcpStream {
    l.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match l.accept() {
            Ok((s, _)) => {
                s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                return s;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "accept deadline");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("{e}"),
        }
    }
}
pub(super) fn join<T>(t: std::thread::JoinHandle<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !t.is_finished() {
        assert!(Instant::now() < deadline, "join deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
    t.join().unwrap_or_else(|e| std::panic::resume_unwind(e))
}
#[test]
fn inherited_net_missing_and_wrong_shared_fail_closed_other_tools_unchanged() {
    let shared = Shared::new();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let _scanner = tool_scope("Scanner");
    let expected = scanner_io::ExpectedScanner.install().unwrap();
    assert!(send_raw(
        &shared,
        "127.0.0.1",
        port,
        b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
    )
    .resp
    .is_none());
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 0);
    let c = Coordinator::new(shared.clone(), limits()).unwrap();
    let b = c.open().unwrap();
    let context = b.context();
    let _installed = context.enter(&shared).unwrap();
    let wrong = Shared::new();
    assert!(scanner_send_admission(&wrong).is_err());
    drop(_installed);
    drop(expected);
    let _other = tool_scope("Repeater");
    assert!(scanner_send_admission(&wrong).is_ok());
}
#[test]
fn inherited_net_old_cancel_new_owner_reset_blocks_plain_tls_helpers_and_macro() {
    for proxy in [false, true] {
        let shared = Shared::new();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        if proxy {
            *shared.upstream.lock().unwrap() = crate::upstream::UpstreamConfig {
                kind: crate::upstream::UpstreamKind::Http,
                host: "127.0.0.1".into(),
                port: port.to_string(),
                ..Default::default()
            };
        }
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let old = c.open().unwrap();
        let context = old.context();
        let cancel = old.cancel_handle();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let sh = shared.clone();
        let worker = std::thread::spawn(move || {
            let _installed = context.enter(&sh).unwrap();
            ready_tx.send(()).unwrap();
            resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let _helper = tool_scope("Session");
            let raw = b"GET /old HTTP/1.1\r\nHost: h\r\n\r\n";
            assert!(send_raw(&sh, "127.0.0.1", port, raw).resp.is_none());
            assert!(send_from(&sh, "127.0.0.1", port, raw, None).resp.is_none());
            assert!(send_inner(&sh, "127.0.0.1", port, raw, None).is_err());
            assert!(send_tls_raw(&sh, "127.0.0.1", port, raw).resp.is_none());
            assert!(send_tls_inner(&sh, "127.0.0.1", port, raw, None).is_err());
            let steps = run_macro_text(
                &sh,
                &format!("GET /macro HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
            );
            assert_eq!(steps.len(), 1);
            assert!(steps[0].response.is_none());
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        cancel.cancel();
        drop(old);
        let new = c.open().unwrap();
        shared.scan.stop.store(false, Ordering::SeqCst);
        resume_tx.send(()).unwrap();
        join(worker);
        assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 0);
        l.set_nonblocking(true).unwrap();
        assert_eq!(
            l.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let server = std::thread::spawn(move || {
            let mut s = accept(&l);
            let mut bytes = [0; 4096];
            let n = s.read(&mut bytes).unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            String::from_utf8_lossy(&bytes[..n]).into_owned()
        });
        let ctx = new.context();
        let _installed = ctx.enter(&shared).unwrap();
        assert!(send_raw(
            &shared,
            "127.0.0.1",
            port,
            b"GET /new HTTP/1.1\r\nHost: h\r\n\r\n"
        )
        .resp
        .is_some());
        assert!(join(server).contains("/new"));
    }
}
#[test]
fn inherited_net_budgeted_finalizer_installs_exact_ledger_and_denies_exhaustion() {
    let shared = Shared::new();
    let c = Coordinator::new(shared.clone(), limits()).unwrap();
    let b = c.open().unwrap();
    let f = match b.finish().unwrap() {
        Handoff::Finalize(f) => f,
        _ => panic!("finalizer"),
    };
    assert_eq!(
        f.run(|p| {
            assert!(matches!(
                crate::scan_lifecycle::captured(),
                Some(ExecutionContext::Budgeted(_))
            ));
            assert!(scanner_send_admission(&shared).is_ok());
            assert!(p
                .ledger()
                .reserve(&[(crate::scan_budget::Resource::HttpAttempt, 101)])
                .is_err());
            assert!(scanner_send_admission(&shared).is_err());
            Finish::Incomplete
        }),
        Finish::Incomplete
    );
}

#[test]
fn inherited_net_macro_continuation_keeps_cancelled_owner_after_reset() {
    let shared = Shared::new();
    let c = Coordinator::new(shared.clone(), limits()).unwrap();
    let b = c.open().unwrap();
    let context = b.context();
    let cancellation = b.cancel_handle();
    let _installed = context.enter(&shared).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let co = c.clone();
    let sh = shared.clone();
    let server = std::thread::spawn(move || {
        let mut s = accept(&l);
        let mut bytes = [0; 4096];
        assert!(s.read(&mut bytes).unwrap() > 0);
        cancellation.cancel();
        drop(b);
        let _next = co.open().unwrap();
        sh.scan.stop.store(false, Ordering::SeqCst);
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
        l
    });
    let text=format!("GET /first HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n###\nGET /second HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let results = run_macro_text(&shared, &text);
    assert_eq!(results.len(), 2);
    assert!(results[0].response.is_some());
    assert!(results[1].response.is_none());
    let l = join(server);
    l.set_nonblocking(true).unwrap();
    assert_eq!(
        l.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 1);
}
