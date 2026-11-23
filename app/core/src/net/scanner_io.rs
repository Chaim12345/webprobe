//! Experimental direct H1 budgeted transport. No production/default wiring.
//! Counts are conservative application-byte allowance reservations, not
//! delivered bytes or ciphertext/IP traffic. Each <=4096-byte read/write is
//! reserved irreversibly, including short I/O, errors and EOF. This can consume
//! capacity faster than actual bytes, especially on trickle/short-read traffic.
use super::*;
use crate::scan_budget::Resource;
use crate::scan_lifecycle::{BudgetedExecution, ExecutionContext};

pub(crate) struct PartialExchange {
    pub response: Vec<u8>,
    pub complete: bool,
    pub diagnostic: Option<String>,
}
fn io_error(reason: impl ToString) -> std::io::Error {
    std::io::Error::other(reason.to_string())
}
pub(crate) fn permit(_shared: &Shared) -> Option<BudgetedExecution> {
    match crate::scan_lifecycle::captured() {
        Some(ExecutionContext::Budgeted(p)) => Some(p),
        _ => None,
    }
}
pub(crate) fn supported(shared: &Shared, host: &str, sink: bool) -> Result<(), String> {
    if sink
        || shared.upstream_for(host).kind != crate::upstream::UpstreamKind::None
        || shared.h2c_upgrade.load(Ordering::SeqCst)
        || H2_CHOICE.with(|c| c.get().is_some_and(|c| c.want_h2 == Some(true)))
        || !shared.streaming.lock().unwrap().urls.is_empty()
        || !shared.cookie_jar.lock().unwrap().cookies.is_empty()
        || !shared.session_rules.lock().unwrap().is_empty()
        || !shared.mr_request.lock().unwrap().is_empty()
        || !shared.mr_response.lock().unwrap().is_empty()
        || !shared
            .ext_hooks
            .lock()
            .unwrap()
            .as_any_mut()
            .is::<NoExtHooks>()
    {
        return Err("budgeted transport incomplete: configured boundary unsupported".into());
    }
    Ok(())
}
struct Metered<'a> {
    stream: TcpStream,
    shared: &'a Shared,
    permit: &'a BudgetedExecution,
    failed: bool,
    first: bool,
}
impl Metered<'_> {
    fn check(&self) -> std::io::Result<Duration> {
        scanner_send_admission(self.shared).map_err(io_error)?;
        self.permit
            .ledger()
            .remaining(Duration::from_millis(READ_TIMEOUT_MS))
            .map_err(|e| io_error(format!("ledger: {e:?}")))
    }
}
impl Read for Metered<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let result = (|| {
            let left = self.check()?;
            self.stream.set_read_timeout(Some(left))?;
            let available = self
                .permit
                .ledger()
                .available(Resource::Response)
                .and_then(|response| {
                    self.permit
                        .ledger()
                        .available(Resource::Decompressed)
                        .map(|decoded| response.min(decoded))
                })
                .map_err(|e| io_error(format!("ledger: {e:?}")))?;
            if available == 0 {
                return Err(io_error("response allowance exhausted"));
            }
            let cap = out
                .len()
                .min(4096)
                .min(usize::try_from(available).unwrap_or(usize::MAX));
            // Conservative irreversible allowance is reserved before socket read,
            // including short reads and EOF. Advisory capacity grants no access.
            self.permit
                .ledger()
                .reserve(&[
                    (Resource::Response, cap as u64),
                    (Resource::Decompressed, cap as u64),
                ])
                .map_err(|e| io_error(format!("ledger: {e:?}")))?;
            let n = self.stream.read(&mut out[..cap])?;
            Ok(n)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}
impl ResponseRead for Metered<'_> {
    fn set_read_timeout_ms(&self, _ms: u64) -> std::io::Result<()> {
        self.stream.set_read_timeout(Some(self.check()?))
    }
}
impl Write for Metered<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let left = self.check()?;
        self.stream.set_write_timeout(Some(left))?;
        let n = bytes.len().min(4096);
        let mut charges = vec![(Resource::Outgoing, n as u64)];
        if self.first {
            charges.push((Resource::HttpAttempt, 1));
        }
        self.permit
            .ledger()
            .reserve(&charges)
            .map_err(|e| io_error(format!("ledger: {e:?}")))?;
        self.first = false;
        // Reservation is intentionally not refunded after short/failed writes.
        self.stream.write(&bytes[..n])
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.check()?;
        self.stream.flush()
    }
}
pub(crate) fn exchange(
    shared: &Shared,
    permit: &BudgetedExecution,
    host: &str,
    port: u16,
    request: &[u8],
) -> PartialExchange {
    let mut buffer = Vec::new();
    let result = (|| -> Result<Vec<u8>, String> {
        permit
            .validate_shared(shared)
            .map_err(|_| "invalid budgeted owner")?;
        supported(shared, host, false)?;
        permit
            .ledger()
            .reserve(&[(Resource::Input, request.len() as u64)])
            .map_err(|e| format!("input: {e:?}"))?;
        let deadline = permit
            .ledger()
            .deadline()
            .map_err(|e| format!("deadline: {e:?}"))?;
        let addresses = crate::scan_resolver::process_resolver()
            .map_err(|e| format!("resolver: {e:?}"))?
            .resolve(permit.owner().clone(), host, port, deadline)
            .map_err(|e| format!("resolve: {e:?}"))?;
        let mut connected = None;
        for address in addresses {
            scanner_send_admission(shared)?;
            permit
                .ledger()
                .reserve(&[(Resource::ConnectionAttempt, 1)])
                .map_err(|e| format!("connect reservation: {e:?}"))?;
            let left = permit
                .ledger()
                .remaining(Duration::from_millis(CONNECT_TIMEOUT_MS))
                .map_err(|e| format!("connect time: {e:?}"))?;
            shared.conns_opened.fetch_add(1, Ordering::SeqCst);
            if let Ok(stream) = TcpStream::connect_timeout(&address, left) {
                connected = Some(stream);
                break;
            }
        }
        let stream = connected.ok_or("no admitted connection succeeded")?;
        let mut io = Metered {
            stream,
            shared,
            permit,
            failed: false,
            first: true,
        };
        io.write_all(request).map_err(|e| format!("write: {e}"))?;
        let method = request
            .split(|b| *b == b' ')
            .next()
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or("");
        let (response, _) = crate::codec::read_message(&mut io, &mut buffer, method, None)
            .map_err(|e| format!("read: {e}"))?;
        if io.failed {
            buffer = response;
            return Err("incomplete response I/O".into());
        }
        let Some(head) = util::find_head_end(&response) else {
            buffer = response;
            return Err("incomplete response head".into());
        };
        let parts = util::parse_http(&response[..head]);
        if util::get_header(&parts.headers, "Content-Encoding")
            .is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
        {
            buffer = response;
            return Err("incomplete: compressed response unsupported".into());
        }
        let code = parts.status.parse::<u16>().unwrap_or(0);
        let body_len = response.len().saturating_sub(head);
        let complete = match crate::codec::response_body_kind_strict(&response[..head], method) {
            Ok(crate::codec::BodyKind::None) => body_len == 0,
            Ok(crate::codec::BodyKind::Length(n)) => body_len == n,
            Ok(crate::codec::BodyKind::Chunked) => {
                let mut cursor = crate::codec::ChunkCursor::default();
                matches!(crate::codec::scan_chunked(&response[head..],&mut cursor,|_|{}),crate::codec::Chunked::Complete(n) if n==body_len)
            }
            Ok(crate::codec::BodyKind::UntilEof) => true,
            Err(_) => false,
        };
        if !(200..600).contains(&code)
            || !complete
            || crate::streaming::decide(
                &super::request_url(host, port, false, request),
                &response[..head],
                &shared.streaming.lock().unwrap(),
            ) == crate::streaming::Decision::Streaming
        {
            buffer = response;
            return Err("incomplete response framing or unsupported streaming".into());
        }
        Ok(response)
    })();
    match result {
        Ok(response) => PartialExchange {
            response,
            complete: true,
            diagnostic: None,
        },
        Err(diagnostic) => {
            permit.mark_incomplete();
            PartialExchange {
                response: buffer,
                complete: false,
                diagnostic: Some(diagnostic),
            }
        }
    }
}

thread_local! {static EXPECTED:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};}
/// Explicit handoff marker for a scanner helper that lost its execution mode.
/// Installing a marker alone grants no authority; net fails closed without mode.
#[derive(Clone, Copy)]
pub(crate) struct ExpectedScanner;
pub(crate) struct ExpectedInstalled(bool, std::marker::PhantomData<std::rc::Rc<()>>);
impl ExpectedScanner {
    pub(crate) fn install(self) -> ExpectedInstalled {
        ExpectedInstalled(EXPECTED.with(|v| v.replace(true)), std::marker::PhantomData)
    }
}
impl Drop for ExpectedInstalled {
    fn drop(&mut self) {
        EXPECTED.with(|v| v.set(self.0));
    }
}
pub(crate) fn expected() -> bool {
    EXPECTED.with(|v| v.get())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_lifecycle::{Coordinator, Finish, Handoff};
    fn limits() -> crate::scan_budget::Limits {
        crate::scan_budget::Limits {
            duration: Duration::from_secs(2),
            http_attempts: 20,
            connection_attempts: 20,
            outgoing: 65536,
            response: 65536,
            decompressed: 65536,
            inputs: 65536,
            evidence: 65536,
            evidence_records: 20,
            records: 20,
        }
    }
    fn finish(
        shared: &Arc<Shared>,
        limits: crate::scan_budget::Limits,
        body: impl FnOnce(&BudgetedExecution) -> Finish,
    ) -> Finish {
        let c = Coordinator::new(shared.clone(), limits).unwrap();
        let b = c.open().unwrap();
        match b.finish().unwrap() {
            Handoff::Finalize(f) => f.run(body),
            _ => panic!("finalizer"),
        }
    }
    fn server(reply: Vec<u8>, trickle: bool) -> (u16, std::thread::JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let mut s = super::super::inherited_context_tests::accept(&l);
            let mut b = [0; 4096];
            assert!(s.read(&mut b).unwrap() > 0);
            if trickle {
                for b in reply {
                    if s.write_all(&[b]).is_err() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(15));
                }
            } else {
                let _ = s.write_all(&reply);
            }
        });
        (port, t)
    }
    #[test]
    fn budgeted_h1_real_emission_counts_once_and_includes_framing() {
        let shared = Shared::new();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let count = response.len();
        let (port, t) = server(response, false);
        let req = b"GET /positive HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(
            finish(&shared, limits(), |p| {
                let up = send_raw(&shared, "127.0.0.1", port, req);
                assert!(up.resp.is_some(), "{:?}", up.error);
                assert_eq!(p.ledger().used(Resource::HttpAttempt), 1);
                assert_eq!(p.ledger().used(Resource::ConnectionAttempt), 1);
                assert_eq!(p.ledger().used(Resource::Outgoing), req.len() as u64);
                assert!(p.ledger().used(Resource::Response) >= count as u64);
                assert_eq!(
                    p.ledger().used(Resource::Response),
                    4096,
                    "reserved allowance, not delivered count"
                );
                Finish::Complete
            }),
            Finish::Complete
        );
        super::super::inherited_context_tests::join(t);
    }
    #[test]
    fn budgeted_h1_trickle_deadline_keeps_partial_bytes_and_no_retry() {
        let shared = Shared::new();
        let (port, t) = server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\nabcdef".to_vec(),
            true,
        );
        let mut config = limits();
        config.duration = Duration::from_millis(85);
        let started = Instant::now();
        assert_eq!(
            finish(&shared, config, |p| {
                let outcome = exchange(
                    &shared,
                    p,
                    "127.0.0.1",
                    port,
                    b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                );
                assert!(!outcome.complete);
                assert!(!outcome.response.is_empty());
                assert!(outcome.diagnostic.is_some());
                assert_eq!(p.ledger().used(Resource::HttpAttempt), 1);
                assert!(p.ledger().used(Resource::Response) > 0);
                Finish::Incomplete
            }),
            Finish::Incomplete
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        super::super::inherited_context_tests::join(t);
    }
    #[test]
    fn budgeted_h1_response_capacity_stops_before_growth_and_charges_partial() {
        let shared = Shared::new();
        let (port, t) = server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\nabcdef".to_vec(),
            false,
        );
        let mut config = limits();
        config.response = 16;
        assert_eq!(
            finish(&shared, config, |p| {
                let out = exchange(
                    &shared,
                    p,
                    "127.0.0.1",
                    port,
                    b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                );
                assert!(!out.complete);
                assert_eq!(out.response.len(), 16);
                assert_eq!(p.ledger().used(Resource::Response), 16);
                Finish::Incomplete
            }),
            Finish::Incomplete
        );
        super::super::inherited_context_tests::join(t);
    }
    #[test]
    fn budgeted_h1_unsupported_tls_proxy_session_and_missing_mode_marker_zero_wire() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        {
            let _marker = ExpectedScanner.install();
            let _helper = tool_scope("Session");
            assert!(send_raw(
                &shared,
                "127.0.0.1",
                port,
                b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
            )
            .resp
            .is_none());
        }
        assert_eq!(
            finish(&shared, limits(), |p| {
                assert!(send_tls_raw(
                    &shared,
                    "127.0.0.1",
                    port,
                    b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
                )
                .resp
                .is_none());
                shared.upstream.lock().unwrap().kind = crate::upstream::UpstreamKind::Http;
                assert!(send_raw(
                    &shared,
                    "127.0.0.1",
                    port,
                    b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
                )
                .resp
                .is_none());
                assert_eq!(p.ledger().used(Resource::ConnectionAttempt), 0);
                assert_eq!(p.ledger().used(Resource::HttpAttempt), 0);
                Finish::Incomplete
            }),
            Finish::Incomplete
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn budgeted_h1_pause_consumes_same_absolute_deadline() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let mut config = limits();
        config.duration = Duration::from_millis(30);
        shared.scan.paused.store(true, Ordering::SeqCst);
        assert_eq!(
            finish(&shared, config, |p| {
                assert!(send_raw(
                    &shared,
                    "127.0.0.1",
                    port,
                    b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
                )
                .resp
                .is_none());
                assert_eq!(p.ledger().used(Resource::ConnectionAttempt), 0);
                Finish::Incomplete
            }),
            Finish::Incomplete
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn budgeted_h1_swallowed_unsupported_and_truncated_responses_remain_incomplete() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx".to_vec(),
        ] {
            let shared = Shared::new();
            let (port, t) = server(response, false);
            assert_eq!(
                finish(&shared, limits(), |_| {
                    let up = send_raw(
                        &shared,
                        "127.0.0.1",
                        port,
                        b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                    );
                    assert!(up.resp.is_none());
                    Finish::Complete
                }),
                Finish::Incomplete
            );
            super::super::inherited_context_tests::join(t);
        }
        for boundary in 0..4 {
            let shared = Shared::new();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            listener.set_nonblocking(true).unwrap();
            assert_eq!(
                finish(&shared, limits(), |p| {
                    match boundary {
                        0 => {
                            let _ = send_tls_raw(
                                &shared,
                                "127.0.0.1",
                                port,
                                b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                            );
                        }
                        1 => {
                            shared.upstream.lock().unwrap().kind =
                                crate::upstream::UpstreamKind::Http;
                            let _ = send_raw(
                                &shared,
                                "127.0.0.1",
                                port,
                                b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                            );
                        }
                        2 => {
                            shared.h2c_upgrade.store(true, Ordering::SeqCst);
                            let _ = send_raw(
                                &shared,
                                "127.0.0.1",
                                port,
                                b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                            );
                        }
                        _ => {
                            let _h2 = http2_scope(Http2Choice {
                                want_h2: Some(true),
                                strip_connection: true,
                            });
                            let _ = send_raw(
                                &shared,
                                "127.0.0.1",
                                port,
                                b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                            );
                        }
                    }
                    assert_eq!(p.ledger().used(Resource::HttpAttempt), 0);
                    assert_eq!(p.ledger().used(Resource::ConnectionAttempt), 0);
                    Finish::Complete
                }),
                Finish::Incomplete
            );
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
    #[test]
    fn budgeted_h1_outgoing_capacity_zero_http_exposure_is_not_success() {
        let shared = Shared::new();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let mut s = super::super::inherited_context_tests::accept(&l);
            let mut b = [0; 1];
            assert_eq!(s.read(&mut b).unwrap(), 0);
        });
        let mut config = limits();
        config.outgoing = 1;
        assert_eq!(
            finish(&shared, config, |p| {
                assert!(send_raw(
                    &shared,
                    "127.0.0.1",
                    port,
                    b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
                )
                .resp
                .is_none());
                assert_eq!(p.ledger().used(Resource::HttpAttempt), 0);
                assert_eq!(p.ledger().used(Resource::Outgoing), 0);
                assert_eq!(p.ledger().used(Resource::ConnectionAttempt), 1);
                Finish::Complete
            }),
            Finish::Incomplete
        );
        super::super::inherited_context_tests::join(t);
    }
}
