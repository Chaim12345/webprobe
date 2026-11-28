//! Experimental direct H1 budgeted transport. No production/default wiring.
//! Counts are conservative application-byte allowance reservations, not
//! delivered bytes or ciphertext/IP traffic. Each <=4096-byte read/write is
//! reserved irreversibly, including short I/O, errors and EOF. This can consume
//! capacity faster than actual bytes, especially on trickle/short-read traffic.
//! The per-response 64MiB cap counts raw headers plus body. At exact cap an
//! UntilEOF response stays Incomplete, even if its peer closed: no further read
//! is admitted just to establish EOF. This is a conservative capacity outcome.
use super::*;
use crate::scan_budget::Resource;
use crate::scan_lifecycle::{BudgetedExecution, ExecutionContext};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExchangeStatus {
    Complete,
    Incomplete,
}
pub(crate) struct PartialExchange {
    pub response: Vec<u8>,
    pub status: ExchangeStatus,
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
        || !shared.streaming.lock().urls.is_empty()
        || !shared.cookie_jar.lock().cookies.is_empty()
        || !shared.session_rules.lock().is_empty()
        || !shared.mr_request.lock().is_empty()
        || !shared.mr_response.lock().is_empty()
        || !shared.ext_hooks.lock().as_any_mut().is::<NoExtHooks>()
    {
        return Err("budgeted transport incomplete: configured boundary unsupported".into());
    }
    Ok(())
}
struct Metered<'a> {
    stream: TcpStream,
    shared: &'a Shared,
    permit: &'a BudgetedExecution,
    first: bool,
}
impl Metered<'_> {
    fn check(&self) -> std::io::Result<Duration> {
        exact(self.shared, self.permit).map_err(io_error)?;
        scanner_send_admission(self.shared).map_err(io_error)?;
        self.permit
            .ledger()
            .remaining(Duration::from_millis(READ_TIMEOUT_MS))
            .map_err(|e| io_error(format!("ledger: {e:?}")))
    }
}
impl Read for Metered<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        (|| {
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
        })()
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
        exact(shared, permit)?;
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
            first: true,
        };
        let request = util::origin_form(request);
        io.write_all(&request).map_err(|e| format!("write: {e}"))?;
        let method = request
            .split(|b| *b == b' ')
            .next()
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or("");
        let mut parser = RawParser::default();
        loop {
            match parser.assess(&buffer, method, false)? {
                Assessment::Complete => return Ok(std::mem::take(&mut buffer)),
                Assessment::Need => {}
            }
            let mut scratch = [0; 4096];
            let cap = scratch
                .len()
                .min(crate::codec::MAX_BODY.saturating_sub(buffer.len()));
            if cap == 0 {
                return Err("per-response 64MiB cap reached, not EOF".into());
            }
            let n = io
                .read(&mut scratch[..cap])
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return match parser.assess(&buffer, method, true)? {
                    Assessment::Complete => Ok(std::mem::take(&mut buffer)),
                    Assessment::Need => Err("incomplete clean EOF".into()),
                };
            }
            buffer.extend_from_slice(&scratch[..n]);
        }
    })();
    match result {
        Ok(response) => PartialExchange {
            response,
            status: ExchangeStatus::Complete,
            diagnostic: None,
        },
        Err(diagnostic) => {
            permit.mark_incomplete();
            PartialExchange {
                response: buffer,
                status: ExchangeStatus::Incomplete,
                diagnostic: Some(diagnostic),
            }
        }
    }
}

thread_local! {
    static EXPECTED:std::cell::RefCell<Vec<u64>>=const{std::cell::RefCell::new(Vec::new())};
    static MARKER_ID:std::cell::Cell<u64>=const{std::cell::Cell::new(0)};
}
#[derive(Clone, Copy)]
pub(crate) struct ExpectedScanner;
pub(crate) struct ExpectedInstalled(u64, std::marker::PhantomData<std::rc::Rc<()>>);
impl ExpectedScanner {
    pub(crate) fn install(self) -> Result<ExpectedInstalled, String> {
        let id = MARKER_ID
            .with(|v| v.get().checked_add(1))
            .ok_or("marker identity exhausted")?;
        EXPECTED.with(|v| {
            let mut v = v.borrow_mut();
            if v.len() >= 64 {
                return Err::<(), String>("marker depth exceeded".into());
            }
            v.push(id);
            Ok(())
        })?;
        MARKER_ID.with(|v| v.set(id));
        Ok(ExpectedInstalled(id, std::marker::PhantomData))
    }
}
impl Drop for ExpectedInstalled {
    fn drop(&mut self) {
        EXPECTED.with(|v| v.borrow_mut().retain(|id| *id != self.0));
    }
}
pub(crate) fn expected() -> bool {
    EXPECTED.with(|v| !v.borrow().is_empty())
}
fn exact(shared: &Shared, permit: &BudgetedExecution) -> Result<(), String> {
    permit
        .validate_shared(shared)
        .map_err(|_| "invalid budgeted owner")?;
    match crate::scan_lifecycle::captured() {
        Some(ExecutionContext::Budgeted(p))
            if Arc::ptr_eq(p.owner(), permit.owner())
                && std::ptr::eq(p.ledger(), permit.ledger()) =>
        {
            Ok(())
        }
        _ => Err("budgeted execution ambient owner/ledger mismatch".into()),
    }
}
pub(crate) fn send_budgeted(
    shared: &Shared,
    permit: &BudgetedExecution,
    https: bool,
    host: &str,
    port: u16,
    request: &[u8],
) -> PartialExchange {
    if https {
        permit.mark_incomplete();
        return PartialExchange {
            response: Vec::new(),
            status: ExchangeStatus::Incomplete,
            diagnostic: Some("TLS unsupported".into()),
        };
    }
    exchange(shared, permit, host, port, request)
}
enum Assessment {
    Need,
    Complete,
}
#[derive(Default)]
struct RawParser {
    searched: usize,
    head: Option<usize>,
    kind: Option<crate::codec::BodyKind>,
    chunk_at: usize,
    chunk_end: Option<usize>,
    zero: bool,
}
impl RawParser {
    fn assess(&mut self, raw: &[u8], method: &str, eof: bool) -> Result<Assessment, String> {
        let head = if let Some(head) = self.head {
            head
        } else {
            let from = self.searched.saturating_sub(3);
            let Some(found) = util::find_head_end(&raw[from..]) else {
                self.searched = raw.len();
                return if raw.len() > 65536 {
                    Err("head limit".into())
                } else {
                    Ok(Assessment::Need)
                };
            };
            let head = from + found;
            if head > 65536 {
                return Err("head limit".into());
            }
            self.head = Some(head);
            head
        };
        if self.kind.is_none() {
            let text = std::str::from_utf8(&raw[..head]).map_err(|_| "invalid header bytes")?;
            if text
                .as_bytes()
                .iter()
                .enumerate()
                .any(|(i, b)| *b == b'\n' && (i == 0 || text.as_bytes()[i - 1] != b'\r'))
            {
                return Err("bare LF".into());
            }
            let mut lines = text.split("\r\n");
            let status = lines.next().unwrap_or("");
            let mut fields = status.splitn(3, ' ');
            let version = fields.next().unwrap_or("");
            let code = fields.next().unwrap_or("");
            let reason = fields.next();
            if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
                || code.len() != 3
                || !code.bytes().all(|b| b.is_ascii_digit())
                || reason.is_none()
            {
                return Err("invalid status line".into());
            }
            if reason.unwrap_or("").bytes().any(|b| b < 32 || b == 127) {
                return Err("invalid reason phrase".into());
            }
            let code = code.parse::<u16>().map_err(|_| "invalid status")?;
            if !(200..600).contains(&code) {
                return Err("unsupported interim/upgrade/invalid status".into());
            }
            let mut encoding = false;
            let mut lengths = Vec::new();
            let mut transfers = Vec::new();
            for line in lines {
                if line.is_empty() {
                    continue;
                }
                let (name, value) = line.split_once(':').ok_or("invalid header")?;
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                    || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
                {
                    return Err("invalid header syntax".into());
                }
                if name.eq_ignore_ascii_case("content-length") {
                    lengths.push(value.trim());
                }
                if name.eq_ignore_ascii_case("transfer-encoding") {
                    transfers.push(value.trim());
                }
                if name.eq_ignore_ascii_case("content-encoding")
                    && !value.trim().eq_ignore_ascii_case("identity")
                {
                    encoding = true;
                }
                if name.eq_ignore_ascii_case("content-type")
                    && value
                        .trim()
                        .to_ascii_lowercase()
                        .starts_with("text/event-stream")
                {
                    return Err("streaming unsupported".into());
                }
            }
            if encoding {
                return Err("compressed response unsupported after bounded head read".into());
            }
            if !lengths.is_empty() && !transfers.is_empty() {
                return Err("TE plus CL".into());
            }
            let mut length = None;
            for value in lengths.iter().flat_map(|v| v.split(',')) {
                let value = value.trim();
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("bad CL".into());
                }
                let n = value.parse::<usize>().map_err(|_| "CL overflow")?;
                if length.is_some_and(|old| old != n) {
                    return Err("conflicting CL".into());
                }
                length = Some(n);
            }
            if !transfers.is_empty()
                && (transfers.len() != 1 || !transfers[0].eq_ignore_ascii_case("chunked"))
            {
                return Err("unsupported TE chain".into());
            }
            if code == 204 && (!lengths.is_empty() || !transfers.is_empty()) {
                return Err("204 illegal framing".into());
            }
            self.kind = Some(
                if method.eq_ignore_ascii_case("HEAD") || code == 204 || code == 304 {
                    crate::codec::BodyKind::None
                } else if !transfers.is_empty() {
                    crate::codec::BodyKind::Chunked
                } else if let Some(n) = length {
                    crate::codec::BodyKind::Length(n)
                } else {
                    crate::codec::BodyKind::UntilEof
                },
            );
        }
        let body = &raw[head..];
        match self.kind.unwrap() {
            crate::codec::BodyKind::None => {
                if body.is_empty() {
                    Ok(Assessment::Complete)
                } else {
                    Err("excess bodyless bytes".into())
                }
            }
            crate::codec::BodyKind::Length(n) => match body.len().cmp(&n) {
                std::cmp::Ordering::Less => Ok(Assessment::Need),
                std::cmp::Ordering::Equal => Ok(Assessment::Complete),
                _ => Err("excess response bytes".into()),
            },
            crate::codec::BodyKind::UntilEof => Ok(if eof {
                Assessment::Complete
            } else {
                Assessment::Need
            }),
            crate::codec::BodyKind::Chunked => loop {
                if let Some(end) = self.chunk_end {
                    if body.len() < end {
                        return Ok(Assessment::Need);
                    }
                    if &body[end - 2..end] != b"\r\n" {
                        return Err("chunk terminator".into());
                    }
                    self.chunk_at = end;
                    self.chunk_end = None;
                }
                if self.zero {
                    return if body.len() < self.chunk_at + 2 {
                        Ok(Assessment::Need)
                    } else if &body[self.chunk_at..] == b"\r\n" {
                        Ok(Assessment::Complete)
                    } else {
                        Err("trailers/excess unsupported".into())
                    };
                }
                let at = self.chunk_at;
                let Some(end) = body[at..].windows(2).position(|w| w == b"\r\n") else {
                    if body.len() - at > 32 {
                        return Err("chunk line limit".into());
                    }
                    return Ok(Assessment::Need);
                };
                let line = &body[at..at + end];
                if line.is_empty() || line.len() > 32 || !line.iter().all(|b| b.is_ascii_hexdigit())
                {
                    return Err("strict chunk size/extensions rejected".into());
                }
                let n =
                    usize::from_str_radix(std::str::from_utf8(line).map_err(|_| "chunk size")?, 16)
                        .map_err(|_| "chunk overflow")?;
                self.chunk_at = at + end + 2;
                if n == 0 {
                    self.zero = true;
                } else {
                    self.chunk_end = Some(
                        self.chunk_at
                            .checked_add(n)
                            .and_then(|n| n.checked_add(2))
                            .ok_or("chunk overflow")?,
                    );
                }
            },
        }
    }
}
#[cfg(test)]
fn assess(raw: &[u8], method: &str, eof: bool) -> Result<Assessment, String> {
    RawParser::default().assess(raw, method, eof)
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
        let mut panic = None;
        let result = match b.finish().unwrap() {
            Handoff::Finalize(f) => f.run(|p| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(p))) {
                    Ok(v) => v,
                    Err(e) => {
                        panic = Some(e);
                        Finish::Incomplete
                    }
                }
            }),
            _ => panic!("finalizer"),
        };
        if let Some(e) = panic {
            std::panic::resume_unwind(e);
        }
        result
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
                assert!(
                    p.ledger().used(Resource::Response) > count as u64,
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
                assert_eq!(outcome.status, ExchangeStatus::Incomplete);
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
                assert_eq!(out.status, ExchangeStatus::Incomplete);
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
            let _marker = ExpectedScanner.install().unwrap();
            let _helper = tool_scope("Session");
            assert!(
                send_raw(
                    &shared,
                    "127.0.0.1",
                    port,
                    b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
                )
                .resp
                .is_none()
            );
        }
        assert_eq!(
            finish(&shared, limits(), |p| {
                assert!(
                    send_tls_raw(
                        &shared,
                        "127.0.0.1",
                        port,
                        b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
                    )
                    .resp
                    .is_none()
                );
                shared.upstream.lock().kind = crate::upstream::UpstreamKind::Http;
                assert!(
                    send_raw(
                        &shared,
                        "127.0.0.1",
                        port,
                        b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
                    )
                    .resp
                    .is_none()
                );
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
                assert!(
                    send_raw(
                        &shared,
                        "127.0.0.1",
                        port,
                        b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
                    )
                    .resp
                    .is_none()
                );
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
                            shared.upstream.lock().kind = crate::upstream::UpstreamKind::Http;
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
                                force_h2: false,
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
                assert!(
                    send_raw(
                        &shared,
                        "127.0.0.1",
                        port,
                        b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"
                    )
                    .resp
                    .is_none()
                );
                assert_eq!(p.ledger().used(Resource::HttpAttempt), 0);
                assert_eq!(p.ledger().used(Resource::Outgoing), 0);
                assert_eq!(p.ledger().used(Resource::ConnectionAttempt), 1);
                Finish::Complete
            }),
            Finish::Incomplete
        );
        super::super::inherited_context_tests::join(t);
    }
    #[test]
    fn budgeted_h1_strict_raw_rejects_malformed_and_excess_before_complete() {
        for raw in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nxHTTP/1.1 200 OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n",
            b"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;x=y\r\nx\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\n0\r\n\r\n",
        ] {
            assert!(
                !matches!(assess(raw, "GET", true), Ok(Assessment::Complete)),
                "malformed accepted"
            );
        }
        assert!(matches!(
            assess(b"HTTP/1.1 200 OK\r\n\r\nx", "GET", false),
            Ok(Assessment::Need)
        ));
        assert!(matches!(
            assess(b"HTTP/1.1 200 OK\r\n\r\nx", "GET", true),
            Ok(Assessment::Complete)
        ));
    }
    #[test]
    fn budgeted_h1_expected_marker_both_drop_orders_and_depth_are_exact() {
        for reverse in [false, true] {
            let a = ExpectedScanner.install().unwrap();
            let b = ExpectedScanner.install().unwrap();
            assert!(expected());
            if reverse {
                drop(b);
                assert!(expected());
                drop(a);
            } else {
                drop(a);
                assert!(expected());
                drop(b);
            }
            assert!(!expected());
        }
        let markers = (0..64)
            .map(|_| ExpectedScanner.install().unwrap())
            .collect::<Vec<_>>();
        assert!(ExpectedScanner.install().is_err());
        drop(markers);
        assert!(!expected());
    }
    #[test]
    fn budgeted_h1_normalizes_absolute_form_and_until_eof_requires_clean_close() {
        let shared = Shared::new();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let mut s = super::super::inherited_context_tests::accept(&l);
            let mut bytes = [0; 4096];
            let n = s.read(&mut bytes).unwrap();
            assert!(bytes[..n].starts_with(b"GET /origin HTTP/1.1"));
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\nclean").unwrap();
        });
        assert_eq!(
            finish(&shared, limits(), |p| {
                let req = format!("GET http://127.0.0.1:{port}/origin HTTP/1.1\r\nHost: h\r\n\r\n");
                let out = send_budgeted(&shared, p, false, "127.0.0.1", port, req.as_bytes());
                assert_eq!(out.status, ExchangeStatus::Complete);
                Finish::Complete
            }),
            Finish::Complete
        );
        super::super::inherited_context_tests::join(t);
    }
    #[test]
    fn budgeted_h1_foreign_ambient_permit_and_header_only_compression_fail_before_body() {
        let shared = Shared::new();
        let other = Shared::new();
        let mut mismatch = None;
        let mut nested_result = None;
        let result = finish(&shared, limits(), |first| {
            let other_result = finish(&other, limits(), |_| {
                let denied = exact(&shared, first).is_err();
                let out = send_budgeted(
                    &shared,
                    first,
                    false,
                    "127.0.0.1",
                    9,
                    b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                );
                mismatch = Some((denied, out.status));
                Finish::Complete
            });
            nested_result = Some(other_result);
            Finish::Complete
        });
        assert_eq!(result, Finish::Incomplete);
        assert_eq!(nested_result, Some(Finish::Complete));
        assert_eq!(mismatch, Some((true, ExchangeStatus::Incomplete)));
        let shared = Shared::new();
        let (port, t) = server(
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 99999999\r\n\r\n"
                .to_vec(),
            false,
        );
        let mut observed = None;
        let result = finish(&shared, limits(), |p| {
            let out = send_budgeted(
                &shared,
                p,
                false,
                "127.0.0.1",
                port,
                b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            );
            observed = Some((out.status, out.response.len()));
            Finish::Complete
        });
        assert_eq!(result, Finish::Incomplete);
        let (status, len) = observed.unwrap();
        assert_eq!(status, ExchangeStatus::Incomplete);
        assert!(len <= 4096);
        super::super::inherited_context_tests::join(t);
    }
    #[test]
    fn budgeted_h1_all_framing_validated_before_bodyless_wire_controls() {
        for (raw, method, complete) in [
            (
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".as_slice(),
                "GET",
                false,
            ),
            (
                b"HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\n".as_slice(),
                "GET",
                false,
            ),
            (
                b"HTTP/1.1 204 No Content\r\nContent-Length: x\r\n\r\n",
                "GET",
                false,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
                "HEAD",
                false,
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
                "GET",
                false,
            ),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "GET", true),
            (
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n\r\n",
                "GET",
                true,
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
                "GET",
                true,
            ),
        ] {
            let shared = Shared::new();
            let (port, t) = server(raw.to_vec(), false);
            let mut observed = None;
            let outcome = finish(&shared, limits(), |p| {
                let req = format!("{method} / HTTP/1.1\r\nHost: h\r\n\r\n");
                observed = Some(
                    send_budgeted(&shared, p, false, "127.0.0.1", port, req.as_bytes()).status,
                );
                Finish::Complete
            });
            assert_eq!(
                observed,
                Some(if complete {
                    ExchangeStatus::Complete
                } else {
                    ExchangeStatus::Incomplete
                })
            );
            assert_eq!(
                outcome,
                if complete {
                    Finish::Complete
                } else {
                    Finish::Incomplete
                }
            );
            super::super::inherited_context_tests::join(t);
        }
    }
    #[test]
    fn budgeted_h1_actual_wire_per_response_cap_is_incomplete_not_eof() {
        let shared = Shared::new();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let mut stream = super::super::inherited_context_tests::accept(&l);
            let mut req = [0; 4096];
            let _ = stream.read(&mut req).unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
            let chunk = [b'x'; 4096];
            for _ in 0..(crate::codec::MAX_BODY / 4096 + 1) {
                if stream.write_all(&chunk).is_err() {
                    break;
                }
            }
        });
        let mut config = limits();
        config.duration = Duration::from_secs(10);
        config.response = 128 * 1024 * 1024;
        config.decompressed = config.response;
        let mut observed = None;
        let outcome = finish(&shared, config, |p| {
            let out = send_budgeted(
                &shared,
                p,
                false,
                "127.0.0.1",
                port,
                b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            );
            observed = Some((out.status, out.response.len(), out.diagnostic));
            Finish::Complete
        });
        assert_eq!(outcome, Finish::Incomplete);
        let (status, len, reason) = observed.unwrap();
        assert_eq!(status, ExchangeStatus::Incomplete);
        assert_eq!(len, crate::codec::MAX_BODY);
        assert!(reason.unwrap().contains("not EOF"));
        super::super::inherited_context_tests::join(t);
    }
}
