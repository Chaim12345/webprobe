//! Keep-alive and pipeline fixtures for the tolerant framing callers
//! (`net::read_request`, `codec::read_message`, `conn_reuse::response_allows_reuse`)
//! beside the strict verdicts. They pin TODAY's behaviour so that wiring
//! strict mode in (gated on these fixtures) changes only what is intended.
//! Cases marked DIVERGES are where strict will close a connection the
//! tolerant path would keep or misframe.

use crate::codec::read_message;
use crate::net::{read_request, response_allows_reuse};
use crate::strict_request::{scan_request_head, RequestFramingError as E, StrictRequest as S};
use std::io::{Cursor, Read};

/// Delivers the script in reads of at most `step` bytes, as a socket would.
struct Script {
    data: Cursor<Vec<u8>>,
    step: usize,
}
impl Script {
    fn new(data: &[u8], step: usize) -> Self {
        Script {
            data: Cursor::new(data.to_vec()),
            step,
        }
    }
}
impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.step);
        self.data.read(&mut buf[..n])
    }
}
impl webprobe_support::io_traits::ResponseRead for Script {
    fn set_read_timeout_ms(&self, _ms: u64) -> std::io::Result<()> {
        Ok(())
    }
}

const STEPS: [usize; 4] = [1, 3, 7, 16_384];

fn msg(wire: &[u8], step: usize, method: &str) -> (Vec<u8>, bool, Vec<u8>) {
    let mut buffer = Vec::new();
    let (m, reuse) = read_message(&mut Script::new(wire, step), &mut buffer, method, None).unwrap();
    (m, reuse, buffer)
}

// ------------------------------------------------------------- responses

#[test]
fn two_pipelined_responses_split_exactly_at_every_read_size() {
    let a = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec();
    let b = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n".to_vec();
    let mut wire = a.clone();
    wire.extend_from_slice(&b);
    for step in STEPS {
        let mut buffer = Vec::new();
        let mut s = Script::new(&wire, step);
        let (m1, r1) = read_message(&mut s, &mut buffer, "GET", None).unwrap();
        assert_eq!((m1, r1), (a.clone(), true), "first, step {step}");
        let (m2, r2) = read_message(&mut s, &mut buffer, "GET", None).unwrap();
        assert_eq!((m2, r2), (b.clone(), true), "second, step {step}");
        assert!(buffer.is_empty(), "nothing left, step {step}");
    }
}

#[test]
fn bodyless_statuses_and_head_keep_the_connection_and_leave_next_bytes() {
    let next = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let cases: [(&str, &[u8], &str); 5] = [
        (
            "204 with length",
            b"HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\n",
            "GET",
        ),
        (
            "304 with length",
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n",
            "GET",
        ),
        (
            "HEAD with length",
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n",
            "HEAD",
        ),
        (
            "HEAD with TE",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HEAD",
        ),
        (
            "100 then 204",
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
            "POST",
        ),
    ];
    for (name, head, method) in cases {
        for step in STEPS {
            let mut wire = head.to_vec();
            wire.extend_from_slice(next);
            let (m, reuse, left) = msg(&wire, step, method);
            assert!(reuse, "{name} step {step}");
            assert!(!m.is_empty());
            // Whatever was read past this response must be the next one, intact.
            let mut rest = left;
            let mut s = Script::new(&wire[wire.len() - next.len()..], 16_384);
            if rest.is_empty() {
                let mut b = Vec::new();
                let _ = s.read_to_end(&mut b);
                rest = b;
            }
            assert!(
                next.starts_with(&rest) || rest == next,
                "{name} step {step}: {rest:?}"
            );
        }
    }
}

#[test]
fn until_eof_and_truncated_bodies_never_allow_reuse() {
    for (name, wire) in [
        (
            "no framing",
            &b"HTTP/1.1 200 OK\r\n\r\nbody until close"[..],
        ),
        (
            "conflicting CL",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 9\r\n\r\nabc",
        ),
        (
            "truncated length",
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc",
        ),
        (
            "truncated chunked",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
        ),
        (
            "malformed chunk size",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nx\r\n0\r\n\r\n",
        ),
    ] {
        let (_, reuse, _) = msg(wire, 7, "GET");
        assert!(!reuse, "{name}");
    }
}

#[test]
fn tolerant_response_framing_where_strict_will_close() {
    // DIVERGES: tolerant reads these with a body framing and keeps the
    // connection; strict (response_body_kind_strict) errors, so a wired
    // strict mode must close instead.
    use crate::codec::{response_body_kind_strict as strict, FramingError as F};
    for (name, wire, want_body, strict_err) in [
        (
            "space before colon",
            &b"HTTP/1.1 200 OK\r\nContent-Length : 3\r\n\r\nabc"[..],
            &b"abc"[..],
            F::SpaceBeforeColon,
        ),
        (
            "TE and CL",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            b"3\r\nabc\r\n0\r\n\r\n",
            F::AmbiguousFraming,
        ),
        (
            "plus length",
            b"HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\nabc",
            b"abc",
            F::BadContentLength,
        ),
    ] {
        let (m, reuse, left) = msg(wire, 5, "GET");
        assert!(m.ends_with(want_body), "{name}: {m:?}");
        assert!(reuse, "{name}: tolerant keeps the connection");
        assert!(left.is_empty());
        let head_end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(strict(&wire[..head_end], "GET"), Err(strict_err), "{name}");
    }
}

#[test]
fn reuse_decision_pins() {
    // (name, wire, reusable today)
    let cases: &[(&str, &[u8], bool)] = &[
        (
            "length complete",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
            true,
        ),
        (
            "length short",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
            false,
        ),
        (
            "chunked complete",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            true,
        ),
        (
            "chunked incomplete",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
            false,
        ),
        (
            "connection close",
            b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (
            "keep-alive, close",
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive, close\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (
            "http/1.0 plain",
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (
            "http/1.0 keep-alive",
            b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
            true,
        ),
        ("204", b"HTTP/1.1 204 No Content\r\n\r\n", true),
        ("100 continue alone", b"HTTP/1.1 100 Continue\r\n\r\n", true),
        // DIVERGES / known quirks, pinned so a change is deliberate:
        // a read-until-close response is "reusable" here (body_complete is
        // true for UntilEof), contradicting the comment in the function.
        // Safe today on the main paths because `read_message` also returns
        // reusable=false for it and both are required; the h2c-declined
        // path in `try_h2c_upgrade` checks only this function.
        ("until eof", b"HTTP/1.1 200 OK\r\n\r\nxyz", true),
        (
            "conflicting CL (until eof)",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nabc",
            true,
        ),
        // trailing bytes after a complete message do not stop reuse.
        (
            "length plus trailing bytes",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcEXTRA",
            true,
        ),
        // a head with a Content-Length and no body bytes at all counts as complete.
        (
            "length, head only",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            true,
        ),
        // HTTP/1.0 keep-alive is trusted whatever the framing.
        (
            "http/1.0 keep-alive until eof",
            b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\nxyz",
            true,
        ),
    ];
    for (name, wire, want) in cases {
        assert_eq!(response_allows_reuse(wire), *want, "{name}");
    }
}

// -------------------------------------------------------------- requests

fn req(wire: &[u8], step: usize) -> Vec<u8> {
    read_request(&mut Script::new(wire, step)).unwrap()
}

#[test]
fn request_reader_reads_exactly_the_framed_body_for_every_read_size() {
    let cases: [(&str, &[u8]); 4] = [
        ("length", b"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello"),
        ("chunked", b"POST /p HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"),
        ("none", b"GET /p HTTP/1.1\r\nHost: a\r\n\r\n"),
        ("zero length", b"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n"),
    ];
    for (name, wire) in cases {
        for step in [1, 4, 16_384] {
            assert_eq!(req(wire, step), wire, "{name} step {step}");
            assert!(
                matches!(scan_request_head(wire), S::Framed { .. }),
                "{name}: strict agrees"
            );
        }
    }
}

#[test]
fn single_shot_read_request_returns_exactly_one_message() {
    // Behaviour change (was: the whole first read came back as one request).
    // The single-shot wrapper now returns the framed message only; callers
    // that may see more bytes use `RequestReader` and keep the leftovers
    // (tests in request_reader_tests).
    let a = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
    let b = b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n";
    let mut wire = a.to_vec();
    wire.extend_from_slice(b);
    for step in [1, 3, 7, 16_384] {
        assert_eq!(req(&wire, step), a.to_vec(), "step {step}");
    }
    let S::Framed { head_len, .. } = scan_request_head(&wire) else {
        panic!()
    };
    assert_eq!(&wire[head_len + 3..], b);
}

#[test]
fn single_shot_chunked_request_stops_at_the_last_chunk() {
    let a = b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
    let b = b"GET /b HTTP/1.1\r\n\r\n";
    let mut wire = a.to_vec();
    wire.extend_from_slice(b);
    for step in [1, 3, 7, 16_384] {
        assert_eq!(req(&wire, step), a.to_vec(), "step {step}");
    }
}

#[test]
fn request_smuggling_shapes_tolerant_read_versus_strict_verdict() {
    // (name, wire, bytes the tolerant reader returns at step 1, strict verdict)
    let te_cl: &[u8] =
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n";
    // TE wins in the reader, so the reader stops after the chunked body and
    // leaves the next request unread: no desync on the proxy side, but the
    // head is forwarded with BOTH headers unless stripped. DIVERGES.
    let got = req(te_cl, 1);
    assert!(
        got.ends_with(b"0\r\n\r\n"),
        "{:?}",
        String::from_utf8_lossy(&got)
    );
    assert_eq!(scan_request_head(te_cl), S::Rejected(E::AmbiguousFraming));

    // Space before the colon: the reader does not see a Content-Length at
    // all, so it forwards the head and NEVER reads the 5-byte body, while a
    // peer that tolerates the space would. DIVERGES (real smuggling shape).
    let sp: &[u8] = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length : 5\r\n\r\nhello";
    let got = req(sp, 1);
    assert_eq!(
        got,
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length : 5\r\n\r\n".to_vec()
    );
    assert_eq!(scan_request_head(sp), S::Rejected(E::SpaceBeforeColon));

    // Duplicate conflicting Content-Length: the reader follows the first.
    let dup: &[u8] =
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nContent-Length: 9\r\n\r\nhi";
    assert_eq!(req(dup, 1), dup.to_vec());
    assert_eq!(scan_request_head(dup), S::Rejected(E::BadContentLength));
}

#[test]
fn connect_head_and_tunnel_bytes_are_not_framed_as_a_body() {
    let head = b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n";
    let mut wire = head.to_vec();
    wire.extend_from_slice(b"\x16\x03\x01\x00\x05hello");
    // Behaviour change: every read size returns exactly the CONNECT head.
    // The coalesced tunnel bytes stay in the reader (request_reader_tests).
    for step in [1, 3, 7, 16_384] {
        assert_eq!(req(&wire, step), head.to_vec(), "step {step}");
    }
    assert!(matches!(
        scan_request_head(&wire),
        S::Framed { head_len, body: crate::strict_request::RequestBody::None } if head_len == head.len()
    ));
}

#[test]
fn http10_and_close_requests_do_not_change_framing() {
    let w = b"POST /p HTTP/1.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi";
    assert_eq!(req(w, 3), w.to_vec());
    assert!(matches!(scan_request_head(w), S::Framed { .. }));
}
