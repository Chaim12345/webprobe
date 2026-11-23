//! Local host-probe response assessment. This does not change proxy codecs.
use crate::codec::{self, BodyKind, ChunkCursor, Chunked};
const HEAD_LIMIT: usize = 64 * 1024;
const INTERIM_LIMIT: usize = 8;
pub(super) struct Assessed<'a> {
    pub status: u16,
    pub body: std::borrow::Cow<'a, [u8]>,
    pub complete: bool,
    pub content_type: String,
}
fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}
fn head_status(head: &[u8]) -> Option<u16> {
    if !head.ends_with(b"\r\n\r\n") || head.len() > HEAD_LIMIT {
        return None;
    }
    for (i, b) in head.iter().enumerate() {
        if (*b == b'\n' && (i == 0 || head[i - 1] != b'\r'))
            || (*b == b'\r' && head.get(i + 1) != Some(&b'\n'))
        {
            return None;
        }
    }
    let mut lines = head[..head.len() - 2].split(|b| *b == b'\n');
    let status = lines.next()?.strip_suffix(b"\r")?;
    if status.len() < 13
        || ![b"HTTP/1.0 ".as_slice(), b"HTTP/1.1 ".as_slice()]
            .iter()
            .any(|p| status.starts_with(p))
        || status[12] != b' '
        || !status[9..12].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    if status[13..]
        .iter()
        .any(|b| *b < 32 && *b != b'\t' || *b == 127)
    {
        return None;
    }
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let line = line.strip_suffix(b"\r")?;
        if line.is_empty() {
            continue;
        }
        let colon = line.iter().position(|b| *b == b':')?;
        if colon == 0
            || !line[..colon].iter().copied().all(token)
            || line[colon + 1..]
                .iter()
                .any(|b| (*b < 32 && *b != b'\t') || *b == 127)
        {
            return None;
        }
    }
    std::str::from_utf8(&status[9..12]).ok()?.parse().ok()
}
// Reject tolerant LF chunk framing before reusing the shared decoder.
// Partial framing is allowed only as incomplete evidence, never complete.
fn strict_chunk_prefix(body: &[u8]) -> (usize, bool) {
    let mut at = 0usize;
    let mut safe = 0usize;
    let mut trailers = false;
    loop {
        let rest = &body[at..];
        let Some(lf) = rest.iter().position(|b| *b == b'\n') else {
            return (safe, false);
        };
        if lf == 0 || rest[lf - 1] != b'\r' {
            return (safe, false);
        }
        let line = &rest[..lf - 1];
        if line.iter().any(|b| (*b < 32 && *b != b'\t') || *b == 127) {
            return (safe, false);
        }
        at += lf + 1;
        if trailers {
            if line.is_empty() {
                return (at, at == body.len());
            }
            let Some(colon) = line.iter().position(|b| *b == b':') else {
                return (safe, false);
            };
            if colon == 0 || !line[..colon].iter().copied().all(token) {
                return (safe, false);
            }
            continue;
        }
        let size = line.split(|b| *b == b';').next().unwrap_or_default();
        if size.is_empty() || size.len() > 16 || !size.iter().all(u8::is_ascii_hexdigit) {
            return (safe, false);
        }
        let Ok(n) = usize::from_str_radix(std::str::from_utf8(size).unwrap_or("x"), 16) else {
            return (safe, false);
        };
        if n == 0 {
            trailers = true;
            continue;
        }
        let Some(stop) = at.checked_add(n) else {
            return (safe, false);
        };
        if body.get(stop..stop.saturating_add(2)) != Some(b"\r\n") {
            return (safe, false);
        }
        at = stop + 2;
        safe = at;
    }
}
// The local assessor only interprets identity content and a single chunked
// transfer coding. Unsupported encodings are unknown, never plain signatures.
fn supported_framing(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head);
    let mut lengths = Vec::new();
    let mut transfers = Vec::new();
    for line in text.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("Content-Encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
        {
            return false;
        }
        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            transfers.push(value.trim());
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            for n in value.split(',').map(str::trim) {
                if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                    return false;
                }
                let Ok(n) = n.parse::<usize>() else {
                    return false;
                };
                lengths.push(n);
            }
        }
    }
    if lengths
        .first()
        .is_some_and(|n| lengths.iter().any(|v| v != n))
    {
        return false;
    }
    transfers.is_empty()
        || (lengths.is_empty()
            && transfers.len() == 1
            && transfers[0].eq_ignore_ascii_case("chunked"))
}
pub(super) fn assess<'a>(raw: &'a [u8], method: &str) -> Option<Assessed<'a>> {
    if raw.len() > codec::MAX_BODY {
        return None;
    }
    let mut offset = 0usize;
    for _ in 0..=INTERIM_LIMIT {
        let bytes = raw.get(offset..)?;
        let end = bytes[..bytes.len().min(HEAD_LIMIT)]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")?
            + 4;
        offset = offset.checked_add(end)?;
        if offset > HEAD_LIMIT {
            return None;
        }
        let head = &bytes[..end];
        let status = head_status(head)?;
        if !supported_framing(head) {
            return None;
        }
        let kind = codec::response_body_kind_strict(head, method).ok()?;
        if (100..200).contains(&status) {
            if status == 101 {
                return None;
            }
            continue;
        }
        if !(200..600).contains(&status) {
            return None;
        }
        let body = &bytes[end..];
        let (decoded, complete) = match kind {
            BodyKind::Length(n) => (
                std::borrow::Cow::Borrowed(&body[..body.len().min(n)]),
                body.len() == n,
            ),
            BodyKind::None => (std::borrow::Cow::Borrowed(&b""[..]), body.is_empty()),
            BodyKind::UntilEof => (std::borrow::Cow::Borrowed(body), false),
            BodyKind::Chunked => {
                let (safe, strict_complete) = strict_chunk_prefix(body);
                let mut decoded = Vec::new();
                let state = codec::scan_chunked(&body[..safe], &mut ChunkCursor::default(), |b| {
                    decoded.extend_from_slice(b)
                });
                if state == Chunked::Malformed || (decoded.is_empty() && !strict_complete) {
                    return None;
                }
                (
                    std::borrow::Cow::Owned(decoded),
                    strict_complete && matches!(state, Chunked::Complete(n) if n == body.len()),
                )
            }
        };
        // The network cap is the allocation bound; never copy more than it.
        if decoded.len() > codec::MAX_BODY {
            return None;
        }
        let parsed = crate::util::parse_http(head);
        return Some(Assessed {
            status,
            body: decoded,
            complete,
            content_type: crate::util::get_header(&parsed.headers, "Content-Type")
                .unwrap_or_default(),
        });
    }
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_head_and_decoded_body_are_distinct_from_incomplete() {
        for bad in [
            b"".as_slice(),
            b"HTTP/1.1 200 OK\r\nX: x",
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 101 Switch\r\n\r\n",
            b"JUNK 200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad : x\r\n\r\n",
        ] {
            assert!(assess(bad, "GET").is_none(), "{bad:?}");
        }
        let a = assess(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            "GET",
        )
        .unwrap();
        assert!(a.complete);
        assert_eq!(&*a.body, b"ok");
        assert!(
            !assess(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok", "GET")
                .unwrap()
                .complete
        );
        assert!(
            !assess(b"HTTP/1.1 200 OK\r\n\r\nok", "GET")
                .unwrap()
                .complete
        );
        let a=assess(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;digest=evil\r\nok\r\n0\r\nX: marker\r\n\r\n","GET").unwrap();
        assert!(a.complete);
        assert_eq!(&*a.body, b"ok");
    }
}

#[cfg(test)]
mod hostile_tests {
    use super::*;
    #[test]
    fn malformed_framing_never_becomes_a_complete_negative_or_signature() {
        for raw in [
            b"HTTP/1.1 200 OK\nX: x\n\n".as_slice(),
            b"HTTP/1.1 200 OK\r\n folded: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: a\x00b\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\nok\n0\n\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n",
        ] {
            assert!(assess(raw, "GET").is_none(), "{raw:?}");
        }
        for raw in [
            b"HTTP/1.1 204 No Content\r\nContent-Length: nope\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nok",
        ] {
            assert!(assess(raw, "GET").is_none());
        }
        let malformed_tail=assess(b"HTTP/1.1 500 Error\r\nTransfer-Encoding: chunked\r\n\r\nf\r\nE{\"digest\":\"x\"}\r\nnope\r\n", "POST").unwrap();
        assert!(!malformed_tail.complete);
        assert_eq!(&*malformed_tail.body, b"E{\"digest\":\"x\"}");
        let too_many = [
            b"HTTP/1.1 100 Continue\r\n\r\n".repeat(9),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ]
        .concat();
        assert!(assess(&too_many, "GET").is_none());
        let too_big = [
            b"HTTP/1.1 200 OK\r\nX: ".to_vec(),
            vec![b'a'; HEAD_LIMIT],
            b"\r\n\r\n".to_vec(),
        ]
        .concat();
        assert!(assess(&too_big, "GET").is_none());
        let prefix = assess(
            b"HTTP/1.1 500 Error\r\nContent-Length: 99\r\n\r\nE{\"digest\":\"x\"}",
            "POST",
        )
        .unwrap();
        assert!(!prefix.complete);
        assert!(super::super::react2shell_hit(
            "500",
            &String::from_utf8_lossy(&prefix.body)
        ));
    }
}
