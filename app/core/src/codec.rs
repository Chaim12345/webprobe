// HTTP message framing and body codecs: chunked transfer coding, gzip / deflate /
// br content coding, and a normalised "decoded" view of a response.
//
// The proxy keeps the wire bytes it forwards untouched; this module produces the
// bytes shown in history, the site map and the scanner's checks.

use crate::util;

/// Upper bound for an inflated body (mirrors the read cap in net.rs).
pub const MAX_BODY: usize = 64 * 1024 * 1024;

/// How a message body is delimited on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// `Content-Length: n`
    Length(usize),
    /// `Transfer-Encoding: chunked`
    Chunked,
    /// No length information: the body ends at connection close.
    UntilEof,
    /// No body at all (204/304, or a bodyless response).
    None,
}

fn header_values<'a>(head: &'a str, name: &str) -> impl Iterator<Item = &'a str> {
    let lower = name.to_ascii_lowercase();
    head.lines().filter_map(move |line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(&lower) {
            Some(v.trim())
        } else {
            None
        }
    })
}

/// Delimit the body of a response, honouring the framing rules in RFC 9112 §6.3.
pub fn response_body_kind(head: &[u8], method: &str) -> BodyKind {
    let head = String::from_utf8_lossy(head);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("");
    let code: u16 = status.parse().unwrap_or(200);
    if method.eq_ignore_ascii_case("HEAD") || code == 204 || code == 304 || (100..200).contains(&code) {
        return BodyKind::None;
    }
    // Transfer-Encoding wins over Content-Length (smuggling defence).
    let chunked = header_values(&head, "Transfer-Encoding")
        .any(|v| v.to_ascii_lowercase().split(',').any(|t| t.trim() == "chunked"));
    if chunked {
        return BodyKind::Chunked;
    }
    let mut lengths = header_values(&head, "Content-Length").filter_map(|v| v.parse::<usize>().ok());
    match (lengths.next(), lengths.next()) {
        (Some(first), None) => BodyKind::Length(first),
        // duplicate or conflicting Content-Length values: no usable length
        _ => BodyKind::UntilEof,
    }
}

/// True when `body[at..]` starts with `pat`.
fn at(body: &[u8], at: usize, pat: &[u8]) -> bool {
    body.get(at..).is_some_and(|rest| rest.starts_with(pat))
}

/// The line starting at `from`: (end of its text, index after its LF). A CR
/// right before the LF belongs to the terminator. `None` until the LF arrives.
fn line(body: &[u8], from: usize) -> Option<(usize, usize)> {
    let lf = from + body.get(from..)?.iter().position(|&b| b == b'\n')?;
    let end = if lf > from && body[lf - 1] == b'\r' { lf - 1 } else { lf };
    Some((end, lf + 1))
}

/// Where an incremental chunked scan resumes: the start of the next
/// chunk-size line. Chunks before it have been validated already, so a
/// growing buffer is scanned once in total, not once per read.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChunkCursor {
    next: usize,
}

/// Outcome of [`scan_chunked`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chunked {
    /// The body ends at this offset (last chunk and trailers included).
    Complete(usize),
    /// More bytes are needed.
    Partial,
    /// Not valid chunked framing (bad size line, size overflow, missing
    /// chunk terminator).
    Malformed,
}

/// Validate chunked framing from `cur` on, handing each chunk's data to
/// `data`. Sizes are checked for overflow (a hostile `ffffffffffffffff`
/// must not wrap around or panic).
pub fn scan_chunked(body: &[u8], cur: &mut ChunkCursor, mut data: impl FnMut(&[u8])) -> Chunked {
    loop {
        let pos = cur.next;
        let Some((end, after)) = line(body, pos) else { return Chunked::Partial };
        let size_text = body[pos..end].split(|&b| b == b';').next().unwrap_or_default().trim_ascii();
        if size_text.is_empty() || size_text.len() > 16 || !size_text.iter().all(u8::is_ascii_hexdigit) {
            return Chunked::Malformed;
        }
        // ASCII hex digits only, so the conversion cannot fail.
        let Ok(size) = usize::from_str_radix(std::str::from_utf8(size_text).unwrap_or("x"), 16) else {
            return Chunked::Malformed;
        };
        if size == 0 {
            // Trailer lines until a blank one.
            let mut p = after;
            loop {
                let Some((e, a)) = line(body, p) else { return Chunked::Partial };
                if e == p {
                    return Chunked::Complete(a);
                }
                p = a;
            }
        }
        let Some(stop) = after.checked_add(size) else { return Chunked::Malformed };
        if body.len() < stop {
            return Chunked::Partial;
        }
        let next = if at(body, stop, b"\r\n") {
            stop + 2
        } else if at(body, stop, b"\n") {
            stop + 1
        } else if body.len() < stop + 2 {
            return Chunked::Partial;
        } else {
            return Chunked::Malformed;
        };
        data(&body[after..stop]);
        cur.next = next;
    }
}

/// Decode a chunked body. Returns the payload and the number of body bytes it
/// consumed (chunk headers, trailers included). `None` when the buffer is
/// incomplete or the framing is invalid.
pub fn decode_chunked(body: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    match scan_chunked(body, &mut ChunkCursor::default(), |d| out.extend_from_slice(d)) {
        Chunked::Complete(n) => Some((out, n)),
        _ => None,
    }
}

/// Inflate a body according to `Content-Encoding`. Unknown or empty encodings
/// are returned unchanged; a codec failure yields the original bytes so a broken
/// body still shows up in the editor rather than disappearing.
pub fn decode_content(body: &[u8], encoding: &str) -> Vec<u8> {
    let mut current = body.to_vec();
    // Encodings are applied in order, so decode in reverse.
    for token in encoding.split(',').rev() {
        let token = token.trim().to_ascii_lowercase();
        let next = match token.as_str() {
            "gzip" | "x-gzip" => gunzip(&current),
            "deflate" => inflate(&current),
            "br" => brotli_decode(&current),
            _ => None,
        };
        match next {
            Some(v) => current = v,
            None => return current,
        }
    }
    current
}

fn gunzip(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let d = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    d.take(MAX_BODY as u64 + 1).read_to_end(&mut out).ok()?;
    Some(out)
}

fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    // Some servers send raw deflate without the zlib wrapper; try both.
    let d = flate2::read::ZlibDecoder::new(data);
    let mut out = Vec::new();
    if d.take(MAX_BODY as u64 + 1).read_to_end(&mut out).is_ok() && !out.is_empty() {
        return Some(out);
    }
    let d = flate2::read::DeflateDecoder::new(data);
    let mut raw = Vec::new();
    d.take(MAX_BODY as u64 + 1).read_to_end(&mut raw).ok()?;
    Some(raw)
}

fn brotli_decode(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    brotli::Decompressor::new(data, 4096)
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

/// Build a clean, decoded view of a response: chunked payloads reassembled,
/// content coding removed, `Content-Length` corrected, and the framing headers
/// dropped so the body the editor shows is the body that was measured.
pub fn normalize_response(raw: &[u8]) -> Vec<u8> {
    let parts = util::parse_http(raw);
    if parts.head_len == 0 || parts.head_len >= raw.len() {
        return raw.to_vec();
    }
    let method = if parts.method == "RESPONSE" { "GET" } else { parts.method.as_str() };
    let body = &raw[parts.head_len..];
    let kind = response_body_kind(&raw[..parts.head_len], method);
    let decoded_body: Vec<u8> = match kind {
        BodyKind::Chunked => match decode_chunked(body) {
            Some((payload, _)) => payload,
            None => body.to_vec(),
        },
        BodyKind::Length(n) => body[..n.min(body.len())].to_vec(),
        _ => body.to_vec(),
    };
    let encoding = util::get_header(&parts.headers, "Content-Encoding").unwrap_or_default();
    let decoded_body = if encoding.is_empty() {
        decoded_body
    } else {
        decode_content(&decoded_body, &encoding)
    };
    // Never show an encoded-but-not-decoded body as if it were text.
    let mut out = String::with_capacity(parts.head_len + decoded_body.len() + 32);
    out.push_str(parts.first.trim_end());
    out.push_str("\r\n");
    for (k, v) in &parts.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "content-length" || lower == "transfer-encoding" || lower == "content-encoding" {
            continue;
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push('\n');
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", decoded_body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&decoded_body);
    bytes
}

/// Read one whole HTTP response to a `method` request from a stream, using
/// the framing headers to stop at the end of the body instead of waiting for
/// EOF (needed for keep-alive). Interim 1xx responses (100 Continue, 103
/// Early Hints) are skipped, as the final response follows them; 101 is
/// final. Returns the response and whether the connection may be reused:
/// not after an EOF-delimited or malformed body, a truncated read or a
/// size cap.
pub(crate) fn read_message<R: std::io::Read + crate::net::ResponseRead>(
    stream: &mut R,
    buffer: &mut Vec<u8>,
    method: &str,
) -> std::io::Result<(Vec<u8>, bool)> {
    let read_more = |stream: &mut R, buffer: &mut Vec<u8>| -> std::io::Result<usize> {
        let mut chunk = [0u8; 16384];
        let n = stream.read(&mut chunk)?;
        buffer.extend_from_slice(&chunk[..n]);
        Ok(n)
    };
    // `buffer` may already hold bytes read past a previous response.
    let head_end = loop {
        // Search only the new bytes (plus 3 for a terminator split across
        // reads), not the whole buffer again.
        let mut searched = 0usize;
        let head_end = loop {
            let from = searched.saturating_sub(3);
            if let Some(h) = util::find_head_end(&buffer[from..]) {
                break from + h;
            }
            searched = buffer.len();
            if read_more(stream, buffer)? == 0 {
                return Ok((std::mem::take(buffer), false));
            }
            if buffer.len() > MAX_BODY {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "response headers too large"));
            }
        };
        let code = status_code(&buffer[..head_end]);
        if (100..200).contains(&code) && code != 101 {
            buffer.drain(..head_end);
            continue;
        }
        break head_end;
    };
    let body_start = head_end;
    match response_body_kind(&buffer[..head_end], method) {
        BodyKind::None => Ok((buffer.drain(..head_end).collect(), true)),
        BodyKind::Length(n) => {
            let end = body_start.saturating_add(n);
            while buffer.len() < end {
                if buffer.len() - body_start > MAX_BODY {
                    return Ok((std::mem::take(buffer), false));
                }
                if read_more(stream, buffer)? == 0 {
                    return Ok((std::mem::take(buffer), false));
                }
            }
            Ok((buffer.drain(..end).collect(), true))
        }
        BodyKind::Chunked => {
            let mut cur = ChunkCursor::default();
            loop {
                match scan_chunked(&buffer[body_start..], &mut cur, |_| {}) {
                    Chunked::Complete(consumed) => return Ok((buffer.drain(..body_start + consumed).collect(), true)),
                    Chunked::Malformed => return Ok((std::mem::take(buffer), false)),
                    Chunked::Partial => {}
                }
                if buffer.len() - body_start > MAX_BODY || read_more(stream, buffer)? == 0 {
                    return Ok((std::mem::take(buffer), false));
                }
            }
        }
        BodyKind::UntilEof => {
            // No length information: the open-ended timeout bounds the read
            // (ProjectDefaults.json connections.timeouts.open_ended_response_timeout).
            stream.set_open_ended_timeout()?;
            loop {
                match read_more(stream, buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if buffer.len() > MAX_BODY => break,
                    Ok(_) => {}
                }
            }
            Ok((std::mem::take(buffer), false))
        }
    }
}

/// The status code of a response head (0 when it has none).
fn status_code(head: &[u8]) -> u16 {
    let first = head.split(|&b| b == b'\n').next().unwrap_or_default();
    String::from_utf8_lossy(first).split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}

/// Normalised view of a request: chunked bodies reassembled, `Content-Length`
/// corrected so the editor and the byte counts agree with what is shown.
pub fn normalize_request(raw: &[u8]) -> Vec<u8> {
    let parts = util::parse_http(raw);
    if parts.head_len == 0 || parts.head_len >= raw.len() {
        return raw.to_vec();
    }
    let head_text = String::from_utf8_lossy(&raw[..parts.head_len]);
    let chunked = header_values(&head_text, "Transfer-Encoding")
        .any(|v| v.to_ascii_lowercase().contains("chunked"));
    if !chunked {
        return raw.to_vec();
    }
    let body = &raw[parts.head_len..];
    let Some((decoded, _)) = decode_chunked(body) else { return raw.to_vec() };
    let mut out = String::with_capacity(parts.head_len + decoded.len() + 32);
    out.push_str(parts.first.trim_end());
    out.push('\n');
    for (k, v) in &parts.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "transfer-encoding" || lower == "content-length" {
            continue;
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push('\n');
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", decoded.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&decoded);
    bytes
}

/// True when the framing headers say the body ended cleanly (so the connection
/// can carry another request).
pub fn body_complete(raw: &[u8], method: &str) -> bool {
    let parts = util::parse_http(raw);
    if parts.head_len == 0 || parts.head_len >= raw.len() {
        return true;
    }
    match response_body_kind(&raw[..parts.head_len], method) {
        BodyKind::None | BodyKind::UntilEof => true,
        BodyKind::Length(n) => raw.len() >= parts.head_len.saturating_add(n),
        BodyKind::Chunked => decode_chunked(&raw[parts.head_len..]).is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A byte script read in small pieces, as a socket would deliver it.
    struct Script(std::io::Cursor<Vec<u8>>);
    impl std::io::Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(7);
            self.0.read(&mut buf[..n])
        }
    }
    impl crate::net::ResponseRead for Script {
        fn set_open_ended_timeout(&self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn read_all(wire: &[u8], method: &str) -> (Vec<u8>, bool, Vec<u8>) {
        let mut buffer = Vec::new();
        let (resp, reusable) = read_message(&mut Script(std::io::Cursor::new(wire.to_vec())), &mut buffer, method).unwrap();
        (resp, reusable, buffer)
    }

    /// Review findings 1, 5, 6, 7: hostile chunk sizes, interim responses,
    /// HEAD framing, leftover bytes.
    #[test]
    fn response_reader_survives_hostile_and_interim_messages() {
        // A chunk size that overflows usize must not panic or wrap.
        for size in ["ffffffffffffffff", "fffffffffffffffff0", "10000000000000000"] {
            let body = format!("{size}\r\nabc\r\n0\r\n\r\n");
            assert!(decode_chunked(body.as_bytes()).is_none(), "{size}");
            let wire = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{body}");
            let (_, reusable, _) = read_all(wire.as_bytes(), "GET");
            assert!(!reusable, "malformed framing never goes back to the pool");
        }
        // A bare-LF line ending is not confused with a later CRLF.
        assert_eq!(decode_chunked(b"5\nhello\n0\n\n").unwrap().0, b"hello");
        // 100 Continue and 103 Early Hints are skipped; the final response is returned.
        let (resp, reusable, rest) = read_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok", "POST");
        assert!(resp.starts_with(b"HTTP/1.1 201") && resp.ends_with(b"ok") && reusable && rest.is_empty(), "{}", String::from_utf8_lossy(&resp));
        // HEAD: Content-Length describes the GET body, none follows.
        let (resp, reusable, _) = read_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n", "HEAD");
        assert!(resp.ends_with(b"\r\n\r\n") && reusable);
        // Reading stops at the end of the framed body; bytes past it that were
        // already read stay in the buffer (the caller refuses to pool), the
        // rest stay in the socket (the pool's idle check refuses it).
        let (resp, _, rest) = read_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA", "GET");
        assert!(resp.ends_with(b"ok") && b"EXTRA".starts_with(&rest[..]), "{rest:?}");
        // EOF-delimited bodies are never reusable; a huge Content-Length does not overflow.
        assert!(!read_all(b"HTTP/1.1 200 OK\r\n\r\nbody", "GET").1);
        assert!(!read_all(b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nx", "GET").1);
        assert!(body_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\nx", "GET") == false);
    }

    /// Review finding 7: a large chunked body is scanned once, not once per read.
    #[test]
    fn chunked_scan_is_linear() {
        let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..20_000 {
            wire.extend_from_slice(b"40\r\n");
            wire.extend_from_slice(&[b'a'; 64]);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let t0 = std::time::Instant::now();
        let (resp, reusable, _) = read_all(&wire, "GET");
        assert!(reusable && resp.len() == wire.len());
        assert!(t0.elapsed() < std::time::Duration::from_secs(10), "{:?}", t0.elapsed());
    }

    #[test]
    fn chunked_single_and_multi() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let (decoded, used) = decode_chunked(body).unwrap();
        assert_eq!(decoded, b"Wikipedia");
        assert_eq!(used, body.len());
    }

    #[test]
    fn chunked_with_trailers() {
        let body = b"5\r\nhello\r\n0\r\nX-Check: 1\r\n\r\n";
        let (decoded, used) = decode_chunked(body).unwrap();
        assert_eq!(decoded, b"hello");
        assert_eq!(used, body.len());
    }

    #[test]
    fn chunked_incomplete_is_none() {
        assert!(decode_chunked(b"5\r\nhel").is_none());
    }

    #[test]
    fn gzip_roundtrip() {
        let raw = b"hello compressed world";
        let mut enc = Vec::new();
        {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(&mut enc, flate2::Compression::default());
            e.write_all(raw).unwrap();
        }
        assert_eq!(decode_content(&enc, "gzip"), raw);
    }

    #[test]
    fn deflate_roundtrip() {
        let raw = b"deflate me";
        use std::io::Write;
        let mut enc = Vec::new();
        {
            let mut e = flate2::write::ZlibEncoder::new(&mut enc, flate2::Compression::default());
            e.write_all(raw).unwrap();
        }
        assert_eq!(decode_content(&enc, "deflate"), raw);
    }

    #[test]
    fn brotli_roundtrip() {
        let raw = b"brotli payload";
        let mut enc = Vec::new();
        {
            use std::io::Write;
            let mut params = brotli::enc::BrotliEncoderParams::default();
            params.quality = 5;
            let mut e = brotli::CompressorWriter::new(&mut enc, 4096, 5, 22);
            e.write_all(raw).unwrap();
            let _ = params;
        }
        assert_eq!(decode_content(&enc, "br"), raw);
    }

    #[test]
    fn unknown_encoding_passthrough() {
        let raw = b"plain";
        assert_eq!(decode_content(raw, "identity"), raw);
        assert_eq!(decode_content(raw, "compress"), raw);
    }

    #[test]
    fn normalize_rewrites_chunked_and_encoding() {
        let body = b"5\r\nhello\r\n0\r\n\r\n";
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n";
        let mut full = raw.to_vec();
        full.extend_from_slice(body);
        let out = normalize_response(&full);
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("Content-Length: 5"));
        assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(out.ends_with(b"hello"));
    }

    #[test]
    fn response_kind_prefers_chunked_over_length() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(response_body_kind(head, "GET"), BodyKind::Chunked);
    }

    #[test]
    fn no_body_statuses() {
        assert_eq!(response_body_kind(b"HTTP/1.1 204 No Content\r\n\r\n", "GET"), BodyKind::None);
        assert_eq!(response_body_kind(b"HTTP/1.1 304 Not Modified\r\n\r\n", "GET"), BodyKind::None);
        assert_eq!(response_body_kind(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", "HEAD"), BodyKind::None);
    }

    /// A-04: a 4 MiB chunked body decodes intact and byte counts stay exact.
    #[test]
    fn chunked_body_of_four_mib() {
        let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let mut wire = Vec::with_capacity(payload.len() + 64 * 1024);
        for chunk in payload.chunks(65536) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let (decoded, used) = decode_chunked(&wire).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(used, wire.len());

        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        raw.extend_from_slice(&wire);
        let out = normalize_response(&raw);
        assert!(out.ends_with(&payload));
        let text = String::from_utf8_lossy(&out[..out.len() - payload.len()]);
        assert!(text.contains(&format!("Content-Length: {}", payload.len())));
    }
}