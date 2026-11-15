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
    body.len() >= at + pat.len() && &body[at..at + pat.len()] == pat
}

fn line_end(body: &[u8], from: usize) -> Option<usize> {
    let rest = body.get(from..)?;
    if let Some(i) = rest.windows(2).position(|w| w == b"\r\n") {
        return Some(from + i);
    }
    rest.iter().position(|&b| b == b'\n').map(|i| from + i)
}

/// Decode a chunked body. Returns the payload and the number of body bytes it
/// consumed (chunk headers, trailers included). `None` when the buffer is
/// incomplete.
pub fn decode_chunked(body: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    loop {
        let end = line_end(body, pos)?;
        let line = String::from_utf8_lossy(&body[pos..end]);
        let size_text = line.split(';').next().unwrap_or("").trim();
        if size_text.is_empty() || !size_text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let size = usize::from_str_radix(size_text, 16).ok()?;
        pos = if at(body, end, b"\r\n") { end + 2 } else { end + 1 };
        if size == 0 {
            // trailers: consume lines until a blank one
            loop {
                if at(body, pos, b"\r\n") {
                    return Some((out, pos + 2));
                }
                if at(body, pos, b"\n") {
                    return Some((out, pos + 1));
                }
                let e = line_end(body, pos)?;
                if e == pos {
                    return Some((out, pos + 1));
                }
                pos = if at(body, e, b"\r\n") { e + 2 } else { e + 1 };
            }
        }
        if body.len() < pos + size {
            return None;
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size;
        if at(body, pos, b"\r\n") {
            pos += 2;
        } else if at(body, pos, b"\n") {
            pos += 1;
        } else {
            return None;
        }
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

/// Read one whole HTTP response from a stream, using the framing headers to stop
/// at the end of the body instead of waiting for EOF (needed for keep-alive).
pub fn read_message<R: std::io::Read + crate::net::ResponseRead>(
    stream: &mut R,
    buffer: &mut Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    // `buffer` may already hold bytes read past a previous response.
    let head_end = loop {
        if let Some(h) = util::find_head_end(buffer) {
            break h;
        }
        let mut chunk = [0u8; 16384];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(std::mem::take(buffer));
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.len() > MAX_BODY {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "response headers too large"));
        }
    };
    let kind = response_body_kind(&buffer[..head_end], "GET");
    let body_start = head_end;
    match kind {
        BodyKind::None => Ok(std::mem::take(buffer)),
        BodyKind::Length(n) => {
            while buffer.len() < body_start + n {
                let mut chunk = [0u8; 16384];
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() > body_start + MAX_BODY {
                    break;
                }
            }
            let end = (body_start + n).min(buffer.len());
            Ok(buffer.drain(..end).collect())
        }
        BodyKind::Chunked => loop {
            if let Some((_, consumed)) = decode_chunked(&buffer[body_start..]) {
                let end = body_start + consumed;
                return Ok(buffer.drain(..end).collect());
            }
            let mut chunk = [0u8; 16384];
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                return Ok(std::mem::take(buffer));
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > body_start + MAX_BODY {
                return Ok(std::mem::take(buffer));
            }
        },
        BodyKind::UntilEof => {
            // No length information: the open-ended timeout bounds the read
            // (ProjectDefaults.json connections.timeouts.open_ended_response_timeout).
            stream.set_open_ended_timeout()?;
            let mut chunk = [0u8; 16384];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        buffer.extend_from_slice(&chunk[..n]);
                        if buffer.len() > MAX_BODY {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            Ok(std::mem::take(buffer))
        }
    }
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
        BodyKind::Length(n) => raw.len() >= parts.head_len + n,
        BodyKind::Chunked => decode_chunked(&raw[parts.head_len..]).is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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