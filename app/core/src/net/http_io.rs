// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

pub fn head_end(bytes: &[u8]) -> Option<usize> {
    util::find_head_end(bytes)
}

pub fn content_length(head: &[u8]) -> Option<usize> {
    let s = String::from_utf8_lossy(head);
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            if let Some(v) = line.split(':').nth(1) {
                return v.trim().parse::<usize>().ok();
            }
        }
    }
    None
}

pub fn read_request<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    let head_len;
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            head_len = None;
            break;
        }
        // Only the new bytes (plus the 3 before them, in case a terminator
        // straddles two reads) can hold a head end: rescanning the whole
        // buffer on every read made a header flood quadratic.
        let from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(h) = head_end(&buf[from..]) {
            head_len = Some(from + h);
            break;
        }
        if buf.len() > 4 * 1024 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
    }
    let head_len = match head_len {
        Some(h) => h,
        None => return Ok(buf),
    };
    let too_large =
        || std::io::Error::new(std::io::ErrorKind::InvalidData, "request body too large");
    // Transfer-Encoding wins over Content-Length (RFC 9112 §6.3). A chunked
    // upload is read to its last chunk; it used to be forwarded with only the
    // bytes of the first read.
    let head = String::from_utf8_lossy(&buf[..head_len]).to_ascii_lowercase();
    let chunked = head
        .lines()
        .any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"));
    if chunked {
        let mut cur = crate::codec::ChunkCursor::default();
        while crate::codec::scan_chunked(&buf[head_len..], &mut cur, |_| {})
            == crate::codec::Chunked::Partial
        {
            if buf.len() - head_len > crate::codec::MAX_BODY {
                return Err(too_large());
            }
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    } else if let Some(len) = content_length(&buf[..head_len]) {
        if len > crate::codec::MAX_BODY {
            return Err(too_large());
        }
        while buf.len() < head_len + len {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    }
    Ok(buf)
}

pub fn read_response_head<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1024);
    // Stop at the header boundary: reading ahead would steal the first WebSocket frame.
    let mut chunk = [0u8; 1];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if out.windows(4).any(|w| w == b"\r\n\r\n") || out.windows(2).any(|w| w == b"\n\n") {
            break;
        }
        if out.len() > 64 * 1024 {
            break;
        }
    }
    Ok(out)
}
