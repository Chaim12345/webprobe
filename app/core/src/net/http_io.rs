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

/// A client connection's request reader. It owns the bytes read past the
/// message it returned (a pipelined request, or the first bytes of a CONNECT
/// tunnel or WebSocket) in a buffer that lives as long as the connection:
/// `read_next` hands out exactly one framed message, never the whole read,
/// and never drops what follows. Whoever takes over the connection after a
/// successful transition (tunnel owner, WebSocket relay) takes the leftovers
/// with [`RequestReader::take_leftovers`].
///
/// Framing is the proxy's tolerant request framing, unchanged: Transfer-
/// Encoding chunked wins over Content-Length, the first Content-Length is
/// used, no framing means no body. Strict rejection is a separate step.
#[derive(Default, Debug)]
pub struct RequestReader {
    buf: Vec<u8>,
    guard: bool,
}

impl RequestReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// A reader for the normal forwarding boundary: a head that
    /// `strict_request::inbound_ambiguity` refuses comes back as
    /// `ReadOutcome::Ambiguous` as soon as the head is complete, before any
    /// body is waited for or framed.
    pub fn guarded() -> Self {
        RequestReader {
            guard: true,
            ..Self::default()
        }
    }

    /// Bytes read from the client but not yet part of a returned message.
    pub fn leftovers(&self) -> &[u8] {
        &self.buf
    }

    /// Hand the owned leftovers to whoever takes the connection over.
    pub fn take_leftovers(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// The next framed request: its head and its body, exactly. Empty when
    /// the client closed with nothing buffered. An unfinished message at EOF
    /// (or a malformed chunked body) comes back as everything buffered, as
    /// before, so the caller sees what the client sent.
    pub fn read_next<R: Read>(&mut self, stream: &mut R) -> std::io::Result<Vec<u8>> {
        Ok(match self.read_message(stream)? {
            ReadOutcome::Message(m)
            | ReadOutcome::Incomplete(m)
            | ReadOutcome::Malformed(m)
            | ReadOutcome::Ambiguous(_, m) => m,
            ReadOutcome::Eof => Vec::new(),
        })
    }

    /// Drop leftovers that are only CR, LF or space (a harmless trailing
    /// CRLF after a body). Returns true when anything was dropped.
    pub fn discard_blank_leftovers(&mut self) -> bool {
        if !self.buf.is_empty() && self.buf.iter().all(|b| matches!(b, b'\r' | b'\n' | b' ')) {
            self.buf.clear();
            return true;
        }
        false
    }

    /// The next request as a typed outcome. Only `Message` is a request to
    /// forward; `Incomplete` (EOF inside a message) and `Malformed` (bad
    /// chunked body) carry the captured bytes for history and nothing else.
    pub fn read_message<R: Read>(&mut self, stream: &mut R) -> std::io::Result<ReadOutcome> {
        let mut chunk = [0u8; 8192];
        let mut scanned = 0usize;
        let head_len = loop {
            // Only new bytes (plus 3 before them, for a terminator split
            // across reads) can hold a head end.
            let from = scanned.saturating_sub(3);
            if let Some(h) = head_end(&self.buf[from..]) {
                break Some(from + h);
            }
            scanned = self.buf.len();
            if self.buf.len() > 4 * 1024 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request too large",
                ));
            }
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break None;
            }
            self.buf.extend_from_slice(&chunk[..n]);
        };
        let Some(head_len) = head_len else {
            return Ok(if self.buf.is_empty() {
                ReadOutcome::Eof
            } else {
                ReadOutcome::Incomplete(self.take_leftovers())
            });
        };
        if self.guard {
            if let Some(why) = crate::strict_request::inbound_ambiguity(&self.buf[..head_len]) {
                return Ok(ReadOutcome::Ambiguous(why, self.take_leftovers()));
            }
        }
        let too_large =
            || std::io::Error::new(std::io::ErrorKind::InvalidData, "request body too large");
        // Transfer-Encoding wins over Content-Length (RFC 9112 §6.3).
        let head = String::from_utf8_lossy(&self.buf[..head_len]).to_ascii_lowercase();
        let chunked = head
            .lines()
            .any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"));
        let end = if chunked {
            let mut cur = crate::codec::ChunkCursor::default();
            loop {
                match crate::codec::scan_chunked(&self.buf[head_len..], &mut cur, |_| {}) {
                    crate::codec::Chunked::Complete(n) => break head_len + n,
                    crate::codec::Chunked::Malformed => {
                        return Ok(ReadOutcome::Malformed(self.take_leftovers()))
                    }
                    crate::codec::Chunked::Partial => {}
                }
                if self.buf.len() - head_len > crate::codec::MAX_BODY {
                    return Err(too_large());
                }
                let n = stream.read(&mut chunk)?;
                if n == 0 {
                    return Ok(ReadOutcome::Incomplete(self.take_leftovers()));
                }
                self.buf.extend_from_slice(&chunk[..n]);
            }
        } else if let Some(len) = content_length(&self.buf[..head_len]) {
            if len > crate::codec::MAX_BODY {
                return Err(too_large());
            }
            let end = head_len.saturating_add(len);
            while self.buf.len() < end {
                let n = stream.read(&mut chunk)?;
                if n == 0 {
                    return Ok(ReadOutcome::Incomplete(self.take_leftovers()));
                }
                self.buf.extend_from_slice(&chunk[..n]);
            }
            end
        } else {
            head_len
        };
        let rest = self.buf.split_off(end);
        Ok(ReadOutcome::Message(std::mem::replace(&mut self.buf, rest)))
    }
}

/// What [`RequestReader::read_message`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    /// One complete framed request.
    Message(Vec<u8>),
    /// The client closed with nothing buffered.
    Eof,
    /// The client closed inside a message; the bytes received so far.
    Incomplete(Vec<u8>),
    /// The chunked body is malformed; the bytes received so far.
    Malformed(Vec<u8>),
    /// The head is ambiguously framed (guarded readers only): everything
    /// received so far, untouched, and why. Never forwarded.
    Ambiguous(crate::strict_request::RequestFramingError, Vec<u8>),
}

/// One request from a connection that is then done with: the leftovers are
/// dropped. Use [`RequestReader`] wherever more bytes may follow.
pub fn read_request<R: Read>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    RequestReader::new().read_next(stream)
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
        // Only the new bytes (plus the 3 before them, in case a terminator
        // straddles two reads) can hold a head end: rescanning the whole
        // buffer on every read made a large response head quadratic.
        let from = out.len().saturating_sub(3);
        out.extend_from_slice(&chunk[..n]);
        let tail = &out[from..];
        if tail.windows(4).any(|w| w == b"\r\n\r\n") || tail.windows(2).any(|w| w == b"\n\n") {
            break;
        }
        if out.len() > 64 * 1024 {
            break;
        }
    }
    Ok(out)
}
