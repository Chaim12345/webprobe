// Minimal synchronous HTTP/2 client (RFC 9113 subset) used for upstream
// requests when ALPN negotiates `h2` or a server accepts an `h2c` upgrade.
//
// Scope: one request per connection, no push, request bodies streamed under
// flow control. Responses are converted to a normalized HTTP/1.1-shaped byte
// string so history, the editor and the scanner see the same shape as
// HTTP/1.x traffic.

use std::io::{Read, Write};

use hpack::{Decoder, Encoder};

/// `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` — the connection preface (RFC 9113 §3.4).
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_PRIORITY: u8 = 0x2;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PUSH_PROMISE: u8 = 0x5;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;

const DEFAULT_WINDOW: i64 = 65_535;
const DEFAULT_MAX_FRAME: usize = 16_384;
/// Frames larger than this can never be legal (24-bit length field is smaller),
/// so treat it as a hard ceiling for anything we allocate.
const MAX_FRAME: usize = 0xFF_FFFF;
const MAX_BODY: usize = 256 * 1024 * 1024;

fn write_frame<W: Write>(w: &mut W, ty: u8, flags: u8, stream: u32, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len();
    if len > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut head = [0u8; 9];
    head[0] = (len >> 16) as u8;
    head[1] = (len >> 8) as u8;
    head[2] = len as u8;
    head[3] = ty;
    head[4] = flags;
    head[5..9].copy_from_slice(&stream.to_be_bytes());
    w.write_all(&head)?;
    w.write_all(payload)?;
    w.flush()
}

struct Frame {
    ty: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Frame> {
    let mut head = [0u8; 9];
    r.read_exact(&mut head)?;
    let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Frame {
        ty: head[3],
        flags: head[4],
        stream: u32::from_be_bytes([head[5], head[6], head[7], head[8]]),
        payload,
    })
}

/// HEADERS fragment after removing PADDED padding and the PRIORITY fields
/// (RFC 9113 §6.2: Pad Length, Exclusive/Stream Dependency/Weight, fragment).
fn header_fragment(flags: u8, payload: &[u8]) -> Result<&[u8], String> {
    let mut p = payload;
    if flags & FLAG_PADDED != 0 {
        let (&pad, rest) = p.split_first().ok_or("h2: padded HEADERS without pad length")?;
        let pad = pad as usize;
        if pad > rest.len() {
            return Err("h2: HEADERS padding exceeds frame".into());
        }
        p = &rest[..rest.len() - pad];
    }
    if flags & FLAG_PRIORITY != 0 {
        if p.len() < 5 {
            return Err("h2: HEADERS priority fields truncated".into());
        }
        p = &p[5..];
    }
    Ok(p)
}

/// DATA payload after removing PADDED padding.
fn data_payload<'a>(flags: u8, payload: &'a [u8]) -> Result<&'a [u8], String> {
    if flags & FLAG_PADDED == 0 {
        return Ok(payload);
    }
    let (&pad, rest) = payload.split_first().ok_or("h2: padded DATA without pad length")?;
    let pad = pad as usize;
    if pad > rest.len() {
        return Err("h2: DATA padding exceeds frame".into());
    }
    Ok(&rest[..rest.len() - pad])
}

/// A parsed HTTP/2 request ready for encoding: pseudo-headers plus ordinary
/// headers, with hop-by-hop headers already removed.
pub struct H2Request {
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Hop-by-hop headers that must not appear in HTTP/2 (RFC 9113 §8.2.2).
fn is_connection_header(name: &str) -> bool {
    matches!(
        name,
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "http2-settings"
    ) || name.starts_with("proxy-")
}

fn send_preface<S: Read + Write>(stream: &mut S) -> Result<(), String> {
    stream.write_all(PREFACE).map_err(|e| format!("h2 preface: {e}"))?;
    // Our SETTINGS: ENABLE_PUSH=0 (id 0x2), INITIAL_WINDOW_SIZE default.
    write_frame(stream, FRAME_SETTINGS, 0, 0, &[0, 2, 0, 0, 0, 0]).map_err(|e| format!("h2 settings: {e}"))
}

/// Encode the request header list. HTTP/2 requires lowercase field names and
/// forbids connection-specific fields (RFC 9113 §8.2); sending `User-Agent`
/// verbatim makes strict servers reject the stream, so names are lowercased.
fn encode_headers(req: &H2Request) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), req.method.as_bytes().to_vec()),
        (b":scheme".to_vec(), req.scheme.as_bytes().to_vec()),
        (b":authority".to_vec(), req.authority.as_bytes().to_vec()),
        (b":path".to_vec(), req.path.as_bytes().to_vec()),
    ];
    for (k, v) in &req.headers {
        let lower = k.to_ascii_lowercase();
        if lower.is_empty() || lower == "host" || lower == "content-length" || is_connection_header(&lower) {
            continue;
        }
        // `te` is the one connection header HTTP/2 allows, and only "trailers".
        if lower == "te" && !v.eq_ignore_ascii_case("trailers") {
            continue;
        }
        headers.push((lower.into_bytes(), v.as_bytes().to_vec()));
    }
    if !req.body.is_empty() {
        headers.push((b"content-length".to_vec(), req.body.len().to_string().into_bytes()));
    }
    enc.encode(headers.iter().map(|(k, v)| (k.as_slice(), v.as_slice())))
}

fn send_request_headers<S: Read + Write>(stream: &mut S, req: &H2Request) -> Result<(), String> {
    let block = encode_headers(req);
    let flags = FLAG_END_HEADERS | if req.body.is_empty() { FLAG_END_STREAM } else { 0 };
    write_frame(stream, FRAME_HEADERS, flags, 1, &block).map_err(|e| format!("h2 headers: {e}"))
}

/// Response assembly plus outbound flow-control accounting.
struct Rx {
    dec: Decoder<'static>,
    status: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    block: Vec<u8>,
    in_continuation: bool,
    pending_end_stream: bool,
    got_headers: bool,
    done: bool,
    settings_seen: bool,
    peer_initial_window: i64,
    stream_window: i64,
    send_window: i64,
    max_frame: usize,
}

impl Rx {
    fn new() -> Self {
        Rx {
            dec: Decoder::new(),
            status: None,
            headers: Vec::new(),
            body: Vec::new(),
            block: Vec::new(),
            in_continuation: false,
            pending_end_stream: false,
            got_headers: false,
            done: false,
            settings_seen: false,
            peer_initial_window: DEFAULT_WINDOW,
            stream_window: DEFAULT_WINDOW,
            send_window: DEFAULT_WINDOW,
            max_frame: DEFAULT_MAX_FRAME,
        }
    }

    /// Decode one complete header block. The decoder keeps the HPACK dynamic
    /// table for the connection, so blocks must be fed in order.
    fn absorb_block(&mut self) -> Result<(), String> {
        let block = std::mem::take(&mut self.block);
        let fields = self.dec.decode(&block).map_err(|e| format!("h2 decode: {e:?}"))?;
        let mut status: Option<String> = None;
        let mut headers: Vec<(String, String)> = Vec::new();
        for (name, value) in fields {
            let name = String::from_utf8_lossy(&name).into_owned();
            let value = String::from_utf8_lossy(&value).into_owned();
            // Never let a decoded field break the normalized HTTP/1.1 view
            // (CR/LF would split headers or the message body).
            if name.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
                || value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
            {
                continue;
            }
            if let Some(rest) = name.strip_prefix(':') {
                if rest == "status" {
                    status = Some(value);
                }
                continue;
            }
            headers.push((name, value));
        }
        match status {
            Some(s) if s.len() == 3 && s.starts_with('1') => {
                // Interim (1xx) response: its fields do not belong to the final one.
                Ok(())
            }
            Some(s) => {
                self.status = Some(s);
                self.headers = headers;
                self.got_headers = true;
                Ok(())
            }
            None => {
                // Trailers follow the body; keep them visible in the view.
                self.headers.extend(headers);
                Ok(())
            }
        }
    }

    fn handle<S: Read + Write>(&mut self, stream: &mut S, f: Frame) -> Result<(), String> {
        if self.in_continuation && !(f.ty == FRAME_CONTINUATION && f.stream == 1) {
            return Err("h2: header block interrupted before CONTINUATION".into());
        }
        match f.ty {
            FRAME_SETTINGS => {
                if f.flags & FLAG_ACK == 0 {
                    for chunk in f.payload.chunks_exact(6) {
                        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                        let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                        match id {
                            SETTINGS_INITIAL_WINDOW_SIZE => {
                                let new = val as i64;
                                // Applies as a delta to every open stream (RFC 9113 §6.5.2).
                                self.stream_window += new - self.peer_initial_window;
                                self.peer_initial_window = new;
                            }
                            SETTINGS_MAX_FRAME_SIZE => {
                                self.max_frame = (val as usize).clamp(DEFAULT_MAX_FRAME, MAX_FRAME);
                            }
                            _ => {}
                        }
                    }
                    self.settings_seen = true;
                    write_frame(stream, FRAME_SETTINGS, FLAG_ACK, 0, &[]).map_err(|e| format!("h2 settings ack: {e}"))?;
                }
            }
            FRAME_PING => {
                if f.payload.len() != 8 {
                    return Err("h2: PING with wrong length".into());
                }
                if f.flags & FLAG_ACK == 0 {
                    write_frame(stream, FRAME_PING, FLAG_ACK, 0, &f.payload).map_err(|e| format!("h2 ping: {e}"))?;
                }
            }
            FRAME_WINDOW_UPDATE => {
                if f.payload.len() < 4 {
                    return Err("h2: short WINDOW_UPDATE".into());
                }
                let inc = (u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]) & 0x7fff_ffff) as i64;
                if inc == 0 {
                    return Err("h2: zero WINDOW_UPDATE".into());
                }
                if f.stream == 0 {
                    self.send_window += inc;
                } else if f.stream == 1 {
                    self.stream_window += inc;
                }
            }
            FRAME_GOAWAY => {
                if f.payload.len() < 8 {
                    return Err("h2: short GOAWAY".into());
                }
                let last = u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]) & 0x7fff_ffff;
                let code = u32::from_be_bytes([f.payload[4], f.payload[5], f.payload[6], f.payload[7]]);
                // Our only stream was not processed, so a fresh connection is safe.
                if last < 1 || code == 0x7 {
                    return Err(format!("h2: GOAWAY (retryable): error={code} last_stream_id={last}"));
                }
                return Err(format!("h2: GOAWAY: error={code} last_stream_id={last}"));
            }
            FRAME_RST_STREAM if f.stream == 1 => {
                let code = if f.payload.len() >= 4 {
                    u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]])
                } else {
                    0
                };
                if code == 0x7 {
                    return Err(format!("h2: stream reset (retryable): error={code}"));
                }
                return Err(format!("h2: stream reset by server: error={code}"));
            }
            FRAME_HEADERS if f.stream == 1 => {
                self.block.extend_from_slice(header_fragment(f.flags, &f.payload)?);
                if f.flags & FLAG_END_HEADERS != 0 {
                    self.in_continuation = false;
                    self.absorb_block()?;
                    if f.flags & FLAG_END_STREAM != 0 {
                        self.done = true;
                    }
                } else {
                    self.in_continuation = true;
                    self.pending_end_stream = f.flags & FLAG_END_STREAM != 0;
                }
            }
            FRAME_CONTINUATION if f.stream == 1 => {
                self.block.extend_from_slice(&f.payload);
                if f.flags & FLAG_END_HEADERS != 0 {
                    self.in_continuation = false;
                    self.absorb_block()?;
                    if self.pending_end_stream {
                        self.pending_end_stream = false;
                        self.done = true;
                    }
                }
            }
            FRAME_DATA if f.stream == 1 => {
                let payload = data_payload(f.flags, &f.payload)?;
                self.body.extend_from_slice(payload);
                if self.body.len() > MAX_BODY {
                    return Err("h2: response body too large".into());
                }
                if f.flags & FLAG_END_STREAM != 0 {
                    // The exchange is over: replenishing now is pointless and
                    // often fails because the peer already closed.
                    self.done = true;
                } else if !f.payload.is_empty() {
                    // Flow control counts the whole DATA payload, padding
                    // included, and must be replenished or a body larger than
                    // the initial window stalls.
                    let inc = (f.payload.len() as u32).to_be_bytes();
                    write_frame(stream, FRAME_WINDOW_UPDATE, 0, 0, &inc).map_err(|e| format!("h2 window update: {e}"))?;
                    write_frame(stream, FRAME_WINDOW_UPDATE, 0, 1, &inc).map_err(|e| format!("h2 window update: {e}"))?;
                }
            }
            FRAME_PUSH_PROMISE => {
                // We advertised ENABLE_PUSH=0; refuse any promised stream instead
                // of choking on it (a short payload must not panic).
                if f.payload.len() >= 4 {
                    let promised = u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]) & 0x7fff_ffff;
                    if promised != 0 {
                        write_frame(stream, FRAME_RST_STREAM, 0, promised, &8u32.to_be_bytes()).ok();
                    }
                }
            }
            FRAME_PRIORITY => {}
            _ => {}
        }
        Ok(())
    }

    /// Normalize to the HTTP/1.1 shape the rest of the app understands. Any
    /// upstream `content-length`/`transfer-encoding` is replaced so the view
    /// never carries two framing headers.
    fn finish(self) -> Result<Vec<u8>, String> {
        let status = self.status.ok_or("h2: response without :status")?;
        if !self.got_headers {
            return Err("h2: response without headers".into());
        }
        if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("h2: invalid :status {status:?}"));
        }
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(format!("HTTP/1.1 {status}\r\n").as_bytes());
        for (k, v) in &self.headers {
            let lower = k.to_ascii_lowercase();
            if lower == "content-length" || lower == "transfer-encoding" || is_connection_header(&lower) {
                continue;
            }
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

/// Send the request body under flow control while consuming server frames.
/// DATA is only written once the server's SETTINGS is known (it is required to
/// be the first frame, RFC 9113 §3.4), so a small INITIAL_WINDOW_SIZE or
/// MAX_FRAME_SIZE is honoured before the first byte goes out.
fn pump<S: Read + Write>(stream: &mut S, mut body: Option<&[u8]>, rx: &mut Rx) -> Result<(), String> {
    let mut sending = body.map(|b| !b.is_empty()).unwrap_or(false);
    loop {
        if sending && rx.settings_seen {
            loop {
                let rest = match body {
                    Some(rest) if !rest.is_empty() => rest,
                    _ => {
                        sending = false;
                        break;
                    }
                };
                let allowance = rx.send_window.min(rx.stream_window);
                if allowance <= 0 {
                    break;
                }
                let n = (allowance as usize).min(rx.max_frame).min(rest.len());
                let last = n == rest.len();
                write_frame(stream, FRAME_DATA, if last { FLAG_END_STREAM } else { 0 }, 1, &rest[..n])
                    .map_err(|e| format!("h2 data: {e}"))?;
                rx.send_window -= n as i64;
                rx.stream_window -= n as i64;
                body = Some(&rest[n..]);
                if last {
                    sending = false;
                    break;
                }
            }
        }
        if rx.done {
            return Ok(());
        }
        let f = read_frame(stream).map_err(|e| format!("h2 read: {e}"))?;
        rx.handle(stream, f)?;
    }
}

/// Perform one request over an established stream. The preface and initial
/// SETTINGS are sent here.
pub fn exchange<S: Read + Write>(stream: &mut S, req: &H2Request) -> Result<Vec<u8>, String> {
    send_preface(stream)?;
    send_request_headers(stream, req)?;
    let mut rx = Rx::new();
    let body = if req.body.is_empty() { None } else { Some(req.body.as_slice()) };
    pump(stream, body, &mut rx)?;
    rx.finish()
}

/// Continue an h2c upgrade (RFC 7540 §3.2): stream 1 *is* the HTTP/1.1 request
/// that was already sent, so only the preface and SETTINGS go out — resending
/// HEADERS or the body would duplicate the request on a half-closed stream.
pub fn exchange_upgraded<S: Read + Write>(stream: &mut S) -> Result<Vec<u8>, String> {
    send_preface(stream)?;
    let mut rx = Rx::new();
    pump(stream, None, &mut rx)?;
    rx.finish()
}

/// True when a failed exchange may be retried on a fresh connection because
/// the server never processed stream 1.
pub fn retryable(error: &str) -> bool {
    error.contains("(retryable)")
}

/// base64url without padding (RFC 7540 §3.2 `HTTP2-Settings` header value).
pub fn base64url(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TBL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(TBL[n as usize & 63] as char);
        }
    }
    out
}

/// The `HTTP2-Settings` value for a SETTINGS frame with ENABLE_PUSH=0.
pub fn empty_settings_value() -> String {
    // SETTINGS payload: id=0x2 (ENABLE_PUSH), value=0
    base64url(&[0, 2, 0, 0, 0, 0])
}

/// Build an `H2Request` from a raw origin-form HTTP/1.x request.
pub fn request_from_raw(raw: &[u8], scheme: &str) -> Option<H2Request> {
    let parts = crate::util::parse_http(raw);
    if parts.head_len == 0 || parts.head_len > raw.len() {
        return None;
    }
    let authority = crate::util::get_header(&parts.headers, "Host").unwrap_or_default();
    if authority.is_empty() {
        return None;
    }
    let mut headers = Vec::new();
    for (k, v) in &parts.headers {
        if k.eq_ignore_ascii_case("Host") {
            continue;
        }
        headers.push((k.clone(), v.clone()));
    }
    let mut body = raw[parts.head_len..].to_vec();
    // HTTP/2 has no chunked transfer coding; send the decoded octets.
    let chunked = crate::util::get_header(&parts.headers, "Transfer-Encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    if chunked {
        if let Some((decoded, _)) = crate::codec::decode_chunked(&body) {
            body = decoded;
        }
    }
    Some(H2Request {
        method: parts.method.clone(),
        scheme: scheme.to_string(),
        authority,
        path: if parts.path.is_empty() { "/".into() } else { parts.path.clone() },
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn base64url_matches_rfc7540_example() {
        // Empty SETTINGS payload encodes to an empty string; ENABLE_PUSH=0 (00 02 00 00 00 00) to "AAIAAAAA".
        assert_eq!(base64url(&[]), "");
        assert_eq!(base64url(&[0, 2, 0, 0, 0, 0]), "AAIAAAAA");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn request_from_raw_extracts_pseudo_headers() {
        let raw = b"GET /a/b?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\nConnection: keep-alive\r\n\r\n";
        let req = request_from_raw(raw, "https").unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.scheme, "https");
        assert_eq!(req.authority, "example.com");
        assert_eq!(req.path, "/a/b?x=1");
        assert!(req.body.is_empty());
        // Hop-by-hop headers are kept here and filtered when encoding.
        assert_eq!(req.headers.len(), 2);
    }

    #[test]
    fn request_from_raw_dechunks_a_chunked_body() {
        let raw = b"POST /up HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let req = request_from_raw(raw, "https").unwrap();
        assert_eq!(req.body, b"hello");
    }

    /// A scripted peer: reads from `input`, collects writes in `out`.
    struct Scripted {
        input: Cursor<Vec<u8>>,
        out: Vec<u8>,
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.out.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn server_bytes(frames: &[(u8, u8, u32, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (ty, flags, stream, payload) in frames {
            out.extend_from_slice(&[(payload.len() >> 16) as u8, (payload.len() >> 8) as u8, payload.len() as u8]);
            out.extend_from_slice(&[*ty, *flags]);
            out.extend_from_slice(&stream.to_be_bytes());
            out.extend_from_slice(payload);
        }
        out
    }

    fn scripted(frames: &[(u8, u8, u32, &[u8])]) -> Scripted {
        Scripted { input: Cursor::new(server_bytes(frames)), out: Vec::new() }
    }

    fn get_request() -> H2Request {
        H2Request {
            method: "GET".into(),
            scheme: "https".into(),
            authority: "example.com".into(),
            path: "/".into(),
            headers: vec![("User-Agent".into(), "probe".into())],
            body: Vec::new(),
        }
    }

    /// Malformed control frames must produce an error, never a panic.
    #[test]
    fn malformed_frames_error_instead_of_panicking() {
        // WINDOW_UPDATE with a 2-byte payload.
        let mut s = scripted(&[(FRAME_SETTINGS, 0, 0, &[]), (FRAME_WINDOW_UPDATE, 0, 0, &[0, 1])]);
        assert!(exchange(&mut s, &get_request()).is_err());

        // PUSH_PROMISE with an empty payload.
        let mut s = scripted(&[(FRAME_SETTINGS, 0, 0, &[]), (FRAME_PUSH_PROMISE, 0, 1, &[])]);
        assert!(exchange(&mut s, &get_request()).is_err());

        // HEADERS marked PADDED with an empty payload.
        let mut s = scripted(&[(FRAME_SETTINGS, 0, 0, &[]), (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_PADDED, 1, &[])]);
        assert!(exchange(&mut s, &get_request()).is_err());

        // HEADERS marked PRIORITY but shorter than the 5-byte prefix.
        let mut s = scripted(&[(FRAME_SETTINGS, 0, 0, &[]), (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_PRIORITY, 1, &[0, 0])]);
        assert!(exchange(&mut s, &get_request()).is_err());

        // DATA marked PADDED whose pad length exceeds the frame.
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x88]),
            (FRAME_DATA, FLAG_END_STREAM | FLAG_PADDED, 1, &[9, b'x']),
        ]);
        assert!(exchange(&mut s, &get_request()).is_err());

        // GOAWAY with a truncated payload.
        let mut s = scripted(&[(FRAME_SETTINGS, 0, 0, &[]), (FRAME_GOAWAY, 0, 0, &[0, 0])]);
        assert!(exchange(&mut s, &get_request()).is_err());
    }

    /// A CONTINUATION block split across frames is reassembled, and END_STREAM
    /// on the HEADERS frame must not end the exchange before the block is done.
    #[test]
    fn split_header_block_is_reassembled() {
        // Encode the two fields as separate blocks with one encoder so the
        // split lands on a field boundary; HPACK has no block framing, so the
        // decoder sees the concatenation as one block.
        let mut enc = Encoder::new();
        let first = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        let rest = enc.encode(vec![(b"content-type".as_ref(), b"text/plain".as_ref())]);
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_STREAM, 1, &first),
            (FRAME_CONTINUATION, FLAG_END_HEADERS, 1, &rest),
        ]);
        let resp = exchange(&mut s, &get_request()).expect("reassembled response");
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("content-type: text/plain"), "{text}");
    }

    /// A real h2 server for the flow-control test: reads HEADERS, then DATA,
    /// issuing WINDOW_UPDATEs, and answers with the received length.
    fn serve_flow_control<S: Read + Write>(s: &mut S, expected_body: usize) {
        let mut preface = [0u8; 24];
        s.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, PREFACE);
        // client SETTINGS
        let f = read_frame(s).unwrap();
        assert_eq!(f.ty, FRAME_SETTINGS);
        // server SETTINGS with a tiny MAX_FRAME_SIZE to force several DATA frames
        write_frame(s, FRAME_SETTINGS, 0, 0, &[0, 5, 0, 0, 0x40, 0x00]).unwrap(); // 16384
        let mut body = Vec::new();
        loop {
            let f = read_frame(s).unwrap();
            match f.ty {
                FRAME_HEADERS => {
                    assert_eq!(f.stream, 1);
                    write_frame(s, FRAME_WINDOW_UPDATE, 0, 0, &10_000_000u32.to_be_bytes()).unwrap();
                }
                FRAME_SETTINGS if f.flags & FLAG_ACK == 0 => {
                    write_frame(s, FRAME_SETTINGS, FLAG_ACK, 0, &[]).unwrap();
                }
                FRAME_DATA => {
                    body.extend_from_slice(&f.payload);
                    write_frame(s, FRAME_WINDOW_UPDATE, 0, 0, &(f.payload.len() as u32).to_be_bytes()).unwrap();
                    write_frame(s, FRAME_WINDOW_UPDATE, 0, 1, &(f.payload.len() as u32).to_be_bytes()).unwrap();
                    if f.flags & FLAG_END_STREAM != 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        assert_eq!(body.len(), expected_body);
        let mut enc = Encoder::new();
        let hb = enc.encode(vec![(b":status".as_ref(), b"200".as_ref())]);
        write_frame(s, FRAME_HEADERS, FLAG_END_HEADERS, 1, &hb).unwrap();
        write_frame(s, FRAME_DATA, FLAG_END_STREAM, 1, b"ok").unwrap();
    }

    /// A body larger than the initial 65 535-byte window must be split into
    /// legal DATA frames and stalled on WINDOW_UPDATE instead of overrunning
    /// the peer's window.
    #[test]
    fn large_body_respects_flow_control() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = vec![b'z'; 150_000];
        let expected = body.len();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
            serve_flow_control(&mut s, expected);
        });
        let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        let req = H2Request {
            method: "POST".into(),
            scheme: "http".into(),
            authority: "127.0.0.1".into(),
            path: "/upload".into(),
            headers: vec![],
            body,
        };
        let resp = exchange(&mut tcp, &req).expect("flow-controlled upload");
        t.join().unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
        assert!(resp.ends_with(b"ok"));
    }
}
