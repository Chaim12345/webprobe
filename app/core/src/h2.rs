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

pub(crate) const FRAME_DATA: u8 = 0x0;
pub(crate) const FRAME_HEADERS: u8 = 0x1;
pub(crate) const FRAME_PRIORITY: u8 = 0x2;
pub(crate) const FRAME_RST_STREAM: u8 = 0x3;
pub(crate) const FRAME_SETTINGS: u8 = 0x4;
pub(crate) const FRAME_PUSH_PROMISE: u8 = 0x5;
pub(crate) const FRAME_PING: u8 = 0x6;
pub(crate) const FRAME_GOAWAY: u8 = 0x7;
pub(crate) const FRAME_WINDOW_UPDATE: u8 = 0x8;
pub(crate) const FRAME_CONTINUATION: u8 = 0x9;

pub(crate) const FLAG_END_STREAM: u8 = 0x1;
pub(crate) const FLAG_ACK: u8 = 0x1;
pub(crate) const FLAG_END_HEADERS: u8 = 0x4;
pub(crate) const FLAG_PADDED: u8 = 0x8;
pub(crate) const FLAG_PRIORITY: u8 = 0x20;

pub(crate) const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub(crate) const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;

pub(crate) const DEFAULT_WINDOW: i64 = 65_535;
pub(crate) const DEFAULT_MAX_FRAME: usize = 16_384;
/// Frames larger than this can never be legal (24-bit length field is smaller),
/// so treat it as a hard ceiling for anything we allocate.
const MAX_FRAME: usize = 0xFF_FFFF;
const MAX_BODY: usize = 256 * 1024 * 1024;
/// Largest header block accepted across HEADERS + CONTINUATION frames:
/// endless CONTINUATION frames must not grow memory without bound
/// (the CVE-2024-27316 class).
const MAX_HEADER_BLOCK: usize = 256 * 1024;

pub(crate) fn write_frame<W: Write>(
    w: &mut W,
    ty: u8,
    flags: u8,
    stream: u32,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = payload.len();
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
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

pub(crate) struct Frame {
    pub(crate) ty: u8,
    pub(crate) flags: u8,
    pub(crate) stream: u32,
    pub(crate) payload: Vec<u8>,
}

/// One frame from the front of `buf`, when it is all there: the frame and
/// the bytes it took. Frames longer than `max` are an error (the peer must
/// not exceed the SETTINGS_MAX_FRAME_SIZE we advertised; RFC 9113 §4.2).
/// Shared by the client (blocking reads) and the server role (a buffer
/// filled by non-blocking reads).
pub(crate) fn parse_frame(buf: &[u8], max: usize) -> Result<Option<(Frame, usize)>, String> {
    if buf.len() < 9 {
        return Ok(None);
    }
    let len = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | buf[2] as usize;
    if len > max {
        return Err(format!(
            "h2: frame of {len} bytes exceeds SETTINGS_MAX_FRAME_SIZE {max}"
        ));
    }
    if buf.len() < 9 + len {
        return Ok(None);
    }
    let stream = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
    Ok(Some((
        Frame {
            ty: buf[3],
            flags: buf[4],
            stream,
            payload: buf[9..9 + len].to_vec(),
        },
        9 + len,
    )))
}

fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Frame> {
    let mut head = [0u8; 9];
    r.read_exact(&mut head)?;
    let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
    // We never advertise SETTINGS_MAX_FRAME_SIZE, so the peer may send at
    // most the default 16 KiB (RFC 9113 §4.2: larger is FRAME_SIZE_ERROR).
    if len > DEFAULT_MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame larger than SETTINGS_MAX_FRAME_SIZE",
        ));
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
pub(crate) fn header_fragment(flags: u8, payload: &[u8]) -> Result<&[u8], String> {
    let mut p = payload;
    if flags & FLAG_PADDED != 0 {
        let (&pad, rest) = p
            .split_first()
            .ok_or("h2: padded HEADERS without pad length")?;
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
pub(crate) fn data_payload(flags: u8, payload: &[u8]) -> Result<&[u8], String> {
    if flags & FLAG_PADDED == 0 {
        return Ok(payload);
    }
    let (&pad, rest) = payload
        .split_first()
        .ok_or("h2: padded DATA without pad length")?;
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
    /// A Connection header to send anyway (Repeater with "Strip Connection
    /// header over HTTP/2" off); otherwise connection headers are dropped.
    pub connection: Option<String>,
}

/// Hop-by-hop headers that must not appear in HTTP/2 (RFC 9113 §8.2.2).
pub(crate) fn is_connection_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "upgrade"
            | "http2-settings"
    ) || name.starts_with("proxy-")
}

pub(crate) fn send_preface<S: Read + Write>(stream: &mut S) -> Result<(), String> {
    stream
        .write_all(PREFACE)
        .map_err(|e| format!("h2 preface: {e}"))?;
    // Our SETTINGS: ENABLE_PUSH=0 (id 0x2), INITIAL_WINDOW_SIZE default.
    write_frame(stream, FRAME_SETTINGS, 0, 0, &[0, 2, 0, 0, 0, 0])
        .map_err(|e| format!("h2 settings: {e}"))
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
        if lower.is_empty()
            || lower == "host"
            || lower == "content-length"
            || is_connection_header(&lower)
        {
            continue;
        }
        // `te` is the one connection header HTTP/2 allows, and only "trailers".
        if lower == "te" && !v.eq_ignore_ascii_case("trailers") {
            continue;
        }
        headers.push((lower.into_bytes(), v.as_bytes().to_vec()));
    }
    if let Some(c) = &req.connection {
        headers.push((b"connection".to_vec(), c.as_bytes().to_vec()));
    }
    if !req.body.is_empty() {
        headers.push((
            b"content-length".to_vec(),
            req.body.len().to_string().into_bytes(),
        ));
    }
    enc.encode(headers.iter().map(|(k, v)| (k.as_slice(), v.as_slice())))
}

fn send_request_headers<S: Read + Write>(
    stream: &mut S,
    sid: u32,
    req: &H2Request,
) -> Result<(), String> {
    let block = encode_headers(req);

    let flags = FLAG_END_HEADERS
        | if req.body.is_empty() {
            FLAG_END_STREAM
        } else {
            0
        };
    write_frame(stream, FRAME_HEADERS, flags, sid, &block).map_err(|e| format!("h2 headers: {e}"))
}

/// Response assembly plus outbound flow-control accounting.
pub(crate) struct Rx {
    sid: u32,
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
    /// What the response sink chose once the head was in (None: no sink
    /// or not asked yet; buffered responses keep `None`).
    mode: Option<crate::streaming::BodyMode>,
    /// Streaming: the client went away; the body is drained, not sent.
    client_gone: bool,
}

fn grow_window(window: &mut i64, delta: i64, what: &str) -> Result<(), String> {
    let next = window
        .checked_add(delta)
        .filter(|value| *value <= 0x7fff_ffff)
        .ok_or_else(|| format!("h2: {what} flow-control window overflow"))?;
    *window = next;
    Ok(())
}

impl Rx {
    pub(crate) fn new(sid: u32) -> Self {
        Rx {
            sid,
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
            mode: None,
            client_gone: false,
        }
    }

    /// The HTTP/1.1 head of the response so far (no framing headers).
    fn head_h1(&self, framing: &str) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {}\r\n", self.status.as_deref().unwrap_or("502"));
        for (k, v) in &self.headers {
            let lower = k.to_ascii_lowercase();
            if lower == "content-length"
                || lower == "transfer-encoding"
                || is_connection_header(&lower)
            {
                continue;
            }
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str(framing);
        out.push_str("\r\n");
        out.into_bytes()
    }

    /// The head is in: ask the sink how to read the body. Streamed to an
    /// HTTP/1.1 client, DATA frames become chunks.
    fn ask_sink(&mut self, sink: &mut Option<&mut (dyn crate::streaming::ResponseSink + '_)>) {
        let (Some(s), true, None) = (sink.as_deref_mut(), self.got_headers, self.mode) else {
            return;
        };
        let head = self.head_h1("");
        let mode = s.head(&head);
        self.mode = Some(mode);
        match mode {
            crate::streaming::BodyMode::Stream => {
                if self.done {
                    let full = self.head_h1("Content-Length: 0\r\n");
                    self.client_gone = s.wire(&full).is_err();
                    s.end(true);
                } else {
                    self.client_gone = s
                        .wire(&self.head_h1("Transfer-Encoding: chunked\r\n"))
                        .is_err();
                }
            }
            crate::streaming::BodyMode::HeadOnly => self.done = true,
            crate::streaming::BodyMode::Buffer => {}
        }
    }

    fn streaming(&self) -> bool {
        self.mode == Some(crate::streaming::BodyMode::Stream)
    }

    /// Decode one complete header block. The decoder keeps the HPACK dynamic
    /// table for the connection, so blocks must be fed in order.
    fn absorb_block(&mut self) -> Result<(), String> {
        let block = std::mem::take(&mut self.block);
        // hpack 0.3 panics on some truncated encodings (e.g. a dynamic table
        // size update cut short); a hostile server must not take the proxy
        // thread down. The connection is dropped with the error.
        let decoded =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.dec.decode(&block)))
                .map_err(|_| "h2 decode: malformed header block".to_string())?;
        let fields = decoded.map_err(|e| format!("h2 decode: {e:?}"))?;
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

    fn handle<S: Read + Write>(
        &mut self,
        stream: &mut S,
        f: Frame,
        sink: &mut Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
    ) -> Result<(), String> {
        if self.in_continuation && !(f.ty == FRAME_CONTINUATION && f.stream == self.sid) {
            return Err("h2: header block interrupted before CONTINUATION".into());
        }
        match f.ty {
            FRAME_SETTINGS => {
                if f.flags & FLAG_ACK == 0 {
                    for chunk in f.payload.as_chunks::<6>().0 {
                        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                        let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                        match id {
                            SETTINGS_INITIAL_WINDOW_SIZE => {
                                let new = val as i64;
                                // Applies as a delta to every open stream (RFC 9113 §6.5.2).
                                grow_window(
                                    &mut self.stream_window,
                                    new - self.peer_initial_window,
                                    "stream",
                                )?;
                                self.peer_initial_window = new;
                            }
                            SETTINGS_MAX_FRAME_SIZE => {
                                self.max_frame = (val as usize).clamp(DEFAULT_MAX_FRAME, MAX_FRAME);
                            }
                            _ => {}
                        }
                    }
                    self.settings_seen = true;
                    write_frame(stream, FRAME_SETTINGS, FLAG_ACK, 0, &[])
                        .map_err(|e| format!("h2 settings ack: {e}"))?;
                }
            }
            FRAME_PING => {
                if f.payload.len() != 8 {
                    return Err("h2: PING with wrong length".into());
                }
                if f.flags & FLAG_ACK == 0 {
                    write_frame(stream, FRAME_PING, FLAG_ACK, 0, &f.payload)
                        .map_err(|e| format!("h2 ping: {e}"))?;
                }
            }
            FRAME_WINDOW_UPDATE => {
                if f.payload.len() < 4 {
                    return Err("h2: short WINDOW_UPDATE".into());
                }
                let inc =
                    (u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]])
                        & 0x7fff_ffff) as i64;
                if inc == 0 {
                    return Err("h2: zero WINDOW_UPDATE".into());
                }
                if f.stream == 0 {
                    grow_window(&mut self.send_window, inc, "connection")?;
                } else if f.stream == self.sid {
                    grow_window(&mut self.stream_window, inc, "stream")?;
                }
            }
            FRAME_GOAWAY => {
                if f.payload.len() < 8 {
                    return Err("h2: short GOAWAY".into());
                }
                let last =
                    u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]])
                        & 0x7fff_ffff;
                let code =
                    u32::from_be_bytes([f.payload[4], f.payload[5], f.payload[6], f.payload[7]]);
                // Our only stream was not processed, so a fresh connection is safe.
                if last < 1 || code == 0x7 {
                    return Err(format!(
                        "h2: GOAWAY (retryable): error={code} last_stream_id={last}"
                    ));
                }
                return Err(format!("h2: GOAWAY: error={code} last_stream_id={last}"));
            }
            FRAME_RST_STREAM if f.stream == self.sid => {
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

            FRAME_HEADERS if f.stream == self.sid => {
                self.block
                    .extend_from_slice(header_fragment(f.flags, &f.payload)?);
                if self.block.len() > MAX_HEADER_BLOCK {
                    return Err("h2: header block too large".into());
                }
                if f.flags & FLAG_END_HEADERS != 0 {
                    self.in_continuation = false;
                    self.absorb_block()?;
                    if f.flags & FLAG_END_STREAM != 0 {
                        self.done = true;
                        self.end_stream(sink);
                    }
                    self.ask_sink(sink);
                } else {
                    self.in_continuation = true;
                    self.pending_end_stream = f.flags & FLAG_END_STREAM != 0;
                }
            }
            FRAME_CONTINUATION if f.stream == self.sid => {
                self.block.extend_from_slice(&f.payload);
                if self.block.len() > MAX_HEADER_BLOCK {
                    return Err("h2: header block too large".into());
                }
                if f.flags & FLAG_END_HEADERS != 0 {
                    self.in_continuation = false;
                    self.absorb_block()?;
                    if self.pending_end_stream {
                        self.pending_end_stream = false;
                        self.done = true;
                        self.end_stream(sink);
                    }
                    self.ask_sink(sink);
                }
            }
            FRAME_DATA if f.stream == self.sid => {
                let payload = data_payload(f.flags, &f.payload)?;
                if self.streaming() {
                    // Passed on as it arrives (as a chunk), never kept here.
                    if let Some(s) = sink.as_deref_mut() {
                        s.payload(payload);
                        if !self.client_gone && !payload.is_empty() {
                            let mut chunk = format!("{:x}\r\n", payload.len()).into_bytes();
                            chunk.extend_from_slice(payload);
                            chunk.extend_from_slice(b"\r\n");
                            self.client_gone = s.wire(&chunk).is_err();
                        }
                    }
                    if let Some(s) = sink.as_deref_mut() {
                        s.flush();
                    }
                    if self.client_gone {
                        return Err("h2: the client closed the streaming response".into());
                    }
                } else {
                    self.body.extend_from_slice(payload);
                }
                if self.body.len() > MAX_BODY {
                    return Err("h2: response body too large".into());
                }
                if f.flags & FLAG_END_STREAM != 0 {
                    self.end_stream(sink);
                    // The exchange is over: replenishing now is pointless and
                    // often fails because the peer already closed.
                    self.done = true;
                } else if !f.payload.is_empty() {
                    // Flow control counts the whole DATA payload, padding
                    // included, and must be replenished or a body larger than
                    // the initial window stalls.
                    let inc = (f.payload.len() as u32).to_be_bytes();

                    write_frame(stream, FRAME_WINDOW_UPDATE, 0, 0, &inc)
                        .map_err(|e| format!("h2 window update: {e}"))?;
                    write_frame(stream, FRAME_WINDOW_UPDATE, 0, self.sid, &inc)
                        .map_err(|e| format!("h2 window update: {e}"))?;
                }
            }
            FRAME_PUSH_PROMISE => {
                // We advertised ENABLE_PUSH=0; refuse any promised stream instead
                // of choking on it (a short payload must not panic).
                if f.payload.len() >= 4 {
                    let promised = u32::from_be_bytes([
                        f.payload[0],
                        f.payload[1],
                        f.payload[2],
                        f.payload[3],
                    ]) & 0x7fff_ffff;
                    if promised != 0 {
                        write_frame(stream, FRAME_RST_STREAM, 0, promised, &8u32.to_be_bytes())
                            .ok();
                    }
                }
            }
            FRAME_PRIORITY => {}
            _ => {}
        }
        Ok(())
    }

    /// A streamed body ended: close the chunked framing.
    fn end_stream(&mut self, sink: &mut Option<&mut (dyn crate::streaming::ResponseSink + '_)>) {
        if !self.streaming() {
            return;
        }
        if let Some(s) = sink.as_deref_mut() {
            if !self.client_gone {
                self.client_gone = s.wire(b"0\r\n\r\n").is_err();
            }
            s.end(true);
        }
    }

    /// Normalize to the HTTP/1.1 shape the rest of the app understands. Any
    /// upstream `content-length`/`transfer-encoding` is replaced so the view
    /// never carries two framing headers.
    pub(crate) fn sid(&self) -> u32 {
        self.sid
    }

    pub(crate) fn finish(self) -> Result<Vec<u8>, String> {
        if self
            .mode
            .is_some_and(|m| m != crate::streaming::BodyMode::Buffer)
        {
            // Streamed or cut after the head: the head is the message.
            return Ok(self.head_h1(""));
        }
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
            if lower == "content-length"
                || lower == "transfer-encoding"
                || is_connection_header(&lower)
            {
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
fn pump<S: Read + Write>(
    stream: &mut S,
    sid: u32,
    mut body: Option<&[u8]>,
    rx: &mut Rx,
    sink: &mut Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
) -> Result<(), String> {
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

                write_frame(
                    stream,
                    FRAME_DATA,
                    if last { FLAG_END_STREAM } else { 0 },
                    sid,
                    &rest[..n],
                )
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
        rx.handle(stream, f, sink)?;
    }
}

/// The peer's initial flow-control window (RFC 7540 6.9.2): the most
/// DATA a connection accepts before the first WINDOW_UPDATE. The
/// single-packet burst writes every stream before a WINDOW_UPDATE can
/// arrive, so the group's total DATA must fit in it.
pub(crate) const INITIAL_WINDOW_SIZE: usize = 65_535;

/// Fail fast when a single-packet group's request bodies would overrun
/// the initial connection window: the server would reset every stream
/// with FLOW_CONTROL_ERROR otherwise.
pub(crate) fn check_burst_window(body_lens: impl IntoIterator<Item = usize>) -> Result<(), String> {
    let total: usize = body_lens.into_iter().sum();
    if total > INITIAL_WINDOW_SIZE {
        return Err(format!(
            "the group's request bodies total {total} bytes, past the HTTP/2 initial flow-control window ({INITIAL_WINDOW_SIZE}): the server would reset every stream with FLOW_CONTROL_ERROR. Send the group in sequence or shrink the bodies"
        ));
    }
    Ok(())
}

/// Every frame of `req` on stream `sid` as one buffer: HEADERS, then the
/// body as DATA frames. R-12's parallel send writes every stream's buffer
/// in a single packet (Burp's single-packet attack). DATA is chunked to
/// 16,384 bytes: the peer's initial SETTINGS_MAX_FRAME_SIZE is 16,384
/// (RFC 7540 6.5.2) and the burst is written before its SETTINGS arrive,
/// so one oversized DATA frame earns a PROTOCOL_ERROR. Bodies whose
/// group total passes the peer's initial window are rejected up front by
/// check_burst_window.
pub(crate) fn request_frames(sid: u32, req: &H2Request) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let block = encode_headers(req);
    let flags = FLAG_END_HEADERS
        | if req.body.is_empty() {
            FLAG_END_STREAM
        } else {
            0
        };
    write_frame(&mut out, FRAME_HEADERS, flags, sid, &block)
        .map_err(|e| format!("h2 headers: {e}"))?;
    let mut chunks = req.body.chunks(16_384).peekable();
    while let Some(chunk) = chunks.next() {
        let flags = if chunks.peek().is_none() {
            FLAG_END_STREAM
        } else {
            0
        };
        write_frame(&mut out, FRAME_DATA, flags, sid, chunk)
            .map_err(|e| format!("h2 data: {e}"))?;
    }
    Ok(out)
}

/// Read frames until every stream in `rxs` is done, feeding each frame to
/// its stream's assembly; connection-level frames go to the first
/// unfinished stream's handler, which covers them. Returns the streams'
/// ids in the order their first response frame arrived (burp.Zglm's
/// "%d/%d" arrival numbering).
pub(crate) fn pump_all<S: Read + Write>(
    stream: &mut S,
    rxs: &mut [Rx],
) -> Result<Vec<u32>, String> {
    let mut arrival = Vec::new();
    loop {
        if rxs.iter().all(|rx| rx.done) {
            return Ok(arrival);
        }
        let f = read_frame(stream).map_err(|e| format!("h2 read: {e}"))?;
        let sid = f.stream;
        let idx = rxs
            .iter()
            .position(|rx| rx.sid == sid)
            .or_else(|| rxs.iter().position(|rx| !rx.done));
        match idx.map(|i| &mut rxs[i]) {
            Some(rx) => {
                if rx.sid == sid
                    && !rx.got_headers
                    && !rx.done
                    && !arrival.contains(&sid)
                    && (f.ty == FRAME_HEADERS || f.ty == FRAME_DATA)
                {
                    arrival.push(sid);
                }
                let mut none = None;
                rx.handle(stream, f, &mut none)?;
            }
            None => return Err("h2: every stream finished but frames keep coming".into()),
        }
    }
}

/// Perform one request over an established stream. The preface and initial
/// SETTINGS are sent here.
///
/// With a `sink`, the sink sees the head first and may take the body as it
/// arrives (see `codec::read_message`); a streamed body that is cut short
/// still returns the head, after telling the sink.
pub fn exchange<S: Read + Write>(
    stream: &mut S,
    req: &H2Request,
    sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
) -> Result<Vec<u8>, String> {
    send_preface(stream)?;
    exchange_on(stream, 1, req, sink)
}

/// One request on stream `sid` of an already-prefaced connection (Repeater
/// send-group single-connection mode, R-12).
pub fn exchange_on<S: Read + Write>(
    stream: &mut S,
    sid: u32,
    req: &H2Request,
    mut sink: Option<&mut (dyn crate::streaming::ResponseSink + '_)>,
) -> Result<Vec<u8>, String> {
    send_request_headers(stream, sid, req)?;
    let mut rx = Rx::new(sid);
    let body = if req.body.is_empty() {
        None
    } else {
        Some(req.body.as_slice())
    };
    if let Err(e) = pump(stream, sid, body, &mut rx, &mut sink) {
        if !rx.streaming() {
            return Err(e);
        }
        if let Some(s) = sink {
            s.end(false);
        }
    }
    rx.finish()
}

/// Continue an h2c upgrade (RFC 7540 §3.2): stream 1 *is* the HTTP/1.1 request
/// that was already sent, so only the preface and SETTINGS go out — resending
/// HEADERS or the body would duplicate the request on a half-closed stream.
pub fn exchange_upgraded<S: Read + Write>(stream: &mut S) -> Result<Vec<u8>, String> {
    send_preface(stream)?;
    let mut rx = Rx::new(1);
    pump(stream, 1, None, &mut rx, &mut None)?;
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
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
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
        path: if parts.path.is_empty() {
            "/".into()
        } else {
            parts.path.clone()
        },
        headers,
        body,
        connection: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A body bigger than the peer's default SETTINGS_MAX_FRAME_SIZE
    /// (16,384) must go out as several DATA frames, END_STREAM on the
    /// last, or the burst earns a PROTOCOL_ERROR.
    #[test]
    fn burst_window_rejects_groups_past_the_initial_window() {
        // Two 40 KB bodies fit their own stream windows but overrun the
        // shared connection window.
        assert!(check_burst_window([40 * 1024, 40 * 1024]).is_err());
        // The same total in one body is rejected too.
        assert!(check_burst_window([80 * 1024]).is_err());
        // At and under the window is fine.
        assert!(check_burst_window([65_535]).is_ok());
        assert!(check_burst_window([1024, 2048]).is_ok());
        assert!(check_burst_window([]).is_ok());
    }

    #[test]
    fn request_frames_chunks_large_bodies() {
        let req = H2Request {
            method: "POST".into(),
            scheme: "https".into(),
            authority: "example.com".into(),
            path: "/".into(),
            headers: Vec::new(),
            body: vec![7u8; 40_000],
            connection: None,
        };
        let burst = request_frames(1, &req).unwrap();
        let mut cursor = Cursor::new(burst.as_slice());
        let mut data_lengths = Vec::new();
        let mut end_stream = false;
        while let Ok(f) = read_frame(&mut cursor) {
            if f.ty == FRAME_DATA {
                data_lengths.push(f.payload.len());
                end_stream = f.flags & FLAG_END_STREAM != 0;
            }
        }
        assert_eq!(data_lengths, vec![16_384, 16_384, 7_232]);
        assert!(end_stream);
        // An empty body keeps END_STREAM on HEADERS and adds no DATA.
        let req = H2Request {
            body: Vec::new(),
            ..req
        };
        let burst = request_frames(1, &req).unwrap();
        let mut cursor = Cursor::new(burst.as_slice());
        let f = read_frame(&mut cursor).unwrap();
        assert_eq!(f.ty, FRAME_HEADERS);
        assert!(f.flags & FLAG_END_STREAM != 0);
        assert!(read_frame(&mut cursor).is_err());
    }

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
            out.extend_from_slice(&[
                (payload.len() >> 16) as u8,
                (payload.len() >> 8) as u8,
                payload.len() as u8,
            ]);
            out.extend_from_slice(&[*ty, *flags]);
            out.extend_from_slice(&stream.to_be_bytes());
            out.extend_from_slice(payload);
        }
        out
    }

    fn scripted(frames: &[(u8, u8, u32, &[u8])]) -> Scripted {
        Scripted {
            input: Cursor::new(server_bytes(frames)),
            out: Vec::new(),
        }
    }

    fn get_request() -> H2Request {
        H2Request {
            method: "GET".into(),
            scheme: "https".into(),
            authority: "example.com".into(),
            path: "/".into(),
            headers: vec![("User-Agent".into(), "probe".into())],
            body: Vec::new(),
            connection: None,
        }
    }

    /// R-06: an event-stream response over an h2 upstream goes to the sink
    /// frame by frame, re-framed as HTTP/1.1 chunks, and is not kept here.
    #[test]
    fn streaming_response_passes_data_frames_to_the_sink() {
        struct Rec(Vec<u8>, Vec<u8>, Option<bool>, usize);
        impl crate::streaming::ResponseSink for Rec {
            fn head(&mut self, head: &[u8]) -> crate::streaming::BodyMode {
                assert!(crate::streaming::is_event_stream(head));
                crate::streaming::BodyMode::Stream
            }
            fn wire(&mut self, b: &[u8]) -> std::io::Result<()> {
                self.0.extend_from_slice(b);
                Ok(())
            }
            fn payload(&mut self, b: &[u8]) {
                self.1.extend_from_slice(b);
            }
            fn end(&mut self, complete: bool) {
                self.2 = Some(complete);
            }
            fn flush(&mut self) {
                self.3 += 1;
            }
        }
        let mut enc = Encoder::new();
        let hb = enc.encode(vec![
            (b":status".as_ref(), b"200".as_ref()),
            (b"content-type".as_ref(), b"text/event-stream".as_ref()),
        ]);
        let frames: [(u8, u8, u32, &[u8]); 4] = [
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS, 1, &hb),
            (FRAME_DATA, 0, 1, b"data: 1\n\n"),
            (FRAME_DATA, FLAG_END_STREAM, 1, b"data: 2\n\n"),
        ];
        let mut rec = Rec(Vec::new(), Vec::new(), None, 0);
        let head = exchange(&mut scripted(&frames), &get_request(), Some(&mut rec)).unwrap();
        assert!(
            String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200")
                && head.ends_with(b"\r\n\r\n")
        );
        let wire = String::from_utf8_lossy(&rec.0).into_owned();
        assert!(wire.contains("Transfer-Encoding: chunked\r\n\r\n9\r\ndata: 1\n\n\r\n9\r\ndata: 2\n\n\r\n0\r\n\r\n"), "{wire}");
        assert_eq!(rec.1, b"data: 1\n\ndata: 2\n\n");
        assert_eq!((rec.2, rec.3 >= 2), (Some(true), true));
    }

    /// Review finding 3: a hostile server cannot panic the HPACK decoder,
    /// grow a header block without bound, or send oversized frames.
    #[test]
    fn hostile_header_blocks_and_frames_are_rejected() {
        // Truncated dynamic table size update: hpack 0.3 panics on it.
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x3f]),
        ]);
        assert!(exchange(&mut s, &get_request(), None).is_err());
        // Endless CONTINUATION frames: stopped at MAX_HEADER_BLOCK.
        let chunk = vec![0x40u8; 16_000];
        let mut frames: Vec<(u8, u8, u32, &[u8])> =
            vec![(FRAME_SETTINGS, 0, 0, &[]), (FRAME_HEADERS, 0, 1, &chunk)];
        for _ in 0..40 {
            frames.push((FRAME_CONTINUATION, 0, 1, &chunk));
        }
        let err = exchange(&mut scripted(&frames), &get_request(), None).unwrap_err();
        assert!(err.contains("header block too large"), "{err}");
        // A frame over the 16 KiB we allow.
        let big = vec![0u8; 20_000];
        let err = exchange(
            &mut scripted(&[(FRAME_SETTINGS, 0, 0, &[]), (FRAME_DATA, 0, 1, &big)]),
            &get_request(),
            None,
        )
        .unwrap_err();
        assert!(err.contains("SETTINGS_MAX_FRAME_SIZE"), "{err}");
    }

    /// Malformed control frames must produce an error, never a panic.
    #[test]
    fn malformed_frames_error_instead_of_panicking() {
        // WINDOW_UPDATE with a 2-byte payload.
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_WINDOW_UPDATE, 0, 0, &[0, 1]),
        ]);
        assert!(exchange(&mut s, &get_request(), None).is_err());

        // PUSH_PROMISE with an empty payload.
        let mut s = scripted(&[(FRAME_SETTINGS, 0, 0, &[]), (FRAME_PUSH_PROMISE, 0, 1, &[])]);
        assert!(exchange(&mut s, &get_request(), None).is_err());

        // HEADERS marked PADDED with an empty payload.
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_PADDED, 1, &[]),
        ]);
        assert!(exchange(&mut s, &get_request(), None).is_err());

        // HEADERS marked PRIORITY but shorter than the 5-byte prefix.
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS | FLAG_PRIORITY, 1, &[0, 0]),
        ]);
        assert!(exchange(&mut s, &get_request(), None).is_err());

        // DATA marked PADDED whose pad length exceeds the frame.
        let mut s = scripted(&[
            (FRAME_SETTINGS, 0, 0, &[]),
            (FRAME_HEADERS, FLAG_END_HEADERS, 1, &[0x88]),
            (FRAME_DATA, FLAG_END_STREAM | FLAG_PADDED, 1, &[9, b'x']),
        ]);
        assert!(exchange(&mut s, &get_request(), None).is_err());

        // GOAWAY with a truncated payload.
        let mut s = scripted(&[(FRAME_SETTINGS, 0, 0, &[]), (FRAME_GOAWAY, 0, 0, &[0, 0])]);
        assert!(exchange(&mut s, &get_request(), None).is_err());
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
        let resp = exchange(&mut s, &get_request(), None).expect("reassembled response");
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
                    write_frame(s, FRAME_WINDOW_UPDATE, 0, 0, &10_000_000u32.to_be_bytes())
                        .unwrap();
                }
                FRAME_SETTINGS if f.flags & FLAG_ACK == 0 => {
                    write_frame(s, FRAME_SETTINGS, FLAG_ACK, 0, &[]).unwrap();
                }
                FRAME_DATA => {
                    body.extend_from_slice(&f.payload);
                    write_frame(
                        s,
                        FRAME_WINDOW_UPDATE,
                        0,
                        0,
                        &(f.payload.len() as u32).to_be_bytes(),
                    )
                    .unwrap();
                    write_frame(
                        s,
                        FRAME_WINDOW_UPDATE,
                        0,
                        1,
                        &(f.payload.len() as u32).to_be_bytes(),
                    )
                    .unwrap();
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

    #[test]
    fn window_update_overflow_is_rejected_without_changing_state() {
        let mut rx = Rx::new(1);
        rx.send_window = 1;
        let mut stream = scripted(&[]);
        let mut sink = None;
        let err = rx
            .handle(
                &mut stream,
                Frame {
                    ty: FRAME_WINDOW_UPDATE,
                    flags: 0,
                    stream: 0,
                    payload: 0x7fff_ffffu32.to_be_bytes().to_vec(),
                },
                &mut sink,
            )
            .unwrap_err();
        assert!(err.contains("overflow"), "{err}");
        assert_eq!(rx.send_window, 1);
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
            s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            serve_flow_control(&mut s, expected);
        });
        let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let req = H2Request {
            method: "POST".into(),
            scheme: "http".into(),
            authority: "127.0.0.1".into(),
            path: "/upload".into(),
            headers: vec![],
            body,
            connection: None,
        };
        let resp = exchange(&mut tcp, &req, None).expect("flow-controlled upload");
        t.join().unwrap();
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));
        assert!(resp.ends_with(b"ok"));
    }
}
