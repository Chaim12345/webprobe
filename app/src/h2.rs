// Minimal synchronous HTTP/2 client (RFC 9113 subset) used for upstream
// requests when ALPN negotiates `h2` or a server accepts an `h2c` upgrade.
//
// Scope: one request per connection, no push, small request bodies. Responses
// are converted to a normalized HTTP/1.1-shaped byte string so history, the
// editor and the scanner see the same shape as HTTP/1.x traffic.

use std::io::{Read, Write};

use hpack::{Decoder, Encoder};

/// `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` — the connection preface (RFC 9113 §3.4).
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;

const DEFAULT_WINDOW: u32 = 65535;
const MAX_FRAME: usize = 1 << 24;

fn write_frame<W: Write>(w: &mut W, ty: u8, flags: u8, stream: u32, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len();
    if len >= MAX_FRAME {
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
    if len >= MAX_FRAME {
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

fn strip_padding(flags: u8, payload: &[u8]) -> &[u8] {
    if flags & FLAG_PADDED != 0 && !payload.is_empty() {
        let pad = payload[0] as usize;
        let end = payload.len().saturating_sub(pad).max(1);
        &payload[1..end]
    } else {
        payload
    }
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
        name.to_ascii_lowercase().as_str(),
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "http2-settings"
    ) || name.to_ascii_lowercase().starts_with("proxy-")
}

/// Perform one request over an established stream. `stream` must already carry
/// the HTTP/2 connection preface state (nothing written yet is required: the
/// preface and initial SETTINGS are sent here).
pub fn exchange<S: Read + Write>(stream: &mut S, req: &H2Request) -> Result<Vec<u8>, String> {
    stream.write_all(PREFACE).map_err(|e| format!("h2 preface: {e}"))?;
    // Our SETTINGS: ENABLE_PUSH=0 (id 0x2), INITIAL_WINDOW_SIZE default.
    write_frame(stream, FRAME_SETTINGS, 0, 0, &[0, 2, 0, 0, 0, 0]).map_err(|e| format!("h2 settings: {e}"))?;

    let mut enc = Encoder::new();
    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), req.method.as_bytes().to_vec()),
        (b":scheme".to_vec(), req.scheme.as_bytes().to_vec()),
        (b":authority".to_vec(), req.authority.as_bytes().to_vec()),
        (b":path".to_vec(), req.path.as_bytes().to_vec()),
    ];
    for (k, v) in &req.headers {
        if !is_connection_header(k) {
            headers.push((k.as_bytes().to_vec(), v.as_bytes().to_vec()));
        }
    }
    let block = enc.encode(headers.iter().map(|(k, v)| (k.as_slice(), v.as_slice())));
    let end_stream = req.body.is_empty();
    let flags = FLAG_END_HEADERS | if end_stream { FLAG_END_STREAM } else { 0 };
    write_frame(stream, FRAME_HEADERS, flags, 1, &block).map_err(|e| format!("h2 headers: {e}"))?;
    if !end_stream {
        write_frame(stream, FRAME_DATA, FLAG_END_STREAM, 1, &req.body).map_err(|e| format!("h2 data: {e}"))?;
    }

    // Read until the response on stream 1 ends. Connection-level control frames
    // are handled as they arrive; HEADERS blocks may span CONTINUATION frames.
    let mut dec = Decoder::new();
    let mut status: Option<String> = None;
    let mut out_headers: Vec<(String, String)> = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    let mut got_headers = false;
    let mut header_block: Vec<u8> = Vec::new();
    let mut in_continuation = false;
    let mut send_window: i64 = DEFAULT_WINDOW as i64;
    let mut stream_window: i64 = DEFAULT_WINDOW as i64;

    loop {
        let f = read_frame(stream).map_err(|e| format!("h2 read: {e}"))?;
        match f.ty {
            FRAME_SETTINGS => {
                if f.flags & FLAG_ACK == 0 {
                    // Ack the server's settings and apply INITIAL_WINDOW_SIZE.
                    for chunk in f.payload.chunks_exact(6) {
                        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                        let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                        if id == 0x4 {
                            stream_window = val as i64;
                        }
                    }
                    write_frame(stream, FRAME_SETTINGS, FLAG_ACK, 0, &[]).map_err(|e| format!("h2 settings ack: {e}"))?;
                }
            }
            FRAME_PING => {
                if f.flags & FLAG_ACK == 0 {
                    write_frame(stream, FRAME_PING, FLAG_ACK, 0, &f.payload).map_err(|e| format!("h2 ping: {e}"))?;
                }
            }
            FRAME_WINDOW_UPDATE => {
                let inc = u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]) as i64;
                if f.stream == 0 {
                    send_window += inc;
                } else {
                    stream_window += inc;
                }
            }
            FRAME_GOAWAY => {
                return Err("h2: server sent GOAWAY".into());
            }
            FRAME_RST_STREAM if f.stream == 1 => {
                return Err("h2: stream reset by server".into());
            }
            FRAME_HEADERS if f.stream == 1 => {
                let payload = strip_padding(f.flags, &f.payload);
                header_block.extend_from_slice(payload);
                if f.flags & FLAG_END_HEADERS != 0 {
                    let hs = dec.decode(&header_block).map_err(|e| format!("h2 decode: {e:?}"))?;
                    header_block.clear();
                    in_continuation = false;
                    for (name, value) in hs {
                        let name = String::from_utf8_lossy(&name).into_owned();
                        let value = String::from_utf8_lossy(&value).into_owned();
                        if let Some(s) = name.strip_prefix(':') {
                            if s == "status" {
                                status = Some(value.clone());
                            }
                            // other pseudo-headers are dropped from the view
                        } else {
                            out_headers.push((name, value));
                        }
                    }
                    got_headers = true;
                } else {
                    in_continuation = true;
                }
                if f.flags & FLAG_END_STREAM != 0 {
                    break;
                }
            }
            FRAME_CONTINUATION if f.stream == 1 && in_continuation => {
                header_block.extend_from_slice(&f.payload);
                if f.flags & FLAG_END_HEADERS != 0 {
                    let hs = dec.decode(&header_block).map_err(|e| format!("h2 decode: {e:?}"))?;
                    header_block.clear();
                    in_continuation = false;
                    for (name, value) in hs {
                        let name = String::from_utf8_lossy(&name).into_owned();
                        let value = String::from_utf8_lossy(&value).into_owned();
                        if let Some(s) = name.strip_prefix(':') {
                            if s == "status" {
                                status = Some(value.clone());
                            }
                        } else {
                            out_headers.push((name, value));
                        }
                    }
                    got_headers = true;
                }
            }
            FRAME_DATA if f.stream == 1 => {
                let payload = strip_padding(f.flags, &f.payload);
                body.extend_from_slice(payload);
                // Replenish flow control for what we consumed.
                let consumed = payload.len() as u32;
                if consumed > 0 {
                    let inc = consumed.to_be_bytes();
                    write_frame(stream, FRAME_WINDOW_UPDATE, 0, 0, &inc).ok();
                    write_frame(stream, FRAME_WINDOW_UPDATE, 0, 1, &inc).ok();
                }
                if f.flags & FLAG_END_STREAM != 0 {
                    break;
                }
            }
            _ => {
                // PRIORITY, PUSH_PROMISE and unknown frames are ignored.
                if f.ty == 0x5 {
                    // Refuse server push on the promised stream.
                    let promised = u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]);
                    write_frame(stream, FRAME_RST_STREAM, 0, promised, &4u32.to_be_bytes()).ok();
                }
            }
        }
    }

    let status = status.ok_or("h2: response without :status")?;
    if !got_headers {
        return Err("h2: response without headers".into());
    }
    let _ = (send_window, stream_window);

    // Normalize to the HTTP/1.1 shape the rest of the app understands.
    let mut out = Vec::with_capacity(256 + body.len());
    out.extend_from_slice(format!("HTTP/1.1 {status}\r\n").as_bytes());
    for (k, v) in &out_headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(&body);
    Ok(out)
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
    Some(H2Request {
        method: parts.method.clone(),
        scheme: scheme.to_string(),
        authority,
        path: if parts.path.is_empty() { "/".into() } else { parts.path.clone() },
        headers,
        body: raw[parts.head_len..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}