// Utilities: codecs, HTTP parsing, PNG writing. No external crates.

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------- Base64 ----------
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::new();
    for c in s.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let v = if c.is_ascii_uppercase() {
            c as u32 - 'A' as u32
        } else if c.is_ascii_lowercase() {
            c as u32 - 'a' as u32 + 26
        } else if c.is_ascii_digit() {
            c as u32 - '0' as u32 + 52
        } else if c == '+' {
            62
        } else if c == '/' {
            63
        } else {
            return Err(format!("not a base64 character: {c}"));
        };
        bits = (bits << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Ok(out)
}

// ---------- Hex ----------
pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex string has an odd number of digits".into());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).ok_or_else(|| format!("bad hex at {i}"))?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or_else(|| format!("bad hex at {}", i + 1))?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

// ---------- URL ----------
fn is_url_safe(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~')
}

pub fn url_encode_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        if is_url_safe(b as char) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            let hex = &s[i + 1..i + 3];
            if hex.len() == 2 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(b'%');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------- HTML entities ----------
pub fn html_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if (c as u32) > 127 => out.push_str(&format!("&#{:04};", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn html_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(end) = s[i..].find(';') {
                let entity = &s[i + 1..i + end];
                let decoded = if let Some(num) = entity.strip_prefix('#') {
                    let (digits, radix) = if num.len() > 1
                        && (num.starts_with('x') || num.starts_with('X'))
                    {
                        (&num[1..], 16u32)
                    } else {
                        (num, 10u32)
                    };
                    u32::from_str_radix(digits, radix)
                        .ok()
                        .and_then(char::from_u32)
                        .map(|c| c.to_string())
                } else {
                    match entity {
                        "amp" => Some("&".to_string()),
                        "lt" => Some("<".to_string()),
                        "gt" => Some(">".to_string()),
                        "quot" => Some("\"".to_string()),
                        "apos" => Some("'".to_string()),
                        "nbsp" => Some("\u{00a0}".to_string()),
                        _ => None,
                    }
                };
                if let Some(d) = decoded {
                    out.push_str(&d);
                    i += end + 1;
                    continue;
                }
            }
        }
        let c = s[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(c);
        i += c.len_utf8();
    }
    out
}

// ---------- HTTP parsing ----------
#[derive(Clone, Debug, Default)]
pub struct HttpParts {
    pub first: String,
    pub method: String,
    pub path: String,
    pub status: String,
    pub headers: Vec<(String, String)>,
    pub head_len: usize,
}

pub fn parse_http(raw: &[u8]) -> HttpParts {
    let mut p = HttpParts::default();
    let head_end = find_sub(raw, b"\r\n\r\n").map(|i| i + 4).unwrap_or_else(|| {
        find_sub(raw, b"\n\n").map(|i| i + 2).unwrap_or(raw.len())
    });
    p.head_len = head_end.min(raw.len());
    let head = String::from_utf8_lossy(&raw[..p.head_len]);
    let mut lines = head.lines();
    if let Some(first) = lines.next() {
        p.first = first.trim().to_string();
        let mut it = p.first.split_whitespace();
        let t1 = it.next().unwrap_or("");
        let t2 = it.next().unwrap_or("");
        if t1.starts_with("HTTP/") {
            p.status = t2.to_string();
            p.method = "RESPONSE".into();
        } else {
            p.method = t1.to_string();
            p.path = t2.to_string();
            p.status = String::new();
        }
    }
    let mut last_header: Option<usize> = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        // Obsolete line folding (RFC 9112 §5.2): a continuation line belongs to
        // the previous header, separated by a single space.
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(i) = last_header {
                let extra = line.trim();
                p.headers[i].1.push(' ');
                p.headers[i].1.push_str(extra);
            }
            continue;
        }
        if let Some(colon) = line.find(':') {
            p.headers.push((line[..colon].trim().to_string(), line[colon + 1..].trim().to_string()));
            last_header = Some(p.headers.len() - 1);
        }
    }
    p
}

pub fn get_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Byte offset just past the CRLFCRLF (or LFLF) that ends the message head.
pub fn find_head_end(raw: &[u8]) -> Option<usize> {
    find_sub(raw, b"\r\n\r\n").map(|i| i + 4).or_else(|| find_sub(raw, b"\n\n").map(|i| i + 2))
}

/// Replace or add an arbitrary request header.
pub fn patch_header(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    let head_end = find_sub(raw, b"\r\n\r\n").map(|i| i + 4).unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..head_end]);
    let mut lines: Vec<String> = head
        .lines()
        .map(|l| l.to_string())
        .collect();
    // strip existing instances of the header
    lines.retain(|l| !l.to_ascii_lowercase().starts_with(&format!("{}:", name.to_ascii_lowercase())));
    let mut out = Vec::with_capacity(raw.len() + 32);
    let first = lines.first().cloned().unwrap_or_default();
    out.extend_from_slice(first.as_bytes());
    out.extend_from_slice(b"\r\n");
    for line in &lines[1..] {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&raw[head_end..]);
    out
}

/// Convert an absolute-form request URI (proxy form) to origin form before
/// sending to an origin server (HTTP/1.1 spec §5.3.2).
pub fn origin_form(raw: &[u8]) -> Vec<u8> {    let line_end = match raw.iter().position(|&b| b == b'\n') {
        Some(i) => i + 1,
        None => return raw.to_vec(),
    };
    let line = String::from_utf8_lossy(&raw[..line_end]).trim_end().to_string();
    let mut it = line.split_whitespace();
    let method = it.next().unwrap_or("");
    let uri = it.next().unwrap_or("");
    let ver = it.next().unwrap_or("HTTP/1.1");
    if method.is_empty() || uri.is_empty() || method.eq_ignore_ascii_case("CONNECT") {
        return raw.to_vec();
    }
    let new_uri = if let Some(rest) = uri.strip_prefix("http://") {
        match rest.find('/') {
            Some(i) => rest[i..].to_string(),
            None => "/".to_string(),
        }
    } else {
        return raw.to_vec();
    };
    let mut out = Vec::with_capacity(raw.len());
    out.extend_from_slice(format!("{method} {new_uri} {ver}\r\n").as_bytes());
    out.extend_from_slice(&raw[line_end.min(raw.len())..]);
    out
}

// ---------- Hex viewer ----------
pub fn hex_view(data: &[u8], limit: usize) -> String {
    let data = &data[..data.len().min(limit)];
    let mut s = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        s.push_str(&format!("{:04x}  ", i * 16));
        for b in chunk {
            s.push_str(&format!("{b:02x} "));
        }
        let pad = 16 - chunk.len();
        for _ in 0..pad {
            s.push_str("   ");
        }
        s.push_str(" |");
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' };
            s.push(c);
        }
        s.push_str("|\n");
    }
    s
}

// ---------- PNG writer (store-mode zlib, no crates) ----------
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, t) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
        }
        *t = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for b in data {
        crc = table[((crc ^ *b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for d in data {
        a = (a + *d as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let mut body = Vec::with_capacity(4 + data.len());
    body.extend_from_slice(kind);
    body.extend_from_slice(data);
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc32(&body).to_be_bytes());
}

/// Encode an RGBA8 image as PNG bytes (store-mode zlib, no external crates).
pub fn encode_png(w: u32, h: u32, rgba: &[u8]) -> Vec<u8> {
    let mut png = Vec::with_capacity(16 + w as usize * h as usize * 4 + 1024);
    png.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(6); // RGBA
    ihdr.extend_from_slice(&[0, 0, 0]);
    png_chunk(&mut png, b"IHDR", &ihdr);

    // raw scanlines with filter 0
    let stride = w as usize * 4;
    let mut raw = Vec::with_capacity(h as usize * (stride + 1));
    for y in 0..h as usize {
        raw.push(0u8);
        let start = y * stride;
        let end = start + stride;
        if end <= rgba.len() {
            raw.extend_from_slice(&rgba[start..end]);
        }
    }

    // zlib with stored blocks
    let mut idat = Vec::with_capacity(raw.len() + raw.len() / 65535 * 5 + 64);
    idat.push(0x78);
    idat.push(0x01);
    let mut off = 0usize;
    while off < raw.len() {
        let n = (raw.len() - off).min(65535);
        let last = off + n >= raw.len();
        idat.push(if last { 1 } else { 0 });
        idat.extend_from_slice(&(n as u16).to_le_bytes());
        idat.extend_from_slice(&(!(n as u16)).to_le_bytes());
        idat.extend_from_slice(&raw[off..off + n]);
        off += n;
    }
    idat.extend_from_slice(&adler32(&raw).to_be_bytes());
    png_chunk(&mut png, b"IDAT", &idat);
    png_chunk(&mut png, b"IEND", &[]);
    png
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A-04: obsolete line folding (RFC 9112 §5.2) is joined into one value.
    #[test]
    fn folded_header_lines_are_joined() {
        let raw = b"HTTP/1.1 200 OK\r\nX-Long: first\r\n\tsecond\r\n  third\r\nContent-Length: 0\r\n\r\n";
        let p = parse_http(raw);
        let long = get_header(&p.headers, "X-Long").unwrap();
        assert_eq!(long, "first second third");
        assert_eq!(get_header(&p.headers, "Content-Length").unwrap(), "0");
    }

    /// A-04: repeated headers are all preserved in order (get_header reads the first).
    #[test]
    fn duplicate_headers_are_preserved() {
        let raw = b"GET / HTTP/1.1\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nHost: x\r\n\r\n";
        let p = parse_http(raw);
        let cookies: Vec<&str> = p
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(cookies, ["a=1", "b=2"]);
        assert_eq!(get_header(&p.headers, "Set-Cookie").unwrap(), "a=1");
    }

    /// A-04: absolute-form is reduced to origin-form for the upstream.
    #[test]
    fn absolute_form_becomes_origin_form() {
        let raw = b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let out = origin_form(raw);
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com"));
        // origin-form input passes through untouched
        let direct = b"POST /submit HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(origin_form(direct).as_slice(), &direct[..]);
    }
}


/// Start a child in its own process group, so it and everything it forks
/// (a browser's zygotes, renderers, GPU and crash handlers) can be ended
/// together. Killing only the main browser process leaves the rest orphaned
/// and running: dozens of processes and gigabytes per browser.
pub fn own_process_group(cmd: &mut std::process::Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
}

/// End a process group started with `own_process_group` (SIGTERM, then
/// SIGKILL after `grace`), plus any stragglers that still carry `marker` in
/// their command line (a browser's unique --user-data-dir), which catches
/// helpers that moved to another group.
pub fn kill_process_tree(pid: u32, marker: Option<&str>, grace: std::time::Duration) {
    #[cfg(unix)]
    {
        let group = format!("-{pid}");
        let _ = std::process::Command::new("kill").args(["-TERM", "--", &group]).output();
        let t0 = std::time::Instant::now();
        while t0.elapsed() < grace {
            let alive = std::process::Command::new("kill").args(["-0", "--", &group]).output().map(|o| o.status.success()).unwrap_or(false);
            if !alive {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = std::process::Command::new("kill").args(["-KILL", "--", &group]).output();
        if let Some(m) = marker {
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for e in entries.flatten() {
                    let Ok(p) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
                    if p == std::process::id() {
                        continue;
                    }
                    let cmdline = std::fs::read(format!("/proc/{p}/cmdline")).unwrap_or_default();
                    if String::from_utf8_lossy(&cmdline).contains(m) {
                        let _ = std::process::Command::new("kill").args(["-KILL", &p.to_string()]).output();
                    }
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (pid, marker, grace);
    }
}


#[cfg(all(test, unix))]
mod process_tree_tests {
    fn alive_with(marker: &str) -> usize {
        std::fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
            .filter(|p| *p != std::process::id())
            .filter(|p| {
                let c = std::fs::read(format!("/proc/{p}/cmdline")).unwrap_or_default();
                let st = std::fs::read_to_string(format!("/proc/{p}/stat")).unwrap_or_default();
                String::from_utf8_lossy(&c).contains(marker) && !st.contains(") Z ")
            })
            .count()
    }

    #[test]
    fn a_forking_child_is_ended_with_all_its_descendants() {
        let marker = format!("wp-tree-test-{}", std::process::id());
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", &format!("sleep 300 & sleep 300 & exec -a {marker} sleep 300")]);
        super::own_process_group(&mut cmd);
        let mut child = cmd.spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        super::kill_process_tree(child.id(), Some(&marker), std::time::Duration::from_secs(2));
        let _ = child.wait();
        let pgid_left = std::process::Command::new("kill").args(["-0", "--", &format!("-{}", child.id())]).output().unwrap().status.success();
        assert!(!pgid_left, "the background sleeps must be gone too");
        assert_eq!(alive_with(&marker), 0);
    }

    /// The real leak: a killed browser left its zygotes and renderers
    /// running (about 70 processes each). Every one must be gone.
    #[test]
    fn a_headless_browser_leaves_no_processes_behind() {
        let Some(bin) = crate::crawl::chromium_binary() else { return };
        let profile = std::env::temp_dir().join(format!("wp-tree-browser-{}", std::process::id()));
        let mut cmd = std::process::Command::new(bin);
        cmd.args(["--headless=new", "--no-sandbox", "--disable-gpu", &format!("--user-data-dir={}", profile.display()), "about:blank"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        super::own_process_group(&mut cmd);
        let mut child = cmd.spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_secs(3));
        let marker = profile.display().to_string();
        assert!(alive_with(&marker) > 1, "browser should have spawned helpers");
        super::kill_process_tree(child.id(), Some(&marker), std::time::Duration::from_secs(2));
        let _ = child.wait();
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(alive_with(&marker), 0, "no browser process may survive");
        let _ = std::fs::remove_dir_all(&profile);
    }
}
