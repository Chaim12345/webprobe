//! interactsh client: Collaborator on a public OAST host (oast.pro & co).
//!
//! Burp's Collaborator is a public service the scanner embeds payloads for
//! and later polls. WebProbe's local listeners only see loopback traffic, so
//! a target on the internet can never reach them. This client registers with
//! a public interactsh server (projectdiscovery/interactsh protocol) and polls
//! it, so out-of-band payloads resolve and are observed like Burp's.
//!
//! Protocol (interactsh client, v1):
//! * register: `POST /register` with `{"public-key": b64(PEM(PKIX RSA pub)),
//!   "secret-key": <uuid>, "correlation-id": <20 chars>}`
//! * payload host: `<correlation-id><13-char nonce>.<server>` — any DNS,
//!   HTTP or SMTP interaction naming it is recorded for the correlation id
//! * poll: `GET /poll?id=<cid>&secret=<secret>` -> `{"data": [b64...],
//!   "aes_key": b64(RSA-OAEP-SHA256(key))}`; each data item is
//!   `iv(16) || AES-CTR(json)` with the unwrapped key (CTR, big-endian
//!   128-bit counter; verified live — a CFB decrypt is right only for the
//!   first block, which both modes share)
//! * deregister: `POST /deregister` with `{"correlation-id","secret-key"}`
//!
//! Routing: every control-server connection (register, poll, deregister)
//! follows the effective upstream route for the server's host (per-
//! destination rules, then the global setting) via
//! `upstream::connect_tls_target` — direct only when that route says
//! direct, an HTTP CONNECT or SOCKS5 tunnel when a proxy is configured.
//! A custom OOB server is an intended distinct destination but is not
//! exempt from a configured proxy. A route that cannot be established
//! fails the operation with its diagnostic (registration fails, a poll
//! round errors) — never a silent direct fallback. The TLS verification
//! name and the Host header stay the OOB server, distinct from the
//! transport endpoint the route dials; with a proxy, the proxy resolves
//! the server name (CONNECT authority / SOCKS5 remote DNS).

use std::io::Write;
#[cfg(test)]
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rand::Rng;

/// Public interactsh servers run by projectdiscovery.
pub const DEFAULT_SERVERS: [&str; 6] = [
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
];
const CID_LEN: usize = 20;
const NONCE_LEN: usize = 13;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn random_lower_alnum(n: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

fn random_uuid() -> String {
    let b: [u8; 16] = rand::thread_rng().r#gen();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-{:02x}{:02x}-{}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6] & 0x0f,
        b[7],
        (b[8] & 0x3f) | 0x80,
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    )
}

/// One interaction as reported by the server (decrypted JSON).
#[derive(Clone, Debug, Default)]
pub struct RemoteInteraction {
    pub protocol: String,
    pub unique_id: String,
    pub full_id: String,
    pub q_type: String,
    pub raw_request: String,
    pub remote_address: String,
    pub smtp_from: String,
}

/// Parse one decrypted interaction message.
pub fn parse_interaction(json: &str) -> Option<RemoteInteraction> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let s = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let it = RemoteInteraction {
        protocol: s("protocol").to_ascii_lowercase(),
        unique_id: s("unique-id").to_ascii_lowercase(),
        full_id: s("full-id").to_ascii_lowercase(),
        q_type: s("q-type"),
        raw_request: s("raw-request"),
        remote_address: s("remote-address"),
        smtp_from: s("smtp-from"),
    };
    if it.protocol.is_empty() {
        return None;
    }
    Some(it)
}

/// Unwrap the AES key (RSA-OAEP-SHA256) and decrypt each `iv || AES-CTR`
/// message. Messages that fail to decode are skipped.
pub fn decrypt_messages(
    key: &rsa::PrivateKey,
    aes_key_b64: &str,
    data: &[String],
) -> Result<Vec<String>, String> {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    let wrapped = B64
        .decode(aes_key_b64.trim())
        .map_err(|e| format!("aes_key base64: {e}"))?;
    let aes_key = key
        .oaep_decrypt::<rsa::sha2::Sha256>(&wrapped)
        .map_err(|e| format!("aes_key unwrap: {e}"))?;
    let mut out = Vec::new();
    for item in data {
        let Ok(raw) = B64.decode(item.trim()) else {
            continue;
        };
        if raw.len() < 16 {
            continue;
        }
        let (iv, ct) = raw.split_at(16);
        let mut buf = ct.to_vec();
        let ok = match aes_key.len() {
            32 => ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&aes_key, iv)
                .map(|mut c| c.apply_keystream(&mut buf))
                .is_ok(),
            24 => ctr::Ctr128BE::<aes::Aes192>::new_from_slices(&aes_key, iv)
                .map(|mut c| c.apply_keystream(&mut buf))
                .is_ok(),
            16 => ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&aes_key, iv)
                .map(|mut c| c.apply_keystream(&mut buf))
                .is_ok(),
            n => return Err(format!("unsupported AES key length {n}")),
        };
        if ok {
            out.push(String::from_utf8_lossy(&buf).into_owned());
        }
    }
    Ok(out)
}

/// Minimal HTTPS/1.1 request to the interactsh server (Connection: close).
/// `auth` is a private server's token, sent as interactsh's `Authorization`
/// header (`interactsh-server -auth` / `-token`).
/// Largest interactsh response read (polls carry interaction batches).
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

fn https_request(
    host: &str,
    port: u16,
    route: &crate::upstream::UpstreamConfig,
    auth: Option<&str>,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, Vec<u8>), String> {
    let mut cfg = (*crate::tls::verified_client_config()).clone();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    https_request_with(host, port, route, Arc::new(cfg), auth, method, path, body)
}

/// `https_request` with the TLS client config supplied (tests inject a
/// fixture root; production uses the verified system roots).
#[expect(
    clippy::too_many_arguments,
    reason = "one request's worth of parameters"
)]
fn https_request_with(
    host: &str,
    port: u16,
    route: &crate::upstream::UpstreamConfig,
    cfg: Arc<rustls::ClientConfig>,
    auth: Option<&str>,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, Vec<u8>), String> {
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("server name: {e}"))?;
    let conn = rustls::ClientConnection::new(cfg, name).map_err(|e| format!("tls: {e}"))?;
    // The transport follows the effective route; a failed route fails the
    // request, it never falls back to a direct connection.
    let sock = crate::upstream::connect_tls_target(route, host, port)
        .map_err(|e| format!("route to {host} ({:?}): {e}", route.kind))?;
    sock.set_read_timeout(Some(Duration::from_secs(20))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let mut tls = rustls::StreamOwned::new(conn, sock);
    let body = body.unwrap_or("");
    let host_hdr = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let auth = auth
        .filter(|t| !t.is_empty())
        .map(|t| format!("Authorization: {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: webprobe-interactsh\r\n{auth}Accept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    // Bounded: a server streaming without end cannot exhaust memory.
    // (Servers that close without close_notify still sent a full response.)
    let resp = crate::util::read_capped(&mut tls, MAX_RESPONSE, "the interactsh response")
        .map_err(|e| format!("read: {e}"))?;
    let p = crate::util::parse_http(&resp);
    let status: u16 = p
        .status
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut payload = resp[p.head_len.min(resp.len())..].to_vec();
    let chunked = crate::util::get_header(&p.headers, "Transfer-Encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked && let Some((decoded, _)) = crate::codec::decode_chunked(&payload) {
        payload = decoded;
    }
    Ok((status, payload))
}

/// A registered interactsh session.
pub struct Session {
    /// Payload domain (the server's host name).
    pub server: String,
    /// API port (443 unless the server was given as `host:port`).
    pub port: u16,
    pub cid: String,
    secret: String,
    token: Option<String>,
    key: rsa::PrivateKey,
    /// The upstream route every control-server connection follows,
    /// captured at registration; a route change applies to the next
    /// registration.
    route: crate::upstream::UpstreamConfig,
}

/// Split a server setting (`host`, `host:port`, optionally with `https://`
/// and a trailing slash) into the payload domain and the API port.
pub fn parse_server(server: &str) -> Result<(String, u16), String> {
    let s = server.trim();
    let s = s
        .strip_prefix("https://")
        .unwrap_or(s)
        .trim_end_matches('/')
        .to_ascii_lowercase();
    if s.is_empty() || s.contains('/') || s.contains(char::is_whitespace) {
        return Err(format!("not a server host name: {server:?}"));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => p
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0 && !h.is_empty())
            .map(|p| (h.to_string(), p))
            .ok_or_else(|| format!("bad port in {server:?}")),
        None => Ok((s, 443)),
    }
}

impl Session {
    /// Generate an RSA key pair and register a correlation id, dialing
    /// over `route` (direct only when the route says direct).
    pub fn register(server: &str, route: &crate::upstream::UpstreamConfig) -> Result<Self, String> {
        Self::register_with(server, None, route)
    }

    /// Register on a server that may be private: `server` is `host` or
    /// `host:port`, `token` its auth token when it requires one. All
    /// control-server traffic of the session (this registration, polls,
    /// deregistration) transports over `route`.
    pub fn register_with(
        server: &str,
        token: Option<&str>,
        route: &crate::upstream::UpstreamConfig,
    ) -> Result<Self, String> {
        use rsa::pkcs8::EncodePublicKey;
        let (server, port) = parse_server(server)?;
        let key = rsa::PrivateKey::new(&mut crate::tls::OsRandom, 2048)
            .map_err(|e| format!("rsa: {e}"))?;
        let der = key
            .to_public_key()
            .to_public_key_der()
            .map_err(|e| format!("pkix: {e}"))?;
        let pem = crate::tls::pem_armor(der.as_bytes(), "RSA PUBLIC KEY");
        let s = Self {
            server,
            port,
            token: token
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_string),
            cid: random_lower_alnum(CID_LEN),
            secret: random_uuid(),
            key,
            route: route.clone(),
        };
        let body = serde_json::json!({
            "public-key": B64.encode(pem.as_bytes()),
            "secret-key": s.secret,
            "correlation-id": s.cid,
        })
        .to_string();
        let (status, resp) = s.request("POST", "/register", Some(&body))?;
        if status != 200 {
            return Err(format!(
                "register on {} failed: HTTP {status} {}",
                s.server,
                String::from_utf8_lossy(&resp)
            ));
        }
        Ok(s)
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, Vec<u8>), String> {
        https_request(
            &self.server,
            self.port,
            &self.route,
            self.token.as_deref(),
            method,
            path,
            body,
        )
    }

    /// A fresh payload id (`cid + nonce`) and host (`id.server`).
    pub fn new_payload(&self) -> (String, String) {
        let id = format!("{}{}", self.cid, random_lower_alnum(NONCE_LEN));
        let host = format!("{id}.{}", self.server);
        (id, host)
    }

    /// Fetch and decrypt pending interactions.
    pub fn poll(&self) -> Result<Vec<RemoteInteraction>, String> {
        let path = format!("/poll?id={}&secret={}", self.cid, self.secret);
        let (status, resp) = self.request("GET", &path, None)?;
        if status != 200 {
            return Err(format!(
                "poll on {} failed: HTTP {status} {}",
                self.server,
                String::from_utf8_lossy(&resp)
            ));
        }
        if std::env::var_os("WB_INTERACTSH_DEBUG").is_some() {
            tracing::debug!(target: "webprobe", event_code = "oast.poll.received",
                status, response_bytes = resp.len(), "Collaborator poll received (body omitted)");
        }
        let v: serde_json::Value =
            serde_json::from_slice(&resp).map_err(|e| format!("poll json: {e}"))?;
        let data: Vec<String> = v
            .get("data")
            .and_then(|d| d.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if data.is_empty() {
            return Ok(Vec::new());
        }
        // The server's PollResponse JSON tag is "aes-key" (interactsh
        // server package); accept the snake_case variant too for robustness.
        let aes_key = v
            .get("aes-key")
            .or_else(|| v.get("aes_key"))
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        Ok(decrypt_messages(&self.key, aes_key, &data)?
            .iter()
            .filter_map(|m| parse_interaction(m))
            .collect())
    }

    pub fn deregister(&self) {
        let body = serde_json::json!({ "correlation-id": self.cid, "secret-key": self.secret })
            .to_string();
        let _ = self.request("POST", "/deregister", Some(&body));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    #[test]
    fn server_settings_parse_host_and_port() {
        assert_eq!(parse_server("oast.pro").unwrap(), ("oast.pro".into(), 443));
        assert_eq!(
            parse_server(" https://OAST.Example.com:8443/ ").unwrap(),
            ("oast.example.com".into(), 8443)
        );
        assert!(parse_server("a.b:0").is_err());
        assert!(parse_server("a.b/x").is_err());
        assert!(parse_server("").is_err());
    }

    #[test]
    fn decrypts_interactsh_messages() {
        use ctr::cipher::{KeyIvInit, StreamCipher};
        let mut rng = rand::thread_rng();
        let key = rsa::PrivateKey::new(&mut crate::tls::OsRandom, 1024).unwrap();
        let aes_key: [u8; 32] = rng.r#gen();
        let wrapped = key
            .to_public_key()
            .oaep_encrypt::<rsa::sha2::Sha256>(&aes_key)
            .unwrap();
        let msg = r#"{"protocol":"smtp","unique-id":"ABCDEFGHIJKLMNOPQRST1234567890abc","full-id":"abcdefghijklmnopqrst1234567890abc","raw-request":"MAIL FROM:<a@b>","remote-address":"203.0.113.9","smtp-from":"a@b","timestamp":"2026-11-16T00:00:00Z"}"#;
        let iv: [u8; 16] = rng.r#gen();
        let mut ct = msg.as_bytes().to_vec();
        ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&aes_key, &iv)
            .unwrap()
            .apply_keystream(&mut ct);
        let item = B64.encode([iv.to_vec(), ct].concat());
        let out =
            decrypt_messages(&key, &B64.encode(wrapped), &[item, "not-base64!".into()]).unwrap();
        assert_eq!(out, vec![msg.to_string()]);
        let it = parse_interaction(&out[0]).unwrap();
        assert_eq!(it.protocol, "smtp");
        assert_eq!(
            it.unique_id, "abcdefghijklmnopqrst1234567890abc",
            "ids are lower-cased for matching"
        );
        assert_eq!(it.smtp_from, "a@b");
        assert!(parse_interaction("{}").is_none());
    }

    /// #251: a wrapped key that is not a valid RSA-OAEP-SHA256 ciphertext for
    /// this key is an error, not a panic and not an empty success. The move to
    /// `rsa` 0.10 changed the unwrap call; this pins the failure path.
    #[test]
    fn invalid_oaep_ciphertext_is_an_error() {
        use rsa::traits::PublicKeyParts;
        let key = rsa::PrivateKey::new(&mut crate::tls::OsRandom, 1024).unwrap();
        // A full-size block of zeros cannot carry a valid OAEP encoding.
        let garbage = B64.encode(vec![0u8; key.size()]);
        let err = decrypt_messages(&key, &garbage, &[]).unwrap_err();
        assert!(err.starts_with("aes_key unwrap:"), "{err}");
        // A block longer than the modulus fails the size check first.
        let oversized = B64.encode(vec![0u8; key.size() + 1]);
        assert!(decrypt_messages(&key, &oversized, &[]).is_err());
        // The key field itself still reports its own base64 errors.
        let err = decrypt_messages(&key, "not base64!", &[]).unwrap_err();
        assert!(err.starts_with("aes_key base64:"), "{err}");
    }

    /// Live round trip against a public server (network; run with
    /// `cargo test interactsh -- --ignored`).
    #[test]
    #[ignore]
    fn live_round_trip_on_public_server() {
        let s = Session::register(
            DEFAULT_SERVERS[0],
            &crate::upstream::UpstreamConfig::default(),
        )
        .expect("register");
        let (id, host) = s.new_payload();
        // An HTTP hit on the payload host, exactly as a vulnerable target would make.
        let addr = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 80u16))
            .unwrap()
            .next()
            .unwrap();
        let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).unwrap();
        sock.write_all(
            format!("GET /wb-live HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
        let mut sink = Vec::new();
        let _ = sock.read_to_end(&mut sink);
        eprintln!(
            "hit {host} ({addr}) -> {}",
            String::from_utf8_lossy(&sink[..sink.len().min(200)])
        );
        let mut seen = Vec::new();
        for _ in 0..10 {
            std::thread::sleep(Duration::from_secs(3));
            seen.extend(s.poll().expect("poll"));
            if seen
                .iter()
                .any(|i| i.protocol == "http" && i.unique_id == id)
            {
                break;
            }
        }
        s.deregister();
        assert!(
            seen.iter().any(|i| i.protocol == "http"
                && i.unique_id == id
                && i.raw_request.contains("/wb-live")),
            "interactions: {seen:?}"
        );
    }

    /// Live: which SMTP recipient form does the server attribute to our id?
    /// Burp's address helper (burp.Zbzl.Zm) uses `<id>@<domain>` by default
    /// and `user@<id>.<domain>` when minimising false negatives.
    #[test]
    #[ignore]
    fn live_smtp_recipient_forms() {
        let s = Session::register(
            DEFAULT_SERVERS[0],
            &crate::upstream::UpstreamConfig::default(),
        )
        .expect("register");
        let (id_a, _) = s.new_payload();
        let (id_b, host_b) = s.new_payload();
        let mut sock = TcpStream::connect((s.server.as_str(), 25)).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let line = |sock: &mut TcpStream, cmd: &str| {
            if !cmd.is_empty() {
                sock.write_all(cmd.as_bytes()).unwrap();
            }
            let mut b = [0u8; 512];
            let n = sock.read(&mut b).unwrap_or(0);
            eprintln!(
                "{} -> {}",
                cmd.trim(),
                String::from_utf8_lossy(&b[..n]).trim()
            );
        };
        line(&mut sock, "");
        line(&mut sock, "EHLO webprobe.test\r\n");
        line(&mut sock, "MAIL FROM:<probe@webprobe.test>\r\n");
        line(&mut sock, &format!("RCPT TO:<{id_a}@{}>\r\n", s.server));
        line(&mut sock, &format!("RCPT TO:<user@{host_b}>\r\n"));
        line(&mut sock, "DATA\r\n");
        line(&mut sock, "Subject: t\r\n\r\nhello\r\n.\r\n");
        line(&mut sock, "QUIT\r\n");
        let mut seen = Vec::new();
        for _ in 0..6 {
            std::thread::sleep(Duration::from_secs(3));
            seen.extend(s.poll().expect("poll"));
        }
        s.deregister();
        let smtp: Vec<_> = seen
            .iter()
            .filter(|i| i.protocol == "smtp")
            .map(|i| i.unique_id.clone())
            .collect();
        eprintln!("smtp unique ids: {smtp:?}  a={id_a}  b={id_b}");
        assert!(!smtp.is_empty(), "no SMTP interaction reported");
    }

    // ---- routing fixtures (register/poll over the effective route) ----

    /// The full request helper with an injectable client config, so the
    /// fixture can trust its own root instead of the system roots.
    fn request_with_roots(
        host: &str,
        port: u16,
        route: &crate::upstream::UpstreamConfig,
        root: rustls::pki_types::CertificateDer<'static>,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, Vec<u8>), String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).map_err(|e| format!("root: {e}"))?;
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        https_request_with(host, port, route, Arc::new(cfg), None, method, path, body)
    }

    fn tls_server_config(
        names: &[&str],
    ) -> (
        Arc<rustls::ServerConfig>,
        rustls::pki_types::CertificateDer<'static>,
    ) {
        let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(
            names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
                )
                .unwrap(),
        );
        (config, cert.der().clone())
    }

    fn read_head(r: &mut impl std::io::Read) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match r.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => head.push(byte[0]),
            }
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    /// A listener that only counts connections: any direct fallback shows
    /// up here.
    fn counting_bait() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits2 = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                hits2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        (port, hits)
    }

    /// Register-shaped and poll-shaped requests must travel through the
    /// configured HTTP proxy's CONNECT tunnel (verification name the OOB
    /// server, transport endpoint the proxy); the "target" port counts
    /// direct dials and must stay at zero.
    #[test]
    fn control_requests_route_through_an_http_connect_proxy() {
        let (server_config, cert) = tls_server_config(&["localhost"]);
        let (target_port, bait_hits) = counting_bait();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        let proxy_thread = std::thread::spawn(move || {
            for stream in proxy.incoming().take(2).flatten() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut stream = stream;
                let head = read_head(&mut stream);
                tx.send(head).unwrap();
                stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .unwrap();
                let mut server = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(server_config.clone()).unwrap(),
                    stream,
                );
                let req_head = read_head(&mut server);
                let len: usize = req_head
                    .split("\r\n")
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                // Read the body before answering: closing a socket with
                // unread data can RST the response away.
                let mut left = len;
                let mut buf = [0u8; 4096];
                while left > 0 {
                    let take = left.min(buf.len());
                    let n = server.read(&mut buf[..take]).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    left -= n;
                }
                let body = if req_head.contains("/register") {
                    "{}"
                } else {
                    "{\"data\":[]}"
                };
                tx.send(req_head).unwrap();
                server
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                let _ = server.flush();
            }
        });
        let route = crate::upstream::UpstreamConfig {
            kind: crate::upstream::UpstreamKind::Http,
            host: "127.0.0.1".into(),
            port: proxy_port.to_string(),
            ..Default::default()
        };
        let (status, _) = request_with_roots(
            "localhost",
            target_port,
            &route,
            cert.clone(),
            "POST",
            "/register",
            Some("{\"public-key\":\"x\"}"),
        )
        .expect("register over the tunnel");
        assert_eq!(status, 200);
        let (status, _) = request_with_roots(
            "localhost",
            target_port,
            &route,
            cert,
            "GET",
            "/poll?id=x&secret=y",
            None,
        )
        .expect("poll over the tunnel");
        assert_eq!(status, 200);
        let connect1 = rx.recv().unwrap();
        let req1 = rx.recv().unwrap();
        let connect2 = rx.recv().unwrap();
        let req2 = rx.recv().unwrap();
        for head in [&connect1, &connect2] {
            assert!(
                head.starts_with(&format!("CONNECT localhost:{target_port} HTTP/1.1\r\n")),
                "{head}"
            );
        }
        assert!(req1.starts_with("POST /register HTTP/1.1\r\n"), "{req1}");
        assert!(
            req1.contains(&format!("\r\nHost: localhost:{target_port}\r\n")),
            "{req1}"
        );
        assert!(
            req2.starts_with("GET /poll?id=x&secret=y HTTP/1.1\r\n"),
            "{req2}"
        );
        proxy_thread.join().unwrap();
        assert_eq!(
            bait_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "zero direct connections to the control server"
        );
    }

    /// Registration fails closed when the route fails (proxy rejects the
    /// CONNECT): the error names the route and the target sees nothing.
    #[test]
    fn register_fails_closed_when_the_route_fails() {
        let (target_port, bait_hits) = counting_bait();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Some(Ok(mut stream)) = proxy.incoming().next() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let _ = read_head(&mut stream);
                stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                    )
                    .unwrap();
            }
        });
        let route = crate::upstream::UpstreamConfig {
            kind: crate::upstream::UpstreamKind::Http,
            host: "127.0.0.1".into(),
            port: proxy_port.to_string(),
            ..Default::default()
        };
        let err = Session::register_with(&format!("localhost:{target_port}"), None, &route)
            .err()
            .expect("a rejected CONNECT must fail the registration");
        assert!(err.contains("407"), "{err}");
        assert!(err.contains("route"), "diagnostic names the route: {err}");
        assert_eq!(
            bait_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "zero direct connections on route failure"
        );
    }

    /// An unusable route (HTTP kind with no proxy configured) also fails
    /// closed before anything is dialed.
    #[test]
    fn register_fails_closed_on_an_unusable_route() {
        let (target_port, bait_hits) = counting_bait();
        let route = crate::upstream::UpstreamConfig {
            kind: crate::upstream::UpstreamKind::Http,
            host: String::new(),
            port: String::new(),
            ..Default::default()
        };
        let err = Session::register_with(&format!("localhost:{target_port}"), None, &route)
            .err()
            .expect("an unusable route must fail closed");
        assert!(err.contains("upstream proxy"), "{err}");
        assert_eq!(bait_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn payload_ids_follow_the_interactsh_layout() {
        assert_eq!(random_lower_alnum(CID_LEN).len(), 20);
        let u = random_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(u.as_bytes()[14], b'4');
    }
}

#[cfg(test)]
#[path = "interactsh_route_tests.rs"]
mod interactsh_route_tests;
