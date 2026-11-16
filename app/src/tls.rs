// The proxy's certificate authority and per-host TLS server configurations for
// CONNECT. Like Burp's CA (kept in its user settings), the CA persists across
// restarts so a browser or OS that trusts it keeps trusting it: the key and
// certificate parameters live in ~/.config/webprobe/ca.json (mode 0600; set
// WEBPROBE_CA_DIR to move it). No operating-system trust store is touched.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use rand::RngCore;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SerialNumber, PKCS_RSA_SHA256,
};
use rsa::pkcs8::EncodePrivateKey;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use time::{Duration, OffsetDateTime};

const RSA_BITS: usize = 2048;
const CA_SERIAL_BITS: usize = 32;
const CA_NOT_BEFORE_YEAR: i32 = 2014;
const CA_VALIDITY_YEARS: i32 = 10;
const LEAF_BACKDATE_DAYS: i64 = 14;
const LEAF_VALIDITY_DAYS: i64 = 199;

fn generate_rsa_key() -> Result<KeyPair, String> {
    let mut rng = rand::rngs::OsRng;
    let key = rsa::RsaPrivateKey::new(&mut rng, RSA_BITS).map_err(|e| format!("generate RSA key: {e}"))?;
    let der = key.to_pkcs8_der().map_err(|e| format!("encode RSA key: {e}"))?;
    KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(der.as_bytes()), &PKCS_RSA_SHA256)
        .map_err(|e| format!("import RSA key: {e}"))
}

fn add_calendar_years(value: OffsetDateTime, years: i32) -> Result<OffsetDateTime, String> {
    let year = value.year() + years;
    value.replace_year(year).or_else(|_| value.replace_day(28).and_then(|v| v.replace_year(year)))
        .map_err(|e| format!("set certificate year: {e}"))
}

// burp.Zg88.Z_: set CA notBefore to 2014 only when the current year is later.
fn ca_not_before_year(current_year: i32) -> i32 {
    current_year.min(CA_NOT_BEFORE_YEAR)
}

struct CaSeed {
    serial: u64,
    not_before: i64,
    not_after: i64,
}

/// Where the CA is kept: $WEBPROBE_CA_DIR, else $XDG_CONFIG_HOME/webprobe or
/// ~/.config/webprobe.
pub fn default_ca_dir() -> Option<std::path::PathBuf> {
    if let Some(d) = std::env::var_os("WEBPROBE_CA_DIR") {
        return Some(d.into());
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))?;
    Some(base.join("webprobe"))
}

/// Write a file only its owner can read (the CA private key is inside).
fn write_private(dir: &std::path::Path, file: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let tmp = file.with_extension("tmp");
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(bytes)?;
    }
    std::fs::rename(tmp, file)
}

pub struct MitmAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    next_serial: AtomicI32,
    hosts: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl MitmAuthority {
    /// The persistent CA (created on first run), or an in-memory one in tests.
    pub fn new() -> Result<Self, String> {
        if cfg!(test) {
            return Self::load_or_create(None);
        }
        Self::load_or_create(default_ca_dir())
    }

    /// Load the CA saved in `dir`, or create one and save it there.
    pub fn load_or_create(dir: Option<std::path::PathBuf>) -> Result<Self, String> {
        let file = dir.as_ref().map(|d| d.join("ca.json"));
        if let Some(f) = &file {
            if let Ok(text) = std::fs::read_to_string(f) {
                match Self::from_saved(&text) {
                    Ok(ca) => return Ok(ca),
                    Err(e) => eprintln!("webprobe: ignoring unreadable CA file {}: {e}", f.display()),
                }
            }
        }
        let now = OffsetDateTime::now_utc();
        let mut rng = rand::rngs::OsRng;
        let mut serial_bytes = [0u8; CA_SERIAL_BITS / 8];
        rng.fill_bytes(&mut serial_bytes);
        let seed = CaSeed {
            serial: u64::from(u32::from_be_bytes(serial_bytes)),
            not_before: add_calendar_years(now, ca_not_before_year(now.year()) - now.year())?.unix_timestamp(),
            not_after: add_calendar_years(now, CA_VALIDITY_YEARS)?.unix_timestamp(),
        };
        let ca_key = generate_rsa_key()?;
        if let (Some(d), Some(f)) = (&dir, &file) {
            let saved = serde_json::json!({
                "serial": seed.serial,
                "not_before": seed.not_before,
                "not_after": seed.not_after,
                "key_pkcs8": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ca_key.serialize_der()),
            });
            if let Err(e) = write_private(d, f, saved.to_string().as_bytes()) {
                eprintln!("webprobe: could not save the CA to {}: {e}; it will change on the next start", f.display());
            }
        }
        Self::from_seed(&seed, ca_key)
    }

    fn from_saved(text: &str) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let seed = CaSeed {
            serial: v["serial"].as_u64().ok_or("no serial")?,
            not_before: v["not_before"].as_i64().ok_or("no not_before")?,
            not_after: v["not_after"].as_i64().ok_or("no not_after")?,
        };
        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v["key_pkcs8"].as_str().ok_or("no key")?)
            .map_err(|e| e.to_string())?;
        let key = KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(der), &PKCS_RSA_SHA256)
            .map_err(|e| format!("CA key: {e}"))?;
        Self::from_seed(&seed, key)
    }

    /// The CA certificate is rebuilt from its saved parameters and key; RSA
    /// PKCS#1 v1.5 signatures are deterministic, so it is byte-identical to
    /// the one a browser or OS was told to trust.
    fn from_seed(seed: &CaSeed, ca_key: KeyPair) -> Result<Self, String> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "WebProbe Local CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.serial_number = Some(SerialNumber::from(seed.serial));
        params.not_before = OffsetDateTime::from_unix_timestamp(seed.not_before).map_err(|e| e.to_string())?;
        params.not_after = OffsetDateTime::from_unix_timestamp(seed.not_after).map_err(|e| e.to_string())?;
        let ca_cert = params.self_signed(&ca_key).map_err(|e| format!("generate CA: {e}"))?;
        let ca_der = ca_cert.der().clone();
        let ca_pem = ca_cert.pem();
        let now = OffsetDateTime::now_utc();
        let leaf_seed = (now.unix_timestamp_nanos() / 1_000_000) as i32;
        Ok(Self {
            ca_cert,
            ca_key,
            ca_der,
            ca_pem,
            next_serial: AtomicI32::new(leaf_seed),
            hosts: Mutex::new(HashMap::new()),
        })
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn ca_der(&self) -> CertificateDer<'static> {
        self.ca_der.clone()
    }

    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        if let Some(config) = self.hosts.lock().unwrap().get(host) {
            return Ok(config.clone());
        }
        let config = self.build_config(host, Vec::new())?;
        self.hosts.lock().unwrap().insert(host.to_string(), config.clone());
        Ok(config)
    }

    /// A fresh server config (not cached) advertising the given ALPN protocols,
    /// e.g. `h2` for an HTTP/2 upstream test server.
    pub fn server_config_with_alpn(&self, host: &str, alpn: Vec<Vec<u8>>) -> Result<Arc<ServerConfig>, String> {
        self.build_config(host, alpn)
    }

    /// A server config that requires and verifies client certificates signed by
    /// the given roots (upstream mTLS test servers).
    pub fn server_config_with_client_auth(&self, host: &str, client_roots: RootCertStore) -> Result<Arc<ServerConfig>, String> {
        use rustls::server::WebPkiClientVerifier;
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|e| format!("configure client verifier: {e}"))?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| format!("invalid host for certificate: {e}"))?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let not_before = OffsetDateTime::now_utc() - Duration::days(LEAF_BACKDATE_DAYS);
        params.not_before = not_before;
        params.not_after = not_before + Duration::days(LEAF_VALIDITY_DAYS);
        let serial = self.next_serial.fetch_add(1, Ordering::Relaxed).unsigned_abs();
        params.serial_number = Some(SerialNumber::from(u64::from(serial)));
        let leaf_key = generate_rsa_key()?;
        let leaf = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| format!("sign host certificate: {e}"))?;
        let chain = vec![leaf.der().clone(), self.ca_der.clone()];
        let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key.into())
            .map_err(|e| format!("configure host TLS: {e}"))?;
        Ok(Arc::new(config))
    }

    /// A client certificate signed by this CA, returned as PEM strings
    /// (certificate, PKCS8 private key) for upstream mTLS.
    pub fn client_certificate(&self, common_name: &str) -> Result<(String, String), String> {
        let mut params = CertificateParams::new(Vec::new())
            .map_err(|e| format!("invalid client certificate name: {e}"))?;
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let not_before = OffsetDateTime::now_utc() - Duration::days(LEAF_BACKDATE_DAYS);
        params.not_before = not_before;
        params.not_after = not_before + Duration::days(LEAF_VALIDITY_DAYS);
        let serial = self.next_serial.fetch_add(1, Ordering::Relaxed).unsigned_abs();
        params.serial_number = Some(SerialNumber::from(u64::from(serial)));
        let key = generate_rsa_key()?;
        let cert = params
            .signed_by(&key, &self.ca_cert, &self.ca_key)
            .map_err(|e| format!("sign client certificate: {e}"))?;
        Ok((cert.pem(), pem_armor(&key.serialize_der(), "PRIVATE KEY")))
    }

    fn build_config(&self, host: &str, alpn: Vec<Vec<u8>>) -> Result<Arc<ServerConfig>, String> {
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| format!("invalid host for certificate: {e}"))?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let not_before = OffsetDateTime::now_utc() - Duration::days(LEAF_BACKDATE_DAYS);
        params.not_before = not_before;
        params.not_after = not_before + Duration::days(LEAF_VALIDITY_DAYS);
        // Java uses Math.abs(previous), then wrapping increment. rcgen only emits positive serials;
        // unsigned_abs deliberately maps Java's negative MIN_VALUE overflow to +2147483648.
        let serial = self.next_serial.fetch_add(1, Ordering::Relaxed).unsigned_abs();
        params.serial_number = Some(SerialNumber::from(u64::from(serial)));
        let leaf_key = generate_rsa_key()?;
        let leaf = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| format!("sign host certificate: {e}"))?;
        let chain = vec![leaf.der().clone(), self.ca_der.clone()];
        let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key.into())
            .map_err(|e| format!("configure host TLS: {e}"))?;
        config.alpn_protocols = alpn;
        Ok(Arc::new(config))
    }
}

/// TLS to the targets the proxy and tools talk to. Like Burp (which does not
/// validate upstream server certificates by default), any certificate is
/// accepted: self-signed, private-CA, expired or wrong-name servers are
/// exactly what gets tested. The handshake signatures are still checked, so
/// the peer must hold the key of the certificate it presents.
pub fn upstream_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
        .with_no_client_auth();
    // Offer HTTP/2 via ALPN; servers without it fall back to HTTP/1.1.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

/// TLS to WebProbe's own external services (the public OAST server), which
/// must be the real thing: verified against the WebPKI roots.
pub fn verified_client_config() -> Arc<ClientConfig> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

#[derive(Debug)]
struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A client config that presents a client certificate (mTLS) to upstream
/// servers, trusting the given roots.
pub fn pem_armor(der: &[u8], label: &str) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        b64.push(TBL[(n >> 18) as usize & 63] as char);
        b64.push(TBL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            b64.push(TBL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            b64.push(TBL[n as usize & 63] as char);
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

pub fn client_auth_config(cert_pem: &str, key_pem: &str, roots: RootCertStore) -> Result<Arc<ClientConfig>, String> {
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
        let normalized = pem.replace("\\n", "\n");
        let body: String = normalized
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        data_encoding_decode(&body)
    }
    // Minimal PEM-armour decode (base64 body between BEGIN/END lines).
    fn data_encoding_decode(body: &str) -> Result<Vec<u8>, String> {
        const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut lut = [255u8; 256];
        for (i, &c) in TBL.iter().enumerate() {
            lut[c as usize] = i as u8;
        }
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0u32;
        for c in body.bytes() {
            if c == b'=' || c.is_ascii_whitespace() {
                continue;
            }
            let v = lut[c as usize];
            if v == 255 {
                return Err("invalid base64 in PEM body".into());
            }
            buf = (buf << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        Ok(out)
    }
    let cert_der = pem_to_der(cert_pem)?;
    let key_der = pem_to_der(key_pem)?;
    let key: rustls::pki_types::PrivateKeyDer<'static> =
        rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![CertificateDer::from(cert_der)], key)
        .map_err(|e| format!("configure client certificate: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    #[test]
    fn ca_persists_byte_identical_across_restarts() {
        let d = std::env::temp_dir().join(format!("wp-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let a = super::MitmAuthority::load_or_create(Some(d.clone())).unwrap();
        let b = super::MitmAuthority::load_or_create(Some(d.clone())).unwrap();
        assert_eq!(a.ca_der(), b.ca_der(), "same CA after a restart");
        assert_eq!(a.ca_pem(), b.ca_pem());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.join("ca.json")).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "private key file is owner-only");
        }
        // A leaf issued after the restart chains to the saved CA.
        assert!(b.server_config("example.test").is_ok());
        let _ = std::fs::remove_dir_all(&d);
        let c = super::MitmAuthority::load_or_create(None).unwrap();
        assert_ne!(c.ca_der(), a.ca_der(), "no directory: a fresh in-memory CA");
    }

    use super::{ca_not_before_year, CA_NOT_BEFORE_YEAR};

    #[test]
    fn ca_not_before_uses_original_year_clamp() {
        assert_eq!(ca_not_before_year(2026), CA_NOT_BEFORE_YEAR);
        assert_eq!(ca_not_before_year(2013), 2013);
    }
}
