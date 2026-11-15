// In-memory certificate authority and per-host TLS server configurations for CONNECT.
// No operating-system trust settings or on-disk private keys are changed.

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

pub struct MitmAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    next_serial: AtomicI32,
    hosts: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl MitmAuthority {
    pub fn new() -> Result<Self, String> {
        let now = OffsetDateTime::now_utc();
        let mut rng = rand::rngs::OsRng;
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "WebProbe Local CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let mut serial_bytes = [0u8; CA_SERIAL_BITS / 8];
        rng.fill_bytes(&mut serial_bytes);
        params.serial_number = Some(SerialNumber::from(u64::from(u32::from_be_bytes(serial_bytes))));
        params.not_before = add_calendar_years(now, ca_not_before_year(now.year()) - now.year())?;
        params.not_after = add_calendar_years(now, CA_VALIDITY_YEARS)?;
        let ca_key = generate_rsa_key()?;
        let ca_cert = params.self_signed(&ca_key).map_err(|e| format!("generate CA: {e}"))?;
        let ca_der = ca_cert.der().clone();
        let ca_pem = ca_cert.pem();
        let seed = (now.unix_timestamp_nanos() / 1_000_000) as i32;
        Ok(Self {
            ca_cert,
            ca_key,
            ca_der,
            ca_pem,
            next_serial: AtomicI32::new(seed),
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

pub fn upstream_config() -> Arc<ClientConfig> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Offer HTTP/2 via ALPN; servers without it fall back to HTTP/1.1.
    let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
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
    use super::{ca_not_before_year, CA_NOT_BEFORE_YEAR};

    #[test]
    fn ca_not_before_uses_original_year_clamp() {
        assert_eq!(ca_not_before_year(2026), CA_NOT_BEFORE_YEAR);
        assert_eq!(ca_not_before_year(2013), 2013);
    }
}
