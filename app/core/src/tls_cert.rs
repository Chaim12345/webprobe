//! TLS certificate analysis (Burp G.13, KB 01000100, type 16777472).
//!
//! burp.Zut6 captures the `SSLSession` on the host's shared Robots/TLS
//! exchange, builds certificate details for the presented chain and flags
//! not-yet-valid/expired dates, hostname mismatch (wildcard aware) and
//! trust failure (`Zut6.java:75-107,167-264`). WebProbe's equivalent: one
//! TLS handshake per host with a recording verifier — the chain is kept
//! whether or not verification succeeds — then a pure analysis pass.
//!
//! `Zp64.java:12-52` always constructs the issue when the capture path
//! returns, with severity 3 for hostname/trust failures, 2 for validity
//! dates and 1 otherwise; the KB's typical severity is Medium. WebProbe
//! reports only flagged certificates, so the severities in use are High
//! (hostname/trust) and Medium (dates); the unflagged informational case
//! is not reported.

#[cfg(test)]
use std::io::Read as _;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};
use x509_parser::prelude::X509Certificate;
use x509_parser::parse_x509_certificate;

/// How the delegated verification of a captured chain ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyKind {
    Hostname,
    Validity,
    Trust,
}

/// What the recording verifier saw during one handshake: the presented
/// chain (end entity first) and the verification outcome.
#[derive(Clone, Debug, Default)]
pub struct TlsCapture {
    pub chain: Vec<Vec<u8>>,
    pub verify_error: Option<String>,
    pub error_kind: Option<VerifyKind>,
}

/// A certificate problem worth reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertFlag {
    NotYetValid,
    Expired,
    HostnameMismatch,
    Untrusted,
}

/// The verifier the chain is checked against: webpki over the configured
/// roots, or a reject-all when no trust anchors are configured at all
/// (webpki's builder refuses an empty store; the capture must still run).
#[derive(Debug)]
enum InnerVerifier {
    Webpki(Arc<WebPkiServerVerifier>),
    RejectAll,
}

impl InnerVerifier {
    fn verify(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], server_name: &ServerName<'_>, ocsp_response: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        match self {
            InnerVerifier::Webpki(v) => v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now),
            InnerVerifier::RejectAll => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        }
    }
}

#[derive(Debug)]
struct RecordingVerifier {
    inner: InnerVerifier,
    seen: Arc<Mutex<TlsCapture>>,
}

fn classify(error: &rustls::Error) -> VerifyKind {
    use rustls::CertificateError as Ce;
    match error {
        rustls::Error::InvalidCertificate(Ce::NotValidForName) | rustls::Error::InvalidCertificate(Ce::NotValidForNameContext { .. }) => VerifyKind::Hostname,
        rustls::Error::InvalidCertificate(Ce::Expired) | rustls::Error::InvalidCertificate(Ce::NotValidYet) => VerifyKind::Validity,
        _ => VerifyKind::Trust,
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.as_ref().to_vec()];
        chain.extend(intermediates.iter().map(|c| c.as_ref().to_vec()));
        let result = self.inner.verify(end_entity, intermediates, server_name, ocsp_response, now);
        let mut seen = self.seen.lock().unwrap();
        seen.chain = chain;
        if let Err(e) = &result {
            seen.verify_error = Some(e.to_string());
            seen.error_kind = Some(classify(e));
        }
        result
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        match &self.inner {
            InnerVerifier::Webpki(v) => v.verify_tls12_signature(message, cert, dss),
            InnerVerifier::RejectAll => Err(rustls::Error::General("no trust anchors configured".into())),
        }
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        match &self.inner {
            InnerVerifier::Webpki(v) => v.verify_tls13_signature(message, cert, dss),
            InnerVerifier::RejectAll => Err(rustls::Error::General("no trust anchors configured".into())),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        match &self.inner {
            InnerVerifier::Webpki(v) => v.supported_verify_schemes(),
            // The usual webpki set: an empty list would encode a broken
            // signature_algorithms extension in the ClientHello.
            InnerVerifier::RejectAll => vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
            ],
        }
    }
}

/// One TLS handshake against `host:port`, recording the presented chain.
/// The handshake's own outcome is discarded: a failed verification is the
/// interesting case, and the chain is captured either way. Returns None
/// when no TLS handshake happened at all (connection refused, reset).
pub fn capture(host: &str, port: u16, roots: &RootCertStore, timeout: Duration) -> Option<TlsCapture> {
    let seen: Arc<Mutex<TlsCapture>> = Arc::new(Mutex::new(TlsCapture::default()));
    let inner = match WebPkiServerVerifier::builder_with_provider(Arc::new(roots.clone()), rustls::crypto::ring::default_provider().into()).build() {
        Ok(v) => InnerVerifier::Webpki(v),
        Err(_) => InnerVerifier::RejectAll,
    };
    let verifier = RecordingVerifier { inner, seen: seen.clone() };
    let config = ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(verifier)).with_no_client_auth();
    let name = ServerName::try_from(host.to_string()).ok()?;
    let mut conn = ClientConnection::new(Arc::new(config), name).ok()?;
    // Try each resolved address: a name can map to families the server
    // does not listen on (localhost -> ::1 with an IPv4-only server).
    let mut tcp = None;
    for addr in (host, port).to_socket_addrs().ok()? {
        if let Ok(s) = TcpStream::connect_timeout(&addr, timeout) {
            tcp = Some(s);
            break;
        }
    }
    let mut tcp = tcp?;
    tcp.set_read_timeout(Some(timeout)).ok()?;
    tcp.set_write_timeout(Some(timeout)).ok()?;
    // Drive the handshake; the capture is recorded during it either way.
    let _ = conn.complete_io(&mut tcp);
    let seen = seen.lock().unwrap().clone();
    if seen.chain.is_empty() {
        return None;
    }
    Some(seen)
}

/// One hostname against one certificate dNSName/CN pattern: exact match,
/// or a `*.example.com` wildcard covering exactly one leading label
/// (burp.Zut6's wildcard handling). Case-insensitive.
fn pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // The host must be exactly one label longer than the suffix.
        return host.len() > suffix.len() + 1 && host.ends_with(&suffix) && host[..host.len() - suffix.len() - 1].bytes().all(|b| b != b'.') && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
    }
    pattern == host
}

/// The names the certificate is valid for: SAN dNSName entries when the
/// extension is present, otherwise the subject CN (the pre-SAN fallback
/// Burp's check shares).
fn cert_names(cert: &X509Certificate<'_>) -> Vec<String> {
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        let names: Vec<String> = san
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                _ => None,
            })
            .collect();
        if !names.is_empty() {
            return names;
        }
    }
    cert.subject()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok().map(str::to_string))
        .collect()
}

/// The flags a captured chain earns for `host` at `now`. Pure: testable
/// with generated certificates, no network.
pub fn analyze(capture: &TlsCapture, host: &str, now: SystemTime) -> Vec<CertFlag> {
    let mut flags = Vec::new();
    let mut push = |f: CertFlag| {
        if !flags.contains(&f) {
            flags.push(f);
        }
    };
    let mut parsed = false;
    if let Some(leaf) = capture.chain.first() {
        if let Ok((_, cert)) = parse_x509_certificate(leaf) {
            parsed = true;
            let ts = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
            let validity = cert.validity();
            if validity.not_before.timestamp() > ts {
                push(CertFlag::NotYetValid);
            }
            if validity.not_after.timestamp() < ts {
                push(CertFlag::Expired);
            }
            let names = cert_names(&cert);
            if !names.is_empty() && !names.iter().any(|n| pattern_matches(n, host)) {
                push(CertFlag::HostnameMismatch);
            }
        }
    }
    // The delegated verifier's outcome backs up (or, for a certificate we
    // could not parse, replaces) our own reading of the leaf.
    match capture.error_kind {
        Some(VerifyKind::Hostname) => push(CertFlag::HostnameMismatch),
        Some(VerifyKind::Validity) if !parsed => push(CertFlag::Expired),
        Some(VerifyKind::Trust) => push(CertFlag::Untrusted),
        _ => {}
    }
    flags
}

/// The report's severity: High for hostname/trust failures, Medium for
/// validity dates (Zp64's 3 and 2; the KB's typical severity is Medium).
pub fn severity(flags: &[CertFlag]) -> &'static str {
    if flags.iter().any(|f| matches!(f, CertFlag::HostnameMismatch | CertFlag::Untrusted)) {
        "high"
    } else {
        "medium"
    }
}

/// A short human summary of the leaf certificate for the issue detail.
pub fn leaf_summary(capture: &TlsCapture) -> String {
    let Some(leaf) = capture.chain.first() else { return String::new() };
    let Ok((_, cert)) = parse_x509_certificate(leaf) else { return String::new() };
    format!(
        "The certificate presented for this site is issued to {}, signed by {}, valid from {} to {}.",
        cert.subject(),
        cert.issuer(),
        cert.validity().not_before,
        cert.validity().not_after
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, CertifiedKey, KeyPair};
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use std::io::Write as _;
    use std::net::TcpListener;

    fn leaf_der(sans: &[&str], not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> Vec<u8> {
        let mut params = CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<String>>()).unwrap();
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn cap_for(der: Vec<u8>, kind: Option<VerifyKind>) -> TlsCapture {
        TlsCapture { chain: vec![der], verify_error: kind.map(|k| format!("{k:?}")), error_kind: kind }
    }

    #[test]
    fn valid_matching_cert_has_no_flags() {
        let cap = cap_for(leaf_der(&["example.com"], (2020, 1, 1), (2030, 1, 1)), None);
        assert!(analyze(&cap, "example.com", SystemTime::now()).is_empty());
    }

    #[test]
    fn expired_and_not_yet_valid_are_flagged() {
        let cap = cap_for(leaf_der(&["example.com"], (2020, 1, 1), (2021, 1, 1)), None);
        assert_eq!(analyze(&cap, "example.com", SystemTime::now()), vec![CertFlag::Expired]);
        let cap = cap_for(leaf_der(&["example.com"], (2030, 1, 1), (2031, 1, 1)), None);
        assert_eq!(analyze(&cap, "example.com", SystemTime::now()), vec![CertFlag::NotYetValid]);
    }

    #[test]
    fn hostname_matching_covers_wildcards_and_cn_fallback() {
        // Wildcard covers exactly one label, not the apex and not two.
        let cap = cap_for(leaf_der(&["*.example.com"], (2020, 1, 1), (2030, 1, 1)), None);
        assert!(analyze(&cap, "www.example.com", SystemTime::now()).is_empty());
        assert!(analyze(&cap, "example.com", SystemTime::now()).contains(&CertFlag::HostnameMismatch));
        assert!(analyze(&cap, "a.b.example.com", SystemTime::now()).contains(&CertFlag::HostnameMismatch));
        // A plain mismatch, case-insensitive both ways.
        let cap = cap_for(leaf_der(&["Other.COM"], (2020, 1, 1), (2030, 1, 1)), None);
        assert_eq!(analyze(&cap, "example.com", SystemTime::now()), vec![CertFlag::HostnameMismatch]);
    }

    #[test]
    fn verifier_kinds_fill_in_and_dedup() {
        let cap = cap_for(leaf_der(&["other.com"], (2020, 1, 1), (2030, 1, 1)), Some(VerifyKind::Hostname));
        assert_eq!(analyze(&cap, "example.com", SystemTime::now()), vec![CertFlag::HostnameMismatch]);
        let cap = cap_for(leaf_der(&["example.com"], (2020, 1, 1), (2030, 1, 1)), Some(VerifyKind::Trust));
        assert_eq!(analyze(&cap, "example.com", SystemTime::now()), vec![CertFlag::Untrusted]);
    }

    /// A capture against a local TLS server with a self-signed
    /// certificate: the chain arrives and an empty root store leaves the
    /// certificate untrusted.
    #[test]
    fn capture_records_the_chain_through_a_failing_handshake() {
        let CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()))
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // Two handshakes: the untrusted probe, then the trusted one.
            for stream in listener.incoming().take(2) {
                let Ok(stream) = stream else { return };
                let config = server_config.clone();
                std::thread::spawn(move || {
                    let mut server = StreamOwned::new(ServerConnection::new(config).unwrap(), stream);
                    let mut buf = [0u8; 64];
                    let _ = server.read(&mut buf);
                    let _ = server.flush();
                });
            }
        });
        let cap = capture("localhost", port, &RootCertStore::empty(), Duration::from_secs(10)).unwrap();
        assert_eq!(cap.chain.len(), 1);
        assert_eq!(cap.error_kind, Some(VerifyKind::Trust));
        assert!(analyze(&cap, "localhost", SystemTime::now()).contains(&CertFlag::Untrusted));
        // Trust the self-signed certificate and the handshake verifies;
        // no flags remain.
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let cap = capture("localhost", port, &roots, Duration::from_secs(10)).unwrap();
        assert!(cap.verify_error.is_none(), "{:?}", cap.verify_error);
        assert!(analyze(&cap, "localhost", SystemTime::now()).is_empty());
    }
}
