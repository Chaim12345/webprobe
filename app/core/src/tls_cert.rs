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
//!
//! Routing: the configured upstream route (Settings > Network > Upstream
//! proxy servers, per-destination rules then the global setting) is a
//! network/privacy boundary, so the capture's transport always follows it
//! through `upstream::connect_tls_target` — direct only when the effective
//! route says direct, an HTTP CONNECT tunnel or SOCKS5 negotiation when a
//! proxy is configured. A route that cannot be established fails closed
//! with its diagnostic as `Err`; there is never a silent direct fallback.
//! The TLS verification name (and the hostname analysis) always use the
//! target host, distinct from the transport endpoint the route dials.

use crate::sync::Mutex;
#[cfg(test)]
use std::io::Read as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::X509Certificate;

/// How the delegated verification of a captured chain ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyKind {
    Hostname,
    Validity,
    /// The chain did not lead to a configured trust anchor
    /// (`UnknownIssuer`): the only error that establishes a trust-chain
    /// failure.
    Trust,
    /// Anything else the verifier reported (bad signature, encoding,
    /// application-level rejection, a non-certificate handshake error):
    /// kept with its diagnostic, never read as a trust failure.
    Inconclusive,
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
    /// The delegated verifier reported a validity problem but the failing
    /// certificate could not be identified from the leaf (an unparseable
    /// leaf or a chain certificate), so expired vs not-yet-valid is unknown.
    ValidityUnknown,
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
    fn verify(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self {
            InnerVerifier::Webpki(v) => {
                v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            }
            InnerVerifier::RejectAll => Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            )),
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
        rustls::Error::InvalidCertificate(Ce::NotValidForName)
        | rustls::Error::InvalidCertificate(Ce::NotValidForNameContext { .. }) => {
            VerifyKind::Hostname
        }
        rustls::Error::InvalidCertificate(Ce::Expired)
        | rustls::Error::InvalidCertificate(Ce::NotValidYet) => VerifyKind::Validity,
        rustls::Error::InvalidCertificate(Ce::UnknownIssuer) => VerifyKind::Trust,
        // Bad signatures, encoding problems, application-level rejections and
        // non-certificate errors say nothing certain about the trust chain.
        _ => VerifyKind::Inconclusive,
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
        let result = self
            .inner
            .verify(end_entity, intermediates, server_name, ocsp_response, now);
        let mut seen = self.seen.lock();
        seen.chain = chain;
        if let Err(e) = &result {
            seen.verify_error = Some(e.to_string());
            seen.error_kind = Some(classify(e));
        }
        result
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        match &self.inner {
            InnerVerifier::Webpki(v) => v.verify_tls12_signature(message, cert, dss),
            InnerVerifier::RejectAll => {
                Err(rustls::Error::General("no trust anchors configured".into()))
            }
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        match &self.inner {
            InnerVerifier::Webpki(v) => v.verify_tls13_signature(message, cert, dss),
            InnerVerifier::RejectAll => {
                Err(rustls::Error::General("no trust anchors configured".into()))
            }
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

/// One TLS handshake against `host:port` over the configured `route`,
/// recording the presented chain. The handshake's own outcome is discarded:
/// a failed verification is the interesting case, and the chain is captured
/// either way. `Err` means the route itself failed (bad proxy config,
/// unreachable proxy, a rejected CONNECT): the failure is explicit and
/// nothing was sent to the target. `Ok(None)` means the transport came up
/// but no TLS handshake happened at all (a plain-HTTP service, a reset).
pub fn capture(
    host: &str,
    port: u16,
    route: &crate::upstream::UpstreamConfig,
    roots: &RootCertStore,
    timeout: Duration,
) -> Result<Option<TlsCapture>, String> {
    let seen: Arc<Mutex<TlsCapture>> = Arc::new(Mutex::new(TlsCapture::default()));
    let inner = match WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots.clone()),
        rustls::crypto::ring::default_provider().into(),
    )
    .build()
    {
        Ok(v) => InnerVerifier::Webpki(v),
        Err(_) => InnerVerifier::RejectAll,
    };
    let verifier = RecordingVerifier {
        inner,
        seen: seen.clone(),
    };
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid TLS verification name {host}: {e}"))?;
    let mut conn = ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    // The transport follows the effective route; fail closed, never fall
    // back to a direct connection.
    let mut tcp = crate::upstream::connect_tls_target(route, host, port)?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    // Drive the handshake; the capture is recorded during it either way.
    let _ = conn.complete_io(&mut tcp);
    let seen = seen.lock().clone();
    if seen.chain.is_empty() {
        return Ok(None);
    }
    Ok(Some(seen))
}

/// One hostname against one certificate dNSName/CN pattern: exact match,
/// or a `*.example.com` wildcard covering exactly one leading label
/// (burp.Zut6's wildcard handling). Case-insensitive.
fn pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // The host must be exactly one label longer than the suffix.
        return host.len() > suffix.len() + 1
            && host.ends_with(&suffix)
            && host[..host.len() - suffix.len() - 1]
                .bytes()
                .all(|b| b != b'.')
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
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
                // IP SANs count too: for an IP-literal target rustls accepts
                // on an IP SAN, and dropping them flags a false mismatch
                x509_parser::extensions::GeneralName::IPAddress(b) => match b.len() {
                    4 => Some(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()),
                    16 => {
                        let mut o = [0u8; 16];
                        o.copy_from_slice(b);
                        Some(std::net::Ipv6Addr::from(o).to_string())
                    }
                    _ => None,
                },
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
    let mut validity_from_leaf = false;
    if let Some(leaf) = capture.chain.first()
        && let Ok((_, cert)) = parse_x509_certificate(leaf)
    {
        let ts = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let validity = cert.validity();
        if validity.not_before.timestamp() > ts {
            validity_from_leaf = true;
            push(CertFlag::NotYetValid);
        }
        if validity.not_after.timestamp() < ts {
            validity_from_leaf = true;
            push(CertFlag::Expired);
        }
        let names = cert_names(&cert);
        if !names.is_empty() && !names.iter().any(|n| pattern_matches(n, host)) {
            push(CertFlag::HostnameMismatch);
        }
    }
    // The delegated verifier's outcome backs up (or, for a certificate we
    // could not parse, replaces) our own reading of the leaf. A validity
    // failure that our leaf read did not explain belongs to another
    // certificate in the chain (typically an expired intermediate).
    match capture.error_kind {
        Some(VerifyKind::Hostname) => push(CertFlag::HostnameMismatch),
        Some(VerifyKind::Validity) if !validity_from_leaf => push(CertFlag::ValidityUnknown),
        Some(VerifyKind::Trust) => push(CertFlag::Untrusted),
        // Inconclusive stays unflagged: the diagnostic travels in
        // `verify_error`, and no trust failure is claimed without proof.
        _ => {}
    }
    flags
}

/// The report's severity: High for hostname/trust failures, Medium for
/// validity dates (Zp64's 3 and 2; the KB's typical severity is Medium).
pub fn severity(flags: &[CertFlag]) -> &'static str {
    if flags
        .iter()
        .any(|f| matches!(f, CertFlag::HostnameMismatch | CertFlag::Untrusted))
    {
        "high"
    } else {
        "medium"
    }
}

/// A short human summary of the leaf certificate for the issue detail.
pub fn leaf_summary(capture: &TlsCapture) -> String {
    let Some(leaf) = capture.chain.first() else {
        return String::new();
    };
    let Ok((_, cert)) = parse_x509_certificate(leaf) else {
        return String::new();
    };
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
        let mut params =
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<String>>())
                .unwrap();
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn ip_literal_host_matches_ip_san() {
        // a cert carrying the target as an IP SAN (plus unrelated DNS names)
        // is not a hostname mismatch for that IP target
        let cap = cap_for(
            leaf_der(&["example.com", "10.0.0.9"], (2020, 1, 1), (2030, 1, 1)),
            None,
        );
        assert!(analyze(&cap, "10.0.0.9", SystemTime::now()).is_empty());
        // ...but a different IP still mismatches
        let flags = analyze(&cap, "10.0.0.10", SystemTime::now());
        assert!(flags.contains(&CertFlag::HostnameMismatch));
    }

    fn cap_for(der: Vec<u8>, kind: Option<VerifyKind>) -> TlsCapture {
        TlsCapture {
            chain: vec![der],
            verify_error: kind.map(|k| format!("{k:?}")),
            error_kind: kind,
        }
    }

    #[test]
    fn unparseable_leaf_with_a_validity_failure_is_unknown_not_expired() {
        let cap = cap_for(vec![0, 1, 2, 3], Some(VerifyKind::Validity));
        let flags = analyze(&cap, "example.com", SystemTime::now());
        assert!(flags.contains(&CertFlag::ValidityUnknown));
        assert!(!flags.contains(&CertFlag::Expired));
        assert!(!flags.contains(&CertFlag::NotYetValid));
        assert_eq!(severity(&flags), "medium");
    }

    #[test]
    fn parsed_leaf_with_a_chain_validity_failure_is_unknown() {
        // The leaf's own dates are fine, so the verifier's validity error
        // can only come from another certificate in the chain.
        let cap = cap_for(
            leaf_der(&["example.com"], (2020, 1, 1), (2030, 1, 1)),
            Some(VerifyKind::Validity),
        );
        let flags = analyze(&cap, "example.com", SystemTime::now());
        assert_eq!(flags, vec![CertFlag::ValidityUnknown]);
        assert_eq!(severity(&flags), "medium");
    }

    #[test]
    fn valid_matching_cert_has_no_flags() {
        let cap = cap_for(leaf_der(&["example.com"], (2020, 1, 1), (2030, 1, 1)), None);
        assert!(analyze(&cap, "example.com", SystemTime::now()).is_empty());
    }

    #[test]
    fn expired_and_not_yet_valid_are_flagged() {
        let cap = cap_for(leaf_der(&["example.com"], (2020, 1, 1), (2021, 1, 1)), None);
        assert_eq!(
            analyze(&cap, "example.com", SystemTime::now()),
            vec![CertFlag::Expired]
        );
        let cap = cap_for(leaf_der(&["example.com"], (2030, 1, 1), (2031, 1, 1)), None);
        assert_eq!(
            analyze(&cap, "example.com", SystemTime::now()),
            vec![CertFlag::NotYetValid]
        );
    }

    #[test]
    fn hostname_matching_covers_wildcards_and_cn_fallback() {
        // Wildcard covers exactly one label, not the apex and not two.
        let cap = cap_for(
            leaf_der(&["*.example.com"], (2020, 1, 1), (2030, 1, 1)),
            None,
        );
        assert!(analyze(&cap, "www.example.com", SystemTime::now()).is_empty());
        assert!(
            analyze(&cap, "example.com", SystemTime::now()).contains(&CertFlag::HostnameMismatch)
        );
        assert!(
            analyze(&cap, "a.b.example.com", SystemTime::now())
                .contains(&CertFlag::HostnameMismatch)
        );
        // A plain mismatch, case-insensitive both ways.
        let cap = cap_for(leaf_der(&["Other.COM"], (2020, 1, 1), (2030, 1, 1)), None);
        assert_eq!(
            analyze(&cap, "example.com", SystemTime::now()),
            vec![CertFlag::HostnameMismatch]
        );
    }

    #[test]
    fn unexpected_verifier_errors_are_inconclusive_not_trust() {
        // A certificate-error outside hostname/validity/UnknownIssuer (here:
        // a bad signature) must not read as "not issued by a trusted
        // authority": no flag is claimed and the diagnostic is kept.
        let cap = cap_for(
            leaf_der(&["example.com"], (2020, 1, 1), (2030, 1, 1)),
            Some(VerifyKind::Inconclusive),
        );
        assert!(analyze(&cap, "example.com", SystemTime::now()).is_empty());
        assert_eq!(cap.verify_error.as_deref(), Some("Inconclusive"));
        // classify() itself: BadSignature is not a trust-chain failure.
        assert_eq!(
            classify(&rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature
            )),
            VerifyKind::Inconclusive
        );
        assert_eq!(
            classify(&rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            )),
            VerifyKind::Trust
        );
    }

    #[test]
    fn verifier_kinds_fill_in_and_dedup() {
        let cap = cap_for(
            leaf_der(&["other.com"], (2020, 1, 1), (2030, 1, 1)),
            Some(VerifyKind::Hostname),
        );
        assert_eq!(
            analyze(&cap, "example.com", SystemTime::now()),
            vec![CertFlag::HostnameMismatch]
        );
        let cap = cap_for(
            leaf_der(&["example.com"], (2020, 1, 1), (2030, 1, 1)),
            Some(VerifyKind::Trust),
        );
        assert_eq!(
            analyze(&cap, "example.com", SystemTime::now()),
            vec![CertFlag::Untrusted]
        );
    }

    fn tls_server_config(
        names: &[&str],
    ) -> (
        Arc<ServerConfig>,
        rustls::pki_types::CertificateDer<'static>,
    ) {
        let CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(
            names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
                )
                .unwrap(),
        );
        (config, cert.der().clone())
    }

    fn serve_tls_on(stream: std::net::TcpStream, config: Arc<ServerConfig>) {
        std::thread::spawn(move || {
            let mut server = StreamOwned::new(ServerConnection::new(config).unwrap(), stream);
            let mut buf = [0u8; 64];
            let _ = server.read(&mut buf);
            let _ = server.flush();
        });
    }

    /// A port nothing listens on: any direct connection to it is refused.
    fn unbound_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        port
    }

    /// Read one HTTP head (CONNECT request) off a mock proxy stream.
    fn read_connect_head(stream: &mut std::net::TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    /// A capture against a local TLS server with a self-signed
    /// certificate: the chain arrives and an empty root store leaves the
    /// certificate untrusted.
    #[test]
    fn capture_records_the_chain_through_a_failing_handshake() {
        let (server_config, cert) = tls_server_config(&["localhost"]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // Two handshakes: the untrusted probe, then the trusted one.
            for stream in listener.incoming().take(2) {
                let Ok(stream) = stream else { return };
                serve_tls_on(stream, server_config.clone());
            }
        });
        let route = crate::upstream::UpstreamConfig::default(); // direct
        let cap = capture(
            "localhost",
            port,
            &route,
            &RootCertStore::empty(),
            Duration::from_secs(10),
        )
        .expect("direct route")
        .expect("chain captured through the failing handshake");
        assert_eq!(cap.chain.len(), 1);
        assert_eq!(cap.error_kind, Some(VerifyKind::Trust));
        assert!(analyze(&cap, "localhost", SystemTime::now()).contains(&CertFlag::Untrusted));
        // Trust the self-signed certificate and the handshake verifies;
        // no flags remain.
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let cap = capture("localhost", port, &route, &roots, Duration::from_secs(10))
            .expect("direct route")
            .expect("chain captured");
        assert!(cap.verify_error.is_none(), "{:?}", cap.verify_error);
        assert!(analyze(&cap, "localhost", SystemTime::now()).is_empty());
    }

    /// A plain-TCP service: the transport comes up but no TLS handshake
    /// happens, reported as `Ok(None)` (transient, retried) and not as a
    /// route failure.
    #[test]
    fn capture_reports_no_handshake_on_a_plain_tcp_service() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(1).flatten() {
                drop(stream); // accept, then hang up without speaking TLS
            }
        });
        let route = crate::upstream::UpstreamConfig::default();
        let res = capture(
            "localhost",
            port,
            &route,
            &RootCertStore::empty(),
            Duration::from_secs(10),
        )
        .expect("the route itself works");
        assert!(res.is_none(), "no handshake, no capture");
    }

    /// The effective route is an HTTP proxy: the capture must CONNECT
    /// through it (verification name `localhost`, transport endpoint the
    /// proxy), never dial the target directly. The target port is unbound,
    /// so a direct connection would be refused.
    #[test]
    fn capture_routes_through_an_http_connect_proxy() {
        let (server_config, cert) = tls_server_config(&["localhost"]);
        let target_port = unbound_port();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let proxy_thread = std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let head = read_connect_head(&mut stream);
            seen_tx.send(head).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .unwrap();
            serve_tls_on(stream, server_config);
        });
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let route = crate::upstream::UpstreamConfig {
            kind: crate::upstream::UpstreamKind::Http,
            host: "127.0.0.1".into(),
            port: proxy_port.to_string(),
            ..Default::default()
        };
        let cap = capture(
            "localhost",
            target_port,
            &route,
            &roots,
            Duration::from_secs(10),
        )
        .expect("proxy route")
        .expect("chain captured through the CONNECT tunnel");
        assert!(cap.verify_error.is_none(), "{:?}", cap.verify_error);
        assert!(analyze(&cap, "localhost", SystemTime::now()).is_empty());
        let head = seen_rx.recv().unwrap();
        assert!(
            head.starts_with(&format!("CONNECT localhost:{target_port} HTTP/1.1\r\n")),
            "{head}"
        );
        proxy_thread.join().unwrap();
    }

    /// Same for a SOCKS5 route (no auth, remote DNS): the proxy receives
    /// the target name and port, and the capture runs over the tunnel.
    #[test]
    fn capture_routes_through_a_socks5_proxy() {
        let (server_config, cert) = tls_server_config(&["localhost"]);
        let target_port = unbound_port();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let proxy_thread = std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5u8, 1, 0]);
            stream.write_all(&[5u8, 0]).unwrap();
            let mut head = [0u8; 4];
            stream.read_exact(&mut head).unwrap();
            assert_eq!(&head[..3], &[5u8, 1, 0]);
            let host = match head[3] {
                1 => {
                    let mut a = [0u8; 4];
                    stream.read_exact(&mut a).unwrap();
                    std::net::Ipv4Addr::from(a).to_string()
                }
                3 => {
                    let mut l = [0u8; 1];
                    stream.read_exact(&mut l).unwrap();
                    let mut h = vec![0u8; l[0] as usize];
                    stream.read_exact(&mut h).unwrap();
                    String::from_utf8(h).unwrap()
                }
                other => panic!("unexpected address type {other}"),
            };
            let mut port_b = [0u8; 2];
            stream.read_exact(&mut port_b).unwrap();
            seen_tx.send((host, u16::from_be_bytes(port_b))).unwrap();
            stream
                .write_all(&[5u8, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .unwrap();
            serve_tls_on(stream, server_config);
        });
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let route = crate::upstream::UpstreamConfig {
            kind: crate::upstream::UpstreamKind::Socks5,
            host: "127.0.0.1".into(),
            port: proxy_port.to_string(),
            ..Default::default()
        };
        let cap = capture(
            "localhost",
            target_port,
            &route,
            &roots,
            Duration::from_secs(10),
        )
        .expect("proxy route")
        .expect("chain captured through the SOCKS5 tunnel");
        assert!(cap.verify_error.is_none(), "{:?}", cap.verify_error);
        let (host, port) = seen_rx.recv().unwrap();
        assert_eq!((host.as_str(), port), ("localhost", target_port));
        proxy_thread.join().unwrap();
    }

    /// A route that fails (the proxy rejects the CONNECT) fails closed
    /// with the diagnostic; the target sees zero direct connections.
    #[test]
    fn capture_fails_closed_when_the_proxy_rejects_connect() {
        let (server_config, _cert) = tls_server_config(&["localhost"]);
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_port = target.local_addr().unwrap().port();
        let direct_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = direct_hits.clone();
        std::thread::spawn(move || {
            for stream in target.incoming().flatten() {
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                serve_tls_on(stream, server_config.clone());
            }
        });
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let _ = read_connect_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let route = crate::upstream::UpstreamConfig {
            kind: crate::upstream::UpstreamKind::Http,
            host: "127.0.0.1".into(),
            port: proxy_port.to_string(),
            ..Default::default()
        };
        let err = capture(
            "localhost",
            target_port,
            &route,
            &RootCertStore::empty(),
            Duration::from_secs(10),
        )
        .expect_err("a rejected CONNECT must fail closed");
        assert!(err.contains("403"), "{err}");
        assert_eq!(
            direct_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no direct target connection after a route failure"
        );
    }

    /// An unusable route (HTTP kind with no proxy configured) also fails
    /// closed before anything is dialed.
    #[test]
    fn capture_fails_closed_on_an_unusable_route() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_port = target.local_addr().unwrap().port();
        let direct_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = direct_hits.clone();
        std::thread::spawn(move || {
            for stream in target.incoming().flatten() {
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(stream);
            }
        });
        let route = crate::upstream::UpstreamConfig {
            kind: crate::upstream::UpstreamKind::Http,
            host: String::new(),
            port: String::new(),
            ..Default::default()
        };
        let err = capture(
            "localhost",
            target_port,
            &route,
            &RootCertStore::empty(),
            Duration::from_secs(10),
        )
        .expect_err("an unusable route must fail closed");
        assert!(err.contains("upstream proxy"), "{err}");
        assert_eq!(direct_hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
