// Split from net.rs (L5, issue #35). Bodies unchanged; visibility promoted
// to pub where siblings across the split need access.

use super::*;

/// Client certificate rule for upstream mTLS: presented when `host_pattern`
/// matches the upstream host (exact name or `*.example.com` wildcard).
#[derive(Clone)]
pub struct ClientCertRule {
    pub host_pattern: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// Exact host match or `*.suffix` wildcard (wildcard covers exactly one label).
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern.eq_ignore_ascii_case(host) {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix('*') {
        if let Some(suffix) = rest.strip_prefix('.') {
            let dotted = format!(".{suffix}");
            if let Some(prefix) = host
                .to_ascii_lowercase()
                .strip_suffix(&dotted.to_ascii_lowercase())
            {
                return !prefix.is_empty() && !prefix.contains('.');
            }
        }
    }
    false
}

/// The TLS client config for an upstream host: a per-host client certificate
/// (mTLS) when one is configured, otherwise the shared upstream config.
pub fn tls_client_config(shared: &Shared, host: &str) -> std::sync::Arc<rustls::ClientConfig> {
    let base = tls_client_config_base(shared, host);
    // A sender that chose the protocol (Repeater) offers only that one.
    match H2_CHOICE.with(|c| c.get()).and_then(|c| c.want_h2) {
        Some(h2) => {
            let mut c = (*base).clone();
            c.alpn_protocols = vec![if h2 {
                b"h2".to_vec()
            } else {
                b"http/1.1".to_vec()
            }];
            Arc::new(c)
        }
        None => base,
    }
}

pub fn tls_client_config_base(shared: &Shared, host: &str) -> std::sync::Arc<rustls::ClientConfig> {
    let rule = shared
        .client_certs
        .lock()
        .unwrap()
        .iter()
        .find(|r| host_matches(&r.host_pattern, host))
        .cloned();
    if let Some(rule) = rule {
        let roots = shared.tls_roots.lock().unwrap().clone();
        match crate::tls::client_auth_config(&rule.cert_pem, &rule.key_pem, roots) {
            Ok(config) => return config,
            Err(e) => shared.log(&format!("client certificate for {host} ignored: {e}")),
        }
    }
    shared.tls_upstream.clone()
}
