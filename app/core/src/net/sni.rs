//! Custom TLS server-name (SNI) sending (D-12): the Collaborator-everywhere
//! SNI probe connects to the target but names the Collaborator domain in
//! the ClientHello (burp.Zs31.ZG, set by Ze2j.issueRequest).

thread_local! {
    static TLS_SNI: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Restores the thread's previous SNI override when dropped.
pub struct SniScope(Option<String>);

impl Drop for SniScope {
    fn drop(&mut self) {
        let prev = self.0.take();
        TLS_SNI.with(|s| *s.borrow_mut() = prev);
    }
}

/// Send TLS requests on this thread with `sni` as the ClientHello server
/// name instead of the connect host, until the scope ends (burp.Zs31.ZG,
/// set by Ze2j.issueRequest for the Collaborator-everywhere SNI probe).
/// Such connections never come from or go back to the pool: a pooled
/// connection was negotiated under another name.
pub fn sni_scope(sni: &str) -> SniScope {
    SniScope(TLS_SNI.with(|s| s.borrow_mut().replace(sni.to_string())))
}

pub(crate) fn sni_override() -> Option<String> {
    TLS_SNI.with(|s| s.borrow().clone())
}

/// burp.Ze89.Zg: a name Burp puts in the SNI extension: only
/// `[a-zA-Z0-9_.-]`, not starting or ending with `.` or `-`. Burp leaves
/// the socket's default (the connect host) otherwise (Ze89.ZV).
pub(crate) fn sni_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        && !name.starts_with(['.', '-'])
        && !name.ends_with(['.', '-'])
}

/// The TLS server name for a connection to `host`: the thread's SNI
/// override when Burp would use it, else the host.
pub(crate) fn effective_server_name(host: &str) -> String {
    sni_override()
        .filter(|s| sni_name_ok(s))
        .unwrap_or_else(|| host.to_string())
}

/// What a TLS lab connection saw: its index, the ClientHello server name
/// and each request's head.
#[cfg(test)]
pub(crate) type SniLog = std::sync::Arc<std::sync::Mutex<Vec<(usize, Option<String>, String)>>>;

/// A loopback HTTPS lab for tests: every connection (served on its own
/// thread, keep-alive) records the SNI it received and each request head,
/// and answers `200 ok`.
#[cfg(test)]
pub(crate) fn tls_sni_lab(shared: &super::Shared) -> (u16, SniLog) {
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let config = shared.mitm.server_config("localhost").unwrap();
    let log: SniLog = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    std::thread::spawn(move || {
        for (idx, s) in l.incoming().flatten().enumerate() {
            let (config, seen) = (config.clone(), seen.clone());
            std::thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                let mut tls =
                    rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), s);
                loop {
                    let Ok(head) = super::read_request(&mut tls) else {
                        return;
                    };
                    if head.is_empty() {
                        return;
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let sni = tls.conn.server_name().map(str::to_string);
                    let close = head.to_ascii_lowercase().contains("connection: close");
                    seen.lock().unwrap().push((idx, sni, head));
                    let _ = tls.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{}\r\nok",
                            if close { "Connection: close\r\n" } else { "" }
                        )
                        .as_bytes(),
                    );
                    let _ = tls.flush();
                    if close {
                        tls.conn.send_close_notify();
                        let _ = tls.flush();
                        return;
                    }
                }
            });
        }
    });
    (port, log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{send_tls_raw, Shared};
    use std::sync::atomic::Ordering;

    /// D-12: a send under `sni_scope` puts the custom name in the
    /// ClientHello while connecting to the host, on a connection of its
    /// own: it neither takes the pooled connection nor leaves one behind.
    #[test]
    fn custom_sni_uses_its_own_unpooled_connection() {
        let shared = Shared::new();
        shared.keep_alive.store(true, Ordering::SeqCst);
        let (port, log) = tls_sni_lab(&shared);
        let get = |path: &str, host: &str| format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        let a = send_tls_raw(
            &shared,
            "localhost",
            port,
            get("/a", &format!("localhost:{port}")).as_bytes(),
        );
        assert!(a.resp.is_some(), "{:?}", a.error);
        {
            let _sni = sni_scope("sni.oast.test");
            let b = send_tls_raw(
                &shared,
                "localhost",
                port,
                get("/b", "sni.oast.test").as_bytes(),
            );
            assert!(b.resp.is_some(), "{:?}", b.error);
        }
        let c = send_tls_raw(
            &shared,
            "localhost",
            port,
            get("/c", &format!("localhost:{port}")).as_bytes(),
        );
        assert!(c.resp.is_some(), "{:?}", c.error);
        let seen: Vec<(usize, Option<String>, String)> = log
            .lock()
            .unwrap()
            .iter()
            .map(|(i, s, h)| (*i, s.clone(), h.lines().next().unwrap_or("").to_string()))
            .collect();
        let lh = Some("localhost".to_string());
        assert_eq!(
            seen,
            vec![
                (0, lh.clone(), "GET /a HTTP/1.1".to_string()),
                (
                    1,
                    Some("sni.oast.test".to_string()),
                    "GET /b HTTP/1.1".to_string()
                ),
                (0, lh, "GET /c HTTP/1.1".to_string()),
            ],
            "the SNI send opened connection 1; /c reused connection 0"
        );
        // Outside the scope the override is gone.
        assert_eq!(sni_override(), None);
    }

    #[test]
    fn sni_names_follow_burps_rule() {
        // burp.Ze89.Zg: ^[a-zA-Z0-9_.-]+$, no leading/trailing '.' or '-'.
        assert!(sni_name_ok("abc.oastify.com") && sni_name_ok("a_b-c.d"));
        for bad in ["", ".a.b", "a.b.", "-a", "a-", "a b", "a:443", "ü.test"] {
            assert!(!sni_name_ok(bad), "{bad}");
        }
        // A name Burp would not send falls back to the connect host.
        let _sni = sni_scope("bad name");
        assert_eq!(effective_server_name("localhost"), "localhost");
    }
}
