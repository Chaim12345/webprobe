//! First-run setup, verification checklist and sample traffic (M-07).
//!
//! Grounding (Burp build 52685, shipped documentation in
//! `resources/Documentation/burp/documentation/desktop/external-browser-config/`):
//!   * `check-listener.html` — the first step is to check the proxy listener is
//!     running; the default is 127.0.0.1:8080.
//!   * `certificate/index.html` + `proxy-troubleshooting.html` — the CA
//!     certificate is fetched *through the proxy* by visiting `http://burpsuite`;
//!     the browser must already be proxying through Burp. Verification is "visit
//!     an HTTPS URL and get no security warning".
//!   * `check-browser-configuration.html` — "these steps enable you to test
//!     applications that use HTTP; to test HTTPS URLs, install Burp's CA
//!     certificate".
//!   * `certificate/index.html` — most users never do this at all, because the
//!     bundled browser is preconfigured. WebProbe has no bundled browser
//!     (L-05), so the checklist says so instead of pretending otherwise.
//!
//! WebProbe therefore serves its own equivalent page at `http://webprobe` (and
//! answers `http://burpsuite` too, so a tutorial written for Burp still works),
//! with the CA in PEM and DER, exactly where the browser can reach it.

use eframe::egui::{self, RichText, Ui};

use crate::feedback;
use crate::net;
use crate::theme::{self, c};
use crate::App;

/// Hosts answered locally instead of being proxied upstream.
pub const SETUP_HOSTS: [&str; 2] = ["webprobe", "burpsuite"];

/// A checklist line, derived from live state rather than from a stored flag, so
/// it cannot claim a step is done when it is not.
pub struct Check {
    pub label: String,
    pub detail: String,
    pub done: bool,
}

pub fn checks(app: &App) -> Vec<Check> {
    let port = app.shared.proxy_port.load(std::sync::atomic::Ordering::SeqCst);
    let listening = app.shared.listener_running.load(std::sync::atomic::Ordering::SeqCst);
    let history: Vec<net::HistEntry> = app.shared.history.lock().map(|h| h.clone()).unwrap_or_default();
    let https = history.iter().filter(|e| e.https).count();
    let waiting = app.shared.count_waiting();

    vec![
        Check {
            label: "Proxy listener is running".into(),
            detail: if listening {
                format!("127.0.0.1:{port}")
            } else {
                format!("not listening on 127.0.0.1:{port}")
            },
            done: listening,
        },
        Check {
            label: "CA certificate trusted by your browser".into(),
            detail: if https > 0 {
                format!("{https} HTTPS exchange(s) decrypted without a browser warning")
            } else {
                "visit http://webprobe through the proxy, then trust the CA".into()
            },
            done: https > 0,
        },
        Check {
            label: "Traffic is flowing".into(),
            detail: if history.is_empty() {
                "no requests seen yet".into()
            } else {
                format!("{} request(s) in history", history.len())
            },
            done: !history.is_empty(),
        },
        Check {
            label: "Intercept holds messages".into(),
            detail: if app.shared.intercept_on.load(std::sync::atomic::Ordering::SeqCst) {
                format!("on; {waiting} held")
            } else {
                "off (Ctrl+T toggles)".into()
            },
            done: app.shared.intercept_on.load(std::sync::atomic::Ordering::SeqCst),
        },
    ]
}

/// The onboarding panel. Returns true when the user dismissed it this frame.
pub fn panel(app: &mut App, ui: &mut Ui) -> bool {
    let checks = checks(app);
    let done = checks.iter().filter(|c| c.done).count();

    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Set up WebProbe")
                .size(14.0)
                .strong()
                .color(c(theme::MONO7)),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new(format!("{}/{} steps done", done, checks.len()))
                .size(11.5)
                .color(c(if done == checks.len() { theme::GOOD } else { theme::MONO6 })),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("Hide").clicked() {
                return true;
            }
            false
        })
        .inner
    });

    for check in &checks {
        ui.horizontal(|ui| {
            let (mark, colour) = if check.done { ("OK", theme::GOOD) } else { ("--", theme::MONO4) };
            ui.add_sized([26.0, 18.0], egui::Label::new(RichText::new(mark).monospace().size(11.5).color(c(colour))));
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(check.label.clone())
                        .size(12.0)
                        .color(c(if check.done { theme::EDITOR_TEXT } else { theme::MONO6 })),
                );
                ui.label(RichText::new(check.detail.clone()).size(11.0).color(c(theme::MONO4)));
            });
        });
    }

    ui.add_space(6.0);
    let port = app.shared.proxy_port.load(std::sync::atomic::Ordering::SeqCst);
    ui.label(
        RichText::new(format!(
            "Point your browser at 127.0.0.1:{port}, then open http://webprobe to download the CA certificate. Burp's own page is http://burpsuite; both are answered locally by the proxy."
        ))
        .size(11.5)
        .color(c(theme::MONO6)),
    );

    ui.add_space(6.0);
    ui.horizontal_wrapped(|ui| {
        if ui.button("Send sample traffic").clicked() {
            sample_traffic(&app.shared);
        }
        if ui.button("Copy CA certificate").clicked() {
            ui.ctx().copy_text(app.shared.mitm.ca_pem().to_string());
            feedback::toast(feedback::Level::Info, "CA certificate copied (PEM)");
        }
        if ui.button("Export CA certificate").clicked() {
            export_ca(app);
        }
        ui.hyperlink_to(
            "Install the CA (docs)",
            "https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate",
        );
        ui.hyperlink_to("Proxy listener (docs)", "https://portswigger.net/burp/documentation/desktop/external-browser-config");
    });

    false
}

fn export_ca(app: &App) {
    let dir = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let path = dir.join("webprobe-ca.pem");
    match std::fs::write(&path, app.shared.mitm.ca_pem()) {
        Ok(()) => {
            app.shared.log(&format!("CA certificate exported to {}", path.display()));
            feedback::toast(feedback::Level::Success, format!("CA written to {}", path.display()));
        }
        Err(e) => feedback::toast(feedback::Level::Error, format!("CA export failed: {e}")),
    }
}

/// Route one real request through our own listener, so the user can see history,
/// a status line and (with an HTTPS URL) a decrypted exchange. Runs off-thread:
/// the listener answers from its own accept loop.
pub fn sample_traffic(shared: &std::sync::Arc<net::Shared>) {
    let port = shared.proxy_port.load(std::sync::atomic::Ordering::SeqCst);
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: WebProbe/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    let shared = shared.clone();
    std::thread::spawn(move || {
        let out = crate::send_internal_probe(port, request.as_bytes());
        if out.is_empty() {
            shared.log(&format!("Sample traffic failed: no response from the proxy on 127.0.0.1:{port}"));
            feedback::toast(
                feedback::Level::Error,
                format!("No response from 127.0.0.1:{port}; start the listener first"),
            );
            return;
        }
        let status = String::from_utf8_lossy(&out)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        shared.log(&format!("Sample traffic: {status}"));
        feedback::toast(feedback::Level::Success, format!("Sample traffic: {status}"));
    });
}

/// The page served for `http://webprobe` and `http://burpsuite`.
///
/// Burp's page tells you to download the certificate and explains that the
/// browser must already be proxying through the listener; this keeps that shape
/// (and the same two download formats) without copying its assets.
pub fn setup_page(port: u16) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>WebProbe</title>\
<style>body{{font:14px/1.5 system-ui,sans-serif;max-width:44em;margin:3em auto;padding:0 1em;color:#1b1f24}}\
h1{{margin:0 0 .25em}}code,pre{{font-family:ui-monospace,monospace;background:#f2f4f6;padding:.1em .35em;border-radius:3px}}\
pre{{padding:.8em;overflow:auto}}a{{color:#0b5cad}}li{{margin:.35em 0}}</style></head><body>\
<h1>WebProbe proxy</h1>\
<p>Your browser reached WebProbe through the proxy on <code>127.0.0.1:{port}</code>. \
If you are reading this, the listener is running and your browser is configured correctly.</p>\
<h2>1. Install the CA certificate</h2>\
<p>WebProbe signs the per-host HTTPS certificates with a local CA whose private key never leaves this process. \
Trust it to browse HTTPS without warnings:</p>\
<ul><li><a href=\"/webprobe-ca.pem\">Download the CA certificate (PEM)</a> &mdash; for Firefox, macOS Keychain, Android</li>\
<li><a href=\"/webprobe-ca.der\">Download the CA certificate (DER)</a> &mdash; for Windows, iOS, Java</li></ul>\
<h2>2. Check the listener</h2>\
<p>The listener is on <code>127.0.0.1:{port}</code>. WebProbe's Dashboard shows it as the first checklist step.</p>\
<h2>3. Verify</h2>\
<p>Visit any HTTPS URL. The browser should load it with no security warning, and the request appears in Proxy &gt; HTTP history with the padlock marked.</p>\
<h2>4. Interception</h2>\
<p>Press <code>Ctrl+T</code> to hold messages, <code>Ctrl+F</code> to forward a held request, and <code>Ctrl+K</code> for the command palette.</p>\
<hr><p style=\"color:#666\">Reference documentation for the original tool: \
<a href=\"https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate\">installing a CA certificate</a>, \
<a href=\"https://portswigger.net/burp/documentation/desktop/settings/ui/hotkeys.html\">hotkeys</a>.</p>\
</body></html>"
    )
}

/// True when this request is for the local setup page (or the CA download) and
/// should be answered by the proxy instead of being sent upstream.
pub fn local_response(host: &str, path: &str, port: u16, ca_pem: &str, ca_der: &[u8]) -> Option<Vec<u8>> {
    let host = host.split(':').next().unwrap_or(host);
    if !SETUP_HOSTS.iter().any(|h| h.eq_ignore_ascii_case(host)) {
        return None;
    }
    let path = path.split(['?', '#']).next().unwrap_or("/");
    let (body, content_type): (Vec<u8>, &str) = match path {
        "/webprobe-ca.pem" => (ca_pem.as_bytes().to_vec(), "application/x-pem-file"),
        "/webprobe-ca.der" | "/cert" | "/burp/cert" => (ca_der.to_vec(), "application/pkix-cert"),
        _ => (setup_page(port).into_bytes(), "text/html; charset=utf-8"),
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(&body);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_hosts_are_answered_locally() {
        for host in ["webprobe", "burpsuite", "WEBPROBE", "burpsuite:8080"] {
            let r = local_response(host, "/", 8080, "PEM", b"DER").expect(host);
            let text = String::from_utf8_lossy(&r);
            assert!(text.starts_with("HTTP/1.1 200 OK"), "{host}");
            assert!(text.contains("WebProbe proxy"), "{host}");
        }
        assert!(local_response("example.com", "/", 8080, "PEM", b"DER").is_none());
    }

    #[test]
    fn ca_downloads_have_the_right_content_type() {
        let pem = local_response("webprobe", "/webprobe-ca.pem", 8080, "PEM", b"DER").unwrap();
        let text = String::from_utf8_lossy(&pem);
        assert!(text.contains("application/x-pem-file"), "{text}");
        assert!(pem.ends_with(b"PEM"));

        let der = local_response("webprobe", "/webprobe-ca.der", 8080, "PEM", b"DER").unwrap();
        let text = String::from_utf8_lossy(&der);
        assert!(text.contains("application/pkix-cert"), "{text}");
        assert!(der.ends_with(b"DER"));
    }

    #[test]
    fn page_documents_both_paths_and_the_verification_step() {
        let page = setup_page(8080);
        assert!(page.contains("127.0.0.1:8080"));
        assert!(page.contains("/webprobe-ca.pem") && page.contains("/webprobe-ca.der"));
        assert!(page.contains("Ctrl+K"));
        // Burp serves the same page at http://burpsuite, and the port shown must
        // be the listener's, not a hard-coded 8080.
        assert!(setup_page(9090).contains("127.0.0.1:9090"));
    }
#[test]
fn sample_traffic_populates_history_through_the_listener() {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    let shared = net::Shared::new(); // already an Arc<Shared>
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    shared.proxy_port.store(port, Ordering::SeqCst);
    net::start_proxy(shared.clone());
    for _ in 0..100 {
        if shared.listener_running.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(shared.listener_running.load(Ordering::SeqCst), "listener never started");

    sample_traffic(&shared);
    for _ in 0..100 {
        if !shared.history.lock().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // example.com may be unreachable in the sandbox; either way the exchange is
    // recorded (a 502 with the upstream error, or the real response).
    let history = shared.history.lock().unwrap();
    assert!(!history.is_empty(), "sample traffic never reached the proxy");
    assert_eq!(history[0].host, "example.com");
}

}
