/// R-13 (b) vertical slice: a page passing location.hash into
/// document.write is DOM-based XSS; a page that never touches the
/// hash is not. Skipped when no Chromium is available.
#[test]
fn dom_xss_hash_slice_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, |_method, path, _raw| {
        let body = if path.starts_with("/xss") {
            "<html><body><script>document.write('<p>' + location.hash.slice(1) + '</p>');</script></body></html>"
        } else {
            "<html><body><p>hello</p></body></html>"
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let host = format!("127.0.0.1:{port}");
    let got = lab_scan(
        port,
        &["active.dom-xss"],
        "GET",
        "/xss",
        format!("GET /xss HTTP/1.1\r\nHost: {host}\r\n\r\n"),
    );
    assert!(
        got.iter()
            .any(|(n, s, c)| n == "Cross-site scripting (DOM-based)" && s == "high" && c == "Firm"),
        "{got:?}"
    );
    let got = lab_scan(
        port,
        &["active.dom-xss"],
        "GET",
        "/benign",
        format!("GET /benign HTTP/1.1\r\nHost: {host}\r\n\r\n"),
    );
    assert!(
        !got.iter()
            .any(|(n, ..)| n == "Cross-site scripting (DOM-based)"),
        "{got:?}"
    );
}

/// R-13 batch 1: the JavaScript-injection, open-redirection and
/// cookie-manipulation DOM families against live lab pages driven by a
/// real browser. Skipped when no Chromium is available.
#[test]
fn dom_families_batch1_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, |_method, path, _raw| {
        let body = if path.starts_with("/js-inj") {
            "<html><body><script>eval(location.hash.slice(1));</script></body></html>"
        } else if path.starts_with("/openredir") {
            "<html><body><script>window.open(location.hash.slice(1));</script></body></html>"
        } else if path.starts_with("/cookie") {
            "<html><body><script>document.cookie = 'x=' + location.hash.slice(1);</script></body></html>"
        } else {
            "<html><body><p>hello</p></body></html>"
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let host = format!("127.0.0.1:{port}");
    let expect = [
        (
            "/js-inj",
            "active.dom-javascript-injection",
            "JavaScript injection (DOM-based)",
            "high",
            "Firm",
        ),
        (
            "/openredir",
            "active.dom-open-redirection",
            "Open redirection (DOM-based)",
            "low",
            "Tentative",
        ),
        (
            "/cookie",
            "active.dom-cookie-manipulation",
            "Cookie manipulation (DOM-based)",
            "low",
            "Firm",
        ),
    ];
    for (page, id, name, sev, conf) in expect {
        let got = lab_scan(
            port,
            &[id],
            "GET",
            page,
            format!("GET {page} HTTP/1.1\r\nHost: {host}\r\n\r\n"),
        );
        assert!(
            got.iter()
                .any(|(n, s, c)| n == name && s == sev && c == conf),
            "{name}: {got:?}"
        );
    }
    // A benign page reports none of the three.
    let got = lab_scan(
        port,
        &[
            "active.dom-javascript-injection",
            "active.dom-open-redirection",
            "active.dom-cookie-manipulation",
        ],
        "GET",
        "/benign2",
        format!("GET /benign2 HTTP/1.1\r\nHost: {host}\r\n\r\n"),
    );
    assert!(got.is_empty(), "{got:?}");
}

/// R-13 batch 2: the storage, JSON-injection, XPath-injection and
/// document-domain DOM families against live lab pages driven by a
/// real browser. Skipped when no Chromium is available.
#[test]
fn dom_families_batch2_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, |_method, path, _raw| {
        let body = if path.starts_with("/storage") {
            "<html><body><script>localStorage.setItem('k', location.hash.slice(1));</script></body></html>"
        } else if path.starts_with("/json") {
            "<html><body><script>JSON.parse(location.hash.slice(1));</script></body></html>"
        } else if path.starts_with("/xpath") {
            "<html><body><script>document.evaluate(location.hash.slice(1), document, null, 0, null);</script></body></html>"
        } else if path.starts_with("/domain") {
            "<html><body><script>document.domain = location.hash.slice(1);</script></body></html>"
        } else {
            "<html><body><p>hello</p></body></html>"
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let host = format!("127.0.0.1:{port}");
    let expect = [
        (
            "/storage",
            "active.dom-storage-manipulation",
            "HTML5 storage manipulation (DOM-based)",
            "info",
            "Firm",
        ),
        (
            "/json",
            "active.dom-json-injection",
            "Client-side JSON injection (DOM-based)",
            "low",
            "Firm",
        ),
        (
            "/xpath",
            "active.dom-xpath-injection",
            "Client-side XPath injection (DOM-based)",
            "low",
            "Firm",
        ),
        (
            "/domain",
            "active.dom-document-domain",
            "Document domain manipulation (DOM-based)",
            "medium",
            "Firm",
        ),
    ];
    for (page, id, name, sev, conf) in expect {
        let got = lab_scan(
            port,
            &[id],
            "GET",
            page,
            format!("GET {page} HTTP/1.1\r\nHost: {host}\r\n\r\n"),
        );
        assert!(
            got.iter()
                .any(|(n, s, c)| n == name && s == sev && c == conf),
            "{name}: {got:?}"
        );
    }
    let got = lab_scan(
        port,
        &[
            "active.dom-storage-manipulation",
            "active.dom-json-injection",
            "active.dom-xpath-injection",
            "active.dom-document-domain",
        ],
        "GET",
        "/benign3",
        format!("GET /benign3 HTTP/1.1\r\nHost: {host}\r\n\r\n"),
    );
    assert!(got.is_empty(), "{got:?}");
}

use super::*;

fn xpath_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[test]
fn xpath_boolean_detection_requires_a_repeated_true_false_difference() {
    let baseline = xpath_response("baseline");
    let found = xpath_boolean_detection(
        &baseline,
        crate::variations::Accuracy::Normal,
        "1",
        |payload| {
            let body = if payload.contains("true()") && !payload.contains("not(true())") {
                "allowed"
            } else {
                "denied"
            };
            Some(xpath_response(body))
        },
    );
    assert!(found.is_some());
    let absent =
        xpath_boolean_detection(&baseline, crate::variations::Accuracy::Normal, "1", |_| {
            Some(xpath_response("same"))
        });
    assert!(absent.is_none());
    let reflected = xpath_boolean_detection(
        &baseline,
        crate::variations::Accuracy::Normal,
        "1",
        |payload| Some(xpath_response(&format!("echo {payload}"))),
    );
    assert!(
        reflected.is_none(),
        "payload reflection alone is not an XPath vulnerability: {reflected:?}"
    );
}

/// The registries are the run order; reordering changes which duplicate
/// is reported first and must be deliberate.
#[test]
fn registry_order_is_pinned() {
    let points: Vec<&str> = POINT_CHECKS.iter().map(|c| c.id()).collect();
    assert_eq!(
        points,
        [
            "active.light-probes",
            "active.external-interaction",
            "active.os-command-injection",
            "active.file-path-traversal",
            "active.link-manipulation",
            "active.file-path-manipulation",
            "active.ssi-injection",
            "active.server-side-template-injection",
            "active.xss-reflected",
            "active.client-side-template-injection",
            "active.php-code-injection",
            "active.input-returned-reflected",
            "active.http-response-header-injection",
            "active.open-redirection",
            "active.sql-injection-error",
            "active.sql-injection-boolean",
            "active.xml-injection-collaborator",
            "active.xml-injection-error",
            "active.ldap-injection",
            "active.smtp-header-injection",
            "active.stored-echo",
            "active.jwt",
            "active.expression-language-injection",
            "active.xpath-injection",
        ]
    );
    // Stage A4 (burp.Zwp6) runs once per stored-input pair.
    assert_eq!(
        STORED_CHECKS.iter().map(|c| c.id()).collect::<Vec<_>>(),
        ["active.xss-stored"]
    );
    let requests: Vec<(&str, Scope, Option<&str>)> = REQUEST_CHECKS
        .iter()
        .map(|c| (c.id(), c.scope(), c.group()))
        .collect();
    assert_eq!(
        requests,
        [
            ("active.dom-xss", Scope::Request, Some(BURP_GROUP)),
            (
                "active.dom-javascript-injection",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            (
                "active.dom-open-redirection",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            (
                "active.dom-cookie-manipulation",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            (
                "active.dom-data-manipulation",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            (
                "active.dom-link-manipulation",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            (
                "active.dom-websocket-poisoning",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            ("active.dom-dos", Scope::Request, Some(BURP_GROUP)),
            (
                "active.dom-ajax-header-manipulation",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            (
                "active.dom-storage-manipulation",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            (
                "active.dom-web-message-manipulation",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            (
                "active.dom-json-injection",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            (
                "active.dom-xpath-injection",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            (
                "active.dom-document-domain",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            (
                "active.dom-prototype-pollution",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            ("active.cors", Scope::Request, Some(BURP_GROUP)),
            (
                "active.path-relative-style-sheet-import",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            ("active.http-trace-enabled", Scope::Host, Some(BURP_GROUP)),
            ("active.openapi-definition", Scope::Host, Some(BURP_GROUP)),
            ("active.collaborator-everywhere", Scope::Host, None),
            (
                "active.server-trace-echo",
                Scope::Request,
                Some(SERVER_GROUP)
            ),
            (
                "active.server-options-methods",
                Scope::Request,
                Some(SERVER_GROUP)
            ),
            ("active.header-manipulation", Scope::Request, None),
            ("active.xxe-file-read", Scope::Request, None),
            ("active.csrf", Scope::Request, None),
            ("active.http-put-enabled", Scope::Host, None),
            ("active.aspnet-tracing", Scope::Host, None),
            ("active.aspnet-debugging", Scope::Host, None),
            ("active.graphql-introspection", Scope::Request, None),
            ("active.graphql-suggestions", Scope::Request, None),
            ("active.graphql-content-type", Scope::Request, None),
            ("active.spoofable-client-ip", Scope::Request, None),
            ("active.backup-file", Scope::Request, None),
            ("active.graphql-endpoint-discovered", Scope::Host, None),
            ("active.web-cache-poisoning", Scope::Request, None),
            ("active.web-cache-deception", Scope::Request, None),
        ]
    );
    let mut ids: Vec<&str> = points
        .iter()
        .copied()
        .chain(requests.iter().map(|r| r.0))
        .collect();
    ids.sort();
    ids.dedup();
    assert_eq!(
        ids.len(),
        POINT_CHECKS.len() + REQUEST_CHECKS.len(),
        "ids must be unique"
    );
}

/// A check that ports a Burp check names Burp's issue, so its issues
/// get Burp's type id; WebProbe's own probes name theirs and get 0.
#[test]
fn check_issue_names_resolve_to_burp_types() {
    let own = [
        "active.light-probes",
        "active.stored-echo",
        "active.server-trace-echo",
        "active.server-options-methods",
        "active.header-manipulation",
    ];
    let issues = POINT_CHECKS
        .iter()
        .map(|c| (c.id(), c.issue()))
        .chain(REQUEST_CHECKS.iter().map(|c| (c.id(), c.issue())));
    for (id, issue) in issues {
        assert_eq!(
            issue_type_id(issue) == 0,
            own.contains(&id),
            "{id}: {issue}"
        );
    }
}

#[test]
fn every_burp_issue_name_has_a_type() {
    for name in KB_ISSUE_NAMES.lines() {
        assert_ne!(issue_type_id(name), 0, "{name}");
    }
    assert_eq!(
        webprobe_support::issues::KB_ISSUE_TYPES.len(),
        KB_ISSUE_NAMES.lines().count()
    );
    assert_eq!(issue_type_id("SQL injection"), 0x0010_0200);
    assert_eq!(
        issue_type_id("External service interaction (DNS)"),
        3_146_240
    );
    assert_eq!(
        issue_type_id("Active probe: TRACE method enabled (cross-site tracing)"),
        0
    );
    use crate::burp_checks::CorsKind;
    for k in [
        CorsKind::Generic,
        CorsKind::Arbitrary,
        CorsKind::Subdomains,
        CorsKind::Unencrypted,
    ] {
        assert_ne!(issue_type_id(k.kb_name()), 0, "{}", k.kb_name());
    }
}

#[test]
fn kind_applicability() {
    let pt = |kind: IpKind| InsertionPoint::new(kind, "x", "v");
    let multipart_file = pt(IpKind::Multipart {
        index: 0,
        filename: Some("a.txt".into()),
    });
    let multipart_plain = pt(IpKind::Multipart {
        index: 0,
        filename: None,
    });
    assert!(PhpCodeInjection.applies_to(&multipart_file));
    assert!(!PhpCodeInjection.applies_to(&multipart_plain));
    assert!(!PhpCodeInjection.applies_to(&pt(IpKind::Query)));
    assert!(!XmlInjectionError.applies_to(&pt(IpKind::Header)));
    assert!(XmlInjectionError.applies_to(&pt(IpKind::Cookie)));
}

#[test]
fn point_rules_follow_the_burp_check_classes() {
    let pt = |kind: IpKind, name: &str, value: &str| InsertionPoint::new(kind, name, value);
    let ua = pt(IpKind::Header, "User-Agent", "Mozilla");
    let referer = pt(IpKind::Header, "Referer", "https://h/");
    let xff = pt(IpKind::Header, "X-Forwarded-For", "1.2.3.4");
    let folder = pt(IpKind::PathFolder(0), "URL path folder 1", "api");
    // burp.Zexx / Zgcg: no URL path folders, no User-Agent or Referer.
    for c in [&SsiInjection as &dyn PointCheck, &SmtpHeaderInjection] {
        assert!(
            !c.applies_to(&ua) && !c.applies_to(&referer) && !c.applies_to(&folder),
            "{}",
            c.id()
        );
        assert!(c.applies_to(&xff), "{}", c.id());
    }
    // burp.Zibp.ZZ (Zp3a): no headers at all.
    for c in [&PathTraversal as &dyn PointCheck, &FilePathManipulation] {
        assert!(!c.applies_to(&xff), "{}", c.id());
    }
    assert!(PathTraversal.applies_to(&folder));
    // burp.Zp3a.Zw: file path manipulation never on URL path points nor
    // on an http(s) URL value.
    assert!(
        !FilePathManipulation.applies_to(&folder)
            && !FilePathManipulation.applies_to(&pt(
                IpKind::PathFilename(1),
                "URL path filename",
                "styles.css"
            ))
    );
    assert!(
        !FilePathManipulation.applies_to(&pt(IpKind::Query, "f", "https://x/a.txt"))
            && FilePathManipulation.applies_to(&pt(IpKind::Query, "f", "a/b.txt"))
    );
    // burp.Zxfo: no folders, no User-Agent; Zibp.ZU: no true / false values.
    assert!(
        !ExternalInteraction.applies_to(&ua)
            && !ExternalInteraction.applies_to(&folder)
            && ExternalInteraction.applies_to(&referer)
    );
    assert!(
        !ExternalInteraction.applies_to(&pt(IpKind::Query, "f", "TRUE"))
            && !ExternalInteraction.applies_to(&pt(IpKind::Query, "f", "a\u{2}b"))
    );
    // burp.Zx8l: no true / false values (the query value is decoded first).
    assert!(
        !OsCommandInjection.applies_to(&pt(IpKind::Query, "f", "%66alse"))
            && OsCommandInjection.applies_to(&pt(IpKind::Query, "f", "1"))
    );
}

#[test]
fn recorder_picks_probe_and_control() {
    let r = Recorder::default();
    r.note("a", b"GET /a", Some(&b"HTTP/1.1 200 OK\r\n\r\nA"[..]));
    r.note("b", b"GET /b", Some(&b"HTTP/1.1 200 OK\r\n\r\nB"[..]));
    r.note("a", b"GET /a2", None);
    r.note("c", b"GET /c", Some(&b"HTTP/1.1 404 Not Found\r\n\r\n"[..]));
    assert_eq!(&*r.last("a").unwrap().request, b"GET /a2");
    assert_eq!(&*r.next_after("a").unwrap().request, b"GET /c");
    assert!(r.next_after("c").is_none());
    assert!(r.last("zz").is_none());
    assert_eq!(r.since_last("b").len(), 3);
}

/// R-10 batch 1 host checks against a live lab: PUT store/retrieve,
/// trace.axd with the tracecontent span, DEBUG with the 500 marker.
#[test]
fn r10_host_checks_against_a_live_lab() {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    let files: Arc<Mutex<std::collections::HashMap<String, Vec<u8>>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let files_t = files.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let files = files_t.clone();
            std::thread::spawn(move || {
                let mut s = s;
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let mut raw = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    let n = s.read(&mut buf).unwrap_or(0);
                    raw.extend_from_slice(&buf[..n]);
                    let done = String::from_utf8_lossy(&raw)
                        .find("\r\n\r\n")
                        .is_some_and(|h| {
                            let cl = String::from_utf8_lossy(&raw[..h])
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            raw.len() >= h + 4 + cl
                        });
                    if n == 0 || done {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&raw).to_string();
                let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                let method = head.split_whitespace().next().unwrap_or("").to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let resp = if method == "PUT" {
                    files.lock().unwrap().insert(path, body.as_bytes().to_vec());
                    "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                } else if method == "GET" && path == "/trace.axd" {
                    let b = "<html><body><span class=\"tracecontent\">trace</span></body></html>";
                    format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
                } else if method == "DEBUG" {
                    let b = "DebugSessionID corrupted or not provided.";
                    format!("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len())
                } else if method == "GET" {
                    match files.lock().unwrap().get(&path) {
                        Some(b) => format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", b.len(), String::from_utf8_lossy(b)),
                        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    }
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                };
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    let shared = crate::net::Shared::new();
    let host = format!("127.0.0.1:{port}");
    // Only the three checks under test run.
    let mut cfg = crate::scan_config::ScanConfig::default();
    let keep = [
        "active.http-put-enabled",
        "active.aspnet-tracing",
        "active.aspnet-debugging",
    ];
    for (id, ..) in crate::scan::check_catalogue() {
        if !keep.contains(&id) {
            cfg.disabled_checks.insert(id.into());
        }
    }
    *crate::scan_config::shared_config(&shared).lock().unwrap() = cfg;
    let mut e = crate::net::HistEntry {
        method: "GET".into(),
        host: "127.0.0.1".into(),
        port,
        path: "/".into(),
        ..Default::default()
    };
    e.req_raw = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")
        .into_bytes()
        .into();
    crate::scan::start_active_scan(shared.clone(), e, &[], &[]);
    let t0 = std::time::Instant::now();
    while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(60) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!shared.scan.is_busy(), "scan did not finish");
    let issues = shared.issues.lock().unwrap();
    let got: Vec<(&str, &str, &str)> = issues
        .iter()
        .map(|i| (i.name.as_str(), i.sev.as_str(), i.confidence.as_str()))
        .collect();
    assert!(
        got.contains(&("HTTP PUT method is enabled", "high", "Certain")),
        "{got:?}"
    );
    assert!(
        got.contains(&("ASP.NET tracing enabled", "high", "Certain")),
        "{got:?}"
    );
    assert!(
        got.contains(&("ASP.NET debugging enabled", "medium", "Firm")),
        "{got:?}"
    );
}

/// One lab request/response cycle: read a full request (headers plus
/// Content-Length body), answer with the handler's response.
fn lab_serve(
    l: std::net::TcpListener,
    handler: impl Fn(&str, &str, &str) -> String + Send + Sync + 'static,
) -> u16 {
    use std::io::{Read, Write};
    let port = l.local_addr().unwrap().port();
    let handler = std::sync::Arc::new(handler);
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let handler = handler.clone();
            std::thread::spawn(move || {
                let mut s = s;
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let mut raw = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    let n = s.read(&mut buf).unwrap_or(0);
                    raw.extend_from_slice(&buf[..n]);
                    let done = String::from_utf8_lossy(&raw)
                        .find("\r\n\r\n")
                        .is_some_and(|h| {
                            let cl = String::from_utf8_lossy(&raw[..h])
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            raw.len() >= h + 4 + cl
                        });
                    if n == 0 || done {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&raw).to_string();
                let (head, _) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                let method = head.split_whitespace().next().unwrap_or("").to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let _ = s.write_all(handler(&method, &path, &text).as_bytes());
            });
        }
    });
    port
}

/// Run one scan against the lab with only `keep` checks enabled and
/// return the (name, severity, confidence) of every issue it raises.
fn lab_scan(
    port: u16,
    keep: &[&str],
    method: &str,
    path: &str,
    req_raw: String,
) -> Vec<(String, String, String)> {
    let shared = crate::net::Shared::new();
    let mut cfg = crate::scan_config::ScanConfig::default();
    for (id, ..) in crate::scan::check_catalogue() {
        if !keep.contains(&id) {
            cfg.disabled_checks.insert(id.into());
        }
    }
    *crate::scan_config::shared_config(&shared).lock().unwrap() = cfg;
    let mut e = crate::net::HistEntry {
        method: method.into(),
        host: "127.0.0.1".into(),
        port,
        path: path.into(),
        ..Default::default()
    };
    e.req_raw = req_raw.into_bytes().into();
    crate::scan::start_active_scan(shared.clone(), e, &[], &[]);
    let t0 = std::time::Instant::now();
    while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(60) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!shared.scan.is_busy(), "scan did not finish");
    let issues = shared.issues.lock().unwrap();
    issues
        .iter()
        .map(|i| (i.name.clone(), i.sev.clone(), i.confidence.clone()))
        .collect()
}

/// R-10 batch 2: the three GraphQL checks against a live endpoint.
/// The lab answers the introspection query with a schema, the
/// `query{__type}` probe with a suggestion error, and the query in
/// every carrying style (JSON body, GET parameter, form body).
#[test]
fn r10_graphql_checks_against_a_live_lab() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, |_method, _path, raw| {
        let (body, ct) = if raw.contains("__schema") {
            (r#"{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"types":[]}}}"#.to_string(), "application/json")
        } else if raw.contains("__typename") {
            (
                r#"{"data":{"__typename":"Query"}}"#.to_string(),
                "application/json",
            )
        } else if raw.contains("query{__type}") || raw.contains("query%7B__type%7D") {
            (r#"{"errors":[{"message":"Field '__type' must have a selection of subfields. Did you mean '__type { ... }'?"}]}"#.to_string(), "application/json")
        } else {
            (
                r#"{"data":{"user":{"name":"alice"}}}"#.to_string(),
                "application/json",
            )
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let host = format!("127.0.0.1:{port}");
    let req = format!("POST /graphql HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: 32\r\n\r\n{{\"query\":\"query{{ user {{ name }} }}\"}}");
    let got = lab_scan(
        port,
        &[
            "active.graphql-introspection",
            "active.graphql-suggestions",
            "active.graphql-content-type",
        ],
        "POST",
        "/graphql",
        req,
    );
    let got: Vec<(&str, &str, &str)> = got
        .iter()
        .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str()))
        .collect();
    assert!(
        got.contains(&("GraphQL introspection enabled", "low", "Certain")),
        "{got:?}"
    );
    assert!(
        got.contains(&("GraphQL suggestions enabled", "low", "Certain")),
        "{got:?}"
    );
    assert!(
        got.contains(&("GraphQL content type not validated", "low", "Certain")),
        "{got:?}"
    );
}

/// R-10 batch 3: SpoofableClientIp and BackupFile against a live lab.
/// The lab echoes the X-Forwarded-For value in its page and serves a
/// copy of /files/index.php at /files/index.php~; everything else
/// under /files/ is a 404, so the random-name controls stay flat.
#[test]
fn r10_spoofable_ip_and_backup_file_against_a_live_lab() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, |_method, path, raw| {
        let xff = raw.lines().find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("x-forwarded-for:")
                .map(|v| v.trim().to_string())
        });
        let client = xff.unwrap_or_else(|| "direct".into());
        let (status, body) = match path {
            "/files/index.php" => (
                "200 OK",
                format!("<html><body>files<!-- client {client} --></body></html>"),
            ),
            "/files/index.php~" => ("200 OK", "<?php // backup source ?>".to_string()),
            _ => ("404 Not Found", String::new()),
        };
        format!("HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let host = format!("127.0.0.1:{port}");
    let req = format!("GET /files/index.php HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let got = lab_scan(
        port,
        &["active.spoofable-client-ip", "active.backup-file"],
        "GET",
        "/files/index.php",
        req,
    );
    let got: Vec<(&str, &str, &str)> = got
        .iter()
        .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str()))
        .collect();
    assert!(
        got.contains(&("Spoofable client IP address", "info", "Tentative")),
        "{got:?}"
    );
    assert!(got.contains(&("Backup file", "info", "Certain")), "{got:?}");
}

/// R-10 web cache poisoning (Zp22 / Zg1g rule): reported only when a
/// clean request with the probe's cache buster gets the poisoned page
/// back. The lab reflects X-Forwarded-Host; with `cache` on it caches
/// whole responses keyed on the full request target (path + query).
fn cache_lab(cache: bool) -> u16 {
    let store = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        String,
    >::new()));
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    lab_serve(l, move |_method, target, raw| {
        if cache {
            if let Some(hit) = store.lock().unwrap().get(target) {
                return hit.clone();
            }
        }
        let xfh = raw
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("x-forwarded-host")
                    .then(|| v.trim().to_string())
            })
            .unwrap_or_else(|| "lab.test".into());
        let body = format!(
            "<html><head><script src=\"//{xfh}/app.js\"></script></head><body>home</body></html>"
        );
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: public, max-age=60\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        if cache {
            store
                .lock()
                .unwrap()
                .insert(target.to_string(), resp.clone());
        }
        resp
    })
}

#[test]
fn r10_cache_poisoning_needs_a_clean_retrieval() {
    let keep = ["active.web-cache-poisoning"];
    let port = cache_lab(true);
    let req = format!("GET /home HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let got = lab_scan(port, &keep, "GET", "/home", req);
    assert!(
        got.iter()
            .any(|(n, s, c)| n == "Web cache poisoning" && s == "high" && c == "Certain"),
        "cached lab: {got:?}"
    );
    // Reflection with no cache: never poisoning.
    let port = cache_lab(false);
    let req = format!("GET /home HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let got = lab_scan(port, &keep, "GET", "/home", req);
    assert!(
        !got.iter().any(|(n, ..)| n == "Web cache poisoning"),
        "uncached lab: {got:?}"
    );
}

/// R-10 point checks: Expression Language and XPath injection against
/// a live lab. The lab "evaluates" Burp's EL probe (echoing d1 z b z
/// d2 back) and answers a value with a trailing quote with an XPath
/// error message.
#[test]
fn r10_el_and_xpath_against_a_live_lab() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, |_method, target, _raw| {
        let q = target
            .split_once('?')
            .map(|(_, q)| q.to_string())
            .unwrap_or_default();
        let v = q
            .split('&')
            .find_map(|kv| kv.strip_prefix("name="))
            .unwrap_or("");
        let v = util::url_decode(&v.replace('+', " "));
        let el = regex::Regex::new(r#"([a-z]+)\$\{"z([a-z]+)z"\.toString\(\)\.replace\("([a-z]+)", "([a-z]+)"\)\}([a-z]+)"#).unwrap();
        let body = if let Some(c) = el.captures(&v) {
            format!(
                "<html><body>profile {}{}{}{}{}</body></html>",
                &c[1], "z", &c[4], "z", &c[5]
            )
        } else if v.ends_with('\'') || v.ends_with('"') {
            "<html><body>javax.xml.xpath.XPathExpressionException: Unexpected quote</body></html>"
                .to_string()
        } else {
            "<html><body>profile page</body></html>".to_string()
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let host = format!("127.0.0.1:{port}");
    let req = format!("GET /profile?name=x HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let got = lab_scan(
        port,
        &[
            "active.expression-language-injection",
            "active.xpath-injection",
        ],
        "GET",
        "/profile?name=x",
        req,
    );
    let got: Vec<(&str, &str, &str)> = got
        .iter()
        .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str()))
        .collect();
    assert!(
        got.contains(&("Expression Language injection", "high", "Certain")),
        "{got:?}"
    );
    assert!(
        got.contains(&("XPath injection", "high", "Firm")),
        "{got:?}"
    );
}

#[test]
fn collaborator_everywhere_builds_burps_request_set() {
    let collab = |slot: &str| Some(format!("{slot}.oast.test"));
    let probes = everywhere_probes("shop.test:8080", "shop.test", 8080, true, &collab);
    let first_lines: Vec<&str> = probes
        .iter()
        .map(|p| p.request.split("\r\n").next().unwrap())
        .collect();
    assert_eq!(
        first_lines,
        vec![
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "GET @authfrag.oast.test/ HTTP/1.1",
            "GET http://absurl.oast.test/ HTTP/1.1",
            "GET / HTTP/1.1",
            "CONNECT connect.oast.test:443 HTTP/1.1"
        ]
    );
    assert!(probes[0].request.contains("\r\nHost: host.oast.test\r\nPragma: no-cache\r\nCache-Control: no-cache, no-transform\r\nConnection: close\r\n\r\n"));
    assert!(probes[1]
        .request
        .contains("\r\nHost: shop.test:8080\r\nX-Forwarded-Host: xfh.oast.test\r\n"));
    assert!(probes[2]
        .request
        .contains("\r\nHost: shop.test:8080@hostauth.oast.test\r\n"));
    // One request carries the six client-IP / Referer headers, an id each.
    let combined = &probes[5];
    assert_eq!(
        combined.ids.iter().map(|(s, _, _)| *s).collect::<Vec<_>>(),
        vec!["xff", "tci", "xrip", "referer", "wap", "scraped"]
    );
    assert!(combined.request.contains(
        "\r\nReferer: http://referer.oast.test/\r\nX-WAP-Profile: http://wap.oast.test/wap.xml\r\n"
    ));
    assert_eq!(combined.ids[3].2, "HTTP Referer header");
    // Behind an upstream proxy: no request-line variants (Zs61.Zu).
    let proxied = everywhere_probes("shop.test", "shop.test", 80, false, &collab);
    assert_eq!(proxied.len(), 4);
    // No Collaborator ids: nothing to send.
    assert!(everywhere_probes("h", "h", 80, true, &|_| None).is_empty());
}

#[test]
fn inband_oob_resource_load_uses_burps_text() {
    let token = "abc123xyz";
    let marker = crate::collaborator::inband_marker(token);
    assert_eq!(marker, "zyx321cba");
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\r\n<p>Preview: <html><body>{}</body></html></p>",
        marker.to_uppercase()
    );
    assert!(inband_hit(resp.as_bytes(), token), "searched ignoring case");
    assert!(
        !inband_hit(b"HTTP/1.1 200 OK\r\n\r\nabc123xyz", token),
        "the id echoed as sent is not the served content"
    );
    let e = HistEntry {
        host: "h".into(),
        path: "/p?u=1".into(),
        ..Default::default()
    };
    let delivery = crate::oob::delivery_sentence(
        "The payload",
        "abc123xyz.oast.test",
        "<b>u</b> parameter",
        "",
    );
    let i = oob_resource_load_issue(
        &e,
        &delivery,
        "GET /p?u=x HTTP/1.1\r\n\r\n",
        resp.as_bytes(),
    );
    assert_eq!(
        (i.name.as_str(), i.sev.as_str(), i.confidence.as_str()),
        ("Out-of-band resource load (HTTP)", "high", "Certain")
    );
    assert_eq!(
        i.detail,
        "It is possible to induce the application to retrieve the contents of an arbitrary external URL and return those contents in its own response.<br><br>The payload <b>abc123xyz.oast.test</b> was submitted in the <b>u</b> parameter.<br><br>The application performed an HTTP request to the specified domain. The response from that request was then included in the application's own response."
    );
    assert_eq!(i.evidence.len(), 1);
}

#[test]
fn hardening_recorder_missing_keys_have_no_implicit_evidence() {
    let recorder = Recorder::default();
    recorder.note("present", b"request", None);
    assert!(recorder.last("absent").is_none());
    assert!(recorder.next_after("absent").is_none());
    assert!(recorder.since_last("absent").is_empty());
}

#[test]
fn hardening_recorder_repeated_payload_selects_latest_probe_and_followups() {
    let recorder = Recorder::default();
    recorder.note("probe", b"old", Some(b"old response"));
    recorder.note("control", b"old control", None);
    recorder.note("probe", b"new", None);
    recorder.note("control", b"new control", Some(b"negative"));
    recorder.note("retrieve", b"retrieve", Some(b"stored"));
    let exchanges = recorder.since_last("probe");
    assert_eq!(
        exchanges
            .iter()
            .map(|e| e.request.as_ref())
            .collect::<Vec<_>>(),
        [
            b"new".as_slice(),
            b"new control".as_slice(),
            b"retrieve".as_slice()
        ]
    );
    assert_eq!(recorder.last("probe"), Some(exchanges[0].clone()));
    assert_eq!(recorder.next_after("probe"), Some(exchanges[1].clone()));
    assert!(exchanges[0].response.is_none());
    assert!(recorder.next_after("retrieve").is_none());
}

#[test]
fn hardening_recorder_owns_bounded_snapshot_of_exchange() {
    let recorder = Recorder::default();
    let mut request = vec![b'q'; EVIDENCE_MAX_BYTES + 10];
    let mut response = vec![b'r'; EVIDENCE_MAX_BYTES + 10];
    recorder.note("payload", &request, Some(&response));
    request.fill(b'x');
    response.fill(b'y');
    let saved = recorder.last("payload").unwrap();
    assert_eq!(saved.request.len(), EVIDENCE_MAX_BYTES);
    assert!(saved.request.iter().all(|b| *b == b'q'));
    let saved_response = saved.response.unwrap();
    assert_eq!(saved_response.len(), EVIDENCE_MAX_BYTES);
    assert!(saved_response.iter().all(|b| *b == b'r'));
}

#[test]
fn hardening_evidence_filter_preserves_order_and_empty_responses() {
    let first = ScanEvidence::new(b"first", None);
    let second = ScanEvidence::new(b"second", Some(b""));
    assert_eq!(
        evidence([None, Some(first.clone()), None, Some(second.clone())]),
        [first, second]
    );
    assert!(evidence([None, None]).is_empty());
}

#[test]
fn dom_families_share_one_probe_and_refresh_on_the_next_run() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    let vulnerable = Arc::new(AtomicBool::new(true));
    let enabled = vulnerable.clone();
    let visits = Arc::new(AtomicUsize::new(0));
    let count = visits.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(listener, move |_, path, _| {
        // The DOM navigation carries the probe payload in the query
        // string ("/cache?..."); the baseline is the bare "/cache".
        if path == "/cache" || path.starts_with("/cache?") {
            count.fetch_add(1, Ordering::SeqCst);
        }
        let body = if enabled.load(Ordering::SeqCst) {
            r#"<html><body><script>
            var s=location.hash.slice(1);
            document.body.innerHTML='<p>'+s+'</p>';
            try { eval(s); } catch(e) {}
            window.open(s); document.cookie='x='+s; localStorage.setItem('k',s);
            try { JSON.parse(s); } catch(e) {}
            try { document.evaluate(s,document,null,0,null); } catch(e) {}
            try { document.domain=s; } catch(e) {}
            </script></body></html>"#
        } else {
            "<html><body>benign<script>void 0</script></body></html>"
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
    });
    let shared = crate::net::Shared::new();
    let mut config = crate::scan_config::ScanConfig::default();
    for (id, ..) in crate::scan::check_catalogue() {
        if !id.starts_with("active.dom-") {
            config.disabled_checks.insert(id.into());
        }
    }
    *crate::scan_config::shared_config(&shared).lock().unwrap() = config;
    let entry = || crate::net::HistEntry {
        method: "GET".into(),
        host: "127.0.0.1".into(),
        port,
        path: "/cache".into(),
        req_raw: format!("GET /cache HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
            .into_bytes()
            .into(),
        ..Default::default()
    };
    let run = || {
        crate::scan::start_active_scan(shared.clone(), entry(), &[], &[]);
        let start = std::time::Instant::now();
        while shared.scan.is_busy() && start.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!shared.scan.is_busy());
    };
    run();
    assert_eq!(
        shared.issues.lock().unwrap().len(),
        8,
        "all families must share one browser result"
    );
    assert_eq!(
        visits.load(Ordering::SeqCst),
        3,
        "one baseline outside DOM budget, one stored-token submission and one DOM navigation"
    );
    vulnerable.store(false, Ordering::SeqCst);
    shared.issues.lock().unwrap().clear();
    run();
    assert!(
        shared.issues.lock().unwrap().is_empty(),
        "previous run's hits must not leak"
    );
    assert_eq!(
        visits.load(Ordering::SeqCst),
        6,
        "next run gets a fresh DOM probe"
    );
}

/// Two-token source provenance matrix: hash-only
/// evidence keeps the family confidence; search-only and mixed evidence
/// are reported conservatively as Tentative; a reflected token that never
/// reaches a wrapped sink, a pre-existing unrelated Object.prototype
/// property and a benign page report nothing. Live Chromium, skipped when
/// no browser is available.
#[test]
fn dom_source_provenance_matrix_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, |_method, path, _raw| {
        let body = if path.starts_with("/hashonly") {
            "<html><body><script>document.write('<p>' + location.hash.slice(1) + '</p>');</script></body></html>"
        } else if path.starts_with("/searchonly") {
            "<html><body><script>document.write('<p>' + location.search.slice(1) + '</p>');</script></body></html>"
        } else if path.starts_with("/both") {
            "<html><body><script>document.write('<p>' + location.search.slice(1) + '|' + location.hash.slice(1) + '</p>');</script></body></html>"
        } else if path.starts_with("/reflect") {
            // The tokens reach the page but no wrapped sink: no finding.
            "<html><body><script>var d=document.createElement('div'); d.appendChild(document.createTextNode(location.search+location.hash)); document.body.appendChild(d);</script></body></html>"
        } else if path.starts_with("/preexisting") {
            // An unrelated pre-existing prototype property is not a finding.
            "<html><body><script>Object.prototype.wpPreExisting123='x';</script></body></html>"
        } else {
            "<html><body><p>hello</p><script>void 0</script></body></html>"
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let host = format!("127.0.0.1:{port}");
    let shared = crate::net::Shared::new();
    let mut config = crate::scan_config::ScanConfig::default();
    for (id, ..) in crate::scan::check_catalogue() {
        if !id.starts_with("active.dom-") {
            config.disabled_checks.insert(id.into());
        }
    }
    *crate::scan_config::shared_config(&shared).lock().unwrap() = config;
    let scan = |path: &str| {
        shared.issues.lock().unwrap().clear();
        let entry = crate::net::HistEntry {
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            path: path.into(),
            req_raw: format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n")
                .into_bytes()
                .into(),
            ..Default::default()
        };
        crate::scan::start_active_scan(shared.clone(), entry, &[], &[]);
        let start = std::time::Instant::now();
        while shared.scan.is_busy() && start.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!shared.scan.is_busy());
        shared.issues.lock().unwrap().clone()
    };
    let names = |issues: &[webprobe_support::issues::ScanIssue]| {
        issues
            .iter()
            .map(|i| format!("{}|{}|{}", i.name, i.sev, i.confidence))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let xss = |issues: &[webprobe_support::issues::ScanIssue]| {
        issues
            .iter()
            .filter(|i| i.name == "Cross-site scripting (DOM-based)")
            .count()
    };
    let hit = |issues: &[webprobe_support::issues::ScanIssue]| {
        assert_eq!(xss(issues), 1, "{}", names(issues));
        issues
            .iter()
            .find(|i| i.name == "Cross-site scripting (DOM-based)")
            .unwrap()
            .clone()
    };
    let hash = scan("/hashonly");
    let h = hit(&hash);
    assert_eq!(h.confidence, "Firm", "{}", names(&hash));
    assert!(
        h.detail.contains("read from <b>location.hash</b>"),
        "{}",
        h.detail
    );
    let search = scan("/searchonly");
    let h = hit(&search);
    assert_eq!(h.confidence, "Tentative", "{}", names(&search));
    assert!(
        h.detail.contains("read from <b>location.search</b>"),
        "{}",
        h.detail
    );
    let both = scan("/both");
    let h = hit(&both);
    assert_eq!(h.confidence, "Tentative", "{}", names(&both));
    assert!(
        h.detail
            .contains("read from <b>location.hash and location.search</b>"),
        "{}",
        h.detail
    );
    for page in ["/reflect", "/preexisting", "/benignp"] {
        let got = scan(page);
        assert!(got.is_empty(), "{page}: {}", names(&got));
    }
}

/// R-13 reflected-DOM variant: a page whose response copies the query
/// payload's token into a JavaScript string literal and passes it to a
/// sink is the reflected variant; the plain location.hash page stays the
/// DOM variant. Under the conservative confidence mapping the reflected
/// variant is Tentative (burp.Zwf8's mapping is established for
/// location.hash only). Skipped when no Chromium is available.
#[test]
fn dom_xss_reflected_variant_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, |_method, path, _raw| {
        let body = if path.starts_with("/reflxss") {
            let q = path.split('?').nth(1).unwrap_or("");
            format!("<html><body><script>var t = '{q}'; document.write('<p>' + t + '</p>');</script></body></html>")
        } else if path.starts_with("/xss") {
            "<html><body><script>document.write('<p>' + location.hash.slice(1) + '</p>');</script></body></html>".to_string()
        } else {
            "<html><body><p>hello</p></body></html>".to_string()
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let host = format!("127.0.0.1:{port}");
    let got = lab_scan(
        port,
        &["active.dom-xss"],
        "GET",
        "/reflxss",
        format!("GET /reflxss HTTP/1.1\r\nHost: {host}\r\n\r\n"),
    );
    assert!(
        got.iter().any(
            |(n, s, c)| n == "Cross-site scripting (reflected DOM-based)"
                && s == "high"
                && c == "Tentative"
        ),
        "reflected variant: {got:?}"
    );
    assert!(
        !got.iter()
            .any(|(n, ..)| n == "Cross-site scripting (DOM-based)"),
        "not the plain variant: {got:?}"
    );
    let got = lab_scan(
        port,
        &["active.dom-xss"],
        "GET",
        "/xss",
        format!("GET /xss HTTP/1.1\r\nHost: {host}\r\n\r\n"),
    );
    assert!(
        got.iter()
            .any(|(n, s, c)| n == "Cross-site scripting (DOM-based)" && s == "high" && c == "Firm"),
        "plain variant: {got:?}"
    );
}

/// R-13 stored-DOM variant: the lab remembers the previous request's
/// query payload and embeds it in a JavaScript string literal of the next
/// page, which passes it to document.write: the stored variant, not the
/// plain or reflected ones (Tentative, like every non-location.hash
/// provenance). Skipped when no Chromium is available.
#[test]
fn dom_xss_stored_variant_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let stored = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let st = stored.clone();
    let port = lab_serve(l, move |_method, path, _raw| {
        // Render the value stored BEFORE this request, then store this
        // request's query payload: the stored token can only reach a page
        // through an earlier request.
        let embed = st.lock().unwrap().clone();
        if let Some(q) = path.split('?').nth(1) {
            if q.contains("__proto__") {
                *st.lock().unwrap() = q.to_string();
            }
        }
        let body = if path.starts_with("/storexss") {
            format!("<html><body><script>var t = '{embed}'; document.write('<p>' + t + '</p>');</script></body></html>")
        } else {
            "<html><body><p>hello</p></body></html>".to_string()
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let host = format!("127.0.0.1:{port}");
    let got = lab_scan(
        port,
        &["active.dom-xss"],
        "GET",
        "/storexss",
        format!("GET /storexss HTTP/1.1\r\nHost: {host}\r\n\r\n"),
    );
    assert!(
        got.iter()
            .any(|(n, s, c)| n == "Cross-site scripting (stored DOM-based)"
                && s == "high"
                && c == "Tentative"),
        "stored variant: {got:?}"
    );
    assert!(
        !got.iter()
            .any(|(n, ..)| n == "Cross-site scripting (DOM-based)"
                || n == "Cross-site scripting (reflected DOM-based)"),
        "not the other variants: {got:?}"
    );
}

/// Session-preserving wire evidence for all DOM requests, with a mixed
/// stored/hash flow through the SAME sink. The baseline is counted apart
/// from the two-request admitted DOM operation.
#[test]
fn dom_session_headers_and_mixed_same_sink_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let captured = seen.clone();
    let stored = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let st = stored.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(listener, move |_, path, raw| {
        let prior = st.lock().unwrap().clone();
        if let Some(q) = path.split('?').nth(1) {
            *st.lock().unwrap() = q.into();
        }
        if !raw.is_empty() {
            captured.lock().unwrap().push(raw.into());
        }
        let body = format!("<html><head><link rel='icon' href='data:,'></head><body><script>document.write('<p>'+location.hash+'</p>');document.write('<p>{prior}</p>');</script></body></html>");
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
    });
    let got = lab_scan(port, &["active.dom-xss"], "GET", "/mixed",
        format!("GET /mixed HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: session=kept\r\nAuthorization: Bearer lab-only\r\nConnection: X-Remove\r\nX-Remove: unsafe\r\nProxy-Authorization: lab-proxy\r\n\r\n"));
    for name in [
        "Cross-site scripting (DOM-based)",
        "Cross-site scripting (stored DOM-based)",
    ] {
        assert!(
            got.iter().any(|(n, _, _)| n == name),
            "missing {name}: {got:?}"
        );
    }
    let wire = seen.lock().unwrap();
    assert_eq!(
        wire.len(),
        3,
        "baseline + submission + navigation: {wire:?}"
    );
    for raw in wire.iter().skip(1) {
        let lower = raw.to_ascii_lowercase();
        assert!(lower.contains("cookie: session=kept"), "{raw}");
        assert!(lower.contains("authorization: bearer lab-only"), "{raw}");
        assert!(!lower.contains("proxy-authorization:"), "{raw}");
        assert!(!lower.contains("x-remove:"), "{raw}");
        assert!(!lower.contains("transfer-encoding:"), "{raw}");
        assert!(raw.ends_with("\r\n\r\n"), "{raw}");
    }
}

/// The server applies the submission then drops the connection. The
/// submission is not replayed, no browser navigation follows, and the
/// per-URL cache prevents every other family from trying again.
#[test]
fn dom_unknown_submission_outcome_is_not_replayed_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let capture = requests.clone();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let end = done.clone();
    let server = std::thread::spawn(move || {
        while !end.load(std::sync::atomic::Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                        .unwrap();
                    let mut data = Vec::new();
                    let mut b = [0; 4096];
                    while let Ok(n) = stream.read(&mut b) {
                        if n == 0 {
                            break;
                        }
                        data.extend_from_slice(&b[..n]);
                        if data.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let raw = String::from_utf8_lossy(&data).to_string();
                    let is_submission = raw.split_whitespace().nth(1).unwrap_or("").contains('?');
                    if raw.is_empty() {
                        continue;
                    }
                    capture.lock().unwrap().push(raw);
                    if !is_submission {
                        let body = "<html><script>document.write(location.hash)</script></html>";
                        let _=write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
                    }
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    });
    let got = lab_scan(
        port,
        &["active.dom-xss", "active.dom-javascript-injection"],
        "GET",
        "/drop",
        format!("GET /drop HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    );
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    server.join().unwrap();
    assert!(
        got.is_empty(),
        "unknown outcome is not clean evidence: {got:?}"
    );
    let wire = requests.lock().unwrap();
    assert_eq!(
        wire.len(),
        2,
        "baseline + exactly one effect-then-drop submission: {wire:?}"
    );
}

/// Reflection classification uses the actual navigation response, even
/// when a hypothetical subsequent query fetch would contain script text.
#[test]
fn dom_reflection_uses_only_fulfilled_navigation_response_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = n.clone();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, move |_, path, raw| {
        if raw.is_empty() {
            return String::new();
        }
        let q = path.split('?').nth(1).unwrap_or("");
        let attempt = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let body = if attempt >= 3 {
            format!("<html><script>var reflected='{q}';</script></html>")
        } else {
            "<html><head><link rel='icon' href='data:,'></head><script>document.write(location.search)</script></html>".into()
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
    });
    let got = lab_scan(
        port,
        &["active.dom-xss"],
        "GET",
        "/response",
        format!("GET /response HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    );
    assert!(
        got.iter()
            .any(|(name, _, _)| name == "Cross-site scripting (DOM-based)"),
        "{got:?}"
    );
    assert!(
        !got.iter()
            .any(|(name, _, _)| name == "Cross-site scripting (reflected DOM-based)"),
        "{got:?}"
    );
    assert_eq!(
        n.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "no later query repetition"
    );
}

/// The outer stored submission and every resource request consume the
/// same 64-request operation cap. Baseline is outside that operation.
#[test]
fn dom_outer_submission_and_resources_share_request_cap_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    let n = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = n.clone();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, move |_, path, raw| {
        if raw.is_empty() {
            return String::new();
        }
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let body = if path.starts_with("/cap") {
            let imgs = (0..100)
                .map(|i| format!("<img src='/resource/{i}'>"))
                .collect::<String>();
            format!("<html><head><link rel='icon' href='data:,'></head><script>void 0</script>{imgs}</html>")
        } else {
            String::new()
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
    });
    let got = lab_scan(
        port,
        &["active.dom-xss"],
        "GET",
        "/cap",
        format!("GET /cap HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
    );
    assert!(got.is_empty(), "{got:?}");
    assert_eq!(
        n.load(std::sync::atomic::Ordering::SeqCst),
        1 + crate::crawl::DOM_MAX_REQUESTS_PER_PROBE,
        "one baseline plus 64 admitted-operation requests including submission"
    );
}

#[test]
fn dom_form_action_real_properties_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, move |_, path, _| {
        let tag = if path.starts_with("/button") {
            "button"
        } else {
            "input"
        };
        let body=format!("<html><head><link rel='icon' href='data:,'></head><script>var e=document.createElement('{tag}');e.formAction=location.hash;</script></html>");
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
    });
    for path in ["/button", "/input"] {
        let got = lab_scan(
            port,
            &["active.dom-link-manipulation"],
            "GET",
            path,
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert!(
            got.iter()
                .any(|(n, _, c)| n == "Link manipulation (DOM-based)" && c == "Firm"),
            "{path}: {got:?}"
        );
    }
}

/// R-13 prototype pollution on the shared DOM probe, under two-token
/// source attribution: a page deep-merging the query string pollutes
/// Object.prototype from __proto__[key] (location.search provenance,
/// reported Tentative under the conservative rule); a page deep-merging
/// the fragment does the same (location.hash, Firm); a page that only
/// reflects the payload into a sink has NOT polluted (reflection is not
/// pollution); a page filtering those keys is clean. Bounded fixtures:
/// loopback-only lab, throwaway browser profile per probe, random inert
/// tokens, so the pollution lives only inside the probe browser.
/// Skipped when no Chromium is available.
#[test]
fn dom_prototype_pollution_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, |_method, path, _raw| {
        let merge = r#"function setpath(o, parts, v) { var cur = o; for (var i = 0; i < parts.length - 1; i++) { if (typeof cur[parts[i]] !== 'object' || cur[parts[i]] === null) { cur[parts[i]] = {}; } cur = cur[parts[i]]; } cur[parts[parts.length - 1]] = v; }
function parseqs(s, filter) { var cfg = {}; s.replace(/^[?#]/, '').split('&').forEach(function (p) { if (!p) { return; } var kv = p.split('='); var parts = kv[0].split('[').map(function (x) { return x.replace(/\]$/, ''); }); if (filter && (parts[0] === '__proto__' || parts[0] === 'constructor' || parts[0] === 'prototype')) { return; } setpath(cfg, parts, decodeURIComponent(kv[1] || '')); }); }"#;
        let body = if path.starts_with("/vulnpp-hash") {
            format!("<html><body><script>\n{merge}\nparseqs(location.hash, false);\n</script></body></html>")
        } else if path.starts_with("/vulnpp") {
            format!("<html><body><script>\n{merge}\nparseqs(location.search, false);\n</script></body></html>")
        } else if path.starts_with("/reflectpp") {
            "<html><body><script>document.write('<p>' + location.hash + '</p>');</script></body></html>".to_string()
        } else if path.starts_with("/safepp") {
            format!("<html><body><script>\n{merge}\nparseqs(location.search, true);\nparseqs(location.hash, true);\n</script></body></html>")
        } else {
            "<html><body><p>hello</p></body></html>".to_string()
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let host = format!("127.0.0.1:{port}");
    for (page, confidence) in [
        ("/vulnpp", Some("Tentative")),
        ("/vulnpp-hash", Some("Firm")),
        ("/reflectpp", None),
        ("/safepp", None),
    ] {
        let got = lab_scan(
            port,
            &["active.dom-prototype-pollution"],
            "GET",
            page,
            format!("GET {page} HTTP/1.1\r\nHost: {host}\r\n\r\n"),
        );
        let hit = got
            .iter()
            .find(|(n, s, _)| n == "Client-side prototype pollution" && s == "info");
        match confidence {
            Some(c) => assert_eq!(hit.map(|(_, _, x)| x.as_str()), Some(c), "{page}: {got:?}"),
            None => assert!(hit.is_none(), "{page}: {got:?}"),
        }
    }
}

/// Multi-family isolation regression, one navigation: a page that
/// deep-merges the query string (query token) AND passes the fragment to
/// an HTML sink (fragment token) must yield one pollution finding and
/// one DOM-XSS finding, each keeping its own family, source and
/// confidence - neither token may label the other family's finding. A
/// page that only reflects the fragment (no new Object.prototype own
/// key) yields the XSS finding and NO pollution finding, and a page that
/// leaves the prototype unchanged yields neither. This coverage is
/// ADDITION-ONLY: it pins detection and attribution of added properties
/// and makes no overwrite-detection claim (tracked as a follow-up).
/// Bounded: loopback lab, one throwaway browser profile per run, random
/// inert tokens. Skipped when no Chromium is available.
#[test]
fn dom_prototype_pollution_multi_family_isolation_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let visits = Arc::new(AtomicUsize::new(0));
    let count = visits.clone();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, move |_method, path, _raw| {
        if path.starts_with("/mixed") {
            count.fetch_add(1, Ordering::SeqCst);
        }
        let merge = r#"function setpath(o, parts, v) { var cur = o; for (var i = 0; i < parts.length - 1; i++) { if (typeof cur[parts[i]] !== 'object' || cur[parts[i]] === null) { cur[parts[i]] = {}; } cur = cur[parts[i]]; } cur[parts[parts.length - 1]] = v; }
function parseqs(s) { var cfg = {}; s.replace(/^[?#]/, '').split('&').forEach(function (p) { if (!p) { return; } var kv = p.split('='); var parts = kv[0].split('[').map(function (x) { return x.replace(/\]$/, ''); }); setpath(cfg, parts, decodeURIComponent(kv[1] || '')); }); }"#;
        let body = if path.starts_with("/mixed") {
            // Query token pollutes the prototype; fragment token reaches
            // an HTML sink. One navigation, two families.
            format!("<html><body><script>\n{merge}\nparseqs(location.search);\ndocument.body.innerHTML = '<p>' + location.hash + '</p>';\n</script></body></html>")
        } else if path.starts_with("/reflectonly") {
            "<html><body><script>document.body.innerHTML = '<p>' + location.hash + '</p>';</script></body></html>".to_string()
        } else if path.starts_with("/unchanged") {
            "<html><body><script>var x = 1 + 1; document.title = 't' + x;</script></body></html>"
                .to_string()
        } else {
            "<html><body><p>hello</p></body></html>".to_string()
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let run = |path: &str| {
        let shared = crate::net::Shared::new();
        let mut config = crate::scan_config::ScanConfig::default();
        for (id, ..) in crate::scan::check_catalogue() {
            if !["active.dom-prototype-pollution", "active.dom-xss"].contains(&id) {
                config.disabled_checks.insert(id.into());
            }
        }
        *crate::scan_config::shared_config(&shared).lock().unwrap() = config;
        let e = crate::net::HistEntry {
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            path: path.into(),
            req_raw: format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
                .into_bytes()
                .into(),
            ..Default::default()
        };
        crate::scan::start_active_scan(shared.clone(), e, &[], &[]);
        let start = std::time::Instant::now();
        while shared.scan.is_busy() && start.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!shared.scan.is_busy(), "scan did not finish");
        let issues = shared.issues.lock().unwrap();
        (issues
            .iter()
            .map(|i| {
                (
                    i.name.clone(),
                    i.sev.clone(),
                    i.confidence.clone(),
                    i.detail.clone(),
                )
            })
            .collect::<Vec<_>>(),)
    };
    let (mixed,) = run("/mixed");
    let pp: Vec<_> = mixed
        .iter()
        .filter(|(n, ..)| n == "Client-side prototype pollution")
        .collect();
    let xss: Vec<_> = mixed
        .iter()
        .filter(|(n, ..)| n == "Cross-site scripting (DOM-based)")
        .collect();
    assert_eq!(pp.len(), 1, "one pollution finding: {mixed:?}");
    assert_eq!(xss.len(), 1, "one DOM-XSS finding: {mixed:?}");
    // The pollution finding belongs to the query token: search
    // provenance, conservative Tentative, and no hash labeling.
    assert_eq!(pp[0].1, "info");
    assert_eq!(pp[0].2, "Tentative", "{:?}", pp[0].3);
    assert!(pp[0].3.contains("location.search"), "{:?}", pp[0].3);
    assert!(!pp[0].3.contains("location.hash"), "{:?}", pp[0].3);
    // The XSS finding belongs to the fragment token: hash provenance,
    // Firm, and no search labeling.
    assert_eq!(xss[0].1, "high");
    assert_eq!(xss[0].2, "Firm", "{:?}", xss[0].3);
    assert!(xss[0].3.contains("location.hash"), "{:?}", xss[0].3);
    assert!(!xss[0].3.contains("location.search"), "{:?}", xss[0].3);
    assert_eq!(
        visits.load(Ordering::SeqCst),
        3,
        "one baseline, one submission and one shared DOM navigation served both families"
    );
    // A reflected token with no new Object.prototype own key: XSS yes,
    // pollution no.
    let (reflect,) = run("/reflectonly");
    assert!(
        reflect
            .iter()
            .any(|(n, ..)| n == "Cross-site scripting (DOM-based)"),
        "{reflect:?}"
    );
    assert!(
        !reflect
            .iter()
            .any(|(n, ..)| n == "Client-side prototype pollution"),
        "reflection must not be reported as pollution: {reflect:?}"
    );
    // Unchanged prototype: neither family reports.
    let (unchanged,) = run("/unchanged");
    assert!(unchanged.is_empty(), "{unchanged:?}");
}

/// Combined #186/pollution contract, addition-only. Stored-only prototype
/// additions are deliberately not covered. One admitted operation serves
/// both families, including separate hash/query pollution and stored DOM
/// evidence. No overwrite-detection claim.
#[test]
fn dom_pollution_stored_exclusion_and_combined_budget_against_a_live_lab() {
    if crate::crawl::chromium_binary().is_none() {
        return;
    }
    use std::sync::{Arc, Mutex};
    let wire = Arc::new(Mutex::new(Vec::<String>::new()));
    let captured = wire.clone();
    let previous = Arc::new(Mutex::new(
        std::collections::HashMap::<String, String>::new(),
    ));
    let store = previous.clone();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, move |_, path, raw| {
        if raw.is_empty() {
            return String::new();
        }
        captured.lock().unwrap().push(path.to_string());
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let prior = store
            .lock()
            .unwrap()
            .get(route)
            .cloned()
            .unwrap_or_default();
        if !query.is_empty() {
            store.lock().unwrap().insert(route.into(), query.into());
        }
        let merge = r#"function merge(s) { s.replace(/^[?#]/,'').split('&').forEach(function(p) {var m=/^__proto__\[([^\]]+)\]=(.*)$/.exec(p);if(m) Object.prototype[m[1]]=decodeURIComponent(m[2]);}); }"#;
        let script = match route {
            "/ppmixed" | "/ppcap" => format!("{merge} merge('{prior}');merge(location.search);merge(location.hash);document.write('<p>{prior}</p>');document.write('<p>{prior}</p>');"),
            "/ppstored" => format!("{merge} merge('{prior}');document.write('<p>{prior}</p>');"),
            "/ppmixedtoken" => format!("var m=/__proto__\\[([^\\]]+)\\]/.exec(location.search);if(m)Object.prototype[m[1]]='{prior}';document.write('<p>{prior}</p>');"),
            "/ppreflect" => "document.write('<p>'+location.hash+'</p>');".into(),
            _ => "void 0".into(),
        };
        let resources = if route == "/ppcap" {
            (0..100)
                .map(|i| format!("<img src='/ppresource/{i}'>"))
                .collect::<String>()
        } else {
            String::new()
        };
        let body = format!("<html><head><link rel='icon' href='data:,'></head><body><script>{script}</script>{resources}</body></html>");
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
    });
    for route in [
        "/ppmixed",
        "/ppstored",
        "/ppmixedtoken",
        "/ppreflect",
        "/ppunchanged",
        "/ppcap",
    ] {
        wire.lock().unwrap().clear();
        let shared = crate::net::Shared::new();
        let mut config = crate::scan_config::ScanConfig::default();
        for (id, ..) in crate::scan::check_catalogue() {
            if !["active.dom-prototype-pollution", "active.dom-xss"].contains(&id) {
                config.disabled_checks.insert(id.into());
            }
        }
        *crate::scan_config::shared_config(&shared).lock().unwrap() = config;
        let e = crate::net::HistEntry {
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            path: route.into(),
            req_raw: format!("GET {route} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
                .into_bytes()
                .into(),
            ..Default::default()
        };
        crate::scan::start_active_scan(shared.clone(), e, &[], &[]);
        let start = std::time::Instant::now();
        while shared.scan.is_busy() && start.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!shared.scan.is_busy(), "scan timeout: {route}");
        let issues = shared.issues.lock().unwrap();
        let summary = issues
            .iter()
            .map(|i| (&i.name, &i.confidence, &i.detail))
            .collect::<Vec<_>>();
        let pollution: Vec<_> = issues
            .iter()
            .filter(|i| i.name == "Client-side prototype pollution")
            .collect();
        let stored: Vec<_> = issues
            .iter()
            .filter(|i| i.name == "Cross-site scripting (stored DOM-based)")
            .collect();
        let requests = wire.lock().unwrap();
        let expected = if route == "/ppcap" {
            1 + crate::crawl::DOM_MAX_REQUESTS_PER_PROBE
        } else {
            3
        };
        assert_eq!(
            requests.len(),
            expected,
            "shared operation count: {route}: {requests:?}"
        );
        let submission = requests[1].split_once('?').unwrap().1;
        let stored_token = submission
            .split_once('[')
            .unwrap()
            .1
            .split(']')
            .next()
            .unwrap();
        let query = requests[2].split_once('?').unwrap().1;
        let query_token = query.split_once('[').unwrap().1.split(']').next().unwrap();
        assert_ne!(stored_token, query_token);
        match route {
            "/ppmixed" | "/ppcap" => {
                assert_eq!(pollution.len(), 2, "separate query/hash dedup: {summary:?}");
                for (source, confidence) in
                    [("location.search", "Tentative"), ("location.hash", "Firm")]
                {
                    let found: Vec<_> = pollution
                        .iter()
                        .filter(|i| i.detail.contains(&format!("read from <b>{source}</b>")))
                        .collect();
                    assert_eq!(found.len(), 1, "{source}: {summary:?}");
                    assert_eq!(found[0].confidence, confidence);
                    assert_eq!(found[0].sev, "info");
                    assert!(
                        !found[0].detail.contains(stored_token),
                        "stored must not label pollution"
                    );
                    assert_eq!(
                        found[0].detail.contains(query_token),
                        source == "location.search",
                        "token isolation"
                    );
                }
                assert_eq!(stored.len(), 1, "stored XSS dedup: {summary:?}");
                assert_eq!(issues.len(), 3, "no extra variants: {summary:?}");
            }
            "/ppstored" | "/ppmixedtoken" => {
                assert!(
                    pollution.is_empty(),
                    "stored pollution must not be reported: {summary:?}"
                );
                assert_eq!(stored.len(), 1);
                assert_eq!(issues.len(), 1);
            }
            "/ppreflect" => {
                assert!(
                    pollution.is_empty(),
                    "reflection is not pollution: {summary:?}"
                );
                assert_eq!(issues.len(), 1);
                assert_eq!(issues[0].name, "Cross-site scripting (DOM-based)");
                assert_eq!(issues[0].confidence, "Firm");
            }
            _ => assert!(issues.is_empty(), "unchanged prototype: {summary:?}"),
        }
        for hit in stored {
            assert_eq!(hit.confidence, "Tentative");
            assert_eq!(hit.sev, "high");
            assert!(hit.detail.contains(stored_token));
            assert!(!hit.detail.contains(query_token));
            assert!(!hit.detail.contains("location.hash"));
            assert!(!hit.detail.contains("location.search"));
        }
    }
}
