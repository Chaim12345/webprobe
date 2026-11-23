use super::*;

#[test]
fn react2shell_requires_the_specific_marker() {
    assert!(react2shell_hit("500", r#"...E{"digest":"abc"}..."#));
    // generic error words alone are just an error page, not React2Shell
    assert!(!react2shell_hit("500", "Error: invalid digest supplied"));
    assert!(!react2shell_hit("200", r#"E{"digest":"abc"}"#));
}

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
            "active.css-injection",
            "active.client-side-hpp",
            "active.form-action-hijacking",
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
        [
            "active.xss-stored",
            "active.link-manipulation-stored",
            "active.css-injection-stored",
            "active.client-side-hpp-stored",
            "active.form-action-hijacking-stored"
        ]
    );
    let requests: Vec<(&str, Scope, Option<&str>)> = REQUEST_CHECKS
        .iter()
        .map(|c| (c.id(), c.scope(), c.group()))
        .collect();
    assert_eq!(
        requests,
        [
            ("active.cors", Scope::Request, Some(BURP_GROUP)),
            (
                "active.path-relative-style-sheet-import",
                Scope::Request,
                Some(BURP_GROUP)
            ),
            ("active.http-trace-enabled", Scope::Host, Some(BURP_GROUP)),
            ("active.robots-txt", Scope::Host, Some(BURP_GROUP)),
            ("active.react2shell", Scope::Host, Some(BURP_GROUP)),
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
            ("active.broken-access-control", Scope::Request, None),
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

/// R-10 G.15: the lab serves the same page with or without the
/// session cookie on /open (broken access control) and 403s without
/// it on /guarded (enforced). The check must report /open only.
#[test]
fn r10_broken_access_control_against_a_live_lab() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(l, |_method, target, raw| {
        let authed = raw.to_ascii_lowercase().contains("\r\ncookie:");
        let (status, body) = match (target.split('?').next().unwrap_or(""), authed) {
            ("/open", _) => (
                "200 OK",
                "<html><head><title>account</title></head><body>same</body></html>".to_string(),
            ),
            ("/guarded", true) => (
                "200 OK",
                "<html><head><title>account</title></head><body>same</body></html>".to_string(),
            ),
            ("/guarded", false) => (
                "403 Forbidden",
                "<html><head><title>denied</title></head></html>".to_string(),
            ),
            _ => ("404 Not Found", String::new()),
        };
        format!("HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
    });
    let host = format!("127.0.0.1:{port}");
    // Session material removed (cookie + x-*) and the page unchanged:
    // reported.
    let req = format!("GET /open HTTP/1.1\r\nHost: {host}\r\nCookie: sid=abc\r\nX-Csrf: t\r\n\r\n");
    let got = lab_scan(port, &["active.broken-access-control"], "GET", "/open", req);
    assert!(
        got.iter()
            .any(|(i, s, c)| i == "Broken access control" && s == "info" && c == "Tentative"),
        "{got:?}"
    );
    // The response changes without the session: not reported.
    let req = format!("GET /guarded HTTP/1.1\r\nHost: {host}\r\nCookie: sid=abc\r\n\r\n");
    let got = lab_scan(
        port,
        &["active.broken-access-control"],
        "GET",
        "/guarded",
        req,
    );
    assert!(got.is_empty(), "{got:?}");
    // Nothing to remove: not reported.
    let req = format!("GET /open HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let got = lab_scan(port, &["active.broken-access-control"], "GET", "/open", req);
    assert!(got.is_empty(), "{got:?}");
}

#[test]
fn bac_non_get_sends_no_requests_beyond_the_scanner_baseline() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = requests.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(listener, move |_, _, _| {
        seen.fetch_add(1, Ordering::SeqCst);
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".into()
    });
    for method in ["POST", "HEAD"] {
        requests.store(0, Ordering::SeqCst);
        let req = format!(
            "{method} / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: sid=abc\r\nContent-Length: 0\r\n\r\n"
        );
        let issues = lab_scan(port, &["active.broken-access-control"], method, "/", req);
        assert!(issues.is_empty(), "{method} must be skipped");
        assert_eq!(
            requests.load(Ordering::SeqCst),
            1,
            "{method}: only the scanner baseline is allowed"
        );
    }
}

#[test]
fn host_probe_checks_use_expected_requests_and_reject_soft_errors() {
    use std::sync::{Arc, Mutex};
    for positive in [true, false] {
        let captured = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
        let seen = captured.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = lab_serve(listener, move |method, path, raw| {
            seen.lock()
                .unwrap()
                .push((method.into(), path.into(), raw.into()));
            let (status, content_type, body) = if path == "/robots.txt" {
                if positive {
                    ("200 OK", "text/plain", "User-agent: *\nDisallow: /admin")
                } else {
                    ("200 OK", "text/html", "<html>User-agent: * Allow: /</html>")
                }
            } else if method == "POST" {
                if positive {
                    (
                        "500 Internal Server Error",
                        "text/x-component",
                        "0:E{\"digest\":\"abc\"}",
                    )
                } else {
                    (
                        "500 Internal Server Error",
                        "text/plain",
                        "Error: invalid digest supplied",
                    )
                }
            } else {
                ("200 OK", "text/x-component", "ok")
            };
            format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        });
        let req = format!("GET /start HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        let issues = lab_scan(
            port,
            &["active.robots-txt", "active.react2shell"],
            "GET",
            "/start",
            req,
        );
        assert_eq!(issues.len(), if positive { 2 } else { 0 }, "{issues:?}");
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 3, "one baseline and two probes");
        assert_eq!(
            captured
                .iter()
                .filter(|(m, p, _)| m == "GET" && p == "/robots.txt")
                .count(),
            1
        );
        let post = captured
            .iter()
            .find(|(m, p, _)| m == "POST" && p == "/")
            .unwrap();
        assert!(post.2.contains("Next-Action:"));
        assert!(post.2.contains("[\"$1:a:a\"]"));
    }
}

#[test]
fn react2shell_does_not_post_without_a_fingerprint() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lab_serve(listener, move |_, _, _| {
        seen.fetch_add(1, Ordering::SeqCst);
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into()
    });
    let req = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
    let issues = lab_scan(port, &["active.react2shell"], "GET", "/", req);
    assert!(issues.is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 1, "baseline only, no POST");
    assert!(is_burp_issue(
        "React Server Components remote code execution (React2Shell)"
    ));
}

/// Host-probe dedupe claims must be released when the probe's transport
/// fails, so a later scan of the same host retries instead of treating
/// the host as done. The lab drops the first /robots.txt GET and the
/// first React2Shell POST (accepted, then closed without a response)
/// and answers the retries; a second scan of the same entry must send
/// both probes again and report both issues.
#[test]
fn host_probe_claim_is_released_when_the_probe_transport_fails() {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    // (robots GET attempts, react2shell POST attempts), across both scans.
    let attempts = Arc::new(Mutex::new((0usize, 0usize)));
    let seen = attempts.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut s = s;
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                // Peek (without consuming) until the request head classifies.
                // For a "dropped" probe the socket is then closed with the
                // request still unread, which makes the kernel RST the
                // connection: a real transport failure, not a clean EOF.
                let mut buf = [0u8; 8192];
                let head_len = loop {
                    match s.peek(&mut buf) {
                        Ok(0) => return,
                        Ok(m) => {
                            if String::from_utf8_lossy(&buf[..m])
                                .find("\r\n\r\n")
                                .is_some()
                            {
                                break m;
                            }
                        }
                        Err(_) => return,
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_len]).to_string();
                let method = head.split_whitespace().next().unwrap_or("").to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let probe = if path == "/robots.txt" {
                    let mut a = seen.lock().unwrap();
                    a.0 += 1;
                    Some((a.0, false))
                } else if method == "POST" {
                    let mut a = seen.lock().unwrap();
                    a.1 += 1;
                    Some((a.1, true))
                } else {
                    None
                };
                if let Some((1, _)) = probe {
                    // First probe of each kind: drop with the request unread.
                    return;
                }
                // Answered request: consume it fully, then respond.
                let mut raw = Vec::new();
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
                let resp = match probe {
                    Some((_, false)) => {
                        let body = "User-agent: *\nDisallow: /admin";
                        format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                    }
                    Some((_, true)) => {
                        let body = "0:E{\"digest\":\"abc\"}";
                        format!("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/x-component\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                    }
                    None => {
                        // Baseline: Next.js/RSC fingerprint so React2Shell arms.
                        "HTTP/1.1 200 OK\r\nContent-Type: text/x-component\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
                    }
                };
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    // One Shared for both scans: start_active_scan does not reset
    // scan_state (only crawl_and_audit does), so a claim that survives
    // the first scan would suppress the retry in the second.
    let shared = crate::net::Shared::new();
    let mut cfg = crate::scan_config::ScanConfig::default();
    for (id, ..) in crate::scan::check_catalogue() {
        if !["active.robots-txt", "active.react2shell"].contains(&id) {
            cfg.disabled_checks.insert(id.into());
        }
    }
    *crate::scan_config::shared_config(&shared).lock().unwrap() = cfg;
    let run_scan = |shared: &Arc<crate::net::Shared>| {
        let mut e = crate::net::HistEntry {
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            path: "/start".into(),
            ..Default::default()
        };
        e.req_raw = format!("GET /start HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
            .into_bytes()
            .into();
        crate::scan::start_active_scan(shared.clone(), e, &[], &[]);
        let t0 = std::time::Instant::now();
        while shared.scan.is_busy() && t0.elapsed() < std::time::Duration::from_secs(60) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!shared.scan.is_busy(), "scan did not finish");
    };
    // One task batch must never retry either uncertain attempt.
    let batch = crate::scan::StoredBatch::open(&shared);
    // First scan: both probes die on the wire, so nothing is reported.
    run_scan(&shared);
    assert_eq!(*attempts.lock().unwrap(), (1, 1), "one attempt each");
    assert!(
        shared.issues.lock().unwrap().is_empty(),
        "dropped probes report nothing"
    );
    run_scan(&shared);
    assert_eq!(
        *attempts.lock().unwrap(),
        (1, 1),
        "RST must not retry within batch"
    );
    drop(batch);
    // Only a later explicit scan may retry uncertain probes.
    run_scan(&shared);
    assert_eq!(
        *attempts.lock().unwrap(),
        (2, 2),
        "released claims are retried"
    );
    let issues = shared.issues.lock().unwrap();
    let names: Vec<&str> = issues.iter().map(|i| i.name.as_str()).collect();
    assert!(names.contains(&"Robots.txt file"), "{names:?}");
    assert!(
        names.contains(&"React Server Components remote code execution (React2Shell)"),
        "{names:?}"
    );
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
fn host_probe_incomplete_wire_attempts_wait_for_a_new_explicit_scan() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    for check in ["active.robots-txt", "active.react2shell"] {
        for (wire, complete) in [
            ("", false),
            ("HTTP/1.1 200 OK\r\nContent-Leng", false),
            ("HTTP/1.1 100 Continue\r\n\r\n", false),
            ("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nno", false),
            ("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno", true),
        ] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let seen = attempts.clone();
            let port = lab_serve(
                std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
                move |method, path, _| {
                    if (check == "active.robots-txt" && path == "/robots.txt")
                        || (check == "active.react2shell" && method == "POST")
                    {
                        seen.fetch_add(1, Ordering::SeqCst);
                        wire.to_string()
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Type: text/x-component\r\nContent-Length: 0\r\n\r\n".into()
                    }
                },
            );
            let shared = crate::net::Shared::new();
            let mut cfg = crate::scan_config::ScanConfig::default();
            for (id, ..) in crate::scan::check_catalogue() {
                if id != check {
                    cfg.disabled_checks.insert(id.into());
                }
            }
            *crate::scan_config::shared_config(&shared).lock().unwrap() = cfg;
            let run = || {
                let e = crate::net::HistEntry {
                    method: "GET".into(),
                    host: "127.0.0.1".into(),
                    port,
                    path: "/start".into(),
                    req_raw: format!("GET /start HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
                        .into_bytes()
                        .into(),
                    ..Default::default()
                };
                crate::scan::start_active_scan(shared.clone(), e, &[], &[]);
                assert!(shared
                    .scan
                    .wait_idle(Some(std::time::Duration::from_secs(10))));
            };
            let batch = crate::scan::StoredBatch::open(&shared);
            run();
            run();
            assert_eq!(
                attempts.load(Ordering::SeqCst),
                1,
                "same batch must not resend {wire:?}"
            );
            drop(batch);
            run();
            assert_eq!(
                attempts.load(Ordering::SeqCst),
                if complete { 1 } else { 2 },
                "next explicit run {wire:?}"
            );
            assert!(shared.issues.lock().unwrap().is_empty());
            if !complete {
                assert!(shared
                    .events
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|e| e.contains("incomplete")));
            }
        }
    }
}

#[test]
fn host_probe_unknown_routed_batch_has_zero_direct_egress() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let direct = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    direct.set_nonblocking(true).unwrap();
    let target = direct.local_addr().unwrap().port();
    let attempts = Arc::new(AtomicUsize::new(0));
    let seen = attempts.clone();
    let proxy_port = lab_serve(
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        move |_, path, _| {
            if path.ends_with("/robots.txt") {
                seen.fetch_add(1, Ordering::SeqCst);
                String::new()
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into()
            }
        },
    );
    let shared = crate::net::Shared::new();
    *shared.upstream.lock().unwrap() = crate::upstream::UpstreamConfig {
        kind: crate::upstream::UpstreamKind::Http,
        host: "127.0.0.1".into(),
        port: proxy_port.to_string(),
        ..Default::default()
    };
    let mut cfg = crate::scan_config::ScanConfig::default();
    for (id, ..) in crate::scan::check_catalogue() {
        if id != "active.robots-txt" {
            cfg.disabled_checks.insert(id.into());
        }
    }
    *crate::scan_config::shared_config(&shared).lock().unwrap() = cfg;
    let run = || {
        let e = crate::net::HistEntry {
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port: target,
            path: "/start".into(),
            req_raw: format!("GET /start HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n")
                .into_bytes()
                .into(),
            ..Default::default()
        };
        crate::scan::start_active_scan(shared.clone(), e, &[], &[]);
        assert!(shared
            .scan
            .wait_idle(Some(std::time::Duration::from_secs(10))));
    };
    let batch = crate::scan::StoredBatch::open(&shared);
    run();
    run();
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    drop(batch);
    run();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(matches!(direct.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
}

#[test]
fn parameterized_real_a4_link_registry_retains_meaningful_finding() {
    real_a4_case(0);
}
#[test]
fn real_a4_oversize_charges_record_before_skip() {
    real_a4_case(1);
}
#[test]
fn real_a4_failed_send_is_incomplete_not_negative() {
    real_a4_case(2);
}
#[test]
fn real_a4_paused_caller_expires_without_net_entry() {
    real_a4_case(3);
}
#[test]
fn real_a4_oversize_json_continues_to_valid_finding() {
    real_a4_case(4);
}
#[test]
fn real_a4_retention_exhaustion_never_claims_complete() {
    real_a4_case(5);
}
fn real_a4_case(mode: u8) {
    use crate::scan_lifecycle::{Coordinator, Finish, Handoff};
    let remembered = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let saved = remembered.clone();
    let wire = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = wire.clone();
    let port = lab_serve(
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        move |_, path, _| {
            seen.fetch_add(1, Ordering::SeqCst);
            if path.starts_with("/inject?") {
                let value = path
                    .split_once("?x=")
                    .map(|(_, v)| crate::util::url_decode(v))
                    .unwrap_or_default();
                *saved.lock().unwrap() = value;
            }
            let body = format!("<a href=\"{}\">saved</a>", saved.lock().unwrap());
            format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
        },
    );
    let port = if mode == 2 { 0 } else { port };
    let shared = crate::net::Shared::new();
    if mode == 3 {
        shared.scan.paused.store(true, Ordering::SeqCst);
    }

    let mut cfg = crate::scan_config::ScanConfig::default();
    for check in STORED_CHECKS {
        if check.id() != "active.link-manipulation-stored" {
            cfg.disabled_checks.insert(check.id().into());
        }
    }
    *crate::scan_config::shared_config(&shared).lock().unwrap() = cfg;
    let limits = crate::scan_budget::Limits {
        duration: if mode == 3 {
            std::time::Duration::from_millis(30)
        } else {
            std::time::Duration::from_secs(5)
        },
        http_attempts: 100,
        connection_attempts: 100,
        outgoing: 65536,
        response: 65536,
        decompressed: 65536,
        inputs: 65536,
        evidence: if mode == 5 { 1 } else { 65536 },
        evidence_records: 100,
        records: 100,
    };
    let c = Coordinator::new(shared.clone(), limits).unwrap();
    let batch = c.open().unwrap();
    let make = |path: &str| crate::stored::Item {
        entry: crate::net::HistEntry {
            method: "GET".into(),
            host: "127.0.0.1".into(),
            port,
            path: path.into(),
            ..Default::default()
        },
        req: format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        host: "127.0.0.1".into(),
        port,
        https: false,
    };
    let (a, _, injection) = c.admit(make("/inject?x=old")).unwrap();
    assert!(matches!(a.complete(), Ok(Handoff::Joined)));
    let point = InsertionPoint::new(IpKind::Query, "x", "old");
    let token = shared.stored.token(injection, &point);
    shared
        .stored
        .note_injection(&token, b"injected", Some(b"saved"));
    let (a, _, retrieval) = c.admit(make("/retrieve")).unwrap();
    assert!(matches!(a.complete(), Ok(Handoff::Joined)));
    if mode == 4 {
        let oversized = InsertionPoint::new(IpKind::Json(vec![String::new(); 10000]), "x", "old");
        let huge = shared.stored.token(injection, &oversized);
        shared
            .stored
            .observe(retrieval, b"GET /retrieve", huge.as_bytes());
    }
    assert_eq!(
        shared
            .stored
            .observe(retrieval, b"GET /retrieve", token.as_bytes())
            .len(),
        1
    );
    let Handoff::Finalize(f) = batch.finish().unwrap() else {
        panic!("finalizer")
    };
    let thread_shared = shared.clone();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let mut counts = (0, 0, 0, 0);
        let outcome = f.run(|permit| {
            let result = run_stored_stage_budgeted(
                &thread_shared,
                permit,
                if mode == 4 { 2 } else { 1 },
                if mode == 1 { 1 } else { 8192 },
            );
            use crate::scan_budget::Resource;
            counts = (
                permit.ledger().used(Resource::Record),
                permit.ledger().used(Resource::Input),
                permit.ledger().used(Resource::ConnectionAttempt),
                permit.ledger().used(Resource::EvidenceRecord),
            );
            result
        });
        tx.send((outcome, counts)).unwrap();
    });
    let (outcome, counts) = rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("A4 completion watchdog");
    worker.join().unwrap();
    assert_eq!(
        outcome,
        if mode == 0 {
            Finish::Complete
        } else {
            Finish::Incomplete
        }
    );
    assert_eq!(counts.0, if mode == 4 { 2 } else { 1 });
    if mode == 1 {
        assert_eq!(counts.1, 0);
    }
    if mode == 3 {
        assert_eq!(counts.2, 0);
        assert_eq!(wire.load(Ordering::SeqCst), 0);
        assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 0);
    }
    if mode == 0 || mode == 4 {
        assert!(counts.3 > 0);
    }
    if mode == 5 {
        assert_eq!(counts.3, 0);
    }
    assert_eq!(
        mode == 0 || mode == 4,
        shared
            .issues
            .lock()
            .unwrap()
            .iter()
            .any(|i| i.name == "Link manipulation (stored)")
    );
}

#[test]
fn required_limits_actual_engine_rejects_busy_without_reset_or_egress() {
    use crate::scan_lifecycle::{AdmissionError, Finish, Handoff};
    let wire = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = wire.clone();
    let port = lab_serve(
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        move |_, _, _| {
            seen.fetch_add(1, Ordering::SeqCst);
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into()
        },
    );
    let shared = crate::net::Shared::new();
    {
        let config_slot = crate::scan_config::shared_config(&shared);
        let mut cfg = config_slot.lock().unwrap();
        for (id, ..) in crate::scan::check_catalogue() {
            cfg.disabled_checks.insert(id.into());
        }
    }
    let limits = crate::scan_budget::Limits {
        duration: std::time::Duration::from_secs(5),
        http_attempts: 100,
        connection_attempts: 100,
        outgoing: 65536,
        response: 65536,
        decompressed: 65536,
        inputs: 65536,
        evidence: 65536,
        evidence_records: 100,
        records: 100,
    };
    let engine = crate::scan::ExperimentalEngine::new(shared.clone(), limits).unwrap();
    let batch = engine.open().unwrap();
    let entry = crate::net::HistEntry {
        method: "GET".into(),
        host: "127.0.0.1".into(),
        port,
        path: "/base".into(),
        req_raw: format!("GET /base HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
            .into_bytes()
            .into(),
        ..Default::default()
    };
    assert!(matches!(engine.audit(entry.clone()), Ok(Handoff::Joined)));
    assert_eq!(wire.load(Ordering::SeqCst), 1);
    let Handoff::Finalize(finalizer) = batch.finish().unwrap() else {
        panic!("finalizer")
    };
    shared.scan.stop.store(true, Ordering::SeqCst);
    shared.scan.done.store(77, Ordering::SeqCst);
    assert!(matches!(engine.audit(entry), Err(AdmissionError::Busy)));
    assert!(shared.scan.stop.load(Ordering::SeqCst));
    assert_eq!(shared.scan.done.load(Ordering::SeqCst), 77);
    assert_eq!(wire.load(Ordering::SeqCst), 1);
    assert_eq!(
        finalizer.run(|p| run_stored_stage_budgeted(&shared, p, 10, 8192)),
        Finish::Complete
    );
}

#[test]
fn required_limits_actual_engine_adopts_inflight_baseline_without_second_owner() {
    use crate::scan_lifecycle::{Finish, Handoff};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (at_tx, at_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut raw = [0u8; 4096];
        assert!(stream.read(&mut raw).unwrap() > 0);
        at_tx.send(()).unwrap();
        release_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let shared = crate::net::Shared::new();
    {
        let config_slot = crate::scan_config::shared_config(&shared);
        let mut cfg = config_slot.lock().unwrap();
        for (id, ..) in crate::scan::check_catalogue() {
            cfg.disabled_checks.insert(id.into());
        }
    }
    let limits = crate::scan_budget::Limits {
        duration: std::time::Duration::from_secs(5),
        http_attempts: 100,
        connection_attempts: 100,
        outgoing: 65536,
        response: 65536,
        decompressed: 65536,
        inputs: 65536,
        evidence: 65536,
        evidence_records: 100,
        records: 100,
    };
    let engine = Arc::new(crate::scan::ExperimentalEngine::new(shared.clone(), limits).unwrap());
    let running = engine.clone();
    let entry = crate::net::HistEntry {
        method: "GET".into(),
        host: "127.0.0.1".into(),
        port,
        path: "/base".into(),
        req_raw: format!("GET /base HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
            .into_bytes()
            .into(),
        ..Default::default()
    };
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        done_tx.send(running.audit(entry)).unwrap();
    });
    at_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    let batch = engine.open().unwrap();
    release_tx.send(()).unwrap();
    assert!(matches!(
        done_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap(),
        Ok(Handoff::Joined)
    ));
    worker.join().unwrap();
    server.join().unwrap();
    let Handoff::Finalize(f) = batch.finish().unwrap() else {
        panic!("finalizer")
    };
    assert_eq!(
        f.run(|p| run_stored_stage_budgeted(&shared, p, 10, 8192)),
        Finish::Complete
    );
    assert!(!shared.scan.is_busy());
}

#[test]
fn cancelled_batch_actual_engine_admission_cannot_reset_shared_stop() {
    use crate::scan_lifecycle::{AdmissionError, Finish, Handoff};
    let shared = crate::net::Shared::new();
    let limits = crate::scan_budget::Limits {
        duration: std::time::Duration::from_secs(5),
        http_attempts: 10,
        connection_attempts: 10,
        outgoing: 65536,
        response: 65536,
        decompressed: 65536,
        inputs: 65536,
        evidence: 65536,
        evidence_records: 10,
        records: 10,
    };
    let engine = crate::scan::ExperimentalEngine::new(shared.clone(), limits).unwrap();
    let b = engine.open().unwrap();
    b.cancel_handle().cancel();
    shared.scan.stop.store(true, Ordering::SeqCst);
    shared.scan.done.store(99, Ordering::SeqCst);
    let e = crate::net::HistEntry {
        method: "GET".into(),
        host: "127.0.0.1".into(),
        port: 9,
        req_raw: b"GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"
            .to_vec()
            .into(),
        ..Default::default()
    };
    assert!(matches!(engine.audit(e), Err(AdmissionError::Busy)));
    assert!(matches!(engine.open(), Err(AdmissionError::Busy)));
    assert!(shared.scan.stop.load(Ordering::SeqCst));
    assert_eq!(shared.scan.done.load(Ordering::SeqCst), 99);
    assert_eq!(shared.conns_opened.load(Ordering::SeqCst), 0);
    let Handoff::Finalize(f) = b.finish().unwrap() else {
        panic!("finalizer")
    };
    assert_eq!(f.run(|_| Finish::Complete), Finish::Incomplete);
}
