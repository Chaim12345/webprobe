//! Manually generated issues (burp.Zgwg / Zr7j / Zp_6 / Zcxr.ZD / Zchl).
//! The service and path vectors were checked against the reference build:
//! burp.Zpw7.ZT and burp.Zuub.Zu called by reflection on
//! /root/burp-re/in/burpsuite.jar.

use super::*;

#[test]
fn dialog_opens_with_the_messages_service_and_path() {
    let req = b"GET /a/b?q=1 HTTP/1.1\r\nHost: x.test\r\n\r\n";
    let f = ManualIssueForm::for_message("x.test", 443, true, req);
    assert_eq!(f.service, "https://x.test");
    assert_eq!(f.path, "/a/b?q=1", "Burp keeps the query string");
    assert_eq!(f.severity, "Information");
    assert_eq!(f.confidence, "Certain");
    assert!(f.name.is_empty() && f.detail.is_empty() && f.remediation.is_empty());
    // Burp's service text (burp.Zxrb.ZC).
    assert_eq!(service_url("x.test", 80, false), "http://x.test");
    assert_eq!(service_url("x.test", 8443, true), "https://x.test:8443");
    assert_eq!(service_url("x.test", 443, false), "http://x.test:443");
    assert_eq!(service_url("::1", 8080, false), "http://[::1]:8080");
    // An absolute http:// target is cut to its path (burp.Zudh.Zc).
    assert_eq!(
        request_target(b"GET http://x.test/p?z HTTP/1.1\r\n\r\n").as_deref(),
        Some("/p?z")
    );
    assert_eq!(request_target(b"GET\r\n\r\n"), None);
    assert_eq!(
        request_target(b"GET  /two-spaces HTTP/1.1").as_deref(),
        Some("/two-spaces")
    );
}

#[test]
fn service_follows_burps_validator() {
    for (s, ok) in [
        ("https://example.com", true),
        ("http://example.com:8080", true),
        ("example.com", false),
        ("https://example.com/", false),
        ("https://example.com:0", false),
        ("https://ex ample.com", false),
        ("HTTPS://Example.com", false),
        ("ftp://a.com", false),
        ("https://a.com:443", true),
        ("https://a_b.com", true),
        ("https://-a.com", true),
        ("https://.a.com", false),
        ("https://a..b", false),
        ("https://127.0.0.1", true),
        ("https://[::1]", false),
        ("https://[::1]:8443", false),
        ("https://a.com:65535", true),
        ("https://a.com:65536", false),
        ("https://a.com:", false),
        ("https://a.com:abc", false),
        ("http://localhost", true),
        ("https://xn--bcher-kva.example", true),
        ("https://\u{e9}.com", false),
        ("https://a.com:080", true),
    ] {
        assert_eq!(parse_service(s).is_some(), ok, "{s}");
    }
    assert_eq!(
        parse_service("https://a.com"),
        Some(("a.com".into(), 443, true))
    );
    assert_eq!(
        parse_service("http://a.com"),
        Some(("a.com".into(), 80, false))
    );
    assert_eq!(
        parse_service("https://a.com:080"),
        Some(("a.com".into(), 80, true))
    );
}

#[test]
fn path_follows_burps_validator() {
    for (p, ok) in [
        ("/", true),
        ("/a b", false),
        ("/a?x=1", true),
        ("a", true),
        ("", false),
        ("/%zz", false),
        ("/a#b", true),
        ("//x", true),
        ("/a\"b", false),
        ("/a<b", false),
        ("/a>b", false),
        ("/a|b", false),
        ("/\u{e9}", true),
        ("/a%2", false),
        ("/a%2g", false),
        ("/a%20b", true),
        ("/a#b#c", false),
        ("/[x]", false),
        ("/a\tb", false),
        ("/a{b}", false),
        ("/a^b", false),
        ("/a`b", false),
        ("/a\\b", false),
        ("/~!$&'()*+,;=:@", true),
        ("/?a=b&c=d", true),
        ("@evil.com", true),
        ("/a%", false),
        ("x y", false),
        (":80/a", true),
        ("/\u{1}", false),
        (":abc", false),
        ("/a?b?c", true),
        ("/%41", true),
    ] {
        assert_eq!(path_valid(p), ok, "{p:?}");
    }
}

#[test]
fn validation_names_the_bad_fields_in_burps_order() {
    let mut f = ManualIssueForm::for_message("x.test", 443, true, b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(f.error_text().as_deref(), Some("Invalid: name"));
    f.name = "   ".into();
    f.service = "x.test".into();
    f.path = String::new();
    assert_eq!(f.invalid_fields(), ["name", "HTTP service", "path"]);
    assert_eq!(
        f.error_text().as_deref(),
        Some("Invalid: name, HTTP service, path")
    );
    f.name = "Weak lockout".into();
    f.service = "https://x.test".into();
    f.path = "/login".into();
    assert_eq!(f.error_text(), None);
}

#[test]
fn created_issue_is_a_manual_issue_with_the_message_as_evidence() {
    let req = b"POST /login?next=/ HTTP/1.1\r\nHost: x.test\r\n\r\nu=a";
    let resp = b"HTTP/1.1 200 OK\r\n\r\nwelcome";
    let mut f = ManualIssueForm::for_message("x.test", 8443, true, req);
    f.name = "No account lockout".into();
    f.severity = "Medium".into();
    f.confidence = "Firm".into();
    f.detail = "Ten <b>wrong</b> passwords & no lockout.".into();
    f.remediation = "Lock the account.".into();
    let i = mk_manual_issue(&f, req, Some(resp)).expect("valid form");
    assert_eq!(i.type_id, 0x0800_8000);
    assert_eq!(i.type_id, issue_type_id("Manually generated issue"));
    assert_eq!(i.name, "No account lockout");
    assert_eq!(
        (i.host.as_str(), i.path.as_str()),
        ("x.test", "/login?next=/")
    );
    assert_eq!((i.sev.as_str(), i.confidence.as_str()), ("medium", "Firm"));
    assert!(!i.false_positive);
    // User text is shown, not interpreted (burp.Zevt.Ze escapes the tags).
    assert!(
        i.detail
            .contains("Ten &lt;b&gt;wrong&lt;/b&gt; passwords & no lockout."),
        "{}",
        i.detail
    );
    assert!(i.detail.contains("Remediation detail") && i.detail.contains("Lock the account."));
    assert_eq!(i.evidence, vec![ScanEvidence::new(req, Some(resp))]);
    assert!(is_manual_issue(&i));

    // Blank detail and remediation are left out (burp.Zp_6: blank = null).
    f.detail = "  ".into();
    f.remediation = String::new();
    f.severity = "False positive".into();
    let i = mk_manual_issue(&f, req, None).unwrap();
    assert!(i.detail.is_empty());
    assert!(i.false_positive && i.sev == "info");
    // The host comes from the typed service, not the message.
    f.service = "http://other.test:81".into();
    assert_eq!(mk_manual_issue(&f, req, None).unwrap().host, "other.test");
    f.service = "other.test".into();
    assert!(mk_manual_issue(&f, req, None).is_none());
}

#[test]
fn add_to_issue_appends_evidence_to_manual_issues_only() {
    let req1 = b"GET /a HTTP/1.1\r\n\r\n";
    let req2 = b"GET /b HTTP/1.1\r\n\r\n";
    let mut f = ManualIssueForm::for_message("x.test", 443, true, req1);
    f.name = "Manual".into();
    let mut i = mk_manual_issue(&f, req1, Some(b"HTTP/1.1 200 OK\r\n\r\n")).unwrap();
    assert!(add_manual_evidence(
        &mut i,
        req2,
        Some(b"HTTP/1.1 404 Not Found\r\n\r\n")
    ));
    assert_eq!(i.evidence.len(), 2);
    assert_eq!(
        &i.evidence[0].request[..],
        req1,
        "the first exchange is kept"
    );
    assert_eq!(&i.evidence[1].request[..], req2);
    // A scanner issue is not offered and takes nothing.
    let mut scanner = ScanIssue {
        name: "SQL injection".into(),
        type_id: issue_type_id("SQL injection"),
        ..Default::default()
    };
    assert!(!is_manual_issue(&scanner));
    assert!(!add_manual_evidence(&mut scanner, req2, None));
    assert!(scanner.evidence.is_empty());
}
