// Coverage for history recording and its derived fields.
use super::*;
use webprobe_support::ext::Annotations;

fn entry(req: &str, resp: Option<&str>) -> HistEntry {
    HistEntry {
        id: 1,
        method: "GET".into(),
        host: "127.0.0.1".into(),
        port: 80,
        req_raw: req.as_bytes().to_vec().into(),
        resp_raw: resp.map(|r| r.as_bytes().to_vec().into()),
        ..Default::default()
    }
}

#[test]
fn history_host_omits_default_ports() {
    let mut e = entry("GET / HTTP/1.1\r\n\r\n", None);
    e.host = "a.test".into();
    assert_eq!(history_host(&e), "http://a.test");
    e.port = 8080;
    assert_eq!(history_host(&e), "http://a.test:8080");
    e.https = true;
    assert_eq!(history_host(&e), "https://a.test:8080");
    e.port = 443;
    assert_eq!(history_host(&e), "https://a.test");
    e.port = 0;
    assert_eq!(
        history_host(&e),
        "https://a.test",
        "port 0 is shown as default"
    );
}

#[test]
fn derived_fields_detect_params_extension_title_and_cookies() {
    let e = entry(
        "GET /static/app.JS?v=1 HTTP/1.1\r\nHost: h\r\n\r\n",
        Some("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; HttpOnly\r\n\r\n<html><title> Hello </title></html>"),
    );
    let (params, ext, title, cookies) = derive_history_fields(&e);
    assert!(params, "query string counts as params");
    assert_eq!(ext, "js", "lowercased, query ignored");
    assert_eq!(title, "Hello");
    assert_eq!(cookies, "a=1; b=2");
}

#[test]
fn derived_fields_for_plain_requests() {
    let (params, ext, title, cookies) =
        derive_history_fields(&entry("GET /index HTTP/1.1\r\nHost: h\r\n\r\n", None));
    assert!(!params);
    assert_eq!(
        (ext.as_str(), title.as_str(), cookies.as_str()),
        ("", "", "")
    );
    // Cookie header or a urlencoded body count as params; a JSON body does not.
    assert!(derive_history_fields(&entry("GET / HTTP/1.1\r\nCookie: s=1\r\n\r\n", None)).0);
    let form = "POST /f HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=b";
    assert!(derive_history_fields(&entry(form, None)).0);
    let json = "POST /f HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    assert!(!derive_history_fields(&entry(json, None)).0);
}

#[test]
fn extension_comes_from_the_path_not_the_host_of_an_absolute_uri() {
    let e = entry(
        "GET http://files.example.com/dir.d/readme.txt HTTP/1.1\r\n\r\n",
        None,
    );
    assert_eq!(derive_history_fields(&e).1, "txt");
    let bare = entry("GET http://files.example.com HTTP/1.1\r\n\r\n", None);
    assert_eq!(
        derive_history_fields(&bare).1,
        "",
        "host dots are not an extension"
    );
    let dir = entry("GET /a.b/c HTTP/1.1\r\n\r\n", None);
    assert_eq!(
        derive_history_fields(&dir).1,
        "",
        "only the last segment counts"
    );
}

#[test]
fn title_is_empty_for_non_html_or_unterminated_tags() {
    let non_html = entry(
        "GET / HTTP/1.1\r\n\r\n",
        Some("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n<title>x</title>"),
    );
    assert_eq!(derive_history_fields(&non_html).2, "");
    let open = entry(
        "GET / HTTP/1.1\r\n\r\n",
        Some("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title>never closed"),
    );
    assert_eq!(derive_history_fields(&open).2, "");
    let attrs = entry(
        "GET / HTTP/1.1\r\n\r\n",
        Some(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title id=\"t\">With attrs</title>",
        ),
    );
    assert_eq!(derive_history_fields(&attrs).2, "With attrs");
}

#[test]
fn annotations_join_notes_and_set_highlight() {
    let mut e = entry("GET / HTTP/1.1\r\n\r\n", None);
    annotate(&mut e, &Annotations::default());
    assert_eq!(
        (e.note.clone(), e.highlight),
        (None, None),
        "empty annotations change nothing"
    );
    annotate(
        &mut e,
        &Annotations {
            notes: "first".into(),
            highlight: Some(2),
        },
    );
    assert_eq!((e.note.as_deref(), e.highlight), (Some("first"), Some(2)));
    annotate(
        &mut e,
        &Annotations {
            notes: "second".into(),
            highlight: None,
        },
    );
    assert_eq!(e.note.as_deref(), Some("first; second"));
    assert_eq!(e.highlight, Some(2), "no highlight keeps the old one");
    e.note = Some(String::new());
    annotate(
        &mut e,
        &Annotations {
            notes: "x".into(),
            highlight: None,
        },
    );
    assert_eq!(
        e.note.as_deref(),
        Some("x"),
        "an empty note is replaced, not joined"
    );
}

#[test]
fn record_stores_the_exchange_with_derived_fields_and_increasing_ids() {
    let shared = Shared::new();
    let ann = Annotations {
        notes: "n".into(),
        highlight: Some(0),
    };
    record(
        &shared,
        b"GET http://127.0.0.1:8081/p.html?q=1 HTTP/1.1\r\nHost: 127.0.0.1:8081\r\n\r\n",
        Some(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 20\r\n\r\n<title>Gone</title>".to_vec()),
        Some("c".into()),
        80,
        false,
        8080,
        true,
        &ann,
    );
    record(
        &shared,
        b"POST /x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        None,
        None,
        80,
        true,
        8080,
        false,
        &Annotations::default(),
    );
    let rows = shared.history.snapshot();
    assert_eq!(rows.len(), 2);
    assert!(rows[1].id > rows[0].id);
    let a = &rows[0];
    assert_eq!(
        (a.method.as_str(), a.host.as_str(), a.port),
        ("GET", "127.0.0.1", 8081)
    );
    assert_eq!(
        (a.path.as_str(), a.status.as_str(), a.extension.as_str()),
        ("/p.html?q=1", "404", "html")
    );
    assert_eq!(a.title, "Gone");
    assert!(a.params && a.edited && !a.https);
    assert_eq!(a.note.as_deref(), Some("c; n"));
    assert_eq!(a.highlight, Some(0));
    assert_eq!(a.listener_port, 8080);
    assert_eq!(
        a.resp_len,
        a.resp_raw.as_ref().unwrap().len(),
        "length counts headers"
    );
    let b = &rows[1];
    assert!(b.https && b.resp_raw.is_none() && b.status.is_empty() && b.resp_len == 0);
}

#[test]
fn repeat_of_a_post_builds_an_escaped_auto_submitting_form() {
    let shared = Shared::new();
    let mut e = entry(
        "POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: 40\r\n\r\nu=a%22b&p=%3Cx%3E%26y&flag",
        None,
    );
    e.id = 9;
    e.method = "POST".into();
    e.host = "h.test".into();
    e.port = 8443;
    e.https = true;
    shared.history.push(e);
    let html = String::from_utf8(browser_item_response(&shared, "/repeat/9/").unwrap()).unwrap();
    assert!(
        html.contains("action=\"https://h.test:8443/login\""),
        "{html}"
    );
    assert!(html.contains("method=\"POST\""));
    assert!(
        html.contains("name=\"u\" value=\"a&quot;b\""),
        "quote escaped: {html}"
    );
    assert!(
        !html.contains("value=\"<x>&y\""),
        "angle bracket is escaped"
    );
    assert!(html.contains("&lt;x>&amp;y"), "{html}");
    assert!(html.contains("name=\"flag\" value=\"\""));
    assert!(html.contains("document.forms[0].submit()"));
    let declared: usize = html
        .split("Content-Length: ")
        .nth(1)
        .unwrap()
        .split("\r\n")
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(declared, html.split("\r\n\r\n").nth(1).unwrap().len());
}

#[test]
fn browser_item_routes_reject_bad_ids_and_missing_bodies() {
    let shared = Shared::new();
    assert!(browser_item_response(&shared, "/show/abc").is_none());
    assert!(browser_item_response(&shared, "/show/").is_none());
    assert!(
        browser_item_response(&shared, "/show/404").is_none(),
        "unknown id"
    );
    let mut e = entry("GET / HTTP/1.1\r\n\r\n", None);
    e.id = 3;
    shared.history.push(e);
    assert!(
        browser_item_response(&shared, "/show/3").is_none(),
        "no response stored"
    );
    let rep = String::from_utf8(browser_item_response(&shared, "/repeat/3?x=1").unwrap()).unwrap();
    assert!(rep.starts_with("HTTP/1.1 302"), "{rep}");
}

#[test]
fn burp_mime_of_follows_the_response_content_type() {
    assert_eq!(burp_mime_of(&entry("GET / HTTP/1.1\r\n\r\n", None)), "");
    let html = entry(
        "GET / HTTP/1.1\r\n\r\n",
        Some("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>"),
    );
    assert_eq!(burp_mime_of(&html), "HTML");
    let json = entry(
        "GET / HTTP/1.1\r\n\r\n",
        Some("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"),
    );
    assert_eq!(burp_mime_of(&json), "JSON");
}
