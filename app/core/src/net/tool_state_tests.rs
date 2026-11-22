// Coverage for per-thread tool state (scopes), HTTP/2 downgrade, the tool
// log ring buffer and the tool streaming sink.
use super::*;
use crate::streaming::{BodyMode, ResponseSink};

fn up(resp: Option<&[u8]>) -> Upstream {
    Upstream {
        resp: resp.map(|r| r.to_vec()),
        error: None,
    }
}

#[test]
fn as_http1_rewrites_only_an_h2_request_line() {
    let out = as_http1(b"GET /a HTTP/2\r\nHost: h\r\n\r\n");
    assert_eq!(&out[..], b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n");
    let out = as_http1(b"GET /a HTTP/2.0\nHost: h\n\n");
    assert_eq!(
        &out[..],
        b"GET /a HTTP/1.1\nHost: h\n\n",
        "bare LF line ends survive"
    );
    let h1 = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
    assert!(
        matches!(as_http1(h1), std::borrow::Cow::Borrowed(_)),
        "no copy when unchanged"
    );
    assert_eq!(
        &as_http1(b"HTTP/2\r\n")[..],
        b"HTTP/2\r\n",
        "a bare version is not a request line"
    );
    assert_eq!(&as_http1(b"")[..], b"");
    // HTTP/2 inside a header or the body is left alone.
    let body = b"POST / HTTP/1.1\r\nX: HTTP/2\r\n\r\nHTTP/2";
    assert_eq!(&as_http1(body)[..], &body[..]);
}

#[test]
fn tool_scopes_nest_and_restore_on_drop() {
    assert!(TOOL.with(|t| t.get()).is_none());
    {
        let _a = tool_scope("Scanner");
        assert_eq!(TOOL.with(|t| t.get()), Some("Scanner"));
        {
            let _b = tool_scope("Intruder");
            assert_eq!(TOOL.with(|t| t.get()), Some("Intruder"));
        }
        assert_eq!(TOOL.with(|t| t.get()), Some("Scanner"));
    }
    assert!(TOOL.with(|t| t.get()).is_none());
}

#[test]
fn http2_scopes_nest_and_restore_on_drop() {
    let outer = Http2Choice {
        want_h2: Some(true),
        strip_connection: false,
    };
    let inner = Http2Choice {
        want_h2: Some(false),
        strip_connection: true,
    };
    {
        let _o = http2_scope(outer);
        {
            let _i = http2_scope(inner);
            assert_eq!(H2_CHOICE.with(|c| c.get()), Some(inner));
        }
        assert_eq!(H2_CHOICE.with(|c| c.get()), Some(outer));
    }
    assert_eq!(H2_CHOICE.with(|c| c.get()), None);
}

#[test]
fn tool_log_ignores_untagged_threads_and_handles_missing_responses() {
    let shared = Shared::new();
    log_tool_exchange(
        &shared,
        "h",
        80,
        false,
        b"GET / HTTP/1.1\r\n\r\n",
        &up(None),
    );
    assert!(shared.tool_log.lock().unwrap().is_empty());
    let _t = tool_scope("Sequencer");
    log_tool_exchange(
        &shared,
        "h",
        8080,
        true,
        b"POST /x?y HTTP/1.1\r\n\r\nbody",
        &up(None),
    );
    let log = shared.tool_log.lock().unwrap();
    let e = &log[0];
    assert_eq!(
        (e.tool, e.method.as_str(), e.path.as_str()),
        ("Sequencer", "POST", "/x?y")
    );
    assert_eq!(
        (e.status.as_str(), e.resp_len, e.mime.as_str()),
        ("", 0, "")
    );
    assert!(e.response.is_none() && e.https && e.port == 8080);
}

#[test]
fn tool_log_is_a_ring_and_truncates_stored_messages() {
    let shared = Shared::new();
    let _t = tool_scope("Scanner");
    let req = b"GET / HTTP/1.1\r\n\r\n";
    let big = {
        let mut r = b"HTTP/1.1 200 OK\r\nContent-Type: Text/Plain; charset=x\r\n\r\n".to_vec();
        r.resize(TOOL_LOG_MESSAGE_MAX + 1000, b'a');
        r
    };
    log_tool_exchange(&shared, "h", 80, false, req, &up(Some(&big)));
    {
        let log = shared.tool_log.lock().unwrap();
        assert_eq!(log[0].resp_len, big.len(), "length is the real size");
        assert_eq!(
            log[0].response.as_ref().unwrap().len(),
            TOOL_LOG_MESSAGE_MAX,
            "stored copy is capped"
        );
        assert_eq!(log[0].mime, "text/plain", "parameters dropped, lowercased");
        assert_eq!(log[0].status, "200");
    }
    for i in 0..TOOL_LOG_MAX + 10 {
        let path = format!("GET /{i} HTTP/1.1\r\n\r\n");
        log_tool_exchange(&shared, "h", 80, false, path.as_bytes(), &up(None));
    }
    let log = shared.tool_log.lock().unwrap();
    assert_eq!(log.len(), TOOL_LOG_MAX);
    assert_eq!(log.last().unwrap().path, format!("/{}", TOOL_LOG_MAX + 9));
    assert_eq!(
        log[0].path, "/10",
        "the oldest entries were dropped, including the big one"
    );
}

#[test]
fn tool_sink_is_off_for_proxy_repeater_and_untagged_threads() {
    let shared = Shared::new();
    let req = b"GET /s HTTP/1.1\r\n\r\n";
    assert!(tool_sink(&shared, "h", 80, false, req).is_none(), "no tool");
    for tool in ["Proxy", "Repeater"] {
        let _t = tool_scope(tool);
        assert!(tool_sink(&shared, "h", 80, false, req).is_none(), "{tool}");
    }
    let _t = tool_scope("Intruder");
    assert!(tool_sink(&shared, "h", 80, false, req).is_some());
}

#[test]
fn jar_and_session_hooks_pass_through_without_a_tool() {
    let shared = Shared::new();
    let req = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
    assert!(matches!(
        jar_request(&shared, "h", false, req),
        std::borrow::Cow::Borrowed(_)
    ));
    let same = session_request(&shared, 80, false, std::borrow::Cow::Borrowed(&req[..]));
    assert_eq!(&same[..], &req[..]);
    session_after(&shared, "h");
    jar_response(
        &shared,
        "h",
        req,
        &up(Some(b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\n\r\n")),
    );
    assert!(
        shared.cookie_jar.lock().unwrap().cookies.is_empty(),
        "no tool: nothing stored"
    );
    // With a tool but an empty jar the request is also untouched.
    let _t = tool_scope("Scanner");
    assert!(matches!(
        jar_request(&shared, "h", false, req),
        std::borrow::Cow::Borrowed(_)
    ));
}

#[test]
fn tool_sink_buffers_normal_responses_without_logging() {
    let shared = Shared::new();
    let _t = tool_scope("Scanner");
    let mut sink = tool_sink(&shared, "h", 80, false, b"GET /s HTTP/1.1\r\n\r\n").unwrap();
    let normal = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\n";
    assert!(matches!(sink.head(normal), BodyMode::Buffer));
    assert!(shared.tool_log.lock().unwrap().is_empty());
    sink.wire(b"x").unwrap();
    sink.payload(b"x");
    sink.end(true);
}
