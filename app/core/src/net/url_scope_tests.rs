// Coverage for the small proxy helpers: host/port splitting, absolute-form
// URIs, scope matching and cookie plumbing used by session rules and Intruder.
use super::*;

fn parts(req: &str) -> util::HttpParts {
    util::parse_http(req.as_bytes())
}

#[test]
fn split_host_port_uses_the_port_or_the_default() {
    assert_eq!(
        split_host_port("example.com:8080", 80),
        ("example.com".into(), 8080)
    );
    assert_eq!(
        split_host_port("example.com", 443),
        ("example.com".into(), 443)
    );
    // A non-numeric or out-of-range suffix is not a port.
    assert_eq!(
        split_host_port("example.com:http", 80),
        ("example.com:http".into(), 80)
    );
    assert_eq!(
        split_host_port("example.com:99999", 80),
        ("example.com:99999".into(), 80)
    );
    assert_eq!(split_host_port("", 80), ("".into(), 80));
}

#[test]
fn host_of_prefers_the_host_header_then_the_absolute_uri() {
    let p = parts("GET /x HTTP/1.1\r\nHost: a.test:8081\r\n\r\n");
    assert_eq!(host_of(&p, 80), ("a.test".into(), 8081));
    let p = parts("GET http://b.test:9000/x?y=1 HTTP/1.1\r\n\r\n");
    assert_eq!(host_of(&p, 80), ("b.test".into(), 9000));
    let p = parts("GET http://c.test?y=1 HTTP/1.1\r\n\r\n");
    assert_eq!(
        host_of(&p, 80),
        ("c.test".into(), 80),
        "query ends the authority"
    );
    let p = parts("GET /x HTTP/1.1\r\n\r\n");
    assert_eq!(host_of(&p, 8080), ("".into(), 8080), "no host at all");
}

#[test]
fn path_of_converts_absolute_form_to_origin_form() {
    assert_eq!(
        path_of(&parts("GET http://h.test/a/b?c=1 HTTP/1.1\r\n\r\n")),
        "/a/b?c=1"
    );
    assert_eq!(path_of(&parts("GET http://h.test HTTP/1.1\r\n\r\n")), "/");
    assert_eq!(path_of(&parts("GET /plain HTTP/1.1\r\n\r\n")), "/plain");
}

#[test]
fn pattern_matches_literal_regex_and_invalid_regex() {
    assert!(
        pattern_matches("", false, "anything"),
        "empty pattern matches all"
    );
    assert!(pattern_matches("", true, "anything"));
    assert!(pattern_matches("api", false, "http://x/api/v1"));
    assert!(
        !pattern_matches("^api", false, "http://x/api/v1"),
        "literal, not regex"
    );
    assert!(pattern_matches(
        r"^https?://x/api/\d+$",
        true,
        "http://x/api/12"
    ));
    assert!(!pattern_matches(
        r"^https?://x/api/\d+$",
        true,
        "http://x/api/ab"
    ));
    assert!(
        !pattern_matches("(unclosed", true, "(unclosed"),
        "invalid regex never matches"
    );
}

fn scope(shared: &Shared, rules: Vec<ScopeRule>) {
    *shared.scope.lock().unwrap() = rules;
}

#[test]
fn scope_with_no_includes_allows_everything_and_excludes_win() {
    let shared = Shared::new();
    scope(&shared, vec![]);
    assert!(in_scope(&shared, "http://any.test/"));

    let mut exclude = ScopeRule::include("logout", false);
    exclude.include = false;
    scope(&shared, vec![exclude.clone()]);
    assert!(
        in_scope(&shared, "http://any.test/home"),
        "exclude only: rest in scope"
    );
    assert!(!in_scope(&shared, "http://any.test/logout"));

    scope(
        &shared,
        vec![ScopeRule::include("any.test", false), exclude],
    );
    assert!(in_scope(&shared, "http://any.test/home"));
    assert!(
        !in_scope(&shared, "http://any.test/logout"),
        "exclude beats include"
    );
    assert!(!in_scope(&shared, "http://other.test/home"), "not included");
}

#[test]
fn disabled_scope_rules_are_ignored() {
    let shared = Shared::new();
    let mut inc = ScopeRule::include("only.test", false);
    inc.enabled = false;
    scope(&shared, vec![inc]);
    assert!(
        in_scope(&shared, "http://elsewhere.test/"),
        "a disabled include does not restrict"
    );
    let mut exc = ScopeRule::include("bad", false);
    exc.include = false;
    exc.enabled = false;
    scope(&shared, vec![exc]);
    assert!(in_scope(&shared, "http://bad.test/"));
}

/// #246: a blank rule is the one the scope editor creates before the user
/// types a pattern. As an exclusion it must select nothing, not everything.
#[test]
fn blank_exclusion_rule_is_ignored() {
    let shared = Shared::new();
    let mut blank = ScopeRule::include("", false);
    blank.include = false;
    scope(&shared, vec![blank]);
    assert!(in_scope(&shared, "http://any.test/home"));
    assert!(in_scope(&shared, "https://other.test/path"));

    // Whitespace only is blank too, and a blank rule beside a real include
    // removes nothing.
    let mut spaces = ScopeRule::include("   ", false);
    spaces.include = false;
    scope(
        &shared,
        vec![ScopeRule::include("only.test", false), spaces],
    );
    assert!(in_scope(&shared, "http://only.test/x"));
    assert!(!in_scope(&shared, "http://other.test/x"));
}

/// #246: an invalid regex never matches. As an exclusion that leaves every
/// URL in scope; as the only include rule it selects nothing.
#[test]
fn invalid_regex_scope_rule_never_matches() {
    let shared = Shared::new();
    let mut exclude = ScopeRule::include("(unclosed", true);
    exclude.include = false;
    scope(&shared, vec![exclude]);
    assert!(
        in_scope(&shared, "http://any.test/"),
        "an invalid exclusion must not exclude anything"
    );
    scope(&shared, vec![ScopeRule::include("(unclosed", true)]);
    assert!(
        !in_scope(&shared, "http://any.test/"),
        "an invalid include selects nothing"
    );
}

#[test]
fn regex_scope_rule_matches_by_pattern() {
    let shared = Shared::new();
    scope(
        &shared,
        vec![ScopeRule::include(r"^https://[a-z]+\.corp\.test/", true)],
    );
    assert!(in_scope(&shared, "https://app.corp.test/x"));
    assert!(!in_scope(&shared, "https://app.evil.test/x"));
}

#[test]
fn append_cookie_adds_or_merges() {
    let raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
    let out = String::from_utf8(append_cookie(raw, "sid", "1")).unwrap();
    assert!(out.contains("Cookie: sid=1"), "{out}");
    let out2 = append_cookie(out.as_bytes(), "csrf", "z");
    let p = util::parse_http(&out2);
    assert_eq!(
        util::get_header(&p.headers, "Cookie").as_deref(),
        Some("sid=1; csrf=z")
    );
    assert_eq!(
        out2.iter().filter(|b| **b == b'\n').count(),
        out.matches('\n').count(),
        "one Cookie header"
    );
}

#[test]
fn latest_cookie_returns_the_newest_matching_set_cookie() {
    let shared = Shared::new();
    assert_eq!(latest_cookie(&shared, "sid"), None);
    let resp = |h: &str| {
        Some(
            format!("HTTP/1.1 200 OK\r\n{h}\r\nContent-Length: 0\r\n\r\n")
                .into_bytes()
                .into(),
        )
    };
    shared.history.push(HistEntry {
        id: 1,
        resp_raw: resp("Set-Cookie: sid=old; Path=/"),
        ..Default::default()
    });
    shared.history.push(HistEntry {
        id: 2,
        resp_raw: None,
        ..Default::default()
    });
    shared.history.push(HistEntry {
        id: 3,
        resp_raw: resp("Set-Cookie: other=x\r\nset-cookie: SID= new ; HttpOnly"),
        ..Default::default()
    });
    assert_eq!(
        latest_cookie(&shared, "sid").as_deref(),
        Some("new"),
        "newest wins, name is case-insensitive, value trimmed"
    );
    assert_eq!(latest_cookie(&shared, "other").as_deref(), Some("x"));
    assert_eq!(latest_cookie(&shared, "missing"), None);
}

// ---- http_io: reading requests off a stream ----

use std::io::Cursor;

/// A reader that yields at most `n` bytes per call, like a slow socket.
struct Trickle<'a>(&'a [u8], usize);
impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.1.min(self.0.len()).min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

#[test]
fn content_length_is_case_insensitive_and_rejects_garbage() {
    assert_eq!(
        content_length(b"POST / HTTP/1.1\r\ncontent-length: 12\r\n\r\n"),
        Some(12)
    );
    assert_eq!(
        content_length(b"POST / HTTP/1.1\r\nCONTENT-LENGTH:7\r\n\r\n"),
        Some(7)
    );
    assert_eq!(
        content_length(b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n"),
        None
    );
    assert_eq!(
        content_length(b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n"),
        None
    );
    assert_eq!(content_length(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"), None);
}

#[test]
fn read_request_collects_a_body_split_across_reads() {
    let raw = b"POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 11\r\n\r\nhello world";
    let got = read_request(&mut Trickle(raw, 3)).unwrap();
    assert_eq!(got, raw.to_vec());
}

#[test]
fn read_request_consumes_exactly_one_request_and_keeps_the_pipelined_next() {
    let first = b"POST /p HTTP/1.1\r\nContent-Length: 2\r\n\r\nab";
    let second = b"GET /next HTTP/1.1\r\n\r\n";
    let raw = [first.as_slice(), second.as_slice()].concat();
    let mut stream = Cursor::new(raw.as_slice());

    // Exact consume (#110): a reader that supplies both requests at once gets
    // back only the first framed request; the pipelined remainder stays in
    // the caller-held pending buffer for the next call.
    let mut pending = Vec::new();
    let got = read_request_pending(&mut stream, &mut pending).unwrap();
    assert_eq!(got, first, "head plus declared body only");
    assert_eq!(
        pending, second,
        "the next request was read ahead, not consumed"
    );
    let got = read_request_pending(&mut stream, &mut pending).unwrap();
    assert_eq!(got, second, "second request served from pending");
    assert!(pending.is_empty());
    assert_eq!(stream.position(), raw.len() as u64);
    assert!(read_request(&mut stream).unwrap().is_empty());
}

#[test]
fn read_request_leaves_the_next_request_when_a_read_ends_at_the_body_boundary() {
    let first = b"POST /p HTTP/1.1\r\nContent-Length: 2\r\n\r\nab";
    let second = b"GET /next HTTP/1.1\r\n\r\n";
    let raw = [first.as_slice(), second.as_slice()].concat();
    let mut stream = Trickle(&raw, 1);

    // Single-byte reads prevent read-ahead. The declared body length must
    // stop this call exactly, leaving the full next request for the next call.
    assert_eq!(read_request(&mut stream).unwrap(), first);
    assert_eq!(stream.0, second);
    assert_eq!(read_request(&mut stream).unwrap(), second);
    assert!(stream.0.is_empty());
}

#[test]
fn read_request_reads_a_chunked_body_to_the_last_chunk() {
    let raw = b"POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let got = read_request(&mut Trickle(raw, 4)).unwrap();
    assert_eq!(got, raw.to_vec(), "all chunks, not just the first read");
}

#[test]
fn transfer_encoding_wins_over_content_length() {
    let raw = b"POST /c HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let got = read_request(&mut Trickle(raw, 5)).unwrap();
    assert_eq!(got, raw.to_vec());
}

#[test]
fn read_request_returns_what_it_has_when_the_peer_closes_early() {
    let partial = b"POST /p HTTP/1.1\r\nContent-Length: 50\r\n\r\nshort";
    let got = read_request(&mut Cursor::new(&partial[..])).unwrap();
    assert_eq!(got, partial.to_vec());
    let no_head = b"GET / HTT";
    assert_eq!(
        read_request(&mut Cursor::new(&no_head[..])).unwrap(),
        no_head.to_vec()
    );
    assert!(read_request(&mut Cursor::new(&b""[..])).unwrap().is_empty());
}

#[test]
fn read_request_rejects_an_oversized_declared_body() {
    let raw = format!(
        "POST /p HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        usize::MAX / 2
    );
    let err = read_request(&mut Cursor::new(raw.into_bytes())).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn read_response_head_stops_at_the_blank_line_and_leaves_the_body() {
    let raw = b"HTTP/1.1 101 Switching\r\nUpgrade: websocket\r\n\r\n\x81\x05hello";
    let mut cur = Cursor::new(&raw[..]);
    let head = read_response_head(&mut cur).unwrap();
    assert!(head.ends_with(b"\r\n\r\n"));
    let mut rest = Vec::new();
    cur.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"\x81\x05hello", "first frame not consumed");
    // Bare-LF terminators also end the head.
    let head = read_response_head(&mut Cursor::new(&b"HTTP/1.1 200 OK\nA: b\n\nbody"[..])).unwrap();
    assert!(head.ends_with(b"\n\n"));
    // A head that never ends is capped at 64 KiB + 1 read.
    let endless = vec![b'x'; 200_000];
    assert!(read_response_head(&mut Cursor::new(endless)).unwrap().len() <= 64 * 1024 + 1);
}
