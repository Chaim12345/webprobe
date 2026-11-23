// Edge cases of the Intruder results/grep/target helpers that the main
// suite in intruder_run.rs does not reach.
use crate::intruder_run::*;
use std::sync::Arc;

#[test]
fn unescape_expression_handles_known_and_unknown_escapes() {
    assert_eq!(unescape_expression(r"a\nb\rc\\d"), "a\nb\rc\\d");
    assert_eq!(
        unescape_expression(r"\x"),
        r"\x",
        "unknown escape kept verbatim"
    );
    assert_eq!(
        unescape_expression(r"trailing\"),
        r"trailing\",
        "lone backslash at end"
    );
    assert_eq!(unescape_expression("héllo"), "héllo");
    assert_eq!(unescape_expression(""), "");
}

#[test]
fn extract_item_label_shows_regex_or_start_and_end() {
    let regex = ExtractItem {
        regex: Some("id=(\\d+)".into()),
        ..Default::default()
    };
    assert_eq!(regex.label(), "id=(\\d+)");
    let lit = ExtractItem {
        start: ExtractStart::After("<b>".into()),
        end: ExtractEnd::Delimiter("</b>".into()),
        ..Default::default()
    };
    assert_eq!(lit.label(), "<b>...</b>");
    let pos = ExtractItem {
        start: ExtractStart::Offset(3),
        end: ExtractEnd::Length(5),
        ..Default::default()
    };
    assert_eq!(pos.label(), "[3]...[5]");
}

#[test]
fn parse_target_defaults_ports_by_scheme() {
    assert_eq!(
        parse_target("https://h.test"),
        Some(("h.test".into(), 443, true))
    );
    assert_eq!(
        parse_target("http://h.test"),
        Some(("h.test".into(), 80, false))
    );
    assert_eq!(
        parse_target("  h.test:8080/path  "),
        Some(("h.test".into(), 8080, false))
    );
    assert_eq!(
        parse_target("https://h.test:8443/x/y"),
        Some(("h.test".into(), 8443, true))
    );
    assert_eq!(parse_target(""), None);
    assert_eq!(parse_target("https:///path"), None, "no authority");
}

#[test]
fn csv_field_quotes_only_when_needed() {
    assert_eq!(csv_field("plain"), "plain");
    assert_eq!(csv_field("a,b"), "\"a,b\"");
    assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    assert_eq!(csv_field("two\nlines"), "\"two\nlines\"");
    assert_eq!(csv_field(""), "");
}

#[test]
fn extract_value_edge_cases() {
    let resp = b"HTTP/1.1 200 OK\r\nX: tok=hdr\r\n\r\n<p>tok=body;rest</p>";
    let item = ExtractItem {
        start: ExtractStart::After("tok=".into()),
        end: ExtractEnd::Delimiter(";".into()),
        exclude_headers: true,
        ..Default::default()
    };
    assert_eq!(
        extract_value(&item, resp, 100).as_deref(),
        Some("body"),
        "headers skipped"
    );
    let mut with_headers = item.clone();
    with_headers.exclude_headers = false;
    assert_eq!(
        extract_value(&with_headers, resp, 100).as_deref(),
        Some("hdr\r\n\r\n<p>tok=body"),
        "first match, to first delimiter"
    );
    // max_len truncates by characters, not bytes.
    let multi = "HTTP/1.1 200 OK\r\n\r\nvalue=ééééé;".as_bytes();
    let cut = ExtractItem {
        start: ExtractStart::After("value=".into()),
        end: ExtractEnd::Delimiter(";".into()),
        ..Default::default()
    };
    assert_eq!(extract_value(&cut, multi, 3).as_deref(), Some("ééé"));
    // Missing start expression: nothing extracted.
    let missing = ExtractItem {
        start: ExtractStart::After("nope=".into()),
        ..cut.clone()
    };
    assert_eq!(extract_value(&missing, multi, 10), None);
    // Offset past the end of the response.
    let off = ExtractItem {
        start: ExtractStart::Offset(10_000),
        end: ExtractEnd::Length(4),
        ..Default::default()
    };
    assert_eq!(extract_value(&off, multi, 10), None);
    // Length end is clamped to the response size.
    let len = ExtractItem {
        start: ExtractStart::After("value=".into()),
        end: ExtractEnd::Length(10_000),
        ..Default::default()
    };
    assert!(extract_value(&len, multi, 100)
        .unwrap()
        .starts_with("ééééé;"));
    // Invalid regex and regex without a capture group give nothing.
    let bad = ExtractItem {
        regex: Some("(".into()),
        ..Default::default()
    };
    assert_eq!(extract_value(&bad, multi, 10), None);
    let nogroup = ExtractItem {
        regex: Some("value".into()),
        ..Default::default()
    };
    assert_eq!(extract_value(&nogroup, multi, 10), None);
}

#[test]
fn grep_match_flags_without_items_or_with_empty_item() {
    let mut cfg = GrepMatch {
        items: vec![],
        ..Default::default()
    };
    assert!(grep_match_flags(&cfg, b"anything").is_empty());
    cfg.items = vec![String::new(), "ok".into()];
    assert_eq!(
        grep_match_flags(&cfg, b"HTTP/1.1 200 OK\r\n\r\nall ok"),
        [false, true]
    );
    // Regex mode is case-insensitive unless case_sensitive is set.
    cfg.regex = true;
    cfg.items = vec!["^ALL".into()];
    assert_eq!(grep_match_flags(&cfg, b"H\r\n\r\nall ok"), [true]);
    cfg.case_sensitive = true;
    assert_eq!(grep_match_flags(&cfg, b"H\r\n\r\nall ok"), [false]);
}

#[test]
fn grep_handles_non_utf8_responses_without_panicking() {
    let mut resp = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
    resp.extend_from_slice(&[0xff, 0xfe, b'o', b'k', 0xc3]);
    let cfg = GrepMatch::default();
    let flags = grep_match_flags(&cfg, &resp);
    assert_eq!(flags.len(), cfg.items.len());
    let item = ExtractItem {
        start: ExtractStart::After("ok".into()),
        ..Default::default()
    };
    let _ = extract_value(&item, &resp, 10);
}

#[test]
fn results_csv_with_sets_and_grep_columns_matches_header_width() {
    let mut cfg = AttackSettings::default();
    cfg.grep_match.enabled = true;
    cfg.grep_match.items = vec!["a".into(), "b".into()];
    cfg.grep_extract.enabled = true;
    cfg.grep_extract.items = vec![ExtractItem::default()];
    cfg.grep_payloads.enabled = true;
    let rows = vec![Arc::new(ResultRow {
        number: 1,
        payloads: vec![Some("x,y".into()), None],
        status: "200".into(),
        length: 5,
        matches: vec![true, false],
        extracts: vec![Some("v".into())],
        reflected: vec![true, false],
        ..Default::default()
    })];
    let cols = result_columns(2, &cfg);
    let cells = rows[0].cells(2, &cfg);
    assert_eq!(
        cols.len(),
        cells.len(),
        "header and row have the same width"
    );
    let csv = results_csv(&rows, 2, &cfg);
    let lines: Vec<&str> = csv.split("\r\n").collect();
    assert_eq!(lines.len(), 3, "header, row, trailing empty");
    assert!(lines[1].starts_with("1,\"x,y\","), "{}", lines[1]);
}

#[test]
fn sort_order_is_stable_for_ties_and_handles_missing_columns() {
    let cfg = AttackSettings::default();
    let mk = |n: usize, status: &str| {
        Arc::new(ResultRow {
            number: n,
            status: status.into(),
            ..Default::default()
        })
    };
    let rows = vec![mk(1, "200"), mk(2, "404"), mk(3, "200")];
    // Column 2 is the status.
    assert_eq!(sort_order(&rows, 1, &cfg, 2, true), vec![0, 2, 1]);
    assert_eq!(sort_order(&rows, 1, &cfg, 2, false), vec![1, 2, 0]);
    // A column index beyond the table keys everything as empty: request order.
    assert_eq!(sort_order(&rows, 1, &cfg, 99, true), vec![0, 1, 2]);
    assert!(sort_order(&[], 1, &cfg, 0, true).is_empty());
}

#[test]
fn throttle_delay_edge_cases() {
    let off = PoolConfig::default();
    assert_eq!(throttle_delay_ms(&off, 5, 0.9), 0, "delay disabled");
    let inc_only = PoolConfig {
        increment_enabled: true,
        increment_ms: 0,
        ..Default::default()
    };
    assert_eq!(
        throttle_delay_ms(&inc_only, 0, 0.0),
        1,
        "increments floor at 1 ms"
    );
    let huge = PoolConfig {
        increment_enabled: true,
        increment_ms: u64::MAX,
        ..Default::default()
    };
    assert_eq!(
        throttle_delay_ms(&huge, u64::MAX, 0.0),
        u64::MAX,
        "saturates instead of overflowing"
    );
}
