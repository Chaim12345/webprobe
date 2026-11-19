// Split from ui.rs (L5, issue #35). Item bodies unchanged; visibility
// promoted to pub(crate) where siblings across the split need access.

use super::*;

#[cfg(test)]
mod repeater_fix_tests {
    use super::*;

    /// Second review, finding 3: several links (and non-ASCII text) neither
    /// hang nor panic.
    #[test]
    fn links_in_response_walks_every_link() {
        let body = "<a href=\"http://a\"> x <a href=\"http://b\"> é <img src=\"https://c/ü\"> <a href=\"/rel\">";
        let e = net::HistEntry { resp_raw: Some(format!("HTTP/1.1 200 OK\r\n\r\n{body}").into()), ..Default::default() };
        assert_eq!(links_in_response(&e), "http://a\nhttp://b\nhttps://c/ü");
    }

    /// Issue #2 item 2: Cancel frees the tab at once and a late response
    /// is dropped (its generation is stale).
    #[test]
    fn cancel_abandons_the_in_flight_send() {
        let sh = net::Shared::new();
        let tab = sh.repeaters.lock().unwrap()[0].id;
        let gen = sh.rep.begin(tab);
        cancel_repeater_send(&sh);
        assert_eq!(sh.repeaters.lock().unwrap()[0].result_line, "Request cancelled", "shown in the tab's status line");
        assert!(!sh.rep.is_busy());
        assert_eq!(sh.rep.result(), "Request cancelled");
        assert!(!sh.rep.is_current(gen), "the worker sees a stale generation");
        // Cancel with nothing in flight changes nothing.
        cancel_repeater_send(&sh);
        assert_eq!(sh.rep.result(), "Request cancelled");
    }

    /// Issue #2 item 1: tab numbers are never reused, so routing by id can
    /// not hit a different tab after a close.
    #[test]
    fn repeater_tab_ids_are_never_reused() {
        let sh = net::Shared::new();
        let first = sh.repeaters.lock().unwrap()[0].id;
        let a = sh.rep.new_tab_id();
        let b = sh.rep.new_tab_id();
        assert!(a != first && b != a && b != first);
    }
}

#[cfg(test)]
mod suite {
    use super::{history_new_rows, history_view};
    use crate::net::HistEntry;
    use crate::table::TableState;

    fn entry(id: u64, host: &str) -> HistEntry {
        HistEntry {
            id,
            ts: 0,
            method: "GET".to_string(),
            host: host.to_string(),
            port: 80,
            path: "/".to_string(),
            status: "200".to_string(),
            resp_len: 0,
            req_raw: Vec::new().into(),
            resp_raw: None,
            https: false,
            note: None,
            highlight: None,
            audited: false,
            params: false,
            edited: false,
            extension: String::new(),
            title: String::new(),
            cookies: String::new(),
            listener_port: 0,
            ip: String::new(),
            diffs: 0,
        }
    }

    #[test]
    fn history_view_keeps_every_match_and_new_rows_go_on_top() {
        let history: Vec<_> = (1..=1500u64).map(|id| entry(id, if id == 1 { "old.example" } else { "other.example" })).collect();
        // The only match is the oldest entry.
        let (rows, truncated) = history_view(&history, |e| e.host.contains("old.example"), &TableState::new());
        assert_eq!(rows.iter().map(|row| row.id).collect::<Vec<_>>(), [1]);
        assert!(!truncated);
        // No cap: all 1500 rows, newest first.
        let (rows, truncated) = history_view(&history, |_| true, &TableState::new());
        assert_eq!(rows.len(), 1500);
        assert!(!truncated);
        assert_eq!((rows.first().unwrap().id, rows.last().unwrap().id), (1500, 1));
        // Appended rows, filtered and newest first, are what an incremental
        // update puts on top: the result equals a full rebuild.
        let mut grown = history.clone();
        grown.extend((1501..=1505u64).map(|id| entry(id, if id % 2 == 0 { "old.example" } else { "x" })));
        let keep = |e: &crate::net::HistEntry| e.host.contains("old.example");
        let mut incremental = history_new_rows(&grown, history.len(), keep);
        incremental.extend(history_view(&history, keep, &TableState::new()).0);
        let full = history_view(&grown, keep, &TableState::new()).0;
        assert_eq!(incremental.iter().map(|r| r.id).collect::<Vec<_>>(), full.iter().map(|r| r.id).collect::<Vec<_>>());
        assert_eq!(full.iter().map(|r| r.id).collect::<Vec<_>>(), [1504, 1502, 1]);
        assert!(history_new_rows(&history, 9999, keep).is_empty());
    }

    #[test]
    fn history_sorts_by_method_before_limiting() {
        let mut history: Vec<_> = (1..=5).map(|id| entry(id, "example.test")).collect();
        history[0].method = "POST".to_string();
        let mut state = TableState::new();
        state.sort_col = 2; // Method (Burp column order: #, Host, Method, ...)
        state.sort_asc = true;
        let (rows, _) = history_view(&history, |_| true, &state);
        // Ascending by method: GET rows keep newest-first order, POST sorts last.
        assert_eq!(rows[0].method, "GET");
        assert_eq!(rows[4].method, "POST");
    }

    #[test]
    fn csrf_poc_replays_the_body() {
        let e = crate::net::HistEntry {
            method: "POST".into(),
            host: "h".into(),
            port: 80,
            path: "/change".into(),
            req_raw: b"POST /change HTTP/1.1\r\nHost: h\r\n\r\nemail=a%40b.c&x=1".to_vec().into(),
            ..Default::default()
        };
        let html = crate::ui::csrf_poc_html(&e);
        assert!(html.contains("action=\"http://h/change\"") && html.contains("name=\"email\" value=\"a@b.c\""), "{html}");
    }

    #[test]
    fn add_marker_wraps_the_selection() {
        assert_eq!(crate::ui::add_marker("q=apple", (2, 7)), "q=\u{00A7}apple\u{00A7}");
        assert_eq!(crate::ui::add_marker("ab", (1, 1)), "a\u{00A7}\u{00A7}b");
    }

    #[test]
    fn tools_get_origin_form_without_proxy_connection() {
        let r = crate::ui::request_for_tools(b"GET http://h:1/a?b=1 HTTP/1.1\r\nHost: h:1\r\nProxy-Connection: Keep-Alive\r\nAccept: */*\r\n\r\n");
        assert_eq!(r, "GET /a?b=1 HTTP/1.1\r\nHost: h:1\r\nAccept: */*\r\n\r\n");
    }

    #[test]
    fn repeater_updates_content_length() {
        let r = crate::ui::update_content_length("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nabcd");
        assert!(r.contains("Content-Length: 4\r\n"), "{r}");
        let g = crate::ui::update_content_length("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        assert!(!g.contains("Content-Length"));
    }

    #[test]
    fn a_sort_sees_the_whole_history() {
        let mut history: Vec<_> = (1..=1500u64).map(|id| entry(id, "example.test")).collect();
        history[0].method = "POST".to_string(); // the oldest entry
        let mut state = TableState::new();
        state.sort_col = 2; // Method
        state.sort_asc = false; // POST first
        let (rows, truncated) = history_view(&history, |_| true, &state);
        assert!(!truncated);
        assert_eq!(rows.len(), 1500);
        assert_eq!(rows[0].id, 1, "the sort must see the whole list");
    }
}
