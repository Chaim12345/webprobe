#![allow(dead_code)] // Engine only: UI wiring lands in the next wave.
//! Burp-style Logger: a bounded, newest-first list of HTTP tool traffic.
//!
//! Every entry records one request/response pair with the tool that produced
//! it (`Proxy`, `Repeater`, `Scanner`, ...). The store is a ring buffer capped
//! at `cap` entries; pushing past the cap evicts the oldest entry. Ids are
//! monotonic and are never reused, even after `clear`.

use std::collections::VecDeque;

/// Default number of entries retained before the oldest is dropped.
pub const DEFAULT_CAP: usize = 5000;

/// One captured request/response pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub id: u64,
    pub ts: u64,
    pub tool: String,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub status: String,
    pub req_len: usize,
    pub resp_len: usize,
    pub mime: String,
    pub source: String,
}

impl Default for LogEntry {
    fn default() -> Self {
        Self {
            id: 0,
            ts: 0,
            tool: String::new(),
            method: String::new(),
            host: String::new(),
            port: 0,
            path: String::new(),
            status: String::new(),
            req_len: 0,
            resp_len: 0,
            mime: String::new(),
            source: String::new(),
        }
    }
}

/// Filter applied to the log view. All set fields must match.
#[derive(Clone, Debug, Default)]
pub struct LogQuery {
    /// Case-insensitive substring over host, path, method and status.
    pub text: String,
    /// Exact (case-insensitive) tool name, e.g. `Proxy`.
    pub tool: Option<String>,
    /// Status class, 1-5 (i.e. `4` matches 400-499).
    pub status_class: Option<u8>,
    /// Case-insensitive substring of the MIME type.
    pub mime: String,
}

impl LogQuery {
    /// True when the query accepts every entry.
    pub fn is_empty(&self) -> bool {
        self.text.trim().is_empty()
            && self.tool.as_deref().map_or(true, |t| t.trim().is_empty())
            && self.status_class.is_none()
            && self.mime.trim().is_empty()
    }

    fn matches(&self, e: &LogEntry) -> bool {
        let text = self.text.trim();
        if !text.is_empty() {
            let needle = text.to_lowercase();
            let hay = |s: &str| s.to_lowercase().contains(&needle);
            if !(hay(&e.host) || hay(&e.path) || hay(&e.method) || hay(&e.status)) {
                return false;
            }
        }
        if let Some(tool) = self.tool.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            if !e.tool.eq_ignore_ascii_case(tool) {
                return false;
            }
        }
        if let Some(class) = self.status_class {
            let matches_class = e
                .status
                .chars()
                .next()
                .and_then(|c| c.to_digit(10))
                .map(|d| d == u32::from(class))
                .unwrap_or(false);
            if !matches_class {
                return false;
            }
        }
        let mime = self.mime.trim();
        if !mime.is_empty() && !e.mime.to_lowercase().contains(&mime.to_lowercase()) {
            return false;
        }
        true
    }
}

/// Bounded log store. `entries` is oldest-first; `snapshot` reverses it.
#[derive(Debug)]
pub struct Logger {
    pub entries: VecDeque<LogEntry>,
    pub next_id: u64,
    pub cap: usize,
}

impl Logger {
    /// New logger retaining at most `cap` entries; `0` means [`DEFAULT_CAP`].
    pub fn new(cap: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            next_id: 1,
            cap: if cap == 0 { DEFAULT_CAP } else { cap },
        }
    }

    /// Append `entry`, assigning it a fresh id. Returns that id. The oldest
    /// entry is evicted when the cap is exceeded.
    pub fn push(&mut self, mut entry: LogEntry) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        entry.id = id;
        self.entries.push_back(entry);
        while self.entries.len() > self.cap {
            self.entries.pop_front();
        }
        id
    }

    /// Drop every entry. Ids keep counting from where they left off.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Entries matching `q`, oldest-first (same order as storage).
    pub fn filter(&self, q: &LogQuery) -> Vec<&LogEntry> {
        self.entries.iter().filter(|e| q.matches(e)).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Owned copy of the log, newest entry first (what the UI table shows).
    pub fn snapshot(&self) -> Vec<LogEntry> {
        self.entries.iter().rev().cloned().collect()
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new(DEFAULT_CAP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tool: &str, host: &str, path: &str, method: &str, status: &str, mime: &str) -> LogEntry {
        LogEntry {
            tool: tool.into(),
            host: host.into(),
            path: path.into(),
            method: method.into(),
            status: status.into(),
            mime: mime.into(),
            ..Default::default()
        }
    }

    fn sample() -> LogEntry {
        entry("Proxy", "example.com", "/index.html", "GET", "200", "text/html")
    }

    #[test]
    fn push_assigns_monotonic_ids() {
        let mut log = Logger::new(10);
        assert_eq!(log.push(sample()), 1);
        assert_eq!(log.push(sample()), 2);
        assert_eq!(log.next_id, 3);
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn cap_evicts_oldest() {
        let mut log = Logger::new(3);
        for _ in 0..5 {
            log.push(sample());
        }
        assert_eq!(log.len(), 3);
        let ids: Vec<u64> = log.entries.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![3, 4, 5]);
    }

    #[test]
    fn zero_cap_uses_default() {
        assert_eq!(Logger::new(0).cap, DEFAULT_CAP);
    }

    #[test]
    fn filter_by_text_is_case_insensitive_over_host_path_method_status() {
        let mut log = Logger::new(10);
        log.push(entry("Proxy", "Example.COM", "/a", "GET", "200", "text/html"));
        log.push(entry("Proxy", "other.org", "/Admin/Login", "POST", "302", "text/html"));
        log.push(entry("Proxy", "third.net", "/x", "GET", "404", "application/json"));

        let q = LogQuery { text: "example".into(), ..Default::default() };
        assert_eq!(log.filter(&q).len(), 1);

        let q = LogQuery { text: "ADMIN".into(), ..Default::default() };
        assert_eq!(log.filter(&q)[0].path, "/Admin/Login");

        let q = LogQuery { text: "post".into(), ..Default::default() };
        assert_eq!(log.filter(&q).len(), 1);

        let q = LogQuery { text: "404".into(), ..Default::default() };
        assert_eq!(log.filter(&q).len(), 1);
    }

    #[test]
    fn filter_by_tool_status_class_and_mime() {
        let mut log = Logger::new(10);
        log.push(entry("Proxy", "a.com", "/1", "GET", "200", "text/html"));
        log.push(entry("Repeater", "a.com", "/2", "GET", "404", "application/json"));
        log.push(entry("Scanner", "a.com", "/3", "GET", "500", "application/json"));

        let q = LogQuery { tool: Some("repeater".into()), ..Default::default() };
        assert_eq!(log.filter(&q).len(), 1);
        assert_eq!(log.filter(&q)[0].path, "/2");

        let q = LogQuery { status_class: Some(5), ..Default::default() };
        assert_eq!(log.filter(&q).len(), 1);
        assert_eq!(log.filter(&q)[0].status, "500");

        let q = LogQuery { mime: "JSON".into(), ..Default::default() };
        assert_eq!(log.filter(&q).len(), 2);

        let q = LogQuery {
            tool: Some("Proxy".into()),
            status_class: Some(2),
            mime: "html".into(),
            text: "a.com".into(),
        };
        assert_eq!(log.filter(&q).len(), 1);
    }

    #[test]
    fn empty_query_matches_everything() {
        let mut log = Logger::new(10);
        log.push(sample());
        log.push(sample());
        let q = LogQuery::default();
        assert!(q.is_empty());
        assert_eq!(log.filter(&q).len(), 2);
    }

    #[test]
    fn clear_empties_but_ids_continue() {
        let mut log = Logger::new(10);
        log.push(sample());
        log.push(sample());
        log.clear();
        assert_eq!(log.len(), 0);
        assert!(log.snapshot().is_empty());
        assert_eq!(log.push(sample()), 3);
    }

    #[test]
    fn snapshot_is_newest_first() {
        let mut log = Logger::new(10);
        for i in 0..4 {
            log.push(LogEntry { ts: i, ..sample() });
        }
        let snap = log.snapshot();
        let ts: Vec<u64> = snap.iter().map(|e| e.ts).collect();
        assert_eq!(ts, vec![3, 2, 1, 0]);
        // Storage itself stays oldest-first.
        let stored: Vec<u64> = log.entries.iter().map(|e| e.ts).collect();
        assert_eq!(stored, vec![0, 1, 2, 3]);
    }
}
