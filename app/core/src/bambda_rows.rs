//! Table rows as Bambda inputs (R-16).
//!
//! The evaluator speaks Burp's HTTP shape (`ProxyHttpRequestResponse`). Proxy
//! history and Logger rows already are HTTP exchanges, so they pass through
//! unchanged. A WebSocket message is presented as a synthetic
//! `POST /websocket` request whose body is the message payload and whose
//! `X-Webprobe-*` headers carry the direction and opcode, because the backend
//! has no `WebSocketMessage` program kind.
//!
//! Every snapshot is capped: it records the newest rows and says how many it
//! left out, so a table can show what the script did and did not see.

use crate::bambda::{Exchange, MAX_RAW_BATCH_BYTES};
use crate::history::ProxyHistory;
use crate::logger::{LogEntry, Logger};
use crate::net::HistEntry;
use crate::ws_history::{WsEntry, WsHistory};

/// Which rows a snapshot came from. Only used to tell a view whether the run
/// still matches the table ("12 newer exchanges since this run").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stamp {
    pub rows: usize,
    pub last_id: u64,
}

/// A bounded table snapshot ready for one Bambda run.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// Newest first, at most the requested cap.
    pub rows: Vec<Exchange>,
    /// Ids left out because one exchange was larger than a whole batch.
    pub skipped: Vec<u64>,
    /// The table at the moment of the snapshot.
    pub stamp: Stamp,
}

impl Snapshot {
    /// Rows the script is asked about.
    pub fn evaluated(&self) -> usize {
        self.rows.len()
    }
}

/// Room a row's own bytes may take, not counting the synthetic request head.
fn fits(size: usize) -> bool {
    size <= MAX_RAW_BATCH_BYTES
}

/// One history entry as a Bambda row, or `None` when it does not fit a batch.
pub fn history_row(entry: &HistEntry) -> Option<Exchange> {
    let request = entry.req_raw.to_vec();
    let response = entry.resp_raw.as_ref().map(|b| b.to_vec());
    let size = request.len() + response.as_ref().map_or(0, Vec::len) + entry.host.len();
    fits(size).then(|| Exchange {
        id: entry.id,
        host: entry.host.clone(),
        port: entry.port,
        secure: entry.https,
        request,
        response,
    })
}

/// A slice of history entries as Bambda rows, with the oversized ids.
pub fn history_rows(entries: &[HistEntry]) -> (Vec<Exchange>, Vec<u64>) {
    let mut rows = Vec::with_capacity(entries.len());
    let mut skipped = Vec::new();
    for entry in entries {
        match history_row(entry) {
            Some(row) => rows.push(row),
            None => skipped.push(entry.id),
        }
    }
    (rows, skipped)
}

/// Newest `cap` proxy-history rows.
pub fn history_snapshot(history: &ProxyHistory, cap: usize) -> Snapshot {
    history.with_rows(|rows| {
        let mut snap = Snapshot {
            stamp: Stamp {
                rows: rows.len(),
                last_id: rows.last().map(|e| e.id).unwrap_or(0),
            },
            ..Snapshot::default()
        };
        for entry in rows.iter().rev().take(cap) {
            match history_row(entry) {
                Some(row) => snap.rows.push(row),
                None => snap.skipped.push(entry.id),
            }
        }
        snap
    })
}

fn log_row(entry: &LogEntry, history: &ProxyHistory) -> Option<Exchange> {
    // Proxy rows keep their messages in the history; tool rows carry their own.
    let mirrored = entry.hist_id.and_then(|id| history.get(id));
    let request = match (&entry.request, mirrored.as_ref().map(|h| &h.req_raw)) {
        (Some(bytes), _) => bytes.to_vec(),
        (None, Some(bytes)) => bytes.to_vec(),
        (None, None) => return None,
    };
    let response = match (
        &entry.response,
        mirrored.as_ref().and_then(|h| h.resp_raw.as_ref()),
    ) {
        (Some(bytes), _) => Some(bytes.to_vec()),
        (None, Some(bytes)) => Some(bytes.to_vec()),
        (None, None) => None,
    };
    let size = request.len() + response.as_ref().map_or(0, Vec::len) + entry.host.len();
    fits(size).then(|| Exchange {
        id: entry.id,
        host: entry.host.clone(),
        port: entry.port,
        secure: entry.https,
        request,
        response,
    })
}

/// Newest `cap` Logger rows. Rows whose messages were dropped (older tool
/// traffic, cleared history) are skipped rather than invented.
pub fn log_snapshot(log: &Logger, history: &ProxyHistory, cap: usize) -> Snapshot {
    let rows = log.len();
    let mut snap = Snapshot {
        stamp: Stamp {
            rows,
            last_id: log.next_id.saturating_sub(1),
        },
        ..Snapshot::default()
    };
    for entry in log.entries.iter().skip(rows.saturating_sub(cap)) {
        match log_row(entry, history) {
            Some(row) => snap.rows.push(row),
            None => snap.skipped.push(entry.id),
        }
    }
    snap.rows.reverse();
    snap
}

/// Header values and the host come from recorded traffic: a CR or LF would
/// inject headers into the synthetic request.
fn header_safe(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

/// The synthetic request a WebSocket message is shown to a script as.
pub fn websocket_request(entry: &WsEntry) -> Vec<u8> {
    let payload = entry.payload.as_ref();
    let head = format!(
        "POST /websocket HTTP/1.1\r\nHost: {}\r\nX-Webprobe-Direction: {}\r\nX-Webprobe-Opcode: {}\r\nContent-Length: {}\r\n\r\n",
        header_safe(&entry.host),
        header_safe(&entry.direction),
        header_safe(&entry.opcode),
        payload.len()
    );
    let mut out = Vec::with_capacity(head.len() + payload.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(payload);
    out
}

fn websocket_row(entry: &WsEntry) -> Option<Exchange> {
    let request = websocket_request(entry);
    let size = request.len() + entry.host.len();
    fits(size).then(|| Exchange {
        id: entry.id,
        host: entry.host.clone(),
        // A message has no origin of its own; the connection upgrade did.
        port: 443,
        secure: true,
        request,
        response: None,
    })
}

/// Newest `cap` WebSocket messages.
pub fn websocket_snapshot(history: &WsHistory, cap: usize) -> Snapshot {
    history.with_rows(|rows| {
        let mut snap = Snapshot {
            stamp: Stamp {
                rows: rows.len(),
                last_id: rows.last().map(|e| e.id).unwrap_or(0),
            },
            ..Snapshot::default()
        };
        for entry in rows.iter().rev().take(cap) {
            match websocket_row(entry) {
                Some(row) => snap.rows.push(row),
                None => snap.skipped.push(entry.id),
            }
        }
        snap
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::Body;

    fn history_entry(id: u64, request: &[u8], response: Option<&[u8]>) -> HistEntry {
        HistEntry {
            id,
            host: "example.test".into(),
            port: 8443,
            https: true,
            req_raw: Body::from(request.to_vec()),
            resp_raw: response.map(|b| Body::from(b.to_vec())),
            ..HistEntry::default()
        }
    }

    fn ws_entry(id: u64, direction: &str, opcode: &str, payload: &[u8]) -> WsEntry {
        WsEntry {
            id,
            ts: 0,
            host: "ws.test".into(),
            direction: direction.into(),
            opcode: opcode.into(),
            payload: Body::from(payload.to_vec()),
            socket: 1,
        }
    }

    #[test]
    fn history_snapshot_is_newest_first_and_capped() {
        let history = ProxyHistory::default();
        for id in 1..=5 {
            history.push(history_entry(
                id,
                b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
                Some(b"HTTP/1.1 200 OK\r\n\r\n"),
            ));
        }
        let snap = history_snapshot(&history, 3);
        assert_eq!(snap.stamp.rows, 5);
        assert_eq!(snap.stamp.last_id, 5);
        let ids: Vec<u64> = snap.rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![5, 4, 3]);
        assert_eq!(snap.rows[0].host, "example.test");
        assert_eq!(snap.rows[0].port, 8443);
        assert!(snap.rows[0].secure);
        // Bytes are kept verbatim, not through UTF-8.
        assert!(snap.rows[0].request.ends_with(b"\r\n\r\n"));
        assert!(snap.skipped.is_empty());
    }

    #[test]
    fn an_oversized_history_row_is_skipped_not_failed() {
        let history = ProxyHistory::default();
        history.push(history_entry(1, b"GET / HTTP/1.1\r\n\r\n", None));
        history.push(history_entry(2, &vec![b'a'; MAX_RAW_BATCH_BYTES + 1], None));
        let snap = history_snapshot(&history, 10);
        assert_eq!(snap.rows.len(), 1);
        assert_eq!(snap.rows[0].id, 1);
        assert_eq!(snap.skipped, vec![2]);
    }

    #[test]
    fn log_rows_read_mirrored_messages_from_history_and_own_bytes_otherwise() {
        let history = ProxyHistory::default();
        history.push(history_entry(
            9,
            b"GET /mirrored HTTP/1.1\r\n\r\n",
            Some(b"HTTP/1.1 200 OK\r\n\r\n"),
        ));
        let mut log = Logger::new(10);
        let mirrored = log.push(LogEntry {
            hist_id: Some(9),
            host: "example.test".into(),
            ..LogEntry::default()
        });
        let own: std::sync::Arc<[u8]> = std::sync::Arc::from(&b"GET /tool HTTP/1.1\r\n\r\n"[..]);
        let tool = log.push(LogEntry {
            tool: "Repeater".into(),
            host: "tool.test".into(),
            request: Some(own.clone()),
            response: Some(own),
            ..LogEntry::default()
        });
        // An old tool row whose bytes were dropped is skipped, not invented.
        let dropped = log.push(LogEntry {
            tool: "Scanner".into(),
            ..LogEntry::default()
        });
        let snap = log_snapshot(&log, &history, 10);
        assert_eq!(snap.stamp.rows, 3);
        assert_eq!(snap.stamp.last_id, log.next_id - 1);
        let ids: Vec<u64> = snap.rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![tool, mirrored]);
        assert_eq!(snap.skipped, vec![dropped]);
        assert_eq!(snap.rows[0].request, b"GET /tool HTTP/1.1\r\n\r\n");
        assert_eq!(snap.rows[1].request, b"GET /mirrored HTTP/1.1\r\n\r\n");
        assert!(snap.rows[1].response.is_some());
    }

    #[test]
    fn a_websocket_message_is_a_synthetic_post_with_the_payload_as_body() {
        let ws = WsHistory::new();
        ws.push(ws_entry(
            1,
            "client -> server",
            "binary",
            &[0xff, 0x00, b'x'],
        ));
        ws.push(ws_entry(2, "server -> client", "text", b"hello"));
        let snap = websocket_snapshot(&ws, 10);
        assert_eq!(snap.stamp.rows, 2);
        assert_eq!(snap.rows[0].id, 2);
        assert_eq!(
            snap.rows[0].request,
            websocket_request(&ws_entry(2, "server -> client", "text", b"hello"))
        );

        let parsed = crate::util::parse_http(&snap.rows[0].request);
        assert_eq!(parsed.first, "POST /websocket HTTP/1.1");
        let header = |name: &str| {
            parsed
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(header("Host").as_deref(), Some("ws.test"));
        assert_eq!(
            header("X-Webprobe-Direction").as_deref(),
            Some("server -> client")
        );
        assert_eq!(header("X-Webprobe-Opcode").as_deref(), Some("text"));
        assert_eq!(header("Content-Length").as_deref(), Some("5"));
        assert_eq!(&snap.rows[0].request[parsed.head_len..], b"hello");
        // Binary bytes survive unchanged (row 1 has its own head length).
        let binary = crate::util::parse_http(&snap.rows[1].request);
        assert_eq!(
            &snap.rows[1].request[binary.head_len..],
            &[0xff, 0x00, b'x']
        );
    }

    #[test]
    fn a_recorded_crlf_cannot_inject_a_header_into_the_synthetic_request() {
        let mut entry = ws_entry(1, "client -> server", "text", b"x");
        entry.host = "evil.test\r\nX-Injected: 1".into();
        let parsed = crate::util::parse_http(&websocket_request(&entry));
        assert!(
            !parsed
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("X-Injected"))
        );
        assert_eq!(
            parsed
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.as_str()),
            Some("evil.test  X-Injected: 1")
        );
    }
}
