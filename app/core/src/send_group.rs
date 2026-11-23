//! R-12 Repeater groups: Burp's Zr4d group-send model (single connection,
//! separate connections, last-byte synchronized parallel sends), the
//! Zrup dialog's group registry, and the Zsch project payload.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use crate::net::{self, Shared, Upstream, UpstreamConn};

/// Burp's fourteen group colours (Zrup), in cycle order.
pub const GROUP_COLOURS: usize = 15;

/// One saved group: its tabs, in the tab bar's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepGroup {
    pub id: u64,
    pub name: String,
    pub colour: u8,
    pub tabs: Vec<u64>,
}

/// The next colour: the first unused one, else the one after the last
/// created group's (Burp's rotation).
pub fn next_colour(groups: &[RepGroup]) -> u8 {
    let used: Vec<u8> = groups.iter().map(|g| g.colour).collect();
    for c in 0..GROUP_COLOURS as u8 {
        if !used.contains(&c) {
            return c;
        }
    }
    groups.last().map_or(0, |g| (g.colour + 1) % GROUP_COLOURS as u8)
}

/// Create a group from checked tabs. Members sit side by side in the tab
/// bar, at the position of the earliest one; the rest keep their order.
pub fn create_group(
    groups: &mut Vec<RepGroup>,
    order: &mut Vec<u64>,
    id: u64,
    name: &str,
    colour: u8,
    tabs: &[u64],
) -> Option<u64> {
    let name = name.trim();
    if name.is_empty() || tabs.is_empty() {
        return None;
    }
    let members: Vec<u64> = order.iter().copied().filter(|t| tabs.contains(t)).collect();
    if members.is_empty() {
        return None;
    }
    for &t in tabs {
        remove_from_group(groups, t);
    }
    let at = order.iter().position(|t| members.contains(t))?;
    order.retain(|t| !members.contains(t));
    for (off, t) in members.iter().enumerate() {
        order.insert(at + off, *t);
    }
    groups.push(RepGroup { id, name: name.into(), colour, tabs: members });
    Some(id)
}

/// The group a tab belongs to.
pub fn group_of(groups: &[RepGroup], tab: u64) -> Option<&RepGroup> {
    groups.iter().find(|g| g.tabs.contains(&tab))
}

/// Move a tab into a group: it leaves its old group (which vanishes when
/// emptied) and joins after the new group's last tab in the bar.
pub fn add_to_group(groups: &mut Vec<RepGroup>, order: &mut Vec<u64>, group: u64, tab: u64) {
    remove_from_group(groups, tab);
    let Some(g) = groups.iter_mut().find(|g| g.id == group) else { return };
    g.tabs.push(tab);
    let after: Vec<u64> = g.tabs.clone();
    order.retain(|t| *t != tab);
    let at = order.iter().rposition(|t| after[..after.len() - 1].contains(t)).map_or(order.len(), |p| p + 1);
    order.insert(at.min(order.len()), tab);
}

/// Drop a tab from its group; an empty group disappears.
pub fn remove_from_group(groups: &mut Vec<RepGroup>, tab: u64) {
    let mut empty = None;
    for (i, g) in groups.iter_mut().enumerate() {
        if let Some(p) = g.tabs.iter().position(|t| *t == tab) {
            g.tabs.remove(p);
            if g.tabs.is_empty() {
                empty = Some(i);
            }
        }
    }
    if let Some(i) = empty {
        groups.remove(i);
    }
}

/// Rename or recolour. A blank name is refused.
pub fn edit_group(groups: &mut [RepGroup], id: u64, name: &str, colour: u8) -> bool {
    let name = name.trim();
    if name.is_empty() {
        return false;
    }
    if let Some(g) = groups.iter_mut().find(|g| g.id == id) {
        g.name = name.into();
        g.colour = colour % GROUP_COLOURS as u8;
        return true;
    }
    false
}

/// Delete a group. Its tabs stay; the freed ones are returned.
pub fn delete_group(groups: &mut Vec<RepGroup>, id: u64) -> Vec<u64> {
    if let Some(p) = groups.iter().position(|g| g.id == id) {
        return groups.remove(p).tabs;
    }
    Vec::new()
}

/// Ungroup: same as delete (the UI keeps its tabs open either way).
pub fn ungroup(groups: &mut Vec<RepGroup>, id: u64) {
    delete_group(groups, id);
}

/// Close every tab of the group and drop it.
pub fn close_group_tabs(groups: &mut Vec<RepGroup>, id: u64) -> Vec<u64> {
    delete_group(groups, id)
}

/// Zsch: groups persist by tab position, so ids can be reissued on load.
pub fn to_project(groups: &[RepGroup], order: &[u64]) -> Vec<crate::project::ProjectRepeaterGroup> {
    groups
        .iter()
        .map(|g| crate::project::ProjectRepeaterGroup {
            name: g.name.clone(),
            colour: g.colour,
            tabs: g.tabs.iter().filter_map(|t| order.iter().position(|o| o == t)).collect(),
        })
        .collect()
}

/// Back from Zsch: positions become tabs again, with fresh group ids.
pub fn from_project(
    saved: &[crate::project::ProjectRepeaterGroup],
    order: &[u64],
    mut next_id: impl FnMut() -> u64,
) -> Vec<RepGroup> {
    saved
        .iter()
        .filter_map(|g| {
            let tabs: Vec<u64> = g.tabs.iter().filter_map(|&p| order.get(p).copied()).collect();
            if tabs.is_empty() {
                return None;
            }
            Some(RepGroup { id: next_id(), name: g.name.clone(), colour: g.colour, tabs })
        })
        .collect()
}

/// One sendable tab snapshot (built by the UI from its Repeater state).
#[derive(Debug, Clone)]
pub struct GroupItem {
    pub tab: u64,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub request: Vec<u8>,
    pub http2: bool,
    pub websocket: bool,
}

/// Zr4d's three ways of sending a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMode {
    /// Sent in order, down a single connection.
    SingleConnection,
    /// Sent in order, each on its own connection.
    Separate,
    /// Sent in parallel with last-byte synchronization.
    Parallel,
}

/// A pre-send problem Zr4d would refuse with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    EmptyRequest,
    TargetMissing,
    WebSocketTab,
    ServiceMismatch,
    ProtocolMismatch,
    Http1KeepAlive,
}

impl Problem {
    pub fn text(self) -> &'static str {
        match self {
            Self::EmptyRequest => "One or more requests in this group are empty",
            Self::TargetMissing => "Target host or port is not specified for one or more requests in this group",
            Self::WebSocketTab => "WebSocket messages cannot be sent as part of a Repeater group",
            Self::ServiceMismatch => "All requests in a group must be sent to the same service when using a single connection or sending in parallel",
            Self::ProtocolMismatch => "All requests in a group must use the same protocol version",
            Self::Http1KeepAlive => "HTTP/1 connection reuse is enabled for one or more requests in this group",
        }
    }
}

/// Zr4d's per-mode refusal list, in one pass.
pub fn validate(mode: GroupMode, items: &[GroupItem], keep_alive: bool) -> Vec<Problem> {
    let mut out = Vec::new();
    let mut push = |p: Problem| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    if items.iter().any(|i| String::from_utf8_lossy(&i.request).trim().is_empty()) {
        push(Problem::EmptyRequest);
    }
    let first = items.first();
    let same_service =
        |a: &GroupItem, b: &GroupItem| a.host == b.host && a.port == b.port && a.https == b.https;
    match mode {
        GroupMode::SingleConnection | GroupMode::Parallel => {
            if let Some(f) = first {
                if items.iter().any(|i| !same_service(f, i)) {
                    push(Problem::ServiceMismatch);
                }
            }
        }
        GroupMode::Separate => {
            if items.iter().any(|i| i.host.is_empty() || i.port == 0) {
                push(Problem::TargetMissing);
            }
        }
    }
    if mode != GroupMode::Separate && items.iter().any(|i| i.http2 != first.is_some_and(|f| f.http2)) {
        push(Problem::ProtocolMismatch);
    }
    if mode == GroupMode::Parallel && keep_alive && items.iter().all(|i| !i.http2) {
        push(Problem::Http1KeepAlive);
    }
    if items.iter().any(|i| i.websocket) {
        push(Problem::WebSocketTab);
    }
    out
}

/// How a group run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceEnd {
    Completed,
    /// Cancelled after this many responses.
    Cancelled(usize),
    /// Stopped after an UnknownHost error at this index (Burp aborts the
    /// sequence on unknown hosts).
    UnknownHost(usize),
}

/// Per-item result handed to the UI callback.
#[derive(Debug, Clone)]
pub struct GroupResult {
    pub response: Option<Vec<u8>>,
    pub error: Option<String>,
    /// For parallel sends: (arrival position, group size) once all are in.
    pub arrival: Option<(usize, usize)>,
    /// The request as it went out (after jar/session rewriting): what the
    /// tab's history and the tool log show.
    pub sent: Vec<u8>,
    /// "HTTP/2" or "HTTP/1.1", for the result line.
    pub protocol: &'static str,
    /// Send-to-response time; 0 where the burst makes it meaningless.
    pub elapsed_ms: u128,
}

/// Drop groups whose tabs are gone (after tab closes); member lists
/// follow the tab bar. Call after any close/reorder.
pub fn prune(groups: &mut Vec<RepGroup>, order: &[u64]) {
    for g in groups.iter_mut() {
        g.tabs.retain(|t| order.contains(t));
        g.tabs.sort_by_key(|t| order.iter().position(|o| o == t).unwrap_or(usize::MAX));
    }
    groups.retain(|g| !g.tabs.is_empty());
}

/// The error of a failed name lookup (dns::resolve), Burp's
/// UnknownHostException: the sequence stops on it, other errors do not.
pub(crate) fn unknown_host(error: &str) -> bool {
    error.starts_with("dns ") && !error.contains("timed out")
}

/// Shared HTTP/2 group transport lives in h2_group (split out for the
/// file-length gate). run_sequence dispatches there for the single-
/// connection mode; the parallel mode's single-packet h2 burst too.

/// Open a fresh connection to the target, TLS with an h2 ALPN offer when
/// the tab spoke HTTP/2 (mirrors the conn_reuse upstream-TLS pattern).
pub(crate) fn open_conn(
    shared: &Shared,
    host: &str,
    port: u16,
    https: bool,
    http2: bool,
) -> Result<UpstreamConn, String> {
    let config = shared.upstream_for(host);
    let tcp = crate::upstream::connect_tls_target(&config, host, port)?;
    tcp.set_read_timeout(Some(Duration::from_millis(net::READ_TIMEOUT_MS))).ok();
    tcp.set_nodelay(true).ok();
    if !https {
        return Ok(UpstreamConn::Plain(tcp));
    }
    let base = net::tls_client_config_base(shared, host);
    let cfg = if http2 {
        let mut c = (*base).clone();
        c.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(c)
    } else {
        base
    };
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|e| format!("invalid upstream TLS name {host}: {e}"))?;
    let conn = rustls::ClientConnection::new(cfg, name)
        .map_err(|e| format!("configure upstream TLS: {e}"))?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    // Settle the handshake so ALPN and certificate errors surface here.
    tls.conn.complete_io(&mut tls.sock).map_err(|e| format!("tls: {e}"))?;
    Ok(UpstreamConn::Tls(Box::new(tls)))
}

/// Finish one exchange: jar + session handling, tool log. The calling
/// thread must hold a `net::tool_scope("Repeater")` guard for the jar,
/// session rules and log to engage (run_sequence/run_parallel set one).
pub(crate) fn finish_item(
    shared: &Shared,
    item: &GroupItem,
    request: &[u8],
    outcome: Result<(Vec<u8>, Option<(usize, usize)>), String>,
    hooked: Option<Vec<u8>>,
) -> GroupResult {
    let shown = hooked.unwrap_or_else(|| request.to_vec());
    let protocol = if item.http2 { "HTTP/2" } else { "HTTP/1.1" };
    match outcome {
        Ok((resp, arrival)) => {
            let up = Upstream { resp: Some(resp.clone()), error: None };
            net::jar_response(shared, &item.host, request, &up);
            net::session_after(shared, &item.host);
            net::log_tool_exchange(shared, &item.host, item.port, item.https, &shown, &up);
            GroupResult { response: Some(resp), error: None, arrival, sent: shown, protocol, elapsed_ms: 0 }
        }
        Err(e) => {
            let up = Upstream { resp: None, error: Some(e.clone()) };
            net::log_tool_exchange(shared, &item.host, item.port, item.https, &shown, &up);
            GroupResult { response: None, error: Some(e), arrival: None, sent: shown, protocol, elapsed_ms: 0 }
        }
    }
}

/// Session rules + cookie jar rewrite a request before it goes out;
/// returns what should be shown in the log when it differs.
pub fn hooked(shared: &Shared, item: &GroupItem) -> (Vec<u8>, Option<Vec<u8>>) {
    let req = net::jar_request(shared, &item.host, item.https, &item.request);
    let req = net::session_request(shared, item.port, item.https, req)
        .unwrap_or_else(|_| item.request.as_slice().into());
    let hooked = (req.as_ref() != item.request.as_slice()).then(|| req.to_vec());
    (req.into_owned(), hooked)
}

/// Send a request over one open connection (h1), as the tab has it.
fn send_on(
    conn: &mut UpstreamConn,
    _host: &str,
    req: &[u8],
) -> Result<Vec<u8>, String> {
    let (resp, _) = net::exchange(conn, req, None)?;
    Ok(resp)
}

/// h2 one-off send for separate-connections mode: one TLS connection,
/// one request, done.
fn h2_exchange(shared: &Shared, item: &GroupItem, req: &[u8]) -> Result<Vec<u8>, String> {
    let conn = open_conn(shared, &item.host, item.port, item.https, true)?;
    let UpstreamConn::Tls(mut tls) = conn else {
        return Err("h2 group over cleartext is not supported".into());
    };
    let h2req = crate::h2::request_from_raw(req, "https").ok_or("h2: request without Host header")?;
    crate::h2::exchange(tls.as_mut(), &h2req, None)
}

/// Zr4d's ordered modes. Returns how it ended; per-item results go to
/// `on_item` with the item's position.
pub fn run_sequence(
    shared: &Shared,
    items: &[GroupItem],
    single_connection: bool,
    cancel: &AtomicBool,
    mut on_item: impl FnMut(usize, GroupResult),
) -> SequenceEnd {
    if single_connection && items.first().is_some_and(|i| i.http2) {
        return crate::h2_group::run_single_connection(shared, items, cancel, on_item);
    }
    let _tool = net::tool_scope("Repeater");
    let mut conn: Option<UpstreamConn> = None;
    let mut answered = 0usize;
    for (n, item) in items.iter().enumerate() {
        if n > 0 && cancel.load(Ordering::SeqCst) {
            return SequenceEnd::Cancelled(answered);
        }
        let t0 = std::time::Instant::now();
        let (req, hook) = hooked(shared, item);
        let outcome = (|| -> Result<Vec<u8>, String> {
            if item.http2 {
                // Separate-mode h2: one TLS connection per send.
                return h2_exchange(shared, item, &req);
            }
            let c = match (single_connection, conn.as_mut()) {
                (true, Some(c)) => c,
                _ => {
                    let c = open_conn(shared, &item.host, item.port, item.https, false)?;
                    if single_connection {
                        conn = Some(c);
                        conn.as_mut().unwrap()
                    } else {
                        // Not stored; dropped after the response.
                        conn = Some(c);
                        conn.as_mut().unwrap()
                    }
                }
            };
            let out = send_on(c, &item.host, &req);
            if !single_connection {
                conn = None;
            }
            out
        })();
        let unknown = outcome.as_ref().err().is_some_and(|e| unknown_host(e));
        let mut r = finish_item(shared, item, &req, outcome.map(|r| (r, None)), hook);
        r.elapsed_ms = t0.elapsed().as_millis();
        on_item(n, r);
        answered += 1;
        if unknown {
            return SequenceEnd::UnknownHost(n);
        }
    }
    SequenceEnd::Completed
}

/// Zr4d's parallel mode ("single-packet attack"): every request goes out
/// on its own connection with all but the last byte, a barrier releases
/// the senders together, and the last bytes land as close to simultaneous
/// as the OS allows.
pub fn run_parallel(
    shared: &Shared,
    items: &[GroupItem],
    cancel: &AtomicBool,
    on_item: impl Fn(usize, GroupResult) + Send + Sync,
) -> SequenceEnd {
    if items.first().is_some_and(|i| i.http2) {
        return crate::h2_group::run_parallel_single_packet(shared, items, cancel, on_item);
    }
    if cancel.load(Ordering::SeqCst) {
        return SequenceEnd::Cancelled(0);
    }
    let _tool = net::tool_scope("Repeater");
    let n_items = items.len();
    let gate = Arc::new(Barrier::new(n_items));
    let arrival = Arc::new(std::sync::Mutex::new(Vec::new()));
    let on_item = &on_item;
    std::thread::scope(|s| {
        for (n, item) in items.iter().enumerate() {
            let gate = gate.clone();
            let arrival = arrival.clone();
            s.spawn(move || {
                let _tool = net::tool_scope("Repeater");
                let t0 = std::time::Instant::now();
                let (req, hook) = hooked(shared, item);
                let outcome = (|| -> Result<Vec<u8>, String> {
                    if req.is_empty() {
                        // Like the connect/write failures below: arrive at
                        // the barrier before bailing, or the other senders
                        // wait on a barrier that can never release.
                        gate.wait();
                        return Err("empty request".into());
                    }
                    let mut conn = match open_conn(shared, &item.host, item.port, item.https, false) {
                        Ok(c) => c,
                        Err(e) => {
                            gate.wait();
                            return Err(e);
                        }
                    };
                    if item.https {
                        // TLS record framing absorbs the last-byte split;
                        // release together and send whole.
                        gate.wait();
                        conn.write_all(&req).and_then(|()| conn.flush()).map_err(|e| format!("send: {e}"))?;
                    } else {
                        if let UpstreamConn::Plain(tcp) = &conn {
                            tcp.set_read_timeout(Some(Duration::from_millis(net::READ_TIMEOUT_MS * 4))).ok();
                        }
                        let (prefix, last) = req.split_at(req.len() - 1);
                        if let Err(e) = conn.write_all(prefix) {
                            gate.wait();
                            return Err(format!("send: {e}"));
                        }
                        conn.flush().ok();
                        // Every sender is here: all prefixes are sent.
                        // Release the last bytes together.
                        gate.wait();
                        conn.write_all(last).and_then(|()| conn.flush()).map_err(|e| format!("send: {e}"))?;
                    }
                    let method = String::from_utf8_lossy(&req)
                        .split(' ')
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    let mut buffer = Vec::new();
                    let (resp, _) = crate::codec::read_message(&mut conn, &mut buffer, &method, None)
                        .map_err(|e| format!("read: {e}"))?;
                    Ok(resp)
                })();
                let at = {
                    let mut done = arrival.lock().unwrap();
                    done.push(n);
                    done.len()
                };
                let mut r = finish_item(shared, item, &req, outcome.map(|resp| (resp, None)), hook);
                r.arrival = Some((at, n_items));
                r.elapsed_ms = t0.elapsed().as_millis();
                on_item(n, r);
            });
        }
    });
    SequenceEnd::Completed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    fn group(id: u64, colour: u8, tabs: &[u64]) -> RepGroup {
        RepGroup { id, name: format!("g{id}"), colour, tabs: tabs.to_vec() }
    }

    #[test]
    fn groups_gather_their_tabs_and_vanish_when_empty() {
        let mut order = vec![1, 2, 3, 4, 5];
        let mut groups = Vec::new();
        assert_eq!(create_group(&mut groups, &mut order, 10, "  ", 0, &[2, 4]), None, "blank name");
        assert_eq!(create_group(&mut groups, &mut order, 10, "login", 0, &[]), None, "no tabs");
        assert_eq!(create_group(&mut groups, &mut order, 10, " login ", 3, &[4, 2]), Some(10));
        assert_eq!(order, vec![1, 2, 4, 3, 5], "members side by side at the first one's place");
        assert_eq!(groups, vec![RepGroup { id: 10, name: "login".into(), colour: 3, tabs: vec![2, 4] }]);
        // A second group takes 5 and 1; 1 comes first in the bar.
        let colour = next_colour(&groups);
        create_group(&mut groups, &mut order, 11, "race", colour, &[5, 1]);
        assert_eq!(order, vec![1, 5, 2, 4, 3]);
        assert_eq!(groups[1].colour, 0, "first unused colour");
        // Moving tab 3 into "login" puts it after the group's last tab.
        add_to_group(&mut groups, &mut order, 10, 3);
        assert_eq!(order, vec![1, 5, 2, 4, 3]);
        assert_eq!(group_of(&groups, 3).map(|g| g.id), Some(10));
        // Moving 1 from "race" to "login": "race" keeps 5.
        add_to_group(&mut groups, &mut order, 10, 1);
        assert_eq!(group_of(&groups, 5).unwrap().tabs, vec![5]);
        assert_eq!(group_of(&groups, 1).unwrap().tabs, vec![2, 4, 3, 1]);
        assert_eq!(order, vec![5, 2, 4, 3, 1]);
        // Removing the last tab removes the group.
        remove_from_group(&mut groups, 5);
        assert!(groups.iter().all(|g| g.id != 11));
        assert!(edit_group(&mut groups, 10, "renamed", 20) && groups[0].colour == 5);
        assert!(!edit_group(&mut groups, 10, " ", 1));
        assert_eq!(delete_group(&mut groups, 10), vec![2, 4, 3, 1]);
        assert!(groups.is_empty());
        // Ungroup keeps the tabs (the caller closes nothing).
        let mut gs = vec![group(1, 0, &[1, 2])];
        ungroup(&mut gs, 1);
        assert!(gs.is_empty());
    }

    #[test]
    fn colours_follow_burps_choice() {
        assert_eq!(next_colour(&[]), 0);
        assert_eq!(next_colour(&[group(1, 0, &[1]), group(2, 2, &[2])]), 1);
        let all: Vec<RepGroup> = (0..GROUP_COLOURS).map(|c| group(c as u64, c as u8, &[c as u64])).collect();
        assert_eq!(next_colour(&all), 0, "after GROUP_14 comes GROUP_0");
        let mut rot = all.clone();
        rot.push(group(99, 6, &[99]));
        assert_eq!(next_colour(&rot), 7, "the one after the last group's");
    }

    #[test]
    fn groups_survive_a_project_round_trip_by_tab_position() {
        let order = vec![7, 8, 9, 10];
        let groups = vec![group(1, 4, &[8, 10]), group(2, 14, &[9])];
        let saved = to_project(&groups, &order);
        let json = serde_json::to_string(&saved).unwrap();
        let back: Vec<crate::project::ProjectRepeaterGroup> = serde_json::from_str(&json).unwrap();
        // Fresh ids on load.
        let fresh = vec![21, 22, 23, 24];
        let mut next = 100;
        let loaded = from_project(&back, &fresh, || {
            next += 1;
            next
        });
        assert_eq!(loaded, vec![RepGroup { id: 101, name: "g1".into(), colour: 4, tabs: vec![22, 24] }, RepGroup { id: 102, name: "g2".into(), colour: 14, tabs: vec![23] }]);
        // An index past the end is dropped; a group left empty is not made.
        let bad = vec![crate::project::ProjectRepeaterGroup { name: "x".into(), colour: 1, tabs: vec![9] }];
        assert!(from_project(&bad, &fresh, || 1).is_empty());
        // A project written before groups loads without any.
        let old: crate::project::ProjectData = serde_json::from_str("{}").unwrap_or_default();
        assert!(old.repeater_groups.is_empty());
    }

    fn item(tab: u64, host: &str, port: u16, req: &str) -> GroupItem {
        GroupItem { tab, host: host.into(), port, https: false, request: req.as_bytes().to_vec(), http2: false, websocket: false }
    }

    #[test]
    fn validation_follows_zr4d_per_mode() {
        use GroupMode::*;
        let a = item(1, "h", 80, "GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        let mut b = a.clone();
        b.port = 81;
        let ok = [a.clone(), a.clone()];
        for m in [SingleConnection, Separate, Parallel] {
            assert!(validate(m, &ok, false).is_empty(), "{m:?}");
        }
        assert_eq!(validate(Parallel, &ok, true), vec![Problem::Http1KeepAlive]);
        assert!(validate(Separate, &ok, true).is_empty() && validate(SingleConnection, &ok, true).is_empty());
        let mixed = [a.clone(), b];
        assert_eq!(validate(SingleConnection, &mixed, false), vec![Problem::ServiceMismatch]);
        assert_eq!(validate(Parallel, &mixed, false), vec![Problem::ServiceMismatch]);
        assert!(validate(Separate, &mixed, false).is_empty(), "separate connections may go to different targets");
        let mut h2 = a.clone();
        h2.http2 = true;
        assert_eq!(validate(SingleConnection, &[a.clone(), h2.clone()], false), vec![Problem::ProtocolMismatch]);
        assert!(validate(Parallel, &[h2.clone(), h2], true).is_empty(), "keep-alive is an HTTP/1 matter");
        let mut empty = a.clone();
        empty.request = b" \r\n".to_vec();
        let mut ws = a.clone();
        ws.websocket = true;
        let mut no_target = a.clone();
        no_target.host.clear();
        assert_eq!(validate(Separate, &[empty.clone(), ws.clone(), no_target.clone()], false), vec![Problem::EmptyRequest, Problem::TargetMissing, Problem::WebSocketTab]);
        // TARGET_MISSING is a Separate-mode problem only (Zr4d); the others
        // see a service mismatch instead.
        assert_eq!(validate(Parallel, &[a, no_target], false), vec![Problem::ServiceMismatch]);
        assert_eq!(Problem::Http1KeepAlive.text(), "HTTP/1 connection reuse is enabled for one or more requests in this group");
    }

    /// A lab recording (connection index, request line) for each request,
    /// answering keep-alive.
    fn h1_lab() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<(usize, String)>>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = log.clone();
        std::thread::spawn(move || {
            for (idx, s) in l.incoming().flatten().enumerate() {
                let seen = seen.clone();
                std::thread::spawn(move || {
                    let mut s = s;
                    s.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head: Vec<u8> = buf.drain(..end + 4).collect();
                            let line = String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string();
                            let body = format!("conn{idx} {line}");
                            seen.lock().unwrap().push((idx, line));
                            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
                        }
                        match s.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                });
            }
        });
        (port, log)
    }

    /// R-12 parallel (single-packet attack) over HTTP/1: the lab logs the
    /// moment each connection has all but the request's last byte
    /// (Prefix) and the moment the last byte lands (Last). The client's
    /// barrier puts every prefix on the wire before any last byte; the
    /// lab mirrors it with a barrier of its own — it accepts every
    /// connection, reads every prefix, and only then reads the last
    /// bytes — so the observation does not depend on how the OS schedules
    /// forty threads. Each connection still proves its request completed
    /// only once its last byte arrived.
    #[test]
    fn parallel_last_byte_synchronizes_twenty_senders() {
        const SENDERS: usize = 20;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = events.clone();
        std::thread::spawn(move || {
            // Accept every connection before any reading starts: a
            // connection still in the backlog already holds its prefix,
            // and reading must not start ahead of it.
            let mut accepted = Vec::new();
            while accepted.len() < SENDERS {
                match l.accept() {
                    Ok((s, _)) => accepted.push(s),
                    Err(_) => return,
                }
            }
            let gate = std::sync::Arc::new(std::sync::Barrier::new(SENDERS));
            for s in accepted {
                let seen = seen.clone();
                let gate = gate.clone();
                std::thread::spawn(move || {
                    let mut s = s;
                    s.set_read_timeout(Some(std::time::Duration::from_secs(15))).ok();
                    let mut buf = Vec::new();
                    let mut byte = [0u8; 1];
                    // Phase one: read up to the request's last-but-one
                    // byte (a bare GET ends in \r\n\r\n, so the prefix
                    // ends in \r\n\r).
                    loop {
                        match s.read(&mut byte) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {
                                buf.push(byte[0]);
                                if buf.len() >= 3 && &buf[buf.len() - 3..] == b"\r\n\r" {
                                    break;
                                }
                            }
                        }
                    }
                    seen.lock().unwrap().push("prefix");
                    // Every prefix is in: now the last bytes may come.
                    gate.wait();
                    match s.read(&mut byte) {
                        Ok(1) => {
                            seen.lock().unwrap().push("last");
                            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                        }
                        _ => return,
                    }
                });
            }
        });
        let shared = crate::net::Shared::new();
        let cancel = AtomicBool::new(false);
        let items: Vec<GroupItem> = (0..20).map(|i| GroupItem {
            tab: i as u64,
            host: "127.0.0.1".into(),
            port,
            https: false,
            request: format!("GET /race/{i} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").into_bytes(),
            http2: false,
            websocket: false,
        }).collect();
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let keep = got.clone();
        let end = run_parallel(&shared, &items, &cancel, move |n, r| keep.lock().unwrap().push((n, r)));
        assert_eq!(end, SequenceEnd::Completed);
        let got = got.lock().unwrap();
        assert_eq!(got.len(), 20);
        assert!(got.iter().all(|(_, r)| r.error.is_none() && r.response.is_some()));
        assert!(got.iter().all(|(_, r)| r.arrival.is_some_and(|(_, total)| total == 20)));
        let ev = events.lock().unwrap();
        assert_eq!(ev.iter().filter(|e| **e == "prefix").count(), 20, "{ev:?}");
        assert_eq!(ev.iter().filter(|e| **e == "last").count(), 20, "{ev:?}");
        let last_prefix = ev.iter().rposition(|e| *e == "prefix").unwrap();
        let first_last = ev.iter().position(|e| *e == "last").unwrap();
        assert!(last_prefix < first_last, "every prefix must land before the first last byte: {ev:?}");
    }

    /// One sender that cannot connect must not leave the others waiting
    /// on the prefix barrier forever: the group completes, with the
    /// failed tab carrying its error.
    #[test]
    fn parallel_sender_error_releases_the_barrier() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            while let Ok((mut s, _)) = l.accept() {
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    use std::io::Read as _;
                    s.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
                    let mut got = 0;
                    while got < buf.len() {
                        match s.read(&mut buf[got..]) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                got += n;
                                if buf[..got].ends_with(b"\r\n\r\n") { break; }
                            }
                        }
                    }
                    use std::io::Write as _;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                });
            }
        });
        let shared = crate::net::Shared::new();
        let cancel = AtomicBool::new(false);
        let good = GroupItem { tab: 0, host: "127.0.0.1".into(), port, https: false, request: get("/ok", port).into_bytes(), http2: false, websocket: false };
        // Nothing listens on this port: the connect fails fast.
        let bad_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let bad = GroupItem { tab: 1, host: "127.0.0.1".into(), port: bad_port, https: false, request: get("/bad", bad_port).into_bytes(), http2: false, websocket: false };
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let keep = got.clone();
        let end = run_parallel(&shared, &[good, bad], &cancel, move |n, r| keep.lock().unwrap().push((n, r)));
        assert_eq!(end, SequenceEnd::Completed);
        let got = got.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.iter().find(|(n, _)| *n == 0).is_some_and(|(_, r)| r.error.is_none() && r.response.is_some()));
        assert!(got.iter().find(|(n, _)| *n == 1).is_some_and(|(_, r)| r.error.is_some()));
    }

    fn get(path: &str, port: u16) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n")
    }

    #[test]
    fn sequence_on_one_connection_and_on_separate_ones() {
        let shared = Shared::new();
        let (port, log) = h1_lab();
        let items: Vec<GroupItem> = ["/a", "/b", "/c"].iter().enumerate().map(|(i, p)| item(i as u64, "127.0.0.1", port, &get(p, port))).collect();
        let cancel = AtomicBool::new(false);
        let mut got = Vec::new();
        // Keep-alive off for the project: the single connection still
        // carries all three (the request is sent as written).
        assert_eq!(run_sequence(&shared, &items, true, &cancel, |n, r| got.push((n, r))), SequenceEnd::Completed);
        assert_eq!(log.lock().unwrap().clone(), vec![(0, "GET /a HTTP/1.1".into()), (0, "GET /b HTTP/1.1".into()), (0, "GET /c HTTP/1.1".into())]);
        let bodies: Vec<String> = got.iter().map(|(_, r)| String::from_utf8_lossy(r.response.as_deref().unwrap()).rsplit("\r\n\r\n").next().unwrap().to_string()).collect();
        assert_eq!(bodies, vec!["conn0 GET /a HTTP/1.1", "conn0 GET /b HTTP/1.1", "conn0 GET /c HTTP/1.1"]);
        assert_eq!(got.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![0, 1, 2]);
        log.lock().unwrap().clear();
        assert_eq!(run_sequence(&shared, &items, false, &cancel, |_, _| {}), SequenceEnd::Completed);
        let conns: Vec<usize> = log.lock().unwrap().iter().map(|(c, _)| *c).collect();
        assert_eq!(conns, vec![1, 2, 3], "a new connection per request");
    }

    #[test]
    fn unknown_host_stops_the_sequence_other_errors_do_not() {
        let shared = Shared::new();
        let (port, log) = h1_lab();
        // A refused connection is recorded and the sequence goes on.
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let items = vec![item(1, "127.0.0.1", dead_port, &get("/x", dead_port)), item(2, "127.0.0.1", port, &get("/y", port))];
        let cancel = AtomicBool::new(false);
        let mut got = Vec::new();
        assert_eq!(run_sequence(&shared, &items, false, &cancel, |n, r| got.push((n, r.error.is_some()))), SequenceEnd::Completed);
        assert_eq!(got, vec![(0, true), (1, false)]);
        // An unknown host stops it: tab 2 is never sent.
        let items = vec![item(1, "no-such-host.invalid", 80, "GET / HTTP/1.1\r\nHost: no-such-host.invalid\r\n\r\n"), item(2, "127.0.0.1", port, &get("/z", port))];
        log.lock().unwrap().clear();
        let mut got = Vec::new();
        assert_eq!(run_sequence(&shared, &items, false, &cancel, |n, r| got.push((n, r.error))), SequenceEnd::UnknownHost(0));
        assert_eq!(got.len(), 1);
        assert!(log.lock().unwrap().is_empty());
        // Cancelled after the first response: the second never goes out.
        let items = vec![item(1, "127.0.0.1", port, &get("/p", port)), item(2, "127.0.0.1", port, &get("/q", port))];
        let cancel = AtomicBool::new(false);
        let end = run_sequence(&shared, &items, true, &cancel, |_, _| cancel.store(true, Ordering::SeqCst));
        assert_eq!(end, SequenceEnd::Cancelled(1));
        assert_eq!(log.lock().unwrap().iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>(), vec!["GET /p HTTP/1.1"]);
    }
}
