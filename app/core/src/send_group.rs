//! Repeater tab groups and "Send group" (R-12).
//!
//! The model follows Burp's (burp.Zisp: name, colour, members; burp.Zfla
//! keeps a group's tabs side by side; burp.Zs1q picks the colour). Sending
//! follows burp.Zxnu: the three modes of burp.Zsmu, checked first against
//! the problems of burp.Zr4d (the group is refused with all of them), then
//! sent in sequence by burp.Zx_o over one connection or one connection per
//! request (send-group.html "Sending requests in sequence").

use std::sync::atomic::{AtomicBool, Ordering};

use crate::net::{self, Shared, Upstream, UpstreamConn};

/// The number of group colours (burp.Zxpb GROUP_0 .. GROUP_14).
pub const GROUP_COLOURS: u8 = 15;

/// One Repeater tab group. `tabs` lists member tab ids; their order is the
/// order of the tabs in the tab bar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepGroup {
    pub id: u64,
    pub name: String,
    /// burp.Zxpb id, 0..GROUP_COLOURS.
    pub colour: u8,
    pub tabs: Vec<u64>,
}

/// burp.Zs1q.ZF: the first colour no group uses; when all are taken, the
/// one after the last group's (burp.Zxpb.ZF wraps).
pub fn next_colour(groups: &[RepGroup]) -> u8 {
    (0..GROUP_COLOURS)
        .find(|c| !groups.iter().any(|g| g.colour == *c))
        .unwrap_or_else(|| groups.last().map_or(0, |g| (g.colour + 1) % GROUP_COLOURS))
}

/// burp.Zg52: Create is enabled with a non-blank name and at least one tab.
pub fn can_create(name: &str, tabs: &[u64]) -> bool {
    !name.trim().is_empty() && !tabs.is_empty()
}

/// The group `tab` belongs to (a tab is in at most one group).
pub fn group_of(groups: &[RepGroup], tab: u64) -> Option<&RepGroup> {
    groups.iter().find(|g| g.tabs.contains(&tab))
}

/// Create a group of `members` (tab ids, in any order): they leave any
/// group they were in, and move next to the first of them in the tab bar
/// (burp.Zfla.Zx). `order` is the tab bar (tab ids in order). Returns the
/// new group's id, None when [`can_create`] says no.
pub fn create_group(groups: &mut Vec<RepGroup>, order: &mut Vec<u64>, id: u64, name: &str, colour: u8, members: &[u64]) -> Option<u64> {
    let members: Vec<u64> = order.iter().copied().filter(|t| members.contains(t)).collect();
    if !can_create(name, &members) {
        return None;
    }
    for g in groups.iter_mut() {
        g.tabs.retain(|t| !members.contains(t));
    }
    groups.retain(|g| !g.tabs.is_empty());
    groups.push(RepGroup { id, name: name.trim().to_string(), colour: colour % GROUP_COLOURS, tabs: members });
    gather(groups, order, id);
    Some(id)
}

/// Add `tab` to group `group` (leaving its old group), placed after the
/// group's last tab.
pub fn add_to_group(groups: &mut Vec<RepGroup>, order: &mut Vec<u64>, group: u64, tab: u64) {
    if !order.contains(&tab) || !groups.iter().any(|g| g.id == group) {
        return;
    }
    remove_from_group(groups, tab);
    if let Some(g) = groups.iter_mut().find(|g| g.id == group) {
        g.tabs.push(tab);
    }
    gather(groups, order, group);
}

/// "Remove tab from group"; a group left without tabs is gone
/// (groups.html).
pub fn remove_from_group(groups: &mut Vec<RepGroup>, tab: u64) {
    for g in groups.iter_mut() {
        g.tabs.retain(|t| *t != tab);
    }
    groups.retain(|g| !g.tabs.is_empty());
}

/// "Ungroup tabs": the group goes, its tabs stay open.
pub fn ungroup(groups: &mut Vec<RepGroup>, group: u64) {
    groups.retain(|g| g.id != group);
}

/// "Close all tabs in group" (burp.Zio9; groups.html "Delete entire
/// group"): the group goes and its tab ids are returned for closing.
pub fn delete_group(groups: &mut Vec<RepGroup>, group: u64) -> Vec<u64> {
    let tabs = groups.iter().find(|g| g.id == group).map(|g| g.tabs.clone()).unwrap_or_default();
    ungroup(groups, group);
    tabs
}

/// Edit a group's name and colour (burp.Zu_x edit dialog). A blank name
/// is refused.
pub fn edit_group(groups: &mut [RepGroup], group: u64, name: &str, colour: u8) -> bool {
    match groups.iter_mut().find(|g| g.id == group) {
        Some(g) if !name.trim().is_empty() => {
            g.name = name.trim().to_string();
            g.colour = colour % GROUP_COLOURS;
            true
        }
        _ => false,
    }
}

/// Bring the tabs of `group` together in the tab bar at the place of its
/// first tab, keeping their relative order (burp.Zfla.Zx), and make the
/// member list follow the tab bar.
pub fn gather(groups: &mut [RepGroup], order: &mut Vec<u64>, group: u64) {
    let Some(g) = groups.iter_mut().find(|g| g.id == group) else { return };
    let Some(at) = order.iter().position(|t| g.tabs.contains(t)) else { return };
    // Members in their place order first, then any not yet placed in the
    // order they were added.
    let mut members: Vec<u64> = order.iter().copied().filter(|t| g.tabs.contains(t)).collect();
    members.sort_by_key(|t| g.tabs.iter().position(|x| x == t));
    let before = order[..at].iter().filter(|t| !members.contains(t)).count();
    order.retain(|t| !members.contains(t));
    let at = before.min(order.len());
    order.splice(at..at, members.iter().copied());
    g.tabs = members;
}

/// Drop tabs that no longer exist and groups left empty; member lists
/// follow the tab bar order.
pub fn prune(groups: &mut Vec<RepGroup>, order: &[u64]) {
    for g in groups.iter_mut() {
        g.tabs = order.iter().copied().filter(|t| g.tabs.contains(t)).collect();
    }
    groups.retain(|g| !g.tabs.is_empty());
}

/// Groups as saved in a project: members are indices into the saved tab
/// list, because tab ids are fresh on every load.
pub fn to_project(groups: &[RepGroup], order: &[u64]) -> Vec<crate::project::ProjectRepeaterGroup> {
    groups
        .iter()
        .map(|g| crate::project::ProjectRepeaterGroup {
            name: g.name.clone(),
            colour: g.colour,
            tabs: g.tabs.iter().filter_map(|t| order.iter().position(|o| o == t)).collect(),
        })
        .filter(|g| !g.tabs.is_empty())
        .collect()
}

/// Groups of a loaded project over the loaded tabs' fresh ids (`order`).
/// Indices out of range and tabs already in an earlier group are dropped.
pub fn from_project(saved: &[crate::project::ProjectRepeaterGroup], order: &[u64], mut next_id: impl FnMut() -> u64) -> Vec<RepGroup> {
    let mut out: Vec<RepGroup> = Vec::new();
    for s in saved {
        let tabs: Vec<u64> = s.tabs.iter().filter_map(|i| order.get(*i).copied()).filter(|t| group_of(&out, *t).is_none()).collect();
        if !tabs.is_empty() && !s.name.trim().is_empty() {
            out.push(RepGroup { id: next_id(), name: s.name.clone(), colour: s.colour % GROUP_COLOURS, tabs });
        }
    }
    out
}

// ---------------------------------------------------------------- sending

/// burp.Zsmu: how a group is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupMode {
    /// SEND_ON_SINGLE_CONNECTION: "Send group in sequence (single connection)".
    SingleConnection,
    /// SEND_SEQUENCE: "Send group in sequence (separate connections)".
    Separate,
    /// SEND_PARALLEL: "Send group in parallel".
    Parallel,
}

impl GroupMode {
    pub fn label(self) -> &'static str {
        match self {
            GroupMode::SingleConnection => "Send group in sequence (single connection)",
            GroupMode::Separate => "Send group in sequence (separate connections)",
            GroupMode::Parallel => "Send group in parallel",
        }
    }
}

/// One tab of a group as sent: its target and request at send time.
#[derive(Clone, Debug)]
pub struct GroupItem {
    pub tab: u64,
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub request: Vec<u8>,
    /// The tab sends over HTTP/2 (only over TLS).
    pub http2: bool,
    /// A WebSocket Repeater tab.
    pub websocket: bool,
}

/// burp.Zr4d: why a group cannot be sent in a mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    EmptyRequest,
    TargetMissing,
    WebSocketTab,
    ServiceMismatch,
    ProtocolMismatch,
    Http1KeepAlive,
}

impl Problem {
    /// The explanation shown in the "Cannot send group" dialog (burp.Ze17).
    pub fn text(self) -> &'static str {
        match self {
            Problem::EmptyRequest => "There are empty tabs in this group",
            Problem::TargetMissing => "You have not specified a target for one or more requests in this group",
            Problem::WebSocketTab => "There are WebSocket tabs in this group",
            Problem::ServiceMismatch => "The selected target is not the same for all requests in this group",
            Problem::ProtocolMismatch => "The selected protocol (HTTP/1 or HTTP/2) is not the same for all requests in this group",
            Problem::Http1KeepAlive => "HTTP/1 connection reuse is enabled for one or more requests in this group",
        }
    }

    /// The modes it applies to (burp.Zr4d constructor lists).
    fn applies(self, mode: GroupMode) -> bool {
        use GroupMode::*;
        match self {
            Problem::EmptyRequest | Problem::WebSocketTab => true,
            Problem::TargetMissing => mode == Separate,
            Problem::ServiceMismatch | Problem::ProtocolMismatch => mode != Separate,
            Problem::Http1KeepAlive => mode == Parallel,
        }
    }
}

/// burp.Zh87 / Zw1s: every problem that stops `items` being sent in
/// `mode`; empty = the group can go. `keep_alive`: the project's HTTP/1
/// keep-alive (Burp's per-request connection reuse).
pub fn validate(mode: GroupMode, items: &[GroupItem], keep_alive: bool) -> Vec<Problem> {
    let mut out = Vec::new();
    let mut add = |p: Problem, hit: bool| {
        if hit && p.applies(mode) && !out.contains(&p) {
            out.push(p);
        }
    };
    add(Problem::EmptyRequest, items.iter().any(|i| !i.websocket && i.request.iter().all(u8::is_ascii_whitespace)));
    add(Problem::TargetMissing, items.iter().any(|i| i.host.trim().is_empty() || i.port == 0));
    add(Problem::WebSocketTab, items.iter().any(|i| i.websocket));
    let service = |i: &GroupItem| (i.host.to_ascii_lowercase(), i.port, i.https);
    add(Problem::ServiceMismatch, items.windows(2).any(|w| service(&w[0]) != service(&w[1])));
    add(Problem::ProtocolMismatch, items.windows(2).any(|w| w[0].http2 != w[1].http2));
    add(Problem::Http1KeepAlive, keep_alive && items.iter().any(|i| !i.http2));
    out
}

/// What one tab got.
#[derive(Clone, Debug, Default)]
pub struct GroupResult {
    /// The request as it went out (cookie jar, session rules applied).
    pub sent: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub error: Option<String>,
    /// "HTTP/1.1" or "HTTP/2".
    pub protocol: &'static str,
    pub elapsed_ms: u128,
    /// Parallel over HTTP/2: this response's place among the group's
    /// responses, by arrival of its first frame, and the count
    /// (burp.Zglm.processHttpRequestResults: "%d/%d").
    pub arrival: Option<(usize, usize)>,
}

impl GroupResult {
    pub(crate) fn from_up(sent: Vec<u8>, up: Upstream, protocol: &'static str, elapsed_ms: u128) -> GroupResult {
        GroupResult { sent, response: up.resp, error: up.error, protocol, elapsed_ms, arrival: None }
    }
}

/// How a sequence ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceEnd {
    /// Every tab was sent.
    Completed,
    /// Stopped after tab `n` (0-based) because its host is unknown
    /// (burp.Zrp4.Zh: UnknownHostException returns false and Zx_o stops).
    UnknownHost(usize),
    /// Cancelled before tab `n` was sent (burp.Zx_o.ZN).
    Cancelled(usize),
}

/// The error of a failed name lookup (net::resolve), Burp's UnknownHostException.
pub(crate) fn unknown_host(error: &str) -> bool {
    error.starts_with("dns ") && !error.contains("timed out")
}

/// The cookie jar and session rules around one exchange, and the tool log,
/// as every other sender does (net::send_raw_with).
pub(crate) fn hooked(shared: &Shared, item: &GroupItem, send: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>) -> (Vec<u8>, Upstream) {
    let request = net::jar_request(shared, &item.host, item.https, &item.request);
    let request = net::session_request(shared, item.port, item.https, request).into_owned();
    let up = match send(&request) {
        Ok(resp) => Upstream { resp: Some(resp), error: None },
        Err(e) => Upstream { resp: None, error: Some(e) },
    };
    net::jar_response(shared, &item.host, &request, &up);
    net::session_after(shared, &item.host);
    net::log_tool_exchange(shared, &item.host, item.port, item.https, &request, &up);
    (request, up)
}

/// Open a connection of its own to the item's target (through the
/// upstream proxy when one serves it); over TLS, ALPN offers only the
/// item's protocol.
pub(crate) fn open_conn(shared: &Shared, item: &GroupItem) -> Result<UpstreamConn, String> {
    let config = shared.upstream_for(&item.host);
    shared.conns_opened.fetch_add(1, Ordering::SeqCst);
    if !item.https {
        let tcp = crate::upstream::connect_target(&config, &item.host, item.port)?;
        tcp.set_read_timeout(Some(std::time::Duration::from_millis(net::READ_TIMEOUT_MS))).ok();
        return Ok(UpstreamConn::Plain(tcp));
    }
    let tcp = crate::upstream::connect_tls_target(&config, &item.host, item.port)?;
    tcp.set_read_timeout(Some(std::time::Duration::from_millis(net::READ_TIMEOUT_MS))).ok();
    let mut cfg = (*net::tls_client_config_base(shared, &item.host)).clone();
    cfg.alpn_protocols = vec![if item.http2 { b"h2".to_vec() } else { b"http/1.1".to_vec() }];
    let name = rustls::pki_types::ServerName::try_from(item.host.clone()).map_err(|e| format!("invalid upstream TLS name {}: {e}", item.host))?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(cfg), name).map_err(|e| format!("configure upstream TLS: {e}"))?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).map_err(|e| format!("TLS handshake: {e}"))?;
    }
    if item.http2 && tls.conn.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err("the server did not agree to HTTP/2 (ALPN); switch the request to HTTP/1".into());
    }
    Ok(UpstreamConn::Tls(Box::new(tls)))
}

/// The HTTP/1 request line form the connection needs: origin form, or
/// absolute form through a plain upstream HTTP proxy; a request shown as
/// HTTP/2 goes out as HTTP/1.1.
fn http1_wire(shared: &Shared, item: &GroupItem, request: &[u8]) -> Vec<u8> {
    let req = net::as_http1(request).into_owned();
    let req = crate::util::origin_form(&req);
    if item.https {
        req
    } else {
        crate::upstream::absolute_form_request(&shared.upstream_for(&item.host), &req, &item.host, item.port)
    }
}

/// One HTTP/2 request on a connection of its own.
fn h2_on(conn: &mut UpstreamConn, request: &[u8]) -> Result<Vec<u8>, String> {
    let h2req = crate::h2::request_from_raw(request, "https").ok_or("h2: request without Host header")?;
    match conn {
        UpstreamConn::Tls(tls) => crate::h2::exchange(tls.as_mut(), &h2req, None),
        UpstreamConn::Plain(_) => Err("h2: not a TLS connection".into()),
    }
}

/// Send `items` in tab order, one after another (burp.Zx_o.run): over one
/// connection opened for the group and closed at the end (`single`), or
/// over a new connection per request. `on_result` gets each tab's result
/// as it completes. A tab whose host is unknown stops the sequence
/// (burp.Zrp4.Zh returns false); other failures are recorded on the tab
/// and the sequence goes on. `cancel` is checked before each request.
/// Validate first ([`validate`]): this sends what it is given.
pub fn run_sequence(shared: &Shared, items: &[GroupItem], single: bool, cancel: &AtomicBool, mut on_result: impl FnMut(usize, GroupResult)) -> SequenceEnd {
    if single && items.first().is_some_and(|i| i.http2 && i.https) {
        return crate::h2_group::run_single_connection(shared, items, cancel, on_result);
    }
    let mut shared_conn: Option<Result<UpstreamConn, String>> = None;
    for (n, item) in items.iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            return SequenceEnd::Cancelled(n);
        }
        let t0 = std::time::Instant::now();
        let h2 = item.http2 && item.https;
        let (sent, up) = hooked(shared, item, |request| {
            if single {
                // The group's connection, opened by its first request.
                let conn = shared_conn.get_or_insert_with(|| open_conn(shared, item));
                let conn = conn.as_mut().map_err(|e| e.clone())?;
                let (resp, reusable) = net::exchange(conn, &http1_wire(shared, item, request), None)?;
                if !reusable {
                    // The server ended the connection: the rest of the
                    // group has none to go over.
                    shared_conn = Some(Err("the server closed the group's connection".into()));
                }
                Ok(resp)
            } else {
                let mut conn = open_conn(shared, item)?;
                if h2 {
                    h2_on(&mut conn, request)
                } else {
                    net::exchange(&mut conn, &http1_wire(shared, item, request), None).map(|(r, _)| r)
                }
            }
        });
        let stop = up.error.as_deref().is_some_and(unknown_host);
        on_result(n, GroupResult::from_up(sent, up, if h2 { "HTTP/2" } else { "HTTP/1.1" }, t0.elapsed().as_millis()));
        if stop {
            return SequenceEnd::UnknownHost(n);
        }
    }
    SequenceEnd::Completed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

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
        let all: Vec<RepGroup> = (0..GROUP_COLOURS).map(|c| group(c as u64, c, &[c as u64])).collect();
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
