//! R-12 "Send group in sequence (single connection)" over HTTP/2: one TLS
//! connection, one preface, then the group's requests on client streams
//! 1, 3, 5... in tab order (burp.Zx_o over the group's shared h2
//! connection). HTTP/1 groups and per-connection sending live in
//! `send_group`; only the h2 single-connection walk is here.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::h2;
use crate::net::Shared;
use crate::send_group::{self, GroupItem, GroupResult, SequenceEnd};

/// Send every item over one h2 connection, in order. Opens the connection
/// on the first item's target (single-connection groups pass validation
/// only when every item shares it).
pub fn run_single_connection(shared: &Shared, items: &[GroupItem], cancel: &AtomicBool, mut on_result: impl FnMut(usize, GroupResult)) -> SequenceEnd {
    let Some(first) = items.first() else { return SequenceEnd::Completed };
    let mut conn = match send_group::open_conn(shared, first) {
        Ok(c) => c,
        Err(e) => {
            let up = crate::net::Upstream { resp: None, error: Some(e) };
            on_result(0, GroupResult::from_up(Vec::new(), up, "HTTP/2", 0));
            return SequenceEnd::Cancelled(0);
        }
    };
    if let Err(e) = h2::send_preface(&mut conn) {
        let up = crate::net::Upstream { resp: None, error: Some(e) };
        on_result(0, GroupResult::from_up(Vec::new(), up, "HTTP/2", 0));
        return SequenceEnd::Cancelled(0);
    }
    for (n, item) in items.iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            return SequenceEnd::Cancelled(n);
        }
        let sid = 2 * n as u32 + 1;
        let t0 = std::time::Instant::now();
        let (sent, up) = send_group::hooked(shared, item, |request| {
            let req = h2::request_from_raw(request, "https").ok_or_else(|| "the request is not a valid HTTP request".to_string())?;
            h2::exchange_on(&mut conn, sid, &req, None)
        });
        let stop = up.error.as_deref().is_some_and(send_group::unknown_host);
        on_result(n, GroupResult::from_up(sent, up, "HTTP/2", t0.elapsed().as_millis()));
        if stop {
            return SequenceEnd::UnknownHost(n);
        }
    }
    SequenceEnd::Completed
}
