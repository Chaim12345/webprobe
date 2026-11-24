// Split from net.rs (L5, issue #35): net is now a module directory.

use crate::sync::Mutex;
use crate::util;
/// One captured WebSocket frame or handshake record.
pub use crate::ws_history::WsEntry;

// Marker parsing moved to intruder (L8, #38); keep the old net path working.
pub use crate::intruder::{MarkerSeg, parse_markers};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

thread_local! {
    /// Set while a session rule is itself sending (a macro, a validation
    /// request), so those requests do not trigger the rules again.
    static IN_SESSION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

thread_local! {
    static H2_CHOICE: std::cell::Cell<Option<Http2Choice>> = const { std::cell::Cell::new(None) };
    /// The last upstream HTTP/1 exchange on this thread read a complete,
    /// self-delimited response with nothing left over (the authoritative
    /// `read_message` outcome). False until an exchange proves it.
    static LAST_EXCHANGE_REUSABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LAST_PROTOCOL: std::cell::Cell<&'static str> = const { std::cell::Cell::new("HTTP/1.1") };
}

thread_local! {
    static TOOL: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

thread_local! {
    /// Port of the listener the connection on this thread arrived on.
    static LISTENER_PORT: std::cell::Cell<Option<u16>> = const { std::cell::Cell::new(None) };
}

mod types;
pub use types::*;

mod match_replace;
pub use match_replace::*;

mod session;
pub use session::*;

mod scope_rules;
pub use scope_rules::*;

mod shared;
pub use shared::*;

mod http_io;
pub use http_io::*;

mod upstream_conn;
pub use upstream_conn::*;

mod hist;
pub use hist::*;

mod scan_hooks;
mod send;
pub use scan_hooks::*;
pub use send::*;

pub use webprobe_support::io_traits::*;

mod conn_reuse;
pub use conn_reuse::*;

mod tool_log;
pub use tool_log::*;
mod tool_state;
pub use tool_state::*;

mod accept_wait;
mod engine;
pub use engine::*;
mod ext_source;
pub use ext_source::*;

mod url_helpers;
pub use url_helpers::*;

mod intercept;
pub use intercept::*;

mod ws;
pub use ws::*;

mod tls_client;
pub use tls_client::*;

mod attack;
mod sni;
pub use attack::*;
#[cfg(test)]
pub(crate) use sni::tls_sni_lab;
pub use sni::{SniScope, sni_scope};

#[cfg(test)]
mod intercept_all_tests;

#[cfg(test)]
mod conn_reuse_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod tool_log_tests;

#[cfg(test)]
mod cookie_jar_tests;

#[cfg(test)]
mod session_rule_tests;

#[cfg(test)]
mod read_request_tests;

#[cfg(test)]
mod read_response_head_tests;

#[cfg(test)]
mod wake_tests;

#[cfg(test)]
mod replay_safety_tests;

#[cfg(test)]
mod url_scope_tests;

#[cfg(test)]
mod hist_tests;

#[cfg(test)]
mod tool_state_tests;

/// Experimental inherited-context seam only. No production send policy changes.
/// Wrappers check status without charging: transport accounting is a separate
/// unified patch, and this seam is not evidence of byte/attempt limits.
#[cfg(test)]
pub(crate) fn scanner_send_admission(shared: &Shared) -> Result<(), String> {
    use crate::scan_lifecycle::{ExecutionContext, captured};
    let inherited = captured();
    // TOOL is a display/session label, not experimental admission evidence.
    // Unmigrated production callers retain legacy behavior in cfg(test) builds.
    // Migrated callers must carry the explicit expected-scanner marker.
    if inherited.is_none() && !scanner_io::expected() {
        return Ok(());
    }
    let context = inherited.ok_or("scanner execution context missing")?;
    loop {
        context
            .validate(shared)
            .map_err(|_| "scanner execution context cancelled, stale or mismatched")?;
        if let ExecutionContext::Budgeted(permit) = &context {
            permit
                .ledger()
                .reserve(&[])
                .map_err(|_| "scanner execution ledger denied")?;
        }
        if !shared.scan.paused.load(Ordering::SeqCst) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[cfg(test)]
mod inherited_context_tests;

#[cfg(test)]
pub(crate) mod scanner_io;
