// Per-scan-run state (issue #38): the once-per-host(-and-session) dedup
// sets the active checks share. Owned by the scan and fresh by
// construction: crawl_and_audit swaps a new one in at run start, which
// replaces the hand-reset OnceLock statics (reset_openapi_hosts).

use std::collections::HashSet;
use std::sync::Arc;

use crate::net::Shared;
use crate::sync::Mutex;

/// Dedup sets the active checks share for one scan run (and, until the
/// next run starts, the session: standalone audits of an already-probed
/// host stay quiet, matching the old statics).
#[derive(Default)]
pub struct ScanDedup {
    /// Hosts already probed by the per-host OpenAPI check (Burp runs APH_
    /// checks once per host).
    pub openapi_hosts: Mutex<HashSet<String>>,
    /// Hosts already probed by the collaborator-everywhere check
    /// (burp.Zc7h, once per host).
    pub everywhere_hosts: Mutex<HashSet<String>>,
}

/// The run's current state: the one swapped in when the latest scan run
/// started (Shared::new's until then).
pub fn scan_dedup_of(shared: &Shared) -> Arc<ScanDedup> {
    Arc::clone(&shared.scan_state.lock().unwrap())
}
