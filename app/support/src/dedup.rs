// Per-scan-run dedup sets (issue #38), moved from core scan::state so
// net::Shared can hold them without naming scan. Owned by the scan and
// fresh by construction: crawl_and_audit swaps a new one in at run start.

use std::collections::HashSet;

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
    /// Dynamic DOM results belong to this scan run, not a process global.
    pub dom_hits: Mutex<DomCache>,
}

/// One dynamic DOM-analysis hit: a source value reached a sink (the
/// scanner's dynamic result record, burp.Zcwh's fields, first slice).
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomHit {
    pub source: String,
    pub sink: String,
    pub source_value: String,
    pub sink_value: String,
    /// location.href where the sink ran: the instrumentation also fires on
    /// the browser's own error pages (an empty/invalid response navigates
    /// to chrome-error://chromewebdata/, whose scripts run wrapped sinks);
    /// callers keep only hits on the target origin.
    pub page_url: String,
}

pub type DomCache =
    std::collections::HashMap<String, std::sync::Arc<std::sync::OnceLock<Vec<DomHit>>>>;
