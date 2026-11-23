// Per-scan-run dedup sets (issue #38), moved from core scan::state so
// net::Shared can hold them without naming scan. Owned by the scan and
// fresh by construction: crawl_and_audit swaps a new one in at run start.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex as StdMutex};

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
    /// Chromium budget for dynamic DOM analysis in this run. Fresh with
    /// the run, so a new run gets the full budget again.
    pub dom_budget: DomRunBudget,
}

impl ScanDedup {
    /// A fresh DOM run: drop the per-URL probe cache and reset the
    /// browser budget. Used where a new run keeps the same ScanDedup
    /// (standalone scans); crawl runs get a new ScanDedup instead.
    pub fn reset_dom(&self) {
        self.dom_hits.lock().unwrap().clear();
        self.dom_budget.reset();
    }
}

/// Browsers allowed to run at once for DOM analysis in one scan run.
pub const DOM_MAX_CONCURRENT_BROWSERS: usize = 2;
/// Browser navigations allowed in one scan run. Each navigation takes
/// seconds; the cap keeps dynamic analysis a bounded part of a scan.
pub const DOM_MAX_PROBES_PER_RUN: usize = 100;

/// Per-run Chromium budget for dynamic DOM analysis. Fail-closed: when
/// the navigation budget is spent, probes report no hits and spawn no
/// browser. The concurrency cap makes a caller wait (checking the scan
/// stop flag) until a browser slot frees up.
#[derive(Debug)]
pub struct DomRunBudget {
    max_concurrent: usize,
    max_probes: usize,
    slots: StdMutex<usize>,
    slot_free: Condvar,
    probes_spent: AtomicUsize,
}

impl Default for DomRunBudget {
    fn default() -> Self {
        Self::with_limits(DOM_MAX_CONCURRENT_BROWSERS, DOM_MAX_PROBES_PER_RUN)
    }
}

/// A held browser slot; releases back to the budget on drop.
pub struct DomBrowserPermit<'a> {
    budget: &'a DomRunBudget,
}

impl Drop for DomBrowserPermit<'_> {
    fn drop(&mut self) {
        let mut slots = self.budget.slots.lock().unwrap();
        *slots = slots.saturating_sub(1);
        drop(slots);
        self.budget.slot_free.notify_one();
    }
}

impl DomRunBudget {
    pub fn with_limits(max_concurrent: usize, max_probes: usize) -> Self {
        Self {
            max_concurrent,
            max_probes,
            slots: StdMutex::new(0),
            slot_free: Condvar::new(),
            probes_spent: AtomicUsize::new(0),
        }
    }

    /// One browser navigation, counted against the run. False when the
    /// run's navigation budget is already spent: the caller skips the
    /// probe entirely (fail-closed, no browser launched).
    pub fn spend_probe(&self) -> bool {
        self.probes_spent.fetch_add(1, Ordering::SeqCst) < self.max_probes
    }

    /// A browser slot, waiting (in bounded slices so a scan stop is seen)
    /// while `max_concurrent` browsers are already running. `stopped` is
    /// the scan's stop flag; None means give up without spawning.
    pub fn acquire_browser(&self, stopped: &dyn Fn() -> bool) -> Option<DomBrowserPermit<'_>> {
        let mut slots = self.slots.lock().unwrap();
        loop {
            if stopped() {
                return None;
            }
            if *slots < self.max_concurrent {
                *slots += 1;
                return Some(DomBrowserPermit { budget: self });
            }
            let (guard, _) = self
                .slot_free
                .wait_timeout(slots, std::time::Duration::from_millis(200))
                .unwrap();
            slots = guard;
        }
    }

    fn reset(&self) {
        self.probes_spent.store(0, Ordering::SeqCst);
    }
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

/// One URL's dynamic DOM-analysis outcome for this run: the source-to-sink
/// hits, the reflected-variant query token (`Some` only when the server
/// contains the query token in script text of the fulfilled navigation
/// response; this does not prove a string-literal data flow), and
/// the stored token submitted before the probe (a hit holding it came from
/// application-stored content: the stored variant).
#[derive(Clone, Debug, Default)]
pub struct DomProbeOutcome {
    pub hits: Vec<DomHit>,
    pub reflected: Option<String>,
    pub stored: String,
}

pub type DomCache =
    std::collections::HashMap<String, std::sync::Arc<std::sync::OnceLock<DomProbeOutcome>>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dom_budget_spends_up_to_the_run_limit() {
        let b = DomRunBudget::with_limits(2, 3);
        assert!(b.spend_probe());
        assert!(b.spend_probe());
        assert!(b.spend_probe());
        assert!(!b.spend_probe(), "fourth probe is over budget");
    }

    #[test]
    fn dom_budget_slots_release_on_drop_and_stop_wins() {
        let b = DomRunBudget::with_limits(1, 10);
        let p = b.acquire_browser(&|| false).expect("first slot");
        assert!(b.acquire_browser(&|| true).is_none(), "stop flag wins");
        drop(p);
        assert!(b.acquire_browser(&|| false).is_some(), "slot came back");
    }

    #[test]
    fn dom_budget_reset_restores_the_probe_allowance() {
        let b = DomRunBudget::with_limits(1, 1);
        assert!(b.spend_probe());
        assert!(!b.spend_probe());
        b.reset();
        assert!(b.spend_probe());
    }
}
