//! The active scanner's run state (N-07): one scan at a time, claimed and
//! released only through [`ScanGuard`], with idle waits that block on a
//! condition variable instead of polling.

use crate::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar};
use std::time::{Duration, Instant};

/// Bounded per-URL DOM operation result exposed in the scan record.
#[derive(Clone, Debug)]
pub struct DomScanRecord {
    pub url: String,
    pub complete: bool,
    pub cancelled: bool,
    pub proven_hits: Vec<webprobe_support::dedup::DomHit>,
    pub diagnostic: String,
}

#[derive(Default)]
pub struct ScanRun {
    busy: Mutex<bool>,
    pub dom_outcomes: Mutex<Vec<DomScanRecord>>,
    idle: Condvar,
    /// Stop the running scan at the next check.
    pub stop: AtomicBool,
    /// Scanner requests wait while this is set (a paused task).
    pub paused: AtomicBool,
    /// Progress: requests planned and done.
    pub total: AtomicUsize,
    pub done: AtomicUsize,
    /// The last active scan was started outside the task queue (the selftest
    /// hook, the headless runner); the Dashboard shows it as its own card.
    pub direct: AtomicBool,
    /// Id of the task being run, 0 when none.
    pub running_task: AtomicU64,
    /// While a caller collects (the REST API's scan task), every issue the
    /// scanner itself raises is copied here: the process-wide issue list is
    /// shared with the live proxy audit and manual findings, so a position
    /// in it does not say who raised an issue.
    collected: Mutex<Option<Vec<webprobe_support::issues::ScanIssue>>>,
}

/// Bound on one task's collected issues.
const MAX_COLLECTED: usize = 10_000;

impl ScanRun {
    /// Start collecting the scanner's own issues (drops an earlier set).
    pub fn begin_collect(&self) {
        *self.collected.lock() = Some(Vec::new());
    }

    /// Copy issues the scanner raised into the active collection, if any.
    pub fn collect(&self, issues: &[webprobe_support::issues::ScanIssue]) {
        if let Some(set) = self.collected.lock().as_mut() {
            let room = MAX_COLLECTED.saturating_sub(set.len());
            set.extend(issues.iter().take(room).cloned());
        }
    }

    /// What has been collected so far.
    pub fn collected(&self) -> Vec<webprobe_support::issues::ScanIssue> {
        self.collected.lock().clone().unwrap_or_default()
    }

    /// Stop collecting and hand over the set.
    pub fn end_collect(&self) -> Vec<webprobe_support::issues::ScanIssue> {
        self.collected.lock().take().unwrap_or_default()
    }

    pub fn record_dom(&self, mut record: DomScanRecord) {
        record.url = record.url.chars().take(500).collect();
        record.diagnostic = record.diagnostic.chars().take(500).collect();
        record.proven_hits.truncate(50);
        let mut records = self.dom_outcomes.lock();
        if let Some(old) = records.iter_mut().find(|r| r.url == record.url) {
            *old = record;
        } else if records.len() < 100 {
            records.push(record);
        }
    }
    pub fn is_busy(&self) -> bool {
        *self.busy.lock()
    }

    /// Block until no scan runs, or until `timeout` passes. True when idle.
    pub fn wait_idle(&self, timeout: Option<Duration>) -> bool {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut busy = self.busy.lock();
        while *busy {
            match deadline {
                None => busy = self.idle.wait(busy).unwrap_or_else(|p| p.into_inner()),
                Some(d) => {
                    let left = d.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return false;
                    }
                    busy = self
                        .idle
                        .wait_timeout(busy, left)
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
            }
        }
        true
    }

    fn claim(&self) -> bool {
        let mut busy = self.busy.lock();
        if *busy {
            return false;
        }
        *busy = true;
        self.dom_outcomes.lock().clear();
        true
    }

    fn release(&self) {
        // The planned total assumes every check runs; settle it at the end.
        self.total
            .store(self.done.load(Ordering::SeqCst), Ordering::SeqCst);
        *self.busy.lock() = false;
        self.idle.notify_all();
    }
}

/// Holds the scanner; dropping it (however the scan ends, a panic included)
/// releases it and wakes everyone waiting for idle.
pub struct ScanGuard {
    scan: Arc<ScanRun>,
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        self.scan.release();
    }
}

/// Claim the scanner, or `None` when a scan is already running.
pub fn try_claim(scan: &Arc<ScanRun>) -> Option<ScanGuard> {
    scan.claim().then(|| ScanGuard {
        scan: Arc::clone(scan),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_claim_at_a_time_and_idle_waits_wake() {
        let scan = Arc::new(ScanRun::default());
        let g = try_claim(&scan).expect("first claim");
        assert!(try_claim(&scan).is_none(), "second claim refused");
        assert!(scan.is_busy());
        assert!(
            !scan.wait_idle(Some(Duration::from_millis(50))),
            "still busy"
        );
        let s2 = Arc::clone(&scan);
        let waiter = std::thread::spawn(move || s2.wait_idle(Some(Duration::from_secs(10))));
        std::thread::sleep(Duration::from_millis(50));
        scan.done.store(7, Ordering::SeqCst);
        drop(g);
        assert!(waiter.join().unwrap(), "waiter woken by the release");
        assert_eq!(scan.total.load(Ordering::SeqCst), 7, "total settled");
        // Released by a panic too.
        let s3 = Arc::clone(&scan);
        let _ = std::thread::spawn(move || {
            let _g = try_claim(&s3).unwrap();
            panic!("check failed");
        })
        .join();
        assert!(!scan.is_busy());
    }
}
