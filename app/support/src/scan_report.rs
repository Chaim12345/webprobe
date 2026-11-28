//! Per-run, append-only scanner events and completion diagnostics.
//!
//! A report is explicitly installed on the crawl thread and inherited by
//! the active-scan worker. Unrelated proxy, UI and extension activity does
//! not share that thread-local owner and cannot contaminate the report.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use crate::issues::ScanIssue;

const MAX_EVENTS: usize = 10_000;

#[derive(Default)]
struct ReportState {
    events: Vec<ScanIssue>,
    failure: Option<String>,
}

#[derive(Default)]
pub struct ScanReport(Mutex<ReportState>);

impl ScanReport {
    /// Immutable snapshots of events in their original emission order.
    pub fn events(&self) -> Vec<ScanIssue> {
        self.0.lock().unwrap().events.clone()
    }

    /// The first reason the run could not complete, if any.
    pub fn failure(&self) -> Option<String> {
        self.0.lock().unwrap().failure.clone()
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Arc<ScanReport>>> = const { RefCell::new(None) };
}

/// Installs a report for this thread until the guard is dropped.
pub fn install(report: Option<Arc<ScanReport>>) -> ReportGuard {
    ReportGuard(CURRENT.with(|slot| slot.replace(report)))
}

pub struct ReportGuard(Option<Arc<ScanReport>>);

impl Drop for ReportGuard {
    fn drop(&mut self) {
        CURRENT.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}

pub fn current() -> Option<Arc<ScanReport>> {
    CURRENT.with(|slot| slot.borrow().clone())
}

pub fn record(issue: &ScanIssue) {
    if let Some(report) = current() {
        let mut state = report.0.lock().unwrap();
        if state.events.len() < MAX_EVENTS {
            state.events.push(issue.clone());
        } else if state.failure.is_none() {
            state.failure = Some("scan issue event limit reached".into());
        }
    }
}

pub fn fail(reason: &str) {
    if let Some(report) = current() {
        let mut state = report.0.lock().unwrap();
        if state.failure.is_none() {
            state.failure = Some(reason.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_are_run_owned_and_append_only() {
        let first = Arc::new(ScanReport::default());
        let second = Arc::new(ScanReport::default());
        let mut issue = ScanIssue {
            name: "one".into(),
            host: "same.test".into(),
            ..Default::default()
        };
        {
            let _guard = install(Some(first.clone()));
            record(&issue);
            issue.name = "changed".into();
            {
                let _nested = install(Some(second.clone()));
                record(&issue);
                fail("incomplete");
            }
            record(&issue);
        }
        assert_eq!(
            first
                .events()
                .iter()
                .map(|i| i.name.as_str())
                .collect::<Vec<_>>(),
            vec!["one", "changed"]
        );
        assert_eq!(second.events()[0].name, "changed");
        assert_eq!(second.failure().as_deref(), Some("incomplete"));
        assert!(first.failure().is_none());
        assert!(current().is_none());
    }
}
