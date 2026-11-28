//! AR-05: live passive audits off the proxy connection threads.
//!
//! `start_proxy` starts one worker that drains a bounded queue of recorded
//! exchanges. With no worker, or a full queue, the recording thread audits
//! the exchange itself, as before. The state lives in a tool-state slot,
//! so `Shared` gains no field (ADR 0002).
use super::*;

/// Entries the queue holds before the proxy thread audits its own exchange
/// instead (backpressure, never a dropped audit).
pub const LIVE_AUDIT_QUEUE: usize = 256;

#[derive(Default)]
pub struct LiveAudit {
    /// Present once a worker is running.
    queue: Mutex<Option<std::sync::mpsc::SyncSender<HistEntry>>>,
    /// Entries queued or being audited, with the signal for `wait_idle`.
    pending: (std::sync::Mutex<usize>, std::sync::Condvar),
}

/// The engine's live-audit state.
pub fn live_audit(shared: &Shared) -> Arc<LiveAudit> {
    shared.tool_state.get_or_insert()
}

impl LiveAudit {
    /// Install the queue a worker will drain. False when one is already
    /// installed (the receiver is then dropped by the caller).
    pub(crate) fn install_queue(&self, sender: std::sync::mpsc::SyncSender<HistEntry>) -> bool {
        let mut slot = self.queue.lock();
        if slot.is_some() {
            return false;
        }
        *slot = Some(sender);
        true
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, usize> {
        self.pending
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Hand `entry` to the worker. False when there is no worker or its
    /// queue is full: the caller audits the entry itself.
    pub(crate) fn enqueue(&self, entry: &HistEntry) -> bool {
        let Some(sender) = self.queue.lock().clone() else {
            return false;
        };
        *self.pending() += 1;
        if sender.try_send(entry.clone()).is_ok() {
            return true;
        }
        self.finished_one();
        false
    }

    /// The worker finished (or gave up on) one queued entry.
    pub(crate) fn finished_one(&self) {
        let mut n = self.pending();
        *n = n.saturating_sub(1);
        if *n == 0 {
            self.pending.1.notify_all();
        }
    }

    /// Wait until every queued live audit has finished, at most `timeout`.
    /// True when the queue is idle. Anything that reads the issue list
    /// right after traffic (a report, a save, a test) calls this first.
    pub fn wait_idle(&self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut n = self.pending();
        while *n > 0 {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            n = self
                .pending
                .1
                .wait_timeout(n, left)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        true
    }
}

/// Start the worker that runs live passive audits. One worker, so stateful
/// checks still see exchanges in the order they were recorded. Idempotent.
/// The worker holds only a weak handle and ends when the engine is dropped.
pub fn start_passive_worker(shared: &Arc<Shared>) {
    let (tx, rx) = std::sync::mpsc::sync_channel(LIVE_AUDIT_QUEUE);
    let state = live_audit(shared);
    if !state.install_queue(tx) {
        return;
    }
    let weak = Arc::downgrade(shared);
    crate::util::spawn_contained("passive-audit", move || {
        loop {
            match rx.recv_timeout(std::time::Duration::from_secs(1)) {
                Ok(entry) => {
                    let Some(shared) = weak.upgrade() else { break };
                    // A panicking check must not leave `wait_idle` waiting.
                    let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if let Some(hooks) = scan_hooks() {
                            let issues = hooks.passive_check_live(&shared, &entry);
                            hooks.add_passive_issues(&shared, issues);
                        }
                    }));
                    state.finished_one();
                    if done.is_err() {
                        crate::notice::toast(
                            crate::notice::Level::Warn,
                            "a live passive check panicked on one exchange; auditing continues",
                        );
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if weak.strong_count() == 0 {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AR-05: with no worker an audit is not queued; with one, entries
    /// queue up to the cap, the next one is handed back to the caller, and
    /// `wait_idle` returns once the worker has finished them.
    #[test]
    fn live_audit_queue_hands_back_when_absent_or_full_and_reports_idle() {
        let state = LiveAudit::default();
        let entry = HistEntry::default();
        assert!(!state.enqueue(&entry), "no worker: the caller audits");
        assert!(state.wait_idle(std::time::Duration::from_millis(1)));
        let (tx, rx) = std::sync::mpsc::sync_channel(2);
        assert!(state.install_queue(tx));
        let (again, _keep) = std::sync::mpsc::sync_channel(1);
        assert!(!state.install_queue(again), "one queue only");
        assert!(state.enqueue(&entry));
        assert!(state.enqueue(&entry));
        assert!(!state.enqueue(&entry), "full: the caller audits");
        assert!(!state.wait_idle(std::time::Duration::from_millis(20)));
        assert_eq!(rx.try_iter().count(), 2);
        state.finished_one();
        state.finished_one();
        assert!(state.wait_idle(std::time::Duration::from_millis(1)));
    }
}
