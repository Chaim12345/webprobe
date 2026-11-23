//! Non-routed owner contract adapters. One live authority: HostAdmission.0.
//! These are test-only until production caller/transport migration is reviewed.
use crate::host_probe_state::AttemptScope;
use crate::scan_lifecycle::{Coordinator, Finish};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlResult {
    Applied,
    Closed,
    Stale,
    Cancelled,
}
#[derive(Default)]
pub(crate) struct PauseState {
    pub(crate) predicate: Mutex<PausePredicate>,
    pub(crate) changed: Condvar,
}
#[derive(Default)]
pub(crate) struct PausePredicate {
    pub(crate) paused: bool,
    pub(crate) terminal: bool,
    pub(crate) version: u64,
}
#[derive(Clone)]
pub(crate) struct Control {
    pub(crate) coordinator: Weak<Coordinator>,
    pub(crate) owner: Arc<AttemptScope>,
    pub(crate) pause: Arc<PauseState>,
}
impl Control {
    pub(crate) fn cancel(&self) -> ControlResult {
        // Cancellation on a retained terminal owner stays sticky on THAT owner only.
        match self.coordinator.upgrade() {
            Some(c) => c.addressed_control(self, Some(true)),
            None => {
                self.cancel_and_notify();
                ControlResult::Closed
            }
        }
    }
    pub(crate) fn cancel_and_notify(&self) {
        {
            let mut p = self
                .pause
                .predicate
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            self.owner.cancel();
            p.version = p.version.wrapping_add(1);
        }
        self.pause.changed.notify_all();
    }
    pub(crate) fn pause(&self) -> ControlResult {
        self.coordinator
            .upgrade()
            .map_or(ControlResult::Closed, |c| {
                c.addressed_control(self, Some(false))
            })
    }
    pub(crate) fn resume(&self) -> ControlResult {
        self.coordinator
            .upgrade()
            .map_or(ControlResult::Closed, |c| c.addressed_control(self, None))
    }
    pub(crate) fn wait(&self, deadline: Instant) -> Result<(), ControlResult> {
        self.wait_before_sleep(deadline, || {})
    }
    pub(crate) fn wait_before_sleep(
        &self,
        deadline: Instant,
        before: impl FnOnce(),
    ) -> Result<(), ControlResult> {
        // Lock order: authority -> predicate for updates. Waiter owns predicate ONLY,
        // and Condvar atomically releases it. No authority lock is acquired here.
        let mut p = self
            .pause
            .predicate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        before(); // test barrier only; not a runtime callback boundary
        loop {
            if self.owner.is_cancelled() {
                return Err(ControlResult::Cancelled);
            }
            if p.terminal {
                return Err(ControlResult::Closed);
            }
            if Instant::now() >= deadline {
                return Err(ControlResult::Closed);
            }
            if !p.paused {
                return Ok(());
            }
            let version = p.version;
            let duration = deadline.saturating_duration_since(Instant::now());
            p = self
                .pause
                .changed
                .wait_timeout_while(p, duration, |p| {
                    p.version == version && p.paused && !p.terminal && !self.owner.is_cancelled()
                })
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Completion {
    Terminal(Finish),
    Joined,
    Abandoned,
    SenderLost,
}
/// Submission owns this value BEFORE the queued body is entered. Drop never
/// calls arbitrary code, runs A4, or waits. It only releases its Audit receipt.
pub(crate) struct Submission {
    audit: Option<crate::scan_lifecycle::Audit>,
    completion: Option<std::sync::mpsc::Sender<Completion>>,
}
impl Submission {
    pub(crate) fn new(
        audit: crate::scan_lifecycle::Audit,
    ) -> (Self, std::sync::mpsc::Receiver<Completion>) {
        let (tx, rx) = std::sync::mpsc::channel();
        (
            Self {
                audit: Some(audit),
                completion: Some(tx),
            },
            rx,
        )
    }
    pub(crate) fn run(mut self, body: impl FnOnce() -> Finish) {
        let phase = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body))
            .unwrap_or(Finish::Incomplete);
        let audit = self.audit.take().unwrap();
        if phase == Finish::Incomplete {
            audit.mark_incomplete();
        }
        let outcome = match audit.complete() {
            Ok(crate::scan_lifecycle::Handoff::Finalize(f)) => {
                Completion::Terminal(f.run(|_| phase))
            }
            Ok(crate::scan_lifecycle::Handoff::Joined) => Completion::Joined,
            Err(_) => Completion::Terminal(Finish::Incomplete),
        };
        if let Some(tx) = self.completion.take() {
            let _ = tx.send(outcome);
        }
    }
    pub(crate) fn receive(rx: &std::sync::mpsc::Receiver<Completion>) -> Completion {
        rx.recv().unwrap_or(Completion::SenderLost)
    }
}
impl Drop for Submission {
    fn drop(&mut self) {
        drop(self.audit.take());
        if let Some(tx) = self.completion.take() {
            let _ = tx.send(Completion::Abandoned);
        }
    }
}

/// Incarnations are explicit nonserialized capabilities, never derived from
/// task id, slot, timestamps, names or record contents. Adapter operations use
/// tasks -> owner. No waits, user callbacks or diagnostics under those locks.
pub(crate) struct TaskIncarnation(pub(crate) Arc<()>);
pub(crate) struct TaskRegistration {
    pub(crate) incarnation: Weak<()>,
    pub(crate) id: u64,
    pub(crate) reservation: Option<Arc<()>>,
    pub(crate) control: Option<Control>,
}
#[derive(Default)]
pub(crate) struct DispatchState {
    registrations: Vec<TaskRegistration>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchError {
    Stale,
    Cancelled,
    Busy,
    Unavailable,
    Internal,
}
impl DispatchState {
    pub(crate) fn clear(&mut self) -> Vec<Control> {
        std::mem::take(&mut self.registrations)
            .into_iter()
            .filter_map(|r| r.control)
            .collect()
    }
    pub(crate) fn create(&mut self, id: u64) -> TaskIncarnation {
        self.registrations.retain(|r| r.id != id);
        let key = Arc::new(());
        self.registrations.push(TaskRegistration {
            incarnation: Arc::downgrade(&key),
            id,
            reservation: None,
            control: None,
        });
        TaskIncarnation(key)
    }
    pub(crate) fn invalidate(&mut self, key: &TaskIncarnation) {
        self.registrations
            .retain(|r| !r.incarnation.ptr_eq(&Arc::downgrade(&key.0)));
    }
    pub(crate) fn get(&mut self, key: &TaskIncarnation) -> Option<&mut TaskRegistration> {
        self.registrations
            .iter_mut()
            .find(|r| r.incarnation.ptr_eq(&Arc::downgrade(&key.0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_lifecycle::{AdmissionError, Handoff};
    fn limits() -> crate::scan_budget::Limits {
        crate::scan_budget::Limits {
            duration: std::time::Duration::from_secs(2),
            http_attempts: 10,
            connection_attempts: 10,
            outgoing: 1024,
            response: 1024,
            decompressed: 1024,
            inputs: 1024,
            evidence: 1024,
            evidence_records: 10,
            records: 10,
        }
    }
    fn item() -> crate::stored::Item {
        crate::stored::Item {
            entry: Default::default(),
            req: "GET / HTTP/1.1\r\nHost: test\r\n\r\n".into(),
            host: "test".into(),
            port: 80,
            https: false,
        }
    }
    fn finish(b: crate::scan_lifecycle::Batch) {
        let Handoff::Finalize(f) = b.finish().unwrap() else {
            panic!("finalizer")
        };
        assert_eq!(f.run(|_| Finish::Complete), Finish::Complete);
    }
    #[test]
    fn explicit_adoption_fences_unrelated_standalone_and_stale_store_paths() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open_standalone().unwrap();
        assert!(matches!(c.open(), Err(AdmissionError::Busy)));
        assert!(matches!(c.admit(item()), Err(AdmissionError::Busy)));
        assert!(matches!(
            c.admit_standalone(item()),
            Err(AdmissionError::Busy)
        ));
        let nested = c.adopt(&b).unwrap();
        let store = b.generation().unwrap();
        let (a, _, index) = c.admit_in(&b, item()).unwrap();
        assert!(matches!(a.complete(), Ok(Handoff::Joined)));
        let point = webprobe_support::insertion::InsertionPoint::new(
            webprobe_support::insertion::IpKind::Query,
            "x",
            "y",
        );
        let token = store.token(index, &point).unwrap();
        store
            .note_injection(&token, b"request", Some(b"response"))
            .unwrap();
        assert!(store.item(index).unwrap().is_some());
        assert_eq!(
            store
                .observe(index, b"other", token.as_bytes())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.pairs().unwrap().len(), 1);
        assert!(store.pair_bounded(0, 65536).unwrap().is_some());
        assert!(matches!(nested.finish(), Ok(Handoff::Joined)));
        finish(b);
        let fresh = c.open_standalone().unwrap();
        assert!(store.add_item(item()).is_err());
        assert!(store.item(0).is_err());
        assert!(store.token(0, &point).is_err());
        assert!(store.note_injection(&token, b"stale", None).is_err());
        assert!(store.observe(0, b"other", token.as_bytes()).is_err());
        assert!(store.pairs().is_err());
        assert!(store.close().is_err());
        assert!(store.pair_bounded(0, 65536).is_err());
        assert!(fresh.generation().unwrap().item(0).unwrap().is_none());
        finish(fresh);
    }
    #[test]
    fn physical_guard_transfers_without_idle_gap_and_terminal_precedes_replacement() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let (a, legacy, _) = c.admit_standalone(item()).unwrap();
        let Handoff::Finalize(f) = a.complete().unwrap() else {
            panic!("finalizer")
        };
        assert!(shared.scan.is_busy());
        assert!(!shared.scan.wait_idle(Some(std::time::Duration::ZERO)));
        assert!(matches!(c.open_standalone(), Err(AdmissionError::Busy)));
        assert_eq!(f.run(|_| Finish::Complete), Finish::Complete);
        assert_eq!(
            *legacy.owner.terminal.lock().unwrap(),
            Some(Finish::Complete)
        );
        assert!(!shared.scan.is_busy());
        finish(c.open_standalone().unwrap());
    }
    #[test]
    fn queued_abandonment_panic_and_receiver_drop_are_not_success() {
        for mode in 0..4 {
            let shared = crate::net::Shared::new();
            let c = Coordinator::new(shared.clone(), limits()).unwrap();
            let (a, legacy, _) = c.admit_standalone(item()).unwrap();
            let (submission, rx) = Submission::new(a);
            match mode {
                0 => {
                    drop(submission);
                    assert_eq!(Submission::receive(&rx), Completion::Abandoned);
                }
                1 => {
                    submission.run(|| panic!("body panic"));
                    assert_eq!(
                        Submission::receive(&rx),
                        Completion::Terminal(Finish::Incomplete)
                    );
                }
                2 => {
                    drop(rx);
                    drop(submission);
                }
                _ => {
                    let queued = Some(submission);
                    drop(queued);
                    assert_eq!(Submission::receive(&rx), Completion::Abandoned);
                }
            }
            assert_eq!(
                *legacy.owner.terminal.lock().unwrap(),
                Some(Finish::Incomplete)
            );
            assert!(!shared.scan.is_busy());
            finish(c.open_standalone().unwrap());
        }
    }
    #[test]
    fn pause_boundary_notification_and_stale_resume_do_not_revive_or_poison() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open_standalone().unwrap();
        let control = b.control().unwrap();
        assert_eq!(control.pause(), ControlResult::Applied);
        let waiter = control.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            waiter.wait_before_sleep(Instant::now() + std::time::Duration::from_secs(2), || {
                tx.send(()).unwrap();
            })
        });
        rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap();
        assert_eq!(control.cancel(), ControlResult::Applied);
        assert_eq!(t.join().unwrap(), Err(ControlResult::Cancelled));
        assert_eq!(control.resume(), ControlResult::Cancelled);
        let Handoff::Finalize(f) = b.finish().unwrap() else {
            panic!("finalizer")
        };
        assert_eq!(f.run(|_| Finish::Complete), Finish::Incomplete);
        let fresh = c.open_standalone().unwrap();
        let fresh_control = fresh.control().unwrap();
        assert_eq!(control.cancel(), ControlResult::Closed);
        assert_eq!(control.resume(), ControlResult::Closed);
        assert_eq!(
            fresh_control.wait(Instant::now() + std::time::Duration::from_secs(1)),
            Ok(())
        );
        finish(fresh);
    }
    #[test]
    fn returned_control_reentry_foreign_rejection_and_absolute_pause_deadline() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open_standalone().unwrap();
        let control = b.control().unwrap();
        let other = Coordinator::new(crate::net::Shared::new(), limits()).unwrap();
        assert!(matches!(other.adopt(&b), Err(AdmissionError::Busy)));
        assert!(matches!(
            other.admit_in(&b, item()),
            Err(AdmissionError::Busy)
        ));
        assert_eq!(
            other.addressed_control(&control, Some(true)),
            ControlResult::Stale
        );
        assert_eq!(control.pause(), ControlResult::Applied);
        assert_eq!(control.wait(Instant::now()), Err(ControlResult::Closed));
        assert_eq!(control.resume(), ControlResult::Applied);
        // Deferred observer executes only after transaction returns. It can
        // reenter the same authority, unlike Shared::log under the old lock.
        let deferred = || {
            assert_eq!(control.cancel(), ControlResult::Applied);
        };
        deferred();
        let Handoff::Finalize(f) = b.finish().unwrap() else {
            panic!("finalizer")
        };
        assert_eq!(f.run(|_| Finish::Complete), Finish::Incomplete);
    }
    #[test]
    fn task_cancel_and_reservation_are_serialized_on_actual_records() {
        for cancel_first in [true, false] {
            let shared = crate::net::Shared::new();
            let c = Coordinator::new(shared.clone(), limits()).unwrap();
            let key = Arc::new(c.task_insert(task(9)).unwrap());
            let (go_tx, go_rx) = std::sync::mpsc::channel();
            let worker = c.clone();
            let child = key.clone();
            let t = std::thread::spawn(move || {
                go_rx
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .unwrap();
                worker.dispatch_cancel(&child).unwrap();
            });
            if cancel_first {
                go_tx.send(()).unwrap();
                t.join().unwrap();
                assert!(matches!(
                    c.dispatch(&key, true, false),
                    Err(DispatchError::Cancelled)
                ));
                assert!(!shared.scan.is_busy());
                let fresh = c.open_standalone().unwrap();
                finish(fresh);
            } else {
                let b = c.dispatch(&key, true, false).unwrap();
                let control = b.control().unwrap();
                go_tx.send(()).unwrap();
                t.join().unwrap();
                assert_eq!(control.resume(), ControlResult::Cancelled);
                let Handoff::Finalize(f) = b.finish().unwrap() else {
                    panic!("finalizer")
                };
                assert_eq!(f.run(|_| Finish::Complete), Finish::Incomplete);
            }
        }
    }
    #[test]
    fn joined_submission_reports_phase_not_terminal_success() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open_standalone().unwrap();
        let (a, _, _) = c.admit_in(&b, item()).unwrap();
        let (submission, rx) = Submission::new(a);
        submission.run(|| Finish::Complete);
        assert_eq!(Submission::receive(&rx), Completion::Joined);
        finish(b);
    }
    #[test]
    fn cancel_linearization_before_terminal_commit_normalizes_published_result() {
        for cancel_before in [true, false] {
            let shared = crate::net::Shared::new();
            let c = Coordinator::new(shared.clone(), limits()).unwrap();
            let b = c.open_standalone().unwrap();
            let control = b.control().unwrap();
            let Handoff::Finalize(f) = b.finish().unwrap() else {
                panic!("finalizer")
            };
            let (at_tx, at_rx) = std::sync::mpsc::channel();
            let (go_tx, go_rx) = std::sync::mpsc::channel();
            let t = std::thread::spawn(move || {
                f.run_before_commit(
                    |_| Finish::Complete,
                    || {
                        at_tx.send(()).unwrap();
                        go_rx
                            .recv_timeout(std::time::Duration::from_secs(1))
                            .unwrap();
                    },
                )
            });
            at_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            if cancel_before {
                assert_eq!(control.cancel(), ControlResult::Applied);
            }
            go_tx.send(()).unwrap();
            let published = t.join().unwrap();
            assert_eq!(
                published,
                if cancel_before {
                    Finish::Incomplete
                } else {
                    Finish::Complete
                }
            );
            assert_eq!(*control.owner.terminal.lock().unwrap(), Some(published));
            assert_eq!(control.cancel(), ControlResult::Closed);
            assert_eq!(*control.owner.terminal.lock().unwrap(), Some(published));
        }
    }
    #[test]
    fn failed_registration_and_store_close_never_publish_complete() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open_standalone().unwrap();
        let control = b.control().unwrap();
        b.generation().unwrap().close().unwrap();
        assert!(matches!(
            c.admit_in(&b, item()),
            Err(AdmissionError::Internal)
        ));
        assert!(!shared.scan.is_busy());
        let Handoff::Finalize(f) = b.finish().unwrap() else {
            panic!("finalizer")
        };
        assert_eq!(f.run(|_| Finish::Complete), Finish::Incomplete);
        assert_eq!(
            *control.owner.terminal.lock().unwrap(),
            Some(Finish::Incomplete)
        );
        assert!(matches!(
            c.fail_standalone_registration(item()),
            Err(AdmissionError::Internal)
        ));
        assert!(!shared.scan.is_busy());
        finish(c.open_standalone().unwrap());
    }
    #[test]
    fn same_owner_new_generation_invalidates_old_generation_capability() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open_standalone().unwrap();
        let old = b.generation().unwrap();
        let control = b.control().unwrap();
        let replacement = shared
            .stored
            .begin_generation(&shared, control.owner.clone());
        assert!(old.add_item(item()).is_err());
        assert!(old.close().is_err());
        assert_eq!(replacement.add_item(item()).unwrap(), 0);
        let Handoff::Finalize(f) = b.finish().unwrap() else {
            panic!("finalizer")
        };
        assert_eq!(f.run(|_| Finish::Complete), Finish::Incomplete);
    }
    #[test]
    fn duplicate_live_task_does_not_displace_paused_control_or_rewrite_terminal() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let key = c.task_insert(task(11)).unwrap();
        let b = c.dispatch(&key, true, false).unwrap();
        let control = b.control().unwrap();
        assert_eq!(control.pause(), ControlResult::Applied);
        assert!(matches!(c.task_insert(task(11)), Err(DispatchError::Busy)));
        assert_eq!(c.dispatch_cancel(&key), Ok(ControlResult::Applied));
        assert_eq!(control.resume(), ControlResult::Cancelled);
        let Handoff::Finalize(f) = b.finish().unwrap() else {
            panic!("finalizer")
        };
        assert_eq!(f.run(|_| Finish::Complete), Finish::Incomplete);
        shared.tasks.lock().unwrap()[0].state = crate::tasks::TaskState::Finished;
        assert_eq!(c.dispatch_cancel(&key), Ok(ControlResult::Closed));
        assert_eq!(
            shared.tasks.lock().unwrap()[0].state,
            crate::tasks::TaskState::Finished
        );
    }
    #[test]
    fn coordinator_gone_paused_handle_cancels_and_wakes_exceptional_waiter() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open_standalone().unwrap();
        let mut control = b.control().unwrap();
        assert_eq!(control.pause(), ControlResult::Applied);
        // Simulated orphan weak link, not a claim normal capability Drop leaks.
        control.coordinator = Weak::new();
        let waiter = control.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            waiter.wait_before_sleep(Instant::now() + std::time::Duration::from_secs(1), || {
                tx.send(()).unwrap()
            })
        });
        rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap();
        assert_eq!(control.cancel(), ControlResult::Closed);
        assert_eq!(t.join().unwrap(), Err(ControlResult::Cancelled));
        drop(b);
    }
    fn task(id: u64) -> crate::tasks::ScanTask {
        crate::tasks::ScanTask {
            id,
            name: "test".into(),
            kind: crate::tasks::TaskKind::Audit(vec![]),
            state: crate::tasks::TaskState::Queued,
            done: 0,
            total: Some(0),
            issues_found: 0,
            created: 0,
            finished: None,
        }
    }
    #[test]
    fn task_incarnation_cancel_before_dispatch_rollback_and_reuse() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let first = c.task_insert(task(7)).unwrap();
        assert!(matches!(
            c.dispatch(&first, false, false),
            Err(DispatchError::Unavailable)
        ));
        assert!(matches!(
            c.dispatch(&first, true, true),
            Err(DispatchError::Internal)
        ));
        assert_eq!(
            shared.tasks.lock().unwrap()[0].state,
            crate::tasks::TaskState::Queued
        );
        c.dispatch_cancel(&first).unwrap();
        assert!(matches!(
            c.dispatch(&first, true, false),
            Err(DispatchError::Cancelled)
        ));
        c.task_remove(&first).unwrap();
        let keys = c.tasks_reload(vec![task(7)]);
        let next = &keys[0];
        assert!(matches!(
            c.dispatch(&first, true, false),
            Err(DispatchError::Stale)
        ));
        let b = c.dispatch(next, true, false).unwrap();
        assert_eq!(c.dispatch_cancel(next), Ok(ControlResult::Applied));
        let Handoff::Finalize(f) = b.finish().unwrap() else {
            panic!("finalizer")
        };
        assert_eq!(f.run(|_| Finish::Complete), Finish::Incomplete);
    }
}
