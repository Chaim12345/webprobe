//! Non-routed owner contract adapters. One live authority: HostAdmission.0.
//! These are test-only until production caller/transport migration is reviewed.
use crate::host_probe_state::AttemptScope;
use crate::scan_lifecycle::{Coordinator, Finish};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    UserCancelled,
    BudgetExhausted(crate::scan_budget::Denied),
    AdmissionRejected,
    Abandoned,
    InternalOrStoreFailure,
    RetentionLoss,
    ActiveAtFinish,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Aggregate {
    pub(crate) outcome: Finish,
    pub(crate) reasons: Vec<Reason>,
}
impl Reason {
    pub(crate) fn from_denied(denied: crate::scan_budget::Denied) -> Self {
        use crate::scan_budget::Denied;
        match denied {
            Denied::Exhausted(_) | Denied::Expired => Self::BudgetExhausted(denied),
            _ => Self::InternalOrStoreFailure,
        }
    }
}
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
        self.owner.record_reason(Reason::UserCancelled);
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
    pub(crate) fn run(self, body: impl FnOnce() -> Finish) {
        self.run_with_finalizer(body, |_| Finish::Complete);
    }
    pub(crate) fn run_with_finalizer(
        mut self,
        body: impl FnOnce() -> Finish,
        finalizer: impl FnOnce(&crate::scan_lifecycle::BudgetedExecution) -> Finish,
    ) {
        let phase = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body))
            .unwrap_or(Finish::Incomplete);
        let audit = self.audit.take().unwrap();
        if phase == Finish::Incomplete {
            audit.mark_incomplete();
        }
        let outcome = match audit.complete() {
            Ok(crate::scan_lifecycle::Handoff::Finalize(f)) => {
                Completion::Terminal(f.run(|permit| {
                    let final_phase = finalizer(permit);
                    if phase == Finish::Complete {
                        final_phase
                    } else {
                        Finish::Incomplete
                    }
                }))
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
    pub(crate) fn remove(&mut self, key: &TaskIncarnation) -> Option<TaskRegistration> {
        let index = self
            .registrations
            .iter()
            .position(|r| r.incarnation.ptr_eq(&Arc::downgrade(&key.0)))?;
        Some(self.registrations.remove(index))
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

/// Task-side observer carries immutable incarnation, never a fresh id lookup.
pub(crate) struct TaskCompletion {
    coordinator: Weak<Coordinator>,
    incarnation: TaskIncarnation,
    control: Control,
}
impl TaskCompletion {
    pub(crate) fn new(
        coordinator: &Arc<Coordinator>,
        incarnation: &TaskIncarnation,
        control: Control,
    ) -> Self {
        Self {
            coordinator: Arc::downgrade(coordinator),
            incarnation: TaskIncarnation(incarnation.0.clone()),
            control,
        }
    }
    pub(crate) fn publish(&self, completion: Completion) -> Result<ControlResult, DispatchError> {
        self.coordinator
            .upgrade()
            .ok_or(DispatchError::Stale)?
            .task_terminal(&self.incarnation, &self.control, completion)
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
            c.fail_published_batch_child_registration(item()),
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
    #[test]
    fn concurrent_idle_observer_sees_terminal_before_replacement_and_old_progress_is_settled() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let (audit, legacy, _) = c.admit_standalone(item()).unwrap();
        shared
            .scan
            .done
            .store(7, std::sync::atomic::Ordering::SeqCst);
        let Handoff::Finalize(f) = audit.complete().unwrap() else {
            panic!("finalizer")
        };
        let (at_tx, at_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel();
        let terminal = legacy.owner.clone();
        let scanner = shared.clone();
        let observer_c = c.clone();
        let (observer_ready_tx, observer_ready_rx) = std::sync::mpsc::channel();
        let observer = std::thread::spawn(move || {
            observer_ready_tx.send(()).unwrap();
            assert!(scanner
                .scan
                .wait_idle(Some(std::time::Duration::from_secs(3))));
            assert_eq!(*terminal.terminal.lock().unwrap(), Some(Finish::Complete));
            let new = observer_c.open_standalone().unwrap();
            scanner
                .scan
                .done
                .store(99, std::sync::atomic::Ordering::SeqCst);
            new
        });
        let runner = std::thread::spawn(move || {
            f.run_before_commit(
                |_| Finish::Complete,
                || {
                    at_tx.send(()).unwrap();
                    go_rx
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                },
            )
        });
        at_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        observer_ready_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(matches!(c.open_standalone(), Err(AdmissionError::Busy)));
        assert!(!shared.scan.wait_idle(Some(std::time::Duration::ZERO)));
        go_tx.send(()).unwrap();
        assert_eq!(runner.join().unwrap(), Finish::Complete);
        let new = observer.join().unwrap();
        assert_eq!(
            shared.scan.done.load(std::sync::atomic::Ordering::SeqCst),
            99
        );
        assert_eq!(
            shared.scan.total.load(std::sync::atomic::Ordering::SeqCst),
            7
        );
        finish(new);
    }
    #[test]
    fn task_terminal_derives_aggregate_and_retires_exact_incarnation() {
        for abandoned in [false, true] {
            let shared = crate::net::Shared::new();
            let c = Coordinator::new(shared.clone(), limits()).unwrap();
            let key = c.task_insert(task(17)).unwrap();
            let batch = c.dispatch(&key, true, false).unwrap();
            let control = batch.control().unwrap();
            let completion = TaskCompletion::new(&c, &key, control.clone());
            assert_eq!(
                completion.publish(Completion::Terminal(Finish::Complete)),
                Err(DispatchError::Busy)
            );
            assert_eq!(
                shared.tasks.lock().unwrap()[0].state,
                crate::tasks::TaskState::Running
            );
            let mut forged = control.clone();
            forged.pause = Arc::new(Default::default());
            assert_eq!(
                TaskCompletion::new(&c, &key, forged)
                    .publish(Completion::Terminal(Finish::Complete)),
                Err(DispatchError::Stale)
            );
            let mut forged = control.clone();
            forged.coordinator = Weak::new();
            assert_eq!(
                TaskCompletion::new(&c, &key, forged)
                    .publish(Completion::Terminal(Finish::Complete)),
                Err(DispatchError::Stale)
            );
            let (audit, _, _) = c.admit_in(&batch, item()).unwrap();
            let (submitted, rx) = Submission::new(audit);
            submitted.run(|| Finish::Complete);
            assert_eq!(Submission::receive(&rx), Completion::Joined);
            assert_eq!(
                completion.publish(Completion::Joined),
                Ok(ControlResult::Applied)
            );
            assert_eq!(
                shared.tasks.lock().unwrap()[0].state,
                crate::tasks::TaskState::Running
            );
            if abandoned {
                drop(batch);
            } else {
                finish(batch);
            }
            // Intentionally wrong labels: retained published aggregate alone
            // determines the record. Neither is evidence of user cancellation.
            let terminal = if abandoned {
                Completion::Terminal(Finish::Complete)
            } else {
                Completion::Abandoned
            };
            assert_eq!(completion.publish(terminal), Ok(ControlResult::Applied));
            assert_eq!(
                shared.tasks.lock().unwrap()[0].state,
                if abandoned {
                    crate::tasks::TaskState::Cancelled
                } else {
                    crate::tasks::TaskState::Finished
                }
            );
            assert_eq!(completion.publish(terminal), Err(DispatchError::Stale));
            let keys = c.tasks_reload(vec![task(17)]);
            let new = &keys[0];
            let next = c.dispatch(new, true, false).unwrap();
            assert_eq!(completion.publish(terminal), Err(DispatchError::Stale));
            assert_eq!(
                shared.tasks.lock().unwrap()[0].state,
                crate::tasks::TaskState::Running
            );
            finish(next);
        }
    }
    #[test]
    fn paused_wait_expires_at_absolute_deadline_without_resume() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open_standalone().unwrap();
        let control = b.control().unwrap();
        assert_eq!(control.pause(), ControlResult::Applied);
        let start = Instant::now();
        let deadline = start + std::time::Duration::from_millis(25);
        assert_eq!(control.wait(deadline), Err(ControlResult::Closed));
        assert!(Instant::now() >= deadline);
        assert_eq!(control.resume(), ControlResult::Applied);
        finish(b);
    }
    #[test]
    fn raw_strict_access_rejects_before_mutation_and_multiple_reasons_survive() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open_standalone().unwrap();
        let g = b.generation().unwrap();
        let control = b.control().unwrap();
        let index = g.add_item(item()).unwrap();
        let point = crate::scan::insertion::InsertionPoint::new(
            crate::scan::insertion::IpKind::Query,
            "x",
            "y",
        );
        let token = g.token(index, &point).unwrap();
        for access in 0..13 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match access {
                0 => shared.stored.clear(),
                1 => {
                    shared.stored.add_item(item());
                }
                2 => {
                    shared.stored.open_batch();
                }
                3 => shared.stored.close_batch(),
                4 => {
                    shared.stored.observe(index, b"x", b"y");
                }
                5 => {
                    shared.stored.item(index);
                }
                6 => {
                    shared.stored.token(index, &point);
                }
                7 => shared.stored.note_injection(&token, b"r", None),
                8 => {
                    shared.stored.pairs();
                }
                9 => {
                    let _ = shared.stored.pair_bounded(0, 8192, |_| true);
                }
                10 => {
                    shared.stored.has_pair(0);
                }
                11 => {
                    shared.stored.is_empty();
                }
                _ => {
                    shared.stored.in_batch();
                }
            }));
            assert!(result.is_err());
            assert!(g.item(index).unwrap().is_some());
        }
        control.owner.record_reason(Reason::InternalOrStoreFailure);
        control.owner.record_reason(Reason::AdmissionRejected);
        assert_eq!(control.cancel(), ControlResult::Applied);
        let Handoff::Finalize(f) = b.finish().unwrap() else {
            panic!("finalizer")
        };
        assert_eq!(f.run(|_| Finish::Complete), Finish::Incomplete);
        let reasons = control.owner.reasons();
        assert!(reasons.contains(&Reason::UserCancelled));
        assert!(reasons.contains(&Reason::InternalOrStoreFailure));
        assert!(reasons.contains(&Reason::AdmissionRejected));
    }
    #[test]
    fn strict_retirement_clears_batch_fences_invalidation_and_freezes_aggregate() {
        for mode in 0..4 {
            let shared = crate::net::Shared::new();
            let c = Coordinator::new(shared.clone(), limits()).unwrap();
            let b = c.open_standalone().unwrap();
            let g = b.generation().unwrap();
            let control = b.control().unwrap();
            let retained = b.context().cancel_handle();
            if mode == 2 {
                g.close().unwrap();
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| shared
                        .stored
                        .clear()))
                    .is_err()
                );
            }
            if mode == 3 {
                let gate = Arc::new(std::sync::Barrier::new(2));
                let release = gate.clone();
                let stale = g.clone();
                let worker = std::thread::spawn(move || {
                    release.wait();
                    stale.close().unwrap();
                });
                gate.wait();
                worker.join().unwrap();
            }
            if mode == 1 {
                drop(b);
            } else {
                let Handoff::Finalize(f) = b.finish().unwrap() else {
                    panic!("finalizer")
                };
                assert_eq!(
                    f.run(|_| Finish::Complete),
                    if mode >= 2 {
                        Finish::Incomplete
                    } else {
                        Finish::Complete
                    }
                );
            }
            assert!(!shared.stored.in_batch());
            assert!(!shared.scan.is_busy());
            let frozen = retained.aggregate().unwrap();
            retained.cancel();
            control.cancel();
            control.owner.record_reason(Reason::AdmissionRejected);
            assert_eq!(retained.aggregate().unwrap(), frozen);
            assert!(!frozen.reasons.contains(&Reason::UserCancelled));
            // Legacy standalone now sees no open batch, so it owns the A4 obligation.
            assert!(!shared.stored.in_batch());
            let (audit, _, _) = c.admit(item()).unwrap();
            assert!(matches!(audit.complete().unwrap(), Handoff::Finalize(_)));
            assert!(!shared.stored.in_batch());
        }
    }
    #[test]
    fn scanner_capability_adoption_rejects_foreign_expired_cancelled_and_closed() {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let (audit, cap, _) = c.admit_standalone(item()).unwrap();
        let other = Coordinator::new(crate::net::Shared::new(), limits()).unwrap();
        assert!(matches!(
            other.adopt_scanner(&cap),
            Err(crate::scan_lifecycle::AdmissionError::Busy)
        ));
        assert!(matches!(
            c.open(),
            Err(crate::scan_lifecycle::AdmissionError::Busy)
        ));
        let adopted = c.adopt_scanner(&cap).unwrap();
        assert!(matches!(audit.complete().unwrap(), Handoff::Joined));
        // Audit lease has expired, even though its owner still lives through adopted batch.
        assert!(matches!(
            c.adopt_scanner(&cap),
            Err(crate::scan_lifecycle::AdmissionError::Busy)
        ));
        finish(adopted);
        assert!(matches!(
            c.adopt_scanner(&cap),
            Err(crate::scan_lifecycle::AdmissionError::Busy)
        ));
        let (audit, cancelled, _) = c.admit_standalone(item()).unwrap();
        cancelled.owner.cancel();
        assert!(matches!(
            c.adopt_scanner(&cancelled),
            Err(crate::scan_lifecycle::AdmissionError::Busy)
        ));
        drop(audit);
        assert!(!shared.scan.is_busy());
        assert!(!shared.stored.in_batch());
        let (audit, stale, _) = c.admit_standalone(item()).unwrap();
        stale.generation.close().unwrap();
        assert!(matches!(
            c.adopt_scanner(&stale),
            Err(crate::scan_lifecycle::AdmissionError::Internal)
        ));
        drop(audit);
        assert!(!shared.scan.is_busy());
        assert!(!shared.stored.in_batch());
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
