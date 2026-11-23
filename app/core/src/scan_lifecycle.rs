//! Isolated owner/finish interface milestone. Uses actual Shared::stored and
//! ScanGuard, but is not connected to production entry points or A4 sends.
use crate::{
    host_probe_state::AttemptScope,
    net::Shared,
    scan_budget::{Ledger, Limits},
    scan_run::ScanGuard,
    stored::Item,
    sync::Mutex,
};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    Busy,
    InvalidLimits,
    IncompleteActive,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Open,
    Closing,
    Finalizing,
    Closed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Finish {
    Complete,
    Incomplete,
}
/// Legacy mode is structurally different from a budget-required A4 permit.
pub(crate) struct LegacyScanner {
    pub owner: Arc<AttemptScope>,
}
pub(crate) struct BudgetedExecution {
    owner: Arc<AttemptScope>,
    ledger: Arc<Ledger>,
}
impl BudgetedExecution {
    pub fn owner(&self) -> &Arc<AttemptScope> {
        &self.owner
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub fn validate(&self, owner: &Arc<AttemptScope>) -> Result<(), AdmissionError> {
        if !Arc::ptr_eq(owner, &self.owner) || self.owner.is_cancelled() {
            Err(AdmissionError::Busy)
        } else {
            Ok(())
        }
    }
}
struct Run {
    ledger: Arc<Ledger>,
    owner: Arc<AttemptScope>,
    phase: Phase,
    leases: usize,
    active: bool,
    incomplete: bool,
}
pub(crate) struct Coordinator {
    shared: Arc<Shared>,
    limits: Limits,
    state: Mutex<Option<Run>>,
}
pub(crate) struct Batch {
    coordinator: Arc<Coordinator>,
    owner: Arc<AttemptScope>,
    live: bool,
}
pub(crate) struct Audit {
    coordinator: Arc<Coordinator>,
    owner: Arc<AttemptScope>,
    guard: Option<ScanGuard>,
    live: bool,
}
pub(crate) struct Finalizer {
    coordinator: Arc<Coordinator>,
    permit: BudgetedExecution,
    guard: Option<ScanGuard>,
    live: bool,
}
pub(crate) enum Handoff {
    Joined,
    Finalize(Box<Finalizer>),
}
impl Coordinator {
    pub fn new(shared: Arc<Shared>, limits: Limits) -> Result<Arc<Self>, AdmissionError> {
        Ledger::new(limits).map_err(|_| AdmissionError::InvalidLimits)?;
        let mut published = shared.host_admission.1.lock().unwrap();
        if let Some(existing) = published.upgrade() {
            return Ok(existing);
        }
        let owner = Arc::new(Self {
            shared: shared.clone(),
            limits,
            state: Mutex::new(None),
        });
        *published = Arc::downgrade(&owner);
        Ok(owner)
    }
    fn fresh(&self) -> Arc<AttemptScope> {
        crate::host_probe_state::experimental_scope(&self.shared)
    }
    pub fn open(self: &Arc<Self>) -> Result<Batch, AdmissionError> {
        let mut state = self.state.lock().unwrap();
        let owner = if let Some(run) = state.as_mut() {
            if run.phase != Phase::Open {
                return Err(AdmissionError::Busy);
            }
            run.leases = run.leases.checked_add(1).ok_or(AdmissionError::Busy)?;
            run.owner.clone()
        } else {
            // The mutex binds actual stored clear/publication to owner creation.
            let ledger =
                Arc::new(Ledger::new(self.limits).map_err(|_| AdmissionError::InvalidLimits)?);
            self.shared.stored.open_batch();
            let owner = self.fresh();
            *state = Some(Run {
                ledger,
                owner: owner.clone(),
                phase: Phase::Open,
                leases: 1,
                active: false,
                incomplete: false,
            });
            owner
        };
        Ok(Batch {
            coordinator: self.clone(),
            owner,
            live: true,
        })
    }
    pub fn admit(
        self: &Arc<Self>,
        item: Item,
    ) -> Result<(Audit, LegacyScanner, usize), AdmissionError> {
        let mut state = self.state.lock().unwrap();
        if state
            .as_ref()
            .is_some_and(|r| r.phase != Phase::Open || r.active)
        {
            return Err(AdmissionError::Busy);
        }
        let guard = crate::scan_run::try_claim(&self.shared.scan).ok_or(AdmissionError::Busy)?;
        if state.is_none() {
            let ledger =
                Arc::new(Ledger::new(self.limits).map_err(|_| AdmissionError::InvalidLimits)?);
            self.shared.stored.clear();
            let owner = self.fresh();
            *state = Some(Run {
                ledger,
                owner,
                phase: Phase::Open,
                leases: 0,
                active: false,
                incomplete: false,
            });
        }
        let run = state.as_mut().unwrap();
        run.active = true;
        let owner = run.owner.clone();
        let index = self.shared.stored.add_item(item);
        Ok((
            Audit {
                coordinator: self.clone(),
                owner: owner.clone(),
                guard: Some(guard),
                live: true,
            },
            LegacyScanner { owner },
            index,
        ))
    }
    fn cleanup(&self, owner: &Arc<AttemptScope>) {
        let mut state = self.state.lock().unwrap();
        if let Some(run) = state.as_mut() {
            if Arc::ptr_eq(&run.owner, owner) && !run.active {
                run.phase = Phase::Closed;
                self.shared.stored.close_batch();
                *state = None;
            }
        }
    }
    fn make_finalizer(
        self: &Arc<Self>,
        owner: Arc<AttemptScope>,
        state: &mut Run,
    ) -> Result<Finalizer, AdmissionError> {
        let guard = crate::scan_run::try_claim(&self.shared.scan).ok_or(AdmissionError::Busy)?;
        state.phase = Phase::Finalizing;
        Ok(Finalizer {
            coordinator: self.clone(),
            permit: BudgetedExecution {
                owner,
                ledger: state.ledger.clone(),
            },
            guard: Some(guard),
            live: true,
        })
    }
}
impl Batch {
    pub fn finish(mut self) -> Result<Handoff, AdmissionError> {
        let c = self.coordinator.clone();
        let mut state = c.state.lock().unwrap();
        let run = state
            .as_mut()
            .filter(|r| Arc::ptr_eq(&r.owner, &self.owner))
            .ok_or(AdmissionError::Busy)?;
        if run.phase != Phase::Open || run.leases == 0 {
            return Err(AdmissionError::Busy);
        }
        self.live = false;
        run.leases -= 1;
        if run.leases > 0 {
            return Ok(Handoff::Joined);
        }
        run.phase = Phase::Closing;
        if run.active {
            run.incomplete = true;
            return Err(AdmissionError::IncompleteActive);
        }
        match c.make_finalizer(self.owner.clone(), run) {
            Ok(f) => Ok(Handoff::Finalize(Box::new(f))),
            Err(e) => {
                run.incomplete = true;
                drop(state);
                c.cleanup(&self.owner);
                Err(e)
            }
        }
    }
}
impl Drop for Batch {
    fn drop(&mut self) {
        if !self.live {
            return;
        }
        self.live = false;
        let mut state = self.coordinator.state.lock().unwrap();
        if let Some(run) = state.as_mut() {
            if Arc::ptr_eq(&run.owner, &self.owner) && run.phase == Phase::Open {
                run.incomplete = true;
                run.leases = run.leases.saturating_sub(1);
                if run.leases == 0 {
                    run.phase = Phase::Closing;
                    if !run.active {
                        drop(state);
                        self.coordinator.cleanup(&self.owner);
                    }
                }
            }
        }
    }
}
impl Audit {
    pub fn complete(mut self) -> Result<Handoff, AdmissionError> {
        let c = self.coordinator.clone();
        let mut state = c.state.lock().unwrap();
        let run = state
            .as_mut()
            .filter(|r| Arc::ptr_eq(&r.owner, &self.owner))
            .ok_or(AdmissionError::Busy)?;
        run.active = false;
        drop(self.guard.take());
        self.live = false;
        if run.phase == Phase::Closing {
            drop(state);
            c.cleanup(&self.owner);
            return Err(AdmissionError::IncompleteActive);
        }
        if run.leases > 0 {
            return Ok(Handoff::Joined);
        }
        run.phase = Phase::Closing;
        match c.make_finalizer(self.owner.clone(), run) {
            Ok(f) => Ok(Handoff::Finalize(Box::new(f))),
            Err(e) => {
                drop(state);
                c.cleanup(&self.owner);
                Err(e)
            }
        }
    }
}
impl Drop for Audit {
    fn drop(&mut self) {
        if !self.live {
            return;
        }
        self.live = false;
        let mut state = self.coordinator.state.lock().unwrap();
        if let Some(run) = state.as_mut() {
            if Arc::ptr_eq(&run.owner, &self.owner) {
                run.active = false;
                run.incomplete = true;
                drop(self.guard.take());
                if run.leases == 0 {
                    run.phase = Phase::Closing;
                    drop(state);
                    self.coordinator.cleanup(&self.owner);
                }
            }
        }
    }
}
impl Finalizer {
    /// Explicit execution, never invoked by Drop. Callback stands in for the
    /// forthcoming real budget-required A4 path, not acceptance evidence.
    pub fn run(mut self, body: impl FnOnce(&BudgetedExecution)) -> Finish {
        let result = if self.permit.owner.is_cancelled() {
            false
        } else {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&self.permit))).is_ok()
        };
        let incomplete = self
            .coordinator
            .state
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|r| r.incomplete);
        drop(self.guard.take());
        self.coordinator.cleanup(&self.permit.owner);
        self.live = false;
        if result && !incomplete && !self.permit.owner.is_cancelled() {
            Finish::Complete
        } else {
            Finish::Incomplete
        }
    }
}
impl Drop for Finalizer {
    fn drop(&mut self) {
        if self.live {
            drop(self.guard.take());
            self.coordinator.cleanup(&self.permit.owner);
            self.live = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    fn limits() -> Limits {
        Limits {
            duration: std::time::Duration::from_secs(1),
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
    fn item(path: &str) -> Item {
        Item {
            entry: crate::net::HistEntry::default(),
            req: format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n"),
            host: "test".into(),
            port: 80,
            https: false,
        }
    }
    fn finalizer(h: Handoff) -> Finalizer {
        match h {
            Handoff::Finalize(f) => *f,
            _ => panic!("expected finalizer"),
        }
    }
    #[test]
    fn actual_store_standalone_adoption_preserves_item_and_defers_finish() {
        let shared = Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let (audit, legacy, index) = c.admit(item("/baseline")).unwrap();
        let batch = c.open().unwrap();
        assert!(Arc::ptr_eq(&batch.owner, &legacy.owner));
        assert!(shared.stored.item(index).unwrap().req.contains("/baseline"));
        assert!(matches!(audit.complete(), Ok(Handoff::Joined)));
        let f = finalizer(batch.finish().unwrap());
        assert!(matches!(c.open(), Err(AdmissionError::Busy)));
        assert!(matches!(
            c.admit(item("/denied")),
            Err(AdmissionError::Busy)
        ));
        assert_eq!(
            f.run(|permit| {
                permit.validate(&legacy.owner).unwrap();
                permit.ledger().reserve(&[]).unwrap();
            }),
            Finish::Complete
        );
        assert!(c.open().is_ok());
    }
    #[test]
    fn both_lease_orders_have_one_finalizer_and_abandonment_is_sticky() {
        for reverse in [false, true] {
            let c = Coordinator::new(Shared::new(), limits()).unwrap();
            let a = c.open().unwrap();
            let b = c.open().unwrap();
            let (first, last) = if reverse { (b, a) } else { (a, b) };
            assert!(matches!(first.finish(), Ok(Handoff::Joined)));
            let calls = AtomicUsize::new(0);
            assert_eq!(
                finalizer(last.finish().unwrap()).run(|_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                }),
                Finish::Complete
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
        let c = Coordinator::new(Shared::new(), limits()).unwrap();
        let a = c.open().unwrap();
        let b = c.open().unwrap();
        drop(a);
        assert_eq!(
            finalizer(b.finish().unwrap()).run(|_| {}),
            Finish::Incomplete
        );
    }
    #[test]
    fn active_close_is_cleanup_only_and_panic_drop_never_runs_stage() {
        let shared = Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open().unwrap();
        let (a, _, index) = c.admit(item("/keep")).unwrap();
        assert!(matches!(b.finish(), Err(AdmissionError::IncompleteActive)));
        assert!(shared.stored.item(index).is_some());
        assert!(matches!(c.open(), Err(AdmissionError::Busy)));
        drop(a);
        let b = c.open().unwrap();
        let f = finalizer(b.finish().unwrap());
        assert_eq!(
            f.run(|_| panic!("injected stage panic")),
            Finish::Incomplete
        );
        let b = c.open().unwrap();
        drop(finalizer(b.finish().unwrap()));
        assert!(c.open().is_ok());
    }
    #[test]
    fn concurrent_actual_admit_open_barrier_preserves_registered_baseline() {
        let shared = Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = c.clone();
        let t = std::thread::spawn(move || {
            let (audit, legacy, index) = worker.admit(item("/barrier")).unwrap();
            accepted_tx.send((legacy.owner, index)).unwrap();
            release_rx.recv().unwrap();
            assert!(matches!(audit.complete(), Ok(Handoff::Joined)));
        });
        let (owner, index) = accepted_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        let batch = c.open().unwrap();
        assert!(Arc::ptr_eq(&owner, &batch.owner));
        assert!(shared.stored.item(index).unwrap().req.contains("/barrier"));
        release_tx.send(()).unwrap();
        t.join().unwrap();
        assert_eq!(
            finalizer(batch.finish().unwrap()).run(|_| {}),
            Finish::Complete
        );
    }
    #[test]
    fn one_authority_per_shared_and_owner_ledger_survives_all_leases() {
        let shared = Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let other = Coordinator::new(shared, limits()).unwrap();
        assert!(Arc::ptr_eq(&c, &other));
        let a = c.open().unwrap();
        let ledger = c.state.lock().unwrap().as_ref().unwrap().ledger.clone();
        ledger
            .reserve(&[(crate::scan_budget::Resource::HttpAttempt, 1)])
            .unwrap();
        let b = other.open().unwrap();
        assert!(matches!(a.finish(), Ok(Handoff::Joined)));
        let f = finalizer(b.finish().unwrap());
        assert!(Arc::ptr_eq(&ledger, &f.permit.ledger));
        assert_eq!(
            f.permit
                .ledger
                .used(crate::scan_budget::Resource::HttpAttempt),
            1
        );
        assert_eq!(f.run(|_| {}), Finish::Complete);
    }
    #[test]
    fn permit_rejects_other_owner_and_cancel_prevents_callback() {
        let c = Coordinator::new(Shared::new(), limits()).unwrap();
        let b = c.open().unwrap();
        let f = finalizer(b.finish().unwrap());
        let other = Coordinator::new(Shared::new(), limits()).unwrap();
        let ob = other.open().unwrap();
        assert_eq!(f.permit.validate(&ob.owner), Err(AdmissionError::Busy));
        assert!(Arc::ptr_eq(f.permit.owner(), &f.permit.owner));
        f.permit.owner.cancel();
        assert_eq!(
            f.run(|_| panic!("cancelled callback must never run")),
            Finish::Incomplete
        );
    }
}
