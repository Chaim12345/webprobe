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
    ConfigurationMismatch,
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
#[derive(Clone)]
pub(crate) struct LegacyScanner {
    coordinator: std::sync::Weak<Coordinator>,
    pub owner: Arc<AttemptScope>,
    lease: std::sync::Weak<std::sync::atomic::AtomicBool>,
}
#[derive(Clone)]
pub(crate) struct BudgetedExecution {
    coordinator: std::sync::Weak<Coordinator>,
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
    pub fn validate_shared(&self, shared: &Shared) -> Result<(), AdmissionError> {
        let c = self.coordinator.upgrade().ok_or(AdmissionError::Busy)?;
        if !std::ptr::eq(c.shared.as_ref(), shared) {
            return Err(AdmissionError::Busy);
        }
        self.validate(&self.owner)
    }
    pub fn validate(&self, owner: &Arc<AttemptScope>) -> Result<(), AdmissionError> {
        let Some(c) = self.coordinator.upgrade() else {
            return Err(AdmissionError::Busy);
        };
        let state = c.state.lock().unwrap();
        if !state.as_ref().is_some_and(|r| {
            r.phase == Phase::Finalizing
                && Arc::ptr_eq(&r.owner, &self.owner)
                && Arc::ptr_eq(&r.ledger, &self.ledger)
        }) || !Arc::ptr_eq(owner, &self.owner)
            || self.owner.is_cancelled()
        {
            Err(AdmissionError::Busy)
        } else {
            Ok(())
        }
    }
}
/// Owned inherited context has an exact, nonoptional execution mode.
#[derive(Clone)]
pub(crate) enum ExecutionContext {
    Legacy(LegacyScanner),
    Budgeted(BudgetedExecution),
}
#[derive(Clone)]
pub(crate) struct CancelHandle(Arc<AttemptScope>);
impl CancelHandle {
    pub fn cancel(&self) {
        self.0.cancel();
    }
}
thread_local! {static INSTALLED:std::cell::RefCell<Vec<(u64,ExecutionContext)>>=const{std::cell::RefCell::new(Vec::new())};static NEXT:std::cell::Cell<u64>=const{std::cell::Cell::new(0)};}
pub(crate) struct Installed {
    id: u64,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl ExecutionContext {
    pub fn cancel_handle(&self) -> CancelHandle {
        CancelHandle(match self {
            Self::Legacy(l) => l.owner.clone(),
            Self::Budgeted(p) => p.owner.clone(),
        })
    }
    pub fn validate(&self, shared: &Shared) -> Result<(), AdmissionError> {
        match self {
            Self::Budgeted(p) => p.validate_shared(shared),
            Self::Legacy(l) => {
                let c = l.coordinator.upgrade().ok_or(AdmissionError::Busy)?;
                if !std::ptr::eq(shared, c.shared.as_ref()) || l.owner.is_cancelled() {
                    return Err(AdmissionError::Busy);
                }
                let state = c.state.lock().unwrap();
                if state.as_ref().is_some_and(|r| {
                    r.phase == Phase::Open
                        && Arc::ptr_eq(&r.owner, &l.owner)
                        && l.lease
                            .upgrade()
                            .is_some_and(|v| v.load(std::sync::atomic::Ordering::SeqCst))
                }) {
                    Ok(())
                } else {
                    Err(AdmissionError::Busy)
                }
            }
        }
    }
    pub fn enter(&self, shared: &Shared) -> Result<Installed, AdmissionError> {
        self.validate(shared)?;
        if INSTALLED.with(|slot| slot.borrow().len() >= 64) {
            return Err(AdmissionError::Busy);
        }
        let id = NEXT.with(|next| {
            let id = next.get().checked_add(1).ok_or(AdmissionError::Busy)?;
            next.set(id);
            Ok(id)
        })?;
        INSTALLED.with(|slot| slot.borrow_mut().push((id, self.clone())));
        Ok(Installed {
            id,
            _thread_bound: std::marker::PhantomData,
        })
    }
}
pub(crate) fn captured() -> Option<ExecutionContext> {
    INSTALLED.with(|slot| slot.borrow().last().map(|(_, c)| c.clone()))
}
impl Drop for Installed {
    fn drop(&mut self) {
        INSTALLED.with(|slot| slot.borrow_mut().retain(|(id, _)| *id != self.id));
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
    terminal: Mutex<Option<(Arc<AttemptScope>, Finish)>>,
}
pub(crate) struct Batch {
    lease: Arc<std::sync::atomic::AtomicBool>,
    coordinator: Arc<Coordinator>,
    owner: Arc<AttemptScope>,
    live: bool,
}
pub(crate) struct Audit {
    lease: Arc<std::sync::atomic::AtomicBool>,
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
            if existing.limits != limits {
                return Err(AdmissionError::ConfigurationMismatch);
            }
            return Ok(existing);
        }
        let owner = Arc::new(Self {
            shared: shared.clone(),
            limits,
            state: Mutex::new(None),
            terminal: Mutex::new(None),
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
                Arc::new(Ledger::pending(self.limits).map_err(|_| AdmissionError::InvalidLimits)?);
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
            lease: Arc::new(std::sync::atomic::AtomicBool::new(true)),
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
                Arc::new(Ledger::pending(self.limits).map_err(|_| AdmissionError::InvalidLimits)?);
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
        let lease = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let index = self.shared.stored.add_item(item);
        Ok((
            Audit {
                lease: lease.clone(),
                coordinator: self.clone(),
                owner: owner.clone(),
                guard: Some(guard),
                live: true,
            },
            LegacyScanner {
                coordinator: Arc::downgrade(self),
                owner,
                lease: Arc::downgrade(&lease),
            },
            index,
        ))
    }
    fn cleanup(&self, owner: &Arc<AttemptScope>) {
        self.cleanup_outcome(owner, Finish::Incomplete);
    }
    fn cleanup_outcome(&self, owner: &Arc<AttemptScope>, outcome: Finish) {
        let mut state = self.state.lock().unwrap();
        if let Some(run) = state.as_mut() {
            if Arc::ptr_eq(&run.owner, owner) && !run.active {
                *owner.terminal.lock().unwrap() = Some(outcome);
                *self.terminal.lock().unwrap() = Some((owner.clone(), outcome));
                run.owner.cancel();
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
        state
            .ledger
            .activate()
            .map_err(|_| AdmissionError::InvalidLimits)?;
        state.phase = Phase::Finalizing;
        Ok(Finalizer {
            coordinator: self.clone(),
            permit: BudgetedExecution {
                coordinator: Arc::downgrade(self),
                owner,
                ledger: state.ledger.clone(),
            },
            guard: Some(guard),
            live: true,
        })
    }
}
impl Batch {
    pub fn context(&self) -> ExecutionContext {
        ExecutionContext::Legacy(LegacyScanner {
            coordinator: Arc::downgrade(&self.coordinator),
            owner: self.owner.clone(),
            lease: Arc::downgrade(&self.lease),
        })
    }
    pub fn cancel_handle(&self) -> CancelHandle {
        self.context().cancel_handle()
    }
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
        self.lease.store(false, std::sync::atomic::Ordering::SeqCst);
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
        self.lease.store(false, std::sync::atomic::Ordering::SeqCst);
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
        self.lease.store(false, std::sync::atomic::Ordering::SeqCst);
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
        self.lease.store(false, std::sync::atomic::Ordering::SeqCst);
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
    pub fn run(mut self, body: impl FnOnce(&BudgetedExecution) -> Finish) -> Finish {
        let result = if self.permit.owner.is_cancelled() || self.permit.ledger.reserve(&[]).is_err()
        {
            false
        } else {
            matches!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let context = ExecutionContext::Budgeted(self.permit.clone());
                    let Ok(_installed) = context.enter(&self.coordinator.shared) else {
                        return Finish::Incomplete;
                    };
                    body(&self.permit)
                })),
                Ok(Finish::Complete)
            )
        };
        let incomplete = self
            .coordinator
            .state
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|r| r.incomplete);
        let complete = result
            && !incomplete
            && !self.permit.owner.is_cancelled()
            && self.permit.ledger.reserve(&[]).is_ok()
            && !self.permit.ledger.retention_lost();
        drop(self.guard.take());
        let outcome = if complete {
            Finish::Complete
        } else {
            Finish::Incomplete
        };
        self.coordinator
            .cleanup_outcome(&self.permit.owner, outcome);
        self.live = false;
        outcome
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
                permit.validate_shared(&shared).unwrap();
                permit.ledger().reserve(&[]).unwrap();
                Finish::Complete
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
                    Finish::Complete
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
            finalizer(b.finish().unwrap()).run(|_| Finish::Complete),
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
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            let (audit, legacy, index) = worker.admit(item("/barrier")).unwrap();
            accepted_tx.send((legacy.owner, index)).unwrap();
            release_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
            assert!(matches!(audit.complete(), Ok(Handoff::Joined)));
            finished_tx.send(()).unwrap();
        });
        let (owner, index) = accepted_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        let batch = c.open().unwrap();
        assert!(Arc::ptr_eq(&owner, &batch.owner));
        assert!(shared.stored.item(index).unwrap().req.contains("/barrier"));
        release_tx.send(()).unwrap();
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        t.join().unwrap();
        assert_eq!(
            finalizer(batch.finish().unwrap()).run(|_| Finish::Complete),
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
        assert_eq!(
            ledger.reserve(&[]),
            Err(crate::scan_budget::Denied::NotActivated)
        );
        let b = other.open().unwrap();
        assert!(matches!(a.finish(), Ok(Handoff::Joined)));
        let f = finalizer(b.finish().unwrap());
        assert!(Arc::ptr_eq(&ledger, &f.permit.ledger));
        assert_eq!(
            f.permit
                .ledger
                .used(crate::scan_budget::Resource::HttpAttempt),
            0
        );
        assert_eq!(f.run(|_| Finish::Complete), Finish::Complete);
    }
    #[test]
    fn mismatch_retired_owner_and_budget_exhaustion_never_claim_complete() {
        let shared = Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let mut changed = limits();
        changed.http_attempts += 1;
        assert!(matches!(
            Coordinator::new(shared, changed),
            Err(AdmissionError::ConfigurationMismatch)
        ));
        let b = c.open().unwrap();
        let retired = b.owner.clone();
        assert_eq!(
            finalizer(b.finish().unwrap()).run(|p| {
                assert!(p
                    .ledger
                    .reserve(&[(crate::scan_budget::Resource::HttpAttempt, 100)])
                    .is_err());
                Finish::Complete
            }),
            Finish::Incomplete
        );
        assert!(retired.is_cancelled());
        let next = c.open().unwrap();
        assert!(!next.owner.is_cancelled());
        assert!(!Arc::ptr_eq(&retired, &next.owner));
        drop(next);
    }
    #[test]
    fn delayed_finalizer_retention_loss_and_owner_held_result() {
        let shared = Shared::new();
        let mut short = limits();
        short.duration = std::time::Duration::from_millis(10);
        let c = Coordinator::new(shared, short).unwrap();
        let b = c.open().unwrap();
        let old = b.owner.clone();
        let f = finalizer(b.finish().unwrap());
        std::thread::sleep(std::time::Duration::from_millis(20));
        let calls = AtomicUsize::new(0);
        assert_eq!(
            f.run(|_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Finish::Complete
            }),
            Finish::Incomplete
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(*old.terminal.lock().unwrap(), Some(Finish::Incomplete));
        drop(c);
        assert_eq!(*old.terminal.lock().unwrap(), Some(Finish::Incomplete));
        let c = Coordinator::new(Shared::new(), limits()).unwrap();
        let b = c.open().unwrap();
        let retained = b.owner.clone();
        assert_eq!(
            finalizer(b.finish().unwrap()).run(|p| {
                p.ledger.retain_proven(1).unwrap();
                assert!(p.ledger.retain_proven(99999).is_err());
                assert_eq!(p.ledger.used(crate::scan_budget::Resource::Evidence), 1);
                Finish::Complete
            }),
            Finish::Incomplete
        );
        let b = c.open().unwrap();
        assert_eq!(
            finalizer(b.finish().unwrap()).run(|_| Finish::Complete),
            Finish::Complete
        );
        assert_eq!(*retained.terminal.lock().unwrap(), Some(Finish::Incomplete));
    }
    #[test]
    fn preexhausted_callback_zero_positive_one_and_record_loss_finalization() {
        let c = Coordinator::new(Shared::new(), limits()).unwrap();
        let b = c.open().unwrap();
        let f = finalizer(b.finish().unwrap());
        assert!(f
            .permit
            .ledger
            .reserve(&[(crate::scan_budget::Resource::HttpAttempt, 999)])
            .is_err());
        let calls = AtomicUsize::new(0);
        assert_eq!(
            f.run(|_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Finish::Complete
            }),
            Finish::Incomplete
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let b = c.open().unwrap();
        assert_eq!(
            finalizer(b.finish().unwrap()).run(|_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Finish::Complete
            }),
            Finish::Complete
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let b = c.open().unwrap();
        assert_eq!(
            finalizer(b.finish().unwrap()).run(|p| {
                for _ in 0..10 {
                    p.ledger.retain_proven(0).unwrap();
                }
                assert!(p.ledger.retain_proven(0).is_err());
                assert!(p.ledger.retention_lost());
                assert_eq!(
                    p.ledger.used(crate::scan_budget::Resource::EvidenceRecord),
                    10
                );
                Finish::Complete
            }),
            Finish::Incomplete
        );
    }
    #[test]
    fn inherited_mode_context_is_exact_phase_bound_and_restored_without_shared_fallback() {
        let shared = Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        assert!(captured().is_none());
        let (audit, legacy, _) = c.admit(item("/context")).unwrap();
        let context = ExecutionContext::Legacy(legacy);
        let cancellation = context.cancel_handle();
        assert_eq!(context.validate(&Shared::new()), Err(AdmissionError::Busy));
        {
            let _installed = context.enter(&shared).unwrap();
            assert!(matches!(captured(), Some(ExecutionContext::Legacy(_))));
        }
        assert!(captured().is_none());
        let f = finalizer(audit.complete().unwrap());
        assert!(context.enter(&shared).is_err());
        let budgeted = ExecutionContext::Budgeted(f.permit.clone());
        {
            let _installed = budgeted.enter(&shared).unwrap();
            assert!(matches!(captured(), Some(ExecutionContext::Budgeted(_))));
        }
        assert_eq!(f.run(|_| Finish::Complete), Finish::Complete);
        assert!(budgeted.enter(&shared).is_err());
        let b = c.open().unwrap();
        assert!(!b.owner.is_cancelled());
        cancellation.cancel();
        assert!(!b.owner.is_cancelled());
    }
    #[test]
    fn lease_context_before_between_items_and_mandatory_budgeted_finish_installation() {
        let shared = Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open().unwrap();
        let legacy = b.context();
        legacy.validate(shared.as_ref()).unwrap();
        let (audit, _, _) = c.admit(item("/one")).unwrap();
        assert!(matches!(audit.complete(), Ok(Handoff::Joined)));
        legacy.validate(shared.as_ref()).unwrap();
        let other = c.open().unwrap();
        let stale = other.context();
        assert!(matches!(other.finish(), Ok(Handoff::Joined)));
        assert!(stale.validate(shared.as_ref()).is_err());
        let cancel = b.cancel_handle();
        let f = finalizer(b.finish().unwrap());
        assert!(legacy.validate(shared.as_ref()).is_err());
        assert_eq!(
            f.run(|_| {
                assert!(matches!(captured(), Some(ExecutionContext::Budgeted(_))));
                Finish::Complete
            }),
            Finish::Complete
        );
        assert!(captured().is_none());
        cancel.cancel();
    }
    #[test]
    fn old_audit_does_not_revive_and_non_lifo_guards_never_restore_detached_context() {
        let shared = Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open().unwrap();
        let (a, legacy, _) = c.admit(item("/a")).unwrap();
        let old = ExecutionContext::Legacy(legacy);
        let first = old.enter(&shared).unwrap();
        let second = b.context().enter(&shared).unwrap();
        drop(first);
        drop(second);
        assert!(captured().is_none());
        assert!(matches!(a.complete(), Ok(Handoff::Joined)));
        let (next, _, _) = c.admit(item("/b")).unwrap();
        assert!(old.enter(&shared).is_err());
        assert!(matches!(next.complete(), Ok(Handoff::Joined)));
        let context = b.context();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = context.enter(&shared).unwrap();
            panic!("unwind guard");
        }));
        assert!(captured().is_none());
        drop(b);
    }
    #[test]
    fn inherited_installation_depth_has_finite_ceiling_and_recovers_after_drop() {
        let shared = Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let b = c.open().unwrap();
        let context = b.context();
        let mut guards = Vec::new();
        for _ in 0..64 {
            guards.push(context.enter(&shared).unwrap());
        }
        assert!(context.enter(&shared).is_err());
        drop(guards);
        assert!(captured().is_none());
        assert!(context.enter(&shared).is_ok());
        drop(b);
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
        let calls = AtomicUsize::new(0);
        assert_eq!(
            f.run(|_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Finish::Complete
            }),
            Finish::Incomplete
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
