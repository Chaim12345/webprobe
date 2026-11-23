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
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

// A lock facade, NOT another mutex: every lifecycle transition owns HostAdmission.0.
struct OwnerState(std::sync::Weak<Shared>);
struct OwnerStateGuard<'a>(std::sync::MutexGuard<'a, crate::host_probe_state::Admission>);
impl Deref for OwnerStateGuard<'_> {
    type Target = Option<Run>;
    fn deref(&self) -> &Self::Target {
        &self.0.protocol
    }
}
impl DerefMut for OwnerStateGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0.protocol
    }
}
impl OwnerState {
    fn lock_on<'a>(&self, shared: &'a Shared) -> OwnerStateGuard<'a> {
        debug_assert!(std::ptr::eq(self.0.as_ptr(), shared));
        OwnerStateGuard(shared.host_admission.0.lock().unwrap())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    Busy,
    Internal,
    InvalidRequest,
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
    /// Exact permit's shared failure latch. Survives swallowed return values
    /// and cloned cross-thread handoffs; proved evidence remains retainable.
    pub fn mark_incomplete(&self) {
        self.ledger.mark_incomplete();
    }
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
        let state = c.state.lock_on(&c.shared);
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
                let state = c.state.lock_on(&c.shared);
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

pub(crate) struct Run {
    strict: bool,
    ledger: Arc<Ledger>,
    owner: Arc<AttemptScope>,
    generation: crate::stored::StoreGeneration,
    pause: Arc<crate::owner_protocol::PauseState>,
    phase: Phase,
    leases: usize,
    active: bool,
    incomplete: bool,
}
pub(crate) struct Coordinator {
    shared: Arc<Shared>,
    limits: Limits,
    state: OwnerState,
    terminal: Mutex<Option<(Arc<AttemptScope>, Finish)>>,
}
pub(crate) struct Batch {
    lease: Arc<std::sync::atomic::AtomicBool>,
    coordinator: Arc<Coordinator>,
    pub(crate) owner: Arc<AttemptScope>,
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
        if shared.host_admission.0.lock().unwrap().protocol.is_some() {
            return Err(AdmissionError::Internal); // exceptional orphan requires explicit reconciliation
        }
        let owner = Arc::new(Self {
            shared: shared.clone(),
            limits,
            state: OwnerState(Arc::downgrade(&shared)),
            terminal: Mutex::new(None),
        });
        *published = Arc::downgrade(&owner);
        Ok(owner)
    }
    fn fresh(&self, admission: &OwnerStateGuard<'_>) -> Arc<AttemptScope> {
        crate::host_probe_state::protocol_scope(&self.shared, &admission.0)
    }
    /// Strict non-routed protocol entry: never adopts an ambient run.
    pub(crate) fn task_insert(
        &self,
        task: crate::tasks::ScanTask,
    ) -> Result<crate::owner_protocol::TaskIncarnation, crate::owner_protocol::DispatchError> {
        let mut tasks = self.shared.tasks.lock().unwrap();
        let mut state = self.state.lock_on(&self.shared);
        let id = task.id;
        if tasks.iter().any(|t| t.id == id) {
            return Err(crate::owner_protocol::DispatchError::Busy);
        }
        let key = state.0.dispatch.create(id);
        tasks.push(task);
        Ok(key)
    }
    pub(crate) fn task_remove(
        &self,
        key: &crate::owner_protocol::TaskIncarnation,
    ) -> Result<(), crate::owner_protocol::DispatchError> {
        let mut tasks = self.shared.tasks.lock().unwrap();
        let mut state = self.state.lock_on(&self.shared);
        let r = state
            .0
            .dispatch
            .get(key)
            .ok_or(crate::owner_protocol::DispatchError::Stale)?;
        let id = r.id;
        let control = r.control.clone();
        if let Some(c) = &control {
            c.owner.cancel();
            let mut p = c.pause.predicate.lock().unwrap_or_else(|e| e.into_inner());
            p.version = p.version.wrapping_add(1);
        }
        state.0.dispatch.invalidate(key);
        tasks.retain(|t| t.id != id);
        drop(state);
        drop(tasks);
        if let Some(c) = control {
            c.pause.changed.notify_all();
        }
        Ok(())
    }
    pub(crate) fn tasks_reload(
        &self,
        replacement: Vec<crate::tasks::ScanTask>,
    ) -> Vec<crate::owner_protocol::TaskIncarnation> {
        let mut tasks = self.shared.tasks.lock().unwrap();
        let mut state = self.state.lock_on(&self.shared);
        let controls = state.0.dispatch.clear();
        for c in &controls {
            c.owner.cancel();
            let mut p = c.pause.predicate.lock().unwrap_or_else(|e| e.into_inner());
            p.version = p.version.wrapping_add(1);
        }
        let old = std::mem::replace(&mut *tasks, replacement);
        let keys = tasks
            .iter()
            .map(|t| state.0.dispatch.create(t.id))
            .collect();
        drop(state);
        drop(tasks);
        drop(old);
        for c in controls {
            c.pause.changed.notify_all();
        }
        keys
    }
    pub(crate) fn dispatch(
        self: &Arc<Self>,
        key: &crate::owner_protocol::TaskIncarnation,
        available: bool,
        inject_failure: bool,
    ) -> Result<Batch, crate::owner_protocol::DispatchError> {
        use crate::owner_protocol::{Control, DispatchError};
        use crate::tasks::TaskState;
        let mut tasks = self.shared.tasks.lock().unwrap();
        let mut state = self.state.lock_on(&self.shared);
        let registration = state.0.dispatch.get(key).ok_or(DispatchError::Stale)?;
        let id = registration.id;
        let task = tasks
            .iter_mut()
            .find(|t| t.id == id)
            .ok_or(DispatchError::Stale)?;
        if task.state == TaskState::Cancelled {
            return Err(DispatchError::Cancelled);
        }
        if task.state != TaskState::Queued || registration.reservation.is_some() {
            return Err(DispatchError::Busy);
        }
        if !available {
            return Err(DispatchError::Unavailable);
        }
        registration.reservation = Some(Arc::new(()));
        if inject_failure {
            registration.reservation = None;
            return Err(DispatchError::Internal);
        }
        if state.is_some() {
            state.0.dispatch.get(key).unwrap().reservation = None;
            return Err(DispatchError::Busy);
        }
        let batch = match self.open_locked(&mut state) {
            Ok(b) => b,
            Err(_) => {
                state.0.dispatch.get(key).unwrap().reservation = None;
                return Err(DispatchError::Internal);
            }
        };
        state.as_mut().unwrap().strict = true;
        let run = state.as_ref().unwrap();
        let control = Control {
            coordinator: Arc::downgrade(self),
            owner: run.owner.clone(),
            pause: run.pause.clone(),
        };
        state.0.dispatch.get(key).unwrap().control = Some(control);
        task.state = TaskState::Running;
        Ok(batch)
    }
    pub(crate) fn dispatch_cancel(
        &self,
        key: &crate::owner_protocol::TaskIncarnation,
    ) -> Result<crate::owner_protocol::ControlResult, crate::owner_protocol::DispatchError> {
        use crate::owner_protocol::{ControlResult, DispatchError};
        let mut tasks = self.shared.tasks.lock().unwrap();
        let mut state = self.state.lock_on(&self.shared);
        let registration = state.0.dispatch.get(key).ok_or(DispatchError::Stale)?;
        let task = tasks
            .iter_mut()
            .find(|t| t.id == registration.id)
            .ok_or(DispatchError::Stale)?;
        let control = registration.control.clone();
        if !task.state.is_open() {
            return Ok(ControlResult::Closed);
        }
        if let Some(c) = &control {
            if !state
                .as_ref()
                .is_some_and(|r| Arc::ptr_eq(&r.owner, &c.owner) && r.phase != Phase::Closed)
            {
                return Ok(ControlResult::Closed);
            }
        }
        task.state = crate::tasks::TaskState::Cancelled;
        let result = if let Some(c) = &control {
            c.owner.cancel();
            let mut p = c.pause.predicate.lock().unwrap_or_else(|e| e.into_inner());
            p.version = p.version.wrapping_add(1);
            ControlResult::Applied
        } else {
            ControlResult::Applied
        };
        drop(state);
        drop(tasks);
        if let Some(c) = control {
            c.pause.changed.notify_all();
        }
        Ok(result)
    }
    pub(crate) fn addressed_control(
        &self,
        handle: &crate::owner_protocol::Control,
        operation: Option<bool>,
    ) -> crate::owner_protocol::ControlResult {
        use crate::owner_protocol::ControlResult;
        if !std::ptr::eq(handle.coordinator.as_ptr(), self) {
            return ControlResult::Stale;
        }
        let state = self.state.lock_on(&self.shared);
        let matching = state
            .as_ref()
            .is_some_and(|r| Arc::ptr_eq(&r.owner, &handle.owner));
        let result = if !matching {
            if operation == Some(true) {
                handle.owner.cancel();
            }
            ControlResult::Closed
        } else if operation == Some(true) {
            handle.owner.cancel();
            ControlResult::Applied
        } else if handle.owner.is_cancelled() {
            ControlResult::Cancelled
        } else if state.as_ref().is_some_and(|r| r.phase != Phase::Open) {
            ControlResult::Closed
        } else {
            ControlResult::Applied
        };
        {
            let mut p = handle
                .pause
                .predicate
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if result == ControlResult::Applied && operation != Some(true) {
                p.paused = operation == Some(false);
            }
            p.version = p.version.wrapping_add(1);
        }
        drop(state);
        handle.pause.changed.notify_all();
        result
    }
    pub(crate) fn control(
        self: &Arc<Self>,
        owner: &Arc<AttemptScope>,
    ) -> Result<crate::owner_protocol::Control, AdmissionError> {
        let state = self.state.lock_on(&self.shared);
        let r = state
            .as_ref()
            .filter(|r| Arc::ptr_eq(&r.owner, owner))
            .ok_or(AdmissionError::Busy)?;
        Ok(crate::owner_protocol::Control {
            coordinator: Arc::downgrade(self),
            owner: owner.clone(),
            pause: r.pause.clone(),
        })
    }
    pub fn open_standalone(self: &Arc<Self>) -> Result<Batch, AdmissionError> {
        let mut state = self.state.lock_on(&self.shared);
        if state.is_some() {
            return Err(AdmissionError::Busy);
        }
        let batch = self.open_locked(&mut state)?;
        state.as_mut().unwrap().strict = true;
        Ok(batch)
    }
    pub fn adopt(self: &Arc<Self>, lease: &Batch) -> Result<Batch, AdmissionError> {
        if !Arc::ptr_eq(self, &lease.coordinator)
            || !lease.live
            || !lease.lease.load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(AdmissionError::Busy);
        }
        let mut state = self.state.lock_on(&self.shared);
        if !state
            .as_ref()
            .is_some_and(|r| Arc::ptr_eq(&r.owner, &lease.owner))
        {
            return Err(AdmissionError::Busy);
        }
        self.open_locked(&mut state)
    }
    pub fn open(self: &Arc<Self>) -> Result<Batch, AdmissionError> {
        let mut state = self.state.lock_on(&self.shared);
        if state.as_ref().is_some_and(|r| r.strict) {
            return Err(AdmissionError::Busy);
        }
        self.open_locked(&mut state)
    }
    fn open_locked(
        self: &Arc<Self>,
        state: &mut OwnerStateGuard<'_>,
    ) -> Result<Batch, AdmissionError> {
        let owner = if let Some(run) = state.as_mut() {
            if run.phase != Phase::Open || run.owner.is_cancelled() {
                return Err(AdmissionError::Busy);
            }
            run.leases = run.leases.checked_add(1).ok_or(AdmissionError::Busy)?;
            run.owner.clone()
        } else {
            // The mutex binds actual stored clear/publication to owner creation.
            let ledger =
                Arc::new(Ledger::pending(self.limits).map_err(|_| AdmissionError::InvalidLimits)?);
            self.shared.stored.open_batch();
            let owner = self.fresh(state);
            self.shared
                .scan
                .stop
                .store(false, std::sync::atomic::Ordering::SeqCst);
            **state = Some(Run {
                strict: false,
                ledger,
                generation: self
                    .shared
                    .stored
                    .begin_generation(&self.shared, owner.clone()),
                owner: owner.clone(),
                pause: Arc::new(Default::default()),
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
    pub fn admit_standalone(
        self: &Arc<Self>,
        item: Item,
    ) -> Result<(Audit, LegacyScanner, usize), AdmissionError> {
        let mut state = self.state.lock_on(&self.shared);
        if state.is_some() {
            return Err(AdmissionError::Busy);
        }
        let accepted = self.admit_locked(item, &mut state)?;
        state.as_mut().unwrap().strict = true;
        Ok(accepted)
    }
    pub fn admit_in(
        self: &Arc<Self>,
        lease: &Batch,
        item: Item,
    ) -> Result<(Audit, LegacyScanner, usize), AdmissionError> {
        if !Arc::ptr_eq(self, &lease.coordinator)
            || !lease.live
            || !lease.lease.load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(AdmissionError::Busy);
        }
        let mut state = self.state.lock_on(&self.shared);
        if !state
            .as_ref()
            .is_some_and(|r| Arc::ptr_eq(&r.owner, &lease.owner))
        {
            return Err(AdmissionError::Busy);
        }
        self.admit_locked(item, &mut state)
    }
    // Compatibility adapter for preserved experimental tests only. Strict protocol
    // callers use admit_standalone/admit_in, never this ambient adoption method.
    pub fn admit(
        self: &Arc<Self>,
        item: Item,
    ) -> Result<(Audit, LegacyScanner, usize), AdmissionError> {
        let mut state = self.state.lock_on(&self.shared);
        if state.as_ref().is_some_and(|r| r.strict) {
            return Err(AdmissionError::Busy);
        }
        self.admit_locked(item, &mut state)
    }
    pub(crate) fn fail_standalone_registration(
        self: &Arc<Self>,
        item: Item,
    ) -> Result<(), AdmissionError> {
        let lease = self.open_standalone()?;
        lease
            .generation()?
            .close()
            .map_err(|_| AdmissionError::Internal)?;
        let result = self.admit_in(&lease, item).map(|_| ());
        drop(lease); // abandoned exact owner cleans up Incomplete, no A4
        result
    }
    fn admit_locked(
        self: &Arc<Self>,
        item: Item,
        state: &mut OwnerStateGuard<'_>,
    ) -> Result<(Audit, LegacyScanner, usize), AdmissionError> {
        if state
            .as_ref()
            .is_some_and(|r| r.phase != Phase::Open || r.active || r.owner.is_cancelled())
        {
            return Err(AdmissionError::Busy);
        }
        let guard = crate::scan_run::try_claim(&self.shared.scan).ok_or(AdmissionError::Busy)?;
        if state.is_none() {
            let ledger =
                Arc::new(Ledger::pending(self.limits).map_err(|_| AdmissionError::InvalidLimits)?);
            self.shared.stored.clear();
            let owner = self.fresh(state);
            self.shared
                .scan
                .stop
                .store(false, std::sync::atomic::Ordering::SeqCst);
            **state = Some(Run {
                strict: false,
                ledger,
                generation: self
                    .shared
                    .stored
                    .begin_generation(&self.shared, owner.clone()),
                owner,
                pause: Arc::new(Default::default()),
                phase: Phase::Open,
                leases: 0,
                active: false,
                incomplete: false,
            });
        }
        let run = state.as_mut().unwrap();
        let index = match run.generation.add_item(item) {
            Ok(index) => index,
            Err(()) => {
                run.incomplete = true;
                return Err(AdmissionError::Internal);
            }
        };
        run.active = true;
        let owner = run.owner.clone();
        let lease = Arc::new(std::sync::atomic::AtomicBool::new(true));
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
        self.cleanup_outcome(owner, Finish::Incomplete, None);
    }
    fn cleanup_outcome(
        &self,
        owner: &Arc<AttemptScope>,
        outcome: Finish,
        mut guard: Option<ScanGuard>,
    ) -> Finish {
        let mut state = self.state.lock_on(&self.shared);
        if let Some(run) = state.as_mut() {
            if Arc::ptr_eq(&run.owner, owner) && !run.active {
                let store_valid = run.generation.close().is_ok();
                let outcome = if outcome == Finish::Complete
                    && !run.incomplete
                    && !run.owner.is_cancelled()
                    && run.ledger.reserve(&[]).is_ok()
                    && !run.ledger.retention_lost()
                    && store_valid
                {
                    Finish::Complete
                } else {
                    Finish::Incomplete
                };
                *owner.terminal.lock().unwrap() = Some(outcome);
                *self.terminal.lock().unwrap() = Some((owner.clone(), outcome));
                run.owner.cancel();
                {
                    let mut p = run
                        .pause
                        .predicate
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    p.terminal = true;
                    p.version = p.version.wrapping_add(1);
                }
                let pause = run.pause.clone();
                run.phase = Phase::Closed;
                self.shared.stored.close_batch();
                if let Some(guard) = guard.as_mut() {
                    guard.release_explicit();
                }
                let retired = state.take();
                drop(state);
                pause.changed.notify_all();
                drop(retired);
                return outcome;
            }
        }
        Finish::Incomplete
    }
    fn make_finalizer(
        self: &Arc<Self>,
        owner: Arc<AttemptScope>,
        state: &mut Run,
        guard: Option<ScanGuard>,
    ) -> Result<Finalizer, AdmissionError> {
        let guard = match guard {
            Some(guard) => guard,
            None => crate::scan_run::try_claim(&self.shared.scan).ok_or(AdmissionError::Busy)?,
        };
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
    pub(crate) fn control(&self) -> Result<crate::owner_protocol::Control, AdmissionError> {
        self.coordinator.control(&self.owner)
    }
    pub(crate) fn generation(&self) -> Result<crate::stored::StoreGeneration, AdmissionError> {
        let state = self.coordinator.state.lock_on(&self.coordinator.shared);
        let run = state
            .as_ref()
            .filter(|r| Arc::ptr_eq(&r.owner, &self.owner) && self.live)
            .ok_or(AdmissionError::Busy)?;
        Ok(run.generation.clone())
    }
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
        let mut state = c.state.lock_on(&c.shared);
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
        match c.make_finalizer(self.owner.clone(), run, None) {
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
        let mut state = self.coordinator.state.lock_on(&self.coordinator.shared);
        if let Some(run) = state.as_mut() {
            if Arc::ptr_eq(&run.owner, &self.owner) && run.phase == Phase::Open {
                run.incomplete = true;
                run.leases = run.leases.saturating_sub(1);
                if run.leases == 0 {
                    run.phase = Phase::Closing;
                    if !run.active {
                        drop(state);
                        self.coordinator
                            .cleanup_outcome(&self.owner, Finish::Incomplete, None);
                    }
                }
            }
        }
    }
}
impl Audit {
    pub fn mark_incomplete(&self) {
        if let Some(run) = self
            .coordinator
            .state
            .lock_on(&self.coordinator.shared)
            .as_mut()
        {
            if Arc::ptr_eq(&run.owner, &self.owner) {
                run.incomplete = true;
            }
        }
    }
    pub fn complete(mut self) -> Result<Handoff, AdmissionError> {
        let c = self.coordinator.clone();
        let mut state = c.state.lock_on(&c.shared);
        let run = state
            .as_mut()
            .filter(|r| Arc::ptr_eq(&r.owner, &self.owner))
            .ok_or(AdmissionError::Busy)?;
        run.active = false;
        let guard = self.guard.take();
        self.live = false;
        self.lease.store(false, std::sync::atomic::Ordering::SeqCst);
        if run.phase == Phase::Closing {
            drop(state);
            c.cleanup_outcome(&self.owner, Finish::Incomplete, guard);
            return Err(AdmissionError::IncompleteActive);
        }
        if run.leases > 0 {
            drop(state);
            drop(guard);
            return Ok(Handoff::Joined);
        }
        run.phase = Phase::Closing;
        match c.make_finalizer(self.owner.clone(), run, guard) {
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
        let mut state = self.coordinator.state.lock_on(&self.coordinator.shared);
        if let Some(run) = state.as_mut() {
            if Arc::ptr_eq(&run.owner, &self.owner) {
                run.active = false;
                run.incomplete = true;
                if run.leases == 0 {
                    run.phase = Phase::Closing;
                    drop(state);
                    self.coordinator.cleanup_outcome(
                        &self.owner,
                        Finish::Incomplete,
                        self.guard.take(),
                    );
                }
            }
        }
    }
}
impl Finalizer {
    /// Explicit execution, never invoked by Drop. Callback stands in for the
    /// forthcoming real budget-required A4 path, not acceptance evidence.
    pub fn run(self, body: impl FnOnce(&BudgetedExecution) -> Finish) -> Finish {
        self.run_before_commit(body, || {})
    }
    pub(crate) fn run_before_commit(
        mut self,
        body: impl FnOnce(&BudgetedExecution) -> Finish,
        before_commit: impl FnOnce(),
    ) -> Finish {
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
            .lock_on(&self.coordinator.shared)
            .as_ref()
            .is_none_or(|r| r.incomplete);
        let complete = result
            && !incomplete
            && !self.permit.owner.is_cancelled()
            && self.permit.ledger.reserve(&[]).is_ok()
            && !self.permit.ledger.retention_lost();
        let outcome = if complete {
            Finish::Complete
        } else {
            Finish::Incomplete
        };
        before_commit(); // test barrier outside the authority critical section
        let published =
            self.coordinator
                .cleanup_outcome(&self.permit.owner, outcome, self.guard.take());
        self.live = false;
        published
    }
}
impl Drop for Finalizer {
    fn drop(&mut self) {
        if self.live {
            self.coordinator.cleanup_outcome(
                &self.permit.owner,
                Finish::Incomplete,
                self.guard.take(),
            );
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
    fn swallowed_failure_is_sticky_across_clones_and_preserves_proven_evidence() {
        let c = Coordinator::new(Shared::new(), limits()).unwrap();
        let b = c.open().unwrap();
        let f = finalizer(b.finish().unwrap());
        assert_eq!(
            f.run(|p| {
                let child = p.clone();
                std::thread::spawn(move || child.mark_incomplete())
                    .join()
                    .unwrap();
                assert_eq!(
                    p.ledger().reserve(&[]),
                    Err(crate::scan_budget::Denied::Failed)
                );
                p.ledger().retain_proven(1).unwrap();
                Finish::Complete
            }),
            Finish::Incomplete
        );
    }
    #[test]
    fn one_authority_per_shared_and_owner_ledger_survives_all_leases() {
        let shared = Shared::new();
        let c = Coordinator::new(shared.clone(), limits()).unwrap();
        let other = Coordinator::new(shared, limits()).unwrap();
        assert!(Arc::ptr_eq(&c, &other));
        let a = c.open().unwrap();
        let ledger = c.state.lock_on(&c.shared).as_ref().unwrap().ledger.clone();
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
    fn installed_guard_is_statically_neither_send_nor_sync() {
        struct Check<T: ?Sized>(std::marker::PhantomData<T>);
        trait AmbiguousSend<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousSend<()> for Check<T> {}
        impl<T: ?Sized + Send> AmbiguousSend<u8> for Check<T> {}
        trait AmbiguousSync<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousSync<()> for Check<T> {}
        impl<T: ?Sized + Sync> AmbiguousSync<u8> for Check<T> {}
        // If Installed acquires Send/Sync, inference has two applicable impls
        // and compilation fails. This tests the real guard, not a stand-in.
        let _ = <Check<Installed> as AmbiguousSend<_>>::marker;
        let _ = <Check<Installed> as AmbiguousSync<_>>::marker;
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
