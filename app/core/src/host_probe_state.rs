//! Host-probe admission and attempts, separate from stored-input pairing.
//! A failed exchange is never retried by another item in the same scope.
use crate::net::Shared;
use crate::scan::ScanDedup;
use crate::sync::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};

const MAX_KEYS: usize = 4096;

#[derive(Default)]
pub struct HostAdmission(pub(crate) Mutex<Admission>);
#[derive(Default)]
pub(crate) struct Admission {
    batch: Option<Arc<AttemptScope>>,
    active: Weak<AttemptScope>,
    batch_leases: usize,
    lease_overflow: bool,
    session: Arc<SessionClaims>,
}
pub struct AttemptScope {
    /// Sticky logical-run identity. Only accepted scope construction makes a
    /// new false value; resetting legacy UI state cannot revive this owner.
    #[cfg(test)] // Experimental token until unified production lifecycle wiring.
    cancelled: std::sync::atomic::AtomicBool,
    pub(crate) dedup: Arc<ScanDedup>,
    attempted: Mutex<HashSet<String>>,
    session: Arc<SessionClaims>,
}
impl AttemptScope {
    /// Cancel this exact logical owner. Safe to retain on bounded resolver
    /// jobs and check both before enqueueing and before lookup starts.
    #[cfg(test)]
    pub(crate) fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Inherited-only check: callers must retain the accepted Arc, never
    /// replace it by looking up whichever owner Shared publishes later.
    #[cfg(test)]
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn new(dedup: Arc<ScanDedup>, session: Arc<SessionClaims>) -> Arc<Self> {
        Arc::new(Self {
            #[cfg(test)]
            cancelled: std::sync::atomic::AtomicBool::new(false),
            dedup,
            session,
            attempted: Mutex::new(HashSet::new()),
        })
    }
}
#[derive(Default)]
pub struct SessionClaims(Mutex<HashMap<String, Claim>>);
enum Claim {
    Pending(Weak<AttemptScope>),
    Complete,
}
pub(crate) enum Acquire {
    Acquired(HostClaim),
    Suppressed,
    Complete,
    Capacity,
}
pub(crate) struct HostClaim {
    scope: Arc<AttemptScope>,
    key: String,
}
impl AttemptScope {
    pub(crate) fn acquire(self: &Arc<Self>, key: String) -> Acquire {
        // Fixed order: session then scope. Neither lock is held during I/O.
        let mut session = self.session.0.lock().unwrap();
        let mut attempted = self.attempted.lock().unwrap();
        if matches!(session.get(&key), Some(Claim::Complete)) {
            return Acquire::Complete;
        }
        if attempted.contains(&key) {
            return Acquire::Suppressed;
        }
        if key.len() > 1024 || attempted.len() >= MAX_KEYS {
            return Acquire::Capacity;
        }
        if let Some(Claim::Pending(owner)) = session.get(&key) {
            if owner.upgrade().is_some() {
                return Acquire::Suppressed;
            }
        }
        if !session.contains_key(&key) && session.len() >= MAX_KEYS {
            return Acquire::Capacity;
        }
        attempted.insert(key.clone());
        session.insert(key.clone(), Claim::Pending(Arc::downgrade(self)));
        Acquire::Acquired(HostClaim {
            scope: self.clone(),
            key,
        })
    }
}
impl HostClaim {
    pub(crate) fn complete(self) {
        let mut session = self.scope.session.0.lock().unwrap();
        if matches!(session.get(&self.key), Some(Claim::Pending(w)) if w.ptr_eq(&Arc::downgrade(&self.scope)))
        {
            session.insert(self.key.clone(), Claim::Complete);
        }
    }
}
impl Drop for HostClaim {
    fn drop(&mut self) {
        let mut session = self.scope.session.0.lock().unwrap();
        if matches!(session.get(&self.key), Some(Claim::Pending(w)) if w.ptr_eq(&Arc::downgrade(&self.scope)))
        {
            session.remove(&self.key);
        }
        // The attempt stays in scope.attempted, even after failure or panic.
    }
}
/// Keeps the capture alive through guard release, including panic unwind.
pub(crate) struct AuditOwner {
    _guard: crate::scan_run::ScanGuard,
    _scope: Arc<AttemptScope>,
}
/// Admission and the scope/dedup pair are captured before the baseline.
pub(crate) fn admit(shared: &Arc<Shared>) -> Option<(AuditOwner, Arc<AttemptScope>)> {
    let mut admission = shared.host_admission.0.lock().unwrap();
    let guard = crate::scan_run::try_claim(&shared.scan)?;
    let scope = admission.batch.clone().unwrap_or_else(|| {
        AttemptScope::new(
            crate::scan::scan_dedup_of(shared),
            admission.session.clone(),
        )
    });
    admission.active = Arc::downgrade(&scope);
    Some((
        AuditOwner {
            _guard: guard,
            _scope: scope.clone(),
        },
        scope,
    ))
}
pub(crate) struct BatchOwner {
    scope: Arc<AttemptScope>,
    closed: std::sync::atomic::AtomicBool,
}
pub(crate) fn open_batch(shared: &Arc<Shared>, fresh_crawl: bool) -> BatchOwner {
    let mut admission = shared.host_admission.0.lock().unwrap();
    if let Some(scope) = admission.batch.clone() {
        shared.log("Host probes incomplete/deferred: nested or overlapping batch shares the active attempt scope");
        if admission.batch_leases == usize::MAX {
            shared.log("Host probes incomplete/deferred: batch lease capacity exhausted; scope remains retained");
            admission.lease_overflow = true;
            return BatchOwner {
                scope,
                closed: std::sync::atomic::AtomicBool::new(true),
            };
        }
        admission.batch_leases += 1;
        return BatchOwner {
            scope,
            closed: std::sync::atomic::AtomicBool::new(false),
        };
    }
    let scope = if let Some(active) = admission.active.upgrade() {
        shared.log("Host probes incomplete/deferred: batch overlaps a captured audit scope; sharing attempts without resetting session claims");
        active
    } else {
        if fresh_crawl {
            *shared.scan_state.lock().unwrap() = Arc::new(ScanDedup::default());
            // Completed session claims survive new crawls. Only run attempts reset.
        }
        AttemptScope::new(
            crate::scan::scan_dedup_of(shared),
            admission.session.clone(),
        )
    };
    admission.batch = Some(scope.clone());
    admission.batch_leases = 1;
    BatchOwner {
        scope,
        closed: std::sync::atomic::AtomicBool::new(false),
    }
}
pub(crate) fn close_batch(shared: &Shared, owner: &BatchOwner) {
    if owner.closed.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let mut admission = shared.host_admission.0.lock().unwrap();
    if admission
        .batch
        .as_ref()
        .is_some_and(|s| Arc::ptr_eq(s, &owner.scope))
    {
        if admission.lease_overflow {
            return;
        } // Fail closed: never evict an uncounted live owner.
        admission.batch_leases -= 1;
        if admission.batch_leases == 0 {
            admission.batch = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn claimed(s: &Arc<AttemptScope>, k: &str) -> HostClaim {
        match s.acquire(k.into()) {
            Acquire::Acquired(c) => c,
            _ => panic!("expected claim"),
        }
    }
    #[test]
    fn admission_overlap_rejection_stale_close_and_next_explicit_run() {
        let shared = Shared::new();
        let (guard, first) = admit(&shared).unwrap();
        assert!(admit(&shared).is_none());
        let batch = open_batch(&shared, true);
        assert!(Arc::ptr_eq(&first, &batch.scope));
        assert!(Arc::ptr_eq(
            &first.dedup,
            &crate::scan::scan_dedup_of(&shared)
        ));
        let nested = open_batch(&shared, true);
        close_batch(&shared, &nested);
        let c = claimed(&first, "unknown");
        drop(c);
        assert!(matches!(
            first.acquire("unknown".into()),
            Acquire::Suppressed
        ));
        drop(guard);
        let (guard, sibling) = admit(&shared).unwrap();
        assert!(Arc::ptr_eq(&first, &sibling));
        drop(guard);
        close_batch(&shared, &batch);
        let (guard, next) = admit(&shared).unwrap();
        assert!(!Arc::ptr_eq(&first, &next));
        let c = claimed(&next, "unknown");
        c.complete();
        // An old scope's owner cannot clear a new scope or its completion.
        close_batch(&shared, &batch);
        assert!(matches!(next.acquire("unknown".into()), Acquire::Complete));
        drop(guard);
        drop(next);
        let (_, third) = admit(&shared).unwrap();
        assert!(matches!(third.acquire("unknown".into()), Acquire::Complete));
    }
    #[test]
    fn simultaneous_claims_have_one_owner_and_capacity_fails_closed() {
        let shared = Shared::new();
        let (_, scope) = admit(&shared).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let wins = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let s = scope.clone();
            let b = barrier.clone();
            let w = wins.clone();
            threads.push(std::thread::spawn(move || {
                b.wait();
                if let Acquire::Acquired(_c) = s.acquire("same".into()) {
                    w.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        barrier.wait();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(wins.load(std::sync::atomic::Ordering::SeqCst), 1);
        let mut set = scope.attempted.lock().unwrap();
        for n in 0..MAX_KEYS {
            set.insert(format!("limit{n}"));
        }
        drop(set);
        assert!(matches!(
            scope.acquire("overflow".into()),
            Acquire::Capacity
        ));
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;
    #[test]
    fn outer_close_cannot_end_nested_scope_and_capture_precedes_first_probe() {
        let shared = Shared::new();
        let (guard, scope) = admit(&shared).unwrap();
        let prior = crate::scan::scan_dedup_of(&shared);
        let outer = open_batch(&shared, true);
        assert!(Arc::ptr_eq(&scope, &outer.scope));
        assert!(Arc::ptr_eq(&prior, &crate::scan::scan_dedup_of(&shared)));
        let nested = open_batch(&shared, true);
        close_batch(&shared, &outer);
        drop(guard);
        let (g, still) = admit(&shared).unwrap();
        assert!(Arc::ptr_eq(&scope, &still));
        drop(g);
        close_batch(&shared, &nested);
        drop(scope);
        drop(still);
        drop(outer);
        drop(nested);
        let fresh = open_batch(&shared, true);
        assert!(!Arc::ptr_eq(&prior, &fresh.scope.dedup));
        close_batch(&shared, &fresh);
        assert!(shared
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.contains("incomplete/deferred")));
    }
    #[test]
    fn completed_session_claim_survives_a_later_fresh_crawl() {
        let shared = Shared::new();
        let (owner, scope) = admit(&shared).unwrap();
        match scope.acquire("completed".into()) {
            Acquire::Acquired(c) => c.complete(),
            _ => panic!(),
        }
        drop(owner);
        drop(scope);
        let crawl = open_batch(&shared, true);
        assert!(matches!(
            crawl.scope.acquire("completed".into()),
            Acquire::Complete
        ));
        close_batch(&shared, &crawl);
    }
    #[test]
    fn lease_overflow_pins_scope_instead_of_reopening() {
        let shared = Shared::new();
        let first = open_batch(&shared, false);
        shared.host_admission.0.lock().unwrap().batch_leases = usize::MAX;
        let overflow = open_batch(&shared, false);
        close_batch(&shared, &overflow);
        close_batch(&shared, &first);
        let state = shared.host_admission.0.lock().unwrap();
        assert!(state.lease_overflow);
        assert!(state
            .batch
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(s, &first.scope)));
    }
    #[test]
    fn stale_claim_drop_cannot_clear_a_different_owner() {
        let shared = Shared::new();
        let (_, old) = admit(&shared).unwrap();
        let old_claim = match old.acquire("key".into()) {
            Acquire::Acquired(c) => c,
            _ => panic!(),
        };
        // White-box hostile old-owner simulation: the only legitimate new
        // owner appears after the old attempt dies. Owner checks must still
        // defend against a delayed result/drop, independently of admission.
        let new = AttemptScope::new(old.dedup.clone(), old.session.clone());
        old.session
            .0
            .lock()
            .unwrap()
            .insert("key".into(), Claim::Pending(Arc::downgrade(&new)));
        drop(old_claim);
        assert!(
            matches!(new.session.0.lock().unwrap().get("key"),Some(Claim::Pending(w)) if w.ptr_eq(&Arc::downgrade(&new)))
        );
    }
}

#[cfg(test)]
mod cancellation_identity_tests {
    use super::*;

    #[test]
    fn sticky_cancellation_belongs_to_the_exact_attempt_scope() {
        let session = Arc::new(SessionClaims::default());
        let old = AttemptScope::new(Arc::new(ScanDedup::default()), session.clone());
        let queued_job_owner = old.clone();
        assert!(!queued_job_owner.is_cancelled());
        old.cancel();
        let new = AttemptScope::new(Arc::new(ScanDedup::default()), session);
        assert!(Arc::ptr_eq(&old, &queued_job_owner));
        assert!(!Arc::ptr_eq(&old, &new));
        assert!(queued_job_owner.is_cancelled());
        assert!(!new.is_cancelled());
        old.cancel();
        assert!(old.is_cancelled());
        assert!(!new.is_cancelled());
    }
}
