//! Experimental scanner ledger primitives. Not wired to production sends.
//! Limits are injected by fixtures; no default or unlimited mode is supplied.
use crate::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub duration: Duration,
    pub http_attempts: u64,
    pub connection_attempts: u64,
    pub outgoing: u64,
    pub response: u64,
    pub decompressed: u64,
    pub inputs: u64,
    pub evidence: u64,
    pub evidence_records: u64,
    pub records: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resource {
    HttpAttempt,
    ConnectionAttempt,
    Outgoing,
    Response,
    Decompressed,
    Input,
    Evidence,
    EvidenceRecord,
    Record,
}
impl Resource {
    fn index(self) -> usize {
        self as usize
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Denied {
    InvalidLimits,
    Expired,
    Exhausted(Resource),
}
struct State {
    used: [u64; 9],
    denied: Option<Denied>,
}
pub(crate) struct Ledger {
    deadline: Instant,
    ceilings: [u64; 9],
    state: Mutex<State>,
}
impl Ledger {
    pub fn new(limits: Limits) -> Result<Self, Denied> {
        let ceilings = [
            limits.http_attempts,
            limits.connection_attempts,
            limits.outgoing,
            limits.response,
            limits.decompressed,
            limits.inputs,
            limits.evidence,
            limits.evidence_records,
            limits.records,
        ];
        if limits.duration.is_zero() || ceilings.contains(&0) {
            return Err(Denied::InvalidLimits);
        }
        let deadline = Instant::now()
            .checked_add(limits.duration)
            .ok_or(Denied::InvalidLimits)?;
        Ok(Self {
            deadline,
            ceilings,
            state: Mutex::new(State {
                used: [0; 9],
                denied: None,
            }),
        })
    }
    /// All resource reservations are atomic and irreversible. A denied attempt
    /// cannot partially spend its multi-resource reservation. Already exposed
    /// bytes/attempts have no refund API. Cancellation is supplied by the owner.
    pub fn reserve(&self, charges: &[(Resource, u64)]) -> Result<(), Denied> {
        let mut state = self.state.lock().unwrap();
        if let Some(reason) = state.denied {
            return Err(reason);
        }
        if Instant::now() >= self.deadline {
            state.denied = Some(Denied::Expired);
            return Err(Denied::Expired);
        }
        let mut proposed = state.used;
        for &(resource, count) in charges {
            let at = resource.index();
            let Some(next) = proposed[at].checked_add(count) else {
                let reason = Denied::Exhausted(resource);
                state.denied = Some(reason);
                return Err(reason);
            };
            if next > self.ceilings[at] {
                let reason = Denied::Exhausted(resource);
                state.denied = Some(reason);
                return Err(reason);
            }
            proposed[at] = next;
        }
        state.used = proposed;
        Ok(())
    }
    /// Retaining a proved finding is allowed after expiry/exhaustion, under a
    /// separate ceiling. This never admits further I/O or clears denial.
    pub fn retain_proven(&self, bytes: u64) -> Result<(), Denied> {
        let mut state = self.state.lock().unwrap();
        let at = Resource::Evidence.index();
        let next = state.used[at]
            .checked_add(bytes)
            .filter(|v| *v <= self.ceilings[at])
            .ok_or(Denied::Exhausted(Resource::Evidence))?;
        let records = Resource::EvidenceRecord.index();
        let next_records = state.used[records]
            .checked_add(1)
            .filter(|v| *v <= self.ceilings[records])
            .ok_or(Denied::Exhausted(Resource::EvidenceRecord))?;
        state.used[at] = next;
        state.used[records] = next_records;
        Ok(())
    }
    pub fn remaining(&self, ordinary_limit: Duration) -> Result<Duration, Denied> {
        if ordinary_limit.is_zero() {
            return Err(Denied::InvalidLimits);
        }
        self.reserve(&[])?;
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            self.reserve(&[])?;
            return Err(Denied::Expired);
        }
        Ok(ordinary_limit.min(left))
    }
    pub fn used(&self, resource: Resource) -> u64 {
        self.state.lock().unwrap().used[resource.index()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    fn limits() -> Limits {
        Limits {
            duration: Duration::from_secs(2),
            http_attempts: 2,
            connection_attempts: 3,
            outgoing: 10,
            response: 10,
            decompressed: 10,
            inputs: 10,
            evidence: 10,
            evidence_records: 2,
            records: 2,
        }
    }
    #[test]
    fn no_default_unlimited_or_zero_configuration() {
        for n in 0..10 {
            let mut l = limits();
            match n {
                0 => l.duration = Duration::ZERO,
                1 => l.http_attempts = 0,
                2 => l.connection_attempts = 0,
                3 => l.outgoing = 0,
                4 => l.response = 0,
                5 => l.decompressed = 0,
                6 => l.inputs = 0,
                7 => l.evidence = 0,
                8 => l.evidence_records = 0,
                _ => l.records = 0,
            };
            assert!(matches!(Ledger::new(l), Err(Denied::InvalidLimits)));
        }
    }
    #[test]
    fn atomic_charging_no_refund_and_proven_evidence_survives_exhaustion() {
        let l = Ledger::new(limits()).unwrap();
        l.reserve(&[(Resource::HttpAttempt, 1), (Resource::Outgoing, 8)])
            .unwrap();
        assert_eq!(
            l.reserve(&[(Resource::HttpAttempt, 1), (Resource::Outgoing, 3)]),
            Err(Denied::Exhausted(Resource::Outgoing))
        );
        assert_eq!(l.used(Resource::HttpAttempt), 1);
        assert_eq!(l.used(Resource::Outgoing), 8);
        assert!(l.reserve(&[(Resource::Response, 1)]).is_err());
        l.retain_proven(8).unwrap();
        assert!(l.retain_proven(3).is_err());
        assert_eq!(l.used(Resource::Evidence), 8);
        assert!(l.reserve(&[]).is_err());
    }
    #[test]
    fn duplicate_resource_overflow_cannot_wrap_or_partially_charge() {
        let mut config = limits();
        config.response = u64::MAX;
        let l = Ledger::new(config).unwrap();
        assert_eq!(
            l.reserve(&[(Resource::Response, u64::MAX), (Resource::Response, 1)]),
            Err(Denied::Exhausted(Resource::Response))
        );
        assert_eq!(l.used(Resource::Response), 0);
    }
    #[test]
    fn concurrent_actual_attempt_reservations_have_one_shared_ceiling() {
        let l = Arc::new(Ledger::new(limits()).unwrap());
        let mut threads = Vec::new();
        for _ in 0..12 {
            let l = l.clone();
            threads.push(std::thread::spawn(move || {
                l.reserve(&[(Resource::HttpAttempt, 1)]).is_ok()
            }));
        }
        let wins = threads
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|v| *v)
            .count();
        assert_eq!(wins, 2);
        assert_eq!(l.used(Resource::HttpAttempt), 2);
    }
    #[test]
    fn monotonic_deadline_does_not_restart_and_preserves_completed_evidence() {
        let mut config = limits();
        config.duration = Duration::from_millis(20);
        let l = Ledger::new(config).unwrap();
        let first = l.remaining(Duration::from_secs(120)).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        assert!(first <= Duration::from_millis(20));
        assert_eq!(l.remaining(Duration::from_secs(120)), Err(Denied::Expired));
        l.retain_proven(2).unwrap();
        assert_eq!(l.used(Resource::Evidence), 2);
    }
    #[test]
    fn evidence_record_limit_applies_even_to_zero_byte_findings_and_timeout_zero_denied() {
        let l = Ledger::new(limits()).unwrap();
        l.retain_proven(0).unwrap();
        l.retain_proven(0).unwrap();
        assert_eq!(
            l.retain_proven(0),
            Err(Denied::Exhausted(Resource::EvidenceRecord))
        );
        assert_eq!(l.used(Resource::Evidence), 0);
        assert_eq!(l.remaining(Duration::ZERO), Err(Denied::InvalidLimits));
        assert!(l.reserve(&[(Resource::HttpAttempt, 1)]).is_ok());
    }
    #[test]
    fn all_resource_domains_are_independent_and_finite() {
        let l = Ledger::new(limits()).unwrap();
        for r in [
            Resource::ConnectionAttempt,
            Resource::Response,
            Resource::Decompressed,
            Resource::Input,
            Resource::Record,
        ] {
            l.reserve(&[(r, 1)]).unwrap();
            assert_eq!(l.used(r), 1);
        }
        assert_eq!(l.used(Resource::Outgoing), 0);
    }
}
