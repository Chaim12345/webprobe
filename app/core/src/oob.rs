//! Collaborator ids of the active scan (N-07): the payload pool the front
//! end keeps stocked, the ids each check registered, and the matching of
//! interactions against them. One owner, so registering, pooling and
//! matching go through these methods only.
//! Burp family SCANNER_ACTIVE_CHECKS_EXTERNAL_INTERACTION.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::collaborator::{CollaboratorState, Interaction};
use crate::scan::ScanIssue;
use crate::sync::Mutex;

/// Pending ids kept at most; the oldest are dropped beyond it (an id that
/// never sees its interaction must not be kept forever).
const MAX_PENDING: usize = 100_000;

#[derive(Default)]
pub struct OobState {
    /// (id, required interaction kind such as "SMTP" or "CNAME", or None for
    /// any; the issue to raise).
    pending: Mutex<Vec<(String, Option<&'static str>, ScanIssue)>>,
    /// "id|kind" pairs already raised as External service interaction.
    reported: Mutex<HashSet<String>>,
    /// Highest interaction id already matched.
    seen: AtomicU64,
    /// Pre-minted (id, payload domain) pairs for scans off the UI thread.
    pool: Mutex<Vec<(String, String)>>,
    /// A scan off the UI thread wants payloads.
    wanted: AtomicBool,
    /// A front end with a Collaborator keeps the pool stocked.
    supplier: AtomicBool,
    /// Ids a waiting `take` needs: `refill` stocks at least this many.
    demand: std::sync::atomic::AtomicUsize,
}

impl OobState {
    /// Register an id a check embedded; `kind` is the interaction that
    /// proves it (None: any, raised per interaction type).
    pub fn register(&self, id: String, kind: Option<&'static str>, issue: ScanIssue) {
        let mut pending = self.pending.lock().unwrap();
        pending.push((id, kind, issue));
        let excess = pending.len().saturating_sub(MAX_PENDING);
        pending.drain(..excess);
    }

    /// Replace the evidence of a pending id once its probe's response is in.
    pub fn set_evidence(&self, id: &str, evidence: Vec<crate::scan::ScanEvidence>) {
        if let Some(p) = self.pending.lock().unwrap().iter_mut().find(|(t, k, _)| t == id && k.is_none()) {
            p.2.evidence = evidence;
        }
    }

    /// (id, kind, issue) of every pending id, for tests and the Dashboard.
    pub fn pending(&self) -> Vec<(String, Option<&'static str>, ScanIssue)> {
        self.pending.lock().unwrap().clone()
    }

    pub fn is_pending_empty(&self) -> bool {
        self.pending.lock().unwrap().is_empty()
    }

    /// This process has a front end that stocks the pool.
    pub fn set_supplier(&self, on: bool) {
        self.supplier.store(on, Ordering::SeqCst);
    }

    /// Ask (or stop asking) the supplier for payloads.
    pub fn want(&self, on: bool) {
        self.wanted.store(on, Ordering::SeqCst);
    }

    pub fn is_wanted(&self) -> bool {
        self.wanted.load(Ordering::SeqCst)
    }

    /// Top the pool up to `high` with `mint` when it is below `low`.
    /// Below `low`, or below what a waiting `take` needs, the pool is
    /// stocked up to the larger of `high` and that need.
    pub fn refill(&self, low: usize, high: usize, mut mint: impl FnMut() -> (String, String)) {
        let need = self.demand.load(Ordering::SeqCst);
        let mut pool = self.pool.lock().unwrap();
        if pool.len() < low || pool.len() < need {
            let target = high.max(need);
            while pool.len() < target {
                pool.push(mint());
            }
        }
    }

    /// Put payloads into the pool directly (tests, headless suppliers).
    pub fn stock(&self, items: impl IntoIterator<Item = (String, String)>) {
        self.pool.lock().unwrap().extend(items);
    }

    pub fn pool_len(&self) -> usize {
        self.pool.lock().unwrap().len()
    }

    /// Take `n` payloads, waiting up to `wait` for a supplier that was asked
    /// to stock enough. Returns what it got: fewer than `n` when the pool
    /// runs short (the caller reports the shortfall).
    pub fn take(&self, n: usize, wait: Duration) -> Vec<(String, String)> {
        let deadline = Instant::now() + wait;
        if self.pool_len() < n {
            // Tell the supplier how many are needed: its low-water refill
            // alone would never stock a request needing more than that.
            self.demand.fetch_max(n, Ordering::SeqCst);
        }
        while self.supplier.load(Ordering::SeqCst) && self.is_wanted() && self.pool_len() < n && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        self.demand.store(0, Ordering::SeqCst);
        let mut pool = self.pool.lock().unwrap();
        let k = n.min(pool.len());
        let at = pool.len() - k;
        pool.split_off(at).into_iter().rev().collect()
    }

    /// Match the interactions `collab` recorded since the last call (cheap
    /// every frame: only new ones are looked at). Returns the issues proved.
    pub fn match_new(&self, collab: &CollaboratorState) -> Vec<ScanIssue> {
        let fresh = collab.interactions_since(self.seen.load(Ordering::SeqCst));
        let Some(last) = fresh.last().map(|i| i.id) else { return Vec::new() };
        self.seen.store(last, Ordering::SeqCst);
        self.match_interactions(&fresh)
    }

    /// Match interactions against the pending ids. A check that names its
    /// own issue (SMTP header injection, XML injection, OS command
    /// injection) waits for one interaction of its kind. The plain
    /// external-interaction probe raises one issue per interaction type, as
    /// Burp does ("External service interaction (DNS)" and "(HTTP)", high,
    /// certain), so its id stays pending until both have been seen.
    pub fn match_interactions(&self, interactions: &[Interaction]) -> Vec<ScanIssue> {
        let mut issues = Vec::new();
        let mut pending = self.pending.lock().unwrap();
        if pending.is_empty() {
            return issues;
        }
        let mut reported = self.reported.lock().unwrap();
        for it in interactions {
            let Some(token) = &it.token else { continue };
            let kind = it.kind().label();
            // "CNAME": a DNS lookup of type CNAME, which only the injected
            // `nslookup -q=cname` makes (burp.Zing.ZR: DNS and type 5).
            let cname = it.dns().is_some_and(|d| d.qtype == 5);
            let fits = |k: &str| k == kind || (k == "CNAME" && cname);
            let Some(pos) = pending.iter().position(|(t, k, _)| t == token && k.is_none_or(fits)) else {
                // An OS-command id that saw some other interaction (an A
                // lookup, an HTTP fetch): Burp reports External service
                // interaction for it (burp.Zfw7.Zr: not Zing.ZR -> Zuet.ZJ)
                // and keeps waiting for the CNAME.
                if let Some(p) = pending.iter().find(|(t, k, _)| t == token && *k == Some("CNAME")) {
                    if (kind == "DNS" || kind == "HTTP") && reported.insert(format!("{token}|{kind}")) {
                        let mut issue = p.2.clone();
                        issue.name = format!("External service interaction ({kind})");
                        issue.sev = "high".into();
                        issue.confidence = "Certain".into();
                        issue.type_id = 0;
                        issue.detail = format!(
                            "The nslookup payload's Collaborator id {token} received a {kind} interaction: {} (source {}).",
                            it.headline(),
                            it.source
                        );
                        issues.push(issue);
                    }
                }
                continue;
            };
            if pending[pos].1.is_some() {
                let (_, _, mut issue) = pending.remove(pos);
                issue.detail = format!("Collaborator interaction observed: {} (source {})", it.headline(), it.source);
                issues.push(issue);
                continue;
            }
            if !reported.insert(format!("{token}|{kind}")) {
                continue;
            }
            let mut issue = pending[pos].2.clone();
            issue.name = format!("External service interaction ({kind})");
            issue.sev = "high".into();
            issue.confidence = "Certain".into();
            issue.detail = format!(
                "It is possible to induce the application to perform server-side {kind} interactions with an arbitrary domain. The payload {token} was submitted and a {kind} interaction was received: {} (source {}).",
                it.headline(),
                it.source
            );
            issues.push(issue);
            if reported.contains(&format!("{token}|DNS")) && reported.contains(&format!("{token}|HTTP")) {
                pending.remove(pos);
            }
        }
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_hands_out_what_there_is_and_waits_only_when_asked() {
        let oob = OobState::default();
        oob.stock((0..3).map(|i| (format!("t{i}"), format!("t{i}.oast.test"))));
        let t0 = Instant::now();
        assert_eq!(oob.take(5, Duration::from_secs(5)).len(), 3, "short pool: what is there, no wait without a supplier");
        assert!(t0.elapsed() < Duration::from_secs(1));
        oob.set_supplier(true);
        oob.want(true);
        let t0 = Instant::now();
        assert!(oob.take(2, Duration::from_millis(200)).is_empty());
        assert!(t0.elapsed() >= Duration::from_millis(150), "an asked supplier gets its time");
        let mut n = 0;
        oob.refill(10, 20, || {
            n += 1;
            (format!("m{n}"), format!("m{n}.oast.test"))
        });
        assert_eq!(oob.pool_len(), 20);
        oob.refill(10, 20, || unreachable!("above the low mark: no refill"));
        assert_eq!(oob.take(4, Duration::ZERO).len(), 4);
        // A request needing more than the pool holds (16 of 30): the waiting
        // take's demand makes the next refill stock enough.
        let o2 = std::sync::Arc::new(OobState::default());
        o2.set_supplier(true);
        o2.want(true);
        o2.stock((0..16).map(|i| (format!("s{i}"), String::new())));
        let taker = { let o = o2.clone(); std::thread::spawn(move || o.take(30, Duration::from_secs(5)).len()) };
        while o2.demand.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut k = 0;
        o2.refill(10, 20, || {
            k += 1;
            (format!("r{k}"), String::new())
        });
        assert_eq!(taker.join().unwrap(), 30, "the demand was stocked");
    }
}
