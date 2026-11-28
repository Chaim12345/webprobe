//! Passive-scan state that spans responses (R-04). Burp keeps it in its
//! per-host state (burp.Zf8t.ZDZ, the `ZE` map of burp.Zirr) for the life
//! of the project; here it lives on `Shared::passive` and is cleared when a
//! project is loaded.
//!
//! What it holds: for each host, the paths forms with password fields post
//! to, the names of those fields, and the last password submitted to each
//! (burp.Zcn0.ZG / Zc / ZW).

use crate::sync::Mutex;
use std::collections::BTreeMap;

/// A password value submitted to a known password field.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Submitted {
    /// The value as sent (raw, not URL-decoded: burp.Zxo6 keeps `Zwwc.ZO`).
    pub value: String,
    /// The request that submitted it, kept as evidence.
    pub request: Vec<u8>,
}

/// host -> form action path -> password field name -> last value.
type Forms = BTreeMap<String, BTreeMap<String, BTreeMap<String, Option<Submitted>>>>;

#[derive(Default)]
pub struct PassiveState {
    forms: Mutex<Forms>,
    /// AR-05: the live-audit queue. Present once a worker is running
    /// (`net::start_passive_worker`); without one, audits run where they
    /// are requested.
    queue: Mutex<Option<std::sync::mpsc::SyncSender<crate::net::HistEntry>>>,
    /// Entries queued or being audited, with the signal for `wait_idle`.
    pending: (std::sync::Mutex<usize>, std::sync::Condvar),
}

/// Entries the live-audit queue holds before the proxy thread audits its
/// own exchange instead (backpressure, never a dropped audit).
pub const LIVE_AUDIT_QUEUE: usize = 256;

/// burp.Zcn0.storePasswordFieldName(String): a value that is likely a real
/// password: 6 characters or more and not one of Burp's placeholders.
fn password_like(v: &str) -> bool {
    v.len() >= 6 && !["password", "script", "javascript"].contains(&v)
}

impl PassiveState {
    /// Install the queue a worker will drain. False when one is already
    /// installed (the receiver is then dropped by the caller).
    pub(crate) fn install_queue(
        &self,
        sender: std::sync::mpsc::SyncSender<crate::net::HistEntry>,
    ) -> bool {
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
    pub(crate) fn enqueue(&self, entry: &crate::net::HistEntry) -> bool {
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

    pub fn clear(&self) {
        self.forms.lock().clear();
    }

    /// A form posting to `host` `path` has a password field `field`
    /// (burp.Zcn0.ZG): remembered without a value unless already known.
    pub(crate) fn note_password_field(&self, host: &str, path: &str, field: &str) {
        let mut f = self.forms.lock();
        f.entry(host.to_string())
            .or_default()
            .entry(path.to_string())
            .or_default()
            .entry(field.to_string())
            .or_insert(None);
    }

    /// A request to `host` `path` with these (name, raw value) parameters
    /// (burp.Zcn0.Zc / ZW): each parameter named like a known password field
    /// records its value when it looks like a password, else clears it.
    /// Returns the passwords this request submitted.
    pub(crate) fn submit(
        &self,
        host: &str,
        path: &str,
        params: &[(String, String)],
        request: &[u8],
    ) -> Vec<Submitted> {
        let mut f = self.forms.lock();
        let Some(fields) = f.get_mut(host).and_then(|h| h.get_mut(path)) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (name, value) in params {
            if let Some(slot) = fields.get_mut(name) {
                if password_like(value) {
                    let s = Submitted {
                        value: value.clone(),
                        request: request.to_vec(),
                    };
                    *slot = Some(s.clone());
                    out.push(s);
                } else {
                    *slot = None;
                }
            }
        }
        out
    }

    /// Every password submitted earlier on `host`, with the path it was
    /// submitted to (burp.Zcn0.ZQ).
    pub(crate) fn submitted_on(&self, host: &str) -> Vec<(String, Submitted)> {
        let f = self.forms.lock();
        f.get(host)
            .map(|paths| {
                paths
                    .iter()
                    .flat_map(|(p, fields)| {
                        fields
                            .values()
                            .flatten()
                            .map(move |s| (p.clone(), s.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AR-05: with no worker an audit is not queued; with one, entries
    /// queue up to the cap, the next one is handed back to the caller, and
    /// `wait_idle` returns once the worker has finished them.
    #[test]
    fn live_audit_queue_hands_back_when_absent_or_full_and_reports_idle() {
        let state = PassiveState::default();
        let entry = crate::net::HistEntry::default();
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

    #[test]
    fn remembers_submitted_passwords_per_host_and_path() {
        let s = PassiveState::default();
        assert!(
            s.submit("h", "/login", &[("pw".into(), "hunter22".into())], b"r")
                .is_empty(),
            "unknown field"
        );
        s.note_password_field("h", "/login", "pw");
        assert!(
            s.submit("h", "/login", &[("pw".into(), "short".into())], b"r")
                .is_empty()
        );
        let got = s.submit(
            "h",
            "/login",
            &[
                ("user".into(), "bob".into()),
                ("pw".into(), "hunter22".into()),
            ],
            b"r",
        );
        assert_eq!(got.len(), 1);
        assert_eq!(
            s.submitted_on("h"),
            vec![("/login".to_string(), got[0].clone())]
        );
        s.note_password_field("h", "/login", "pw");
        assert_eq!(
            s.submitted_on("h").len(),
            1,
            "a known field keeps its value"
        );
        assert!(s.submitted_on("other").is_empty());
        s.clear();
        assert!(s.submitted_on("h").is_empty());
    }
}
