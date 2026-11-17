//! Repeater's send state (N-07): whether a send is in flight, its
//! generation, the status line, and tab ids. Kept under one lock so a
//! cancelled or superseded send can never overwrite the state of a newer one.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::sync::Mutex;

struct State {
    busy: bool,
    generation: u64,
    result: String,
}

pub struct RepeaterRun {
    state: Mutex<State>,
    next_tab: AtomicU64,
}

impl Default for RepeaterRun {
    fn default() -> Self {
        // Tab 1 exists from the start; new tabs count on from 2.
        RepeaterRun { state: Mutex::new(State { busy: false, generation: 0, result: String::new() }), next_tab: AtomicU64::new(2) }
    }
}

impl RepeaterRun {
    /// A tab id never used before (ids are never reused, so routing a late
    /// response by id cannot hit another tab).
    pub fn new_tab_id(&self) -> u64 {
        self.next_tab.fetch_add(1, Ordering::SeqCst)
    }

    pub fn is_busy(&self) -> bool {
        self.state.lock().unwrap().busy
    }

    /// The status line under the editors.
    pub fn result(&self) -> String {
        self.state.lock().unwrap().result.clone()
    }

    /// A status line without a send (a request that cannot be sent).
    pub fn set_result(&self, line: impl Into<String>) {
        self.state.lock().unwrap().result = line.into();
    }

    /// Start a send: busy, "sending...", and the generation the worker must
    /// still hold when it finishes.
    pub fn begin(&self) -> u64 {
        let mut s = self.state.lock().unwrap();
        s.busy = true;
        s.generation += 1;
        s.result = "sending...".into();
        s.generation
    }

    /// Whether `generation` is still the current send (not cancelled or
    /// superseded).
    pub fn is_current(&self, generation: u64) -> bool {
        self.state.lock().unwrap().generation == generation
    }

    /// Finish the send of `generation` with its status line; ignored (false)
    /// when it was cancelled or superseded meanwhile.
    pub fn finish(&self, generation: u64, line: impl Into<String>) -> bool {
        let mut s = self.state.lock().unwrap();
        if s.generation != generation {
            return false;
        }
        s.busy = false;
        s.result = line.into();
        true
    }

    /// Abandon the in-flight send: the tab is free at once and the late
    /// response, if any, never lands. False when nothing was in flight.
    pub fn cancel(&self) -> bool {
        let mut s = self.state.lock().unwrap();
        if !s.busy {
            return false;
        }
        s.generation += 1;
        s.busy = false;
        s.result = "Request cancelled".into();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancelled_send_cannot_finish() {
        let r = RepeaterRun::default();
        let g = r.begin();
        assert!(r.is_busy() && r.result() == "sending...");
        assert!(r.cancel());
        assert!(!r.is_busy() && r.result() == "Request cancelled");
        assert!(!r.finish(g, "Done"), "late result dropped");
        assert_eq!(r.result(), "Request cancelled");
        assert!(!r.cancel(), "nothing in flight");
        let g2 = r.begin();
        assert!(r.is_current(g2) && !r.is_current(g));
        assert!(r.finish(g2, "Done"));
        assert!(!r.is_busy());
        let (a, b) = (r.new_tab_id(), r.new_tab_id());
        assert!(a >= 2 && b > a);
    }
}
