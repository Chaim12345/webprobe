//! Async Phase 1 (issue #42): one tokio runtime on its own dedicated
//! thread; the scanner/intruder engine submits futures to it while the UI
//! and proxy code stay synchronous (the bridging pattern,
//! <https://tokio.rs/tokio/topics/bridging>).
//!
//! - [`probe_pool`] builds a `tokio::sync::Semaphore`, the resource pool
//!   bounding in-flight probes: it replaces the ad-hoc per-scan worker
//!   thread counts.
//! - Cancellation is cooperative for started blocking work. Abort can
//!   prevent a queued blocking body from starting, but cannot interrupt one
//!   already running. Existing atomic stop checks end those bodies.
//! - Results flow back over `tokio::sync::mpsc` channels, drained per
//!   frame by the egui side (see `intruder_run::RunState::drain_rows`).
//!
//! Constraints from the issue: `std::sync::Mutex` stays (the critical
//! sections are short and never held across an `.await`, so no
//! `tokio::sync::Mutex` is needed), and extension hooks (BCheck /
//! ext_host closures) run inside `tokio::task::spawn_blocking`, never on
//! a runtime thread.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// The process-wide engine runtime.
pub struct EngineRt {
    handle: tokio::runtime::Handle,
}

static ENGINE: OnceLock<EngineRt> = OnceLock::new();

/// The engine runtime, started on first use and owned by the process (it
/// never shuts down, like the proxy listener).
pub fn engine() -> &'static EngineRt {
    ENGINE.get_or_init(EngineRt::start)
}

impl EngineRt {
    fn start() -> EngineRt {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build the engine runtime");
        let handle = rt.handle().clone();
        std::thread::Builder::new()
            .name("engine-rt".into())
            .spawn(move || rt.block_on(std::future::pending::<()>()))
            .expect("spawn the engine runtime thread");
        EngineRt { handle }
    }

    /// Submit a future to the engine runtime.
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.handle.spawn(future)
    }

    /// Submit a blocking engine body (a scan run) as one runtime task
    /// (issue #42): the body runs in `tokio::task::spawn_blocking`, never
    /// on a runtime thread, so extension hooks (BCheck / ext_host
    /// closures) stay off the runtime too. `stop` mirrors the tool's
    /// existing cancel flag: once it reports true the task's
    /// `JoinHandle` is aborted. Abort may cancel a body that has not started;
    /// it does not interrupt a running blocking body. The wrapper awaits
    /// that body's completion, which depends on its own cooperative stop
    /// checks and any in-flight blocking calls returning. A panic is contained
    /// and raised as a notice (panic policy "contain and continue",
    /// issue #32).
    pub fn spawn_engine<F, S>(&self, name: &'static str, stop: S, f: F)
    where
        F: FnOnce() + Send + 'static,
        S: Fn() -> bool + Send + 'static,
    {
        self.handle.spawn(async move {
            let mut body = tokio::task::spawn_blocking(f);
            loop {
                tokio::select! {
                    r = &mut body => {
                        if let Err(e) = r {
                            if e.is_panic() {
                                crate::notice::toast(
                                    crate::notice::Level::Warn,
                                    format!(
                                        "engine task '{name}' panicked; the thread ended, the session continues"
                                    ),
                                );
                            }
                        }
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(25)) => {
                        if stop() {
                            body.abort();
                            let _ = body.await;
                            break;
                        }
                    }
                }
            }
        });
    }
}

/// One run's probe pool (issue #42): a `tokio::sync::Semaphore` bounding
/// how many probes are in flight at once, replacing the ad-hoc per-scan
/// worker-thread count.
#[derive(Clone)]
pub struct ProbePool {
    sem: Arc<tokio::sync::Semaphore>,
    limit: usize,
}

/// A probe pool with `limit` in-flight slots (never zero).
pub fn probe_pool(limit: usize) -> ProbePool {
    ProbePool {
        sem: Arc::new(tokio::sync::Semaphore::new(limit.max(1))),
        limit: limit.max(1),
    }
}

impl ProbePool {
    /// Wait for a free in-flight slot: a probe task's abort point, so an
    /// aborted probe is cancelled before any side effect.
    pub async fn acquire(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.sem
            .clone()
            .acquire_owned()
            .await
            .expect("the probe pool is never closed")
    }

    /// The configured in-flight bound.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// The pool caps in-flight probes and every queued probe runs.
    #[test]
    fn probe_pool_caps_in_flight() {
        let pool = probe_pool(3);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicUsize::new(0));
        let mut set = tokio::task::JoinSet::new();
        let rt = engine();
        let (tx, rx) = std::sync::mpsc::channel();
        rt.spawn(async move {
            for _ in 0..20 {
                let (pool, in_flight, max_seen, done) = (
                    pool.clone(),
                    in_flight.clone(),
                    max_seen.clone(),
                    done.clone(),
                );
                set.spawn(async move {
                    let _permit = pool.acquire().await;
                    tokio::task::spawn_blocking(move || {
                        let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        max_seen.fetch_max(n, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(20));
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        done.fetch_add(1, Ordering::SeqCst);
                    })
                    .await
                    .unwrap();
                });
            }
            while set.join_next().await.is_some() {}
            tx.send((max_seen, done)).unwrap();
        });
        let (max_seen, done) = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("probes finished");
        assert_eq!(done.load(Ordering::SeqCst), 20, "every probe ran");
        assert!(max_seen.load(Ordering::SeqCst) <= 3, "pool bound held");
    }

    /// The body has definitely started, and must return by observing Stop.
    /// The channel acknowledgement proves early exit, not merely that a late
    /// side effect has not happened yet. Unpark avoids timing-based setup.
    #[test]
    fn started_engine_body_stops_cooperatively_before_its_deadline() {
        let stop = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (ended_tx, ended_rx) = std::sync::mpsc::channel();
        let (poll_stop, body_stop) = (stop.clone(), stop.clone());
        engine().spawn_engine(
            "cooperative-test",
            move || poll_stop.load(Ordering::SeqCst),
            move || {
                started_tx.send(std::thread::current()).unwrap();
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                while std::time::Instant::now() < deadline {
                    if body_stop.load(Ordering::SeqCst) {
                        ended_tx.send("cooperative stop").unwrap();
                        return;
                    }
                    std::thread::park_timeout(Duration::from_secs(30));
                }
                let _ = ended_tx.send("natural deadline");
            },
        );
        let body_thread = started_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("body started");
        stop.store(true, Ordering::SeqCst);
        body_thread.unpark();
        assert_eq!(
            ended_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("started body exited early"),
            "cooperative stop"
        );
    }
}

#[cfg(test)]
mod owner_blocking_evidence {
    use super::*;
    use crate::owner_protocol::{Completion, ControlResult, Submission};
    use crate::scan_lifecycle::{Coordinator, Finish, Handoff};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    const WAIT: Duration = Duration::from_secs(5);
    struct Release(Option<mpsc::Sender<()>>);
    impl Release {
        fn release(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }
    impl Drop for Release {
        fn drop(&mut self) {
            self.release();
        }
    }
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .max_blocking_threads(1)
            .build()
            .unwrap()
    }
    fn setup() -> (Arc<crate::net::Shared>, Arc<Coordinator>) {
        let shared = crate::net::Shared::new();
        let c = Coordinator::new(
            shared.clone(),
            crate::scan_budget::Limits {
                duration: Duration::from_secs(20),
                http_attempts: 10,
                connection_attempts: 10,
                outgoing: 65536,
                response: 65536,
                decompressed: 65536,
                inputs: 65536,
                evidence: 65536,
                evidence_records: 10,
                records: 10,
            },
        )
        .unwrap();
        (shared, c)
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
    fn replacement(c: &Arc<Coordinator>, shared: &crate::net::Shared) {
        let b = c.open_standalone().unwrap();
        let Handoff::Finalize(f) = b.finish().unwrap() else {
            panic!("finalizer")
        };
        let count = AtomicUsize::new(0);
        assert_eq!(
            f.run(|_| {
                count.fetch_add(1, Ordering::SeqCst);
                Finish::Complete
            }),
            Finish::Complete
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(!shared.scan.is_busy());
        assert!(!shared.stored.in_batch());
    }
    #[test]
    fn blocking_receipt_positive_enters_actual_finalizer_callback_once() {
        let rt = runtime();
        let (shared, c) = setup();
        let (audit, legacy, _) = c.admit_standalone(item()).unwrap();
        let retained = crate::scan_lifecycle::ExecutionContext::Legacy(legacy).cancel_handle();
        let (submission, receipt) = Submission::new(audit);
        let body = Arc::new(AtomicUsize::new(0));
        let a4 = Arc::new(AtomicUsize::new(0));
        let (bc, ac) = (body.clone(), a4.clone());
        let job = rt.spawn_blocking(move || {
            submission.run_with_finalizer(
                || {
                    bc.fetch_add(1, Ordering::SeqCst);
                    Finish::Complete
                },
                |_| {
                    ac.fetch_add(1, Ordering::SeqCst);
                    Finish::Complete
                },
            )
        });
        rt.block_on(async {
            tokio::time::timeout(WAIT, job).await.unwrap().unwrap();
        });
        assert_eq!(
            receipt.recv_timeout(WAIT).unwrap(),
            Completion::Terminal(Finish::Complete)
        );
        assert_eq!(body.load(Ordering::SeqCst), 1);
        assert_eq!(a4.load(Ordering::SeqCst), 1);
        assert_eq!(retained.aggregate().unwrap().outcome, Finish::Complete);
        assert!(shared.scan.wait_idle(Some(WAIT)));
        replacement(&c, &shared);
    }
    #[test]
    fn queued_blocking_abort_awaits_cancel_and_never_enters_body_or_finalizer() {
        let rt = runtime();
        let (shared, c) = setup();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        // Declared after runtime, so unwind releases the worker before runtime teardown.
        let mut release = Release(Some(release_tx));
        let blocker = rt.spawn_blocking(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(WAIT).expect("blocker released");
        });
        entered_rx
            .recv_timeout(WAIT)
            .expect("first worker owns sole blocking slot");
        let (audit, legacy, _) = c.admit_standalone(item()).unwrap();
        let retained = crate::scan_lifecycle::ExecutionContext::Legacy(legacy).cancel_handle();
        let (submission, receipt) = Submission::new(audit);
        let body = Arc::new(AtomicUsize::new(0));
        let a4 = Arc::new(AtomicUsize::new(0));
        let (body_count, a4_count) = (body.clone(), a4.clone());
        let queued = rt.spawn_blocking(move || {
            submission.run_with_finalizer(
                || {
                    body_count.fetch_add(1, Ordering::SeqCst);
                    Finish::Complete
                },
                |_| {
                    a4_count.fetch_add(1, Ordering::SeqCst);
                    Finish::Complete
                },
            )
        });
        queued.abort();
        release.release();
        let result = rt.block_on(async {
            tokio::time::timeout(WAIT, queued)
                .await
                .expect("abort completion bounded")
        });
        assert!(result.unwrap_err().is_cancelled());
        rt.block_on(async {
            tokio::time::timeout(WAIT, blocker).await.unwrap().unwrap();
        });
        assert_eq!(receipt.recv_timeout(WAIT).unwrap(), Completion::Abandoned);
        assert_eq!(body.load(Ordering::SeqCst), 0);
        assert_eq!(a4.load(Ordering::SeqCst), 0);
        let aggregate = retained.aggregate().unwrap();
        assert_eq!(aggregate.outcome, Finish::Incomplete);
        assert!(aggregate
            .reasons
            .contains(&crate::owner_protocol::Reason::Abandoned));
        assert!(shared.scan.wait_idle(Some(WAIT)));
        replacement(&c, &shared);
    }
    #[test]
    fn started_blocking_abort_does_not_interrupt_and_actual_shared_wake_cancels_exact_owner() {
        let rt = runtime();
        let (shared, c) = setup();
        let batch = c.open_standalone().unwrap();
        let control = batch.control().unwrap();
        let context = batch.context();
        let retained = context.cancel_handle();
        let (audit, _, _) = c.admit_in(&batch, item()).unwrap();
        let (submission, receipt) = Submission::new(audit);
        let (wake_tx, wake_rx) = mpsc::channel();
        let weak = Arc::downgrade(&shared);
        let callback_context = context.clone();
        let callback_control = control.clone();
        shared.set_waker(Arc::new(move || {
            let shared = weak.upgrade().unwrap();
            let before = callback_context.validate(&shared);
            let result = callback_control.cancel();
            let after = callback_context.validate(&shared);
            wake_tx
                .send((before.is_ok(), result, after.is_err()))
                .unwrap();
        }));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (continue_tx, continue_rx) = mpsc::channel();
        let mut release = Release(Some(continue_tx));
        let (after_abort_tx, after_abort_rx) = mpsc::channel();
        let running_shared = shared.clone();
        let a4 = Arc::new(AtomicUsize::new(0));
        let a4_count = a4.clone();
        let denied = Arc::new(AtomicUsize::new(0));
        let denied_count = denied.clone();
        let running = rt.spawn_blocking(move || {
            submission.run_with_finalizer(
                || {
                    entered_tx.send(()).unwrap();
                    continue_rx
                        .recv_timeout(WAIT)
                        .expect("started body released");
                    // Reached only after main aborts the JoinHandle. Abort did not interrupt us.
                    after_abort_tx.send(()).unwrap();
                    running_shared.log("owner runtime evidence body notification");
                    assert!(context.validate(&running_shared).is_err());
                    denied_count.fetch_add(1, Ordering::SeqCst);
                    Finish::Incomplete
                },
                |_| {
                    a4_count.fetch_add(1, Ordering::SeqCst);
                    Finish::Complete
                },
            )
        });
        entered_rx.recv_timeout(WAIT).unwrap();
        running.abort();
        assert!(!running.is_finished());
        release.release();
        rt.block_on(async {
            tokio::time::timeout(WAIT, running)
                .await
                .unwrap()
                .expect("started blocking body completes normally despite abort");
        });
        after_abort_rx.recv_timeout(WAIT).unwrap();
        assert_eq!(
            wake_rx.recv_timeout(WAIT).unwrap(),
            (true, ControlResult::Applied, true)
        );
        assert_eq!(denied.load(Ordering::SeqCst), 1);
        assert_eq!(receipt.recv_timeout(WAIT).unwrap(), Completion::Joined);
        assert_eq!(a4.load(Ordering::SeqCst), 0);
        let Handoff::Finalize(f) = batch.finish().unwrap() else {
            panic!("finalizer")
        };
        assert_eq!(
            f.run(|_| {
                a4.fetch_add(1, Ordering::SeqCst);
                Finish::Complete
            }),
            Finish::Incomplete
        );
        assert_eq!(a4.load(Ordering::SeqCst), 0);
        assert_eq!(retained.aggregate().unwrap().outcome, Finish::Incomplete);
        assert!(shared.scan.wait_idle(Some(WAIT)));
        shared.set_waker(Arc::new(|| {}));
        replacement(&c, &shared);
        assert_eq!(control.cancel(), ControlResult::Closed);
    }
}
