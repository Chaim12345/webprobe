//! Fixed-capacity resolver prototype. Experimental fixtures only.
//! A timed-out OS lookup may finish inside a fixed worker, never a new thread
//! per caller. Production integration must use one process-wide instance.
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

const WORKERS: usize = 2;
const QUEUED: usize = 8;
const ADDRESSES: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResolveError {
    InvalidInput,
    Busy,
    Expired,
    Unavailable,
}
struct Job {
    host: String,
    port: u16,
    deadline: Instant,
    response: mpsc::SyncSender<Result<Vec<SocketAddr>, ResolveError>>,
}
pub(crate) struct Resolver {
    tx: mpsc::SyncSender<Job>,
}
type Lookup = dyn Fn(&str, u16) -> Result<Vec<SocketAddr>, ResolveError> + Send + Sync;
impl Resolver {
    fn with_lookup(lookup: Arc<Lookup>) -> Result<Self, ResolveError> {
        let (tx, rx) = mpsc::sync_channel::<Job>(QUEUED);
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..WORKERS {
            let rx = rx.clone();
            let lookup = lookup.clone();
            std::thread::Builder::new()
                .name("scanner-dns".into())
                .spawn(move || loop {
                    let job = {
                        let guard = rx.lock().unwrap_or_else(|p| p.into_inner());
                        guard.recv()
                    };
                    let Ok(job) = job else { break };
                    if Instant::now() >= job.deadline {
                        let _ = job.response.try_send(Err(ResolveError::Expired));
                        continue;
                    }
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        lookup(&job.host, job.port)
                    }))
                    .unwrap_or(Err(ResolveError::Unavailable));
                    let result = if Instant::now() >= job.deadline {
                        Err(ResolveError::Expired)
                    } else {
                        result.and_then(|items| {
                            if items.len() > ADDRESSES {
                                Err(ResolveError::Unavailable)
                            } else {
                                Ok(items)
                            }
                        })
                    };
                    let _ = job.response.try_send(result);
                })
                .map_err(|_| ResolveError::Unavailable)?;
        }
        Ok(Self { tx })
    }
    pub fn resolve(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> Result<Vec<SocketAddr>, ResolveError> {
        if host.is_empty() || host.len() > 253 || host.bytes().any(|b| b.is_ascii_control()) {
            return Err(ResolveError::InvalidInput);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ResolveError::Expired);
        }
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .try_send(Job {
                host: host.into(),
                port,
                deadline,
                response: tx,
            })
            .map_err(|e| match e {
                mpsc::TrySendError::Full(_) => ResolveError::Busy,
                mpsc::TrySendError::Disconnected(_) => ResolveError::Unavailable,
            })?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ResolveError::Expired);
        }
        rx.recv_timeout(left).map_err(|e| match e {
            mpsc::RecvTimeoutError::Timeout => ResolveError::Expired,
            mpsc::RecvTimeoutError::Disconnected => ResolveError::Unavailable,
        })?
    }
}
pub(crate) fn process_resolver() -> Result<&'static Resolver, ResolveError> {
    static RESOLVER: std::sync::OnceLock<Result<Resolver, ResolveError>> =
        std::sync::OnceLock::new();
    RESOLVER
        .get_or_init(|| {
            Resolver::with_lookup(Arc::new(|host, port| {
                (host, port)
                    .to_socket_addrs()
                    .map(|i| i.take(ADDRESSES + 1).collect())
                    .map_err(|_| ResolveError::Unavailable)
            }))
        })
        .as_ref()
        .map_err(|e| *e)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    #[test]
    fn saturation_does_not_spawn_per_timeout_or_start_expired_queued_lookup() {
        let (release_tx, release_rx) = mpsc::channel();
        let release = Arc::new(Mutex::new(release_rx));
        let (started_tx, started_rx) = mpsc::channel();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let pool = Resolver::with_lookup(Arc::new(move |_, _| {
            c.fetch_add(1, Ordering::SeqCst);
            started_tx.send(()).unwrap();
            release.lock().unwrap().recv().unwrap();
            Ok(vec!["127.0.0.1:80".parse().unwrap()])
        }))
        .unwrap();
        for _ in 0..WORKERS {
            assert_eq!(
                pool.resolve(
                    "blocked.test",
                    80,
                    Instant::now() + Duration::from_millis(15)
                ),
                Err(ResolveError::Expired)
            );
            started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        }
        for _ in 0..QUEUED {
            assert_eq!(
                pool.resolve("queued.test", 80, Instant::now() + Duration::from_millis(2)),
                Err(ResolveError::Expired)
            );
        }
        assert_eq!(
            pool.resolve("overflow.test", 80, Instant::now() + Duration::from_secs(1)),
            Err(ResolveError::Busy)
        );
        assert_eq!(count.load(Ordering::SeqCst), WORKERS);
        for _ in 0..WORKERS {
            release_tx.send(()).unwrap();
        }
        drop(pool); // Workers drain expired jobs and then terminate.
    }
    #[test]
    fn bounded_input_results_and_singleton_positive_control() {
        let pool = process_resolver().unwrap();
        assert!(std::ptr::eq(pool, process_resolver().unwrap()));
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            pool.resolve("", 80, deadline),
            Err(ResolveError::InvalidInput)
        );
        assert_eq!(
            pool.resolve(&"a".repeat(254), 80, deadline),
            Err(ResolveError::InvalidInput)
        );
        assert!(!pool.resolve("127.0.0.1", 80, deadline).unwrap().is_empty());
        assert_eq!(
            pool.resolve("127.0.0.1", 80, Instant::now()),
            Err(ResolveError::Expired)
        );
    }
    #[test]
    fn lookup_panic_does_not_kill_fixed_worker_capacity() {
        let n = Arc::new(AtomicUsize::new(0));
        let count = n.clone();
        let pool = Resolver::with_lookup(Arc::new(move |_, _| {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("injected resolver panic")
            }
            Ok(vec!["127.0.0.1:80".parse().unwrap()])
        }))
        .unwrap();
        assert_eq!(
            pool.resolve("test", 80, Instant::now() + Duration::from_secs(1)),
            Err(ResolveError::Unavailable)
        );
        assert!(pool
            .resolve("test", 80, Instant::now() + Duration::from_secs(1))
            .is_ok());
    }
}
