// Poison-tolerant lock wrappers.
//
// With std's Mutex, a panic on any thread that holds a lock poisons it, and
// every later `.lock().unwrap()` panics too: one failed worker (a scan check,
// a proxy connection) would take the UI thread down with it. The state behind
// these locks is plain data that stays usable after an interrupted update, so
// these wrappers hand the guard out directly, as parking_lot does. Call sites
// write `lock()` rather than `lock().unwrap()`, and a poisoned lock is
// recovered (with a notice) instead of propagating a panic.
//
// The guard types stay `std::sync::MutexGuard`/`RwLock*Guard`, so `Condvar`
// keeps working with them.

use std::sync::{PoisonError, RwLockReadGuard, RwLockWriteGuard};

pub use std::sync::MutexGuard;

fn notify_poison() {
    crate::notice::toast(
        crate::notice::Level::Warn,
        "recovered a poisoned lock: a thread panicked while holding it (state may be partially written)",
    );
}

fn recovered<T>(poisoned: PoisonError<T>) -> T {
    notify_poison();
    poisoned.into_inner()
}

#[derive(Default)]
pub struct Mutex<T>(std::sync::Mutex<T>);

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Mutex(std::sync::Mutex::new(value))
    }

    /// The guard, recovering a poisoned lock.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(recovered)
    }

    /// The guard when the lock is free, `None` when it is held.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        match self.0.try_lock() {
            Ok(guard) => Some(guard),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                notify_poison();
                Some(self.0.lock().unwrap_or_else(recovered))
            }
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    pub fn into_inner(self) -> T {
        self.0.into_inner().unwrap_or_else(recovered)
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The reader-writer counterpart, with the same poison recovery.
#[derive(Default)]
pub struct RwLock<T>(std::sync::RwLock<T>);

impl<T> RwLock<T> {
    pub const fn new(value: T) -> Self {
        RwLock(std::sync::RwLock::new(value))
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.0.read().unwrap_or_else(recovered)
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.0.write().unwrap_or_else(recovered)
    }

    pub fn into_inner(self) -> T {
        self.0.into_inner().unwrap_or_else(recovered)
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::{Mutex, RwLock};
    use std::sync::Arc;

    #[test]
    fn a_panic_while_holding_the_lock_does_not_poison_it() {
        let shared = Arc::new(Mutex::new(vec![1, 2]));
        let worker = shared.clone();
        let result = std::thread::spawn(move || {
            let mut guard = worker.lock();
            guard.push(3);
            panic!("worker failed while holding the lock");
        })
        .join();
        assert!(result.is_err(), "the worker must have panicked");
        // std's Mutex would make this unwrap panic; the data is still there.
        assert_eq!(*shared.lock(), vec![1, 2, 3]);
        shared.lock().push(4);
        assert_eq!(shared.lock().len(), 4);
    }

    #[test]
    fn a_panic_while_holding_the_write_lock_does_not_poison_it() {
        let shared = Arc::new(RwLock::new(1));
        let worker = shared.clone();
        let result = std::thread::spawn(move || {
            let mut guard = worker.write();
            *guard = 2;
            panic!("worker failed while holding the write lock");
        })
        .join();
        assert!(result.is_err());
        assert_eq!(*shared.read(), 2);
        *shared.write() = 3;
        assert_eq!(*shared.read(), 3);
    }

    #[test]
    fn try_lock_is_none_while_the_guard_is_held() {
        let m = Mutex::new(1);
        let guard = m.lock();
        assert!(m.try_lock().is_none(), "the lock is held on this thread");
        drop(guard);
        assert_eq!(*m.try_lock().expect("free after the guard drops"), 1);
    }
}
