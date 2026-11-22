// Wake coalescing tests (perf lane, 2026-11-22).
// Every item in this file is test-only code gated by #[cfg(test)] in mod.rs.
use super::*;

#[test]
fn wakes_inside_the_coalescing_window_are_skipped() {
    let shared = Shared::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    shared.set_waker(Arc::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
    }));
    shared.wake();
    shared.wake();
    shared.wake();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a burst of wakes coalesces to one"
    );
    assert_eq!(shared.wakes_coalesced.load(Ordering::SeqCst), 2);
    // After the window the next event wakes the front end again.
    std::thread::sleep(Duration::from_millis(WAKE_COALESCE_MS + 20));
    shared.wake();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn wake_without_a_waker_is_a_no_op() {
    let shared = Shared::new();
    shared.wake();
    assert_eq!(shared.wakes_coalesced.load(Ordering::SeqCst), 0);
}
