//! Test scaffolding shared by the core integration binaries.
//!
//! `Shared` is built on an explicitly injected CA directory, never through the
//! process-global environment: a parallel harness shares `environ` with every
//! other thread, so `set_var` from a test is both unsound and able to clobber
//! a caller's own `WEBPROBE_CA_DIR`.

use std::sync::Arc;
use webprobe_core::net::Shared;

/// A `Shared` on a freshly created, exclusively owned CA directory. The CA is
/// read into memory, so the directory is removed before returning: no test
/// reads or writes the default user CA and nothing is left behind.
pub fn shared() -> Arc<Shared> {
    let dir = unique_ca_dir();
    let shared = Shared::with_ca_dir(Some(dir.clone())).expect("Shared on a private CA dir");
    let _ = std::fs::remove_dir_all(&dir);
    shared
}

/// `create_dir` (not `create_dir_all`) fails if the path already exists, so a
/// stale directory is never reused or deleted.
fn unique_ca_dir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "wp-ca-{}-{nanos}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).expect("exclusive CA directory");
    dir
}
