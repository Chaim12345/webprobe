//! Test scaffolding shared by the core integration binaries.
//!
//! These suites need a `Shared`, not a CA on disk: the CA is generated in
//! memory, so no test reads or writes the default user CA, nothing is left
//! behind if a constructor panics, and no process-global environment is
//! mutated (a parallel harness shares `environ` with every other thread).

use std::sync::Arc;
use webprobe_core::net::Shared;

/// A `Shared` on an in-memory CA.
pub fn shared() -> Arc<Shared> {
    Shared::with_ca_dir(None).expect("Shared on an in-memory test CA")
}
