# AR-01/F13 — test CA isolation: finding evidence vs. fix (source-level)

Pin `692f09728039884c59a676ff314879c06dcb1cf5` (`parity/2026-11-17`).
Branch `goal/f13-test-ca-isolation-20261125`, PR #239.

This note has two strictly separated halves. **Part A is evidence about the
unpatched pin** and was produced by running tests before any change. **Part B
describes the proposed fix and is unqualified**: the source was corrected after
the original runs, and no test, build, check or clippy run has been performed on
the corrected source. Nothing in Part B is a verified result.

---

## Part A — Original finding evidence (unpatched `692f0972`)

### Environment (exactly as used)

| item | value |
| --- | --- |
| worktree (pinned) | `/workspace/wt-f13-692f097` at `692f0972`, branch created from it |
| second worktree for the negative run | `/workspace/wt-f13-base` at `692f0972` (removed after use) |
| toolchain | `/workspace/toolchain/rust-1.100.0` — cargo 1.100.0 (3acc79c0c 2026-11-05), rustc 1.100.0 (0ef1bc386 2026-11-09) |
| env shims | `/workspace/project/webprobe/.openhands/evidence/pr163-fbd3b91/env.sh` (`CARGO_BUILD_RUSTC_WRAPPER=`, linker `gcc`, `RUSTFLAGS=-C incremental=false`) |
| target dirs | `/workspace/f13-692f097-target`, `/workspace/f13-692f097-target-base` (removed) |
| fake HOMEs | `/workspace/f13-ca-test-20261125/home`, `home2`, `final-home`, `dbg`, `dbg2` |
| receipts | `/workspace/f13-ca-test-20261125/` + `MANIFEST.sha256` (45 entries, hashes of logs only) |

`app/.cargo/config.toml` pins `/usr/local/bin/rustc` and `/usr/local/bin/sccache`,
which do not exist in this sandbox; every command below ran with the shims above.

### Defect, as observed

`Shared::new()` (`app/core/src/net/shared.rs`) built its authority with
`MitmAuthority::new()`. `new()` skips the on-disk CA only under `cfg!(test)`
(`app/support/src/tls.rs`), which is **false for the support crate when it is a
dependency**. So `webprobe-core` unit tests and all integration binaries fell
through to `default_ca_dir()` = `$WEBPROBE_CA_DIR`, else
`$XDG_CONFIG_HOME/webprobe`, else `$HOME/.config/webprobe`.

### Sentinel runs (isolated HOME/XDG, sentinel `ca.json` at the default path, no `WEBPROBE_CA_DIR`)

| command (all `--locked --offline -p webprobe-core`) | result | sentinel |
| --- | --- | --- |
| `--lib net::tests` | 77 passed, 0 failed, exit 0 | **mutated** |
| `--test session_contracts` | 25 passed, 0 failed, exit 0 | **mutated** |
| `--lib net::tests::connect_intercepts_https_with_a_ca_signed_host_certificate` | 1 passed | **mutated** |
| `--lib net::tests::client_certificate_presented_to_mtls_server` | 1 passed | **mutated** |
| `-p webprobe-support --lib tls::` | 4 passed, 0 failed | unchanged (explicit temp dirs) |

Control: with `WEBPROBE_CA_DIR` exported, the single-test run left the sentinel
unchanged and wrote `ca.json` (mode 0600) into the override directory. The
override was already honoured; nothing forced a test to use it.

Receipts: `net-tests-full.log` (`7ab94ba5…`), `int-session.log` (`92981035…`),
`per-test-writer.txt` (`291c204f…`), `parallel-isolation.txt` (`31a47151…`).

### Negative fixture against the unpatched pin

The fixture (then a sibling-binary check) was copied into the `692f0972`
worktree and run:

```
test child_loads_ca ... ok
test integration_test_binary_leaves_the_default_user_ca_untouched ... FAILED
test explicit_ca_dir_is_honored_and_default_sentinel_untouched ... ok
test result: FAILED. 2 passed; 1 failed; ...
assertion `left == right` failed: a test run wrote the default user CA sentinel
```

Receipts: `base-ca-isolation.log` (`3974cd58…`), `base-fixture-summary.txt`
(`485b2963…`).

### Caveats on Part A

- The sentinel was synthetic; no real user CA was read into evidence and no CA
  content appears in this note or in any receipt.
- Three concurrent runs with distinct `WEBPROBE_CA_DIR` produced three distinct
  `ca.json` files (`parallel-isolation.txt`), which is consistent with
  contention on the shared default path but does not prove a race.
- These runs are **not** the PR200 workspace/Chromium/UI gate and do not stand in
  for it.

---

## Part B — Proposed fix (unqualified; no run performed on this source)

### G) No global environment mutation

Removed: the per-binary `shared()` helpers that called `unsafe { set_var("WEBPROBE_CA_DIR", …) }`
inside a parallel harness. `set_var` mutates the process-wide `environ`, which
every other test thread shares, and the helper also overwrote a caller's own
`WEBPROBE_CA_DIR`.

Added, as explicit injection:

- `app/support/src/tls.rs` — `MitmAuthority::in_memory()` (delegates to
  `load_or_create(None)`); `new()` unchanged, so production still resolves
  `default_ca_dir()`.
- `app/core/src/net/shared.rs` — `Shared::new()` now delegates to a private
  `with_authority(mitm)`; new `Shared::with_ca_dir(Option<PathBuf>)` loads or
  creates `dir/ca.json`, or keeps the CA in memory for `None`.
- `app/core/tests/test_support/mod.rs` (new) — `shared()` builds a `Shared` on a
  freshly created, exclusively owned temp CA directory (`create_dir`, so an
  existing path is an error rather than a reuse), then removes only that
  directory after the CA is in memory. No environment access.
- `app/core/tests/{session_contracts,pipeline_matrix,intruder_baseline}.rs` —
  `mod test_support; use test_support::shared;` replaces the local helper
  (17 / 7 / 4 call sites). `net/intercept.rs`, `net/engine.rs` and
  `h2_server.rs` were not touched; nothing was adopted from the ccr branch.

### H) Deterministic, bounded fixture

`app/core/tests/ca_isolation.rs` rewritten:

- binds to `std::env::current_exe()` — this exact current-build binary — and
  re-executes it with `--exact child_injects_explicit_ca_dir`. No profile-tree
  scan, no stale-binary selection.
- fails closed: spawn failure, non-zero exit, missing `test result: ok. 1 passed`,
  missing `cases=` count, or a count other than 2 all panic. There is no skip
  path.
- child safety: `try_wait` poll loop with a 120 s deadline, then `kill()` +
  `wait()`; stdout/stderr go to files inside the owned root (no `Command::output`,
  no pipes, no deadlock); stdin is null.
- temp directories: `OwnedDir` with a non-PID-reuse name
  (`wp-f13-case-<pid>-<nanos>`), created with `create_dir` and removed on drop —
  a pre-existing path is an error, never deleted.
- inherited markers: the child runs its body only when `WP_F13_CHILD` is set, and
  then requires the `f13-` prefix, a matching owned root name, a CA directory
  under that root and a CA directory that does not already exist — all validated
  **before** any `Shared` is constructed.
- the parent asserts the sentinel fingerprint (length + mtime + non-crypto
  digest, no content) is unchanged and that the injected CA file is mode 0600.

Runtime proof is deliberately absent: the corrected source has not been compiled
or executed.

### Coverage inventory (what the fix does and does not cover)

| entrypoint | CA used after the fix | covered? |
| --- | --- | --- |
| `app/core/src/**` unit tests (`--lib`, incl. `net/tests.rs` 61 sites, `scan/tests.rs`, `scan_lifecycle.rs`, `request_reader_tests.rs`, …) | `cfg(test)` in-memory branch of `Shared::new()` | yes |
| `app/core/tests/session_contracts.rs`, `pipeline_matrix.rs`, `intruder_baseline.rs` | injected temp CA dir | yes |
| `app/core/tests/ca_isolation.rs` | injected dir + in-memory (child) | yes |
| `app/core/tests` any future file using `Shared::new()` | **default user CA** (cfg(test) false) | no — must use `test_support::shared()` |
| `app/src/**` tests (`tools.rs` 9, `ui/tests.rs` 8, `repeater_ops.rs` 4 sites) | **default user CA** — app crate tests compile core as a dependency, so `cfg(test)` is false | **no — outside this PR's files** |
| `app/core/examples/{extension_drop_probe,loaded_proxy,proxy_bench}.rs` | **default user CA** (not tests; dev tools) | no — out of scope |
| `app/support/tests`, `app/report/tests` | explicit dirs / no `Shared` | not applicable |

`cfg(test)` in the core library is therefore **not** universal coverage. Closing
the app-crate row needs app-side injection (`Shared::with_ca_dir`) or a
test-only constructor, which is outside the files this PR owns and is left as a
proposal.

### I) Receipts

Part A receipts remain untouched under `/workspace/f13-ca-test-20261125/`
(full files, not truncated); `MANIFEST.sha256` lists them. No CA content is
stored, hashed or printed anywhere.

## Not verified

- Every claim in Part B: no `cargo build`, `test`, `check` or `clippy` was run
  after the correction.
- Windows/macOS path behaviour; GUI CA retire/import flows in
  `app/src/proxy_settings.rs` (read only, needs GUI); full workspace test run.
