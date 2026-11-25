# AR-01/F13 — test CA isolation: finding, historical logs, proposal

Pin `692f09728039884c59a676ff314879c06dcb1cf5` (`parity/2026-11-17`).
Branch `goal/f13-test-ca-isolation-20261125`, PR #239.

Three evidence classes, kept apart on purpose:

- **A. Source-supported finding** — read from the code at the pin. Static, no
  run involved.
- **B. Historical log observations** — from runs at the pin, with the tree state
  named per item. They are log observations, including their own contradictions;
  they are **not** acceptance evidence for the current head.
- **C. Proposal** — the change on this branch. Unqualified: no build, test,
  check or lint has been run on it.

---

## A. Source-supported finding (static, at `692f0972`)

`MitmAuthority::new()` (`app/support/src/tls.rs`) is:

```rust
if cfg!(test) { return Self::load_or_create(None); }
Self::load_or_create(default_ca_dir())
```

`cfg!(test)` is a per-crate flag. It is true only for the crate being compiled
as a test target, so it is **false for `webprobe-support` whenever support is a
dependency** — that is, in every `webprobe-core` unit-test build, every
integration binary, and every app-crate test binary.

`Shared::new()` (`app/core/src/net/shared.rs`) calls `MitmAuthority::new()`
without any gating at this pin, and `default_ca_dir()` resolves
`$WEBPROBE_CA_DIR` → `$XDG_CONFIG_HOME/webprobe` → `$HOME/.config/webprobe`.

So: a test-only caller of `Shared::new()` outside the core crate's own
`cfg(test)` build resolves the default user CA. This part needs no run; it
follows from the two code paths above.

## B. Historical log observations (not current-head acceptance)

Runs were made in a worktree whose HEAD was `692f0972`, with
`/workspace/toolchain/rust-1.100.0` (cargo 1.100.0, rustc 1.100.0), the env
shims in `/workspace/project/webprobe/.openhands/evidence/pr163-fbd3b91/env.sh`
and a `CARGO_TARGET_DIR` outside the repo. Some ran before the fix was applied
to the working tree, others after; each item names its receipt and claims only
what that receipt shows. None of it is acceptance evidence for the current head.

### B.1 Suite counts (post-fix observations, historical)

Recorded after the fix was present in the working tree:

| command | logged result | receipt |
| --- | --- | --- |
| `-p webprobe-core --lib net::tests` | 77 passed, 0 failed | `fix-net.log` |
| `-p webprobe-core --test session_contracts` | 25 passed, 0 failed | `fix-session.log` |
| `-p webprobe-support --lib tls::` | 4 passed, 0 failed | `fix-support.log` |
| `-p webprobe-core --test pipeline_matrix` | 7 passed, 0 failed | `fix-pipeline.log` |
| `-p webprobe-core --test intruder_baseline` | 4 passed, 0 failed | `fix-intruder2.log` |
| `-p webprobe-core --test ca_isolation` | 3 passed, 0 failed | `fix-ca-isolation.log` |

### B.2 Default-path sentinel (recorded before the fix)

With an isolated `HOME`/`XDG_CONFIG_HOME` and a sentinel `ca.json` placed at the
default path, a run of `net::tests` left a real CA document at that path instead
of the sentinel (`net-tests-full.log`). The captured packet contains CA JSON
prefixes (a `key_pkcs8` base64 field plus `not_before`, `not_after`, `serial`),
and sentinel hashing was performed. No content is reproduced here, and no claim
is made that the receipts are free of it.

### B.3 Contradictory baseline, preserved as-is

On the same base worktree two preserved receipts disagree:

- `base-ca-isolation.log` records `3 passed; 0 failed`;
- `base-fixture-summary.txt` records `2 passed; 1 failed`, the failure message
  being "a test run wrote the default user CA sentinel".

Both are kept verbatim. The delta is unresolved: no preserved source or command
sequence explains it, and no explanation is asserted here.

### B.4 Intruder compile record, preserved as-is

`fix-intruder.log` records a compile failure for the edited
`intruder_baseline.rs` (`error[E0425]: cannot find type Shared in this scope`;
`fix-exits.txt` records `intruder=101`). After the repair, `fix-intruder2.log`
records `4 passed; 0 failed`.

### B.5 Wording rules applied to these logs

- Cargo fingerprint suffixes such as `195babd0…` and `43c809e6…` are **build
  paths**, not a cryptographic binding of source or binary. Nothing in this
  note treats them as provenance.
- Differing hashes between runs do **not** by themselves identify which test or
  code path wrote the sentinel.

## C. Proposal (unqualified; no run on this head)

### 1. Unwind-safe child

`app/core/tests/ca_isolation.rs` owns each child in a `ChildGuard` whose `Drop`
calls `kill_and_reap` (kill, then wait). `wait_deadline` polls `try_wait` to a
120 s deadline, reaps on success, and on timeout kills, reaps and returns
`TimedOut`; a `try_wait` error propagates and the guard still reaps on unwind.
The guard is held until the case is finished, then `kill_and_reap` is called
explicitly before `drop(root)`; the owned root is also declared **before** the
guard, so reverse drop order reaps the child first even on unwind. The root is
created with mode 0700 (`restrict_to_owner`) rather than inheriting directory
permissions, and the child re-checks that it is owner-only.

### 2. Strict parent-side and child-side validation

- The parent refuses to launch if **any** ambient f13 marker is present in its
  own environment — any key starting with `WP_F13_`, including ones this fixture
  does not know about, or any value starting with `f13-`: an ambient marker means
  the run is not its own.
- The child requires its `WP_F13_*` key set to be exactly the four it was
  given, so an inherited extra marker fails closed.
- The child must be launched as exactly `--exact child_case --nocapture`; any
  other argument shape is rejected. It also requires a well-formed marker and a
  nonce file at `<root>/.f13-nonce` equal to the marker. That is accidental
  ambient-state protection, not authentication: a process that can write the
  root and set every variable itself can forge all of it.
- The layout is exact and resolved: the owned root must be a direct child of the
  temp directory and owner-only; `HOME` must be `<root>/home`, `XDG_CONFIG_HOME`
  `<root>/home/.config`, and the CA directory `<root>/ca`, rebuilt from the
  resolved root. The CA path must be absent by `NotFound` specifically; a
  symlink or any other error is rejected. All of this runs before any `Shared`
  is constructed.

### 3. `test_support::shared` uses an in-memory CA

`app/core/tests/test_support/mod.rs` is now a single call to
`Shared::with_ca_dir(None)`. There is no directory to own, so a constructor
panic cannot leave CA material behind, and there is no ignored cleanup error.
No `set_var` remains in any file this PR touches.

### 4. Fingerprints

`fingerprint()` returns `len`, `modified`, `digest` and `mode`, and returns
`io::Result`: a failed `stat` fails the test instead of becoming `None`.
`override`, `in_memory` and `default` are three separate child runs, each with
its own owned root and sentinel.

### 5. Case separation and what it does not claim

- `override` — `with_ca_dir(Some(dir))`: the fixture asserts the default
  sentinel is identical before and after (length, mtime, digest, mode) and that
  the injected file's mode is owner-only.
- `in_memory` — `with_ca_dir(None)`: the fixture asserts the same sentinel
  equality and that no CA directory was created.
- `default` — `Shared::new()` in an integration binary: reports
  `default_path=changed|unchanged` from a paired fingerprint of the same file;
  mere existence is never treated as a write, and the result is not asserted
  either way.

This fixture therefore does **not** prove a no-default-read guarantee for the
test suite. It proves the two injected paths avoid the default path and shows
where the residual one still reaches it.

### Coverage inventory

| entrypoint | CA after the change | covered |
| --- | --- | --- |
| `app/core/src/**` unit tests (`--lib`, incl. 61 `Shared::new()` sites in `net/tests.rs`) | `cfg(test)` in-memory branch | yes |
| `app/core/tests/{session_contracts,pipeline_matrix,intruder_baseline}.rs` | `test_support::shared()` → in-memory | yes |
| `app/core/tests/ca_isolation.rs` | injected dir + in-memory, default probed | yes |
| any future `app/core/tests` file calling `Shared::new()` | default user CA | no |
| `app/src/**` tests (`tools.rs` 9, `ui/tests.rs` 8, `repeater_ops.rs` 4) | default user CA — app tests compile core as a dependency | **no, outside this PR** |
| `app/core/examples/*` | default user CA (dev tools, not tests) | no |
| `app/support/tests`, `app/report/tests` | explicit dirs / no `Shared` | not applicable |

## D. Limits

- No `cargo build`, `test`, `check` or `clippy` was run on this head; every
  statement in section C is a code claim, not a result.
- Windows/macOS path behaviour is unverified. GUI CA retire/import flows in
  `app/src/proxy_settings.rs` were read, not executed.
- The historical numbers in section B are log observations at the pin, with the
  tree state named per item, and must not be read as current-head acceptance.
