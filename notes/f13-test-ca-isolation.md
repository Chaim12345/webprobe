# AR-01/F13 — test CA isolation audit (pin `692f0972`, parity/2026-11-17)

Branch `goal/f13-test-ca-isolation-20261125`, parent `692f09728039884c59a676ff314879c06dcb1cf5`.

## Defect (reproduced before any change)

`Shared::new()` (`app/core/src/net/shared.rs`) builds its `MitmAuthority` via
`MitmAuthority::new()`. `new()` gates the in-memory CA on `cfg!(test)`
(`app/support/src/tls.rs`), but `cfg!(test)` is false for the support crate when
it is a dependency. Consequences:

- `webprobe-core` unit tests (`--lib`) compile the core lib with `cfg(test)`,
  but the support crate is still compiled without it, so the 61 `Shared::new()`
  call sites in `net::tests` resolved the real default CA directory.
- Integration test binaries (`app/core/tests/*.rs`) compile both crates without
  `cfg(test)` and hit `default_ca_dir()` = `$WEBPROBE_CA_DIR`, else
  `$XDG_CONFIG_HOME/webprobe`, else `~/.config/webprobe`.

Reproduction (isolated `HOME`/`XDG_CONFIG_HOME`, sentinel at the default path,
no `WEBPROBE_CA_DIR`):

| run | sentinel after |
| --- | --- |
| `cargo test -p webprobe-core --lib net::tests` (77 passed) | mutated → real CA JSON written |
| `cargo test -p webprobe-core --test session_contracts` (25 passed) | mutated |
| single test `net::tests::connect_intercepts_https_with_a_ca_signed_host_certificate` | mutated |
| single test `net::tests::client_certificate_presented_to_mtls_server` | mutated |
| support `--lib tls::` (4 passed, explicit temp dirs) | unchanged |

With `WEBPROBE_CA_DIR` exported, the same single test left the sentinel
unchanged and wrote `ca.json` (0600) into the override dir — the override was
already honored; nothing forced test runs to use one.

Negative fixture on the unpatched tree (`ca_isolation.rs` copied into a
`692f0972` worktree):

```
test child_loads_ca ... ok
test integration_test_binary_leaves_the_default_user_ca_untouched ... FAILED
test explicit_ca_dir_is_honored_and_default_sentinel_untouched ... ok
test result: FAILED. 2 passed; 1 failed; ...
assertion `left == right` failed: a test run wrote the default user CA sentinel
```

## Fix (CA-scoped, no TLS/transport changes)

- `app/support/src/tls.rs`: add `MitmAuthority::in_memory()` (delegates to
  `load_or_create(None)`); `new()` unchanged for production.
- `app/core/src/net/shared.rs`: `Shared::new()` uses `in_memory()` under
  `#[cfg(test)]`, `MitmAuthority::new()` otherwise.
- `app/core/tests/{session_contracts,pipeline_matrix,intruder_baseline}.rs`:
  every `Shared::new()` goes through a local `shared()` helper that sets
  `WEBPROBE_CA_DIR` to a per-process temp dir once (17/7/4 call sites).
- `app/core/tests/ca_isolation.rs`: negative fixture. Runs the sibling
  `session_contracts` binary with isolated HOME/XDG and no `WEBPROBE_CA_DIR`
  and asserts the sentinel is untouched; also asserts the override dir is used
  with mode 0600. Comparisons use length+mtime+non-crypto digest only — no CA
  content is read into output.

## Post-fix results (fixed worktree, isolated HOME/XDG, no `WEBPROBE_CA_DIR`)

| command | result |
| --- | --- |
| `cargo test -p webprobe-support --lib tls::` | 4 passed, 0 failed |
| `cargo test -p webprobe-core --lib net::tests` | 77 passed, 0 failed |
| `cargo test -p webprobe-core --test session_contracts` | 25 passed, 0 failed |
| `cargo test -p webprobe-core --test pipeline_matrix` | 7 passed, 0 failed |
| `cargo test -p webprobe-core --test intruder_baseline` | 4 passed, 0 failed |
| `cargo test -p webprobe-core --test ca_isolation` | 3 passed, 0 failed |
| `cargo check -p webprobe-core --lib` (non-test) | ok |

Sentinel (`$XDG_CONFIG_HOME/webprobe/ca.json`, contents `FINAL-SENTINEL`)
sha256 identical before and after the four real suites plus `net::tests`.

Parallel isolation: three concurrent `cargo test` runs with distinct
`WEBPROBE_CA_DIR` each produced their own `ca.json`; no cross-writes.

## Environment / limitations

- Toolchain `/workspace/toolchain/rust-1.100.0`; repo `.cargo/config.toml`
  references `/usr/local/bin/sccache` and `/usr/local/bin/rustc`, which do not
  exist in this sandbox, so the shims in
  `.openhands/evidence/pr163-fbd3b91/env.sh` are required.
- `target/` kept outside the repo (`CARGO_TARGET_DIR`) to bound disk.
- Unverified: Windows/macOS path behavior; GUI CA flows in
  `app/src/proxy_settings.rs` (retire/import) were read but not executed
  (needs GUI); a full `cargo test --workspace` was not run (bounded scope).
- Overlap note: another session's fixture
  (`goal/f9-intercept-disconnect-20261125`, `notes/f9-intercept-disconnect.md`)
  reportedly ran under the sandbox default HOME; it was not rerun here and its
  artifacts were not touched.
