# ADR 0001: Architecture hardening and whether to split into more crates

Status: proposed. Date: 2026-11-19.

## Context

WebProbe is a workspace of two packages: `webprobe-core` (77 modules, ~64k lines, no UI dependency) and
`webprobe` (the egui desktop app, ~16k lines). A review of the open PRs and a comparison against common
Rust architecture guidance found gaps in error handling, shared state, file size and tooling. This ADR
records the measurements, the options for splitting the code into more crates, and a prioritised plan.

Measurements (grep/awk/cargo on `parity/2026-11-17`; counts include tests unless stated):

| Measure | Value |
|---|---|
| `.unwrap()` calls (core + app) | ~1,900, of which ~650 are `lock().unwrap()` |
| `Result<_, String>` signatures | 115; no `thiserror`/`anyhow` |
| Public fields on `net::Shared` / on the app's `App` | 77 / 198 |
| `thread::spawn` calls / async runtime in core | 139 / none |
| Files over 4,000 lines | `net.rs` 6,033, `scan.rs` 5,549, `ui.rs` 4,715, `scan_checks.rs` 4,424 |
| `clippy` warnings in `webprobe-core` | 82 (63 auto-fixable) |
| `cargo fmt --check` diff hunks in core | ~2,800 (code uses long lines; no `rustfmt.toml`) |
| CI / `rustfmt.toml` / `clippy.toml` / `deny.toml` | none |
| Strongly connected component in non-test `crate::` imports | **23 modules** (see below) |

The 23-module cycle is: `codec, collaborator, cookie_jar, ext_calls, ext_host, ext_process, ext_store,
h2, history, interactsh, intruder, macros, net, oob, project, scan, scan_config, scan_library, scan_run,
stored, tasks, upstream, ws_repeater`. `net` alone imports 32 modules and is imported by 33.

## Research summary

- Workspaces suit crates that ship together; a pure core crate with no I/O or UI is the usual shape
  ([reintech](https://reintech.io/blog/rust-project-structure-best-practices-large-applications)).
  matklad recommends a flat `crates/` directory with a virtual manifest for projects of roughly 10k to 1M
  lines ([Large Rust Workspaces](https://matklad.github.io/2021/08/22/large-rust-workspaces.html)).
  ripgrep is a root binary plus library crates under `crates/`
  ([deepwiki](https://deepwiki.com/BurntSushi/ripgrep/2-architecture)); its layout has changed over versions.
- Splitting a crate mainly helps incremental rebuilds, because only changed crates and their dependents
  recompile; incremental compilation applies to workspace members and path dependencies
  ([Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html?highlight=incremental),
  [corrode](https://corrode.dev/blog/tips-for-faster-rust-compile-times/)). It helps little when edits land in a
  foundational crate that everything depends on, and split points should follow invalidation boundaries,
  found with `cargo build --timings`. Codegen-unit splitting hurts inlining
  ([PingCAP](https://www.pingcap.com/blog/rust-huge-compilation-units/)). The speed-up percentages quoted
  by blogs are anecdotal.
- Typed errors in libraries and `anyhow` in binaries is the common rule
  ([Libraries vs Applications](https://kindatechnical.com/rust/lesson-42-error-handling-strategies-for-libraries-vs-applications.html));
  some argue for designing error types deliberately
  ([stop forwarding errors](https://scour.ing/@emschwartz/p/https://fast.github.io/blog/stop-forwarding-errors-start-designing-them)).
- Avoid mutable globals; pass state in and keep a global only as a thin top-level
  ([Avoid Global Mutable State](https://www.joshka.net/practice/rules/boundary/boundary-avoid-global-mutable-state/)).
- egui: one app-state struct, cheap `update`, slow work on background threads, results over channels drained
  each frame ([egui discussion #4415](https://de.github.com/emilk/egui/discussions/4415)).

Most sources are secondary (blogs, community pages), not official guidance.

## Decision on splitting into more crates

**Direction: more, smaller crates ([M-SMALLER-CRATES](https://microsoft.github.io/rust-guidelines/guidelines/universal/#M-SMALLER-CRATES)
says to err on the side of too many). Timing: do not force a split through the current dependency cycle.
Extract the independent leaf modules now, break the cycle, then extract the rest.**

1. A crate boundary cannot contain a cycle. The 23-module component (`net`, `scan`, `project`, `ext_host`,
   `collaborator`, `intruder`, ...) can only be split by first inverting the dependencies that point back
   at `net`, for example by passing `&Shared` sub-structs or small traits instead of reaching into `net`.
   Until then, any crate split would either fail to compile or just move modules into one large crate.
2. The Microsoft guideline justifies a split by independence ("if a submodule can be used independently,
   its contents should be moved into a separate crate"), not by build speed. Build speed is a secondary
   benefit and the one we can measure. No edit-rebuild timing has been taken yet (a no-op
   `cargo check -p webprobe-core` is 1.6 s; a first check was 36 s including dependencies). Record
   `cargo build --timings` for a typical edit in `scan_checks.rs` and `net.rs` before and after each
   extraction; a slow result is a reason to look at the boundary, not to stop splitting.
3. **Stage A (no cycle work needed).** These modules are already acyclic and mostly leaf-like; they can
   become `crates/webprobe-support` (mime, body, streaming, tls, paths, variations, csp, xss, jwt,
   decoder_ops, rules, seq_bits, compare, retirejs, intercept_rules, logger) and
   `crates/webprobe-report` (report, organizer). Risk is low; benefit is modest.
4. **Stage B (after the cycle is broken).** `webprobe-protocol` (codec, h2, h2_server, upstream, cookie_jar),
   `webprobe-collab` (collaborator, interactsh, oob), `webprobe-scan` (scan, scan_checks, passive_*,
   insertion, crawl, active_checks), `webprobe-proxy` (net, history, intercept, ws_*), and the existing
   core as the glue. Keep the desktop app as the top crate, plus the `webprobe-headless` binary.
5. Use a flat `crates/` layout with a virtual manifest and `[workspace.dependencies]`, per matklad.

Rejected: splitting per Burp tab/tool (the tools share `Shared` and would each need the same cycle fix);
and a micro-crate-per-module layout (more manifests and public-API surface than the team can maintain).

## Prioritised plan

Priority = (Impact + Risk) x (6 - Effort); each 1-5.

| # | Item | I | R | E | Score |
|---|---|---|---|---|---|
| 1 | CI baseline (check, tests build, clippy non-blocking) | 4 | 4 | 1 | 40 |
| 2 | Decide the panic policy: either panics stop the process, or locks tolerate poisoning (see revision 1) | 3 | 4 | 2 | 28 |
| 3 | Fix the 82 clippy warnings, then make clippy blocking | 2 | 2 | 1 | 20 |
| 4 | Extract Stage A crates | 3 | 2 | 3 | 15 |
| 5 | Split the four >4,000-line files | 3 | 2 | 3 | 15 |
| 6 | `[workspace.dependencies]` | 2 | 1 | 1 | 15 |
| 7 | Typed errors in core (`thiserror`), starting at module boundaries | 4 | 3 | 4 | 14 |
| 8 | Adopt `rustfmt.toml` and reformat in one commit | 2 | 1 | 2 | 12 |
| 9 | Break the 23-module cycle; split `Shared` into sub-structs; per-scan state owned by the scan | 5 | 3 | 5 | 8 (gating for Stage B) |

Phases: (1) items 1, 3, 6 and 2; (2) items 5, 4 and 8; (3) item 7 incrementally; (4) item 9 then Stage B.
Item 9 scores low only because of effort; it gates the larger split.

## Revision 1: alignment with the Microsoft Pragmatic Rust Guidelines

Source: [Microsoft Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/) (version 2026.6),
read via the Universal, Project, Correctness, Libraries (interop, UX, resilience, building), Applications and
FFI pages. The Macros, Performance, Documentation, AI, Checklist, FAQ and Changelog pages were not read. The
guidelines say to follow their spirit over the letter, and they point to the
[Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html) (checklist not read in full).
They are written for libraries and Microsoft's practice; WebProbe is a desktop application plus a core library.

What changed in this ADR after reading them:

| Guideline | Finding for WebProbe | Change |
|---|---|---|
| [M-PANIC-IS-STOP](https://microsoft.github.io/rust-guidelines/guidelines/correctness/#M-PANIC-IS-STOP) | The guideline lists `unwrap` on a poisoned lock as a valid panic, and has no blanket ban on `unwrap`. It also says a panic means the program should stop, not continue. WebProbe runs work on ~139 spawned threads and catches panics in places (9 `catch_unwind` uses), so a panicking thread poisons a mutex and the process keeps going. | The original "replace ~650 `lock().unwrap()`" item was too broad. The real defect is the *mixed* policy. Decide one: (a) panics are fatal (`panic = "abort"` or a panic hook that saves the project and exits; remove the `catch_unwind` recovery), or (b) keep going and make locks poison-tolerant. Issue #32 is reworded. |
| [M-SMALLER-CRATES](https://microsoft.github.io/rust-guidelines/guidelines/universal/#M-SMALLER-CRATES), [M-CARGO-WORKSPACE](https://microsoft.github.io/rust-guidelines/guidelines/project/#M-CARGO-WORKSPACE), [M-CRATES-IN-WORKSPACE](https://microsoft.github.io/rust-guidelines/guidelines/project/#M-CRATES-IN-WORKSPACE), [M-CRATES-FLAT-FOLDER](https://microsoft.github.io/rust-guidelines/guidelines/project/#M-CRATES-FLAT-FOLDER) | Prefers many crates, one workspace `Cargo.toml`, crates flat under `crates/`, versions in `[workspace.dependencies]`, shared lints inherited. WebProbe's workspace lives in `app/` and also holds the root package. | Split direction reworded above. Issue #36 extended: root workspace manifest, `crates/` layout, inherited `[workspace.lints]`. |
| [M-ERRORS-CANONICAL-STRUCTS](https://microsoft.github.io/rust-guidelines/guidelines/libs/ux/#M-ERRORS-CANONICAL-STRUCTS), [M-FROM-ERROR](https://microsoft.github.io/rust-guidelines/guidelines/libs/ux/#M-FROM-ERROR), [M-APP-ERROR](https://microsoft.github.io/rust-guidelines/guidelines/apps/#M-APP-ERROR) | Library errors are situation-specific structs (backtrace, optional cause, helper methods), with `From` conversions. Applications may use `anyhow`/`eyre` but should not mix several. `webprobe-core` is a library used by the app and the headless binary. | Issue #34: use situation-specific error structs, not one large enum or `String`; `anyhow` is acceptable only in the two binaries. |
| [M-STATIC-VERIFICATION](https://microsoft.github.io/rust-guidelines/guidelines/universal/#M-STATIC-VERIFICATION), [M-LINT-OVERRIDE-EXPECT](https://microsoft.github.io/rust-guidelines/guidelines/universal/#M-LINT-OVERRIDE-EXPECT) | Compiler lints, clippy (categories at `warn`, priority -1, plus selected restriction lints), rustfmt, cargo-audit, cargo-hack, cargo-udeps, miri as gates; overrides use `#[expect(.., reason)]`. WebProbe has 6 `#[allow]` and 0 `#[expect]`, and none of these gates. | Issues #31 and #33 extended: `[workspace.lints]`, `cargo audit`, `#[expect]` migration. Relevant here because the app handles untrusted network input. |
| [M-LATEST-EDITION](https://microsoft.github.io/rust-guidelines/guidelines/project/#M-LATEST-EDITION), [M-MSRV](https://microsoft.github.io/rust-guidelines/guidelines/project/#M-MSRV) | New crates use the latest stable edition; set an MSRV. Both crates are edition 2021 with no `rust-version`. | New issue. |
| [M-LOG-STRUCTURED](https://microsoft.github.io/rust-guidelines/guidelines/universal/#M-LOG-STRUCTURED), [M-LOG-NOT-PRINT](https://microsoft.github.io/rust-guidelines/guidelines/libs/resilience/#M-LOG-NOT-PRINT) | Production code logs through structured telemetry, not `println!`/`dbg!`. WebProbe has up to 56 `println!`/`eprintln!`/`dbg!` hits (includes inline tests; not separated) and a free-text `shared.log(..)`. | New issue. Low priority; headless CLI output is allowed to print. |
| [M-AVOID-STATICS](https://microsoft.github.io/rust-guidelines/guidelines/libs/resilience/#M-AVOID-STATICS) | Libraries should avoid statics and thread-locals where a consistent view matters. About 31 uses here, reset by hand. | Already covered by issue #38 (`ScanState`). |
| [M-INTEGRATION-TESTS](https://microsoft.github.io/rust-guidelines/guidelines/libs/resilience/#M-INTEGRATION-TESTS), [M-TEST-UTIL](https://microsoft.github.io/rust-guidelines/guidelines/libs/resilience/#M-TEST-UTIL), [M-MOCKABLE-SYSCALLS](https://microsoft.github.io/rust-guidelines/guidelines/libs/resilience/#M-MOCKABLE-SYSCALLS) | Public-API tests live in `tests/`; I/O, clocks and entropy are mockable. 59 core files carry inline `#[cfg(test)]` modules, there is no `core/tests/`, and about 55% of `net.rs` is tests. | Issue #35 extended: move tests out of the large files. |
| [M-UNSAFE](https://microsoft.github.io/rust-guidelines/guidelines/correctness/#M-UNSAFE), [M-UNSAFE-IMPLIES-UB](https://microsoft.github.io/rust-guidelines/guidelines/correctness/#M-UNSAFE-IMPLIES-UB) | `unsafe` needs a valid reason and justification. There are 3 `unsafe` blocks (two `mmap`-related in `body.rs` and `project.rs`, one in `main.rs`) and 2 `SAFETY` comments in total. | Add `// SAFETY:` comments and `clippy::undocumented_unsafe_blocks`; folded into #33. |
| [M-DONT-LEAK-TYPES](https://microsoft.github.io/rust-guidelines/guidelines/libs/interop/#M-DONT-LEAK-TYPES), [M-AVOID-WRAPPERS](https://microsoft.github.io/rust-guidelines/guidelines/libs/ux/#M-AVOID-WRAPPERS), [M-PUBLIC-DEBUG](https://microsoft.github.io/rust-guidelines/guidelines/universal/#M-PUBLIC-DEBUG) | Prefer std types in public APIs; avoid `Arc`/`RefCell` in them; public types implement `Debug`, sensitive ones with redaction. `Shared` exposes `Arc<rustls::ClientConfig>` and 77 public fields. | Fold into #38 (the `Shared` split) and note that CA keys and session cookies need redacting `Debug`. |
| [M-SERVICES-CLONE](https://microsoft.github.io/rust-guidelines/guidelines/libs/ux/#M-SERVICES-CLONE) | Heavy services should be cheap-`Clone` handles over `Arc<Inner>`. | Matches how `Arc<Shared>` is used; keep it when `Shared` is split. |

Not applicable or low value for WebProbe: FFI rules (no FFI exports); `M-MIMALLOC-APPS` (an optional allocator
change, to be measured, not adopted by default); the async rules (the core is thread-based with no async
runtime, and no change is proposed).

No file-size or line-count rule exists in the guidelines. The large-file item (#35) is justified by review and
merge-conflict cost, and by the tests-in-`src/` guidance, not by a rule.

## Consequences

CI starts red-free by running checks that pass today (clippy is non-blocking until item 3). The split is
deferred until measurements justify it. The `.cargo/config.toml` in the repo pins a machine-local `rustc`,
`sccache` and `ld.lld-22`; CI and fresh clones must override them (see `.github/workflows/ci.yml`).
