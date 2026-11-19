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

**Do not split into many crates yet. Break the cycle first, then extract in two stages.**

1. A crate boundary cannot contain a cycle. The 23-module component (`net`, `scan`, `project`, `ext_host`,
   `collaborator`, `intruder`, ...) can only be split by first inverting the dependencies that point back
   at `net`, for example by passing `&Shared` sub-structs or small traits instead of reaching into `net`.
   Until then, any crate split would either fail to compile or just move modules into one large crate.
2. Splitting is only worth it where it shortens the edit-compile loop. No edit-rebuild timing has been
   measured yet (a no-op `cargo check -p webprobe-core` is 1.6 s; a first check was 36 s including
   dependencies). Measure `cargo build --timings` for a typical edit in `scan_checks.rs` and `net.rs`
   before and after each extraction, and stop if the gain is not visible.
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
| 2 | Poison-safe lock helper replacing `lock().unwrap()` | 3 | 4 | 2 | 28 |
| 3 | Fix the 82 clippy warnings, then make clippy blocking | 2 | 2 | 1 | 20 |
| 4 | Extract Stage A crates | 3 | 2 | 3 | 15 |
| 5 | Split the four >4,000-line files | 3 | 2 | 3 | 15 |
| 6 | `[workspace.dependencies]` | 2 | 1 | 1 | 15 |
| 7 | Typed errors in core (`thiserror`), starting at module boundaries | 4 | 3 | 4 | 14 |
| 8 | Adopt `rustfmt.toml` and reformat in one commit | 2 | 1 | 2 | 12 |
| 9 | Break the 23-module cycle; split `Shared` into sub-structs; per-scan state owned by the scan | 5 | 3 | 5 | 8 (gating for Stage B) |

Phases: (1) items 1, 3, 6 and 2; (2) items 5, 4 and 8; (3) item 7 incrementally; (4) item 9 then Stage B.
Item 9 scores low only because of effort; it gates the larger split.

## Consequences

CI starts red-free by running checks that pass today (clippy is non-blocking until item 3). The split is
deferred until measurements justify it. The `.cargo/config.toml` in the repo pins a machine-local `rustc`,
`sccache` and `ld.lld-22`; CI and fresh clones must override them (see `.github/workflows/ci.yml`).
