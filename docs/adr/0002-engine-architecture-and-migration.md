# ADR 0002: Engine architecture and the migration to it

**Status:** Accepted in part on 2026-11-24. The owner asked for the architecture work, then set the order: land the remaining features first, optimise afterwards, and build features so that the later work stays easy. Phase 0 (the gates) is therefore implemented now; phases 1 to 8 start after the feature backlog.
**Date:** 2026-11-24
**Deciders:** project owner
**Relates to:** ADR 0001 (crate split, never merged to parity; lives on `wp-integration-2026-11-19`), `qa/ARCH-REVIEW-2026-11-18.md`, `docs/specs/R-18-decomposition.research.md`, issues #34, #36, #38, #41, #44, tasks AR-01..AR-10 and R-18.

## 1. Context

WebProbe is a single-user desktop tool: one tester, one browser, tens of proxy connections (cap 1,024), a bounded scanner probe pool, and histories that can pass 50,000 rows. It ships as an egui desktop app and a headless binary from one Cargo workspace (`app/`: desktop package at the root, `core`, `support`, `report`; about 86,000 lines).

The architecture was repaired once already. The L1-L8 hardening merged on 19-20 November and the module graph was acyclic at `4cddee0`. Four days of feature merges brought the cycle back, because nothing in CI checks it. That history sets the first rule of this plan: a property that is not gated does not last.

### Measurements on `parity/2026-11-17` at `e7a2f8d`

| Measure | Value | Source |
|---|---|---|
| Module cycles in core | one of 10 modules (`bcheck, crawl, ext_host, host_probe_state, net, scan, scan_config, scan_lifecycle, scan_resolver, tasks`) and one of 2 (`h2_group, send_group`) | `scripts/module-cycles.py app/core/src` |
| References that hold the cycle together | `net -> bcheck` 3, `net -> host_probe_state` 3, `send_group -> h2_group` 4, `host_probe_state -> scan` 5, `crawl -> scan` 9, `scan -> bcheck` 10, `scan_lifecycle -> net` 16 | rust-analyzer LSIF |
| Fields on `net::Shared` | 91: 34 used only by `net` and the UI, 21 used only by `net`, 27 used by exactly one other engine module, 6 by two, `issues` and `oob` by four, `scan` by eight | LSIF |
| `Shared` fields the UI reads or writes directly | 59 | LSIF |
| Engine symbols used by the desktop crate | 1,542 (6,456 references) | LSIF |
| `pub` items in core not used outside their own module | about 548 of 1,221 | LSIF |
| Fields on `App` | 168 | `src/main.rs` |
| Files mounted into `scan` with `#[path]` | 7 (`active_checks, scan_checks, csp, insertion, passive_pack, passive_checks, retirejs`) | `core/src/scan/mod.rs` |
| `thread_local!` sites | 12 | `scripts/arch-gate.py` |
| Thread spawn sites outside tests | 16 (`thread::spawn` 5, `thread::Builder` 11); the engine runtime already has a named spawner, `rt.spawn_engine` | `scripts/arch-gate.py` |
| `thread::sleep` calls outside tests | 33 | `scripts/arch-gate.py` |
| `Result<_, String>` signatures in core, outside tests | 90 (`thiserror` is already a dependency) | `scripts/arch-gate.py` |
| `println!`, `eprintln!`, `dbg!` in core, outside tests | 3 | `scripts/arch-gate.py` |
| `#[allow(...)]` attributes | 32 before phase 0, none after: 23 became `#[expect(.., reason)]` and 9 were stale | clippy |
| `[lints]` or `[workspace.lints]` tables | none before phase 0 | manifests |
| `#[cfg(test)]` on fields, statements and branches inside production code | about 40 sites (`host_probe_state`, `scan_checks/stored_input`, `net/conn_reuse`) | source survey |
| Upward references | engine to UI 0, `support` to core 0, `report` to core 14 | LSIF |

Two things already point the right way and are kept: the engine has a tokio runtime on its own thread (`core/src/rt.rs`) for probe pools, pollers and timers, and the core crate has no UI dependency, enforced by `layering_tests`.

### Requirements

- **Behaviour:** Burp parity work continues during the migration (R-13, R-16, R-19, R-20). The headless binary must do what the desktop app does.
- **Safety of change:** no behaviour change in an architecture PR; every step lands on parity with the full suite green; every step can be reverted alone.
- **Throughput:** several agent lanes work in parallel. Merge conflicts on `net/shared.rs`, `main.rs` and `scan/mod.rs` are the main cost, so the plan limits who touches them at one time.
- **Not required:** horizontal scale, multi-user, high availability. Async everywhere is not a goal.

## 2. Decision

Build a **layered modular monolith with gated boundaries**, reached by small behaviour-neutral steps, in this order: gates, cycle repair, state ownership, lifecycle, then crates.

### 2.1 Layers

Dependencies point downward only. A module may use its own layer's leaf types and anything below.

```
L4  apps        webprobe (egui)        webprobe-headless        REST / CLI
                    |  commands down, events and snapshots up  |
L3  engine      Engine: composition root, Settings snapshot, Lifecycle, event channel
L2  tools       scan (checks, bcheck, crawl, dom)   intruder   repeater / send_group
                ext (host, process)   collab (collaborator, interactsh, oob)   project   tasks
L1  proxy       net: listeners, connection pipeline, send path, intercept, history, session, upstream
L0  protocol    codec, h2, h2_server, hpack, tls, body      support crate      report types
```

The decisive change is that **the composition root leaves `net`**. Today `net::Shared` holds scanner, BCheck and host-probe state, so the proxy layer names the layers above it and every tool reaches back into `net`. In the target, `Engine` (L3) owns the subsystems and `net` knows only its own state plus hook traits it defines and upper layers implement (the pattern `net/scan_hooks.rs` and `scan::register_scan_hooks` already use).

### 2.2 State

```
Engine
 ├─ settings:  one immutable Settings value, swapped whole (RwLock<Arc<Settings>>);
 │             compiled rule sets live inside it, built when it is written
 ├─ proxy:     ProxyState        the 21 net-only fields, private to net
 ├─ scan:      ScanState         scan-owned fields, BCheck definitions, host admission, issues
 ├─ tools:     repeater, intruder, organizer, ws repeater: each owns its fields
 ├─ ext:       extension registry and hooks
 ├─ collab:    oob and Collaborator state
 ├─ lifecycle: cancellation, named joinable threads, shutdown
 └─ events:    one bounded channel to the UI
```

How the 91 fields move: the 34 used only by `net` and the UI become `Settings` (after checking each is configuration and not runtime state); 21 stay private in `ProxyState`; 27 move into the one engine module that uses them; the remaining 9 are assigned an owner and reached through that owner's API.

### 2.3 Concurrency

Hybrid, as it already is. Proxy connections stay on blocking threads. The tokio runtime in `rt.rs` keeps probe pools, pollers and timers and gains the lifecycle. No lock is held across I/O or an `.await`; extension hooks run on blocking threads. Issue #44 (move the proxy loop to tokio) is closed as not planned, with a trigger for reopening in section 6.

Request context travels as an explicit `SendCtx` argument (tool, scan id, budget, cancellation), replacing the 12 thread-locals.

### 2.4 Errors, logging, panics

Typed errors (`thiserror`) on functions that cross a layer boundary, converted as each phase touches them; strings only at the UI edge. Structured `tracing` events with redaction replace console prints in core. The panic policy stays "contain and continue" (decided in #32); this is a deliberate deviation from the Microsoft guideline M-PANIC-IS-STOP and is recorded here so reviewers stop reopening it.

### 2.5 Engine to UI

The UI sends commands and reads snapshots and events. It does not lock engine fields. This is reached by ratchet, not by a rewrite: the count of `Shared` fields and engine symbols the UI touches may only go down.

## 3. Options considered

| | A. Gates only | **B. Layered monolith, incremental (chosen)** | C. Crate split first | D. Async rewrite (#44) | E. Actor per subsystem |
|---|---|---|---|---|---|
| Complexity | Low | Medium | High | Very high | High |
| Risk to parity work | None | Low per step | High: blocked by the cycle | High | High |
| Fixes the regression cause | Stops growth only | Yes | Yes, after B's work anyway | No | Yes |
| Cost | S | M to L, spread over many PRs | L up front | XL | L to XL |

- **A** stops the graph getting worse and is phase 0 of B. Alone it leaves the 91-field object and the missing lifecycle in place.
- **C** is ADR 0001's Stage B. A crate boundary cannot contain a cycle, so it needs the same repair first and adds manifest and path churn before any benefit. It becomes the last phase of B.
- **D** has no measured gain: the 18 November review found the pipeline is blocking I/O plus CPU work at Burp-like concurrency, and the roadmap records a benchmark (#88, not re-run for this ADR) showing no regression either way.
- **E** would change the semantics of 6,456 UI references at once and cannot be done behaviour-neutrally.

## 4. Migration plan

Rules for every phase: PRs are mechanical and behaviour-neutral; each merges to parity with `cargo fmt --check`, clippy `-D warnings` and `cargo test --workspace --locked` green through `wp-queue`; each tightens a gate so the gain cannot be lost; only one architecture lane edits `net/shared.rs` at a time. Feature work continues beside it and must pass the same gates.

| Phase | Work | Tasks and issues | Size | Exit check (becomes a CI gate) |
|---|---|---|---|---|
| **0. Gates** | (a) `module-cycles.py`: add a check mode that fails when a cycle grows or a new one appears, and fail on "0 modules" (run from `app/` it finds nothing and prints "no cycles" with exit 0). (b) `[workspace.lints]` in all four manifests; `#[allow]` becomes `#[expect(..., reason)]`. (c) A ratchet script with a committed baseline for the counts in section 1. (d) Run all three in `workspace.yml`. (e) Owner turns on branch protection for parity. | AR-01 (lints part) | S | CI fails on a larger cycle or a higher count |
| **1. Cycle repair** | Fold `h2_group` into `send_group` as a submodule. Move `scan_dedup_of` and the helpers `crawl` and `host_probe_state` take from `scan` into a leaf module. Register BCheck through the check registry so `scan` stops naming `bcheck`. Move `BcheckDefsCache` and `HostAdmission` behind types `net` can hold without importing upward (final home comes in phase 4). Give `scan_lifecycle` its own state instead of `Shared`. Turn the seven `#[path]` mounts into real `scan/` submodules. Narrow unused `pub` to `pub(crate)`, one module per PR, with the compiler as the judge. | #38 (first half) | M | Zero cycles; gate baseline set to zero |
| **2. Engine duties out of the UI** | Move Collaborator supply and matching, the Logger mirror, project capture and restore, and extension tool sends from `App::ui` into core. Can run beside phase 1: it edits `src/`, phase 1 edits `core/`. | AR-02 | M | Headless and desktop produce the same results on the scan lab test |
| **3. Settings snapshot and send context** | Introduce `Settings`; move the confirmed configuration fields in batches of about ten; compile rules when settings are written. Then add `SendCtx` and remove thread-locals one at a time. | AR-03 (first half), AR-04, AR-01 (rule sets) | M | `Shared` at or below 57 fields; thread-locals 0 |
| **4. Split `Shared` into `Engine`** | Create `Engine` above `net`. Move the 27 single-owner fields to their owners first (cheapest, least contention), then the shared nine, then rename what is left to `ProxyState`. `Shared` stays as a thin forwarding type until the last caller is gone, so there is no flag day. | AR-03 (second half), R-18 (engine half), #38 (second half) | L | `net` has no reference to L2; UI direct field count below its baseline |
| **5. Lifecycle and scanner pool** | `Engine::spawn(name, ...)` registers every thread; cancellation token; shutdown joins. Replace sleep polling where a condvar or channel exists. Bounded passive-check queue off the proxy thread. Read the five unmerged `team/owner-*` branches (scanner owner and lifecycle protocol, 2,200 to 2,700 lines each, 117 commits behind) and either port them here or close them. | AR-05, AR-06 | L | No unnamed spawn; clean shutdown test; sleep count down |
| **6. Errors and logging** | Typed errors on the send path, `project` and scan boundaries; `tracing` events with redaction. | #34, #41 | M | `Result<_, String>` and print counts fall each PR; core prints 0 |
| **7. Engine to UI data flow** | One event channel, append-only history view, bytes instead of lossy text in tool state, `App` split into per-tool view structs following the R-18 research. | AR-07, AR-09, R-18 (UI half) | L | `App` fields and UI symbol count below baselines |
| **8. Crates** | Move to a flat `crates/` layout in one commit at a moment with no other open PR, then extract `webprobe-protocol` first, then collab and scan, each only when the layer gate shows no upward edge and `cargo build --timings` shows a rebuild gain. Decide whether `report` keeps its 14 references into core or the shared types move down. | #36 (layout; the shared-dependency half is done), ADR 0001 Stage B | M per crate | Each new crate builds alone |

Independent of the sequence: AR-08 (sidecar reply routing, before R-20) and AR-10.

**Changes from the order proposed in the handoff.** The `crates/` layout moves from second to last: it renames every path used by CI, `wp-queue`, scripts, task evidence and Craft targets, and buys nothing until a new crate exists. AR-02 is added as phase 2, because the 18 November review ranks it first and it is still open.

### Risk and rollback

| Risk | Mitigation |
|---|---|
| The graph regresses again | Phase 0 lands first and is required in CI; baselines only move down |
| Merge conflicts with feature lanes | One lane on `net/shared.rs`; small PRs; moves separated from edits |
| A "mechanical" move changes behaviour | No logic edits in move PRs; full suite plus the lab parity tests per PR |
| `Settings` snapshot changes when a setting takes effect | Read the snapshot once per request, as the fields are read today; note any field whose timing matters before moving it |
| Lock order changes when fields move | Use section 4 of the R-18 research (functions locking two or more fields) as the checklist for phase 4 |
| Box contention makes results untrustworthy | All cargo runs through `wp-queue`; at most two architecture lanes at once |

Every PR reverts alone. There is no long-lived migration branch.

### Rules for feature work until phase 1 starts

These keep the later phases cheap. The gate enforces the first three.

1. No new module cycle and no new member in an existing one. A scanner check registers itself with the check registry; `net` and `scan` do not name it.
2. No new field on `net::Shared` or `App`. State a feature needs lives in a type the feature's module owns, held by one existing field or by its caller.
3. No new thread-local, bare `thread::spawn`, sleep poll, `Result<_, String>` or console print in core. Use `rt.spawn_engine`, a channel or condvar, a `thiserror` enum and `tracing`.
4. No test-only branch inside a production function (`#[cfg(test)]` on a statement or field). Inject the difference through a parameter or a trait.
5. A suppression is `#[expect(lint, reason = "..")]`, never `#[allow]`.

## 5. Consequences

- **Easier:** headless parity, adding a scanner check or a tool without touching `net`, testing a subsystem without building all 91 fields, later crate extraction.
- **Harder:** a feature PR that adds a cross-layer shortcut now fails CI and has to add a hook or an API instead.
- **Accepted cost:** phases 4, 5 and 7 are large and will slow parity work on the files they touch.

## 6. Revisit when

- More than a handful of long-lived bidirectional streams need multiplexing: add a small tokio island for relays (reopens part of #44).
- Project saves become slow or history passes about 50,000 rows before phase 7: bring the append-only history forward.
- A crate extraction shows no rebuild gain in `--timings`: stop extracting.

## 7. Not verified

- Function-level dead-code and test-only-code numbers: the LSIF script mis-sizes functions. Redo with `rust-code-mcp` before phase 5 uses them.
- The `pub` narrowing count is approximate; the compiler decides per item.
- Which of the 34 "net and UI" fields are configuration and which are runtime state.
- The content of the `team/owner-*` branches and benchmark #88 were not read for this ADR.
- `cargo-modules --acyclic` was tried and is not usable as the cycle gate (it fails on a type and its own method).

## 8. Action items

1. [ ] Owner: approve, amend or reject this ADR, and say whether phases 1 and 2 may run in parallel.
2. [ ] Phase 0 PR: cycle gate, lints, ratchet baseline, CI step.
3. [ ] Owner: protect `parity/2026-11-17`.
4. [ ] Phase 1 PRs, smallest edge first (`send_group`/`h2_group`, then the two `net` fields).
5. [ ] Close #44 with a link to section 2.3 once approved.
6. [ ] Mirror the phases into `tasks.json` and the Craft plan once approved.
