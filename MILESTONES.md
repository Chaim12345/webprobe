# WebProbe review and roadmap milestones

Source of truth for task status: `tasks.json`. Work happens in project-local worktrees under `.worktrees/` and is integrated only after focused verification. Each milestone is sized for one implementation/verification pass.

## M0 — Baseline and preservation

**Status:** done.

- Preserve pre-existing scanner edits and unrelated worktrees.
- Keep all new worktrees in `.worktrees/`; exclude that directory through `.git/info/exclude`.
- Baseline: desktop 136/136 passed; core 543/544 passed. `characterisation_active_scan_issue_list` needs two expected `Spoofable client IP address` rows.
- Record baseline failure before changing behavior; do not suppress it.

## M1 — Robustness fixes

**Status:** implementation and focused verification done (13/13 tests).

Worktree: `.worktrees/fixes`.

- Fix RetireJS non-ASCII filename panic.
- Reject HTTP/2 flow-control window overflow without mutating state.
- Bound project, payload, JWT, CA, catalogue, knowledgebase, RetireJS and seed-file reads.
- Cap runtime payload collection at `MAX_PAYLOADS`.
- Keep regression tests for the oversized project, Unicode input and HTTP/2 overflow.

## M2 — R-07 WebSocket reliability

**Status:** implementation and focused verification done (52/52 tests); desktop/full-suite verification remains.

Worktree: `.worktrees/r07`.

- Import and enable WebSocket Repeater/interception regression suites.
- Fix reconnect generation races, live-attach deadlock and strict hex parsing.
- Enforce mask direction, RSV/control-frame rules and reserved opcode rejection.
- Add both-direction match/replace and bounded batch eviction for history.
- Verify: Repeater, interception release, relay, history and rules suites; then desktop build.

## M3 — R-09 JWT checks

**Status:** done (39/39 focused tests).

Worktree: `.worktrees/scanner`.

- Verify five active and two passive JWT issue types with independent HMAC/RSA oracles.
- Add missing `jku`/`x5u` Collaborator slots.
- Raise the registered JWT issue on their HTTP interactions instead of generic external interaction.
- Update `tasks.json` evidence during integration.

## M4 — R-10 active scanner pack

**Status:** done and integrated; full core 587 passed, 12 ignored, clippy correctness/perf gate passed.

Worktree: `.worktrees/scanner`.

Small slices:

1. Fix scanner characterization and registry contracts for checks added at HEAD.
2. Verify GraphQL active checks; add passive `GraphQL endpoint found` coverage.
3. Add XPath true/false differential detection with regression fixtures.
4. Add in-band web cache poisoning with clean retrieval and cache-busted control.
5. Add web cache deception with stable dynamic baseline and cacheability evidence.
6. Run all scanner/cache/GraphQL tests and the characterization test; only then update R-10 evidence. Do not add timing-only checks.

## M5 — R-11 scan configuration library

**Status:** implemented 2026-11-18 (aa490e8, 09e87f8), compiled with 18 smoke tests; full suite and UI not yet run. Work stopped by the user; unclaimed.

Worktree: `.worktrees/r11`.

Small slices:

1. Parse all 29 BuiltInConfigs with malformed-input tests and a resource resolver.
2. Implement last-write-wins overlay, including selected issue type IDs and insertion settings.
3. Enforce passive-only and selected-issue dispatch in the scanner.
4. Apply crawl time/count limits, strategies and supported audit options; report unsupported settings explicitly.
5. Add selection UI, custom Burp JSON import/export and project persistence.
6. Verify all 29 load, combinations preserve overlay order, passive-only runs no active checks, and custom round-trip.

## M6 — D-12 and R-12 network features

**Status:** paused 2026-11-18 by the user. Branch `wp-m6` (pushed): D-12a SNI probe done (97b41bd); D-12b and R-12 send groups partial (9d7de42, compiles, untested). Unclaimed; resume from that branch.

Worktree: `.worktrees/r07` after M2 integration.

- D-12: custom-SNI sender and traced scheme payload variants with loopback TLS tests.
- R-12: Repeater group model and sequential single/separate-connection sending.
- R-12: HTTP/1 last-byte and HTTP/2 single-packet synchronization with deterministic barriers, not timing-only assertions.
- Verify UI persistence and 20-request synchronization at a local lab.

## M7 — R-15 CLI, configuration and REST

**Status:** done (2026-11-18 evening) by the Instinct task agent on branch `r15/cli-rest` (PR #5, open, not merged): Burp headless CLI flags, project/user options JSON import/export on the CLI and in the desktop Suite > Project file page (scan keys routed through R-11's scan_library), and the loopback /v0.1 REST API (scan start, status, issues). 658 lib + 4 CLI tests pass; options UI screenshot-verified.

Worktree: `.worktrees/r15`.

Small slices: Burp CLI flags; project/user JSON import/export; local scan start endpoint; status/issues endpoints; CLI/REST integration tests. Bind locally by default and never log secrets.

Progress (2026-11-18 evening, Instinct task agent, branch `r15/cli-rest`):
- Burp project options JSON (proxy.request_listeners) and user options JSON (user_options.misc.api) import/export in `core/src/burp_config.rs`, keys per AuditDefaults/UserDefaults where recovered. Scan-configuration JSON deliberately not parsed: R-11 owns the scan configuration model (agreed on PR #5).
- Headless: --config-file/--user-config-file (repeatable, last wins), --project-file, --unpause-spider-and-scanner, --version/--help, --data-dir, --diagnostics.
- /v0.1 REST API (`core/src/rest_api.rs`): POST /v0.1/scan, GET /v0.1/scan/{id} (status + issue_events), GET /v0.1/knowledge_base/issue_definitions. Loopback by default, key as path prefix unless insecure_mode, key never logged, refuses to start keyless. Started by headless proxy mode and the desktop app when api.enabled.
- Desktop: same Burp flags plus --disable-extensions and --temporary-project.
Still open: options export in the UI (Project/User options save), scan-config JSON through R-11's model once it lands, R-15 tasks.json status flip when the milestone closes.

## M8 — R-17 and remaining core behavior

**Status:** pending.

- Add predefined Intruder lists, Collaborator payloads and extension-generated payload/processor wiring.
- Complete remaining non-timing scanner families from `docs/specs/R-10-active-pack.research.md` in separate check-sized milestones.
- R-13: implement browser source-to-sink DOM analysis in independently verifiable source/sink families, starting with `location.hash -> innerHTML`; do not claim all 48 types from one fixture.

## M9 — Extension and scripting tasks

**Status:** pending after core features.

- R-14: BCheck parser/validator/executor and examples.
- R-16: Bambda filters/custom columns using the documented Java-script contract.
- R-20: remaining Montoya APIs and ten additional unmodified BApps, each recorded in `docs/MONTOYA-COVERAGE.md`.

## M10 — R-18 decomposition

**Status:** pending; do after behavior-changing work to avoid conflicts.

- Group `App` and `Shared` by subsystem without behavior changes.
- Split `ui.rs` by tool using existing module conventions.
- Run full suite after each mechanical extraction; no mixed feature edits.

## M11 — R-19 and final verification

**Status:** pending.

- Re-score all 13 tabs against shipped Burp references; drive Logger, Organizer and WebSocket interception through egui MCP.
- Replace `qa/parity-scores-2026-11-15.md` with dated evidence.
- Run focused regressions, full core/desktop suites and `scripts/ci.sh`.
- Reconcile `tasks.json`, investigation plan/handoff and milestone statuses with observed evidence only.
