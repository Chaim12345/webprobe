# Handoff

## 2026-11-24 night: status (session app-90, still working)

**Owner's goal and order:** finish the roadmap to full Burp parity. Land all features first, optimise the architecture afterwards (ADR 0002, accepted in part), and build features so the later optimisation stays easy. Old remote branches are out of scope. Run tests in the background and keep working. Use the Craft MCP through mcporter, scripted (`qa/craft/`).

**Merged to parity today (after e7a2f8d):** #210 (flaky-test fixes and the corrected Obscura doc), #211 (ADR 0002 phase 0: architecture ratchet, workspace lint policy, issue-coverage gate, Craft client), #212 (six passive checks), #213 (JWK Set disclosure; coverage gate reads run-time names). Parity is `cfdcdae`.

**Scanner coverage (scripts/issue-coverage.py):** 149 of 183 Burp issue types this morning, 158 on parity now, 161 with open PR #214. Craft findings fnd_90 (coverage map) and fnd_91 (two wrong type ids in Burp's KnowledgeBase JSON).

**Open work:**
- PR #214 (`feat/generated-issue-types-20261124`): stored open redirection, extension issues carry type 0x08000000, React2Shell and Bambda type ids corrected. Verified locally; CI running.
- `feat/sql-second-order-20261124` in `.worktrees/feat`: second-order SQL injection (error-based), written with a lab test, verification running.
- Agent lane, `.worktrees/ct`, `feat/content-type-20261124`: Content type incorrectly stated (burp.Zf9p, Zw8c, Zen8, Zhk1). Result not seen yet.
- Agent lane, `.worktrees/vs`, `feat/viewstate-mac-20261124`: ASP.NET ViewState without MAC (burp.Zg3y, Zcnd, Zpqd, Zbdj). Result not seen yet.

**Still to do, from scripts/issue-coverage-baseline.json (each entry has a note):** Suspicious input transformation (reflected, stored); Hidden HTTP 2 (needs a forced-HTTP/2 send); client-side SQL injection x3 and local file path manipulation x3 (DOM; need static analysis or an established sink list); Manually generated issue; Bambda generated issue. Awaiting the owner: the five timing-based code-injection types. Excluded: request smuggling, client-side desync, Browser XSS filter disabled (Burp never raises it).

**After the issue types:** R-13 leftovers, R-16 (Bambda code exists; check against the acceptance text), R-19 UI re-score, AR-08 then R-20, then ADR 0002 phases 1 to 8.

**How to work here (learned today):**
- Never edit `handoff.md` by hand; use `core_handoff_write` (Craft regenerates the file from `state.json`).
- Do not edit a worktree while a cargo job is running in it; the job picks up half-finished edits.
- CI: `#[expect]` is checked on stable only (the 1.95.0 leg allows unfulfilled expectations, because the older compiler flags less dead code); a workflow step name with ": " must be quoted.
- Burp sources: `/root/burp-re/out/readable_strict/root` (main), `cfr_fixed/burp` (enum arguments, static initialisers), `strings/map_merged.tsv` (decoded string constants), `in/extract/net/portswigger/*.class` (decompile with `in/cfr-0.152.jar`). `burp.Zcot` is the issue-type enum; its constructor names each type's text class.
- A feature PR must update `scripts/issue-coverage-baseline.json` with `--update`.

## 2026-11-24 evening: session handoff

### State of the repo

- Parity (`parity/2026-11-17`) is `e7a2f8d`. Hosted CI and Workspace acceptance were green on `6a3b1c9`; `e7a2f8d` adds only the docs PR #209.
- Merged today: #203, #163, #181, #190, #205 (integration of #201, #200, #192, #196), #206, #207, #208, #209.
- Closed as superseded or integrated: #193, #192, #196, #200, #201, #39.
- Issues closed: #31, #32, #33, #35, #37, #40, #42, #43, #204. Open: #173, #44, #41, #38, #36, #34.
- `tasks.json`: 120 done / 15 todo / 2 rejected.
- Working tree is clean on parity apart from this file (uncommitted) and the untracked `.pi/`.

### Open PR: #210 (`fix/flaky-tests-20261124`) - do not merge as is

All required checks pass (the Kilo bot check failed, as it has on every PR today). It contains:
- `crawl.rs`: the DevTools WebSocket handshake gets a 10 s deadline before the 200 ms poll timeout is applied (real product bug), with a regression test.
- `ext_host.rs`: the stage4 JVM test waits for extension output instead of racing the stderr reader.
- `intruder_run.rs` (#173): the pool test counts only requests carrying its marker header and reports foreign connections. Root cause is still a hypothesis: 72 of 72 runs passed under CPU load.
- `docs/parity/2026-11-24-obscura-evaluation.md` and `qa/obscura-eval/`.

**Obscura doc corrected locally, not committed or pushed** (session app-90, 24 Nov). The fix is in the worktree `/tmp/claude-0/-root-Documents-Craft-Anything-burpsuite-app/c38e947a-376e-4cbb-b234-bebffcdaca2d/scratchpad/wt-flaky` (branch `fix/flaky-tests-20261124`): the doc now scopes its verdict to the two DevTools-driven paths in `crawl.rs`, states that `headless.rs` already uses Obscura for the JS crawl (P-16), and adds the proxy result (reproduced: 6 of 6 request classes through the proxy, POST body seen) and the certificate-patch result. New untracked files in `qa/obscura-eval/`: `proxy-egress-probe.py`, `obscura-0.2.7-proxy.json`, `obscura-ignore-cert.patch`. Waiting for the user's go-ahead to commit, push and merge. A reboot clears this worktree. Trap when re-running the certificate test: a server left on the port answers for the new one, and in `probe2.py` only `nav_err` is meaningful.

### Obscura findings (v0.2.7)

- Works over CDP in session mode: page JS, init-script hooks, sink capture, prototype pollution, fetch/XHR, Network events, response bodies, `setBlockedURLs`.
- Gaps for the DevTools-driven paths: no direct page socket from `/json/list`; sub-resource `Fetch` interception is not enforced (scripts and stylesheets still hit the server); no `postData`; no `responseReceivedExtraInfo`; no `setBypassServiceWorker`; rejects untrusted certificates.
- With `--proxy`, all six request classes went through the proxy and none direct, so WebProbe's proxy can supply egress control, POST bodies and raw heads without patching Obscura.
- Patchability: a 13-line certificate patch (`OBSCURA_IGNORE_CERT_ERRORS=1`) is written and builds. Verified on a no-render build against a self-signed loopback target: with the variable unset the navigation fails with `invalid peer certificate`; with `=1` it succeeds. Not tested on the render or stealth builds. Sub-resource interception would need about 200 lines across 13 call sites in `obscura-browser/src/page.rs`.

### Architecture: decision proposed, not yet approved

The user asked for a review, then "decide the best architecture", then asked whether it matches Rust best practice, then asked for proper graph tooling. No approval to implement was given.

- History: the L1-L8 roadmap merged on 19-20 Nov and the module graph was acyclic at `4cddee0`. It regressed to a 7-module cycle by 23 Nov and to 10 modules plus `send_group`/`h2_group` with #205 today. Nothing in CI runs `scripts/module-cycles.py`.
- Proposed target: layered modular monolith, hybrid concurrency (blocking threads for proxy connections, the existing tokio runtime for pools, timers and lifecycle), `Shared` replaced by an `Engine` of owned subsystems plus one `Settings` snapshot, explicit `SendCtx` instead of thread-locals, typed errors at boundaries, CI gates.
- Proposed order: (1) CI gates incl. `[workspace.lints]` and `#[expect]`; (2) flat `crates/` layout (#36); (3) cycle repair and `pub` narrowing; (4) `SendCtx` and settings snapshot; (5) split `Shared`; (6) lifecycle and scanner pool, resolving the test-only code; (7) logging (#41) and typed errors; (8) bytes, event channel, UI split; (9) protocol crate.
- Compiler-accurate evidence (rust-analyzer LSIF, 45,213 symbols, 143,876 references):
  - The cycle is held by few references: `net -> bcheck` 3 (`BcheckDefsCache` field), `net -> host_probe_state` 3 (`HostAdmission` field), `send_group -> h2_group` 4, `host_probe_state -> scan` 5, `crawl -> scan` 9, `scan -> bcheck` 10, `scan_lifecycle -> net` 16.
  - `net::Shared` has 91 fields: 59 touched by the UI crate, 34 used only by net and UI (settings candidates), 21 net-only, 14 owned by a single engine, three shared widely (`scan`, `issues`, `oob`).
  - No references from engine to UI or from support to engine.
  - The UI uses 1,542 distinct engine symbols (6,456 references).
  - About 548 of 1,221 `pub` items in core are unused outside their own module.
  - Six files (`active_checks`, `csp`, `insertion`, `passive_checks`, `passive_pack`, `retirejs`) are mounted into `scan` with `#[path]`.
- Known deliberate deviation from both Rust guideline sets: the "contain and continue" panic policy (#32).
- Seven `#[allow(dead_code)]` added today in the edition-2024 cleanup should become `#[expect]` with reasons.

### Tooling notes

- CodeGraph is initialised in `app/` (`.codegraph/`, excluded via `.git/info/exclude`) but does not resolve `crate::module::function(...)` calls; do not use it for coupling or dead-code questions.
- codebase-memory is indexed (project `root-Documents-Craft-Anything-burpsuite-app`); usable through `mcporter call --stdio "codebase-memory-mcp" ...` for lookups and single-function traces only.
- `rustup component add rust-analyzer` was run on the stable toolchain.
- `rust-code-mcp` is dropped at the user's request (24 Nov). Its build needs an ONNX Runtime download that returns HTTP 403 here; a rebuild against a local 1.24.2 runtime was started and then stopped. Do not pick it up again unless asked. The clone and the runtime under the scratchpad can be deleted.
- `cargo-modules` v0.28.0 is installed (`cargo binstall`). Its `--acyclic` check is not usable as the module-cycle gate: with `--no-fns --no-types --no-traits` it still fails on an item-level cycle (`ai::AiChat` and `AiChat::default`). `scripts/module-cycles.py` reproduces the 10-module and 2-module cycles and stays the gate candidate.
- Scratch artifacts, which a reboot can clear: `/tmp/claude-0/-root-Documents-Craft-Anything-burpsuite-app/c38e947a-376e-4cbb-b234-bebffcdaca2d/scratchpad/lsif_map.py`, `/tmp/claude-0/-root-Documents-Craft-Anything-burpsuite-app/c38e947a-376e-4cbb-b234-bebffcdaca2d/scratchpad/webprobe.lsif`, `/tmp/claude-0/-root-Documents-Craft-Anything-burpsuite-app/c38e947a-376e-4cbb-b234-bebffcdaca2d/scratchpad/lsif_report.txt`, `/tmp/claude-0/-root-Documents-Craft-Anything-burpsuite-app/c38e947a-376e-4cbb-b234-bebffcdaca2d/scratchpad/obscura-ignore-cert.patch`, `/tmp/claude-0/-root-Documents-Craft-Anything-burpsuite-app/c38e947a-376e-4cbb-b234-bebffcdaca2d/scratchpad/obscura-src/`, `/tmp/claude-0/-root-Documents-Craft-Anything-burpsuite-app/c38e947a-376e-4cbb-b234-bebffcdaca2d/scratchpad/rust-code-mcp/`.

### Traps

- **Never edit `handoff.md` directly.** Every Craft write tool (`core_plan_update` and the others) regenerates `handoff.md`, `plan.md` and the rest from `state.json`, so direct edits are lost on the next Craft write. This happened on 24 Nov and the file was rebuilt from memory and a transcript. Change the handoff only with `core_handoff_write`, passing the whole text.
- The Craft plan was reconciled with `tasks.json` on 24 Nov (nine stale steps set to done, one step added for ADR 0002).
- The function-level numbers from `lsif_map.py` (test-only and never-referenced functions) are wrong: its brace scanner mis-sizes functions. Module edges and `Shared` field consumers are sound; edge weights may be slight undercounts.
- Unmerged remote work that bears on the architecture: four stacked `team/owner-*` branches and `team/production-owner-primitive` (scanner owner/lifecycle protocol). Smaller unported branches: `team/repeater-group-autosave`, `lane/pr192-h2-open-failure`, `investigate/dom-stop-boundary`, `team/resolver-observation-87`, `team/dom-budgeted-h1`, `team/request-reader-leftovers`/`-reconcile`, `wp-review-scanner`.
- `master` is 659 commits behind parity and the parity branch is unprotected.
- Open Dependabot alert (high, hpack): the code uses the pinned `hpack-patched` fork inside `catch_unwind`; the alert itself is still open.
- R-13 stays open: stored-DOM submission is disabled and two stored-DOM tests are ignored.

### Next steps

1. Commit and push the corrected Obscura doc to #210 (user go-ahead needed), then merge it.
2. The architecture plan is written as `docs/adr/0002-engine-architecture-and-migration.md` (status Proposed, uncommitted). It differs from the order above in two ways: the `crates/` layout moves to the last phase, and AR-02 (engine duties out of the UI) is added as phase 2. Get the user's decision; if approved, start with phase 0 (cycle gate, lints, ratchet). Trap for the gate: `scripts/module-cycles.py` run from `app/` finds 0 modules and prints "no cycles" with exit 0.
3. Dropped: the `rust-code-mcp` evaluation. The function-level analysis (test-only and unreferenced functions) has no reliable source yet; ADR 0002 lists it as not verified.

## Previous handoff - 2026-11-24 close-out

Parity is `7648c40`. Merged since the last handoff: #203 (h2 diagnostic + tip fmt), #163 (G.13 TLS check), #181 (four M8/R-10 checks), #190 (R-15 CLI/options/REST), #205 (host-probe correction #201, DOM composition #200, D-12/R-12 #192, Rust 2024/MSRV 1.95 #196) and #206 (TLS chain-validity false negative).

Validation: `scripts/ci.sh` all five gates green; `cargo test --workspace --locked` 164 desktop + 1209 core passed, 15 ignored, 0 failed; `cargo clippy --workspace --all-targets -D warnings` and `cargo fmt --check` clean; hosted CI on #205/#206 and both parity merge commits green, including `core (1.95.0)`.

Roadmap/task ledger is reconciled in `tasks.json` (120 done / 15 todo / 2 rejected): D-12, R-11, R-12, R-14 and R-17 moved to done with evidence. R-13 stays open: 14 wrapped DOM families plus addition-only prototype pollution landed, but stored-token submission is disabled and the coverage matrix lists uncovered sinks.

Craft: project `burpsuite` target is the rebuilt `app/target/debug/webprobe` (sha256 `da6859a20246…`). Craft evidence `ev_131b67…`, `ev_1b70e8…`, `ev_5024ed…`, `ev_50a0e7…`, `ev_a8873c…` confirm `/v0.1/scan`, prototype pollution, send-group, BCheck and cross-domain policy code in the artifact; `ev_36ced4…` confirms the #206 TLS wording.

Open work: R-13's 48-type boundary, R-16 Bambda filters/columns, R-18/AR-01..AR-10 architecture, R-19 UI re-score, R-20 Montoya leftovers.

## Previous handoff — 2026-11-18

2026-11-18 night, work stopped by the user. parity/2026-11-17 is synced to GitHub. Done today: R-07, R-09, R-10 (omp session + PR #4 tests + cache-poisoning rule from Zg1g), R-01..R-04, R-06, R-05, R-08, D-09..D-11. R-11 scan configuration library implemented (aa490e8, 09e87f8) but only smoke-tested: run the full suite in .worktrees/review and click through Settings > Configuration library next. M6 paused on branch wp-m6 (D-12a done; D-12b and R-12 partial, compiles). Architecture review qa/ARCH-REVIEW-2026-11-18.md added tasks AR-01..AR-10 (keep sync threads; fix engine work on the UI frame, Shared god object, thread lifecycle, per-message regex compiles); AR-01 is next after R-11 testing. Open PRs: #4 (Instinct; its remaining commit f9a4bba contradicts Burp's cache rule, comment posted asking to drop it), #5 (Instinct M7/R-15 claim; comment posted to rebase and not duplicate R-11's config model). Known flaky test: headless::tests::js_crawl_follows_script_written_links_through_the_proxy (Obscura, under load). Blocked on the user: a fresh Burp baseline for URL-level parity. Free models: NVIDIA NIM free key heavily throttled (Kimi K3.1 Pro added to pi/opencode/kilo/omp, effectively unusable today); codebuddy credits exhausted except hy3; paseo cannot create omp/opencode agents (daemon zod mismatch, needs a restart: user's call); pi with nvidia/stepfun-ai/step-5-preview answered.

## Handoff to app-90

Written by the earlier session (opencode, scratchpad `c38e947a-…`) at app-90's request on 2026-11-24. That session has stopped.

### In flight or left running

- **Processes and ports:** none. No Obscura, Chromium, graph-tool or rust-analyzer process of mine is running, and nothing listens on the 193xx probe ports.
- **Background shells:** all finished. The last one (the ONNX Runtime diagnosis) has completed.
- **`wp-queue`:** nothing of mine queued. The `rust-code-mcp` build ended with exit 101 and was not retried.
- **Worktrees I created or caused:**
  - `/tmp/opencode/wt-pr200` (detached at `cc84ff3`), used to confirm the #200 test failures pre-existed. Safe to remove.
  - `/tmp/opencode/pr163-rebase`, `pr181-rebase`, `pr190-merge`, `pr196-rebase` (detached). I believe these came from the four review subagents I launched early in the session, which died on a usage limit. Safe to remove.
  - `…/scratchpad/wt-flaky` is not mine.
- **Local branches left behind:** `pr163-rebase`, `pr181-rebase`, `pr190-rebase` (all merged upstream via #163/#181/#190), plus the already-merged `fix/*`, `docs/*` and `integration/open-work-20261124` branches. `local/lint-hygiene-2026-11-18` is the preserved lint pass; keep it.

### Changed outside the scratchpad and not committed

- `investigation.cany/investigation/handoff.md`: the "2026-11-24 evening" section and this one.
- `.git/info/exclude`: added `.codegraph/`.
- `app/.codegraph/`: CodeGraph index (untracked, excluded).
- `~/.cache/codebase-memory-mcp/root-Documents-Craft-Anything-burpsuite-app.db`: codebase-memory index.
- rustup: `rust-analyzer` component added to stable; a `nightly` toolchain was installed by the `rust-code-mcp` build.
- Craft investigation memory: handoff revision 13, plus findings and the brief written earlier today.
- `/tmp/opencode/webprobe-preserve-2026-11-24/dirty-tree.patch`: the preserved lint patch from the morning.
- Not mine: `docs/adr/`, `app/session-a9e4e56c-….json`, `investigation.cany/journal/2026-11-24.jsonl`, `.pi/`.

### Learned and not yet in the handoff

- **`rust-code-mcp` build failure:** `https://cdn.pyke.io/…/ms@1.24.2/x86_64-unknown-linux-gnu.tar.lzma2` returns HTTP 403 to plain `curl` from this box too, so it is not a transient build glitch.
- **Ways around it, untested:**
  - its `flake.nix` builds with `ORT_LIB_PATH`, `ORT_PREFER_DYNAMIC_LINK=1` and `ORT_SKIP_DOWNLOAD=1` against a system ONNX Runtime;
  - `crates/rmc-engine` has a `default = ["core"]` feature set, with embeddings (and `fastembed/ort-download-binaries`) behind an optional feature, so a build without embeddings may be possible;
  - a local ONNX Runtime exists at `/root/.browser-use-env/lib/python3.13/site-packages/onnxruntime`, but it is 1.30.0, not the 1.24.2 the crate asks for.
- **`pkill -f` trap:** a `pkill -f` pattern that also appears in the invoking shell's own command line kills that shell (exit 143). It cost me three runs today.
- **`probe2.py` trap:** its `self_signed_https` field can show the previous page's text; judge the TLS result by `nav_err` only.


