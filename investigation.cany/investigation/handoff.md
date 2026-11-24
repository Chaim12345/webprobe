# Handoff

## 2026-11-24 close-out

Parity is `7648c40`. Merged since the last handoff: #203 (h2 diagnostic + tip fmt), #163 (G.13 TLS check), #181 (four M8/R-10 checks), #190 (R-15 CLI/options/REST), #205 (host-probe correction #201, DOM composition #200, D-12/R-12 #192, Rust 2024/MSRV 1.95 #196) and #206 (TLS chain-validity false negative).

Validation: `scripts/ci.sh` all five gates green; `cargo test --workspace --locked` 164 desktop + 1209 core passed, 15 ignored, 0 failed; `cargo clippy --workspace --all-targets -D warnings` and `cargo fmt --check` clean; hosted CI on #205/#206 and both parity merge commits green, including `core (1.95.0)`.

Roadmap/task ledger is reconciled in `tasks.json` (120 done / 15 todo / 2 rejected): D-12, R-11, R-12, R-14 and R-17 moved to done with evidence. R-13 stays open: 14 wrapped DOM families plus addition-only prototype pollution landed, but stored-token submission is disabled and the coverage matrix lists uncovered sinks.

Craft: project `burpsuite` target is the rebuilt `app/target/debug/webprobe` (sha256 `da6859a20246…`). Craft evidence `ev_131b67…`, `ev_1b70e8…`, `ev_5024ed…`, `ev_50a0e7…`, `ev_a8873c…` confirm `/v0.1/scan`, prototype pollution, send-group, BCheck and cross-domain policy code in the artifact; `ev_36ced4…` confirms the #206 TLS wording.

Open work: R-13's 48-type boundary, R-16 Bambda filters/columns, R-18/AR-01..AR-10 architecture, R-19 UI re-score, R-20 Montoya leftovers.

## Previous handoff — 2026-11-18

2026-11-18 night, work stopped by the user. parity/2026-11-17 is synced to GitHub. Done today: R-07, R-09, R-10 (omp session + PR #4 tests + cache-poisoning rule from Zg1g), R-01..R-04, R-06, R-05, R-08, D-09..D-11. R-11 scan configuration library implemented (aa490e8, 09e87f8) but only smoke-tested: run the full suite in .worktrees/review and click through Settings > Configuration library next. M6 paused on branch wp-m6 (D-12a done; D-12b and R-12 partial, compiles). Architecture review qa/ARCH-REVIEW-2026-11-18.md added tasks AR-01..AR-10 (keep sync threads; fix engine work on the UI frame, Shared god object, thread lifecycle, per-message regex compiles); AR-01 is next after R-11 testing. Open PRs: #4 (Instinct; its remaining commit f9a4bba contradicts Burp's cache rule, comment posted asking to drop it), #5 (Instinct M7/R-15 claim; comment posted to rebase and not duplicate R-11's config model). Known flaky test: headless::tests::js_crawl_follows_script_written_links_through_the_proxy (Obscura, under load). Blocked on the user: a fresh Burp baseline for URL-level parity. Free models: NVIDIA NIM free key heavily throttled (Kimi K3.1 Pro added to pi/opencode/kilo/omp, effectively unusable today); codebuddy credits exhausted except hy3; paseo cannot create omp/opencode agents (daemon zod mismatch, needs a restart: user's call); pi with nvidia/stepfun-ai/step-5-preview answered.
