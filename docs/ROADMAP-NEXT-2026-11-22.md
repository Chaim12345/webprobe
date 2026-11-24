# WebProbe future roadmap, 2026-11-22

> Planning document, docs only. Prepared by the roadmap-planner lane from the repo state on
> `parity/2026-11-17` (tip 7be2efd), `tasks.json`, `qa/ZOOM-OUT-REVIEW-2026-11-18.md`,
> `qa/ISSUE-COVERAGE-2026-11-18.md`, `docs/MONTOYA-COVERAGE.md`, the open PR list (#8..#120),
> and current PortSwigger sources (Burp Suite Pro/Community 2026.11 release notes and the AI
> features documentation). Nothing here is implemented by this PR.

## 1. Where the project stands

Baseline (verified by the team on PR #45 head 4cddee0): 782 tests passing, clippy 0, fmt clean.
The parity branch itself holds 137 tracked tasks in `tasks.json`: 114 done, 2 rejected, 21 todo
(R-11..R-20, AR-01..AR-10, D-12).

Measured parity, per `qa/ZOOM-OUT-REVIEW-2026-11-18.md` unless noted:

| Area | Parity | Main remaining gap |
|---|---|---|
| Scanner on lab apps | 100% on the tested apps (75/75 Juice Shop, 21/21 lab, 58/58 scan 7) | lab coverage does not equal issue-type coverage |
| Scanner issue types | 70 of 183 Burp types reported (`qa/ISSUE-COVERAGE-2026-11-18.md`); zoom-out counts 48 | 113 not reported: 48 DOM-based, 65 other |
| Extensions (Montoya) | ~10% at the zoom-out; four BApps load unmodified (`docs/MONTOYA-COVERAGE.md`) | most accessors partial or unsupported |
| Proxy | ~75% | browser-side HTTP/2 and response streaming landed after that estimate (R-05, R-06) |
| Intruder | ~85% | predefined lists, Collaborator and extension payloads (R-17) |
| Repeater | ~70% | send groups, single-packet attack (R-12) |
| UI | ~80%, stale estimate | never re-scored after the rewrites (R-19) |

## 2. Work already in flight (do not duplicate)

Open PRs as of 2026-11-22. Future items below assume these land; each item names its dependency.

- **#45** hardening integration (L1..L8), reviewer-approved, unmerged. Base for #46, #49, #51.
- **#46** Rust edition 2024 + MSRV 1.95. **#49** async Phase 1 (engine runtime). **#51** test hardening (806 tests).
- **#47..#66** linear stacks: R-10 leftovers (robots/React2Shell #47, TLS certificate #48, broken access control #50, reflected/stored manipulation #52/#53), R-13 DOM analysis (#54..#63, all 14 families plus prototype pollution), R-14 BChecks (#64..#66).
- **#67..#94**: coverage packs, async Phase 2 pollers, chunked-decoder and hpack security fixes, structured logging (#41), UI QA passes 1..3, async benchmark, accept-loop and pooling fixes, ws://-over-CONNECT fix.
- **#95..#120** (current team round): more coverage packs, parser fuzz/property tests, macro safety, linear head scans, perf benchmark on L8, R-16 Bambda backend + UI, R-18 Repeater/Comparer/Decoder/Sequencer state, UI QA B, R-20 keyword/response-variation analyzers, pipeline fix, Burp parity report docs (#112, #113), extension-drop page, Repeater Montoya hook, sequencer and intruder fixes, Logger context menu, Organizer collections.
- Older originals still open: **#8..#44** (R-17 payloads, m8/m9 originals, async/logging/edition issues). The linear and team replacements supersede most of them; closing them is the owner's call.

## 3. Milestone F-A: finish the scanner matrix (P0)

Goal: every Burp scanner issue type either reported or documented as excluded, with a recount
script as the gate. Lanes: three scanner-check lanes in parallel (injection, server-features,
GraphQL/JWT leftovers), one DOM verification lane, one OAST lane, one coverage-gate lane.

| Id | Item | Effort | Risk | Acceptance check | Lane |
|---|---|---|---|---|---|
| F-01 | Remaining injection families: XPath injection, SQL injection (second order), server-side code injection (Perl, Python, Ruby, SSJS, Expression Language, unidentified) | L | Some Burp checks here are timing-only; keep the no-timing rule and use error, differential and OOB evidence instead | Per-check true/false differential fixtures against the lab apps; issue names and ids match the KnowledgeBase table; characterization test updated | scanner-injection |
| F-02 | GraphQL pack: endpoint found/discovered, introspection enabled, suggestions enabled, content type not validated | M | Low; passive plus light active probes | Fixtures against a local GraphQL server assert all five types; no false positive on a hardened config | scanner-graphql |
| F-03 | Reconcile web cache poisoning and web cache deception: M4 added in-band checks but ISSUE-COVERAGE still marks both table-only | S | Naming/registry wiring, not detection | ISSUE-COVERAGE recount shows both types reported; clean retrieval and cache-busted control fixtures stay green | scanner-injection |
| F-04 | Server-feature checks: HTTP PUT enabled, ASP.NET tracing, ASP.NET debugging, ViewState without MAC, SQL statement in request parameter, cross-domain POST, Spoofable client IP second-row baseline fix | M | Low | One fixture per type; the baseline `characterisation_active_scan_issue_list` expectation is corrected, not suppressed | scanner-server |
| F-05 | SMTP interaction end to end: private Collaborator SMTP listener or public interactsh, plus the `External service interaction (SMTP)` issue path | M | External dependency; live SMTP was never verified | A recorded SMTP interaction raises the SMTP issue type in a loopback test and, when available, against the public relay | oast |
| F-06 | HTTP request smuggling and client-side desync | XL | High: timing-based detection, false-positive risk; currently excluded by the no-timing rule. Needs an explicit owner decision to lift it | Decision recorded first. If built: CL.TE and TE.CL fixtures against a lab proxy pair, measured false-positive rate on the labs, opt-in config flag | scanner-injection |
| F-07 | DOM analysis completion and verification after #54..#63 land: confirm all 48 DOM-based types, add any family the linear stack missed | M | Depends on the linear stack merging | Headless-Chrome DOM labs report each family in stored, reflected and DOM variants; canary severities decided (open question from the review stack) | dom-verify |
| F-08 | Coverage gate: script that recomputes ISSUE-COVERAGE from code and fails CI when a reported type regresses to table-only | S | Low | CI job prints reported/total and diffs against a committed baseline; target 183 minus documented exclusions | coverage-gate |

## 4. Milestone F-B: Burp Pro tool parity leftovers (P1)

| Id | Item | Effort | Risk | Acceptance check | Lane |
|---|---|---|---|---|---|
| F-09 | R-11 scan configuration library: implemented on `.worktrees/r11` with 18 smoke tests but never verified end to end | S-M | Stale branch vs current parity | All 29 BuiltInConfigs load, overlay order preserved, passive-only runs zero active checks, custom Burp JSON round-trips, selection UI verified | scanner-config |
| F-10 | R-12 Repeater send groups and single-packet attack: resume branch `wp-m6` (D-12a SNI done, groups partial) | M | Synchronization must be deterministic, not timing | 20-request single-packet group synchronizes at a local lab with barrier assertions; UI persistence across restart | net-proxy |
| F-11 | R-15 Burp CLI flags, config JSON import/export, REST API (scan start, status, issues) | M | API shape sets the contract for F-20 and F-28 | Headless: start a scan via REST, poll status, fetch issues; CLI flags match Burp's names where they exist; binds loopback by default, never logs secrets | net-proxy |
| F-12 | R-19 UI parity re-score, all 13 tabs against Burp 2026.11 captures, Logger/Organizer/WebSocket intercept driven through egui MCP | S | Estimate-only until run | `qa/parity-scores-2026-11-15.md` replaced with dated evidence; every tab has a capture and a score | qa-verify |
| F-13 | R-20 Montoya completion: `HttpMode`/`RequestOptions`, organizer status, project API, `userInterface` hotkeys and WS editors, `utilities` ranking/shell/Brotli, `websockets.createWebSocket`; then 10 more unmodified BApps recorded in MONTOYA-COVERAGE (keyword/variation analyzers land with #99/#118) | L | JVM sidecar round trips; each BApp may expose new unsupported calls | Each chosen BApp loads and its core workflow passes on the QA display; unsupported calls logged once, never panic | ext-montoya |
| F-14 | Private Collaborator hardening: interaction retention config (Burp 2026.11 added `interactionRetention`), public-relay deployment doc, DNS+SMTP+HTTP in one private instance | M | Running a public OAST server is an ops commitment | Retention expiry verified by test; deployment doc followed end to end on a fresh VM produces interactions | oast |

## 5. Milestone F-C: architecture and quality (P1, runs beside F-A/F-B)

| Id | Item | Effort | Risk | Acceptance check | Lane |
|---|---|---|---|---|---|
| F-15 | R-18 decomposition finish: complete the tool-owned state extraction started in #104/#111, then split remaining `App`/`Shared` fields by subsystem | M | Merge churn against open PRs; sequence after the current round lands | Mechanical extraction only, full suite green after each step, no behavior change | engine-arch |
| F-16 | Async Phase 3 decision (#44): benchmark evidence from #88 says no regression either way and the 50 ms accept poll is already fixed (#89) | S to decide, XL to build | Rewrite risk for no measured gain | Owner decision recorded in the repo; if rejected, close #44 with the benchmark citation | engine-arch |
| F-17 | Coverage push: keep the coverage lanes going until core line coverage is measured and reported per crate in CI | M | Coverage number can become theater; gate on critical modules first | CI publishes per-crate coverage; net, codec, scan and ext_host named as required modules | coverage-gate |
| F-18 | Continuous fuzzing: #96 adds parser property/fuzz tests; add a nightly fuzz CI job with a time box | M | CI cost | Nightly job runs the fuzz targets for a fixed budget and files an issue on a crash | devtools-ci |
| F-19 | Project switching and restart parity (Burp 2026.11): project menu in the title bar, open in this/new window, restart preserves task run/pause state and selected tab | M | UI state restore edge cases | Restart during a paused scan restores the tab and the paused task; temp project keeps settings, drops contents | ui |

## 6. Milestone F-D: beyond Burp, phase 1 (P2)

Differentiators Burp does not have, or has only behind its own paid AI. Each is opt-in and must
not weaken the offline default.

| Id | Item | Effort | Risk | Acceptance check | Lane |
|---|---|---|---|---|---|
| F-20 | Headless CI mode: `webprobe scan --config X --sarif out.sarif --junit out.xml`, exit codes on severity threshold, plus a reusable GitHub Action | M | Depends on F-11 | A demo repo workflow scans a lab app and uploads SARIF to GitHub code scanning; threshold exit code verified both ways | devtools-ci |
| F-21 | AI assist, bring your own key: explain selected text/request/response, issue triage with false-positive suggestions, Intruder payload suggestions; implements Montoya `ai.prompt` | L | Cost, privacy, secret handling; must be off without a key and never send project data unasked | Mocked-LLM integration tests; with no key configured every AI entry point is hidden or disabled; per-request consent before data leaves | ai |
| F-22 | Agentic testing tasks (Burp AT equivalent): a tool-using loop over the WebProbe engine APIs, one Dashboard card per task, user can pause/redirect | XL | Depends on F-21 and F-11; scope creep | Scripted lab scenario: agent task finds a seeded vulnerability and writes an issue with evidence, no human input after the prompt | ai |
| F-23 | Extension registry CI: the four verified BApps plus 10 more load-tested nightly against the sidecar; compatibility table published in docs | M | BApp downloads and licenses; jars fetched at test time, never vendored | Nightly job matrix passes or files an issue naming the unsupported Montoya call | ext-montoya |
| F-24 | Reporting upgrade: branded HTML/PDF reports, CVSS vectors per issue, scan-vs-scan diff, remediation status field | M | PDF rendering dependency choice | Golden-file report tests; diff of two lab scans shows the fixed issue as resolved | reporting |

## 7. Milestone F-E: beyond Burp, phase 2 (P3, bigger bets)

| Id | Item | Effort | Risk | Acceptance check | Lane |
|---|---|---|---|---|---|
| F-25 | Native Rust/Wasm extension sandbox beside the JVM sidecar, WASI capability-limited | XL | New attack surface; design review first | A sample Wasm extension registers a passive check with no filesystem or network capability and cannot escape the sandbox in tests | ext-montoya |
| F-26 | Collaboration: team server for shared projects, synced annotations and comments on history items, multi-user audit log | XL | First server component; conflicts with the single-user project-file model | Two clients annotate the same history item and converge; audit log records who changed what | collab |
| F-27 | Protocol expansion: HTTP/3/QUIC upstream, gRPC-aware message views, GraphQL subscriptions over WebSocket | XL | New protocol stacks; hand-rolled h2 argues for vetted crates here | Lab servers for each protocol proxied, replayed and scanned; history shows protocol-native detail | net-proxy |
| F-28 | Read-only web dashboard served from the REST API for reviewing results from any device | L | Auth on a network surface; bind loopback with token auth by default | Dashboard lists scans/issues from F-11's API; mobile viewport renders issue detail; no mutation endpoints exposed | ui |

## 8. Suggested sequencing for the team

1. **Now, in parallel with the open PR round:** F-08 (coverage gate, cheap, prevents regressions),
   F-12 (UI re-score, informs everything), F-16 (decision only), F-09 (verify R-11).
2. **Next, scanner-heavy wave (6+ lanes fit):** F-01, F-02, F-03, F-04, F-07, F-05.
3. **Then:** F-10, F-11, F-13, F-14, F-15, F-17, F-18, F-19.
4. **Once F-11 exists:** F-20, F-21, F-24, and F-23 in parallel.
5. **Bets, one at a time with owner sign-off:** F-06, F-22, F-25, F-26, F-27, F-28.

Dependency notes: F-20/F-22/F-28 need F-11. F-22 needs F-21. F-07 needs the #54..#63 stack.
F-06 needs an owner decision on timing-based checks. Nothing in F-D/F-E blocks Burp parity.

## 9. Open questions for the owner

1. Lift the no-timing rule for smuggling/desync (F-06) and the timing-only code-injection checks?
2. Async Phase 3: build or close (F-16)?
3. AI assist: acceptable at all, and only with the user's own key (F-21/F-22)?
4. Is a team server (F-26) in scope for this project, or does WebProbe stay single-user?
5. Old superseded PRs #8..#44: close them once the linear/team replacements land?

## 10. Status 2026-11-24

Parity is `7648c40`. The task ledger is reconciled to **120 done / 15 todo / 2 rejected**.

Landed since this roadmap was written:

- **F-09 / R-11** scan configuration library — 29 BuiltInConfigs load and the overlay/passive-only behaviour is covered by the #194 verification harness (merged via #205).
- **F-10 / R-12** Repeater send groups and single-packet attack — sequence/separate/parallel modes, h2 single-packet burst and h1 last-byte sync are in `core/src/send_group.rs` + `h2_group.rs`, with the 20-sender lab test.
- **F-11 / R-15** CLI flags, options JSON and `/v0.1` REST API — landed in #190 (loopback default, keyed path auth, 9 REST tests).
- **R-14** BCheck interpreter — parser/validator/runner and scanner wiring landed in #187.
- **R-17** Intruder payload completeness — Collaborator payloads, extension generators and the missing predefined processors landed in #191.
- **R-13 (partial)** DOM analysis — 14 wrapped families plus addition-only prototype pollution landed via #186/#188/#200/#205. Stored-token submission is deliberately disabled, and `docs/specs/R-13-dom-coverage-matrix.md` lists uncovered sinks, so the 48-type acceptance is not yet proved.
- **D-12** Collaborator SNI and scheme payload variants — landed in #192.
- **Rust 2024 / MSRV 1.95** — landed via #196; CI runs both 1.95.0 and stable.

Still open from this plan: F-01/F-02/F-05/F-06/F-07/F-08, F-12..F-20, and the F-D/F-E bets. The concrete remaining engineering items are the 15 non-done entries in `tasks.json` (R-13, R-16, R-18, R-19, R-20 and AR-01..AR-10).
