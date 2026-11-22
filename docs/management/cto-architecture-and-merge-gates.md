# CTO review and merge gates

Date: 2026-11-22. Scope: WebProbe architecture and quality, not product approval or a merge authorization.

## Review baseline

- Documentation branch starts at parity `b1ef6b4a07d384fb1a58ae145cc278328d7c2c44`.
- Integration reviewed: PR #125, `2b756c1b37dae00d8f790f0b1f83471838e4060a`.
- ARTEX plan reviewed: PR #127, `0a7b77be408467642d7ed59775468fdba9adbb04`.
- Burp comparison reviewed at report level: PR #128, `b9968d1c4a12fc9c54803a7e13067a5792fff0cd`.
- This is a source review. No Rust toolchain is installed here. No compilation, tests, fuzzing, benchmark or independent test-count verification was performed.
- Integration is moving. Any later source merge or conflict resolution invalidates a prior whole-head pass until the affected checks run again.

## Technical disposition

PR #125 is the integration candidate, not a certified release. Run and retain exact-head full-workspace evidence before landing. The PR's local test report is useful evidence from its author, not an independently reproduced result here. The CI check names alone do not prove broad test execution.

PR #127 is a sound direction for a small, typed, local-first kernel seam. Amend its transport contract, cancellation interface, crate wiring and licensing language before builders use it as a fixed specification. Do not restore per-step approval: the owner explicitly removed that requirement. Technical limits and permission UX are separate concerns.

Upstream h2 multiplexing should be a connection-manager/state-machine change, not multiple threads calling the current single-request exchange function against a shared socket. Preserve the existing browser-side h2 server boundary and the manual-tool behavior.

## CI coverage actually present

Inspected both files at the integration revision:

| Workflow | What runs | What it does not establish |
| --- | --- | --- |
| `.github/workflows/ci.yml`, core | core check, core test compilation, core all-target clippy, real-JVM Montoya-filtered test execution | execution of the general core suite, support/report suites, desktop suite |
| `.github/workflows/ci.yml`, bambda | pinned-JAR, real-Java ignored Bambda integration tests | the rest of the workspace |
| `.github/workflows/repeater-http.yml` | fmt, default-member test compilation and clippy, real-JVM desktop Repeater-filtered tests | execution of unfiltered desktop tests or explicit all-workspace coverage |

The workspace members are desktop, core, support and report; default members are desktop and core. Tests compiling is not tests running. Dependency builds are not those dependencies' own test suites. Keep the real-JVM jobs; add an unfiltered workspace execution job rather than replacing these focused regressions.

At 13:10 IST, the inspected head's core, bambda and repeater-http checks were running, GitGuardian had succeeded, and Kilo was queued. This is a transient snapshot, not a green verdict. The owner has waived Kilo as a blocker, not waived Rust tests or CI failures. The parity branch API reported `protected: false`; do not assume branch rules mechanically enforce this checklist.

## Merge gate checklist

These are proposed project gates for the manager to apply, not a change to GitHub settings.

### Every code candidate

- [ ] Base is current `parity/2026-11-17`; master and existing source-PR branches are unchanged.
- [ ] Exact base/head SHA and dependency/source-PR list are recorded. No unreviewed late push is covered by an old approval.
- [ ] An independent reviewer checks conflict resolutions and cross-tool semantics, not only source-lane diffs.
- [ ] From `app/`: `cargo check --workspace --all-targets --locked`.
- [ ] `cargo fmt --all -- --check`.
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- [ ] `cargo test --workspace --locked`, with passed/failed/ignored counts and toolchain recorded.
- [ ] Real-JVM Montoya and Bambda tests run with pinned, checksum-verified API and prerequisites required, not silently skipped.
- [ ] Relevant feature-on and feature-off variants are explicit. A manifest declaration is not proof that core and desktop features propagate correctly.
- [ ] Changed parsers receive malformed/truncated/oversized-input tests; network paths receive owned-loopback tests with timeouts and cleanup.
- [ ] Changed UI receives actual screenshots and manual cross-tool checks at a small window and high DPI. Compilation is not visual QA.
- [ ] Dependency/lockfile changes include a current advisory/license review and a dated disposition for each exception.
- [ ] New unsafe code carries a local invariant argument, bounds/lifetime tests and a focused reviewer. Existing unsafe sites touched by a change are re-reviewed.
- [ ] No secrets, captured credentials, provider keys or unnecessary raw traffic are added to source, logs, CI artifacts or PR text.
- [ ] No unresolved owner decision is silently converted into a default behavior change.

### Integration-specific regression matrix

- [ ] Extension Drop followed by a pipelined request closes correctly; no second upstream side effect after the drop-close result.
- [ ] Repeater handlers still execute after UI state regrouping; Logger sends reach the same shared helper.
- [ ] Organizer collections and Inbox destinations work with the integrated state model; deletion behavior stays unchanged pending the owner decision.
- [ ] Sequencer constant-token case and general statistics are checked separately. One special-case fix is not statistical parity.
- [ ] Decoder byte-safe Octal/Binary/Gzip and nested Smart decode have roundtrip/boundary fixtures, not only ASCII examples.
- [ ] Perf history cursor resynchronizes after delete, clear and project load; coalescing does not lose the final repaint; baseline manual-tool behavior remains intact.
- [ ] Burp comparison fixtures are rerun on the integrated head. Separate-head screenshots in #128 are not integrated certification or Professional parity.

### Docs-only candidates

Check links, pinned revisions, intended behavior versus observed behavior, whitespace and the exact changed-file list. Do not claim a Rust test run for documentation-only work. A docs-only PR does not grant approval to execute its plan.

## ARTEX implementation rulings

### A1. Keep the kernel small and independent

Keep the storage/model/tool ports and a desktop adapter. Do not import the default shell dispatcher, PostgreSQL store or server stack into the embedded kernel. Use a typed tool enum plus a separately validated argument type per variant; a `serde_json::Value` field does not itself enforce required arguments, nesting or size. Validate at the dispatch boundary before any side effect.

Keep ACP as an adapter, not the authority boundary. A process boundary is useful operationally but is not, by itself, a legal licensing clearance. Remote team identity/RBAC and distribution need their own design and decision. The ACP statements in #127 were not independently re-researched in this review.

### A2. Replace the contradictory send contract before implementation

The plan specifies unchanged request bytes, one send, no macros/session rules/retries, yet selects `net::send_raw` / `net::send_tls_raw`.

At the reviewed integration head:

- `app/core/src/net/send.rs`: `send_raw_with` invokes cookie/session request processing and response/session follow-up.
- `app/core/src/net/conn_reuse.rs`: TLS wrappers do the same; the lower layer normalizes origin form, rewrites Connection behavior, and has retry paths.

A single Rust function call is not proof of a single wire operation. Introduce a dedicated one-shot agent transport seam with explicit wire-format and retry semantics. Do not claim raw HTTP/1 byte preservation when negotiating HTTP/2, which necessarily changes framing. Test the selected protocol, destination, observed bytes, origin request count and absent cookie/session follow-up at an owned fixture. Test GOAWAY, stale pooled connection, cancellation and timeout without a duplicate side effect. Preserve ordinary Repeater behavior rather than changing the shared wrappers globally.

### A3. Make cancellation and journaling part of M1

`AgentTool::execute` is synchronous in the plan and has no cancellation token. A Stop button cannot interrupt a blocking send merely by setting task state. Provide a deadline/cancellation context to tool execution and a bounded worker bridge; never block the egui thread. Define whether Stop abandons or closes an in-flight request and show an indeterminate outcome honestly.

Persist intent before the side effect, then record its result. On restart, an intent without a recorded outcome is unknown, not failed and not replayable. Include per-task call IDs, duplicate-call detection and evidence/project ownership. Bound event queues and poll batches. Reference-only journals need defined handling for history clear, deletion and project save/reload so evidence IDs do not silently point nowhere.

### A4. Refresh source map and feature ownership

The plan predates L8: `app/core/src/net.rs` is now `net/mod.rs` with transport in `net/send.rs` and `net/conn_reuse.rs`; body storage is in `app/support/src/body.rs`. The workspace has support/report members too. Refresh paths against the chosen integration base.

The agent implementation lives in core, but the plan assigns a dependency/feature edit only to `app/Cargo.toml`. Give the manifest owner responsibility for `app/core/Cargo.toml` and define explicit desktop-to-core feature forwarding. Acceptance must compile and execute agent-on and agent-off across the workspace, and prove the feature-off dependency closure excludes the kernel.

### A5. Keep a no-live-provider M1; do not postpone real-provider safety

A mock model and owned loopback fixture are appropriate for M1. Before a real provider is enabled, provider opt-in, destination visibility, redaction tests, key storage, task caps and untrusted-traffic provenance must be working. This is not a request to reinstate per-step approval or choose optional scope policy on the owner's behalf. The owner still decides optional outbound-scope policy and licensing. Do not describe redaction alone as protection from prompt injection.

## HTTP/2 multiplexing design gate

Observed distinction: `h2_server.rs` already dispatches browser-side streams, with a stream map, flow-control windows and per-stream handler threads. `h2.rs` upstream client creates one Rx with one response and uses stream 1. Adding a mutex around that exchange is not multiplexing.

Required shape and evidence for the lane:

1. One connection owner serializes frame reads/writes and HPACK state. Route stream events to per-stream state, with bounded queues and cancellation, never a socket mutex held across a blocking response wait.
2. Connection-pool identity includes effective route/proxy configuration, scheme, authority, TLS policy and negotiated protocol. Do not coalesce different origins merely because certificates match.
3. Allocate monotonically increasing legal client stream IDs. Honor peer concurrent-stream limits, stream and connection windows, SETTINGS deltas and frame size. Schedule DATA fairly so a large or blocked stream cannot starve a small response.
4. GOAWAY drains already accepted streams and rejects new submissions; REFUSED_STREAM handling is per stream. No opaque string-only error is sufficient to decide retry once streams are multiplexed. Surface typed processed/not-processed/unknown outcomes. No replay of possibly processed non-idempotent requests.
5. Bound aggregate connection memory, per-stream bytes, queued submissions and outstanding work; test blocked flow control, cancellation and connection loss release all waiters.
6. Add a fixture where response 2 arrives before response 1, prove bodies/evidence do not cross, then cover fragmented headers, trailers, reset isolation, GOAWAY races, stream exhaustion, SETTINGS changes, zero/overflow windows and TLS ALPN/h2c paths. Rerun browser-side h2 and h1 regressions.
7. Record request count, connection count, throughput, p50/p95, memory and errors against a fixed baseline. Preserve correctness as the first gate; no throughput claim from a single noisy run.

Dependency choice remains open: evaluate maintained h2-library reuse against the custom parser's raw-observation requirements and migration cost. This review does not prescribe an untested crate migration inside the existing lane.

## Sources and audit method

Live GitHub API and git reads, not cached memory, supplied revisions and source. Entry points:

- https://github.com/Chaim12345/webprobe/pull/125
- https://github.com/Chaim12345/webprobe/pull/127
- https://github.com/Chaim12345/webprobe/pull/128
- https://github.com/Chaim12345/webprobe/pull/126
- https://github.com/Chaim12345/webprobe/pull/103
- https://github.com/Chaim12345/webprobe/pull/96

Paths cited above are at the pinned integration revision. Also inspected `app/Cargo.toml`, `app/core/Cargo.toml`, `app/Cargo.lock`, `app/core/src/project.rs`, `app/support/src/body.rs`, `app/core/src/ai.rs`, and `scripts/module-cycles.py`. Presence of the cycle script does not establish an executed gate. No current vulnerability-database scan or full unsafe-code audit was run.
