# CTO decisions and ARTEX M1 contract amendment

Decision time: 2026-11-22, 13:14 IST. Documentation base: parity `d0e56832150334854665269fb9e2c27dc8c23058`.

Authority: the owner delegated ongoing project decisions on 2026-11-22. This record exercises the CTO's parser, safety, smuggling and agent-transport remit. Product and licensing records remain with their owners. No code, merge or distribution occurs in this document.

This amendment supersedes the conflicting M1 transport, cancellation, budget-authority and feature-wiring details of ARTEX plan PR #127 at `0a7b77be408467642d7ed59775468fdba9adbb04`. The rest of that plan remains a proposal subject to its milestone gates. The program manager should link this amendment alongside #127 in builder briefs; copying #127 alone is no longer a complete contract.

## Decision lines for the program board

- **CTO-D01, parser:** proceed with #96's bounded property/fuzz tests, but make no blanket parser-strictness change; each acceptance change needs a framing-specific fixture, an expected observation model and a reviewed compatibility impact.
- **CTO-D02, agent rails:** typed tools, explicit target scope, bounded task/request/time/byte/provider budgets, no shell/default dispatcher, untrusted-evidence provenance and no unknown-outcome replay are mandatory; there are no per-step approval prompts.
- **CTO-D03, smuggling:** retain the no-timing rule; owned local framing/differential fixtures can proceed, but timing-based active smuggling/desync workflows are not authorized by this record.
- **CTO-D04, one-shot API:** introduce a separate one-shot agent transport port with exact effective-byte accounting, host-enforced limits, cancellation and typed delivery certainty; do not implement it with existing cookie/session/retry wrappers.
- **CTO-D05, ARTEX sequencing:** this contract is ready for an isolated private artex-rs kernel/mock builder; WebProbe linking or combined distribution still waits for the CEO's recorded license position. No live provider or external target is needed for the first slice.

## D01: parser acceptance versus observation

The specific open questions include whitespace before the Content-Length colon, a plus-prefixed length, transfer-coding combinations and bare-LF input. Do not select a universal strict/lenient answer from the fact that WebProbe is a security tool.

Separate the roles:

1. Capture/analysis preserves the original bytes and annotates ambiguity; it must not silently normalize away evidence.
2. Forwarding must know message boundaries. If a proposed acceptance change leaves those boundaries ambiguous, do not make that change without a fixture proving connection and next-message behavior.
3. A fixture must name direction, exact byte input, expected consumed byte count, incomplete/error/completed result and whether remaining bytes belong to another message. Include a companion h1 keep-alive/pipeline case and an owned origin where relevant.
4. Compare the documented target behavior and current behavior; do not treat a leniency differential as proof of an exploit or as automatic permission to forward it.

Accepting #96's tests does not mean every parser behavior they exercise is the desired long-term policy. Keep no-panic/resource properties separate from semantic acceptance tests. Run them on the exact candidate head before landing.

## D02: enforceable rails without approval UX

The trusted task configuration, not model output, sets the allow-list, resource caps, provider destination and policy. Model-supplied limits may narrow but never enlarge those limits. Reject unknown tools and schema variants before dispatch. Arguments use per-tool types with explicit size/depth validation, not unchecked generic JSON.

- Agent sends must stay inside the configured target scope. Apply the check to the effective scheme/authority/port and route; keep the approved hostname semantics when resolving and connecting. Scope must support explicitly allowed private/local targets, since they are valid testing targets.
- M1 does not follow redirects or change routes. Future redirects, DNS changes, upstream proxies and cross-origin reuse need explicit effective-target validation and tests, not inheritance from a prior URL check.
- No shell, arbitrary process dispatcher, dynamic tool registration or raw filesystem access is included in the kernel tool set. The explicitly designed ACP subprocess adapter is not a shell capability.
- Enforce finite turns, sends, bytes, wall time and retries. Real-provider mode additionally needs a bounded cost/usage policy. Do not invent a nonzero payment grant: provider spending still needs an established user budget and method.
- Captured HTTP data, extension text and model/tool results are evidence, not policy changes. Redact secrets before provider disclosure and preserve provenance. A redaction pass is not by itself a prompt-injection defense.
- Journal intent durably before network side effects. Never retry/replay an unknown outcome automatically, including after restart. No human approval dialog is added per send.

The production defaults must have documented finite numerical caps before real-provider enablement. For the mock M1 acceptance fixture, use deterministic local limits (two tool calls, one target send, 64 KiB maximum response, 5 seconds total) so its expected behavior is testable. These fixture caps are not a product-wide throughput setting or a spending authorization.

## D04: corrected one-shot transport contract

These are new API requirements, not claims about an existing implementation. The kernel stays independent of WebProbe transport internals. The desktop adapter supplies a restricted port; shell, PostgreSQL and server dependencies are excluded from the kernel closure.

### Input and ownership

A validated call has a task ID, unique call ID, project identity, a typed target origin, prepared request bytes and requested protocol. Host-owned execution context adds the trusted scope revision, cancellation signal, absolute deadline and remaining resource budget. The model cannot forge a larger budget or replace this context.

For the first fixture, support a direct owned-loopback HTTP/1.1 target only. Return Unsupported before any network activity for unsupported protocols/routes. Production TLS support must pin HTTP/1.1 ALPN for this byte-preserving mode and test it before being exposed. HTTP/2 support is a later protocol-aware mode, not a claim of identical HTTP/1 bytes on the wire.

The prepared request must pass framing/target validation before sending. No cookie-jar substitution, session rules, macros, automatic redirects, extension hook dispatch, upgrade negotiation or automatic retry is run by the one-shot adapter. Do not change normal Repeater wrappers to achieve this. Do not choose `send_raw`/`send_tls_raw` and assume their names establish these properties.

The initial direct-target implementation has no upstream proxy handshake or implicit authentication exchange. A later routed mode must specify and account for those auxiliary operations explicitly rather than concealing them inside the meaning of one send.

### Output and failure certainty

Return a typed outcome with:

- call ID and effective target/protocol;
- actual prepared request/evidence reference, with exact bytes retained locally;
- observed response/evidence reference when present;
- bytes written and bytes read, plus timing and limit termination;
- delivery certainty: **NotStarted**, **PossiblySent**, or **ResponseReceived**;
- typed reason: success, cancellation, deadline, scope rejection, unsupported mode, framing rejection, I/O failure or response cap.

NotStarted is valid only when no request bytes were written. A partial write, lost response or crash-after-intent is not proof of non-delivery. ResponseReceived does not assert that a partially read or capped body is complete; carry a separate completeness flag. The M1 one-shot port never retries, even for NotStarted. A future explicit caller retry policy can use typed evidence, not error-string matching.

### Cancellation and runtime

Tool execution receives cancellation/deadline context, including blocking tools. The kernel's model await also observes the same task deadline and cancellation. Bridge blocking network work through bounded workers; never execute it on the egui thread. Resolver/connect/read/write waits need bounded behavior, and cancellation before request write must prevent a delayed worker from sending after the task returns.

Stop may leave PossiblySent work, which must remain visible in the timeline. Closing a socket cannot undo an already delivered request. A lost worker must not cause hidden replay. Keep bounded queues/events and poll batches; fail with an explicit limit result rather than accumulating work.

### Persistence and evidence

Reserve the call ID and persist an intent before invoking the transport port. Record a result afterward. A repeated call ID is rejected or returns the existing recorded outcome without a second send. On restart, unresolved intent remains PossiblySent/unknown until separately investigated, never replayed.

Evidence references include project identity and survive save/reload. Define tombstones or durable snapshots for history entries referenced by agent tasks before allowing clear/delete to remove the only copy. Cross-project references are rejected. Provider keys and captured credentials are not copied into journals or exported diagnostics.

### Required tests before a real transport is enabled

1. A scripted mock emits one history read and one send; the loopback origin receives exactly one request with the expected bytes and the journal links to the actual exchange.
2. Configure cookie/session data, then prove the agent port does not substitute it or trigger secondary session traffic. Ordinary Repeater retains its existing behavior.
3. Reject unsupported route/protocol and out-of-scope targets before connect/write; test cancellation before resolve, before connect, before write, during partial write and during response wait.
4. Simulate stale connection, reset, timeout and lost response; verify origin counts and zero automatic retries. A response cap retains an explicitly incomplete outcome.
5. Crash between persisted intent and result; restart without a second send. Replay the same call ID and reject cross-project evidence.
6. Stop cannot hang the UI, abandon an unbounded thread set or allow a cancelled queued task to send later.
7. Test agent-on/off feature propagation in desktop and core manifests; the off dependency closure excludes the agent kernel. Add `app/core/Cargo.toml` to the designated manifest owner's files, not only the desktop manifest.

## Builder handoff and gates

The isolated artex-rs kernel builder may implement generic ports, typed calls, host-owned context, mock execution, cancellation, budget accounting and a memory store on its own private branch. It must not introduce a WebProbe link or default shell dispatcher. The WebProbe transport implementation waits for this contract to be carried into its brief and for the licensing path required for that implementation to be recorded.

Keep source branches untouched. Land plan/amendment documentation in dependency order through the integration process, then pin the exact accepted revisions in builder PRs. This document does not waive the full-workspace, real-JVM, feature-matrix or integrated QA gates in CTO review PR #132.

## Provenance and validation

- Original plan and source of contradicted wrapper selection: https://github.com/Chaim12345/webprobe/pull/127
- Source review, exact code paths and risk register: https://github.com/Chaim12345/webprobe/pull/132
- Integration stack: https://github.com/Chaim12345/webprobe/pull/125
- Parser test lane: https://github.com/Chaim12345/webprobe/pull/96

Observed owner instruction: authenticated WhatsApp, 2026-11-22 13:12:51 IST, delegated ongoing decisions. This record does not quote private conversation text. Documentation-only amendment; no Rust compilation, tests, live model use or external traffic occurred while authoring it.
