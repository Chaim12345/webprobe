# Technical risk register

Snapshot: 2026-11-22, 13:10 IST. Integration source reviewed: `2b756c1b37dae00d8f790f0b1f83471838e4060a` (#125). This register records findings and proposed release conditions, not permission to merge, spend, distribute or change product policy.

Status terms: **observed** means directly read in source/API; **design gap** means a plan lacks an enforceable contract; **unverified** means a required check was not performed. Proposed owners are roles for the project manager to route, not claims that another worker accepted the work.

| ID | Priority/status | Risk and evidence | Proposed owner | Exit condition |
| --- | --- | --- | --- | --- |
| T01 | P0, observed | General tests compile in CI but only Montoya, Bambda and Repeater subsets execute. A green label can miss unrelated integration regressions. `ci.yml`, `repeater-http.yml`. | Integration + quality | Unfiltered locked workspace tests execute on exact candidate head; focused real-JVM jobs remain; support/report coverage explicit. |
| T02 | P0, observed | ARTEX one-send/raw-byte contract selects wrappers that mutate cookie/session behavior and lower paths that rewrite/retry. Plan #127 versus `net/send.rs`, `net/conn_reuse.rs`. | ARTEX planner + transport owner | Dedicated one-shot contract; wire-byte, protocol and origin-request-count fixtures pass with cookie/session state configured. |
| T03 | P0 before combined distribution, unverified legal decision | #127 reports ARTEX AGPL-3.0-only and no WebProbe root license. This review observed no root LICENSE in the integration tree but did not independently audit ARTEX licensing. ACP process separation is not an automatic exemption. | Owner + licensing review | Recorded distribution/network-use strategy grounded in both exact source license trees and qualified review where needed; no implicit legal clearance. |
| T04 | P1, design gap | Synchronous agent tool interface has no cancellation context; Stop and bounded execution are unproven. #127 section 5. | ARTEX kernel + desktop adapter | Deadline/cancel propagation; no UI blocking; tests cancel in-flight work, cap queues and report unknown side-effect outcome. |
| T05 | P1, design gap | Journal references alone do not specify crash-after-send, duplicate calls or evidence deleted from history. #127 journal contract. | Agent core + persistence | Durable pre-send intent; no replay of unknown outcomes; duplicate IDs rejected; evidence clear/delete/reload behavior defined and tested. |
| T06 | P1, observed/design gap | ARTEX source map predates L8 and feature edits omit the core manifest although code lives in core. Plan #127 versus workspace manifests and split net modules. | ARTEX planner + manifest owner | Re-pin current base; correct paths, core dependencies and feature forwarding; agent-on/off locked workspace builds and tests. |
| T07 | P1, design gap | Existing upstream h2 exchange assumes stream 1 and one Rx. Sharing it across callers risks cross-stream routing, HPACK races and duplicate retries. `h2.rs`, `net/conn_reuse.rs`. | h2 lane | Connection-owned state machine, typed outcomes, bounded queues and adversarial interleaved-stream matrix in merge-gates doc. |
| T08 | P1 before real provider, design gap | Captured traffic is untrusted and may contain secrets or instructions. Provider safety is scheduled after mock M1 in #127; existing `ai.rs` builds prompts from request/response text. | Agent security/provider lane | Explicit provider opt-in and destination display; key-store/redaction canaries; provenance separation; bounded task execution before live-provider enablement. Scope-only sends remain an owner policy choice, not silently selected here. |
| T09 | P1, unverified | Integration lockfile still contains hpack 0.3.0 and rsa 0.9.10. Earlier dependency PR existence is not proof its changes landed. No current advisory/license scan ran here; this row does not assert either version is vulnerable. | Dependency/security lane | Current locked dependency audit with database date, advisory IDs where applicable, reachability, license inventory and owner-approved exception expiry. |
| T10 | P1, observed/unverified invariant | `project::load` memory-maps an externally selected file; its safety comment relies on replace-by-rename. That describes application saves, not arbitrary external truncation. `support::Body` uses raw slices over append-only mapped segments. No demonstrated exploit or full soundness audit here. | Persistence + unsafe reviewer | Document external-file mutation assumptions or remove that reliance; review Body publication/lifetime/bounds; concurrent load/save, body rollover, disk-full and malformed-project tests. |
| T11 | P1, observed evidence limit | #128 checks separate fix heads, not the integrated candidate; general statistics and several byte/workflow cases remain. #126's UI load benefit is harness evidence, not egui under load. | QA + integration | Integrated cross-tool fixtures, actual pixel QA and bounded-load checks, with remaining Burp/Professional limitations stated. |
| T12 | P1, observed process gap | API reports parity unprotected. Current mutable heads differ from the initial assignment snapshot. Review and CI evidence can go stale during parallel merges. | Program manager + integrator | Frozen candidate SHA per landing batch; all gate evidence matches it; explicit human merge procedure or separately approved branch protection. |
| T13 | P2, pending owner decisions | #103 macro MIME behavior, #96 parser strictness and Organizer delete semantics can become accidental policy decisions in conflict resolution. | Product/owner, CTO implements decision | Exact choices recorded; tests describe chosen semantics; no inference from a neighboring PR. |
| T14 | P2, unverified gate | Module cycle checker exists but neither inspected workflow invokes it; no stable toolchain pin was found in the reviewed tree. Latest stable CI is not a reproducibility or MSRV claim. | Architecture + CI | Chosen toolchain/MSRV documented and checked; run the cycle checker on candidate and treat it as a heuristic, with review for imports/macros it misses. |

## Recommended order

1. Correct ARTEX contracts before starting builders; licensing/governance and kernel-seam research can continue without authorizing combined distribution.
2. Add exact-head unfiltered workspace CI and rerun the integrated regression matrix. Maintain the source lane branches unchanged.
3. Review h2 multiplexing design before implementation is treated as release-ready. Do not block independent docs, hash-list work or local mock fixtures on unrelated decisions.
4. Obtain product decisions as one grouped owner queue: license/distribution strategy, #103 MIME semantics, #96 parser strictness and Organizer deletion behavior. Optional agent scope policy can be presented separately from mandatory implementation correctness.

## Sources and limits

- https://github.com/Chaim12345/webprobe/pull/125
- https://github.com/Chaim12345/webprobe/pull/127
- https://github.com/Chaim12345/webprobe/pull/128
- https://github.com/Chaim12345/webprobe/pull/126
- https://github.com/Chaim12345/webprobe/pull/103
- https://github.com/Chaim12345/webprobe/pull/96

See `cto-architecture-and-merge-gates.md` for exact paths, check commands and disposition. This is a source-only review, not proof of runtime safety, legal advice, a dependency audit or a passing build.
