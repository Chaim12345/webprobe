# PR #7 source accounting and parity-port correction

## Pins and limits

Source: https://github.com/Chaim12345/webprobe/pull/7 at `f58321243108f7b7cf2e3634d63589fa3d377130`.
Source merge-base: `7be2efd44949006526df1ea3616290d9979e67c6`.
Replacement: https://github.com/Chaim12345/webprobe/pull/192, based on `d5b218e4a8b75855223149105942d37207c0e073`.

This is author source accounting, not independent approval or a source-closure authorization. The earlier claim that the initial parity port fully superseded #7 was premature. The correction commit changes behavior and resets affected review, QA and CTO gates. Master and parity are not changed by this branch.

## Whole-source mapping

The source delta spans 16 paths and 11 commits, including inherited work, not only the final f583212 guard. The source branch commits are 834d9c7 (SNI), 592847e (payload/group groundwork), 88827df (module/h2 session wiring), 3536ba0 (parallel modes), 3c43dd7 (ordering/lab/slot fixes), 7c94d68 (h2 lab), 0faed1d (desktop), d64c16a (metadata), 948a31b (barrier failures/wire forms/protocol/chunking), b25b88f (empty request barrier), f583212 (window/empty wire guard). Their base is retained in parity ancestry; ancestry alone is not the behavior proof.

| Source paths | Replacement and accounting |
| --- | --- |
| core/src/url_payloads.rs | Same file, byte-identical at initial port 387ceb7. Zpgu/Zbxl variants and tests retained. |
| core/src/net.rs | Split into net/sni.rs and net/conn_reuse.rs. Custom SNI scope/name rule/lab and no-pool rules retained. Correction also guards the newer parity h2 retry-pool insertion. |
| core/src/scan.rs | scan/request_builders.rs and scan/tests.rs: per-variant slot allocation and pending/OOB slot assertions. |
| core/src/scan_checks.rs | scan_checks/point_checks.rs, collaborator_everywhere.rs and tests.rs: ext variants, delivery wording, SNI everywhere probe, HTTPS signature and tests. |
| core/src/h2.rs | Parity Conn-based head/burst/pump/finish methods replace source free functions. Preserve parity framing, flow-control, commitment/flush and regression assertions; body-window guard and DATA splitting retained. |
| core/src/h2_group.rs | Conn-based sequential and coalesced-write group transport; source stream order, callbacks and arrival numbers retained. |
| core/src/send_group.rs | Registry, validation, project conversion and send contracts. Correction restores missed source wire routing, both ALPN pins/h2 refusal, TLS last-byte barrier, first-item cancellation, post-error hooks, connection counts, closed-connection handling and serialized FnMut callbacks. Session-preparation errors propagate instead of bypassing failed validation. |
| core/src/lib.rs | Group and payload module declarations. |
| core/src/project.rs | Group schema, serde default and default/test literals; settings-only export also clears group data on the newer parity surface. |
| src/repeater_groups.rs | Group chips/dialog/menu/worker/history. Add parity response_sources/history parallel-vector maintenance. |
| src/main.rs | Group state/defaults/module and seed hook, adapted to parity App. |
| src/repeater_ops.rs | Chip/menu/prune wiring, adapted to repeater.sel. |
| src/tools.rs | Save by tab positions, restore against new IDs. |
| src/ui.rs | Now ui/repeater.rs: dialog/tick/group cancellation. |
| MILESTONES.md | M6 evidence rewritten for the new branch. Source's unrelated M5 change is excluded; parity M5 content retained. Historical source test totals/screenshots are not fresh proof. |
| tasks.json | Deliberately retain parity bytes. Source removes ten AR tasks and resets unrelated R11/R18 progress in addition to D12/R12 status changes. Those stale deletions/regressions are excluded explicitly, not treated as feature requirements. New M6 evidence belongs in this packet and MILESTONES, not a wholesale source-metadata replacement. |

## Correction regression evidence

Focused author tests, no full workspace rerun:

- Group tests: original eight plus fourteen new regression cases, 22 passing.
- New cases cover HTTPS proxy CONNECT followed by TLS/origin form; SOCKS remote target/origin form; HTTP proxy sequence/parallel exact absolute HTTP/1.1 wire without CONNECT; direct origin form and cleartext HTTP/2 display normalization; HTTP/1 ALPN pin and h2 refusal before application bytes; TLS four-sender prefix barrier; initial cancellation with zero connections/callbacks; no second send on a closed group connection; post-error macro invocation; session-validation failure without original-request fallback; registry/import/validation/settings-export invariants.
- TLS fixture withholds the last handshake until other senders' prefixes have been checked. An early last byte fails the test. Replacing prefix writes with whole-request writes makes this test fail. Mutations dropping the first cancellation check and routing cleartext via CONNECT also fail their targeted tests. All mutations are reverted.
- Existing h2 tests: 25 passing; custom-SNI lab: one passing; h2 single-packet lab: one passing; desktop test compilation passes.
- The h2 lab took about 61 seconds on one run due to its server read timeout. This is not evidence of fast shutdown.

The 20-sender barrier test proves prefix-before-tail ordering, not a measured 5 ms wall-clock bound. One write is a coalesced application write, not proof of one network packet. The source timing acceptance and actual UI pixels/save-restore still need explicit independent disposition. No refreshed visual inspection is claimed here.

## Pending acceptance

Independent review of corrected source and error/callback contracts; exact-head QA for route/ALPN/TLS/sequential/h2/custom-SNI behavior; actual group UI and project save/restore inspection; then-current parity integration with review of reconciliation and combined gate; CTO acceptance of that exact candidate; sole-writer landing and source-head revalidation/retained-tree proof. #7 stays open until those conditions are satisfied. Existing source approvals and old author suite totals are historical evidence only.

## Review follow-up: failed exchange retirement

Review found that the initial correction retired successful nonreusable responses but retained a socket when exchange returned an error. The new exchange_single helper poisons the group connection on every exchange error before returning that item's error. Later items receive connection-unavailable errors without another write, connection or replay. Truncated length/chunk framing still follows parity codec semantics: partial evidence is returned with reusable=false, and the group socket is dropped. The port does not redefine the codec's partial-evidence behavior.

Tests cover both incomplete length/malformed chunk response followed by a second item, and an open partial response whose socket timeout is set to 80 ms in the fixture. The latter exercises the exact shared helper used by run_sequence, confirms error poisoning, zero second-request bytes and no new accept/connection, and fails when the poison assignment is removed. Separate singleton-readd and duplicate saved-index assertions pass.

Cancellation coverage is initial/between-item only, not mid-flight interruption or bounded cancellation completion. Configured post-request macros can still send their own traffic after a preparation refusal under the source hook contract; no zero-total-effects claim is made for a configured hook workflow. TLS barrier evidence remains ordering evidence, not a 5 ms or one-packet result.

## Isolated candidate: initial HTTP/2 open failures

Supplemental fault-lab inspection found that initial HTTP/2 open failures returned Cancelled(0) with only the first callback. That branch is identical in source #7, so this is a source-inherited reporting inconsistency, not a lost port behavior. The isolated correction branch changes it to match the ordered-mode contract: the attempted first item retains its actual error; non-DNS failures mark later positions connection-unavailable without reconnect/replay; UnknownHost returns after exactly the first callback. Completed means result positions processed, not successful I/O.

The failure-report loop checks cancellation before each later callback/hook. Cancellation set by callback zero returns Cancelled(1) and prevents every later callback and configured post-request macro. Without cancellation, source-compatible post-request hooks run once per reported failed position and may themselves perform traffic. Tests explicitly count those configured macro connections separately from the single failed target connection. This is not a zero-total-effects claim and does not change mid-flight cancellation.

Author-only focused evidence: four new tests pass for refused connection, ALPN refusal with no application bytes/reconnect, DNS UnknownHost first only, and callback cancellation with exactly one callback/hook (plus uncancelled three-callback/three-hook control). Removing the between-result cancellation check fails the targeted test. Existing group tests 22/22 and desktop test compilation pass. No full-suite rerun or adoption/landing is claimed. The defensive cleartext-h2 branch is unreachable through validated public dispatch and intentionally unchanged: it still reports first-only Cancelled. Do not generalize the initial-error fix to every private entry path. This candidate needs exact-pin Reviewer decision before coordinated adoption and fresh QA/CTO gates.
