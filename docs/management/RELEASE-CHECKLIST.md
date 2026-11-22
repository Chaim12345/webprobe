# Canonical release acceptance checklist

Owner: QA / release. Program Manager maintains this index. Snapshot: 2026-11-22 14:25 Asia/Jerusalem. An unchecked item is not a pass; code-read approval, author-run tests and executed final-tree acceptance are separate evidence.

## Safety gates

- [ ] **Crawler: no implicit replay.** Browser crawl items come from the browser's own traffic. The crawler must never resend a request to fill in missing response metadata (a browser-observed POST would run twice at the origin). Missing response head or body is recorded as incomplete evidence (history note starting 'Incomplete browser capture'), keeping the captured request and inventing no response. Explicit replay is a separate user action (Repeater). Check: `cargo test -p webprobe-core --lib -- no_implicit_replay_tests` passes (real origin hit counter). **Unchecked until exact-tree full run.** Lane 5's fix #156 6cc9be9 is reviewer code-read APPROVED; executed final-tree gate unchecked. Keep the fix-or-disable release gate until final acceptance; a valid zero-length body counts as captured.
- [ ] **Bounded #153 claim:** land and reconcile current #153 010de0e (reviewer code-read APPROVED; executed final-tree gate unchecked), rebased on actual #154 parity. Do not describe #153 as eliminating every application-level replay while the browser-crawl fallback remains. Intruder legacy retry count must not override one-send behavior; failed or interim-only check-session validation must stop the pending request. Negotiated-h2 replay is not this PR's scope, it is #145's.
- [ ] **Negotiated h2 #145:** CTO has closed the three TLS-policy source items at #145 5588537; reviewer separately code-read APPROVED 5588537; executed exact-head QA and combined gates remain unchecked. Preserve these invariants: Include TrustAnchor name constraints in complete policy identity; construct key and connection from one effective policy snapshot or a documented checked generation. Add valid matching mTLS, key-change, valid-to-invalid fallback and constraints-only-root-change fixtures. Earlier f2d966f reviewer approval is historical; current 5588537 code-read approval is separate from executed final-tree acceptance. Retain reviewer notes: fallback identity is an Arc address; client-auth build is per request. CTO conditional design approval covers sequential exclusive reuse only. Preserve the now-reviewed committed-before-flush and primed stream-3 origin-counter replay proof.
- [x] **Authoritative response reuse foundation:** #151/#154 landed per live PR API. This is source/landing state, not final integrated acceptance. Preserve complete method-aware final-response gating, no reuse on EOF/truncation/trailing leftovers, and declined-h2c safety when reconciling later branches. Follow-up: 101 plus streaming sink must wire the response head before the raw relay.
- [ ] **Request framing/live persistence:** PR #155 90173f7 is CHANGES NEEDED, not pending approval: replace unsafe response_allows_reuse with authoritative outcome gating, align guard/reader mixed-CRLF/LF terminators and prove the bypass regression. Accept only the repaired, re-reviewed final #155, not old #148 in parallel. Verify typed malformed/incomplete non-forwarding outcomes, 400+close before upstream bytes for normal-boundary ambiguity, exact captured evidence, correct downstream lifecycle and segmentation-independent persistence. The complete R1-R4 acceptance list remains in REVIEW-LEDGER.md. Strict response/chunked global setting stays unwired.

## Combined-tree and workflow gates

- [ ] Pin final source manifest, parity and integration SHA. Merge/rebase source changes in the agreed order; verify no later branch overwrites landed safety fixes. Current #125 is 3ebbd6b; pin and verify its latest parity/source manifest; prior counts certify only their reported tree.
- [ ] Run exact-tree full workspace tests, no-run/fmt/clippy, required real-JVM/Bambda/Repeater checks and current hosted checks. QA signs the actual final SHA; reviewer approval does not replace execution. Keep baseline ignored tests explained.
- [ ] Run integrated project save/reopen, history-to-tools, Repeater extension hooks, extension Drop/pipelining, Intruder stop/drain and baseline, Sequencer constant-token/statistics, Decoder, and Organizer persistence tests. Attach decisive pixels and fixture output, with limits stated.
- [ ] Decoder #150 2efa9e2 landed at cd1e5f1 with triage-reported 982 combined passes; final integrated workflow acceptance remains separate. Keep labeled GZIP-to-base64 text semantics explicit, preserve Unicode and error cases. A UTF-8 text panel is not arbitrary-byte Burp parity. #158 is the code-read-approved Hash replacement, without original #124 Decoder bugs. Reviewer #124 approval is h2-fragmentation-only.
- [x] yaml_serde/lock dependency review reported CLEAR at #125 ad4aa05 by security. This clears that dependency objection only, not later lock changes or all repository advisories. Recheck if the dependency set changes.
- [ ] Retain the open security advisory and provenance review list. No linking, combined ARTEX distribution, public repository, unilateral relicensing or remote exposure before dependency/rights and release-content review. Private local separate-process evaluation remains within D-CEO-05.

## Evidence still needed

| Gate | Owner | Current evidence | Next checkpoint |
| --- | --- | --- | --- |
| Browser-crawl no automatic resend | Lane 5, QA / release | #156 6cc9be9 open; current-head reviewer code-read APPROVED; author reports fail-before/pass-after counters | Targeted origin-counter proof and exact-tree full acceptance |
| H1 replay safety | Lane 4, reviewer, triage | #153 010de0e reviewer code-read APPROVED; executed final-tree gate unchecked; bounded audit, not all app replay | Rebase on actual #154 parity, repeat exact gates, integrate without overwrite |
| H2 policy identity | h2 lane, CTO | #145 5588537 CTO policy source items closed; reviewer code-read APPROVED; executed final-tree gate unchecked | Preserve verified policy snapshot invariants; execute current rebased-head and combined gates |
| 101 streaming response head | h2/codec lane, QA | #157 3601cd3 reviewer code-read APPROVED; clean merge on cd1e5f1 | Execute combined stream-head ordering and full final-tree gates |
| Hash replacement | Hash lane, triage, QA | #158 c014c96 reviewer code-read APPROVED; clean merge on cd1e5f1; no defective #124 Decoder ancestry | Execute combined Hash/Decoder workflow; final-tree gate unchecked |
| Request-reader reconciliation | Lane 15, reviewer, CTO | #155 90173f7 CHANGES NEEDED: unsafe reuse heuristic and mixed-terminator boundary mismatch | Verify rebased head against new #125 and authoritative reuse API |
| Final integrated build | Integration, QA / release | #125 current 3ebbd6b; older da15eb9 had reported 987 workspace +13 Java, not transferable | Refresh after safety landings and repeat on final SHA |

This checklist records project dispositions recorded by the PM; reviewer approvals are code-read only. It does not grant deployment, account, spending, publication or license-change authority.

Follow-up heads at 14:22: #156 6cc9be9, #157 3601cd3, #158 c014c96. New or rebased code-read status never ticks an executed final-tree gate by itself.

Reviewer code-read approvals also cover #157 3601cd3 (101 streaming head) and #158 c014c96 (Hash replacement). Both merged cleanly against cd1e5f1 in reviewer checks. Executed final-tree gates remain unchecked.
