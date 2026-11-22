# Canonical release acceptance checklist

Owner: QA / release. Program Manager maintains this index. Snapshot: 2026-11-22 14:15 Asia/Jerusalem. An unchecked item is not a pass; code-read approval, author-run tests and executed final-tree acceptance are separate evidence.

## Safety gates

- [ ] **Browser-crawl automatic replay:** `crawl.rs::replay_seen` must not resend a browser-observed request merely because head or body response metadata is absent. Fix it, or disable the automatic fallback, before shipping/enabling the affected browser-crawl flow. Lane 5 owns the focused fix, assignment pending acknowledgment at this snapshot. Keep the captured request and explicit missing/incomplete evidence; distinguish absent capture from a valid empty body. Require real origin counters for a completed POST with missing head, missing body and both missing, plus complete-capture regression coverage. Exactly one total origin effect, no manufactured successful response.
- [ ] **Bounded #153 claim:** land and reconcile the reviewed h1 no-unknown-replay work after actual #154 parity. Do not describe #153 as eliminating every application-level replay while the browser-crawl fallback remains. Intruder legacy retry count must not override one-send behavior; failed or interim-only check-session validation must stop the pending request. Negotiated-h2 replay is not this PR's scope, it is #145's.
- [ ] **Negotiated h2 #145:** close the remaining CTO TLS-policy blocker before landing. Include TrustAnchor name constraints in complete policy identity; construct key and connection from one effective policy snapshot or a documented checked generation. Add valid matching mTLS, key-change, valid-to-invalid fallback and constraints-only-root-change fixtures. Reviewer approval at f2d966f does not clear that separate CTO gate. Preserve the now-reviewed committed-before-flush and primed stream-3 origin-counter replay proof.
- [x] **Authoritative response reuse foundation:** #151/#154 landed per live PR API. This is source/landing state, not final integrated acceptance. Preserve complete method-aware final-response gating, no reuse on EOF/truncation/trailing leftovers, and declined-h2c safety when reconciling later branches. Follow-up: 101 plus streaming sink must wire the response head before the raw relay.
- [ ] **Request framing/live persistence:** accept the final rebased #155, not old #148 in parallel. Verify typed malformed/incomplete non-forwarding outcomes, 400+close before upstream bytes for normal-boundary ambiguity, exact captured evidence, correct downstream lifecycle and segmentation-independent persistence. The complete R1-R4 acceptance list remains in REVIEW-LEDGER.md. Strict response/chunked global setting stays unwired.

## Combined-tree and workflow gates

- [ ] Pin final source manifest, parity and integration SHA. Merge/rebase source changes in the agreed order; verify no later branch overwrites landed safety fixes. Current #125 da15eb9 predates #154 parity; prior counts certify only their reported tree.
- [ ] Run exact-tree full workspace tests, no-run/fmt/clippy, required real-JVM/Bambda/Repeater checks and current hosted checks. QA signs the actual final SHA; reviewer approval does not replace execution. Keep baseline ignored tests explained.
- [ ] Run integrated project save/reopen, history-to-tools, Repeater extension hooks, extension Drop/pipelining, Intruder stop/drain and baseline, Sequencer constant-token/statistics, Decoder, and Organizer persistence tests. Attach decisive pixels and fixture output, with limits stated.
- [ ] Decoder #150 is code-read approved at 2efa9e2, not yet final combined/UI acceptance. Keep labeled GZIP-to-base64 text semantics explicit, preserve Unicode and error cases. A UTF-8 text panel is not arbitrary-byte Burp parity. #139 hash owner rebases after this repair without reinstating original #124 Decoder bugs. Reviewer #124 approval is h2-fragmentation-only.
- [x] yaml_serde/lock dependency review reported CLEAR at #125 ad4aa05 by security. This clears that dependency objection only, not later lock changes or all repository advisories. Recheck if the dependency set changes.
- [ ] Retain the open security advisory and provenance review list. No linking, combined ARTEX distribution, public repository, unilateral relicensing or remote exposure before dependency/rights and release-content review. Private local separate-process evaluation remains within D-CEO-05.

## Evidence still needed

| Gate | Owner | Current evidence | Next checkpoint |
| --- | --- | --- | --- |
| Browser-crawl no automatic resend | Lane 5, QA / release | CTO source finding; no fix PR verified yet | Author acknowledgment, focused PR, origin-counter proof |
| H1 replay safety | Lane 4, reviewer, triage | #153 ca5048f code approved; CTO accepts bounded audit, not all app replay | Rebase on actual #154 parity, repeat exact gates, integrate without overwrite |
| H2 policy identity | h2 lane, CTO | #145 f2d966f reviewer approved; CTO name-constraints/snapshot test gap remains | Correct policy identity and discriminate all requested cases |
| Request-reader reconciliation | Lane 15, reviewer, CTO | #155 current 90173f7; earlier 4c1b09f design pass deferred final verdict | Verify rebased head against new #125 and authoritative reuse API |
| Final integrated build | Integration, QA / release | #125 da15eb9 has reported 987 workspace + 13 Java on that tree | Refresh after safety landings and repeat on final SHA |

This checklist records approved project dispositions under the management delegation. It does not grant deployment, account, spending, publication or license-change authority.
