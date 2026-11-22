# WebProbe program board

Snapshot: 2026-11-22 17:50 Asia/Jerusalem. Program owner: Program Manager. [Canonical release checklist](RELEASE-CHECKLIST.md). [Review and decision ledger](REVIEW-LEDGER.md). [Role charters](ROLES.md). [HR staffing register, PR #137](https://github.com/Chaim12345/webprobe/pull/137), proposed file `docs/management/STAFFING.md`.

This is the index for sequencing, not permission to merge or change product behavior. Only the triage lane lands parity changes. Existing PR branches and master stay untouched. Refresh this board when a source head, landing, decision or verification result changes.

## Current position

- Live parity `4ad2591e61f262e36b57965139bd429b3e9f0602`; **114 open PRs**, full paginated refresh and exact ancestry recomputed. Management #160 remains open; previous 1379ae6 docs approval is historical once this refresh changes its head. Self-row SHA stays blank to avoid recursive staleness.
- PR #70 landed at 0c0dee7, #68 at f297951 and #159 at 5c15280. Live API confirms merges. Triage reports 1084 combined passes /14 ignored for #159. PR #67 is now closed after complete source-to-successor proof; this was not a title/ancestry-only closure. Original #139 remains open pending its own complete replacement proof.
- **Acceptance freeze:** triage landed #145 on final parity 4ad2591 and continues to hold every other landing. The single #125 refresh and #155 clean re-merge are published. Keep final candidate #155 c6d0cae pinned for whole-stack review, independent suite/JDK25 and cross-tool UI acceptance; no unrelated feature or management landing during this batch.
- H2 #145 `a88dfe91feb7410d5ea8983da06823a9c5b9483e` **landed at 4ad2591**. Live API and exact ancestry confirm it. Independent QA accepted exact head1017/0/13 and 19/19 executed unique fixtures, then merged tree 1105/0/14, matching triage. Triage reports remote/local merged trees identical to saved tested tree, JDK25 no-run/fmt/clippy clean and non-Kilo CI green. The old24-selector list had 5 wrong-namespace duplicates; zero-match now fails. This closes the #145 semantic-overlap gate, not final #125/#155 release acceptance.
- Canonical #125 is now `3108302f6e4c32c747c6abbf1c232289cb4fb1da`, containing final parity 4ad2591. Reviewer APPROVED the delta/merge resolution and baseline policy, not the whole 85-commit carried stack. h2.rs/conn_reuse.rs/tls_client.rs match landed parity; earlier header-fragmentation commit is absorbed by #145 with its equivalent test. GET/HEAD-only automatic baseline, visible skip, unchanged1-based attack rows and no baseline-derived fields are source-reviewed; failed sends now match attempts=1/no-unknown-replay. Author reports 1149 workspace +13 Bambda=1162 passes/0 failed at3108302. This is author evidence, not independent final-candidate acceptance.
- Final candidate #155 is `c6d0caeda43c9cbdecc2d333dfbc79e64d285fd3`, containing #125 3108302 and parity 4ad2591 by verified ancestry. Clean re-merge published; previous ws.rs/mod.rs/engine close-return conflicts are resolved. Reviewer approves its 12-file own delta and confirms R1 hardening in the merged tree; this is not approval of the entire85-commit carried stack. Author reports core-lib844/0/13 plus fmt/clippy clean. Independent QA switched to this candidate at 17:33, stopped the short #125-only gate and is running full suite/JDK25 phases, then cross-tool Xvfb screenshots; about 2h estimate is not completion. Bare-LF compatibility and conservative h2-upstream downstream-close notes remain.
- Hardened parser replacement #164 `bb3de82` is approved **library-only** and held after original #64's standalone formatting gate failed. BCheck exec #166 `a303848` carries #164 and replaces the older #162 port. Before loading/UI wiring, cap source size and scope-gate Transport destinations; retain shared 64-frame/64-condition-node limits and request/combination budgets.
- New exact-head code-read approvals: diagnostics #161 `a8de045`, TLS #163 `a1b469f`, GET-only BAC #165 `33c5382`, reflected G.11 #167 `509cad7`. These are not executed combined-tree acceptance and do not override the freeze. TLS direct egress bypass and BAC's 16 GET comparisons must stay visible. Reflected context classification is deliberately capped at first32 occurrences, with empty-probe guard and Tentative confidence.
- Stored G.11 #168 is now `18e12d6`, reviewer code-read APPROVED, stacked on #167 `509cad7`. New retrieval GET/HEAD guard runs before any injection; injection itself retains its original method and existing StoredXss is unchanged. First G.11 hit skips later families, but a no-hit pair can still send up to 7 injections +7 retrievals. Probes persist with no cleanup. Source approval is not final combined acceptance.
- Host probes #169 `a3d5ce2` are reviewer code-read APPROVED after Next.js/RSC baseline fingerprint gating and Tentative confidence. Normal issue/check filters apply, including with extra_checks=false. It sends a robots GET and at most one synthetic POST / per fingerprinted host, not a replay of the audited request; signature detection is not RCE proof.
- DOM eight-family #170 `f5a9370` has core-design code-read approval with three unresolved should-fixes: run-level/concurrent-browser budgets; speculative direct-egress verification/isolation; and confidence/evidence/response-body caps. Existing 64-request cap is per URL, not per run. Exact-origin GET/HEAD interception and scanner session routing passed source review, but speculative socket behavior was not tested independently. Cleanup panic guard and unique profile suffix remain review notes.
- DOM browser coverage is author-reported: all 8 positive families across 3 test functions plus an all-eight cache test, not only 3 families. Author reports full core 787 passes at 4 threads; earlier 16-thread lab miss is not isolated. No GUI visual QA. Review fixes are acknowledged but not yet implemented at this snapshot. Edition/MSRV work is local/uncommitted, with unsafe-env/tail-drop audit, real 1.95/all-features and CI-matrix gates still owed; no PR or acceptance claimed.
- All 93 original audit rows are reported audited by triage, with later landings tracked. Audit completion is not permission to close unresolved sources. Old-stack fix-only approvals cannot certify carried features. Historical milestones remain in [milestones.csv](milestones.csv); final integrated gates remain unchecked.

## Landing sequence and stop/start calls

1. **Keep final candidate pinned.** Final parity is4ad2591, #125 3108302 and #155 c6d0cae. Triage alone writes parity and holds all other landings until this batch is accepted. PR #145 is landed and no longer the awaited signal.
2. **Whole-stack review remains distinct.** Current reviewer verdicts certify #125's refresh delta/merge and #155's12-file own delta/R1 hardening. The carried 85-commit tree still requires whole-stack acceptance; do not silently promote a delta approval or author pass count.
3. **QA gates c6d0cae once.** Full workspace, JDK25 required-Java/Bambda, fmt/clippy/no-run and current hosted checks, then one-build project save/reopen, history-to-tools, Repeater hooks/Drop/pipelining, Intruder baseline/replay, Sequencer, Decoder and Organizer screenshots/fixtures. The stopped c394399/3108302-only gates are not current final acceptance.
4. **Then exact landing and cleanup proof.** If the pinned tree is accepted, triage verifies final tested/remote identity. Only after actual #125+#155 landing and pipeline/drop-close/nonblocking-drain preservation propose #148 supersession/#110 integrated closure. PR #139 needs its own complete replacement proof; #67 proof/closure is already done.
5. **Resume slice queue after this batch.** Keep #164 -> #166 and #167 -> #168 dependencies, source-size/destination-scope loader gates and #170 unresolved should-fixes. Library/core-design approvals do not grant loader/network exposure. Preserve source branches and review the full proposed stack.
6. **Retain traffic/privacy limitations.** TLS direct egress, BAC16 GET comparisons, stored G.11 injection/persistence and DOM per-URL budget/speculative-egress/evidence limits remain explicit. Corrected19 unique #145 fixture selectors require an executed pass, never a zero-match success.

## Lane ownership

| Lane | Accountable role | Current next checkpoint | Boundary |
| --- | --- | --- | --- |
| Parity landing | Triage | Await final c6d0cae whole-stack review/QA; exact tested-tree landing | No other landings during batch |
| #145 acceptance | QA/reviewer/triage | DONE: exact 1017/0/13,19 fixtures; merged 1105/0/14; landed 4ad2591 | Not final #125/#155 acceptance |
| Canonical #125 | Integration + reviewer |3108302 published, delta approved; hold source manifest | Whole carried stack not yet accepted |
| #155 request boundary | Request-reader + reviewer/QA |c6d0cae final candidate, own delta approved; independent suite then UI | No own-delta to whole-stack approval transfer |
| Parser / BCheck exec | Triage slice author + reviewer | Hold #164/#166 until batch done; loader gates before wiring | Source size, destination scope, bounded complexity/budgets |
| Other slices | Existing slice authors + reviewer | #161/#163/#165/#167/#168/#169 approved; #170 core design approved with should-fixes | Freeze applies; #168 carries #167 |
| Integrated workflow QA | QA / release | Pinned final combined build | Final release gates still unchecked |
| ARTEX | CTO / isolated builder; CEO license scope | Last recorded isolated kernel/mock scope, recheck before effects | D-CEO-05 private/local/separate-process only |
| Program board | Program Manager | Refresh #160 and obtain current-head docs review | Timestamped evidence, no source mutations |

## Decision register

| Decision | Status and scope | Next action / affected work |
| --- | --- | --- |
| #103 Content-Type handling | Decided: urlencoded form, application/json and application/*+json only; other body bytes preserved | Triage completes review/test gates; #97 supersession closure needs exact proof |
| #96 parser strictness | Decided: bounded property/fuzz coverage only; no broad strictness change without framing fixtures | Keep behavior changes separate and fixture-backed |
| ARTEX / WebProbe license | D-CEO-05/#144: private/local/separate-process evaluation only; no assumed unilateral relicensing, public repo, combined release, in-process linking or remote exposure | Isolated private artex-rs kernel/mock work may proceed after CTO corrections; process separation is not automatic legal clearance |
| Organizer deletion | Decided: deleting a collection moves its items to Inbox, with confirmation | Author implements and QA tests non-destructive persistence/migration behavior |
| Agent safety rails | Decided: typed tools, bounded budgets, scope-limited sends, no shell, no unknown-outcome replay | Implement and test at the kernel/transport boundary, with no per-step approvals |
| Active smuggling workflow | Decided: no timing-based active workflow | Do not start timing-based probes; framing fixtures remain separate |
| ARTEX builder start | Decided: isolated kernel/mock on a new private artex-rs branch after CTO contract corrections | Correct one-shot transport API first; existing session/cookie/retry send path cannot meet the promised contract |
| Per-step ARTEX approval | Resolved for WebProbe integration: requirement removed by owner on Nov 22 at 12:53 | #127 supersedes #122 on this point; preserve the policy hook, do not restore old requirement by accident |
| ACP exposure | Owner requested Nov 22 at 12:50 | Keep the option in the ARTEX plan; kernel/linkage decisions remain separate |
| Kilo failure gate | Owner waived Nov 22 at 13:02; triage recovered original | Do not waive other CI, review or regression failures |

Decision provenance: owner's authenticated WhatsApp messages were checked for ACP and per-step policy. The owner delegated routine decisions at 13:12; CEO/CTO rulings at 13:13 settle the former product holds. No choice is inferred from PR text. This board does not create grants or approve future spending, disclosures or actions.

## Milestone ordering

| Program milestone | Exit evidence | Current state |
| --- | --- | --- |
| P0: recover and stabilize foundation | Exact merged tree and full required-Java suite per landing | #96 now landed too; #138 and remaining lane gates continue |
| P1: one reviewable integrated candidate | #125 manifest matches latest intended source heads; clean combined checks + independent review | 3108302/c6d0cae final candidate published; whole-stack review and independent suite/UI gates pending |
| P2: integrated workflow acceptance | One pinned build passes cross-tool regression with screenshots and traceable fixtures | Not established by separate-head reports |
| P3: reconcile old roadmap | Each of 21 recorded todo tasks mapped to integrated code, residual gap or owner hold | PR board ready; avoid reopening already implemented milestones |
| P4: close measured parity gaps | #128 priorities translated into owned byte-safe Decoder, h2, Sequencer, variation-analysis and workflow fixtures | Hash/h2 lane active; do not claim Burp Pro parity |
| P5: native ARTEX M1 | Reasoned license position before linkage; isolated kernel + one-shot transport contract + mock-model loopback before desktop integration | Isolated builder authorized after CTO corrections; implementation not yet verified |
| Later: ARTEX M2-M6 / broad beyond-Burp roadmap | Separate acceptance criteria and owner prioritization | Not a near-term commitment; #121 is planning input |

## Evidence and refresh rules

- Live GitHub open-PR API, all pages, plus fetched PR refs and `git merge-base --is-ancestor` against the pinned parity/#125 heads establish inventory and exact inclusion.
- Triage CSV supplied at about 13:00 provides prior classification/test evidence. CSV fields explicitly label this historical evidence. A source-head result is reused only if its SHA still matches, and never promoted to a combined-tree pass.
- PR bodies provide reported scope and claimed verification, not owner authority. #122 and #127 have a known policy conflict resolved using the owner's later message.
- `tasks.json` is copied into the milestone register as recorded status. The Program Manager did not rerun Rust tests for this docs-only board.
- After each material change: refresh all open PR pages; pin parity and #125; recompute ancestry; record new source heads and actual test SHAs; update holds; send a short digest of changed state, remaining blocker and next checkpoint. Keep unrelated historical test counts out of a current acceptance claim.

Primary evidence links: [#125](https://github.com/Chaim12345/webprobe/pull/125), [#123](https://github.com/Chaim12345/webprobe/pull/123), [#127](https://github.com/Chaim12345/webprobe/pull/127), [#128](https://github.com/Chaim12345/webprobe/pull/128). Every open PR's observed URL is in the CSV.

## Management change log

- 13:08: detected latest #123 missing from #125 and parallel parity movement.
- 13:09: verified #125 `2b756c1` contains latest #123 and parity `b1ef6b4`; cleared those warnings.
- 13:10: #129 resolution PR and #130 product-priority proposal are now in the inventory. #131 is this board. Prioritize review and verification, not duplicate implementation.

- 13:13: #129/#105 landed; #102 awaits exact-head review, #49 needs author follow-up. Owner delegated routine decisions. CEO/CTO settled MIME, bounded parser scope, non-destructive Organizer delete, agent rails, no timing-based smuggling, and isolated ARTEX builder start. QA/release, security/compliance, engineering management and DevOps roles started. #132 supplies technical rulings.

- 13:14: CEO recorded D-CEO-01..04 in [#133](https://github.com/Chaim12345/webprobe/pull/133): MIME gate, delete-to-Inbox, private fresh-branch ARTEX kernel/mock, and private local separate-process boundary pending dependency/rights review. These are recorded management decisions under the autonomy delegation, not new requests for owner approval.

- 13:17: linked HR staffing register #137. New-position requests require an uncovered outcome, approving manager and staffing-gap evidence; HR prepares the spec, the accepting manager approves it through project coordination, then the role is created.

- 13:27: refreshed full 115-PR inventory and added REVIEW-LEDGER.md for requested exact-head states. #96 landed; latest #123 inclusion gap reopened at f22016f. #136 current delta awaits confirmation beyond prior 043f025 approval. Security #143 and D-CEO-05 #144 recorded without adopting unsupported ownership/relicensing or enforcement-risk conclusions. artex-rs #2 f2b31c1 has code-read approval and builder-reported 27 tests x12, not durable-store/binary-adapter acceptance.

- 13:29: reviewer approved #74/#138/#141/#142/#136 current 741d0b5 and docs #133/#135/#137/#143/#144 (scope in ledger). ARTEX #2 advanced to 5eba878 for K3 grammar; prior f2b31c1 approval is no longer current, re-review pending. Builder reports 28 tests x10 on the new head; hosted/current independent acceptance remains unverified.

- 13:34: #145 sequential h2 reuse added as CHANGES NEEDED for duplicate-send replay, pool identity/policy and connection receive-window credit. #139 is an independent sibling after #124 and need not wait for h2 repair. #141 54d6068 and #142 2178122 approved after parity retargeting; #141 cursor nit resolved. #134 reviewer store() correction conflicts with PM exact-head file-API evidence showing fetch_max; returned for source reconciliation. Inventory delta adds #145 to the prior snapshot rather than claiming a new full census.

- 13:37: #146 2a08ffe reviewer-approved as fixtures only. CTO assigns lane 15 to (2) message/leftovers ownership, then (1)+(4) narrow 400+close inbound framing guards; h2 lane owns (3) authoritative method-aware reuse and declined-h2c pooling disablement before rebasing #145. These are approved fixes, not owner questions. Full strict response/chunked setting stays unwired. #134 source discrepancy resolved: reviewer had read older 586c980; current 4e1be6a uses fetch_max.

- 13:44: full live refresh finds 113 open PRs, parity 7f2ab33, #125 52ba16b with current parity/#123/#134 included. #134 and #147 confirmed merged. Reproduced #124 Unicode/GZIP defects block #139 and #125 acceptance; reassigned Decoder author is working on a bounded replacement. #145 advanced to ecc4deb; renewed review required.

- 13:56: refreshed 112-PR open inventory and parity c25056d. #125 ad4aa05 drops defective Decoder ops; earlier reviewer rejection cleared only for specified reasons. #145 1a9f334 code-approved with replay/pool-key test gaps. #148 f19e8b9 CTO R1-R4 remains blocked; #149 landed and superseded #126; #150 2efa9e2 Decoder repair is in review. Reviewer scopes #124 approval to h2 fragmentation only.

- 14:15: live parity a2fd3d2 carries #141/#152 and #151/#154. #125 da15eb9 must refresh; #153 ca5048f h1 safety can land independently after real parity rebase, while #155 follows the canonical #125 tree. #145 f2d966f replay proof reviewed, TLS-policy constraints/snapshot gate remains. Added canonical RELEASE-CHECKLIST.md with lane-5 crawler no-implicit-resend release gate. #150 code-read approved and yaml dependency review CLEAR.

- 14:18: follow-up to reviewer-approved #131 5dc587c records the four requested accuracy corrections; see ledger and checklist. Own board-row SHA is intentionally blank because committing a claimed self-SHA would make it stale again; its PR link is the current-head source.

- 14:22: requested follow-up adds canonical crawler wording and tracks #156 6cc9be9, #157 3601cd3, #158 c014c96. Live heads #153 010de0e, #145 5588537, #125 3ebbd6b and parity cd1e5f1 recorded. CTO TLS-policy items closed by source inspection; new-head independent and executed gates remain separate.

- 14:46: successor snapshot after #131 landing; 108 open PRs, parity 2ea9447. Six recent landings recorded, #145 a88dfe9 QA pending, #125 c394399 baseline-policy correction and #155 73ff441 resolved-stack re-review required. Fix-only approvals do not certify carried old stacks.

- 15:16: full 113-PR snapshot at parity 5c15280. #70/#68/#159 landed and #67 closed after proof; #161-#168 added with exact review/dependency scopes. Acceptance freeze protects final #145 -> single #125 refresh -> resolved #155 sequence. #145 triage execution passed; independent QA remains awaited.

- 15:47: parity/canonical heads unchanged, 115 open PRs. #168 advanced to approved18e12d6; #169 a3d5ce2 approved; #170 f5a9370 core-design approval carries unimplemented should-fixes. #145 QA ETA corrected after missed checkpoint; triage pass and independent acceptance remain separate.

- 17:19: live 115-PR inventory and parity 5c15280 unchanged. Independent QA accepted #145 a88dfe9 exact head at 17:15,1017/0/13 and corrected19/19 valid selectors, with zero-match treated as failure. Independent merged-tree verification remains in flight. Historical 24-item ETA/list entries below describe the superseded list, not 24 distinct executed fixtures.

- 17:50: live 114 open, final parity 4ad2591 after #145 landing; #125 3108302 refresh and #155 c6d0cae clean combination are published. Independent #145 exact/merged acceptance complete. Final-candidate QA launched 17:33; full carried-stack review and UI gates remain separate. Freeze preserved.
