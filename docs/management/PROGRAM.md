# WebProbe program board

Snapshot: 2026-11-22 14:46 Asia/Jerusalem. Program owner: Program Manager. [Canonical release checklist](RELEASE-CHECKLIST.md). [Review and decision ledger](REVIEW-LEDGER.md). [Role charters](ROLES.md). [HR staffing register, PR #137](https://github.com/Chaim12345/webprobe/pull/137), proposed file `docs/management/STAFFING.md`.

This is the index for sequencing, not permission to merge or change product behavior. Only the triage lane lands parity changes. Existing PR branches and master stay untouched. Refresh this board when a source head, landing, decision or verification result changes.

## Current position

- Live parity `2ea9447f461f01d7288e46b73f15e4978bba790b`; **108 open PRs at 14:46**, full paginated refresh and exact ancestry recomputed; the CSV additionally includes successor #160 self-row created afterward. The prior board PR #131 landed at this parity. This is its management-only successor snapshot, not a change to that merged branch.
- Since the previous snapshot, #157, #156, #153, #158, #136 and #131 landed. Triage reports exact tested/remote tree equality and required gates for each. Latest landing #131 has triage-reported 1009 combined passes /13 ignored. This is not final #125 acceptance or PM test execution.
- Canonical #125 is `c39439946b31f2358e9770df12c94feabb596079`. It includes the earlier #140/#154 refresh, but needs the CTO's Intruder baseline-policy correction and newer parity reconciliation. Automatic baseline only for GET/HEAD; skip effectful/unknown methods visibly, leaving baseline comparison unavailable. Attack rows stay unchanged. Planned preflight and error retry are distinct, but neither justifies an implicit extra POST effect.
- H2 #145 is `a88dfe91feb7410d5ea8983da06823a9c5b9483e`, reviewer code-read APPROVED. The resolved h1 tail preserves landed #153 no-replay behavior; h2 typed retry uses the same policy snapshot. Exact-head QA is underway, not complete. CTO conditional design approval remains sequential exclusive reuse, not concurrent multiplexing; reviewer Arc-address identity and per-request client-auth-build notes remain.
- Request-reader #155 is `73ff441abd8c1dc2af6bfb0e4c093d11846eefcd`. CTO R1 source issue is closed and its design acceptance is conditional; reviewer approves the new own commit, not the full carried #125 stack. Current remote head conflicts with newer parity. Local resolved ae88b49 is unpushed, unreviewed, and has a baseline-related replay fixture failure. Fix #125 baseline policy first, then publish/review/QA the resolved combination. No ordinary-listener macro exploit reachability claim.
- Approved independent code-read queue: #70 `092d890`, #68 `1a30bf8`, #64 `8078183` (library-only), and #159 `49769d4` tests replacement. Triage is testing these. #64 needs nesting-limit hardening before loading/UI exposure. Old #67 and #139 stay open until complete replacement proof, not merely a matching title or cherry-pick.
- Old-stack repairs #83/#69/#71/#84/#86 have fix-commit approvals only. Read-only feature-slice audits must identify unique missing contributions; no merge from fix-only review and no title-only closure. Lane A reports 31 audited, zero closure-ready. These audit findings are not executed tests.
- Historical milestones remain in [milestones.csv](milestones.csv). The checklist distinguishes scoped landed execution from still-unchecked final integrated acceptance.

## Landing sequence and stop/start calls

1. **Triage alone writes parity.** Advance the independently reviewed #70/#68/#64/#159 queue only after exact combined gates; preserve #64's unwired boundary. No edits to source authors' existing branches.
2. **QA owns #145 acceptance.** Pin a88dfe9, execute full required-Java and named replay/policy fixtures, then let triage verify the final merged tree. Do not restore h1 error replay.
3. **Integration corrects #125 baseline policy.** GET/HEAD-only automatic baseline; skipped effectful/unknown baselines are visible and comparison fields unavailable. Prove one requested POST effect after response loss, effectful attack-row-only sends, GET baseline, Stop/channel delivery and pool-permit behavior.
4. **Request-reader lane follows that corrected canonical stack.** Reconcile parity Result handling in ws.rs, test-module keep-both and engine close-return polarity. Publish a final resolved SHA for independent whole-stack review and QA. Reject bare-LF/mixed heads on guarded ingress while preserving raw testing traffic and LF body bytes; h2-upstream downstream-close fallback remains conservative.
5. **Only after actual #125+#155 landing**, verify pipeline/drop-close/nonblocking-drain preservation and then propose #148 supersession/#110 integration closure. #67/#139 need full cherry-pick replacement proof after the replacement lands. No blanket closure based on an audit summary.
6. **Read-only audits precede fresh old-stack slices.** Preserve source branches. Triage owns preparation/landing; reviewer accepts the whole proposed stack, not only a repair commit. Stop duplicate feature implementations and broad refactors during integration.
7. **Release QA remains separate.** One pinned combined build must pass project save/reopen, history-to-tools, Repeater extensions/Drop/pipelining, Intruder baseline and replay, Sequencer, Decoder and Organizer workflows with evidence. Prior separate-head counts do not tick this gate.

## Lane ownership

| Lane | Accountable role | Current next checkpoint | Boundary |
| --- | --- | --- | --- |
| Parity landing / cleanup | Triage | Execute approved independent queue; land exact accepted trees | Sole parity writer; no title-only closure |
| Canonical #125 | Integration | Implement baseline ruling, reconcile latest parity, publish pinned review tree | No hidden effectful baseline; preserve landed safety fixes |
| #155 request boundary | Request-reader lane + CTO/reviewer/QA | Follow corrected #125; publish resolved whole-stack head | No approval transfer from local ae88b49 or own-commit review |
| #145 h2 | Existing h2 lane + QA | Execute a88dfe9 acceptance matrix | Sequential exclusive reuse; preserve h1 no-replay |
| Independent queue | Existing authors + reviewer/triage | #70/#68/#64/#159 combined gates | #64 library-only until nesting hardening |
| Old-stack feature audits | Read-only audit lanes | Unique retained/missing feature slices | No pushes/comments/closure in audit lane |
| Integrated workflow QA | QA / release | Pinned final integrated candidate | No separate-head acceptance transfer |
| ARTEX | CTO / isolated builder; CEO license scope | Last recorded isolated kernel/mock scope, recheck before effects | D-CEO-05 private/local/separate-process only |
| Program board | Program Manager | Publish management-only successor; gated refresh | Timestamped evidence, no source mutations |

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
| P1: one reviewable integrated candidate | #125 manifest matches latest intended source heads; clean combined checks + independent review | c394399 current; baseline-policy correction and newer parity reconciliation required |
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
