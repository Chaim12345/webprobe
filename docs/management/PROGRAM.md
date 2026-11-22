# WebProbe program board

Snapshot: 2026-11-22 14:15 Asia/Jerusalem. Program owner: Program Manager. [Canonical release checklist](RELEASE-CHECKLIST.md). [Review and decision ledger](REVIEW-LEDGER.md). [Role charters](ROLES.md). [HR staffing register, PR #137](https://github.com/Chaim12345/webprobe/pull/137), proposed file `docs/management/STAFFING.md`.

This is the index for sequencing, not permission to merge or change product behavior. Only the triage lane lands parity changes. Existing PR branches and master stay untouched. Refresh this board when a source head, landing, decision or verification result changes.

## Current position

- Live parity `a2fd3d2fc709994ad48e649a4198eace4a7226b3`. Live API confirms #141/#152 and #151/#154 are merged; #154 preserves authoritative response reuse plus fixture adaptations. #149 already replaced #126.
- Single review stack #125 is `da15eb96a3192da2d05205ae4c33aa53680a5920`, from parity c25056d, not current a2fd3d2. Integration reports 987 workspace + 13 real-Java tests on da15eb9. Refresh after #154 and repeat exact-head gates; keep its adapted framing expectations intact. Earlier Decoder rejection is resolved and yaml_serde dependency review is CLEAR.
- **113 open WebProbe PRs**, all pages checked at 14:15. The CSV contains open PRs; landed history and scoped verdicts remain in the ledger.
- **New browser-crawl release gate:** crawl.rs::replay_seen may resend an already browser-observed request when response metadata is missing. Lane 5 is assigned the focused fix. Fix it or disable automatic fallback before shipping/enabling that flow. #153 must not be described as removing every application-level replay; negotiated-h2 replay is #145's scope. See the canonical release checklist.
- H1 safety #153 19dc879 is reviewer-approved (ca5048f superseded) and CTO accepts its bounded caller audit. Rebase on actual #154 parity and rerun gates. It can land independently of #125 and the crawler follow-up.
- H2 #145 f2d966f is reviewer-approved, but CTO still blocks on complete TLS-policy identity (including root name constraints), adequate valid-mTLS/key/fallback fixtures and one effective-policy snapshot for key and connection. The primed stream-3 POST/commitment proofs are now source-reviewed, no longer missing.
- Request reconciliation #155 current 90173f7 follows #125, replacing #148, but reviewer verdict is CHANGES NEEDED: old unsafe reuse heuristic plus guard/reader mixed-CRLF/LF boundary mismatch. Trailing-CRLF discard supplied by #155 addresses #148 reviewer condition but does not clear these new blockers.
- Decoder #150 2efa9e2 is code-read approved, with combined/UI landing gates remaining. Its GZIP/base64 UTF-8 panel is a labeled departure from arbitrary-byte Burp behavior. #139 rebases after accepted repair.
- [Milestone register](milestones.csv) preserves historical tasks; do not start duplicate work based on old todo labels.

## Landing sequence and stop/start calls

1. **One parity writer: triage.** Finish the already reviewed, independently tested queue. #129/#105 has landed. Triage reports 832 passing tests on the exact merged resolution tree with both header-scan test modules preserved. The #149 replacement is landed and #126 closed. PR #141/#152 is landed. Advance reviewed #140/#150/docs independently while the #153 rebase and crawler/h2 fixes proceed.
2. **Integration owns #125.** Latest #123 and HPACK fix are included and defective Decoder ops are removed. Preserve the source manifest, refresh from newer parity, preserve the cleared yaml lock, take #154 adaptations, and use canonical-first #155 reconciliation rather than racing #148. Incorporate the new hash/h2 and crawl-ID heads when ready. Maintain an exact source-head manifest. No parallel landing of the same changes through individual source PRs.
3. **Independent reviewer owns acceptance.** Review the final SHA, not a moving branch. Require clean check/fmt/clippy/full required-Java tests and current CI, applying only the owner's explicit Kilo waiver. Test count deltas alone are not coverage proof.
4. **Cross-tool QA owns the release candidate.** Run project create/save/reopen, Logger to tools, Repeater extension hooks, extension Drop plus pipelining, constant-token Sequencer, Intruder baseline, Decoder bytes/Gzip, and Organizer persistence on one integrated build. #128 is separate-head evidence, not an integrated pass.
5. **Only then clean up source PRs.** Triage may close exact-proof superseded PRs with approved wording. Commit ancestry alone does not choose between sequential landing and closing a historical milestone. The #103 MIME decision is settled; #97 closure still needs exact-proof checks.
6. **Start only non-overlapping new work.** Hash-list/h2 and crawl selection-key work continue in their existing lanes. Stop duplicate R-16/R-18/R-20 implementations; those have reviewed source work already. ARTEX isolated kernel/mock work is approved on a new private artex-rs branch after CTO contract corrections. No WebProbe linking or combined distribution before a reasoned license position is recorded. No new broad refactor during the integration freeze.

## Lane ownership

| Lane | Accountable role | State / next checkpoint | Blocker or conflict boundary |
| --- | --- | --- | --- |
| Parity landing and PR cleanup | PR triage | Active; #141/#152 and #151/#154 landed; #140/#150/docs and #153 rebase next | Sole parity writer; no source-branch edits |
| Review stack #125 | Integration | Active at da15eb9; refresh with #154, then exact-tree gates; #155 follows canonical stack | Conflicts with independent source landing if both proceed unchecked |
| Independent review | Reviewer | Review exact final heads and combination fixes | Earlier approvals do not cover later diffs |
| Hash-list and h2 multiplexing | Existing hash/h2 lane | Active per owner request; publish exact head + tests | Coordinate h2 boundaries with #124; no duplicate Decoder work |
| Crawl counter and selection keys | Existing UI QA B lane | Active follow-up; use `(kind,id)` identity before separate counters | Shared history/crawl selection is load-bearing; #108 project-isolation work is separate |
| Integrated workflow QA | QA / release | Started; accept only a pinned integrated candidate | Must not reuse separate-head #128 results as final acceptance |
| ARTEX kernel / license | CTO to assign | Isolated kernel/mock authorized after CTO contract corrections | License choice gates WebProbe linkage; one manifest owner per wave |
| Priorities / owner choices | CEO + owner | Decide only unresolved product/license questions | No implied approval from a PR description |
| Board and dependencies | Program Manager | Maintain these registers and short change digests | Route cross-lane changes through agreed leads |

These are responsibility assignments, not a claim that every proposed lane has started.

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
| P1: one reviewable integrated candidate | #125 manifest matches latest intended source heads; clean combined checks + independent review | da15eb9 checked; yaml clear; #154 refresh and final exact-tree acceptance remain |
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
