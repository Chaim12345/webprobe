# WebProbe program board

Snapshot: 2026-11-22 13:13 Asia/Jerusalem. Program owner: Program Manager. [Role charters](ROLES.md).

This is the index for sequencing, not permission to merge or change product behavior. Only the triage lane lands parity changes. Existing PR branches and master stay untouched. Refresh this board when a source head, landing, decision or verification result changes.

## Current position

- Parity snapshot: `d0e56832150334854665269fb9e2c27dc8c23058`, after #45, #51, #95, #100 and #129/#105. These landings are not a release or full parity certification.
- Single review stack: **#125**, observed head `2b756c1b37dae00d8f790f0b1f83471838e4060a`. Its body reports 845 passing checks on an earlier tested tree. Do not attach that count to a later SHA without new evidence.
- **107 open PRs** in the 13:13 paginated snapshot; the register additionally includes newly opened CEO decision PR #133 from the 13:14 delta (108 rows). [PR board](pr-board.csv) has one row per open PR: exact head, lane owner, status, blocker, next action and evidence scope.
- **21 current open heads are ancestors of #125**, including #125 itself. This proves commit inclusion, not semantic correctness or approval to close source PRs.
- **Latest #123 `db2cd8d` is now included in #125**, via `92c1ee5`. #125 merged parity `b1ef6b4`, but parity has since advanced to `d0e5683` with #129/#105. Latest-UI inclusion is resolved; reconcile the newly moved base and repeat exact-tree acceptance.
- [Milestone register](milestones.csv) preserves all 137 tasks from parity's `tasks.json`: 114 recorded done, 21 todo, 2 rejected. These are historical repository labels, not fresh verification. Open labels can describe work already present in review PRs. Map coverage before assigning builders.

## Landing sequence and stop/start calls

1. **One parity writer: triage.** Finish the already reviewed, independently tested queue. #129/#105 has landed. Triage reports 832 passing tests on the exact merged resolution tree with both header-scan test modules preserved. #102 is the next independently reviewed/tested candidate; its combined 857-pass report is not yet a landing.
2. **Integration owns #125.** Latest #123 is included, but reconcile the subsequent #129 parity advance. Incorporate the new hash/h2 and crawl-ID heads when ready. Maintain an exact source-head manifest. No parallel landing of the same changes through individual source PRs.
3. **Independent reviewer owns acceptance.** Review the final SHA, not a moving branch. Require clean check/fmt/clippy/full required-Java tests and current CI, applying only the owner's explicit Kilo waiver. Test count deltas alone are not coverage proof.
4. **Cross-tool QA owns the release candidate.** Run project create/save/reopen, Logger to tools, Repeater extension hooks, extension Drop plus pipelining, constant-token Sequencer, Intruder baseline, Decoder bytes/Gzip, and Organizer persistence on one integrated build. #128 is separate-head evidence, not an integrated pass.
5. **Only then clean up source PRs.** Triage may close exact-proof superseded PRs with approved wording. Commit ancestry alone does not choose between sequential landing and closing a historical milestone. The #103 MIME decision is settled; #97 closure still needs exact-proof checks.
6. **Start only non-overlapping new work.** Hash-list/h2 and crawl selection-key work continue in their existing lanes. Stop duplicate R-16/R-18/R-20 implementations; those have reviewed source work already. ARTEX isolated kernel/mock work is approved on a new private artex-rs branch after CTO contract corrections. No WebProbe linking or combined distribution before a reasoned license position is recorded. No new broad refactor during the integration freeze.

## Lane ownership

| Lane | Accountable role | State / next checkpoint | Blocker or conflict boundary |
| --- | --- | --- | --- |
| Parity landing and PR cleanup | PR triage | Active; #129/#105 landed, #102 review, #49 follow-up held | Sole parity writer; no source-branch edits |
| Review stack #125 | Integration | Active; latest #123 included; reconcile new parity d0e5683 | Conflicts with independent source landing if both proceed unchecked |
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
| ARTEX / WebProbe license | D-CEO-04: private local separate-process only; no linking, combined distribution or remote exposure before dependency/rights review | Isolated private artex-rs kernel/mock work may proceed after CTO corrections; process separation is not automatic legal clearance |
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
| P0: recover and stabilize foundation | Exact merged tree and full required-Java suite per landing | #45/#51/#95/#100/#129 landed; #102 review and #49 follow-up remain |
| P1: one reviewable integrated candidate | #125 manifest matches latest intended source heads; clean combined checks + independent review | In progress; latest #123 included, reconcile new d0e5683 parity |
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
