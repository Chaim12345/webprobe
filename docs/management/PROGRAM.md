# WebProbe program board

Snapshot: 2026-11-22 13:09 Asia/Jerusalem. Program owner: Program Manager.

This is the index for sequencing, not permission to merge or change product behavior. Only the triage lane lands parity changes. Existing PR branches and master stay untouched. Refresh this board when a source head, landing, decision or verification result changes.

## Current position

- Parity snapshot: `b1ef6b4a07d384fb1a58ae145cc278328d7c2c44`, after #45, #51, #95 and #100. These landings are not a release or full parity certification.
- Single review stack: **#125**, observed head `2b756c1b37dae00d8f790f0b1f83471838e4060a`. Its body reports 845 passing checks on an earlier tested tree. Do not attach that count to a later SHA without new evidence.
- **106 open PRs**, retrieved across both API pages. [PR board](pr-board.csv) has one row per open PR: exact head, lane owner, status, blocker, next action and evidence scope.
- **21 current open heads are ancestors of #125**, including #125 itself. This proves commit inclusion, not semantic correctness or approval to close source PRs.
- **Latest #123 `db2cd8d` is now included in #125**, via `92c1ee5`. #125 also merged parity `b1ef6b4`. Earlier missing-head and moving-base warnings are resolved; fresh acceptance on the new combined tree remains required.
- [Milestone register](milestones.csv) preserves all 137 tasks from parity's `tasks.json`: 114 recorded done, 21 todo, 2 rejected. These are historical repository labels, not fresh verification. Open labels can describe work already present in review PRs. Map coverage before assigning builders.

## Landing sequence and stop/start calls

1. **One parity writer: triage.** Finish the already reviewed, independently tested queue. #105 needs a new resolution branch after #100; retain both test-module declarations in `net/mod.rs`. Review and test the resolved combined tree, not either source in isolation.
2. **Integration owns #125.** Base and #123 are reconciled at this snapshot. Incorporate the new hash/h2 and crawl-ID heads when ready. Maintain an exact source-head manifest. No parallel landing of the same changes through individual source PRs.
3. **Independent reviewer owns acceptance.** Review the final SHA, not a moving branch. Require clean check/fmt/clippy/full required-Java tests and current CI, applying only the owner's explicit Kilo waiver. Test count deltas alone are not coverage proof.
4. **Cross-tool QA owns the release candidate.** Run project create/save/reopen, Logger to tools, Repeater extension hooks, extension Drop plus pipelining, constant-token Sequencer, Intruder baseline, Decoder bytes/Gzip, and Organizer persistence on one integrated build. #128 is separate-head evidence, not an integrated pass.
5. **Only then clean up source PRs.** Triage may close exact-proof superseded PRs with approved wording. Commit ancestry alone does not choose between sequential landing and closing a historical milestone. Keep #97 held while #103 is undecided.
6. **Start only non-overlapping new work.** Hash-list/h2 and crawl selection-key work continue in their existing lanes. Stop duplicate R-16/R-18/R-20 implementations; those have reviewed source work already. ARTEX may prepare isolated kernel and license analysis, but do not combine code or distribute it before the license choice. No new broad refactor during the integration freeze.

## Lane ownership

| Lane | Accountable role | State / next checkpoint | Blocker or conflict boundary |
| --- | --- | --- | --- |
| Parity landing and PR cleanup | PR triage | Active; #105 resolution, remaining review queue | Sole parity writer; no source-branch edits |
| Review stack #125 | Integration | Active; base and latest #123 reconciled, new-head tests awaited | Conflicts with independent source landing if both proceed unchecked |
| Independent review | Reviewer | Review exact final heads and combination fixes | Earlier approvals do not cover later diffs |
| Hash-list and h2 multiplexing | Existing hash/h2 lane | Active per owner request; publish exact head + tests | Coordinate h2 boundaries with #124; no duplicate Decoder work |
| Crawl counter and selection keys | Existing UI QA B lane | Active follow-up; use `(kind,id)` identity before separate counters | Shared history/crawl selection is load-bearing; #108 project-isolation work is separate |
| Integrated workflow QA | Proposed QA lead | Start once integration candidate is pinned | Must not reuse separate-head #128 results as final acceptance |
| ARTEX kernel / license | CTO to assign | Plan #127; builders not yet confirmed | License choice gates WebProbe linkage; one manifest owner per wave |
| Priorities / owner choices | CEO + owner | Decide only unresolved product/license questions | No implied approval from a PR description |
| Board and dependencies | Program Manager | Maintain these registers and short change digests | Route cross-lane changes through agreed leads |

These are responsibility assignments, not a claim that every proposed lane has started.

## Decision register

| Decision | Status and scope | Next action / affected work |
| --- | --- | --- |
| #103 Content-Type handling | Open: require form/JSON MIME for body macro substitution, or retain wider legacy behavior | Owner chooses; hold #103 behavior and #97 replacement closure |
| #96 parser strictness | Open for behavioral strictness changes; test PR is distinct | Triage/CTO present strictness deltas separately from fuzz/property coverage |
| ARTEX / WebProbe license | Open: plan reports AGPL-only ARTEX and no root WebProbe license | Owner selects license/distribution approach before combining or distributing; process separation is an option to assess, not a legal conclusion |
| Organizer deletion | Open; collection creation #120 does not settle deletion semantics | Specify what deleting a collection does to contained items; add persistence and migration tests |
| Per-step ARTEX approval | Resolved for WebProbe integration: requirement removed by owner on Nov 22 at 12:53 | #127 supersedes #122 on this point; preserve the policy hook, do not restore old requirement by accident |
| ACP exposure | Owner requested Nov 22 at 12:50 | Keep the option in the ARTEX plan; kernel/linkage decisions remain separate |
| Kilo failure gate | Owner waived Nov 22 at 13:02; triage recovered original | Do not waive other CI, review or regression failures |

Decision provenance: owner's authenticated WhatsApp messages were checked for ACP and per-step policy. Other unresolved choices are carried forward from project coordination, not inferred from PR text. This board does not create grants or approve future spending, disclosures or actions.

## Milestone ordering

| Program milestone | Exit evidence | Current state |
| --- | --- | --- |
| P0: recover and stabilize foundation | Exact merged tree and full required-Java suite per landing | #45/#51/#95/#100 landed at snapshot; remaining queue open |
| P1: one reviewable integrated candidate | #125 manifest matches latest intended source heads; clean combined checks + independent review | In progress; latest #123 and current parity included |
| P2: integrated workflow acceptance | One pinned build passes cross-tool regression with screenshots and traceable fixtures | Not established by separate-head reports |
| P3: reconcile old roadmap | Each of 21 recorded todo tasks mapped to integrated code, residual gap or owner hold | PR board ready; avoid reopening already implemented milestones |
| P4: close measured parity gaps | #128 priorities translated into owned byte-safe Decoder, h2, Sequencer, variation-analysis and workflow fixtures | Hash/h2 lane active; do not claim Burp Pro parity |
| P5: native ARTEX M1 | License gate settled; isolated kernel + typed history/send adapter + mock-model loopback + desktop panel | Plan #127 only; no implementation claimed |
| Later: ARTEX M2-M6 / broad beyond-Burp roadmap | Separate acceptance criteria and owner prioritization | Not a near-term commitment; #121 is planning input |

## Evidence and refresh rules

- Live GitHub open-PR API, all pages, plus fetched PR refs and `git merge-base --is-ancestor` against the pinned parity/#125 heads establish inventory and exact inclusion.
- Triage CSV supplied at about 13:00 provides prior classification/test evidence. CSV fields explicitly label this historical evidence. A source-head result is reused only if its SHA still matches, and never promoted to a combined-tree pass.
- PR bodies provide reported scope and claimed verification, not owner authority. #122 and #127 have a known policy conflict resolved using the owner's later message.
- `tasks.json` is copied into the milestone register as recorded status. The Program Manager did not rerun Rust tests for this docs-only board.
- After each material change: refresh all open PR pages; pin parity and #125; recompute ancestry; record new source heads and actual test SHAs; update holds; send a short digest of changed state, remaining blocker and next checkpoint. Keep unrelated historical test counts out of a current acceptance claim.

Primary evidence links: [#125](https://github.com/Chaim12345/webprobe/pull/125), [#123](https://github.com/Chaim12345/webprobe/pull/123), [#127](https://github.com/Chaim12345/webprobe/pull/127), [#128](https://github.com/Chaim12345/webprobe/pull/128). Every open PR's observed URL is in the CSV.
