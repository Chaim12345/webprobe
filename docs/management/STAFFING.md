# WebProbe staffing register

Snapshot: 2026-11-22 13:16 Asia/Jerusalem. Maintainer: HR. This register complements the PM board; it does not replace technical ownership, grant access or approve a release.

## Management positions

| Position | Accountable owner | State | Acceptance boundary |
| --- | --- | --- | --- |
| Product and priorities | CEO | Filled | Product decisions and reasoned licensing position |
| Architecture | CTO | Filled | Technical contracts, compatibility and safety rules |
| Program coordination | PM | Filled | Single board, dependencies and exact-head status |
| Engineering management | Engineering manager | Filled | Author assignment and shared-file boundaries |
| Release acceptance | QA / release manager | Filled | Exact-build regression evidence, independent of authors |
| Security and compliance | Security / compliance lead | Filled | Dependency, rights, privacy and secrets findings |
| Build and delivery | DevOps / CI owner | Filled | Unfiltered workspace gate; preserve required JVM jobs |
| Staffing | HR | Filled | Position specs, responsible-manager approval and roster |

Filled means the position has an assigned owner, not that its outcome has passed acceptance.

## Execution positions

| Position | Current owner / lane | State | Next evidence or gate |
| --- | --- | --- | --- |
| Parity landing | PR triage | Filled | Sole parity writer; current exact-tree landing gates |
| Combined review stack | Integration | Filled | Reconcile #125 to moved parity; source-head manifest |
| Independent source review | Reviewer | Filled | Exact-head findings; do not imply unexecuted tests |
| Cross-check testing | Roadmap tester 1 and tester 2 | Existing assignments | Engineering/QA to reconcile current work before reassignment |
| Hash-list and h2 work | Hash/h2 lane | Filled | Protocol-specific regression fixtures and reviewable head |
| Crawl selection / counters | UI QA B lane | Assigned follow-up | Source-kind plus id identity, migration tests and screenshots |
| Runtime cancellation follow-up | Roadmap implementation A | Assigned follow-up | #49 cooperative-exit evidence and honest in-flight status |
| Parser compatibility fixtures | Parser-fuzz lane | Existing assignment | Preserve #96 tests-only scope; production policy requires CTO ruling |
| Passive-library coverage | Coverage lane | Existing assignment | Exact-head test evidence and independent review |
| Independent change watch | Read-only reviewer | Filled | Findings only; no source-branch changes |
| ARTEX M1 isolated prototype | ARTEX M1 kernel builder | Filled | Corrected #135 contract, owned-loopback h1/mock evidence |
| Organizer delete-to-Inbox | Engineering manager to confirm existing owner | Ownership check pending | Check current branches/assignments before any hiring request |

Existing assignments are evidence of responsibility, not a claim that new follow-ups have been acknowledged or completed. This register does not create new implementation assignments.

## Hiring process

1. A manager or PM identifies an uncovered outcome, with evidence that existing owners cannot cover it without a conflict or unacceptable delay.
2. HR checks the board, current assignments and current repository work to avoid duplicate positions.
3. HR proposes a position spec: role, charter, scope, inputs, outputs, standing rules, escalation, success evidence, budget/lifetime and exclusions.
4. The responsible manager explicitly approves the exact spec or requests changes. A request for more staff is not approval of a different spec.
5. Only after approval does the designated coordinator appoint the position. HR records the owner and approval reference. Appointment is not acceptance of the delivered work.
6. A temporary position ends when its defined evidence is accepted, or returns to the manager for a renewed bounded scope. No automatic expansion into a standing department.

## Required boundaries

- Never merge to master. Use a new non-master branch and a reviewable PR. Do not change another author's existing branch.
- PR triage remains the sole parity writer; staffing approval does not grant landing rights.
- Use the approved saved credential. Never print or commit secrets, credential files or private authentication data.
- Report through the designated coordinator. Conflicting ownership or authority goes to the responsible manager before the affected work proceeds.
- Keep authoring, independent review and release acceptance separate. Report exact source/build heads and distinguish executed evidence from reported claims.
- No new spending, repository settings changes, external target activity or distribution rights are created by a position spec.
- ARTEX remains private local separate-process evaluation only. No WebProbe linking, combined distribution or remote exposure without a broader recorded decision after dependency/rights review.

## Open staffing decisions

- Organizer: confirm current author coverage before proposing a position. Engineering owns this check; PM owns its board entry.
- No additional documentation, commercial or administrative position is justified by the current board. PM owns the index; source authors own source-specific docs.
- ARTEX M1 is already staffed. Do not hire a second kernel builder. Any independent ARTEX acceptance gap must first be checked with QA and CTO.
- Managers may request new positions through the coordinator. HR records requests and drafts specs; it does not self-approve them.

## Evidence and freshness

- [Program board and charters, #131](https://github.com/Chaim12345/webprobe/pull/131), observed at f3f81ce2cbc5e529bd4ccfd1a5bc9e52d72e6bf8.
- [CTO architecture review, #132](https://github.com/Chaim12345/webprobe/pull/132).
- [CEO decisions, #133](https://github.com/Chaim12345/webprobe/pull/133).
- [Corrected ARTEX contract, #135](https://github.com/Chaim12345/webprobe/pull/135), observed at 9ea75de5fc023699f870d1d064c54dbcc6d56be7.
- Current assignment inventory was checked at 13:15. Follow-up acknowledgement and execution remain separately tracked by engineering/PM.

Docs-only staffing snapshot. No Rust tests, runtime checks, release acceptance or new hiring approval are claimed.
