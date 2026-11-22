# WebProbe company roles and operating boundaries

Updated 2026-11-22 18:26 Asia/Jerusalem. The owner delegated routine project decisions to management at 13:12. This roster assigns responsibility; it does not expand repository access, spending authority or distribution rights.

| Role | Charter | Start/state | Escalation and handoff |
| --- | --- | --- | --- |
| CEO / product | Choose product behavior, priorities and a reasoned license position | Active | Return product decisions to PM; unresolved legal basis goes to security/compliance and owner if necessary |
| CTO | Architecture, parser policy, safety rules, smuggling boundary and ARTEX transport contract | Active | Provide a written ruling and acceptance tests; do not substitute design review for executed QA |
| Program Manager | Single program index, dependency map, decision log and change digests | Active | Flag conflicting ownership, stale head claims and missing acceptance evidence to the relevant lead |
| Engineering Manager | Dispatch author lanes, cap work in progress, protect file ownership and remove blocked author work from triage's path | Started | Route implementation proposals through CTO; send exact ready heads to integration/review |
| QA / release | Own integrated workflow acceptance, regression plan and exact-build release recommendation | Started | Block acceptance on unresolved regressions or missing evidence; do not merge independently |
| Security / compliance | Dependency/license review, scope and secrets checks, privacy risks, adversarial cases | Started | Record findings with source evidence; AGPL process separation is not automatic clearance |
| DevOps / CI | Add required unfiltered workspace tests, preserve real-JVM jobs, propose branch-protection setup | Started | Coordinate manifests/workflows through engineering manager; do not silently alter repository protection |
| PR triage / landing | Exact-proof supersession, review queue and parity landing | Active | Sole parity writer; require approved wording for closures and exact-tree verification for merges |
| Integration | Assemble the single review stack #125 with source-head manifest and conflict resolutions | Active | Reconcile with triage before landing, preserve source branches, send final SHA to QA/reviewer |
| Independent reviewer | Review exact diffs, semantics and regression proof | Active | Findings go to authors via engineering manager; approval does not certify tests not run |
| Feature and fix authors | Implement bounded, non-overlapping changes on new branches | Existing lanes | No edits to others' PR branches; no duplicate R-16/R-18/R-20 work already in review |
| HR / staffing | Maintain staffing register, identify gaps and write role specs | Active; staffing register in PR #137 | Request must name uncovered outcome, approving manager and gap evidence; accepting manager approves before role creation |
| Git expert / requirements cleanup | Full PR disposition ledger, requirements coverage and prioritized cleanup proposal | Active, owner request 18:18 | Propose proof-based closure/docs batching and artifacts-branch extraction; no closes, merges, pushes or history rewrite without routed approval |
| Documentation | PM owns index; source authors own technical docs | Covered, no separate hire now | Add a dedicated docs role only if the queue measurably blocks code/release acceptance |

## Decision and change protocol

1. A lead makes a decision within its charter and gives the reasoning plus acceptance checks to PM.
2. PM records the choice, its scope, evidence and remaining gate, then sends a one-line decision digest.
3. Engineering Manager assigns one author per shared-file boundary. Review and QA remain independent of authorship.
4. Triage alone lands parity. Integration and triage agree which route carries each change so it cannot land twice.
5. Master stays untouched. Do not print or commit secrets. D-CEO-04 permits private local separate-process ARTEX work only. No linking, combined distribution or remote exposure before dependency/rights review.
6. A failed exact-tree check stops the affected landing, not unrelated author work. A new material risk reopens the affected decision instead of being hidden by a prior approval.

## Initial assignments (historical, 13:13)

Use PROGRAM.md for current status and stop/start calls.

- Existing hash/h2 and UI crawl-selection lanes continue.
- Engineering Manager routes #49's cancellation proof/wording follow-up to an author; triage can review other independent PRs meanwhile.
- DevOps owns the full workspace execution gap identified in #132, with QA verifying the resulting job behavior.
- ARTEX isolated kernel/mock work starts only after CTO contract corrections. No WebProbe linking or combined distribution in that builder task.
- No extra marketing, sales, finance or people-operations roles are needed to ship this private technical milestone. Add roles for a concrete blocked outcome, not a title count.

Staffing source: [HR register PR #137](https://github.com/Chaim12345/webprobe/pull/137), containing `docs/management/STAFFING.md`. The link targets the PR until its file lands.
