# WebProbe program board

## Accepted and landed, Nov23 09:41

CTO09:38 accepted exact #155 head3384d3c4abf364b427d9e6c45e45fc0c05dea813 for parity-only landing. QA09:37 reports clean full suite19 targets1190/0; workflow-local jobs1-5 passed, JDK25 extras and EINTR fixture passed, complete manual Xvfb UI12/12. #125 landed986fead1ca88175a6283660c8160f4b0085008f6 then #155 landed final parityb18fa29893a21597f7f1ae69a140c1821d9bccb0. Triage reports readback tracked treec99a1f8eb1331e094ece18662735cf1d00ff4dbc identical to accepted3384d3c, no conflict/content changes; master untouched. Live API confirms both merged, parity and93 open PRs. Post-landing smoke is running, not yet complete at this snapshot.

Keep the3384d3c first1001/1 Intruder concurrency-bound failure visible: standalone3/3 and clean1190/0 do not erase it. CTO requests a focused load/concurrency investigation, not another acceptance hold. JVM JAVA_HOME harness corrected5/5. Montoya count reconciled: literal selector3 on both heads; fourth sidecar passes within ext_host15, not removed. JDK21 Bambda13, Repeater33; JDK25 ext_host15/Bambda13/pipeline7 plus evidence-edit1 pass.

Logger caveats remain: pre-reload rows retain metadata only and cannot Send to Repeater; extension-dropped requests are absent from Logger. No claim of complete Logger body persistence or drop-event coverage. Large-entry preview is bounded at1MiB with complete stored256MiB capture; manual final-head smoke responsive at~763.5MB. PM records attributed QA/CTO/triage evidence, not independent test execution or QA screenshot inspection.

The live open count fell113 to93:20 PRs are now merged, not20 manual cleanup closures. Their current heads are ancestors of accepted parity; API merged states are recorded below. #148 remains open until post-landing smoke and whole-source reconciliation. Other routing holds persist, including scanner wiring, partialDOM, #139 accounting-only, #46 fresh migration/patchedhpack, and draft-only docs extraction. Batch landing alone never permits blanket closure.

### API-confirmed merged inventory delta

| PR | Merge SHA | Observed state |
|---|---|---|
| [#99](https://github.com/Chaim12345/webprobe/pull/99) | `acc2b81849709837bfb2c097acc61d047afe7af6` | merged, not manual supersession closure |
| [#104](https://github.com/Chaim12345/webprobe/pull/104) | `64568244805911c2bcd23f51f778fd9e3f6e121e` | merged, not manual supersession closure |
| [#107](https://github.com/Chaim12345/webprobe/pull/107) | `8ac8dda9e533f11d13e174e148d7691c04cc5f1c` | merged, not manual supersession closure |
| [#109](https://github.com/Chaim12345/webprobe/pull/109) | `67dd39453cf4bf804bd526bf311d0c350380d04f` | merged, not manual supersession closure |
| [#110](https://github.com/Chaim12345/webprobe/pull/110) | `3458bbfad61aa1cc6c43cee96a3d6e95c9ef12fc` | merged, not manual supersession closure |
| [#111](https://github.com/Chaim12345/webprobe/pull/111) | `579dd4a7d8d27022f0898e6173076040eab0c19b` | merged, not manual supersession closure |
| [#114](https://github.com/Chaim12345/webprobe/pull/114) | `90000b9537afa9dded345ee4cb8cacf75c80ab0b` | merged, not manual supersession closure |
| [#115](https://github.com/Chaim12345/webprobe/pull/115) | `6d723d18e751be1318000b1b733e78d1a40e61fc` | merged, not manual supersession closure |
| [#116](https://github.com/Chaim12345/webprobe/pull/116) | `f631fd00708fb772e854fd9c145686254b2f56e3` | merged, not manual supersession closure |
| [#117](https://github.com/Chaim12345/webprobe/pull/117) | `311887106ec89dfc53029bd6d9767ad7bcbf4e3f` | merged, not manual supersession closure |
| [#118](https://github.com/Chaim12345/webprobe/pull/118) | `645ecff0317802ca53f7604cbeeb9bfb37ef8ece` | merged, not manual supersession closure |
| [#119](https://github.com/Chaim12345/webprobe/pull/119) | `2acf6e557caac04a67a2ecae24866ffa0a791bb0` | merged, not manual supersession closure |
| [#120](https://github.com/Chaim12345/webprobe/pull/120) | `331d1e7466fabca3a9f7092fe52230dc44a99c58` | merged, not manual supersession closure |
| [#121](https://github.com/Chaim12345/webprobe/pull/121) | `b3ddedbcd11c5039d29f836f11665db268aa93ab` | merged, not manual supersession closure |
| [#122](https://github.com/Chaim12345/webprobe/pull/122) | `1ff04adf76795b76c857a743063b535c4ab86a74` | merged, not manual supersession closure |
| [#124](https://github.com/Chaim12345/webprobe/pull/124) | `41e916c513516de9e81d58f29db018d5ca6b6be3` | merged, not manual supersession closure |
| [#125](https://github.com/Chaim12345/webprobe/pull/125) | `986fead1ca88175a6283660c8160f4b0085008f6` | merged, not manual supersession closure |
| [#127](https://github.com/Chaim12345/webprobe/pull/127) | `7189f84abd121c23f25d89ff1ea7aa5e7ed4d0af` | merged, not manual supersession closure |
| [#128](https://github.com/Chaim12345/webprobe/pull/128) | `91613cb9be01eb800bf4b449689c724765231cc8` | merged, not manual supersession closure |
| [#155](https://github.com/Chaim12345/webprobe/pull/155) | `b18fa29893a21597f7f1ae69a140c1821d9bccb0` | merged, not manual supersession closure |


## Historical local-CI findings08:39, superseded by accepted landing

Candidate3384d3c remains unchanged. QA08:17 workspace first run:1001 passed/1 failed, then aborted. probe_pool_bounds_concurrency_and_rows_drain failed its in-flight bound assertion at intruder_run.rs:2068. This is not the earlier EINTR failure; cause is unverified. Standalone and clean full-suite reruns are required before disposition. Job2 JVM gate failed because the runner omitted JAVA_HOME despite JDK21 on PATH; harness error is separate from product failure and requires corrected rerun. Final UI has not started.

QA08:27-08:38 reports core check/no-run/clippy green, Montoya selector3 executed, JDK21 Bambda13/0, Repeater33/0 plus fmt/no-run/clippy clean. JDK25 extras running. Prior Montoya4 report versus current3 needs reconciliation, not an inferred source removal, because candidate delta is codec-only. These partial passes are not full CI acceptance.

Triage06:42 reports exact172 source0d2528e and landed paritycf28b6d local workspace1111/0/14 each, core check/no-run/clippy and JVM validator12/12 plus5 required contracts each. Rust1.100/JDK21 pinned jar checksum verified; prior JDK25 gates also passed. Hosted checkout/cache/apt actions were not reproduced as hosted actions. This closes source/parity local test-command work, not final3384d3c acceptance.


## Historical gate reset06:36, superseded by accepted landing

#172 is landed at parity `cf28b6d982d7837921de1c759b27caf12d24a102`. Exact fix head0d2528e was rechecked; triage06:28 reports recreated/remote tree equality and1111/0/14. The owner gave a standing instruction to land without hosted CI at06:27:32, then required local CI at06:27:37. Original authenticated WhatsApp messages recovered. This supersedes the earlier171-only limit, without waiving local verification, source approval or final combined-tree/UI acceptance. No billing changes.

Current #125 `6f6f65490ee76778b78fe66b68057830ce041f90` and #155 `3384d3c4abf364b427d9e6c45e45fc0c05dea813` contain parity/#172 and #171. Live pagination06:36:113 open PRs. Reviewer06:31/06:33 code-read APPROVE both exact refreshed heads: only codec.rs+155/-2, approved172 delta kept verbatim,155 evidence functions preserved, no conflicts or other changes. Author reports1251169/0 and1551203/0, fmt/build/clippy clean. These are author checks, not independent acceptance.

QA06:34 independently fetched and verified exact candidate3384d3c,125 ancestry and172 parity inclusion. Full workflow-local jobs running with pinned Rust1.100/JDK21, plus owner-gate JDK25 extras, evidence-edit/EINTR fixture and full UI sweep. Fmt/clippy passed, workspace suite running; JVM/core/Bambda/Repeater jobs and UI pending. #172 landing occurred before the local-CI expansion arrived; triage will also run exact source/parity workflow jobs and report non-reproducible portions separately. No final acceptance or candidate landing yet. Earlier d405f33 clean1187/0 and complete UI are historical evidence; original1029/1 failed run remains recorded. The production EINTR defect is addressed in source but final exact-tree gate closure is pending, not waived.


## Historical d405f33 QA completion01:43, superseded by current gate reset

QA reports the exact d405f33 clean workspace rerun completed19 targets,1187 passed/0 failed; fmt/clippy, real JDK25 ext_host15/Montoya4/Bambda13 and standalone pipeline7/7 twice passed. The entire manual Xvfb/software-rendered UI sweep passed, including Drop/pipelining, Decoder roundtrip/error path, Intruder substitution and large-entry select/switch/save-reload. Large entry first-render RSS944MB, flat944-946MB on switching,481MB after reload; no repeated growth observed. Intruder fixture returned200 for all paths, so status differentiation was not tested, while substitution/result rows were verified.

QA's release-ready verdict is a lane report, not overall acceptance: CTO01:15 requires the EINTR correction in the final tested tree. First run1029/1 remains a failed run. #172 is absent from current d405f33. A clean rerun and UI success do not supersede the CTO blocker or transfer to a future refreshed tree. Hosted-CI authority and final tested/remote identity remain separate.


## EINTR acceptance blocker, CTO 01:15 Nov23, original checkpoint

The d405f33 workspace run failed: 1029 passed / 1 failed, then remaining targets aborted. The evidence-edit fixture received a synthetic 502 after upstream ErrorKind::Interrupted. Later standalone passes and separately completed targets do not erase this failed run. Reviewer01:14 diagnosed a real pre-existing read-path bug: buffered reads can fail, streaming/EOF reads can truncate. CTO01:15 makes this an acceptance blocker for #125+#155, not unrelated work. No network replay is authorized.

[PR #172](https://github.com/Chaim12345/webprobe/pull/172), exact head `0d2528e8f0283183f2a7d5f23d6830b135340c34`, is separate on parity2c2aa12, not included in #125fb3d89f/#155d405f33. Reviewer01:19 source APPROVE only. Triage01:22 reports standalone and clean parity merge each1111/0/14, required-Java no-run/fmt/clippy clean and tested tree saved. Hosted core/workspace/JVM jobs did not start due account billing/spending limits. #172 is NOT landed and needs its own landing authority; #171-only exception does not transfer. Include the fix, refresh affected candidates and rerun evidence-edit plus full exact combined-tree gates before acceptance.

QA d405f33 scoped results01:13-01:26: fmt/clippy clean; standalone pipeline7/7 twice; JDK25 ext_host15/15, Montoya4/4, Bambda13/13. Aborted targets separately passed session25/support115/report12. No clean full workspace run yet. Actual final-head UI PASS reports: incomplete marker/strict-framing wording, real project save/reopen with notes and wire bytes, streaming store ON/OFF plus256MiB size cap, Organizer full cycle/delete-to-Inbox, Sequencer constant-token, live Logger-to-Repeater and Repeater extension hooks. Drop/pipelining, Intruder, Decoder and large-entry select/switch/save-reload remain uncompleted at this snapshot. These mechanics results do not certify a future refreshed tree. PM records attributed QA reports, not independently inspected QA screenshots.


Snapshot: 2026-11-23 09:41 Asia/Jerusalem. Program owner: Program Manager. [Canonical release checklist](RELEASE-CHECKLIST.md). [Review and decision ledger](REVIEW-LEDGER.md). [Role charters](ROLES.md). [HR staffing register, PR #137](https://github.com/Chaim12345/webprobe/pull/137), proposed file `docs/management/STAFFING.md`.

This is the index for sequencing, not permission to merge or change product behavior. Only the triage lane lands parity changes. Existing PR branches and master stay untouched. Refresh this board when a source head, landing, decision or verification result changes.

## Visual kanban

[Open the status board](KANBAN.html) or [view the share image](KANBAN.png). The HTML board has one linked card per open PR, plus program checkpoints; each shows owner, gate and next step. Snapshot data is in `kanban-data.json`. Verified checkpoints are separate from unfinished work. This is not a Monday.com account or live sync.

## Rendering blocker resolved on #171; final combined acceptance remains open

[PR #171](https://github.com/Chaim12345/webprobe/pull/171) at1bb384ae78258b3309224a25c77cfadb2a0e98ca passed the actual 256MiB GUI repro on the same 2GB host, switching and save/reload. CTO 23:28 clears that fix only, contingent on inclusion in the final accepted batch. Triage landed it at parity 2c2aa12 with standalone/merged1108/0/14 and tested/remote tree identity. The owner's hosted-CI exception applied to this exact PR/head only, after jobs failed to start due to an account payment/spending-limit restriction. It is not a batch waiver or billing change.

Final #125 fb3d89f and #155 d405f33 now include the fix and have reviewer 23:39 code-read approval. Full independent exact-head execution/UI reruns remain required, including large-entry selection, switching and save/reload on the final tree.804MB observed peak remains a memory-reduction follow-up; explicit whole-body actions remain copy-heavy and outside the bounded selection fix.

## Prior position, superseded by EINTR blocker above

- Live parity `2c2aa124d4365e3edc0f8768634be5aa562935f2`; **114 open PRs**, full paginated refresh and exact ancestry recomputed. Management #160 remains open; previous 0ca52bc snapshot is historical once this refresh changes its head. Self-row SHA stays blank to avoid recursive staleness.
- PR #70 landed at 0c0dee7, #68 at f297951 and #159 at 5c15280. Live API confirms merges. Triage reports 1084 combined passes /14 ignored for #159. PR #67 is now closed after complete source-to-successor proof; this was not a title/ancestry-only closure. Original #139 remains open pending its own complete replacement proof.
- **Final acceptance held on new final-head gates.** #171 is landed and both refreshed candidates carry it. #125 `fb3d89f4d7a43fbd8c15d2beaf08f9c14165b3db`; #155 `d405f33006c852a4ba59c364e0f21d294e56a180`. Reviewer 23:39 approves exact refresh resolution; QA23:40 pipeline 7/7 is an early signal, full suite/JDK25 and entire one-build UI sweep rerun are in progress. Old 2c7ccdd suite/Java/UI results do not certify d405f33. All unrelated landing/closure freezes remain.
- H2 #145 `a88dfe91feb7410d5ea8983da06823a9c5b9483e` **landed at 4ad2591**. Live API and exact ancestry confirm it. Independent QA accepted exact head1017/0/13 and 19/19 executed unique fixtures, then merged tree 1105/0/14, matching triage. Triage reports remote/local merged trees identical to saved tested tree, JDK25 no-run/fmt/clippy clean and non-Kilo CI green. The old24-selector list had 5 wrong-namespace duplicates; zero-match now fails. This closes the #145 semantic-overlap gate, not final #125/#155 release acceptance.
- Canonical #125 `fb3d89f4d7a43fbd8c15d2beaf08f9c14165b3db` merges approved 359b139 with new parity 2c2aa12, retaining #171. Reviewer verifies only msgpane.rs/views.rs differ (+145/-7), #171 changes preserved and append-only views conflict kept both helpers. Author reports 1166/0 including 13 Bambda, fmt/clippy clean; independent acceptance applies to the final combination, not author counts.
- Candidate #155 `d405f33006c852a4ba59c364e0f21d294e56a180` merges approved 2c7ccdd with refreshed #125 fb3d89f, exact ancestry verified. Only the same two #171 UI files change (+145/-7), reviewer 23:39 code-read APPROVE. Author reports 1200/0 including 13 Bambda, fmt/clippy. QA full gate/UI reruns; rendering path changed, so final-tree large-body/select/switch/save-reload is mandatory. No source-head or test-only carry-over assumed.
- Hardened parser replacement #164 `bb3de82` is approved **library-only** and held after original #64's standalone formatting gate failed. BCheck exec #166 `a303848` carries #164 and replaces the older #162 port. Before loading/UI wiring, cap source size and scope-gate Transport destinations; retain shared 64-frame/64-condition-node limits and request/combination budgets.
- New exact-head code-read approvals: diagnostics #161 `a8de045`, TLS #163 `a1b469f`, GET-only BAC #165 `33c5382`, reflected G.11 #167 `509cad7`. These are not executed combined-tree acceptance and do not override the freeze. TLS direct egress bypass and BAC's 16 GET comparisons must stay visible. Reflected context classification is deliberately capped at first32 occurrences, with empty-probe guard and Tentative confidence.
- Stored G.11 #168 is now `18e12d6`, reviewer code-read APPROVED, stacked on #167 `509cad7`. New retrieval GET/HEAD guard runs before any injection; injection itself retains its original method and existing StoredXss is unchanged. First G.11 hit skips later families, but a no-hit pair can still send up to 7 injections +7 retrievals. Probes persist with no cleanup. Source approval is not final combined acceptance.
- Host probes #169 `a3d5ce2` are reviewer code-read APPROVED after Next.js/RSC baseline fingerprint gating and Tentative confidence. Normal issue/check filters apply, including with extra_checks=false. It sends a robots GET and at most one synthetic POST / per fingerprinted host, not a replay of the audited request; signature detection is not RCE proof.
- DOM eight-family #170 `f5a9370` has core-design code-read approval with three unresolved should-fixes: run-level/concurrent-browser budgets; speculative direct-egress verification/isolation; and confidence/evidence/response-body caps. Existing 64-request cap is per URL, not per run. Exact-origin GET/HEAD interception and scanner session routing passed source review, but speculative socket behavior was not tested independently. Cleanup panic guard and unique profile suffix remain review notes.
- DOM browser coverage is author-reported: all 8 positive families across 3 test functions plus an all-eight cache test, not only 3 families. Author reports full core 787 passes at 4 threads; earlier 16-thread lab miss is not isolated. No GUI visual QA. Review fixes are acknowledged but not yet implemented at this snapshot. Edition/MSRV work is local/uncommitted, with unsafe-env/tail-drop audit, real 1.95/all-features and CI-matrix gates still owed; no PR or acceptance claimed.
- Security reports the c6d0cae three-crate subset CLEAR: yaml_serde 0.10.7/libyaml-rs 0.3.0/ryu 1.0.23 provenance, registry checksum-matched tarballs, permissive licenses and no advisories in the checked set. CI wiring/build compatibility was inspected statically, not compiled by security; independent build gate still applies. Not a whole-repository advisory/legal clearance.
- Owner asked at 18:18 for a dedicated Git expert on requirements, repository cleanup and priorities; the role is assigned. Cleanup priorities: protect the final candidate/policy fix, map requirements and exact retained-source proof, then measured closure/cleanup. Reviewer notes about evidence bloat are recommendations only, not permission for history rewriting or deleting evidence. The Git expert delivered the disposition ledger and draft artifacts/docs grouping; triage and CTO corrections below override its earlier proposals. No extraction push is authorized or reported. PR count is not a completion metric. The active candidate must not move merely to extract evidence while exact-head QA is running.
- All 93 original audit rows are reported audited by triage, with later landings tracked. Audit completion is not permission to close unresolved sources. Old-stack fix-only approvals cannot certify carried features. Historical milestones remain in [milestones.csv](milestones.csv); final integrated gates remain unchecked.

## Earlier landing sequence, #172 inclusion now required before acceptance

1. **Preserve the completed policy fix.** D-CEO-02 remains in force. #125 359b139 moves collection items to Inbox, with evidence/notes/IDs, repeat-delete safety, save/reload regression and correct modal. Exact delta has reviewer code-read approval; author test counts are not independent acceptance.
2. **Hold refreshed final pins.** Parity2c2aa12 includes landed #171; #125 fb3d89f and #155 d405f33 include parity and keep all prior safety work. Reviewer approves both exact deltas. No unrelated landing until final independent execution/workflow gates complete.
3. **Revalidate d405f33.** Full suite/JDK25 and entire UI sweep run on this final tree. Old 2c7ccdd delete-to-Inbox, Sequencer and live Logger-to-Repeater passed at23:32-23:40, proving interaction mechanics only. QA now knows the1.1833 synthetic-click scale factor; prior dialog blocker was mis-aimed clicks. Repeat all checks on d405f33. Reloaded Logger rows lack message bodies and fail gracefully, an unresolved retention/expectation caveat.
4. **Then land and prove cleanup.** Triage verifies final tested/remote identity. Only after actual combined landing and pipeline/drop-close/nonblocking-drain preservation propose #148/#110 cleanup. PR #139 needs its own complete replacement proof; #67 is already closed with proof.
5. **Git expert owns requirements/cleanup priorities.** Reconcile source-to-requirement coverage and propose the smallest safe closure batches. Preserve source branches, evidence and history unless a separately grounded cleanup plan permits a change. Do not turn old-stack fix approvals into full-stack acceptance.
6. **Resume slice queue after the batch.** Retain #164 -> #166 and #167 -> #168, source-size/destination-scope loader gates, traffic/privacy notes and #170 unresolved should-fixes. Library/core-design approval is not unrestricted exposure permission.

## Cleanup routing: CTO decision adopted 18:35

Only [#91](https://github.com/Chaim12345/webprobe/pull/91) closed in this pass, with triage's complete source accounting and four executed successor fixtures; live state independently confirms closed. No other close-now candidate. #158 is already merged; #139 is accounting-only, not a Hash rebuild. Older expert proposal columns yield to CTO routing and its #46 correction.

| Route | PRs / boundary | Required next step |
| --- | --- | --- |
| After actual batch landing | #99/#109-#111/#114-#120; #148 | Complete carrier/reconciliation source mapping. #117 includes safe baseline/no replay; #120 includes Inbox preservation/save-reload; #148 retains R1-R4, boundary/persistence, tunnel/drop/FIN behavior |
| Audit carrier before new work | #104/#107/#121/#122/#127/#128 | Claimed #125 inclusion is a lead; check landed equivalence first, then preserve exact remainder. Do not commission duplicate refactor/Bambda/docs slices |
| After replacement landing and freeze | #169 -> #13/#47; #163 -> #14/#48/#86; #165 -> #15/#50; #167 -> #16/#52/#83; #168 -> #17/#53/#69; #164 -> #64; #164+#166 -> #29/#65/#84/#162; #161 -> #75 | Full own-plus-inherited accounting and retained regression/non-code/safety content, not an open replacement or top-commit patch match |
| DOM partials stay open | #170 candidate matches #18-#20/#54-#56/#71/#73; #21-#27/#57-#63/#72/#76-#82 remain partial | Per-family/source/sink matrix including applicable web-message/reflected/stored/prototype pollution. Eight location.hash families are not all DOM coverage |
| Wiring stays open | #30/#66/#85 | #164 library and #166 executor do not include scanner/Extensions wiring. Require separately landed loading/UI/scanner end-to-end proof |
| Re-audit before missing slices | #87/#90/#93 UI; #89+#106 listener; #92 counters; #94 CONNECT; #98 edge tests; #101 codec/h2; #108 isolation AND settings | Check final landed batch first; then build only a proved missing delta |
| Other holds | #5-#12, #39, #46, #124, #139 | No staleness closes. #39 needs remainder disposition. #46 fresh current-base migration preferred, preserving #74 patched hpack; #45 was merged. #124 keeps rejected Decoder separate from absorbed h2. #139 needs complete source accounting, not rebuild |
| Docs after consolidation lands | #112/#113 reports; #130/#132/#133/#135/#137/#143/#144/#160 management | Retain every document, decision ID, evidence/caveat and supersession order. #121/#122/#127/#128 take carrier audit first |

Triage alone closes, after a fresh live state/source-head check and exact landed SHA accounting for all own and inherited changes. Unaccounted remainder stays open. The old #46 manifest is a reason to inspect/regenerate on current parity, not proof that every three-way merge must revert the patched dependency. Evidence extraction remains draft-only and must not silently change the pinned candidate.

## Preserved source contracts and old-head evidence

CTO Option A retains terminal behavior after forwarded Connection: close; CTO B buffered history keeps incomplete/error notes, actual status, pre-edit received bytes and original framing. These remain included in refreshed d405f33. Prior 2c7ccdd source approval, suite1184/0/27, Java15/4/13, UI marker/framing/project persistence, streaming storageON/OFF and Organizer persistence are historical scoped evidence, not final-head acceptance.

On 2c7ccdd QA later completed Sequencer constant-token, Organizer delete-to-Inbox full click-through and live Logger-to-Repeater. Corrected1.1833 display scaling explains the earlier synthetic-click failure. Reloaded Logger rows lack bodies and show a graceful no-retained-message toast, a separate product-retention question. Final d405f33 reruns the whole sweep including Repeater hooks/Drop/pipelining, Intruder, Decoder and large-entry rendering/switch/save-reload. Current hosted CI/ignored-test policy/final tested-remote identity remain separate gates.

## Lane ownership

| Lane | Accountable role | Current next checkpoint | Boundary |
| --- | --- | --- | --- |
| Parity landing | Triage | #171 landed 2c2aa12; hold batch for final d405f33 gates | No general hosted-CI waiver or other landing/closure permission |
| #145 acceptance | QA/reviewer/triage | DONE: exact 1017/0/13,19 fixtures; merged 1105/0/14; landed 4ad2591 | Not final #125/#155 acceptance |
| Canonical #125 | Integration | fb3d89f exact refresh reviewed | Final combination #155 d405f33, no stale evidence transfer |
| #155 request boundary | Request-reader + reviewer/QA | d405f33 reviewed; pipeline 7/7 early signal | Whole suite/JDK25/UI and final rendering smoke |
| Parser / BCheck exec | Triage slice author + reviewer | Hold #164/#166 until batch done; loader gates before wiring | Source size, destination scope, bounded complexity/budgets |
| Other slices | Existing slice authors + reviewer | #161/#163/#165/#167/#168/#169 approved; #170 core design approved with should-fixes | Freeze applies; #168 carries #167 |
| Integrated workflow QA | QA / release | Pinned final combined build | Final release gates still unchecked |
| ARTEX | CTO / isolated builder; CEO license scope | Last recorded isolated kernel/mock scope, recheck before effects | D-CEO-05 private/local/separate-process only |
| Requirements / repo cleanup | Dedicated Git expert | Prioritized requirement map and proof-based closure batches | No history/evidence deletion implied |
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
| P1: one reviewable integrated candidate | Exact final review/execution/workflows | fb3d89f/d405f33 refreshed with171, reviewer approves; independent rerun/UI pending |
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

- 18:23: whole c6d0cae code-read complete and three-crate security subset CLEAR, not final acceptance. Exact source contradicts D-CEO-02 Organizer preservation; original CEO/CTO decisions recovered and CTO reaffirmed rule. Acceptance blocked on integration fix, new #155 head and rerun. Owner-requested Git expert assigned for requirements/cleanup/priorities.

- 18:26: #125 359b139 preservation fix and #155 85bd159 clean combination verified live; parity remains 4ad2591 and 114 open PRs. Reviewer approves fix delta by code read. QA reruns exact 85bd159; old c6d0cae gate is not final acceptance.

- 18:51: full live 113-PR inventory verified; only #91 removed, all other heads/parity unchanged. Exact 85bd159 reviewer coverage confirmed 18:28, QA remains the final execution/UI gate. CTO 18:34 routing and corrected #46 migration rationale adopted 18:35; no other close authorized.

- 19:53: full live inventory 113, parity 4ad2591/#125 359b139 unchanged; #155 dc170b5 fixture-only correction verified. CTO Option A 19:48, author partial/core evidence scoped, full gate restarted 19:52. New exact-head review/QA required; incomplete-history negative proof gap flagged.

- 19:56: reviewer signs off exact dc170b5 fixtures by code read 19:53; no cargo execution. CTO incomplete/error-history criterion remains open independently; strengthened test follow-up requested, no new head assumed. Full QA continues on dc170b5.

- 20:24: 113 open, parity 4ad2591/#125 359b139 unchanged; final #155 2c7ccdd source delta verified. CTO B implemented and reviewer 20:10 approved; independent pipeline 7/0 at 20:09. Full gate/UI remain open; prior 21712de/dc170b5/85bd159 results stay historical.

- 22:57: live 113 open and source refs/parity unchanged. QA exact 2c7ccdd suite 1184/0/27 and real Java15/4/13 green 22:36; first three marker/framing/project UI checks passed 22:41-22:43. Remaining UI/final verdict held; no landing/closure permission from this milestone.

- 23:05: owner-requested Monday-style kanban added:15 work items and113 individual open-PR cards, image plus filterable HTML. QA reports streaming storageON/OFF and Organizer collection persistence PASS; delete click-through remains automation-blocked. Large-body follow-up: selecting a stored256MiB entry aborts with allocation5368707940 bytes on2GB host, reproduced2/2 (QA app4.log, shots84/85). Storage/cut note correct; lazy/truncated rendering needed. SUPERSEDED23:04 by CTO: acceptance BLOCKER for the combined batch. Lane15 is preparing a bounded-preview fix on a separate PR; no batch acceptance until verified.

- 23:28: live114 open; #171 1bb384a separate bounded-preview fix source-approved by reviewer23:17, clean parity4ad2591 merge check. Caps pane/hash/Inspector at1MiB, Logger borrows stored response. Storage and full export unchanged, small messages unchanged. Author141 bin tests pass/fmt/clippy, headless96MiB smoke only. Actual256MiB GUI repro/combined integration proof still required, so CTO batch blocker stays open. Explicit whole-body Organizer/Comparer/AI actions remain a separate copy-heavy follow-up.

- 23:59: live 113 open; #171 merged2c2aa12 under exact-head-only CI exception, #125 fb3d89f/#155 d405f33 source-reviewed and QA rerunning. Actual #171 GUI repro passed/CTO cleared that fix; final combined rendering smoke and whole-workflow gates remain.
