# Canonical release acceptance checklist

## Batch closeout complete, Nov23 10:11

Triage09:44 reports post-landing automated smoke on b18fa29 passed69/69: pipeline7, message-pane10, Intruder baseline4, no-legacy-retry1, effectful replay7, reader/guard/CONNECT/WS/MITM29, framing/keepalive11. This is automated post-landing smoke, distinct from QA pre-landing1190/0 and manualUI12/12. Parity remainsb18fa29893a21597f7f1ae69a140c1821d9bccb0 and matched accepted treec99a1f8. Master untouched.

Live API10:11 confirms92 openPRs, #148 closed/unmerged after whole-source proof, and focused concurrency investigation [#173](https://github.com/Chaim12345/webprobe/issues/173) open. #148 six-file/inherited-source reconciliation: https://github.com/Chaim12345/webprobe/pull/148#issuecomment-7094636963 . #110 automatically merged through125, not manually closed; ancestry/reconciliation proof: https://github.com/Chaim12345/webprobe/pull/110#issuecomment-7094646391 . Triage refreshed125155 descriptions with exact source/landing evidence, known failure/#173 and Logger caveats. No blanket closures or history/branch deletion.

Canonical125155 acceptance and landing monitoring is complete. Bounded remaining work: current management snapshot review, #173 load investigation, Logger product expectations, and existing source-accounting/wiring/partialDOM/#46 queues. These are separate outcomes, not reasons to keep final-batch QA marked pending. PublicActions repository request remains with its assigned owner, not this board's execution scope.


## Accepted and landed09:41, smoke now completed above

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


Owner: QA / release. Snapshot 23:59 Asia/Jerusalem. Prior 2c7ccdd suite/JDK25/UI are historical. Final d405f33 exact full gate and entire UI rerun required; reviewer 23:39 code approval is not execution.

## Safety and compatibility gates

- [x] **Crawler: no implicit replay.** Browser crawl items come from the browser's own traffic. The crawler must never resend a request to fill in missing response metadata (a browser-observed POST would run twice at the origin). Missing response head or body is recorded as incomplete evidence (history note starting 'Incomplete browser capture'), keeping the captured request and inventing no response. Explicit replay is a separate user action (Repeater). Check: `cargo test -p webprobe-core --lib -- no_implicit_replay_tests` passes (real origin hit counter). **Scoped execution recorded:** #156 6cc9be9 landed at 34dcc8b; triage reports standalone 988 / combined 989 passes, required gates clean and exact tested/remote tree equality. Re-run on the final integrated release tree; missing evidence is never filled by resend.
- [x] Bounded h1 unknown-outcome replay fix #153 010de0e landed at ee1af5c. Triage reports 989 standalone /996 combined passes and exact tested/remote tree equality. This does not claim every application-level implicit send is removed. Negotiated-h2 is #145; Intruder planned baseline is a separate gate below.
- [x] Stream-mode 101 head fix #157 3601cd3 landed at a6d2ce0; triage reports 983 combined passes. Preserve exact head-before-relay behavior in later integration.
- [x] H2 #145 a88dfe9 landed 4ad2591. Independent QA accepted exact 1017/0/13 plus 19/19 executed unique fixtures and merged tree 1105/0/14; triage confirms exact tested/remote tree identity and required JDK25 gates/non-Kilo CI clean. The former 24-selector list had 5 wrong-namespace duplicates; corrected runner requires an actual executed pass and fails zero matches. This is scoped landed execution, not final #125/#155 acceptance. Preserve h1 no-replay/h2 typed retry, policy snapshot identity and Decoder repair.
- [ ] Intruder automatic baseline: reviewer source-approved GET/HEAD-only baseline in #125 3108302, visible skip for effectful/unknown methods, unchanged attack rows and unavailable baseline-derived fields. New effectful-template fixture asserts only 3 POST attack rows and no request 0; failure-path tests align attempts=1. Author execution is reported; independent combined #155 2c7ccdd baseline/replay/GET/Stop/channel/pool-permit gates remain unchecked. No implicit extra effectful preflight and no unknown-outcome retry.
- [ ] Final #155 d405f33 includes refreshed #125 fb3d89f and parity 2c2aa12/#171. Reviewer 23:39 approves exact merge delta; independent pipeline 7/7 only so far. Finish full suite/JDK25, current CI and all UI.
- [ ] Compatibility release note: guarded normal cleartext and decrypted-h1 ingress refuses bare-LF/mixed request heads with 400 + close, verbatim capture and zero upstream bytes. One-write/split-read behavior must agree. Keep valid CRLF and LF body bytes unchanged, raw Repeater/testing traffic outside this guard, successful CONNECT/Upgrade leftovers owned by the protocol. Conservative downstream close after h2-upstream response is safe, not h2 keep-alive parity. Full strict response/chunked global setting stays unwired.

- [ ] New slice exposure notes: #164/#166 remain library-only until source-size and Transport destination-scope gates are tested. Retain 64 recursive frames/64 condition nodes (about 32 atoms in flat binary chains) and request/combination budgets. TLS #163 direct TCP bypasses configured upstream proxy/SOCKS and Logger/history/rate/scope throttle. BAC #165 is GET-only; POST/HEAD regressions prove no BAC replays, but GET still has 16 comparisons and may be effectful. Reflected #167 caps classification at first32 contexts, intentionally missing later hits; #168 18e12d6 is now code-read approved with GET/HEAD retrieval guard and first-hit stop; injection still uses its original method, no-hit volume can reach 7 injections +7 retrievals per pair, and tokens may persist without cleanup. Existing StoredXss is unchanged. Do not describe these as unrestricted raw-byte or traffic-equivalent parity.

- [ ] New host/DOM release limits: #169 a3d5ce2 approval covers baseline fingerprint gating before one synthetic POST / per host, Tentative confidence and normal issue filtering, not proof of code execution. #170 f5a9370 core-design approval retains unimplemented should-fixes for run/concurrency budgets, speculative direct-egress isolation/packet-level verification, request/response evidence, confidence and body-size limits. Its 64-request limit is per URL. Review notes also require panic-safe cleanup and unique profile naming. Author reports all 8 positive browser families across 3 test functions plus cache coverage; prior 16-thread miss unresolved, final 4-thread core run passed, no GUI visual QA. Keep these separate from independent executed acceptance.

## Combined-tree and workflow gates

- [ ] Final tested/remote identity at landing: parity 2c2aa12, #125 fb3d89f, #155 d405f33. Source ancestry verified; tested final tree equality remains a landing gate.
- [x] Reviewer 23:39 exact fb3d89f/d405f33 code-read APPROVE: approved #171 changes retained, msgpane tree identical, views own delta byte-identical and stack content retained. No cargo execution.
- [ ] Final d405f33 full suite/JDK25 execution. QA rerunning, standalone pipeline 7/7 early signal only. Prior 2c7ccdd1184/0/27 and Java15/4/13 are complete old-head evidence, not transferred.
- [ ] Final d405f33 Organizer preservation/delete UI: repeat exact workflow and persistence. Old 2c7ccdd delete click-through PASS 23:40 with corrected display scale; logic and old-head UI pass do not certify changed rendering tree.
- [ ] Final d405f33 marker/strict-framing/project-cycle UI. Prior 2c7ccdd visible notes, original bytes and real save/quit/reopen PASS are historical, must rerun.
- [ ] Entire d405f33 UI sweep: streaming ON/OFF/size-cut, history/Logger-to-tools, Repeater hooks/Drop/pipelines, Sequencer, Intruder, Decoder, Organizer and large-entry select/switch/save-reload. Old-head live Logger, constant-token and delete-to-Inbox passes establish mechanics only. Reloaded Logger body retention remains a caveat.
- [ ] Decoder/Hash workflow: #150 landed at cd1e5f1 with triage-reported 982 combined passes; #158 c014c96 landed at ef4054e with 1009 combined passes. Keep GZIP/base64 UTF-8 labels and Unicode/error behavior honest, not arbitrary-byte Burp parity. #139 original remains open pending complete cherry-pick replacement proof; #124 h2-fragmentation-only approval does not certify its defective Decoder branch.
- [x] Security reports yaml_serde 0.10.7/libyaml-rs 0.3.0/ryu 1.0.23 subset CLEAR at c6d0cae: official provenance/checksum-matched crate tarballs, permissive licenses and no advisories in the checked set. CI wiring/build compatibility was reviewed statically, not compiled by security. Recheck changed dependency sets; no whole-repository/legal clearance claimed.
- [ ] Keep D-CEO-05 private/local/separate-process ARTEX boundary. No assumed unilateral relicensing, linking, combined distribution, public repository or remote exposure before dependency/rights and release-content review. Audit findings do not grant effects.

## Current evidence and next checkpoint

| Gate | Current evidence | Next checkpoint |
| --- | --- | --- |
| Crawler | #156 landed at 34dcc8b, triage exact-tree execution reported | Regress final integrated tree, never invent missing response |
| H1 / 101 / Hash | #153/#157/#158 landed at ee1af5c/a6d2ce0/ef4054e | Preserve through canonical integration; final workflow checks |
| H2 | #145 landed 4ad2591; independent exact 1017/0/13,19 fixtures; merged 1105/0/14 | Preserve in final candidate; scoped gate complete |
| Intruder baseline | Source-approved baseline and attempts=1 carried in 359b139; old author 1162 aggregate scoped | Independent 2c7ccdd baseline/replay workflow acceptance |
| Request reader | d405f33 refreshed with landed171; exact code approval, pipeline 7/7 | Full independent suite/JDK25 and entire UI rerun |
| Landed queue | #70/#68/#159 landed; #67 proof/closure done | Preserve through integration; #139 replacement proof separate |
| Library slices | #164 bb3de82 and stacked #166 a303848 approved library-only | Hold after batch; cap source size/scope-gate Transport before loading |
| Other slices | #161/#163/#165/#167/#168/#169 code-read approved; #170 core design with unresolved should-fixes | Hold unrelated landings until #125 batch; no approval transfer across heads |
| Final release | Prior 2c7ccdd green does not accept refreshed tree | Complete d405f33 gates/current CI/tested-remote proof |

This checklist records project dispositions recorded by the PM; reviewer approvals are code-read only. It does not grant deployment, account, spending, publication or license-change authority.

Cleanup uses CTO routing in PROGRAM.md, not the superseded expert proposals. Only #91 has closed in this pass; every conditional closure requires actual landed replacement/carrier proof and fresh state under the batch freeze.

### Rendering prerequisite: landed, final-tree recheck required

#171 1bb384a passed same 2GB GUI 256MiB repro, stable switching and save/reload; CTO 23:28 clears that bounded fix, not the final batch. Landed parity 2c2aa12 with triage standalone/merged1108/0/14 and tree equality. Exact171 hosted-CI exception does not apply to125/155. Final d405f33 must include it (verified) and pass actual large-entry selection/switch/save-reload again because rendering changed. Explicit whole-body actions and804MB peak remain follow-ups.
