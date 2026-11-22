# Canonical release acceptance checklist

## EINTR acceptance blocker, CTO 01:15 Nov23

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
