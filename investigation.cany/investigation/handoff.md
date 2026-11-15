# Handoff

STATE 2026-11-15: 92 tasks (19 done, 6 in progress, 67 todo). Commits 10bafe7, 6a969c1, ef70eb0, 0ab9711, b0978f8, f12e87d, 05082ca.
DONE THIS SESSION: render fix (gl_env.rs), QA driver, wiring repair, B-01, P-10 (Intruder attack-type UI + generic matrix runner), C-01, P-05 (history derived fields + 14 columns), P-02 (single 13-tab row, active underline), P-13/P-14, gap report, UI+backend PRDs, Obscura eval.
PARALLEL SUBAGENTS RUNNING (disjoint files): researcher -> docs/burp-intruder.md (Burp Intruder docs extract); implementer -> new src/decoder_ops.rs (F-01 codecs/hashes/pipeline, no other files, no build); multimodal-looker -> qa/visual-review-2026-11-15.md (screenshot comparison). Do not edit those three files until they report.
CRAFT: fnd_7 records the Intruder extension surface (IIntruderAttack, IIntruderPayloadGenerator/Factory/Processor, Montoya HttpRequestTemplate/GeneratedPayload/AttackConfiguration; evidence ev_2b28...). Attack-type labels are not literal in bytecode (only an adblock false positive); docs are the source. Z_so is a synthetic switch map, not the enum.
READ: docs/PRD-UI.md, docs/PRD-BACKEND.md, qa/GAP-REPORT-2026-11-15.md, docs/EVAL-OBSCURA.md.
REFERENCE: Burp Pro v2026.7.3 on :98 (proxy 6570); shots /root/webprobe-shots/burp-tour/. QA: qa/qa.sh (:97, proxy 6566).
TRAPS: 8080/8081 belong to burpsy; never pkill with a pattern in your own command line; zsh does not word-split; /root is 700; do not edit ~/.zshrc; do not rebuild while a QA agent drives the binary; keep subagents on disjoint files.
NEXT: collect the three subagent reports, wire decoder_ops.rs (F-01/F-02), use docs/burp-intruder.md for C-03/C-04, fix the top visual gaps; then P-01 menu bar, P-04 Repeater, B-03 Pretty/Render.
