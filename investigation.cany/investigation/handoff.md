# Handoff

STATE 2026-11-15: 92 tasks (19 done, 4 in progress, 69 todo). Commits 10bafe7, 6a969c1, ef70eb0, 0ab9711, b0978f8. P-05 in flight (build green, test run backgrounded; do not edit ui.rs/net.rs while it compiles).
DONE: render fix (gl_env.rs), QA driver, wiring repair, B-01, P-10 (Intruder attack-type selector + generic matrix runner over intruder::requests, limit 100k; C-01 done), P-13/P-14, Obscura eval.
P-05 IN FLIGHT: HistEntry gained params, edited, extension, title, cookies, listener_port, computed once at insert by net::derive_history_fields; record() takes listener_port; project restore recomputes them; history table gained Extension, Title, Cookies, Port columns with matching sort keys.
READ: docs/PRD-UI.md, docs/PRD-BACKEND.md, qa/GAP-REPORT-2026-11-15.md, docs/EVAL-OBSCURA.md.
REFERENCE: Burp Pro v2026.7.3 on :98 (proxy 6570); shots /root/webprobe-shots/burp-tour/.
QA: qa/qa.sh (:97, proxy 6566). Vision subagents all failed; compare screenshots directly.
TRAPS: 8080/8081 belong to burpsy; never pkill with a pattern in your own command line; zsh does not word-split; /root is 700; do not edit ~/.zshrc; do not rebuild while a QA agent drives the binary.
NEXT: finish P-05 (tests + live shot + tasks), then P-01/P-02/P-03 shell, then Repeater P-04 and B-03.
