# Handoff

STATE 2026-11-15: 90 tasks (18 done, 4 in progress, 68 todo); 117 tests green; latest commits ef70eb0 + PRD commit.
DOCS (read these first): docs/PRD-UI.md (what Burp's UI does, UI-* ids with status and task mapping), docs/PRD-BACKEND.md (engine requirements BE-*), qa/GAP-REPORT-2026-11-15.md (side by side), TASKS.md section 7 / tasks.json epic P.
REFERENCE APP: real Burp Pro v2026.7.3 on Xvfb :98 (launch: /opt/BurpSuite/BurpSuite --project-file=/root/burp-qa/qa.burp --config-file=/root/burp-qa/project.json --user-config-file=/root/burp-qa/user.json --disable-extensions; proxy 6570). Shots /root/webprobe-shots/burp-tour/. Docs extract: /root/burp-qa/docs-extract/outline.txt. Burp's HTTP history stayed empty despite listener traffic (open unknown).
QA: qa/qa.sh (WebProbe on :97, proxy 6566, collab 6567). Vision subagents on nemotron all failed (content safety / provider / quota): compare screenshots directly.
TRAPS: ports 8080/8081 belong to burpsy; never pkill with a pattern in your own command line; zsh does not word-split (use bash scripts); do not rebuild while a QA agent drives the binary; do not edit ~/.zshrc (LIBGL_ALWAYS_INDIRECT=1 is the original render bug, app now fixes it itself).
NEXT: P-10 (wire intruder.rs into the Intruder tab, replace net::start_attack), then C-03..C-06; then UI shell P-01..P-03.
