# Handoff

STATE 2026-11-15: 90 tasks (18 done, 4 in progress, 68 todo). Commits 10bafe7, 6a969c1, ef70eb0. 117 tests green.
DONE THIS SESSION: WSL2 render fix (gl_env.rs, root cause LIBGL_ALWAYS_INDIRECT=1 + no /dev/dri), qa/qa.sh live driver, UI wiring repair, intruder.rs engine core (C-01/C-02 in progress), unique scroll ids, glyph fallback font, B-01 done.
GAP ANALYSIS: real Burp Pro v2026.7.3 runs on Xvfb :98 (launch: /opt/BurpSuite/BurpSuite --project-file=/root/burp-qa/qa.burp --config-file=/root/burp-qa/project.json --user-config-file=/root/burp-qa/user.json --disable-extensions; proxy 6570). Shots in /root/webprobe-shots/burp-tour/. Report: qa/GAP-REPORT-2026-11-15.md. Tasks P-01..P-12 (epic P) in tasks.json/TASKS.md section 7.
DOCS: docs/PRD-UI.md (what Burp's UI does, requirement ids UI-*) and docs/PRD-BACKEND.md (engine requirements BE-*), each mapped to task ids.
TRAPS: vision agents on kilo/opencode/nvidia nemotron all failed (content safety, provider errors, free quota); compare screenshots directly. Ports 8080/8081 belong to burpsy: tests use 6566/6567, Burp 6570, origin 6580. Never pkill with a pattern present in your own command line. zsh does not word-split: use bash scripts. Burp history stayed empty despite listener traffic (unknown logged).
NEXT: P-10 (Intruder UI on intruder.rs), then P-01..P-05 UI parity, then backend epics F/H/J/D.
