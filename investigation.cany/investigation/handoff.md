# Handoff

STATE 2026-11-15: 92 tasks (18 done, 4 in progress, 70 todo); 117 tests green; latest commit 6e34b4f.
READ FIRST: docs/PRD-UI.md (UI-* requirements), docs/PRD-BACKEND.md (BE-*), qa/GAP-REPORT-2026-11-15.md, docs/EVAL-OBSCURA.md, TASKS.md section 7 (epic P).
BROWSER DECISION (docs/EVAL-OBSCURA.md): Obscura (Rust+V8 headless, Apache-2.0, v0.2.7) is NOT Burp's interactive browser; it is a candidate headless engine. Tested: SSRF guard blocks loopback unless --allow-private-network; plain HTTP via our proxy works; HTTPS via our MITM needs SSL_CERT_FILE=<webprobe CA pem> (works, seen in history); JS runs; screenshot 0.66 s, 47 MB RSS; never enable --stealth (hides traffic). L-05 split: P-15 interactive Chrome/Chromium launcher (throwaway profile, --proxy-server, CA trusted per profile), P-16 HeadlessBrowser trait + Obscura sidecar spike with 5 acceptance checks (also compare Lightpanda).
REFERENCE APP: real Burp Pro v2026.7.3 on Xvfb :98 (launch: /opt/BurpSuite/BurpSuite --project-file=/root/burp-qa/qa.burp --config-file=/root/burp-qa/project.json --user-config-file=/root/burp-qa/user.json --disable-extensions; proxy 6570); shots /root/webprobe-shots/burp-tour/.
QA: qa/qa.sh (WebProbe :97, proxy 6566, collab 6567). Obscura test binaries in /tmp/obscura-bin (copy of the digest-verified release), scripts in /root/obscura-eval.
TRAPS: ports 8080/8081 belong to burpsy; vision subagents (nemotron) all failed, compare screenshots directly; never pkill with a pattern in your own command line; zsh does not word-split; /root is mode 700 so other users cannot run binaries from it; do not edit ~/.zshrc.
NEXT: P-10 wire intruder.rs into the Intruder tab then C-03..C-06; UI shell P-01..P-03; backend epics F/H/J/D; P-15/P-16 after D-01.
