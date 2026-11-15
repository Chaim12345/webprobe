# Handoff

STATE (2026-11-15): 15/76 tasks done (A 8/8, M 7/7). Commit 10bafe7 holds the WSL2 rendering fix and the UI wiring repair; 107 tests green.
RENDERING: root cause was LIBGL_ALWAYS_INDIRECT=1 exported by ~/.zshrc:296 plus no /dev/dri render node (Mesa 26 falls to zink). The app fixes its own env in src/gl_env.rs; WEBPROBE_GL=native disables. Do not enable GALLIUM_DRIVER=d3d12 (documented host freezes, WSL#14033).
QA: qa/qa.sh drives WebProbe on Xvfb :97 (proxy 6566, collaborator 6567). Real Burp Pro runs on :98 (launch: /opt/BurpSuite/BurpSuite --project-file=/root/burp-qa/qa.burp --config-file=/root/burp-qa/project.json --user-config-file=/root/burp-qa/user.json --disable-extensions; proxy 6570). Static tour shots: /root/webprobe-shots/burp-tour/. Vision agent must be started with model kilo/nvidia/nemotron-3.5-super-vl:free (the earlier general session was rejected by content safety).
TRAPS: ports 8080/8081 belong to burpsy (user's working tool); never pkill with a pattern that appears in your own command line (killed my shell once); pgrep -f matches its own shell. zsh does not word-split unquoted vars: use bash for scripts. Do NOT rebuild or cargo test while the QA agent runs.
NEXT: read the vision agent report, rank gaps, then rebuild once; close B-01/B-02/B-05 bookkeeping; then backend epics C, F, H, J, D with tests.
