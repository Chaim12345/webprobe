# Plan

1. [done] Epic A proxy core (8/8) and M-01..M-07 foundations (7/7) — chunked/gzip/br, keep-alive, HTTP/2, TLS, listeners, design system, a11y, onboarding
2. [done] Fix WSL2 rendering at the source (gl_env.rs) + QA driver qa/qa.sh — LIBGL_ALWAYS_INDIRECT=1 from ~/.zshrc + no /dev/dri render node; 107 tests green, commit 10bafe7
3. [doing] Live comparison against real Burp on Xvfb :98 (vision agent), then fix ranked gaps — Tab bar, menus, Dashboard, Proxy sub-tabs, history table and filter are the first visible gaps; rebuild only after the agent finishes
4. [todo] Close epic B bookkeeping: B-01 (done in code), B-02, B-05; then B-03, B-04, B-06..B-09 — tasks.json still says todo; needs status+evidence+date, TASKS.md, PROGRESS.md, mechanics.json claims
5. [todo] Backend-first epics that need no UI: C Intruder engine (C-01..C-07), F decoder/comparer ops, H sessions, J project file, D crawl/audit engine — Pure engine work with unit tests; UI hooks follow
6. [todo] I Collaborator, E Repeater, G Sequencer, K extensions, L engagement tools, N quality — Depend on engines above; K needs a JVM/Montoya host decision
7. [todo] Deobfuscation: refresh re/mapping for build 52685 and re-open the remapped jar in craft — 301 Montoya-anchored names + 61 string-evidence classes so far; ZKM regenerates names per build
