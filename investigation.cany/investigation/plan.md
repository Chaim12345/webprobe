# Plan

1. [done] Epic A proxy core (8/8), M foundations (7/7), B-01 history table — 18/90 tasks done; tests 117 green
2. [done] P-13 WSL2 render fix + qa/qa.sh; P-14 UI wiring repair — commits 10bafe7, 6a969c1; root cause LIBGL_ALWAYS_INDIRECT=1 + no render node
3. [done] Run real Burp Pro v2026.7.3 on Xvfb :98, capture every tab/menu/dialog, write gap report — qa/GAP-REPORT-2026-11-15.md; 12 new open tasks P-01..P-12
4. [doing] Write the UI PRD (from Burp's shipped docs + live captures) and the backend PRD — docs/PRD-UI.md and docs/PRD-BACKEND.md; every requirement maps to a task id
5. [todo] P-10 wire Intruder UI to intruder.rs (C-01/C-02 in progress), then C-03..C-07 — engine matrix exists with 10 tests; runner and UI are the gap
6. [todo] UI parity batch: P-01 menu bar, P-02 tab bar, P-03 Settings dialog, P-04 Repeater layout, P-05 history columns — top five gaps by tester impact
7. [todo] Backend-first epics with no UI dependency: F decoder ops, H sessions/cookie jar, J project v2, D crawl/audit engine — pure engine work with unit tests
8. [todo] Close B-02/B-05 remainders; refresh re/mapping deobfuscation for build 52685 — history edit-in-place, layout persistence; ZKM renames per build
