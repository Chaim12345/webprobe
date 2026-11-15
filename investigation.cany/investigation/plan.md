# Plan

1. [done] Epic A, M, B-01 done; P-13/P-14 (render fix, wiring repair); tasks.json now 90 tasks (18 done, 4 in progress) — commits 10bafe7, 6a969c1, ef70eb0
2. [done] Live Burp gap analysis + UI PRD (docs/PRD-UI.md, 83 UI-* requirements) + backend PRD (docs/PRD-BACKEND.md, BE-* requirements) — built from live captures and the 364 doc pages in the jar; each requirement maps to a task id and a status
3. [doing] P-10 wire Intruder UI to intruder.rs, then C-03 payload types, C-04 processing, C-05 grep/results, C-06 runner+pools — BE-IN-01/02 engine done; BE-IN-03..08 missing
4. [todo] UI shell batch: P-01 menu bar, P-02 tab row, P-03 Settings dialog with Proxy page — UI-SH-01..07, UI-ST-01..10
5. [todo] Message editor + history: P-05 columns, B-03 Pretty/Render, P-04 Repeater layout + Inspector — UI-ME-*, UI-PX-05, UI-RP-*
6. [todo] Backend engines with no UI: F codec+pipeline, H cookie jar/macros, J project v2 + Burp config import, D insertion points/checks — BE-DC, BE-SS, BE-PJ/CF, BE-SC
7. [todo] Deobfuscation refresh for build 52685 and extension host decision (K-02) — ZKM renames per build; Montoya host needs a JVM decision
