# Plan

1. [done] Visual bridge pass: horizontal Repeater/Intruder panes, menu bar, Proxy sub-tab names — Wave 39
2. [done] Light-palette token pass + remaining chrome — Wave 39 light theme (LightTheme.json colours); verified on :97
3. [done] Structural tool gaps: Logger/Organizer/Discover, Proxy Match and replace, Dashboard and Intruder sub-tabs — All 13 tabs match live Burp v2026.7.3 (burp-real-01.png); parity ledger 2026-11-17
4. [done] Engine done + verified: Logger (app/src/logger.rs) — 
5. [done] Engine done + verified: Organizer (app/src/organizer.rs) — 
6. [done] Engine done + verified: Match and Replace (app/src/match_replace.rs) — 
7. [done] Engine done + verified: Project .burp save/load (app/src/project.rs) — 
8. [done] Robustness: disk-backed history (N-06), subsystem types (N-07), two code reviews (35 findings fixed) — 2026-11-17/18, branch parity/2026-11-17
9. [done] D-11 remaining Burp insertion points (entire body, nested, XML tags, parameter names, server-side skip list) — commit ec380b4, core/src/insertion.rs; class:line refs in tasks.json D-11; lab parity not re-measured
10. [done] D-09 remaining Collaborator variants (Zc7h, Zxvv.ZQ, Zsrh) — commit e7b5eff; leftovers (SNI, Zbxl scheme variants) are D-12
11. [done] D-10 stored XSS retrieval pairing beyond safe GETs — core/src/stored.rs; Zi5k filters not ported; no stored pair seen on a real app yet
12. [done] R-02 [P0/S] Portable build: no developer-machine paths — e96f063, core/src/paths.rs; not run in a clean container
13. [done] R-03 [P0/L] Montoya bridge broad enough for real BApps — a8ed5cb, 462793f, a2f0eec; docs/MONTOYA-COVERAGE.md; four unmodified BApps load; leftovers are R-20
14. [done] R-04 [P0/M] Passive checks in the check registry + missing passive pack — e96f063 + 94026e4; gaps: 'multiple locations' merge, per-cookie identifiers for HttpOnly/Secure
15. [done] R-08 [P1/S] Tests for untested modules — a8ed5cb; eight product bugs fixed
16. [doing] R-06 [P1/M] Response streaming and server-sent events — worker task 10 (R-06 first, then R-05)
17. [doing] R-05 [P1/M] HTTP/2 browser-to-proxy and a working Repeater protocol switch — worker task 10 (R-06 first, then R-05)
18. [done] R-07 [P1/M] WebSocket robustness and tools — R-07 part 1 e32e846, part 2 + hardening f7794db (52 focused tests); full suite at the PR #4 merge
19. [done] R-09 [P1/M] JWT checks — 54d2343: 5 active + 2 passive JWT issue types, 39 tests
20. [done] R-10 [P1/L] Active check pack (non-timing) — 9804b99, dab9255, c6ff86f, 371ebc5, 54d2343: EL, XPath (error + boolean), PUT, ASP.NET, GraphQL, client IP, backup, cache poisoning/deception; smuggling and desync rejected by the no-timing rule (confirmed); hidden HTTP/2 not ported
21. [doing] R-11 [P1/M] Scan configuration library — implemented aa490e8 + 09e87f8, compiled, smoke tests only; full suite and UI pending
22. [doing] R-12 [P2/M] Repeater send groups and single-packet attack — branch wp-m6: D-12a done (97b41bd), D-12b and R-12 partial (9d7de42)
23. [todo] R-17 [P2/S] Intruder payload completeness — Review: 18 payload sources, ~20 processors present; these three missing.
24. [todo] R-15 [P2/M] Burp CLI flags, config JSON and REST API — src/main.rs:949-960 reads only --screenshot; headless has proxy and scan only.
25. [todo] R-13 [P2/L] DOM-based / JavaScript analysis — 48 of Burp's 183 issue types; none reported today. Method depends on Craft unknown about Burp's DOM engine.
26. [todo] R-18 [P2/M] Decompose App / Shared and split ui.rs — src/ui.rs: 4,606 lines, 10 tests; proxy_history alone 410 lines.
27. [todo] R-19 [P2/S] UI parity re-score — qa/parity-scores-2026-11-15.md never redone; no record of Logger/Organizer/WS intercept GUI checks.
28. [doing] D-12 Collaborator leftovers: SNI variant and Zbxl scheme payload variants — branch wp-m6: D-12a done (97b41bd), D-12b and R-12 partial (9d7de42)
29. [doing] R-01 [P0/S] Docs truth pass — headers, banners, generated status table done (09ed7a9); remaining: per-row PRD status re-check
30. [todo] R-14 [P2/L] BCheck interpreter — deferred 2026-11-18 (user: core features before extension work that can wait); src/tools.rs:1216 ('BCheck files are not supported').
31. [todo] R-16 [P2/M] Bambda-style filters and custom columns — deferred 2026-11-18 (user: core features before extension work that can wait); src/tools.rs:1220 (stated unsupported).
32. [todo] R-20 [P2/M] Montoya leftovers and a wider BApp check — deferred 2026-11-18 (user: core features before extension work that can wait); docs/MONTOYA-COVERAGE.md 'Missing' column; first three items in worker task 10
33. [blocked] Re-verify URL-level lab parity (Juice Shop 75/75, lab 21/21) for the code after D-09..D-11 — stored Burp lists, paths.txt and lab.py were lost with /tmp; needs a fresh Burp baseline, which the no-Burp-scans rule excludes until the user decides (qa/parity-2026-11-18/SUMMARY.md)
34. [todo] AR-01 [P1/S] Quick architecture fixes: lints, compiled rule sets, intercept liveness, test CA isolation — qa/ARCH-REVIEW-2026-11-18.md
35. [todo] AR-02 [P1/M] Engine duties out of App into core — qa/ARCH-REVIEW-2026-11-18.md
36. [todo] AR-03 [P1/M] Settings snapshot, then the engine split of Shared — qa/ARCH-REVIEW-2026-11-18.md
37. [todo] AR-04 [P1/M] Explicit send context instead of thread-locals — qa/ARCH-REVIEW-2026-11-18.md
38. [todo] AR-05 [P2/L] Scanner worker pool and passive-check queue — qa/ARCH-REVIEW-2026-11-18.md
39. [todo] AR-06 [P2/M] Lifecycle: cancellation, named joinable threads, no sleep-polling — qa/ARCH-REVIEW-2026-11-18.md
40. [todo] AR-07 [P2/M] Event channel and append-only history to the UI — qa/ARCH-REVIEW-2026-11-18.md
41. [todo] AR-08 [P2/M] Java sidecar: route replies by id, no lock across the round trip — qa/ARCH-REVIEW-2026-11-18.md
42. [todo] AR-09 [P2/M] Bytes, not lossy text, in tool state — qa/ARCH-REVIEW-2026-11-18.md
43. [todo] AR-10 [P2/S] One extensibility pattern and a project format plan — qa/ARCH-REVIEW-2026-11-18.md
