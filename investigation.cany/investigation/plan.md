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
18. [todo] R-07 [P1/M] WebSocket robustness and tools — core/src/net.rs:679, net.rs:2288, src/repeater_ops.rs:1697.
19. [todo] R-09 [P1/M] JWT checks — Burp resources/Scanner/jwt_secrets.txt; none in scan_checks.rs.
20. [todo] R-10 [P1/L] Active check pack (non-timing) — scan_checks.rs:1937 (EL name only); ~74 issue types unowned. Depends on Craft unknown about timing-only detection.
21. [todo] R-11 [P1/M] Scan configuration library — src/settings_dialog.rs:172-173 ('not available yet'); /root/burp-re/in/extract/resources/BuiltInConfigs/. Needs R-04.
22. [todo] R-12 [P2/M] Repeater send groups and single-packet attack — Not in the code. Needs R-05.
23. [todo] R-17 [P2/S] Intruder payload completeness — Review: 18 payload sources, ~20 processors present; these three missing.
24. [todo] R-15 [P2/M] Burp CLI flags, config JSON and REST API — src/main.rs:949-960 reads only --screenshot; headless has proxy and scan only.
25. [todo] R-13 [P2/L] DOM-based / JavaScript analysis — 48 of Burp's 183 issue types; none reported today. Method depends on Craft unknown about Burp's DOM engine.
26. [todo] R-18 [P2/M] Decompose App / Shared and split ui.rs — src/ui.rs: 4,606 lines, 10 tests; proxy_history alone 410 lines.
27. [todo] R-19 [P2/S] UI parity re-score — qa/parity-scores-2026-11-15.md never redone; no record of Logger/Organizer/WS intercept GUI checks.
28. [todo] D-12 Collaborator leftovers: SNI variant and Zbxl scheme payload variants — not ported in D-09
29. [doing] R-01 [P0/S] Docs truth pass — headers, banners, generated status table done (09ed7a9); remaining: per-row PRD status re-check
30. [todo] R-14 [P2/L] BCheck interpreter — deferred 2026-11-18 (user: core features before extension work that can wait); src/tools.rs:1216 ('BCheck files are not supported').
31. [todo] R-16 [P2/M] Bambda-style filters and custom columns — deferred 2026-11-18 (user: core features before extension work that can wait); src/tools.rs:1220 (stated unsupported).
32. [todo] R-20 [P2/M] Montoya leftovers and a wider BApp check — deferred 2026-11-18 (user: core features before extension work that can wait); docs/MONTOYA-COVERAGE.md 'Missing' column; first three items in worker task 10
33. [blocked] Re-verify URL-level lab parity (Juice Shop 75/75, lab 21/21) for the code after D-09..D-11 — stored Burp lists, paths.txt and lab.py were lost with /tmp; needs a fresh Burp baseline, which the no-Burp-scans rule excludes until the user decides (qa/parity-2026-11-18/SUMMARY.md)
