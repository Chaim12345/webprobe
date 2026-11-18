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
11. [doing] D-10 stored XSS retrieval pairing beyond safe GETs — Burp's token pairing traced (Zhqw, Zml_->Zwcz, Zwp6/Zh7d, Zpqv.Z_); worker implementing after the lab parity re-measure
12. [todo] D-12 Collaborator leftovers: SNI variant and Zbxl scheme payload variants — not ported in D-09
13. [doing] R-01 [P0/S] Docs truth pass — headers, banners, generated status table done (09ed7a9); remaining: per-row PRD status re-check
14. [todo] R-02 [P0/S] Portable build: no developer-machine paths — core/src/report.rs:251, src/discovery.rs:111, core/src/crawl.rs:295, src/tools.rs:885, bridge source via CARGO_MANIFEST_DIR.
15. [todo] R-03 [P0/L] Montoya bridge broad enough for real BApps — sidecar/MontoyaBridge.java:276-287 (only proxy() and logging() answer); core/src/ext_host.rs:332. Measured ~10% API coverage.
16. [todo] R-04 [P0/M] Passive checks in the check registry + missing passive pack — core/src/scan.rs:704 (one 315-line function), scan.rs:2967 (active only). WebProbe reports 48 of Burp's 183 issue types.
17. [todo] R-05 [P1/M] HTTP/2 browser-to-proxy and a working Repeater protocol switch — core/src/tls.rs:285 (no ALPN), src/msgpane.rs:1005-1006, src/menus.rs:175-177.
18. [todo] R-06 [P1/M] Response streaming and server-sent events — core/src/codec.rs:257-335 reads the whole response first. PRD BE-PX-12 was assigned to rejected N-04.
19. [todo] R-07 [P1/M] WebSocket robustness and tools — core/src/net.rs:679, net.rs:2288, src/repeater_ops.rs:1697.
20. [todo] R-08 [P1/S] Tests for untested modules — core/src/rules.rs: 628 lines, no tests, runs on every proxied message (net.rs:2516/2621/3034/3049).
21. [todo] R-09 [P1/M] JWT checks — Burp resources/Scanner/jwt_secrets.txt; none in scan_checks.rs.
22. [todo] R-10 [P1/L] Active check pack (non-timing) — scan_checks.rs:1937 (EL name only); ~74 issue types unowned. Depends on Craft unknown about timing-only detection.
23. [todo] R-11 [P1/M] Scan configuration library — src/settings_dialog.rs:172-173 ('not available yet'); /root/burp-re/in/extract/resources/BuiltInConfigs/. Needs R-04.
24. [todo] R-12 [P2/M] Repeater send groups and single-packet attack — Not in the code. Needs R-05.
25. [todo] R-13 [P2/L] DOM-based / JavaScript analysis — 48 of Burp's 183 issue types; none reported today. Method depends on Craft unknown about Burp's DOM engine.
26. [todo] R-14 [P2/L] BCheck interpreter — src/tools.rs:1216 ('BCheck files are not supported').
27. [todo] R-15 [P2/M] Burp CLI flags, config JSON and REST API — src/main.rs:949-960 reads only --screenshot; headless has proxy and scan only.
28. [todo] R-16 [P2/M] Bambda-style filters and custom columns — src/tools.rs:1220 (stated unsupported).
29. [todo] R-17 [P2/S] Intruder payload completeness — Review: 18 payload sources, ~20 processors present; these three missing.
30. [todo] R-18 [P2/M] Decompose App / Shared and split ui.rs — src/ui.rs: 4,606 lines, 10 tests; proxy_history alone 410 lines.
31. [todo] R-19 [P2/S] UI parity re-score — qa/parity-scores-2026-11-15.md never redone; no record of Logger/Organizer/WS intercept GUI checks.
