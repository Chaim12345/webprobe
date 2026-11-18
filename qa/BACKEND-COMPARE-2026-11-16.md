# WebProbe vs Burp Suite Pro — backend capability comparison (2026-11-16)

> **Superseded (2026-11-18).** This report is a dated snapshot and is no longer the statement of where the project stands. Current status: `tasks.json` and `qa/ZOOM-OUT-REVIEW-2026-11-18.md`.


Method: Craft Anything Java tools on the shipped jar, the tracked findings (81), the isolated UAT
(`qa/UAT-2026-11-16.md`), and a read of `app/src`. Craft evidence ids from this session are cited;
the earlier project ledger did not survive a Craft restart, so old ids (`ev_535bfb…`) are referenced
by note only. Status: **MET** · **PARTIAL** · **NOT MET** · **UNPROVEN**.

## Verdict summary

| # | Capability | Burp Pro | WebProbe | Verdict |
|---|---|---|---|---|
| 1 | HTTP/1.1 proxy, keep-alive, chunked, gzip/deflate/br | yes | `net.rs`, `codec.rs`, round-trip tests | MET |
| 2 | HTTP/2 (ALPN, h2c opt-in, stream mapping) | yes | own `h2.rs`; h2c behind `WEBPROBE_H2C`; no per-request toggle | PARTIAL |
| 3 | TLS MITM, per-host leaf certs, pass-through list | yes | `tls.rs` + `net.rs`; CA PEM/DER via `webprobe` vhost | MET |
| 4 | Upstream proxy (HTTP, SOCKS5), auth | yes | `settings.rs` `UpstreamKind::{Http,Socks5}` | MET |
| 5 | WebSocket capture + frame interception (plain and TLS) | yes | `net.rs` `handle_websocket`/`relay_ws_tls`, both directions | MET |
| 6 | Intercept: request + response rules, queue, forward/drop all | yes | single held request; no response interception; no rule engine UI | PARTIAL |
| 7 | Match & replace (header/body/request line, regex) | yes | `rules.rs`, project-persisted, ordered | MET |
| 8 | Listener options (invisible, redirect, cert mode, TLS protocols, HTTP/2 flag) | yes | invisible only; others absent | PARTIAL |
| 9 | History model + derived fields (MIME, extension, title, params, cookies, IP, TLS) | yes | `HistEntry` + `derive_history_fields`; verified live | MET |
| 10 | History filter/sort pipeline shared by tools | yes | `history_filter.rs`, whole-list filter then cap | MET |
| 11 | Scope model (include/exclude, regex, port, file) | yes | pattern list, include/exclude, regex | PARTIAL |
| 12 | Site map (tree, crawl paths, per-node messages) | yes | flat list + crawl-paths view | PARTIAL |
| 13 | Crawler | yes (browser-driven) | static link graph; optional Chromium rendered links; no active crawler | PARTIAL |
| 14 | Passive scan library | ~150 checks | 37 checks (headers, cookies, CORS, disclosure, mixed content, cache, e-mail/IP/card, robots) | PARTIAL |
| 15 | Active scan checks | large family set | SQLi (error/boolean/general), LDAP, XSS reflected, XXE, traversal, file-path manipulation, open redirect, header injection, SSTI, SSI, link manipulation, CORS, OpenAPI, path-relative CSS, reflected input | PARTIAL |
| 16 | Scan result parity | oracle | 75/75 Juice Shop, 18/18 lab (name/severity/confidence); crawl coverage excluded | MET (tested scope) |
| 17 | Insertion points (query, body, JSON, XML, path, headers, cookies) | yes | params, path/folder, XML element values | PARTIAL |
| 18 | Scan config, task queue, reporting | yes | scan speed/accuracy; no queue/report generation | PARTIAL |
| 19 | Collaborator (local, public, private server, SMTP) | yes | local HTTP/DNS + public interactsh (DNS/HTTP/SMTP); no private server mode | PARTIAL |
| 20 | Intruder attack types | 4 | Sniper, Battering ram, Pitchfork, Cluster bomb | MET |
| 21 | Intruder payload types | 19 | 4 (Simple list, Numbers, Brute forcer, Dates) | PARTIAL |
| 22 | Payload processing rules | 14 | none | NOT MET |
| 23 | Intruder grep / extract / result analysis / save-load | yes | status, length, timing, error; no grep/extract/save | PARTIAL |
| 24 | Resource pools (concurrency, delay, backoff) | yes | none; fixed runner concurrency | NOT MET |
| 25 | Repeater (send, views, Inspector, per-tab history) | yes | present | MET |
| 26 | Repeater cancel, redirects, groups, parallel send, h2 toggle | yes | Cancel is a no-op (verified 8214 ms completion); rest absent | PARTIAL |
| 27 | Decoder codecs + hashes | wide | 16 ops incl. MD5/SHA-1/256/512, smart decode; no gzip/octal/binary | PARTIAL |
| 28 | Comparer words/bytes/line, merge | yes | Words/Bytes window works; item 1/2 share one list and Paste is inert | PARTIAL |
| 29 | Sequencer entropy + FIPS suite + live capture | yes | entropy/chi-square + live capture; FIPS/poker/runs/spectral/correlation absent | PARTIAL |
| 30 | Logger (bounded ring buffer, all tools) | yes | present, filterable; memory caps unverified | PARTIAL |
| 31 | Organizer (collections, status, notes) | yes | present | MET |
| 32 | Extensions (Java Montoya, BApps, Bambdas) | yes | Montoya sidecar, ProxyRequest/Response hooks only; static BApp catalog | PARTIAL |
| 33 | Session handling rules/macros | yes | 3 actions + raw macros | PARTIAL |
| 34 | Persistence (project v2, autosave, crash recovery) | yes | save/load v1; UAT lost history on restart; no autosave | NOT MET |
| 35 | Burp-compatible config JSON + CLI flags | yes | only `--screenshot`; no config import | NOT MET |
| 36 | Performance | JVM, pooled | Rust, threads; repaint fixed (request_repaint_after 200 ms) | MET-ish |
| 37 | Test baseline | n/a | findings quote 293 pass/6 ignored; last recorded run in this tree 127 — current count unverified | UNPROVEN |

## Evidence notes (this session)

- Jar inventory: 61,846 `java-class` entries, 41 nested jars — `ev_b62e1f69fd3fca6494b357362c5fa98884ee7234b84b528cf88e498ee85bfb78`.
- Scan-check classes (9 matches) — `ev_1745c6feb43c74e8e3fedabe251a83ab1d891ed750fed12343154f27ec9fc9ca`.
- Intruder payload interfaces (`IIntruderPayloadGenerator/Processor/Factory`) — `ev_e29298e2ecff382803dd01e807c3555ead22b8dcf44f32820fd69af5e6990fc4`.
- Collaborator classes (20 matches) — `ev_721da8de04e53659b72425ec001fcd9acb1415cd79df556835f51473bfb7b4e5`.
- Montoya classes (287 matches) — `ev_3ccd4ab82a480dc1217bfc8bc2b3ab292e89b063cfc844c7492b66fda36fc186`.
- `http2` class-name query: 0/54,868 (obfuscation; not evidence of absence) — `ev_60069e1c678c32c66cc745b43004a022127f0f1e0995105de9b5b15bc864e67a`.
- Rebuild tree inventory — `ev_773a9a546e2253df01648c7d156855e9a62e589609d15b1a637e984314671397`.

Craft findings `fnd_1`–`fnd_15`, five open unknowns (`unk_50cfa955…` crawl parity, `unk_1cada825…` h2
toggle, `unk_6c438ead…` persistence, `unk_dea02bac…` Montoya depth, `unk_4faaafbf…` remaining checks).
Report: `/root/webprobe-uat/BACKEND-VERIFY-2026-11-16.md`.

## UI deltas measured against the Burp tour (same session)

- **Dashboard**: structurally identical (Tasks, Summary/Audit items/Issues/Event log/Logger/Audit log,
  task configuration, progress, log). Missing: paused "Task execution is paused / Resume" banner,
  "View all" / "View configuration" links, empty-state illustration, task-header icon buttons.
- **Proxy history**: Burp's reference history was empty (only its empty state exists); WebProbe is
  functionally ahead. Column schema still differs: Burp has Comment+Label before Cookies; WebProbe
  has one Notes column and extra IP/Time; Time renders truncated (`08:39:`), table scrolls at 1440 px.
- **Repeater**: three panes match; Burp has a Burp AI button, pane-header icon menus, a history pager
  and a Notes/Explanations/Custom actions rail. WebProbe has per-tab history arrows and a Notes label
  without content.
- **Intruder**: config layout matches (attack dropdown, target, Add/Clear/Auto §, payload dock).
  Burp's onboarding illustration and "Don't show this again" are absent; the results window is
  input-dead (functional defect).
- **Decoder**: same input strip + right rail of Decode/Encode/Hash/Smart decode; WebProbe duplicates
  the control strip for its output pane, Burp presents operations as a step list.
- **Target**: near-identical; Burp constrains the empty-state paragraph width and shows the paused
  banner; WebProbe's paragraph spans the full window.
- **Settings**: Burp is a full two-pane dialog with a category tree (Tools, Project, Network, UI, Suite,
  Extensions, Configuration library) and a search box; WebProbe is a small modal with Appearance,
  Hotkeys, Proxy, Sessions and a Close button.
- **Menus**: Burp menus carry full item sets; WebProbe's WebProbe menu has Search, Settings, Quit only.

## egui 0.33 + egui-mcp-client trial (MCP integration path)

`/root/webprobe-egui33` (branch `egui33-trial`) pins eframe/egui 0.33, `egui_extras` 0.33,
`egui-phosphor` 0.8 and `egui-mcp-client` 0.0.5. Build result: **31 errors, 52 warnings** —
19×E0308, 5×E0609, 3×E0061, plus E0631/E0615/E0599/E0596; 21 errors in `ui.rs`, 4 in `msgpane.rs`,
2 in `theme.rs`, one each in `shortcuts.rs`, `main.rs`, `history_filter.rs`, `collaborator_ui.rs`.
Full log: `/tmp/opencode/egui33-errors.log`. So the IPC half of egui-mcp (screenshots, coordinate
input, connection check) costs a framework upgrade with ~31 API fixes; the AT-SPI half already works
without it once `accesskit` is enabled, but the published frame lacks X-window mapping here.

## Priority fixes

1. Intruder results window input; Repeater Cancel (blocking usability).
2. Comparer independent item stores + Paste.
3. Persistence: save/restore history and rules, autosave, crash recovery.
4. Intruder payload types/processing and result grep; resource pools.
5. Crawler coverage and scan queue/reporting; then the remaining payload/decoder/sequencer breadth.
