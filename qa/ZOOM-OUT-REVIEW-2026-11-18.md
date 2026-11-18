# Zoom-out review, 2026-11-18

Read-only review of the whole project against the goal (full Burp parity, robust, clean
architecture). Code paths are relative to `app/`. The roadmap that follows from it is epic
**R** in `tasks.json` (R-01..R-19) and the plan in the Craft investigation.
This supersedes `GAP-REPORT-2026-11-15.md`, `parity-scores-2026-11-15.md` and
`BACKEND-COMPARE-2026-11-16.md` as the statement of where the project stands.

## Where parity stands

| Area | Parity | Basis | Main gap |
|---|---|---|---|
| Scanner, same URLs on the labs | 100% (75/75 Juice Shop, 21/21 lab, 58/58 scan 7) | measured | none on those apps |
| Scanner, issue-type coverage | 48 of 183 issue types (27%) | measured | 48 DOM-based, ~9 behind D-09/D-10, ~74 unowned, 4 non-scanner types |
| Extensions (Montoya API) | ~10% | measured | only `proxy()` and `logging()` answer (`sidecar/MontoyaBridge.java:276-287`) |
| Proxy | ~75% | estimated | no HTTP/2 browser-side, no response streaming |
| Intruder | ~85% | estimated | predefined lists, Collaborator and extension payloads |
| Repeater | ~70% | estimated | protocol switch, send groups, WebSocket Repeater |
| Other tools | ~80% | estimated | CLI flags, REST API, BChecks, Bambdas |
| UI | ~80% | estimated | never re-scored after the rewrites |

## Roadmap (ranked)

| Id | Pri | Size | Item | Evidence |
|---|---|---|---|---|
| R-01 | P0 | S | Docs truth pass | see "Doc contradictions" |
| R-02 | P0 | S | Portable build, no developer-machine paths | `core/src/report.rs:251`, `src/discovery.rs:111`, `core/src/crawl.rs:295`, `src/tools.rs:885` |
| R-03 | P0 | L | Montoya bridge broad enough for real BApps | `sidecar/MontoyaBridge.java:276-287`, `core/src/ext_host.rs:332` |
| R-04 | P0 | M | Passive checks in the registry + missing passive pack | `core/src/scan.rs:704`, `scan.rs:2967` |
| R-05 | P1 | M | HTTP/2 browser-to-proxy, Repeater protocol switch | `core/src/tls.rs:285`, `src/msgpane.rs:1005`, `src/menus.rs:175` |
| R-06 | P1 | M | Response streaming and server-sent events | `core/src/codec.rs:257-335` |
| R-07 | P1 | M | WebSocket robustness and tools | `core/src/net.rs:679`, `net.rs:2288`, `src/repeater_ops.rs:1697` |
| R-08 | P1 | S | Tests for untested modules | `core/src/rules.rs` (628 lines, no tests) |
| R-09 | P1 | M | JWT checks (7 issue types) | Burp `resources/Scanner/jwt_secrets.txt` |
| R-10 | P1 | L | Active check pack, non-timing | Burp `Zula`, `Zf8g`, `Zp22`; `core/src/scan_checks.rs:1937` |
| R-11 | P1 | M | Scan configuration library (29 presets) | `src/settings_dialog.rs:172`, Burp `resources/BuiltInConfigs/` |
| R-12 | P2 | M | Repeater send groups, single-packet attack | not in the code; needs R-05 |
| R-13 | P2 | L | DOM-based / JavaScript analysis (48 issue types) | none reported today |
| R-14 | P2 | L | BCheck interpreter | `src/tools.rs:1216` |
| R-15 | P2 | M | Burp CLI flags, config JSON, REST API | `src/main.rs:949-960` |
| R-16 | P2 | M | Bambda-style filters and custom columns | `src/tools.rs:1220` |
| R-17 | P2 | S | Intruder payload completeness | review |
| R-18 | P2 | M | Decompose `App` (197 fields) / `Shared` (62), split `ui.rs` (4,606 lines) | `src/ui.rs` |
| R-19 | P2 | S | UI parity re-score, incl. Logger, Organizer, WebSocket intercept | `qa/parity-scores-2026-11-15.md` |

Acceptance tests are in `tasks.json`. Still open from before: D-09, D-10, D-11.

## Open questions (Craft unknowns added)
- Which remaining Burp checks detect only by timing (smuggling, desync, Perl/Python/Ruby code injection)? Those stay excluded by the no-timing rule.
- Which Montoya calls do the most-installed BApps make, to order R-03?
- How does Burp find DOM-based issues (static analysis, browser taint tracking, or both)?
- Which checks count as "server-side injection" for the session-cookie skip list (part of D-11)?

## Doc contradictions (R-01)
- `PROGRESS.md` stops at P-13: Intruder "not yet wired" (line 84), "no bundled browser" (line 79), `app/src/codec.rs` (now in `core/`).
- `TASKS.md` §7: no tick on P-02, P-03, P-05..P-12, P-15, P-16; no rows for UAT tasks, N-06, N-07, D-09..D-11; the "15-20% parity" verdict is not marked as history.
- `PRD-BACKEND.md` / `PRD-UI.md` still carry 36 and 46 ❌ markers (for example BE-SC-01..08 although D-01..08 are done); BE-PX-12 streaming is assigned to rejected N-04.
- `tasks.json` P-02 evidence lists old tab names; D-02 claims "35+" Burp passive issues, 19 of 37 passive checks use Burp names.
- `SOURCE-PARITY-2026-11-15.md` lines 153-177 list an Expression Language check that is no longer reported (`core/src/scan_checks.rs:1937` keeps only the name).

## Checked and solid
Poison-tolerant locks (`core/src/sync.rs`); fuzz tests; both code reviews closed; Intruder payload
breadth; the engine crate has no GUI dependency (test-enforced); FIPS tests in `seq_bits.rs`;
performance at 10k history rows.

## Not verified
GUI behaviour of Logger, Organizer and WebSocket intercept; anything at run time (the review ran no builds).
