# WebProbe Backend PRD: the engine behind what Burp Suite Professional's UI can do

Status date: 2026-11-15 · Baseline: `app/src/*.rs`, 117 tests green · Reference: Burp Suite Professional v2026.7.3 (build 52685),
its shipped documentation (364 pages inside the jar), the extracted `UserDefaults.json` / `ProjectDefaults.json`, and live runs.

Companion: `docs/PRD-UI.md` (every UI requirement `UI-*` names the `BE-*` requirement that powers it), `tasks.json`.
Legend: ✅ have · 🚧 partial · ❌ missing · ⛔ out of scope.

## 1. Goals and boundaries

The backend is a set of pure, testable engines with a thin shared state (`net::Shared`), driven by the UI today and by an
extension host later. Rules that hold everywhere:

1. **Engines are pure where possible**: input in, result out, no UI types, no global state. `intruder.rs` (request matrix)
   and `gl_env.rs` (environment policy) are the template: tested in isolation first, wired second.
2. **One pipeline per concern**: e.g. `history_view` (newest first, filter and sort the whole list, then cap) is the only
   place that decides what a table shows; UI and tests share it.
3. **Never block the UI thread**; long work runs on workers with cancellation and progress.
4. **Safe defaults**: listeners bind loopback, the CA private key never leaves memory unless exported on purpose, project
   files never store credentials unless the user ticks it.
5. **Evidence over memory**: behaviour copied from Burp is cited in `app/mechanics.json` with its source (jar class, doc
   page or live observation); estimates are labelled.
6. Test ports are 6566 (proxy), 6567 (collaborator), 6570 (reference Burp), 6580 (origin); 8080/8081 belong to another tool.

## 2. Proxy and HTTP engine (Burp: `Proxy` listeners, invisible proxying, TLS)

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| BE-PX-01 | Multiple listeners (bind address, port), validation (empty bind, port 0, duplicates), restart without losing history; per-listener state and error | `listener_status` / `listener_specs` / `set_listeners`; extra listener serves traffic | ✅ | A-07 |
| BE-PX-02 | Burp listener options: `Invisible`, `Redirect to host:port`, certificate mode (per-host, generated CA, custom), TLS protocol list, HTTP/2 flag | Each option per listener; invisible proxying routes origin-form via `Host` | 🚧 invisible ✅, others ❌ | A-08, B-08 |
| BE-PX-03 | HTTP/1.x parsing: absolute and origin form, header folding, duplicate headers, CL+TE conflict, 4 MiB+ bodies, never panics | Fuzzed | ✅ | A-04, N-03 |
| BE-PX-04 | Transfer and content encodings: chunked, gzip, deflate, br; original encoding kept when forwarding | Round-trip tests | ✅ | A-01, A-02 |
| BE-PX-05 | Upstream connection pooling, keep-alive, no forced `Connection: close` | Socket reuse asserted | ✅ | A-03 |
| BE-PX-06 | HTTP/2 and h2c: ALPN, upgrade, stream mapping, pseudo-headers kept in history, downgrade/upgrade per request | h2 request visible and replayable | ✅ core, 🚧 per-request toggle | A-05, E-01 |
| BE-PX-07 | TLS: per-host leaf certs signed by the local CA, pass-through list (host/port/regex), client certificates (mTLS), upstream trust options | Pass-through hosts are not decrypted | ✅ | A-06 |
| BE-PX-08 | Intercept engine: request and response rules (Enabled, Operator And/Or, Match type, Relationship, Condition), master switch, queue of held messages with edit/forward/drop/forward-all/drop-all, WebSocket interception | Rules evaluate in order; timeouts configurable | 🚧 single held request | B-07, B-08 |
| BE-PX-09 | Match and replace for request, response, WebSocket (header, body, request line, parameter name/value), regex, testing | Applied in order, previewable | ✅ rules, ❌ WebSocket/test | B-08 |
| BE-PX-10 | Local virtual hosts `http://burpsuite` and `http://webprobe` serving setup page and the CA (PEM, DER) | Served from the proxy, never forwarded | ✅ | M-07 |
| BE-PX-11 | Timeouts and limits: connect/read/open-ended response timeouts, response size cap, history cap | Defaults from `ProjectDefaults.json` | 🚧 fixed values | B-08 |
| BE-PX-12 | Streaming and long responses (SSE, chunked streams) forwarded as they arrive | No buffering stall | ❌ | N-04 |

## 3. History, scope and target model (Burp: HTTP history, Target)

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| BE-HS-01 | History record: id, time, tool/source, listener port, host, port, https, IP, method, path+query, params flag, edited flag, status, length, MIME, extension, title, cookies set, notes, highlight, timings (start/end response timer), raw request/response | One struct, all UI columns derive from it | 🚧 id, ts, method, host, port, path, status, resp_len, raw, https, note | P-05 |
| BE-HS-02 | Derived fields computed once at insert (MIME, extension, title, params, edited) not per frame | Cached, tested | 🚧 MIME per call | P-05, N-02 |
| BE-HS-03 | Filter model: request type, MIME groups, status groups, search term (regex, case, negative), extension show/hide, annotation, listener port, in-scope | Shared by Proxy, Logger, Intruder results, Target | 🚧 text/regex/method/status/MIME/in-scope | B-01, P-05 |
| BE-HS-04 | Sort/filter/limit pipeline (`history_view`) | Filter and sort see the whole list before the render cap | ✅ | B-01 |
| BE-HS-05 | Annotations: highlight colour, notes, per-item and bulk | Persisted in project | ❌ | B-07 |
| BE-TG-01 | Scope: include/exclude rules with protocol, host (regex or literal), port, file; advanced scope; exclude always wins; no includes means everything in scope | Used by proxy, scanner, intruder, history filter | 🚧 pattern list | B-06 |
| BE-TG-02 | Site map: tree built from history and scans (domain, directory, file, parameterized request), crawl-paths graph, request/response per node | Incremental updates, not rebuilt per frame | ❌ flat list | B-06, D-01 |
| BE-TG-03 | Issue model: type, severity, confidence, host, path, evidence request/response pairs, remediation, background; definitions library | Stable ids, dedupe | 🚧 name/severity/detail | D-06 |

## 4. Intruder engine (Burp: Intruder)

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| BE-IN-01 | Positions: `§` parse, add from selection, clear, auto-mark (query, cookie, form, JSON scalars), unbalanced marker error | `Template`, `add_marker`, `clear_markers`, `auto_mark` | ✅ engine (10 tests) | C-02 |
| BE-IN-02 | Attack types: Sniper, Battering ram, Pitchfork (lock step, shortest set), Cluster bomb (last position fastest), request count, limit guard, empty/missing set errors | `requests`, `count` | ✅ engine | C-01 |
| BE-IN-03 | Runner: streaming execution of the matrix with concurrency and delay from a resource pool, cancel, pause/resume, progress, per-request error capture (timeout, retry), redirects option | Replaces `net::start_attack` | ❌ (old sniper-only runner) | P-10, C-06 |
| BE-IN-04 | Payload types (documented): Simple list, Runtime file, Custom iterator, Character substitution, Case modification, Recursive grep, Illegal Unicode, Character blocks, Numbers, Dates, Brute forcer, Null payloads, Character frobber, Bit flipper, Username generator, ECB block shuffler, Extension-generated, Copy other payload | Each type is a pure iterator with a known count | ❌ | C-03 |
| BE-IN-05 | Payload processing rules (ordered): prefix, suffix, add/replace/skip, match/replace, substring, reverse substring, modify case, encode (URL, HTML, base64, ASCII hex, GBK-style), decode, hash (MD5, SHA-1/256/512), add raw/ regex skip | Pipeline returns `Option<String>` (skip) | ❌ | C-04 |
| BE-IN-06 | Result analysis: status, length, timers, error, timeout, grep-match (strings, regex, case, exclude HTTP headers), grep-extract (regex or offsets), grep-payloads, auto-pause on match, sort/compare by length | Columns computed at record time | ❌ | C-05 |
| BE-IN-07 | Resource pools: max concurrent requests, delay (fixed/random/increasing), throttle on errors; shared with scanner and live tasks | Pool selected per task | ❌ | C-06, D-05 |
| BE-IN-08 | Save and load attacks and results (CSV, project) | Round-trips | ❌ | C-07, J-01 |

## 5. Repeater engine

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| BE-RP-01 | Send raw request to host/port/scheme, HTTP/1.1 or HTTP/2, update Content-Length option, response with timing | Cancelable, never blocks UI | ✅ send, ❌ cancel/h2 toggle | E-01 |
| BE-RP-02 | Follow redirects (limit, same-host rule), redirect chain recorded | Per-tab setting | ❌ | E-02 |
| BE-RP-03 | Per-tab history (back/forward), per-tab settings, tab groups with send in sequence and in parallel | Parallel group sends in one window (single-packet style) | ❌ | E-04 |
| BE-RP-04 | Streaming responses with a timeout | Streamed bytes visible live | ❌ | E-01 |

## 6. Scanner engine (Burp: Dashboard scans, crawler, audit)

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| BE-SC-01 | Crawl engine: scope-aware, link/form discovery, depth and request limits, login handling, crawl strategy, dedupe by canonical URL | Terminates, reports crawl paths | ❌ | D-01 |
| BE-SC-02 | Insertion points: URL path, query, body (form, JSON, XML, multipart), headers, cookies, tree view | Pure extractor with tests | ❌ | D-03 |
| BE-SC-03 | Audit check library: passive (headers, cookies, info disclosure, mixed content, ...) and active (injection families, XSS, SSRF via collaborator, path traversal, ...) as data-driven checks | Each check has id, severity, confidence, test | 🚧 ~20 passive + 2 active probes | D-02 |
| BE-SC-04 | Scan configuration: crawl/audit options, issue types, insertion point types, speed, library import/export | Config object serializable in Burp-compatible JSON | ❌ | D-04 |
| BE-SC-05 | Task queue: new scan, live audit/crawl from proxy traffic, pause/resume/cancel, per-task progress, queue persistence, resource pools | Survives restart | ❌ | D-05, J-02 |
| BE-SC-06 | Issue activity: audit items, insertion points, audit log, event log | Queryable per task | ❌ | D-06 |
| BE-SC-07 | Reporting: HTML/XML, issue selection and detail level | Deterministic output | ❌ | D-07 |
| BE-SC-08 | Out-of-band checks through the Collaborator engine | Polls and correlates | ❌ | D-08, I-03 |

## 7. Sequencer, Decoder, Comparer engines

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| BE-SQ-01 | Token analysis: entropy, character-level and bit-level tests (documented: FIPS monobit, poker, runs, long runs; spectral; correlation; compression; count/transitions), effective entropy with significance level, reliability | Same sample gives same numbers | 🚧 basic entropy | G-02 |
| BE-SQ-02 | Live capture: replay a request N times, extract token by cookie/form/custom location, pause/stop, save | Rate limited by a pool | ❌ | G-01 |
| BE-DC-01 | Codec library: URL, HTML, base64, ASCII hex, hex, octal, binary, gzip; hashes (MD5, SHA-1, SHA-2 family, others); smart decode heuristic | One module, pure functions, round-trip tests | 🚧 8 ops | F-01 |
| BE-DC-02 | Pipeline: ordered stages with live output, serializable, reused by Intruder payload processing | Same code path | ❌ | F-02, C-04 |
| BE-CP-01 | Diff engine: line (exact LCS) ✅, word, byte, character; merge; export; three-way | Deterministic, tested | 🚧 line only | F-03 |

## 8. Collaborator (OAST), sessions, logging, organizer

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| BE-CB-01 | Local interaction server: HTTP and DNS (non-privileged port), payload generation, interaction polling, correlation to requests | Works offline | ✅ local | I-01, I-02 |
| BE-CB-02 | Private server mode (documented flags `--collaborator-server`, `--collaborator-config`) with SMTP | Config file compatible | ❌ | I-04 |
| BE-SS-01 | Cookie jar updated from responses and applied to matching requests, per-domain rules, per-tool enable | Jar visible and editable | ❌ | H-01 |
| BE-SS-02 | Session handling rules and macros: recorded macros, extract/ update parameter, check session, run macro, scope per tool | Rule order and scope as in Burp | 🚧 3 actions + raw macros | H-02..H-04 |
| BE-LG-01 | Logger: ring buffer by memory limit (default 100 MB) with request/response size caps (1 MB), all tools incl. extensions as source, capture and view filters, annotations | Memory bounded | ❌ | L-04 |
| BE-OR-01 | Organizer: items with status, notes, highlight, collections (create, move, copy, share, import), export | Persisted | ❌ | L-02 |
| BE-SE-01 | Global search across tools (history, repeater, site map, logger), case/regex | Results link back to the item | 🚧 history/repeater/issue search | L-02 |

## 9. Persistence, configuration and startup

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| BE-PJ-01 | Project file v2: settings, proxy config, CA metadata, scanner config, task queue, UI layout, editor buffers, history, repeater, intruder attacks, annotations, collaborator state; versioned with migrations | Open any older version | 🚧 v1 saves history, rules, scope, sessions, macros, repeaters, issues, websockets, upstream, listener port, appearance | J-01 |
| BE-PJ-02 | Autosave and crash recovery (`--auto-repair` equivalent), atomic writes | Kill -9 loses at most one autosave interval | ❌ | J-02 |
| BE-PJ-03 | Temporary project mode and project chooser | Temp project discarded on exit | ❌ | J-04 |
| BE-CF-01 | Burp-compatible configuration JSON: `user_options.*` and `project_options.*`/`proxy.*` shapes (e.g. `proxy.request_listeners[] {certificate_mode, listen_mode, listener_port, running, use_custom_tls_protocols, custom_tls_protocols[], enable_http2}`), import and export, merge of several files | A real Burp config loads; unknown keys preserved | ❌ | J-03 |
| BE-CF-02 | CLI flags (documented): `--help`, `--disable-extensions`, `--diagnostics`, `--use-defaults`, `--collaborator-server`, `--collaborator-config`, `--project-file`, `--config-file` (repeatable), `--user-config-file` (repeatable), `--auto-repair`, `--unpause-spider-and-scanner` | Same names, same semantics; WebProbe-only env switches stay under `WEBPROBE_*` | ❌ | J-04, N-05 |
| BE-CF-03 | Renderer environment policy: drop `LIBGL_ALWAYS_INDIRECT`, software GL and X11 when no render node, `WEBPROBE_GL=native` opt-out | 6 tests | ✅ | P-13 |

## 10. Extensions

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| BE-EX-01 | Native extension API (Rust traits): HTTP handlers, proxy handlers, context menus, custom tabs, scan checks, payload generators/processors, session handling actions, editors, persistence | Example extension in tests | ❌ | K-01 |
| BE-EX-02 | JVM host loading Montoya API jars (`burp.api.montoya.*`) so existing BApps run; capability and error reporting (Details / Output / Errors) | A sample BApp loads | ❌ | K-02 |
| BE-EX-03 | Extension manager: install, remove, order, reload, system impact, per-extension output and errors; `--disable-extensions` | Safe mode starts clean | ❌ | K-03 |

## 11. Cross-cutting requirements

**Performance (targets, measured in `N-02`)**: 100k history rows scroll at 60 fps (virtualized, cached views); proxy adds under
5 ms median per request at 500 req/s on loopback; Intruder sustains the pool limit without UI hitching; memory bounded by
history cap and Logger limit.

**Reliability**: every parser fuzzed (N-03); workers survive panics and report them in an event log; project writes atomic.

**Security**: listeners default to 127.0.0.1; CA key in memory only unless exported; no credentials in logs or project files by
default; extension host runs with an explicit permission list; renderer env edits are limited to process scope.

**Observability**: structured event log (level, source, message, task id) feeds the Dashboard Event log, the Logger and the
status line; a `--diagnostics` dump prints versions, listeners, renderer path and config sources.

**Testing**: unit tests beside each engine; protocol tests with in-process origin servers on ephemeral ports (never 8080/8081);
golden tests against recorded Burp behaviour where a rule is copied (`mechanics.json`); UI checked through `qa/qa.sh`
screenshot pairs. Required before a task is `done`: tests green, evidence line in `tasks.json`, `mechanics.json` claim when
behaviour changed.

## 12. Module map and ownership (current → target)

| Concern | Module today | Target |
|---|---|---|
| Listeners, proxying, history, intercept | `net.rs` (large) | split into `proxy/` (listener, intercept, rules), `history.rs`, `upstream.rs` |
| HTTP codec | `codec.rs`, `h2.rs` | unchanged, plus streaming reader |
| TLS and CA | `tls.rs` | add custom CA import and regenerate |
| Match and replace | `rules.rs` | add WebSocket and test mode |
| Scanner | `scan.rs`, `analysis.rs` | `scanner/` (crawl, insertion, checks, config, queue) |
| Intruder | `intruder.rs` (matrix, positions) | add `payloads.rs`, `processing.rs`, `runner.rs`, `grep.rs`, `pool.rs` |
| Persistence | `project.rs`, `settings.rs` | v2 format, autosave, Burp config import |
| Environment | `gl_env.rs` | unchanged |

## 13. Delivery order (backend first, UI second)
1. **Intruder**: payload types (C-03), processing (C-04), grep/results (C-05), runner and pools (C-06), then wire P-10.
2. **Codec**: Decoder library and pipeline (F-01, F-02) shared with payload processing; diff modes (F-03).
3. **Sessions and project**: cookie jar (H-01), macros and rules (H-02..H-04), project v2, autosave, Burp config import (J-01..J-04).
4. **Scanner**: insertion points (D-03), check library (D-02), crawl (D-01), configuration and queue (D-04, D-05), reporting (D-07).
5. **Collaborator and Sequencer depth** (I, G), then **extensions** (K) once the host decision is made.
