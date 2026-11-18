# WebProbe — Burp Suite gap review and task backlog

> **Historical review (2026-11-12, section 7 from 2026-11-15).** The verdict below ("15-20% parity") and the backlog text describe the build as it was then. The live task list is `tasks.json`; section 8 at the end is generated from it. Current standing: `qa/ZOOM-OUT-REVIEW-2026-11-18.md`.

Review date: 2026-11-12
Baseline: round 6 build (`app/`, 9,610 lines of Rust, 13 top-level tools)
Reference: `/opt/BurpSuite/burpsuite.jar` (Burp Suite Pro build 52685), `app/MECHANICS.md`, `app/mechanics.json`

This is a review of what the build actually contains, not of what the UI labels claim. Every gap below was
checked against the source in `app/src/` and, where relevant, the extracted Burp defaults in `MECHANICS.md`.

---

## 1. Verdict

The build is a credible **HTTP proxy + message viewer**, not yet a Burp Suite replacement. It has the right
top-level tool names, the right dark palette and the right basic request flow, but most tools are shallow
single-purpose screens and the protocol engine is HTTP/1.1-only with no body decoding.

| Area | State | What is missing |
|---|---|---|
| Proxy / HTTP engine | Partial | chunked, gzip/deflate/br, keep-alive, HTTP/2, invisible proxying, TLS pass-through, multiple listeners, response interception |
| Proxy UI | Partial | filterable/sortable history table, message editor, site map tree, splitters, status bar, context menus |
| Target | Shallow | flat host list + flat request list; no site map tree, no issue definitions, no content discovery |
| Scanner | Shallow | ~20 passive checks + 2 active probes; no crawler, no audit check library, no issue definitions, no scan config, no queue, no reporting |
| Intruder | Shallow | one attack shape (sequential sniper); no attack types, payload sets, payload processing, grep/extract, resource pool, result export |
| Repeater | Shallow | tabs + send + raw text; no views, follow-redirects, send-to, copy-as, save, rename/close, compare |
| Sequencer | Good | entropy stats work; no charts, auto-analyze, FIPS tests, export |
| Decoder | Shallow | 8 one-shot encode/decode ops; no smart decode, hash, ROT13, ASCII-hex, construct, pipeline |
| Comparer | Basic | line diff only; no word/byte modes, merge, export |
| Sessions | Shallow | 3 rule actions + raw-request macros; no cookie jar, no macro recorder, no recorded login sequences |
| Collaborator | Local only | no public relay / OAST server, no SMTP, no scanner integration |
| Extensions | Absent | no JVM/Montoya host, no BApp manager, no native extension API |
| Project / settings | Partial | saves history + rules + scope + repeaters + issues; no full state, no settings UI, no autosave/recovery |
| UI system | Basic | one window, fixed panels, no docking, no status bar, no theming, no shortcut help |

**Rough parity:** 15–20% of Burp's feature surface, and a smaller fraction of its depth. The 13 tool tabs give
the appearance of parity; the engine and the editors underneath do not.

---

## 2. UI review

What the current window gives you (`src/ui.rs`):

- 30 px top bar: logo mark, name, 6 tab buttons, a "More tools" menu, and a right-aligned proxy/intercept label.
- One central panel per tool. No menu bar, no toolbar, no status bar, no docking, no detachable windows.
- Tables are `egui::Grid` inside `ScrollArea`; the Proxy history renders at most 1,000 rows.
- Panels use fixed `max_height` / fixed-width side panels, not user-resizable splitters.
- Detail view is read-only text: Raw / Hex / Headers / Params sub-tabs, no editing.
- Repeater uses a plain `TextEdit` for the request and a plain label for the response.

Concretely missing versus Burp's UI:

1. **Status bar** — listener state, intercept state, scan/attack progress, memory/queue, connection errors.
2. **Menu bar / toolbar** — File, Edit, View, Project, Settings; new/open/save project; global actions.
3. **Dockable tabs and split panes** — Burp lets you detach tools into their own windows and resize every split.
4. **Site map tree** — branch/leaf tree with method, URL, status, length, comment; scope colouring; filter.
5. **Message editor** — syntax highlighting, line numbers, wrap, font-size control, find-in-message, hex edit,
   pretty JSON/XML/HTML, rendered HTML, parameter table with editable values.
6. **Table behaviour** — sortable columns, column chooser, resizable widths, sticky header, multi-select,
   right-click context menu, copy/save/send-to, filter bar with regex and column filters.
7. **Context menus everywhere** — currently every action is a button or a hotkey; there are no right-click menus.
8. **Feedback** — progress bars, cancellable tasks, notification toasts, error surfaces with retry.
9. **Theming and density** — one fixed dark theme; no light/high-contrast, no compact/comfortable density,
   no font settings, no persisted layout.
10. **Onboarding** — no first-run proxy/CA setup, no "install CA" checklist, no sample traffic.

The visual language (orange accent, mono shades, zebra striping) is close to Burp's dark theme, so this is a
layout/behaviour gap more than a colour gap.

---

## 3. Functional gaps in detail

### 3.1 HTTP engine (`net.rs`, `util.rs`)

- **No chunked transfer decoding.** `read_response_head` reads to the header boundary and the body is stored
  raw; `Transfer-Encoding: chunked` bodies appear with chunk sizes and are measured wrong.
- **No content decoding.** No gzip, deflate, br or zstd handling; compressed bodies are shown as binary.
- **No keep-alive / connection reuse.** `send_raw` forces `Connection: close`; every request opens a socket.
- **No HTTP/2.** No `h2`/`hyper` dependency; h2c and HTTP/2 over TLS are absent.
- **No invisible proxying.** No reconstruction of requests from `GET /absolute` + Host, no non-proxy client support.
- **No TLS pass-through list.** Every TLS connection is MITM'd; no host exclusion.
- **No client-certificate (mTLS) support.** `with_no_client_auth()` in all client configs.
- **One listener, bound to 127.0.0.1 only.** Port can be changed, address cannot.
- **No response interception.** Only requests can be held; WebSocket messages cannot be intercepted.
- **Request parsing is minimal.** No absolute-URI handling beyond the proxy path, no header folding, no
  HTTP/0.9/1.0 nuance, no body limits beyond 4 MiB for requests.

### 3.2 Proxy (`ui.rs`, `tools.rs`)

- History table: 6 fixed columns, text filter only, 1,000-row render cap, no sort, no column chooser, no export.
- No "save item", "copy as curl", "copy as Python requests", "copy URLs", "add to scope", "deactivate interception".
- No filter by status, method, MIME, host, regex, or "only in-scope".
- Match & replace exists for request and response (literal + regex) but has no enable/disable-all, no import/export,
  no per-rule scope, no "only apply to in-scope".
- Upstream HTTP/SOCKS5 exists; no upstream auth failure surfacing, no per-host routing rules.
- CA can be exported but not imported; no CA generation options (key size, validity) in the UI.
- No WebSocket interception/editing; frames are view-only.
- No proxy listener options: bind address, multiple ports, SOCKS listener, invisible proxy, TLS pass-through,
  HTTP/2, response streaming, timeouts (values are hard-coded from defaults).

### 3.3 Target (`ui.rs`, `scan.rs`)

- Host list is flat; request list is flat; no tree, no branch aggregation, no per-branch counts.
- No issue definitions (name, severity, confidence, remediation, references) — only free-text issue rows.
- No content discovery, no "analyze target", no crawl.
- Scope editor is a 5-column grid of include/exclude literal/regex rules; no advanced scope (URL prefixes,
  file extensions, HTTP methods, "suite scope", "custom scope" modes).
- No site map annotations/comments, no "compare site maps".

### 3.4 Scanner (`scan.rs`)

- Passive checks: ~20 (security headers, cookie flags, server disclosure, 7 error signatures, 6 secret keywords).
- Active checks: 2 probes (SQL error via `'`, XSS reflection marker), query-string parameters only, max 30.
- No crawl engine at all; `CRAWL_MAX_UNIQUE_LOCATIONS` is only used as a passive-audit cap.
- No insertion-point coverage beyond URL query parameters: no body params, headers, cookies, path segments, multipart.
- No audit check library with severity/confidence/remediation; no issue definitions; no false-positive handling.
- No scan configuration UI (crawl limits, audit optimization, insertion points, speed/accuracy, check selection).
- No scan queue/task model, no live audit/live crawl, no pause/resume/cancel beyond a stop flag.
- No reporting/export (HTML/CSV/XML), no "issue activity" grouping, no "advisory".
- No scanner integration with Collaborator (blind SSRF/XXE/OOB).

### 3.5 Intruder (`net.rs::start_attack`, `ui.rs::intruder`)

- Only one attack shape: one marked position at a time, payloads applied sequentially. This is not sniper,
  battering ram, pitchfork or cluster bomb.
- No payload sets (simple list, runtime file, custom iterator, brute forcer, case modification, numbers, dates,
  usernames, null payloads, character frobber).
- No payload processing (prefix/suffix, substring, encode URL/base64/HTML/hex, hash, regex, skip).
- No grep match / grep extract / grep capture / grep payloads; result grid has payload, status, length, ms only.
- No resource pool / concurrency / throttle configuration (a fixed 50 ms sleep is the only pacing).
- No pause/resume, no per-row detail, no save results, no export, no "send to Repeater/Comparer".
- Positions are typed as `§` markers; no auto-mark, clear, add-from-selection, or marker highlighting.

### 3.6 Repeater (`ui.rs::repeater`)

- Tabs can be added but not renamed, closed, reordered, or persisted independently (they are persisted in the project file).
- Request editor is a plain text box; response is a plain label.
- No Raw / Params / Headers / Hex / Render views; no syntax highlighting; no find; no wrap toggle.
- No follow-redirects (never/always/on-site), no "follow and enumerate".
- No send-to Intruder / Comparer / Decoder / Scanner; no copy as curl/Python; no save item; no drop/close.
- No request history per tab, no diff against previous response, no timing/status breakdown.
- No content-type-aware body editing (JSON form, multipart, URL-encoded form).
- No "paste URL" or "change request method" helpers.

### 3.7 Other tools

- **Decoder:** 8 one-shot operations (Base64/URL/hex/HTML encode+decode). Missing smart decode, hashes (MD5/SHA),
  ROT13, ASCII hex, construct, multi-stage pipeline, input/output file.
- **Comparer:** line diff only. Missing word/byte diff, merge, export, three-way compare.
- **Sequencer:** solid token stats and entropy; missing live capture over TLS (only plain `send_raw`), auto-analyze,
  character/bit-level charts, FIPS 140-2 style tests, export.
- **Sessions:** 3 actions (set header, use cookie, run macro) and raw-request macros. No cookie jar shared across
  tools, no macro recorder, no recorded login sequences, no session validation, no browser recovery.
- **Collaborator:** local HTTP/DNS listeners only. No public relay, no payload server, no SMTP, no polling integration
  with the scanner, no private-instance workflow.
- **Extensions:** none. The UI correctly says Java plugins cannot run in a Rust process. No JVM/Montoya host and no
  native extension API either, so there is no extension path at all.
- **Search:** scans Proxy, Repeater, Scanner and WebSocket text; no regex option, no tool/scope filters, no jump-to-hit,
  no cross-tool "search all" with highlighting.
- **Project:** saves history, rules, scope, session rules, macros, repeaters, issues and WebSocket records. Does not
  save settings, proxy config, CA, scanner config, task state, UI layout, or editor buffers; no autosave, no recovery,
  no "new project" wizard, no recent projects.

---

## 4. Task backlog

Priorities: **P0** = required for a usable Burp replacement; **P1** = required for claimed parity;
**P2** = depth/ecosystem. Effort: **S** ≤ 1 round, **M** = 2–4 rounds, **L** = 5+ rounds.
Every task must end with an automated check and a `mechanics.json` claim where it changes behaviour.

### Epic A — HTTP engine correctness (P0)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| A-01 ✅ | Decode `Transfer-Encoding: chunked` for requests and responses | Chunked bodies are reassembled before storage/display; `Content-Length` and byte counts are correct; tests cover single/multi-chunk and trailers | M |
| A-02 ✅ | Decode `Content-Encoding: gzip`, `deflate`, `br` | Compressed response bodies are decoded for passive checks and display; original encoding kept for forwarding; tests per codec | M |
| A-03 ✅ | Keep-alive and connection reuse | Upstream connections are pooled per host; `Connection: close` is not forced; pipelining is off; tests assert socket reuse | M |
| A-04 ✅ | Robust HTTP/1.x parsing | Absolute-form, origin-form, header folding, duplicate headers, `Content-Length` + chunked conflict, 4 MiB+ bodies; malformed input never panics | M |
| A-05 ✅ | HTTP/2 upstream and h2c | Requests negotiate h2 over TLS via ALPN and h2c when offered; HTTP/2 responses are stored with a normalized HTTP/1.1 view; tests against a local h2 server | L |
| A-06 ✅ | TLS pass-through and mTLS | Host exclusion list bypasses MITM; client certificates can be configured per host; tests with a local TLS server | M |
| A-07 ✅ | Proxy listener options | Multiple listeners, bind address, port validation/restart without losing history; status shown in UI | M |
| A-08 ✅ | Invisible proxying | Reconstruct origin-form requests from absolute-form and Host; non-proxy clients work; tests for both forms | M |

### Epic B — Proxy UI and message editing (P0)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| B-01 ✅ | History table with filter/sort/columns | Filter bar (text, regex, method, status, MIME, in-scope), sortable columns, column chooser, resizable widths, sticky header, virtualized rendering above 10k rows | L |
| B-02 🚧 | Message editor | Raw editor with syntax highlighting, line numbers, wrap toggle, font size, find-in-message, hex edit; request editable in place and sendable | L |
| B-03 | Response views | Raw / Params / Headers / Hex / Render (HTML) with correct entity decoding; JSON/XML pretty view; image preview | M |
| B-04 | Context menus | Right-click menus for history, site map, repeater, issues, decoder results; copy/save/send-to/add-to-scope | M |
| B-05 🚧 | Resizable layout + status bar | Splitters between every pane; status bar with listener, intercept, queue, scan/attack progress, last error; layout persisted | L |
| B-06 | Site map tree | Branch/leaf tree with method, URL, status, length, comment; expand/collapse, filter, scope colouring, annotations | L |
| B-07 | Multi-select and bulk actions | Select ranges with shift/ctrl; bulk send-to, export, add-to-scope, delete | M |
| B-08 | Proxy options UI | Listener, interception (request/response/WebSocket), match & replace import/export, upstream per-host rules, TLS/HTTP settings | L |
| B-09 | WebSocket interception | Hold, edit and forward frames; WebSocket history with filters and search; TLS WebSocket relay verified | L |

### Epic C — Intruder parity (P0)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| C-01 🚧 | Four attack types | Sniper, battering ram, pitchfork, cluster bomb produce the correct request matrix; tests assert counts and payload placement | M |
| C-02 🚧 | Payload positions | Auto-mark, clear, add-from-selection, marker highlighting, multiple positions per request | M |
| C-03 🚧 | Payload sets | Simple list, runtime file, custom iterator, brute forcer, case modification, numbers, dates, usernames, null payloads, character frobber | L |
| C-04 ✅ | Payload processing | Prefix/suffix, substring, encode (URL/Base64/HTML/hex), hash, regex, skip; ordered pipeline | M |
| C-05 | Result analysis | Grep match, grep extract, grep capture, grep payloads; configurable result columns; per-row detail | L |
| C-06 | Attack control | Pause/resume/stop, concurrency, throttle, resource pool, retry/backoff, progress | M |
| C-07 | Results I/O | Save/export results (CSV/XML), send row to Repeater/Comparer, copy as curl | M |

### Epic D — Scanner parity (P0)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| D-01 | Crawl engine | Follow links, forms, scripts, redirects; depth/location caps; scope rules; produce a site map; tests on a local multi-page fixture | L |
| D-02 🚧 | Audit check library | ≥ 40 checks with severity, confidence, description, remediation, references; unit tests per check with positive/negative fixtures | L |
| D-03 | Insertion points | Query, body, headers, cookies, path segments, multipart; max 30 per base request; tests per point type | L |
| D-04 | Scan configuration | Crawl/audit/optimization/insertion-point/speed settings; persisted; check selection | M |
| D-05 | Task queue | New scan, pause/resume/cancel, per-task progress, live audit/crawl, queue persistence | L |
| D-06 | Issue activity | Group by host/issue, filter by severity/confidence, evidence, detail view, false-positive marking | M |
| D-07 | Reporting | Export HTML/CSV/XML; summary + detail; severity/confidence tables; remediation text | M |
| D-08 | Collaborator integration | Active checks generate OAST payloads and confirm interactions; blind SSRF/XXE/OOB findings | M |

### Epic E — Repeater parity (P0)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| E-01 | Request/response editors | Raw, Params, Headers, Hex, Render; editable request; syntax highlighting; find | L |
| E-02 | Follow redirects | Never / on-site / always; "follow and enumerate"; redirect chain shown | M |
| E-03 | Send-to and copy | Send to Intruder, Comparer, Decoder, Scanner; copy as curl, Python requests, raw; save item | M |
| E-04 | Tab management | Rename, close, reorder, duplicate, persisted order and contents | M |
| E-05 | Compare | Diff current response against previous; request diff; send both sides to Comparer | M |
| E-06 | Editing helpers | Paste URL, change method, URL-encode as you type, content-type-aware body editing | M |

### Epic F — Decoder and Comparer (P1)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| F-01 | Decoder operations | Smart decode, MD5/SHA-1/SHA-256, ROT13, ASCII hex, URL/Base64/HTML/hex, construct | M |
| F-02 | Decoder pipeline | Multi-stage encode/decode chain with editable stages and live output | M |
| F-03 | Comparer modes | Word, byte and character diff; merge; export; three-way compare | M |

### Epic G — Sequencer (P1)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| G-01 | Live capture | Capture tokens over TLS and plain HTTP, auto-capture N samples, ignore-abnormal toggle | M |
| G-02 | Analysis depth | Character-level and bit-level entropy, FIPS-style tests, confidence rating, charts | M |
| G-03 | Export | Results to CSV/JSON; sample set save/load | S |

### Epic H — Sessions and macros (P1)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| H-01 | Cookie jar | Shared cookie store updated from responses and sent on matching requests; per-domain rules | M |
| H-02 | Macro recorder | Record a proxy-driven sequence, parameterize values, replay, save/load | L |
| H-03 | Recorded login sequences | Capture login, extract token, apply to session rules; validate session | L |
| H-04 | Session rule actions | Set header, set cookie, run macro, validate session, browser recovery, post-request match/replace | M |

### Epic I — Collaborator / OAST (P0)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| I-01 | Payload generation | HTTP, DNS and SMTP payloads with unique IDs; copy/insert into requests | M |
| I-02 | Interaction polling | Poll public relay or self-hosted server; list HTTP/DNS/SMTP interactions with source IP and timing | M |
| I-03 | Scanner integration | Blind checks use generated payloads and raise findings on interaction | M |
| I-04 | Private instance | Configurable server, polling interval, retention, secret; docs for self-hosting | M |

### Epic J — Project, settings and state (P1)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| J-01 | Full-state project file | Version 2 format: settings, proxy config, CA metadata, scanner config, task queue, UI layout, editor buffers | L |
| J-02 | Autosave and recovery | Periodic autosave, crash recovery prompt, temp project support | M |
| J-03 | Settings UI | Searchable settings with sections, import/export, restore defaults, per-setting reset | L |
| J-04 | New/open project flow | Start screen, recent projects, new temporary project, project integrity checks | M |

### Epic K — Extensions (P2)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| K-01 | Native extension API | Stable Rust/WASM ABI for custom tabs, issue definitions, request/response hooks; example extension | L |
| K-02 | JVM/Montoya host | Embed a JVM (JNI) or a subprocess host; load a subset of Montoya API; sandbox and error reporting | L |
| K-03 | Extension manager | Install/enable/disable/remove, dependency view, BApp-like catalogue (no copied assets) | M |

### Epic L — Engagement and utility features (P1)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| L-01 | CSRF PoC generator | Generate an HTML form PoC from a request; copy/download | S |
| L-02 | Engagement tools | Find comments, find scripts, find references, copy URLs, copy as curl | M |
| L-03 | Content discovery | Wordlist-based path discovery with extension set, recursion, scope, result table | M |
| L-04 | Logger | Global traffic log across tools with filters, search, export; independent of Proxy history | M |
| L-05 | Embedded browser | Launch a configured Chromium for proxy testing, or a documented "use your browser" flow | L |

### Epic M — UI/UX system (P0, continuous)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| M-01 ✅ | Design tokens | One token module for colour, spacing, radius, typography, density; no ad-hoc hex in widgets | M |
| M-02 ✅ | Table component | Shared sortable/filterable/virtualized table used by Proxy, Target, Scanner, Intruder, Collaborator | L |
| M-03 ✅ | Editor component | Shared message editor/view used by Proxy, Repeater, Intruder, Sequencer, Decoder | L |
| M-04 ✅ | Feedback and errors | Progress bars, cancel buttons, toasts, inline errors, retry actions, empty/loading states | M |
| M-05 ✅ | Theming and density | Dark/light/high-contrast, compact/comfortable, font size, persisted | M |
| M-06 ✅ | Keyboard and accessibility | Shortcut help overlay, customizable hotkeys, focus order, contrast, screen-reader labels | M |
| M-07 ✅ | Onboarding | First-run CA/proxy setup, verification checklist, sample traffic, docs links | M |

### Epic N — Quality, performance and build (P0)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| N-01 | Parser/engine tests | Unit + integration tests for chunked, gzip, keep-alive, h2, TLS, proxy; run in CI | L |
| N-02 | Performance | 10k history entries and 1k site-map nodes render at 60 fps; no per-frame full-list scans | M |
| N-03 | Fuzzing | Malformed HTTP/TLS/WebSocket inputs never panic or hang; fuzz targets in CI | M |
| N-04 | Builder reliability | Fix the `omp` model-routing 404s (glm-5.3 / kimi-k3.1) so rounds complete; add a working fallback | S |
| N-05 | Release build | `cargo build --release` under 3 minutes; binary starts in under 1 s; screenshot check passes | S |

---

## 5. Suggested build order

1. **N-04** first — the last six rounds lost hours to model-routing 404s; fix the builder before adding scope.
2. **A-01..A-04** — the engine must decode real traffic before any UI work is meaningful.
3. **M-01..M-03, B-01, B-02, B-05** — the shared table/editor/layout foundation; everything else sits on it.
4. **E-01..E-03, C-01..C-04** — the two tools users reach for first; make them actually usable.
5. **D-01..D-04, I-01..I-02** — give the scanner a crawl and the Collaborator a relay.
6. **B-06, B-04, B-07, M-04** — site map, context menus, bulk actions, feedback.
7. **F, G, H, J, L** — depth and workflow.
8. **A-05..A-08, B-08, B-09, K, L-05** — HTTP/2, advanced proxy, extensions, embedded browser.

Definition of done for the current milestone: a user can proxy a browser, see a filterable site map and history,
edit and resend a request in Repeater, run a four-mode Intruder attack, crawl and audit a local app, and export
issues — with chunked/gzip traffic decoded correctly throughout.

---

## 6. How to hand this to the builder

Start a follow-up round with a request like:

> Work through `TASKS.md` in the suggested order. Do one epic per round, update the checkboxes as you finish,
> add a `mechanics.json` claim and an automated check for every task, and do not mark a task done without its
> acceptance criteria passing.

Each round should end with: build passes, screenshot check passes, mechanics claims for the new behaviour, and
a short `PROGRESS.md` entry naming the tasks completed and the next task.

## 7. Gaps found by running real Burp Pro v2026.7.3 on Xvfb (2026-11-15)

Method: the reference jar was launched from `/opt/BurpSuite` on its own display, every tab/menu/dialog was captured and compared with WebProbe at 1440x900. Full write-up: `qa/GAP-REPORT-2026-11-15.md`. 🚧 = in progress.

### Epic P — Live Burp parity gaps (P0 unless noted)

| ID | Task | Acceptance criteria | Effort |
|---|---|---|---|
| P-01 ✅ | Top menu bar (P0) | Burp, Project, Intruder, Repeater, View, Help menus in the window chrome; Burp menu lists Search, Settings, Configuration library, User settings >, Log in, Exit; every item either works or is disabled with a reason; shortcuts shown beside items match shortcuts.rs | M |
| P-02 | Tab bar and global controls parity (P1) | Single tab row in Burp order (Dashboard, Target, Proxy, Intruder, Repeater, Collaborator, Sequencer, Decoder, Comparer, Logger, Organizer, Extensions, Discover) with no 'More tools' overflow at 1440 px; top-right global search, settings gear and browser launcher; active tab shown with an underline | M |
| P-03 | Settings dialog parity (P0) | Searchable dialog with All/User/Project filter pills and a category tree (Tools: Proxy, Intruder, Repeater, Sequencer, Comparer; Project; Sessions; Network; User interface; Suite; Extensions; Configuration library); Proxy page has a listeners table (Running, Interface, Invisible, Redirect, Certificate, TLS protocols) with Add/Edit/Remove, CA import/export/regenerate, request-interception rules table with Up/Down | L |
| P-04 ✅ | Repeater layout parity (P0) | Numbered tabs with close and '+', primary Send, Cancel, back/forward history, Target field with edit action, Request | Response | Inspector panes with side-by-side/stacked/tabbed toggles, Pretty/Raw/Hex views, wrap/non-printable/newline toggles, search bar with highlight count, right dock (Inspector, Notes, Explanations, Custom actions), status line | L |
| P-05 | HTTP history columns and views (P0) | Add Params, Edited, Extension and Title columns; Pretty and Renderer views in the message pane; column chooser exposes all of them | M |
| P-06 | Intercept bar parity (P1) | Intercept on/off toggle, Forward and Drop as split buttons with dropdown actions (forward all, drop all), Open browser, help and overflow menu; empty state text explaining intercept | S |
| P-07 | Decoder layout and operations (P1) | Text/Hex input toggle; 'Decode as', 'Encode as' and 'Hash' dropdowns; Smart decode; chained output panes | M |
| P-08 | Comparer item tables (P1) | Two item tables (# / Length / Data) with Paste, Load, Remove, Clear and Compare Words / Bytes buttons | M |
| P-09 | Dashboard task model (P1) | Task cards (live audit, live crawl, scans) with pause/resume, issue counters and Summary / Audit items / Issues / Event log / Logger / Audit log tabs; 'Task execution is paused' banner | L |
| P-10 | Wire Intruder UI to intruder.rs (P0) | Attack-type selector, Auto/Add/Clear position buttons with marker highlighting, one payload set per position, request count preview with the limit error shown, runner replaces net::start_attack; empty-state text 'To get started, send a request to Intruder from anywhere in Burp' | M |
| P-11 | Light theme as the default option (P2) | Light palette matches Burp's default look (flat white, orange underline accent) and is selectable in Settings; dark remains available | S |
| P-12 | Known small defects (P2) | Target scope header repeats its inner 'Scope' label; onboarding counts seeded history as real HTTPS traffic; selection stays on a row the filter hides; Burp history comparison needs a populated Burp table (listener answered but history stayed empty) | S |
| P-13 ✅ | WSL2 rendering fix and live QA driver (P0) | App opens a window on WSL2/Xvfb without env tweaks; QA driver clicks, types, scrolls and screenshots; policy tested | M |
| P-14 ✅ | Repair UI wiring lost in a bad edit (P0) | Filter bar, Comparer, Target scope, project controls, listener status/editor and appearance options are all reachable again; no dead helpers left | M |
| P-15 | Interactive Open browser launcher (P1) | 'Open browser' (Intercept bar, empty states, Dashboard) launches the user's Chrome/Chromium or a downloaded Chrome for Testing with a throwaway profile, --proxy-server set to the active listener and the WebProbe CA trusted for that profile only; reports clearly when no browser is found | M |
| P-16 | Headless engine trait + Obscura sidecar spike (P1) | HeadlessBrowser trait with an Obscura implementation behind it; gate = the 5 acceptance checks in docs/EVAL-OBSCURA.md (JS crawl finds more links, all traffic incl. HTTPS in history via SSL_CERT_FILE, stored response to PNG <2 s and <150 MB, stealth/tracker blocking off, version pinned and digest verified); also compare Lightpanda in the same fixtures | M |

---

## 8. Status as of 2026-11-18 (generated from tasks.json)

126 tasks: 103 done, 2 rejected, 21 todo. Acceptance criteria and evidence are in `tasks.json`.

### A — HTTP engine correctness

| Id | Pri | Status | Title |
|---|---|---|---|
| A-01 | P0 | ✅ done | Decode `Transfer-Encoding: chunked` for requests and responses |
| A-02 | P0 | ✅ done | Decode `Content-Encoding: gzip`, `deflate`, `br` |
| A-03 | P0 | ✅ done | Keep-alive and connection reuse |
| A-04 | P0 | ✅ done | Robust HTTP/1.x parsing |
| A-05 | P0 | ✅ done | HTTP/2 upstream and h2c |
| A-06 | P0 | ✅ done | TLS pass-through and mTLS |
| A-07 | P0 | ✅ done | Proxy listener options |
| A-08 | P0 | ✅ done | Invisible proxying |

### B — Proxy UI and message editing

| Id | Pri | Status | Title |
|---|---|---|---|
| B-01 | P0 | ✅ done | History table with filter/sort/columns |
| B-02 | P0 | ✅ done | Message editor |
| B-03 | P0 | ✅ done | Response views |
| B-04 | P0 | ✅ done | Context menus |
| B-05 | P0 | ✅ done | Resizable layout + status bar |
| B-06 | P0 | ✅ done | Site map tree |
| B-07 | P0 | ✅ done | Multi-select and bulk actions |
| B-08 | P0 | ✅ done | Proxy options UI |
| B-09 | P0 | ✅ done | WebSocket interception |

### C — Intruder parity

| Id | Pri | Status | Title |
|---|---|---|---|
| C-01 | P0 | ✅ done | Four attack types |
| C-02 | P0 | ✅ done | Payload positions |
| C-03 | P0 | ✅ done | Payload sets |
| C-04 | P0 | ✅ done | Payload processing |
| C-05 | P0 | ✅ done | Result analysis |
| C-06 | P0 | ✅ done | Attack control |
| C-07 | P0 | ✅ done | Results I/O |

### D — Scanner parity

| Id | Pri | Status | Title |
|---|---|---|---|
| D-01 | P0 | ✅ done | Crawl engine |
| D-02 | P0 | ✅ done | Audit check library |
| D-03 | P0 | ✅ done | Insertion points |
| D-04 | P0 | ✅ done | Scan configuration |
| D-05 | P0 | ✅ done | Task queue |
| D-06 | P0 | ✅ done | Issue activity |
| D-07 | P0 | ✅ done | Reporting |
| D-08 | P0 | ✅ done | Collaborator integration |

### E — Repeater parity

| Id | Pri | Status | Title |
|---|---|---|---|
| E-01 | P0 | ✅ done | Request/response editors |
| E-02 | P0 | ✅ done | Follow redirects |
| E-03 | P0 | ✅ done | Send-to and copy |
| E-04 | P0 | ✅ done | Tab management |
| E-05 | P0 | ✅ done | Compare |
| E-06 | P0 | ✅ done | Editing helpers |

### F — Decoder and Comparer

| Id | Pri | Status | Title |
|---|---|---|---|
| F-01 | P1 | ✅ done | Decoder operations |
| F-02 | P1 | ✅ done | Decoder pipeline |
| F-03 | P1 | ✅ done | Comparer modes |

### G — Sequencer

| Id | Pri | Status | Title |
|---|---|---|---|
| G-01 | P1 | ✅ done | Live capture |
| G-02 | P1 | ✅ done | Analysis depth |
| G-03 | P1 | ✅ done | Export |

### H — Sessions and macros

| Id | Pri | Status | Title |
|---|---|---|---|
| H-01 | P1 | ✅ done | Cookie jar |
| H-02 | P1 | ✅ done | Macro recorder |
| H-03 | P1 | ✅ done | Recorded login sequences |
| H-04 | P1 | ✅ done | Session rule actions |

### I — Collaborator / OAST

| Id | Pri | Status | Title |
|---|---|---|---|
| I-01 | P0 | ✅ done | Payload generation |
| I-02 | P0 | ✅ done | Interaction polling |
| I-03 | P0 | ✅ done | Scanner integration |
| I-04 | P0 | ✅ done | Private instance |

### J — Project, settings and state

| Id | Pri | Status | Title |
|---|---|---|---|
| J-01 | P1 | ✅ done | Full-state project file |
| J-02 | P1 | ✅ done | Autosave and recovery |
| J-03 | P1 | ✅ done | Settings UI |
| J-04 | P1 | ✅ done | New/open project flow |

### K — Extensions

| Id | Pri | Status | Title |
|---|---|---|---|
| K-01 | P2 | ✅ done | Native extension API |
| K-02 | P2 | ✅ done | JVM/Montoya host |
| K-03 | P2 | ✅ done | Extension manager |

### L — Engagement and utility features

| Id | Pri | Status | Title |
|---|---|---|---|
| L-01 | P1 | ✅ done | CSRF PoC generator |
| L-02 | P1 | ✅ done | Engagement tools |
| L-03 | P1 | ✅ done | Content discovery |
| L-04 | P1 | ✅ done | Logger |
| L-05 | P1 | ✅ done | Embedded browser |

### M — UI/UX system

| Id | Pri | Status | Title |
|---|---|---|---|
| M-01 | P0 | ✅ done | Design tokens |
| M-02 | P0 | ✅ done | Table component |
| M-03 | P0 | ✅ done | Editor component |
| M-04 | P0 | ✅ done | Feedback and errors |
| M-05 | P0 | ✅ done | Theming and density |
| M-06 | P0 | ✅ done | Keyboard and accessibility |
| M-07 | P0 | ✅ done | Onboarding |

### N — Quality, performance and build

| Id | Pri | Status | Title |
|---|---|---|---|
| N-01 | P0 | ✅ done | Parser/engine tests |
| N-02 | P0 | ✅ done | Performance |
| N-03 | P0 | ✅ done | Fuzzing |
| N-04 | P0 | ⛔ rejected | Builder reliability |
| N-05 | P0 | ✅ done | Release build |

### P — Live Burp parity gaps (found 2026-11-15)

| Id | Pri | Status | Title |
|---|---|---|---|
| P-01 | P0 | ✅ done | Top menu bar |
| P-02 | P1 | ✅ done | Tab bar and global controls parity |
| P-03 | P0 | ✅ done | Settings dialog parity |
| P-04 | P0 | ✅ done | Repeater layout parity |
| P-05 | P0 | ✅ done | HTTP history columns and views |
| P-06 | P1 | ✅ done | Intercept bar parity |
| P-07 | P1 | ✅ done | Decoder layout and operations |
| P-08 | P1 | ✅ done | Comparer item tables |
| P-09 | P1 | ✅ done | Dashboard task model |
| P-10 | P0 | ✅ done | Wire Intruder UI to intruder.rs |
| P-11 | P2 | ✅ done | Light theme as the default option |
| P-12 | P2 | ✅ done | Known small defects |
| P-13 | P0 | ✅ done | WSL2 rendering fix and live QA driver |
| P-14 | P0 | ✅ done | Repair UI wiring lost in a bad edit |
| P-15 | P1 | ✅ done | Interactive Open browser launcher |
| P-16 | P1 | ✅ done | Headless engine trait + Obscura sidecar spike |

### UAT 2026-11-16 — blocking defects

| Id | Pri | Status | Title |
|---|---|---|---|
| UAT-01 | P0 | ✅ done | Intruder attack-results window ignores all input (cannot close, cannot select a row) |
| UAT-02 | P0 | ✅ done | Repeater Cancel does not abort an in-flight request |
| UAT-03 | P0 | ⛔ rejected | Comparer uses one shared item collection and Paste is inert |
| UAT-04 | P1 | ✅ done | Persist proxy history (and site map) in the project file across restarts |
| UAT-05 | P1 | ✅ done | Window intermittently starts unmapped (process spins, proxy bound, no visible UI) |
| UAT-06 | P1 | ✅ done | Paste into request/message editors is ignored or delivers stale clipboard |

### UAT 2026-11-16 — polish

| Id | Pri | Status | Title |
|---|---|---|---|
| UAT-07 | P2 | ✅ done | History Time column is truncated and the table needs horizontal scrolling at 1440 px |
| UAT-08 | P2 | ✅ done | Menu bar parity: WebProbe menu only has Search, Settings, Quit |

### Automation / MCP integration

| Id | Pri | Status | Title |
|---|---|---|---|
| UAT-09 | P2 | ✅ done | Publish a usable accessibility tree and IPC socket for MCP automation |

### N — Quality, performance and build

| Id | Pri | Status | Title |
|---|---|---|---|
| N-06 | P1 | ✅ done | Disk-backed proxy history |
| N-07 | P2 | ✅ done | Split Shared and App by subsystem |

### D — Scanner parity

| Id | Pri | Status | Title |
|---|---|---|---|
| D-11 | P1 | ✅ done | Remaining Burp insertion points |
| D-09 | P1 | ✅ done | Remaining Collaborator check variants |
| D-10 | P2 | todo | Stored XSS retrieval pairing as Burp |
| D-12 | P2 | todo | Collaborator leftovers: SNI variant and scheme payload variants |

### R — Roadmap (zoom-out review 2026-11-18)

| Id | Pri | Status | Title |
|---|---|---|---|
| R-01 | P0 | todo | Docs truth pass |
| R-02 | P0 | todo | Portable build: no developer-machine paths |
| R-03 | P0 | todo | Montoya bridge broad enough for real BApps |
| R-04 | P0 | todo | Passive checks in the check registry + missing passive pack |
| R-05 | P1 | todo | HTTP/2 browser-to-proxy and a working Repeater protocol switch |
| R-06 | P1 | todo | Response streaming and server-sent events |
| R-07 | P1 | todo | WebSocket robustness and tools |
| R-08 | P1 | todo | Tests for untested modules |
| R-09 | P1 | todo | JWT checks |
| R-10 | P1 | todo | Active check pack (non-timing) |
| R-11 | P1 | todo | Scan configuration library |
| R-12 | P2 | todo | Repeater send groups and single-packet attack |
| R-13 | P2 | todo | DOM-based / JavaScript analysis |
| R-14 | P2 | todo | BCheck interpreter |
| R-15 | P2 | todo | Burp CLI flags, config JSON and REST API |
| R-16 | P2 | todo | Bambda-style filters and custom columns |
| R-17 | P2 | todo | Intruder payload completeness |
| R-18 | P2 | todo | Decompose App / Shared and split ui.rs |
| R-19 | P2 | todo | UI parity re-score |
