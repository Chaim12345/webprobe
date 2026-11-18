# WebProbe UI PRD: matching what Burp Suite Professional's interface can do

> **Status column re-checked 2026-11-18.** Every row that was ❌ or 🚧 on 2026-11-15 was re-read against the code; the per-row evidence (file:line) is in `qa/PRD-RECHECK-2026-11-18.md`. The re-check was done by a delegated model and spot-checked, not fully reviewed: rows marked "per task evidence" rest on `tasks.json`, not on a fresh code read. Rows that were already ✅ were not re-checked.


Status date: 2026-11-15 · Baseline: WebProbe `app/` (117 tests green) · Reference: Burp Suite Professional v2026.7.3
(build 52685) run live on Xvfb, plus the 364 documentation pages shipped inside `/opt/BurpSuite/burpsuite.jar`.

Companion: `docs/PRD-BACKEND.md` (engine requirements, ids `BE-*`), `qa/GAP-REPORT-2026-11-15.md` (side-by-side gaps),
`tasks.json` / `TASKS.md` (work items). Status legend: ✅ have · 🚧 partial · ❌ missing · ⛔ out of scope by decision.

## 1. Purpose and non-goals

A security tester who knows Burp must be able to sit down at WebProbe and find every control where they expect it,
doing the same job in the same number of clicks. The UI PRD therefore describes *observable behaviour*, not Burp's code.

Non-goals (decided, not forgotten):
- ⛔ Burp AT / Burp AI features (agentic AI, AI credits, Explore Issue, AI explainers). Not reproducible and not wanted.
- ⛔ The Discover tab's marketing content (Academy, Discord, YouTube cards). A Help menu with documentation links replaces it.
- ⛔ Bundled Chromium ("Burp's browser") in this phase; the setup flow serves `http://webprobe` and `http://burpsuite` instead (task L-05 reopens it).
- ⛔ Pixel-identical styling. Layout, labels, order and behaviour match; the theme tokens stay ours.

Principles: every control either works or is visibly disabled with a reason; nothing blocks the UI thread; every list over
10k rows is virtualized; every screen has an empty state that tells the user the next step; every behaviour claim is
checked against the reference app before it is marked ✅.

## 2. Global shell (Burp: window chrome, `Burp > ...`, tab row, dock)

| ID | Requirement (what Burp does) | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-SH-01 | Menu bar: `Burp`, `Project`, `Intruder`, `Repeater`, `View`, `Help` | Menus open on click and Alt-mnemonic; each item enabled or disabled with a tooltip reason; shortcuts shown match `shortcuts.rs` | 🚧 missing: Alt-mnemonic opening, per-item tooltip reasons, shortcut labels next to items; first menu named "WebProbe", not "Burp" | P-01 |
| UI-SH-02 | `Burp` menu: Search, Settings, Configuration library, User settings >, Log in, Exit | Items present; Log in, Infiltrator, Clickbandit shown disabled ("not in WebProbe") | 🚧 missing: "Log in" item not shown at all (should be present, disabled) | P-01 |
| UI-SH-03 | `Project` menu: new, open, save copy, project options, close | Wired to the project file flow | 🚧 missing: "Project options" and "close" items; the menu is wired to the project flow (menus.rs save_project_copy) | P-01, J-04 |
| UI-SH-04 | `Intruder` / `Repeater` menus: tool-specific commands (start/stop attack, send, rename tab, close tab, tab groups) | Mirror the toolbar actions | 🚧 missing: full Burp command set (start/stop attack, rename/close tab, tab groups) not verified in the menus; groups don't exist (R-12) | P-01, E-04 |
| UI-SH-05 | Single tab row in order Dashboard, Target, Proxy, Intruder, Repeater, Collaborator, Sequencer, Decoder, Comparer, Logger, Organizer, Extensions, (Discover) | 13 tabs visible at 1440 px, no overflow menu; active tab underlined | ✅ | P-02 |
| UI-SH-06 | Arrange and hide top-level tabs; restore default layout | Drag to reorder, right-click hide, `View > Reset layout`; persisted | 🚧 missing: drag-to-reorder and right-click hide of top-level tabs; layout not persisted | P-02 |
| UI-SH-07 | Global controls top right: browser launcher, command/console, global search, settings gear | All four present; search opens a result list across tools | 🚧 missing: command/console control | P-02 |
| UI-SH-08 | Command palette (`Go to Proxy`, `Go to Proxy > HTTP history`, ...) | `Ctrl+K` lists every navigable destination and wired action, recents first | ✅ | M-06 |
| UI-SH-09 | Hotkeys are user settings; all Ctrl-based; duplicates refused both ways | 50 defaults, file-authoritative | ✅ | M-06 |
| UI-SH-10 | Bottom dock: `Event log`, `All issues` opens docked panels; memory readout | Click toggles a panel above the status line; memory shown | ✅ | P-09 |
| UI-SH-11 | Status line per tool (`Ready`, request counters, errors) | Listener, intercept, held, history, messages, last message | ✅ | B-05 |
| UI-SH-12 | Themes: light (default look) and dark, UI scale | Palette Dark / Light / High contrast; light selectable as default | ✅ (per task evidence; code not re-read) | M-05, P-11 |
| UI-SH-13 | Title bar shows product, version, project name | `WebProbe vX · project.webprobe` | 🚧 missing: version number in the title | J-04 |
| UI-SH-14 | Toast and progress feedback for long actions | Toasts, progress with cancel | ✅ | M-04 |

## 3. Settings dialog (Burp: its own window, not a tab)

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-ST-01 | Search box filters the tree and pages live | Typing "listener" highlights Proxy; no match shows empty text | ✅ (per task evidence; code not re-read) | P-03, J-03 |
| UI-ST-02 | `All / User / Project` scope pills | Pills filter categories; each page labelled user or project | ✅ (per task evidence; code not re-read) | P-03 |
| UI-ST-03 | Category tree: Tools (Proxy, Intruder, Repeater, Sequencer, Comparer, Burp's browser), Project, Sessions, Network, User interface, Suite, AI, Extensions, Configuration library | All categories present; unsupported ones show a stub page naming the task that will fill them | ✅ | P-03 |
| UI-ST-04 | Proxy page: listeners table (Running, Interface, Invisible, Redirect, Certificate, TLS protocols, Support HTTP/2) with Add / Edit / Remove | Editing restarts only that listener | 🚧 missing: Invisible/Certificate/TLS columns are fixed text cells, not per-listener editable; no Edit dialog; BE-PX-02 gaps | P-03, B-08 |
| UI-ST-05 | Proxy page: CA import / export / regenerate | Three buttons with confirmation for regenerate | 🚧 missing: regenerate lacks a confirmation step | B-08, BE-TLS |
| UI-ST-06 | Proxy page: request interception rules table (Enabled, Operator, Match type, Relationship, Condition; Add/Edit/Remove/Up/Down) plus `Master interception is turned off` state | Rules evaluate in order with And/Or | ✅ | B-08, BE-IC |
| UI-ST-07 | Proxy page: response interception, WebSocket interception, response modification, match and replace, TLS pass-through, miscellaneous | All sections present | 🚧 missing: "response modification" and "miscellaneous" sections not found | B-08 |
| UI-ST-08 | Intruder, Repeater, Sequencer, Comparer pages (defaults documented in `settings/tools`) | Each page edits the defaults the tool reads | ✅ | P-03 |
| UI-ST-09 | Import / export settings, per-setting reset, restore defaults, configuration library | JSON in Burp's user/project option shape | 🚧 missing: Configuration library ("not available in WebProbe yet", :167-170) | J-03 |
| UI-ST-10 | Network page: upstream proxy, SOCKS, connections, TLS, hostname resolution, out-of-scope behaviour | Per-host upstream rules | 🚧 missing: SOCKS, hostname resolution, TLS, per-host upstream rules pages | B-08 |

## 4. Shared message editor and Inspector (used by every tool)

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-ME-01 | Views: Pretty, Raw, Hex (all), Render (responses); optional Params/Headers/Cookies tabs | Switching keeps scroll and selection | ✅ | B-02, B-03, E-01 |
| UI-ME-02 | Pretty printing for JSON, XML, HTML | Reformat on view, never alters the sent bytes | 🚧 missing: XML and HTML pretty-printing | B-03 |
| UI-ME-03 | Toolbar toggles: hide non-printing characters, word wrap, show `\n`, menu | Four icon buttons | ✅ | B-02 |
| UI-ME-04 | Line numbers, syntax highlighting, font size | Gutter, token colours, size control | ✅ | B-02 |
| UI-ME-05 | Search bar with next/previous and highlight count, case and regex options | `0 highlights` readout | 🚧 missing: regex option in the editor search bar | B-02, E-06 |
| UI-ME-06 | Layout toggle: horizontal, vertical, combined (tabbed) request/response | Three icons; choice remembered per tool | ❌ missing: horizontal/vertical/combined layout toggle, remembered per tool | P-04 |
| UI-ME-07 | Edit in place where the tool allows (Repeater, intercept, Intruder) and read-only elsewhere | History pane shows read-only badge or edits when asked | ✅ (per task evidence; code not re-read) | B-02 |
| UI-ME-08 | Inspector side panel: request attributes, query parameters, body parameters, cookies, headers, decoded values; add/remove/reorder; edits re-encode | Dock left or right, expand/collapse all | ✅ | P-04, E-01 |
| UI-ME-09 | Side docks: Inspector, Notes, Explanations (⛔ AI), Custom actions (⛔ scripts) | Inspector + Notes only | ✅ | P-04 |
| UI-ME-10 | Protocol toggle per request (HTTP/1.1 ↔ HTTP/2) with equivalent request generation | Inspector control | ❌ missing: per-request HTTP/1.1↔HTTP/2 toggle | P-04, BE-H2 |
| UI-ME-11 | Context menu on any message: send to Repeater / Intruder / Comparer / Decoder / Organizer, copy URL, copy as curl, scan, request in browser, show response in browser, generate CSRF PoC | Menu identical across tools | ✅ | B-04, E-03 |
| UI-ME-12 | Quick find hotkeys and text editor hotkeys | Documented in the Help menu | 🚧 missing: documented quick-find and text-editor hotkey sets | E-06 |

## 5. Shared tables, filters and annotations

| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-TB-01 | Sortable columns with arrow, resizable, reorderable, column chooser | Persisted per table | 🚧 missing: column drag-to-reorder | B-01 |
| UI-TB-02 | Copy column data / copy row | Context menu | 🚧 missing: "copy column data" context-menu item on headers (not found) | B-04 |
| UI-TB-03 | Filter bar summarising active filters (`Filter settings: Hiding CSS, image and general binary content`) opens a dialog | Settings mode: request type (in-scope, with response, parameterized), MIME groups (HTML, script, XML, CSS, other text, images, flash, other binary), status groups 2xx/3xx/4xx/5xx, search term with Regex / Case sensitive / Negative, file extension show/hide, annotation, listener port; buttons Show all / Hide all / Revert / Apply | 🚧 missing: request-type subfilters (with response, parameterized), negative search, annotation and listener-port filters | B-01, P-05 |
| UI-TB-04 | Annotations: highlight colour and notes per item | Right-click > Highlight / Add comment; columns `Notes`, colour rows | ✅ | B-07, L-04 |
| UI-TB-05 | Multi-select with Shift/Ctrl and bulk actions | Bulk send, delete, annotate | ✅ | B-07 |
| UI-TB-06 | Row count `N of M` visible | Orange when filtered | ✅ | B-01 |
| UI-TB-07 | Virtualized rendering for ≥10k rows | 60 fps scroll on 100k rows | ✅ | N-02 |
| UI-TB-08 | Script-based custom columns and filters | ⛔ until the extension host (K) exists | ⛔ | K-02 |

## 6. Tools

### 6.1 Dashboard
| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-DB-01 | Task list of cards (live audit, live passive crawl, scans, Intruder attacks) with name, state, capture toggle, issue counters (critical/high/medium/low-info) | Cards update live; rename; filter and search | 🚧 missing: per-card capture toggle, rename, filter/search of cards | P-09, D-05 |
| UI-DB-02 | `New scan`, `New live task`, pause/resume all, settings, help | Wizard for scans | 🚧 missing: settings/help buttons on the Dashboard; multi-step scan wizard | D-04, D-05 |
| UI-DB-03 | Task detail: Summary, Audit items, Issues, Event log, Logger, Audit log, Live crawl view | Tabs per task | 🚧 missing: "Live crawl view" tab | D-06 |
| UI-DB-04 | Banner `Task execution is paused` with Resume | Shown in Dashboard and Target | ✅ | D-05 |
| UI-DB-05 | First-run onboarding checklist | Derived from live state | ✅ (WebProbe addition) | M-07 |

### 6.2 Target
| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-TG-01 | Sub-tabs `Site map`, `Scope`, `Issues` | Present | ✅ | B-06 |
| UI-TG-02 | Site map: URL view tree (domain, directory, file, parameterized request) and Crawl paths view; right pane lists contents and shows the selected request/response and issues | Expand/collapse, filter, annotate | 🚧 missing: Crawl paths view | B-06, D-01 |
| UI-TG-03 | Scope tab: include and exclude tables with protocol, host, port, file; advanced scope control; `Use advanced scope control` | Rules apply to proxy filter, scanner and history `in scope` | 🚧 missing: protocol/host/port/file columns, advanced scope control | B-06 |
| UI-TG-04 | Issues tab: issue list with severity/confidence, advisory pane, definitions | Sort by severity | ✅ | D-06 |
| UI-TG-05 | Empty state `Site map URL view is empty` with `Learn more` | Text and action | ✅ | B-06 |

### 6.3 Proxy
| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-PX-01 | Sub-tabs `Intercept`, `HTTP history`, `WebSockets history`, `Match and replace`, `Proxy settings` | Match and replace is its own sub-tab | ✅ | B-08 |
| UI-PX-02 | Intercept bar: on/off toggle, `Forward` and `Drop` split buttons with `Forward all` / `Drop all`, `Open browser`, help, overflow | Hotkeys Ctrl+F forward; selected messages | ✅ | P-06, B-07 |
| UI-PX-03 | Intercepted messages table (multi-select), `Edit target`, message editor with Pretty/Raw/Hex | Release a selection at once | 🚧 missing: "Edit target" control not found | B-07 |
| UI-PX-04 | Empty state `Intercept is off` with explanation and `Learn more` / `Open browser` | Text and buttons | ✅ | P-06 |
| UI-PX-05 | HTTP history columns: # Host Method URL Params Edited Status code Length MIME type Extension Title Notes TLS IP Cookies Time Listener port Start response timer End response timer | All 19 selectable, 11 default | 🚧 missing: Start/End response timer columns (17 of Burp's 19 present + Diff count) | P-05 |
| UI-PX-06 | Message pane under the table with Request/Response and Pretty/Raw/Hex/Render | Resizable split, remembered | ✅ (per task evidence; code not re-read) | B-03, B-05 |
| UI-PX-07 | WebSockets history with the same table/filter/message model | Frames with direction and opcode | 🚧 missing: GUI editing of a held frame not exercised; fragmented message reassembly (B-09 notes) | B-09 |
| UI-PX-08 | Match and replace rules table: request/response/WebSocket, type (header, body, request line, param name/value), regex, comment; import/export; test | Rules applied in order | 🚧 missing: WebSocket scope, import/export, rule test/preview | B-08 |
| UI-PX-09 | Context menu on history rows | See UI-ME-11 | ✅ | B-04 |

### 6.4 Intruder
| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-IN-01 | Attack tabs (numbered), rename, close, `+`; empty state `To get started, send a request to Intruder from anywhere in Burp` | Tabs persist in project | 🚧 missing: numbered attack tabs with rename/close/+ persisting in project | P-10, C-06 |
| UI-IN-02 | Positions: request editor with `§` markers highlighted, `Add §`, `Clear §`, `Auto §`, attack-type dropdown (Sniper, Battering ram, Pitchfork, Cluster bomb), request count | Engine exists (`intruder.rs`); UI not wired | ✅ (per task evidence; code not re-read) | P-10, C-02 |
| UI-IN-03 | Payloads: set number and type selector, per-type options, payload list editor with Paste / Load / Remove / Clear / Add, payload count, predefined lists, placeholders | One set per position for pitchfork/cluster | 🚧 missing: Load button, predefined payload lists, placeholders, per-type options for all types | C-03, C-04 |
| UI-IN-04 | Payload processing rules table (Add/Edit/Remove/Up/Down) and encoding options | Ordered pipeline preview | ❌ missing: processing rules table and encoding options UI | C-04 |
| UI-IN-05 | Settings: request headers, error handling (retries, pause), results capture, auto-pause on grep, grep-match, grep-extract, grep-payloads, redirects | Per-attack and defaults in Settings | 🚧 missing: auto-pause on grep, redirects option, grep editors in the dock (not found in Settings tab) | C-05, C-06 |
| UI-IN-06 | Resource pool selector with pool editor (max concurrent, delay, throttle) | Shared with scanner | ✅ | C-06 |
| UI-IN-07 | Results window: table with Request #, Payload(s), Status, Error, Timeout, Length, grep columns; sort, filter (capture and view filters), highlight, compare lengths, view request/response | Live updates, pause/resume, save attack | 🚧 missing: view/capture filters and row highlight in the results window | C-05, C-07 |
| UI-IN-08 | Workflow tools: Scan, Send to..., show response in browser, record issue, generate CSRF PoC | Right-click on results | 🚧 missing: Scan, show response in browser, record issue, CSRF PoC on result rows | C-07, L-01 |

### 6.5 Repeater
| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-RP-01 | Numbered tabs with close and `+`, rename, reorder, tab groups (create, edit, close) | Groups collapse | 🚧 missing: tab groups (create/edit/close) | P-04, E-04 |
| UI-RP-02 | Toolbar: `Send` (primary), per-tab settings, `Cancel`, back/forward history with dropdown, `Target: host` with edit pencil | Cancel aborts the in-flight request | ✅ | P-04 |
| UI-RP-03 | Request / Response / Inspector panes with layout toggles; Pretty/Raw/Hex and Render | See UI-ME | 🚧 missing: layout toggles (horizontal/vertical/combined) — same gap as UI-ME-06 | P-04, E-01 |
| UI-RP-04 | Response status line (`Ready`, status, length, time) and `Follow redirection` | Redirect chain viewable | ✅ (per task evidence; code not re-read) | E-02 |
| UI-RP-05 | Send group in sequence or in parallel (single-packet style) | Per-tab-group action | ❌ missing: send group in sequence/parallel (single-packet style) | E-04 |
| UI-RP-06 | Search bar under each pane with highlight count | See UI-ME-05 | ✅ (per task evidence; code not re-read) | E-06 |
| UI-RP-07 | WebSocket Repeater tab | ❌ out for now | ❌ missing: WebSocket Repeater tab | B-09 |

### 6.6 Sequencer, Decoder, Comparer
| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-SQ-01 | Tabs `Live capture`, `Manual load`, `Analysis options`; live capture table with progress, pause, copy tokens; analysis summary with overall result, effective entropy, reliability; per-test charts | Charts for character-level and bit-level tests | 🚧 missing: character-level chart (only bit-level chart found, analysis_ui.rs:109) | G-01..G-03 |
| UI-DC-01 | Decoder: input pane per stage, Text/Hex toggle, `Decode as`, `Encode as`, `Hash` dropdowns, `Smart decode`, each stage adds a new pane; clear and save | Chain editable | ✅ | P-07, F-01, F-02 |
| UI-CP-01 | Comparer: two item tables (`#`, `Length`, `Data`) with Paste / Load / Remove / Clear; `Compare Words` / `Bytes`; synchronized diff windows | Modes switchable, sync scroll | ✅ (per task evidence; code not re-read) | P-08, F-03 |

### 6.7 Logger, Organizer, Collaborator, Extensions
| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-LG-01 | Logger: capture filter bar (`Logger memory limit set to 100MB | Capturing requests up to 1MB...`), `Logging on` toggle, entries table with tool/source column, view filter, annotate, empty state | Captures every tool's traffic incl. extensions | 🚧 missing: annotate in Logger, tool/source column parity, view filter parity | L-04 |
| UI-OR-01 | Organizer: send items, statuses, notes, highlight, collections (create, move, copy, share, import), filter, export | Collections tree | 🚧 missing: statuses, highlight, collections tree, export | L-02 |
| UI-CB-01 | Collaborator: generate payloads (count, copy), poll now/auto, results table with time, type (DNS/HTTP/SMTP), payload, source; detail pane; export | Public or private server config | 🚧 missing: export of interactions | I-01..I-04 |
| UI-EX-01 | Extensions: sub-tabs `Installed`, `BApp Store`, `APIs`, `Custom scan checks`, `Bambda library`, `Extensions settings`; table Loaded, Type, Name, AI enabled, AI credits used, System impact, Auto-reload; Details / Output / Errors panes; Add / Remove / Up / Down; total system impact bar | Load, unload, reload | 🚧 missing: APIs / Custom scan checks / Bambda library sub-tabs (Bambdas unsupported — known fact), system impact bar | K-01..K-03 |

## 7. Projects
| ID | Requirement | Acceptance | Status | Tasks |
|---|---|---|---|---|
| UI-PJ-01 | Start screen: temporary project, new on disk, open existing; use defaults / load config file | Also reachable from the Project menu | 🚧 missing: "use defaults / load config file" choices on the start screen | J-04 |
| UI-PJ-02 | Save/restore full state, autosave, recovery after crash | Reopen restores tabs, history, settings | ✅ (per task evidence; code not re-read) | J-01, J-02 |

## 8. Non-functional UI requirements
- **Size**: layouts hold at 1440×900 and degrade gracefully down to 1100×700; no clipped or overlapping controls (checked by screenshot pairs).
- **Responsiveness**: input-to-paint under 50 ms with 100k history rows; network work never on the UI thread.
- **Accessibility**: all controls keyboard reachable, visible focus, contrast checked for all three palettes (M-06 done).
- **Glyphs**: every non-ASCII character printed is in the guard list (`theme.rs` test) so nothing renders as a box.
- **Verification method**: for each requirement, a screenshot of Burp (`/root/webprobe-shots/burp-tour/`) and of WebProbe
  (`qa/qa.sh shot`) at the same size, compared by a person or a vision model; behaviour checked by driving the window with
  `qa/qa.sh` on proxy 6566 (never 8080/8081).

## 9. Phasing
1. **Shell and settings** (P-01, P-02, P-03): menu bar, one tab row, Settings dialog with the Proxy page.
2. **Message editor and history** (B-02, B-03, P-05, P-04): Pretty/Render views, Inspector, layout toggles, 19 columns, Repeater layout.
3. **Intruder UI** (P-10 then C-03..C-07): attack tabs, payload sets, processing, results.
4. **Target and Dashboard** (B-06, P-09): site map tree, tasks and event log.
5. **Tools breadth** (F, G, L, I, K): Decoder pipeline, Comparer modes, Logger, Organizer, Collaborator, Extensions.
