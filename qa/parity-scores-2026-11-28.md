# Burp parity re-score, all 13 tabs — 2026-11-28

Replaces `qa/parity-scores-2026-11-15.md` (removed in the same commit). Task: R-19 / issue #258.
Baseline: `master` at `010fdfa` (`app/`, 33,971 lines of Rust, 13 top-level tabs).
Reference: Burp Suite Professional v2026.7.3 (build 52685). The reference behaviour used here is the
capture recorded in `docs/PRD-UI.md` (2026-11-15, derived from the live window and the 364 shipped
documentation pages), `qa/VISUAL-DIFF-2026-11-15.md` and `qa/SOURCE-PARITY-2026-11-15.md`.

## 1. Method and its limits — read this before quoting a number

What was done for this re-score:

- Read every tab's implementation in `app/src/` (entry points listed per tab below) and checked each
  Burp requirement in `docs/PRD-UI.md` against what the code actually renders and does.
- Cross-checked behaviour against the frozen-build UAT of 2026-11-16 (`qa/UAT-2026-11-16.md`,
  28 cases, 98 screenshots), which is the newest run of the real window in the repository.

What could **not** be done in this environment, and therefore what these scores are *not*:

| Requirement of #258 | Status here | Why |
|---|---|---|
| Drive WebProbe and record fresh screenshots | **Not done** | No Rust toolchain in the environment (`cargo`/`rustc` absent, `app/target/` absent), no Xvfb/xdotool, no `egui-mcp` endpoint. UAT-09 (accessibility tree + IPC socket for MCP) is still `in_progress`; `app/src/main.rs` exposes env hooks and `--screenshot` only. |
| Compare side by side with live Burp | **Not done** | Burp Pro is not installed here (`/opt/BurpSuite` absent). The reference is the already-recorded 2026-11-15 Burp capture. |
| Confirm Logger, Organizer, WebSocket intercept in the GUI | **Partly** | UAT case 1 proves all 13 tabs *render*; no UAT case exercises these three. Source behaviour is scored; interactive confirmation is listed as debt in §6. |

So these are **source-inspection re-scores** against a recorded live-Burp reference, at a named
commit. They are stronger than the 2026-11-15 numbers (which scored two screens that were then
rewritten) and weaker than a fresh live pass. Every category score below names the code it rests on.
Where a finding is a bug rather than a missing feature, it is already tracked by a UAT issue and is
linked, not re-filed.

## 2. Rubric

Same five categories as the previous file, 10 points each, 50 total. Applied uniformly to all 13 tabs:

| Category | Question |
|---|---|
| **Layout** | Does the pane structure, placement and density match the Burp tool at 1440×900? |
| **Key area** | The tool's defining work surface (history table, request editor, task rail, collections rail, …): is it present and does it do the job? |
| **Views/controls** | The per-tool controls Burp exposes (view toggles, sub-tabs, choosers, toolbars, context menus). |
| **Inspector/target** | The side/secondary surface: Inspector, target field, message viewer, detail or advisory pane. |
| **Clarity** | Empty states, labels, disabled-with-reason, no dead controls, readable density. |

## 3. Scores

| # | Tab | Layout | Key area | Views/controls | Inspector/target | Clarity | **Total** |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1 | Dashboard | 8 | 7 | 7 | 6 | 7 | **35/50** |
| 2 | Target | 8 | 7 | 7 | 7 | 7 | **36/50** |
| 3 | Proxy | 8 | 8 | 7 | 7 | 8 | **38/50** |
| 4 | Intruder | 7 | 8 | 5 | 6 | 6 | **32/50** |
| 5 | Repeater | 8 | 8 | 8 | 8 | 8 | **40/50** |
| 6 | Collaborator | 8 | 7 | 7 | 7 | 7 | **36/50** |
| 7 | Sequencer | 8 | 6 | 6 | 5 | 6 | **31/50** |
| 8 | Decoder | 8 | 7 | 7 | 6 | 8 | **36/50** |
| 9 | Comparer | 8 | 7 | 6 | 6 | 6 | **33/50** |
| 10 | Logger | 8 | 7 | 6 | 6 | 7 | **34/50** |
| 11 | Organizer | 7 | 5 | 6 | 6 | 6 | **30/50** |
| 12 | Extensions | 8 | 6 | 6 | 6 | 6 | **32/50** |
| 13 | Discover | 8 | 6 | 4 | 5 | 7 | **30/50** |

Mean **34.1/50 (68%)**. Spread 30–40. The low mean is in *views/controls* and *inspector* work, not
in layout: every tab now has the Burp-shaped shell. Clarity loses one point on the nine tabs whose
shared tables accept a header sort that does not reorder the rows (§5.0, #273).

### Deltas against the 2026-11-15 file

| Tab | 2026-11-15 | 2026-11-28 | Delta | Note |
|---|---:|---:|---:|---|
| Proxy HTTP history | 29 | 38 | **+9** | 5 sub-tabs, chooser, filter/sort cache, message pane views, grounded context menu |
| Repeater | 30 | 40 | **+10** | three-pane + Inspector + side dock, tabs with close/add, Cancel, history pager, target editor, status line |
| Intruder | 35 | 32 | **−3** | not a regression in code: the 2026-11-15 score credited positions/sets and results while the same rubric applied to Burp's ten payload types, processing rules, grep columns and attack tabs gives 32. See §5.4. |
| Dashboard | 17 | 35 | **+18** | tasks rail, three task cards with pause/resume, issue pills, six task sub-tabs, New scan, task config/progress/log |

The 2026-11-15 file scored four screens on a looser reading and explicitly said the other nine were
unscored. Treat deltas as indicative; the absolute 2026-11-28 numbers are the ones to use.

## 4. What was never checked before, and is now scored

#258 calls out three areas that had no evidence at all. Their evidence, and what is still unverified:

| Area | Code inspected | Scored in |
|---|---|---|
| Logger | `app/src/ui.rs:3657` `logger_view`, `app/src/logger.rs` | §5.10 |
| Organizer | `app/src/ui.rs:3762` `organizer_view`, `app/src/organizer.rs` | §5.11 |
| WebSocket intercept | `app/src/net.rs:1672` `intercept_ws_stream`, `:1831` `relay_ws_tls`, `app/src/ui.rs:980` options, `app/src/ui.rs:2412` intercept pane, `app/src/tools.rs:530` history | §5.3 |

Two claims in the repository are now stale and are contradicted by the code (filed in #269):

- `app/src/tools.rs:533` tells the user "TLS handshakes are recorded; encrypted frame relay is not
  supported yet", but `relay_ws_tls` (`app/src/net.rs:1831`) intercepts TLS WebSocket frames in both
  directions.
- `app/src/net.rs:1773` carries the same stale comment above `handle_websocket`.

## 5. Per-tab findings

Each entry: **verified** (what the code does), **gaps** (what Burp does that WebProbe does not).

### 5.0 Cross-cutting: the shared table's sort control is dead outside two tables — see #273
`table::table_body` (`app/src/table.rs:157`) draws Burp's header, including a click target that
toggles `TableState::sort_col` / `sort_asc` and paints an arrow (`app/src/table.rs:221`–`:243`), and a
right-click column menu. Only two callers then reorder their rows with `table::sort_rows`:
`history_view` (`app/src/ui.rs:529`, Proxy HTTP history) and the Scanner issue table
(`app/src/ui.rs:1262`). The other nine callers pass fixed order: Dashboard > Audit items, Target >
Site map contents, Intruder results, Logger, Organizer, Collaborator interactions, Sequencer request
list, Extensions, and both Comparer item lists. Clicking a column header there visibly sets an arrow
and changes nothing — a control that appears to work and does not, which the PRD forbids. Clarity is
capped at 7 on those tabs for this reason; the fix is one `sort_rows` call per table.

### 5.1 Dashboard — 35/50
Code: `app/src/ui.rs:2743` `dashboard`, `:3040` `dashboard_summary`.
Verified: "Task execution is paused" band with Resume; Tasks rail (New scan, New live task, filter,
search, per-card pause/resume menu); three task cards with severity pills; six sub-tabs (Summary,
Audit items, Issues, Event log, Logger, Audit log); Summary shows "Most serious vulnerabilities
found", Task configuration, Task progress, Task log; New scan dialog (crawl-and-audit or audit
selected URLs). UAT case 22 passed.
Gaps: the three cards are fixed pseudo-tasks, not a list of real scans (no per-scan card, rename or
delete, no task history); "New live task" only resumes the predefined live audit; Audit items shows
history rows rather than items belonging to the selected task; Issues reuses the Scanner view, so
there is no per-task issue list with advisory; no Live crawl view; scan wizard does not expose D-04
crawl/audit/insertion/speed settings.

### 5.2 Target — 36/50
Code: `app/src/ui.rs:3202` `target`.
Verified: `Site map | Scope | Issues` sub-tabs; URL view tree with expand/collapse, folder/file glyphs,
requested (ink) vs unrequested (grey) nodes; Crawl paths view; contents table (Host, Method, URL,
Params, Status code, Length, MIME type, Title); request/response message panes; empty state with
Learn more / Open browser. UAT case 21 passed after traffic.
Gaps: no tree filter or annotation, no parameterised-request nodes, no scope colouring on the tree,
no context menu on tree/contents; Scope is a simple pattern list, not Burp's include/exclude tables
with protocol/host/port/file and advanced scope; Issues has no advisory/definition pane; tree and
table are not splitter-resizable.

### 5.3 Proxy — 38/50
Code: `app/src/ui.rs:2376` `proxy`, `:2412` `proxy_intercept`, `:559` `proxy_history`, `:956`
`proxy_options`, `:1024` match-and-replace, `app/src/tools.rs:530` WebSocket history.
Verified: five sub-tabs (`Intercept | HTTP history | WebSockets history | Match and replace | Proxy
settings`), the last opening the Settings pane; intercept toggle, Forward, Drop, Open browser, held
message peeked not consumed; history with 17 of Burp's 19 columns (all but Start/End response
timer) plus a Diff count column, column chooser, filter bar (text/regex/method/status/MIME/in-scope), sortable columns,
`N of M` counter, keyboard row movement, grounded right-click menu, message pane with
Pretty/Raw/Hex/Render, wrap/non-printable toggles and search; Match and replace as its own sub-tab;
listeners table with restart; CA export; upstream options. WebSocket interception works for plain
**and** TLS upgrades in both directions (`intercept_ws_stream`, `relay_ws_tls`), frames are rebuilt
with correct masking and 7/16/64-bit lengths (unit-tested at `app/src/net.rs:3170`, `:3187`).
Gaps: one held message at a time and no multi-select/`Forward all`/`Drop all` split buttons; no
`Edit target` in the intercept pane; held WebSocket frames land in the HTTP queue with no direction
or opcode and lossy UTF-8 payloads (#268); WebSockets history is a plain grid with no filter, sort,
column chooser or handshake viewer, and its TLS hint is stale (#269); no start/end response timers;
Notes column exists but has no backend; annotations/highlight not wired.

### 5.4 Intruder — 32/50
Code: `app/src/ui.rs:1343` `intruder`, `app/src/intruder.rs`.
Verified: Burp empty state; attack-type selector (Sniper / Battering ram / Pitchfork / Cluster bomb)
wired to `intruder.rs`; Auto/Clear/Add § with selection-based marker; one payload set per position;
per-set Paste/Load/Remove/Clear/Deduplicate/Add and simple-list editor; payload count and request
count with limit error; target field + "Update Host header"; Payloads / Resource pool / Settings
dock; results window with request #, payload, status, time, error, length and request/response
panes; Start/Stop. UAT cases 12–13 passed.
Gaps: no attack tabs (rename/close/duplicate), one payload type only (Burp has ten), no payload
processing rules table, no grep-match/extract/payloads columns, results cannot be sorted/filtered or
saved/exported, no per-attack settings (retries, redirects, auto-pause), resource pool is a fixed
50 ms single pool, no results context menu (scan, send-to, CSRF). The results overlay also ignores
clicks (UAT-01, open).
Why the delta is negative: the earlier rubric rewarded the dense single-column screen for having
positions/sets and a results table; measured against Burp's actual breadth of that area (types,
processing, grep, saved attacks) 5/10 is the honest views/controls score.

### 5.5 Repeater — 40/50
Code: `app/src/ui.rs:1713` `repeater`, `:1955` `repeater_send`, `app/src/msgpane.rs:257`.
Verified: numbered tabs with close and `+`; Send (Ctrl+Space), settings menu (Update Content-Length),
Cancel, back/forward request pager with per-tab history, `Target:` with edit pencil and target
dialog; Request | Response | Inspector panes plus vertical dock and Notes; editable request with
Pretty/Raw/Hex, search with highlight count, wrap and non-printable toggles; response
Pretty/Raw/Hex/Render; status line `Ready`/`Waiting` + bytes and milliseconds. UAT case 10 passed.
Gaps: no rename/reorder/tab groups, no side-by-side/stacked/tabbed layout toggles, no follow
redirects, no send-group in sequence/parallel, no WebSocket Repeater. Cancel does not abort the
in-flight request (UAT-02, open) — a behaviour defect inside an otherwise strong layout.

### 5.6 Collaborator — 36/50
Code: `app/src/collaborator_ui.rs:70` `show`, `settings_panel`.
Verified: onboarding with Get started/Learn more; client bar with Copy to clipboard (generates and
copies a payload), "Include Collaborator server location", Poll now, gear and server label;
interactions table (#, Time, Type, Payload, Source IP address, Comment); detail tabs Description /
Request to Collaborator / Response from Collaborator with HTTP headers/body, DNS query/answer and
SMTP conversation; settings panel for a public interactsh server and loopback HTTP/DNS listeners
with start/stop, bound address and last error; generated payload list with HTTP/DNS copy.
Gaps: no batch payload generation/count, no export, no delete/prune interactions, Comment column is
read-only, no explicit polling interval control in the UI (fixed 3 s), loopback listeners are
local-only by design (documented in-panel).

### 5.7 Sequencer — 31/50
Code: `app/src/tools.rs:165` `sequencer`, `app/src/analysis_ui.rs:41` `show_sequencer_report`.
Verified: `Live capture | Manual load | Sequencer settings`; request list with Remove/Clear;
Cookie / Form field / Custom regex token location with Configure; Start/Stop live capture (20,000
cap, gives up after 20 consecutive misses, ignore-abnormal option), Analyze now; summary stats
(samples, unique tokens, total characters, bits/char, effective alphabet, chi-square, numeric
min/max/mean/std dev).
Gaps: no per-test charts or character-level/bit-level test table, no Burp-style overall reliability
rating ("Excellent"/"Poor"), no token table with copy, no progress/pause during capture, no
save/load of sample sets, no FIPS 140-2 test suite.

### 5.8 Decoder — 36/50
Code: `app/src/ui.rs:2035` `decoder`, `app/src/decoder_ops.rs`.
Verified: stage stack with a new pane per operation; Text/Hex radio per stage; `Decode as ...`
(URL, HTML, Base64, ASCII hex, hex), `Encode as ...` (same set), `Hash ...` (MD5, SHA-1, SHA-256,
SHA-512), Smart decode; selecting an operation truncates lower stages and appends its result. UAT
cases 15–16 passed (Base64, SHA-256 exact match).
Gaps: Hex mode is display-only (cannot edit hex input), no clear-chain control, no save/send-to
Comparer, error output replaces the stage text rather than being shown separately.

### 5.9 Comparer — 33/50
Code: `app/src/ui.rs:3416` `comparer`, `app/src/analysis_ui.rs`.
Verified: the Burp shape — `Select item 1:` / `Select item 2:` tables (#, Length, Data), Paste /
Load / Remove / Clear stack, `Compare ... Words / Bytes`, comparison window with key legend and
both sides rendered row-aligned, colour-coded added/removed/changed lines. UAT case 20 passed (diff
window opens and closes).
Gaps: one shared `cmp_items` collection backs both tables, so a loaded item appears in both sides
(UAT-03, open) and Paste adds nothing (UAT-03); no merge, export, three-way compare or sync scroll
in the window; no per-side item lists.

### 5.10 Logger — 34/50
Code: `app/src/ui.rs:3657` `logger_view`, `app/src/logger.rs`.
Verified: capture-filter bar with "Logger memory limit set to N entries | Capturing requests and
responses in full", search box, Logging on toggle and Clear; 9-column table (#, Time, Tool, Method,
Host, Path, Status code, Length, MIME type) over the bounded newest-first store; Request/Response
message panes for the selected row; explicit empty state naming the tool's purpose.
Gaps: `LogQuery` supports `tool`, `status_class` and `mime` (`app/src/logger.rs:56`) but the UI only
uses free text, so three of four filters are unreachable (#270); no annotate/highlight/notes, no
export, no capture-filter dialog and no per-tool/per-status view filters; the log is memory-only and
does not survive a restart. The shared header offers sort and a column menu, but the rows are always
newest-first: `sort_rows` is never applied here (§5.0, #273).

### 5.11 Organizer — 30/50
Code: `app/src/ui.rs:3762` `organizer_view`, `app/src/organizer.rs`.
Verified: Collections rail with header, New, search and `Inbox (N)`; contents table (#, Time, Item,
Notes); notes editor that writes through; Delete; Request/Response panes; empty state with the
Ctrl+O instruction.
Gaps: the model is a flat item list (`app/src/organizer.rs:17`) — no collections, statuses or
highlight, so the "Collections"/"Inbox" rail advertises structure that does not exist; no
create/move/copy/share/import collection, no export, no status filter, no rename UI despite
`Organizer::rename` existing (#271). This is the lowest-scoring tab because its *key area*, the
collection tree, is the one thing Burp uses the tool for.

### 5.12 Extensions — 32/50
Code: `app/src/tools.rs:976` `extensions`, `app/src/ext_host.rs`.
Verified: six sub-tabs (Installed, BApp Store, APIs, Custom scan checks, Bambda library, Settings);
total system-impact line; Installed table (Loaded, Type, Name, Hooks) with per-row enable toggle and
Add/Remove/Up/Down; Details/Output/Errors panes; Add dialog loads a real Montoya `.jar` through the
sidecar JVM; BApp Store is an offline, informational catalogue of known jars (load them via
Installed > Add) rather than a fake download store.
Gaps: no auto-reload, no AI-enabled/credits columns (AI is a stated non-goal), APIs / Custom scan
checks / Bambda library are informational stubs, no extension dependency view, no per-extension
system-impact estimate beyond None/Low.

### 5.13 Discover — 30/50
Code: `app/src/ui.rs:2710` `discover`.
Verified: hero and three learning cards (Documentation, Keyboard shortcuts, Command palette) plus
the first-run onboarding checklist — the intended replacement for Burp's marketing Discover tab,
which the PRD marks as a non-goal.
Gaps: the three cards are plain labels and do nothing (#272); no documentation index or in-app help;
the tab therefore does not yet deliver the "Help menu with documentation links" the PRD promises.
Parity with Burp's Discover is deliberately not pursued; this score measures the replacement.

## 6. Live verification debt (what still needs a GUI pass)

These items are scored from source and must be confirmed by driving the window when a toolchain and
Burp reference are available. None of them blocks the scores above; each is a smaller surface.

1. Proxy > WebSockets history and intercept with a real plain and TLS WebSocket under traffic
   (frame ordering, masking, Forward/Drop, direction label after #268).
2. Logger capture across tools (Proxy, Repeater, Scanner, Intruder) and its memory cap.
3. Organizer send-to/notes/delete round trip and persistence.
4. Intruder results overlay input and Cancel (UAT-01/UAT-02 are open; treat their scores as
   conditional on the bugs).
5. Comparer per-side items and Paste (UAT-03).
6. Side-by-side visual pass at 1440×900 and 1100×700 for the five re-scored tabs (Dashboard, Target,
   Proxy, Repeater, Decoder) since the 2026-11-15 captures.

## 7. Gaps filed from this re-score

| Issue | Gap | Tab |
|---|---|---|
| #268 | Held WebSocket frames are indistinguishable from HTTP messages (no direction/opcode/URL, lossy payload) | Proxy |
| #269 | WebSockets history is a read-only Grid with no filter/sort/message pane; stale TLS hint | Proxy |
| #270 | Logger exposes only text search although the engine has tool/status/MIME filters; no annotations/export | Logger |
| #271 | Organizer Collections rail is Inbox-only; no collections/status/highlight/export | Organizer |
| #272 | Discover cards are inert labels | Discover |
| #273 | Shared table header sort is dead outside Proxy history and Scanner (9 tables) | Dashboard, Target, Intruder, Comparer, Collaborator, Sequencer, Logger, Organizer, Extensions |

Already tracked, not re-filed: UAT-01 (Intruder results overlay), UAT-02 (Repeater Cancel),
UAT-03 (Comparer shared collection and Paste), UAT-04 (history/site map persistence), #253 (Bambda
filters/custom columns for History, Logger and WebSocket tables), #240 (Repeater/Intruder byte
fidelity).

## 8. Reproducing a live re-score

```bash
# WebProbe, on a private display (needs a built binary and Xvfb; neither exists in this environment)
qa/qa.sh up WEBPROBE_TAB=logger WEBPROBE_SEED_HISTORY=200
qa/qa.sh shot logger-2026-11-28
qa/qa.sh up WEBPROBE_TAB=organizer
qa/qa.sh shot organizer-2026-11-28
qa/qa.sh up WEBPROBE_TAB=proxy WEBPROBE_PROXY_SUB=2
qa/qa.sh shot ws-history-2026-11-28
```

Burp reference captures for the same states live outside the repository (the 2026-11-15 run used
`/root/webprobe-shots/burp-tour/`). A future re-score should pair each `qa.sh shot` with the Burp
capture at the same window size and record the pairing here.
