# Visual diff — WebProbe vs Burp Suite Pro (2026-11-15, v8 pass)

Reference: Burp Suite Professional v2026.7.3 (live, Xvfb `:98`, 1440x900).
Subject: WebProbe `app/` debug build on Xvfb `:97`, 1440x900, QA proxy `:6566`, collaborator `:6567`.
Shots: Burp `/root/webprobe-shots/burp-tour/`, WebProbe `/root/webprobe-shots/cmp/v8-*.png`.

## 1. Method

- Both windows captured at 1440x900, full window, no scaling, same font scale (13.0 pt in the message editors).
- Objective comparison: craft-anything MCP `web_pixels_compare` with `common_area: true`, `tolerance: 16`, via
  `/tmp/mcp_list.py` over the `investigation.cany` project. Pairs JSON: `/tmp/pairs-v8.json`.
- Manual read: every v8 shot and its Burp counterpart inspected with the image reader; the table below records what
  is actually drawn, not what the code intends.
- Chrome landmarks after the menu-bar pass: menu row `y≈13`, tab row `y≈44`, Proxy action buttons `y≈245`.

**Metric caveat (important).** Burp's reference window is light-themed (white fills); WebProbe is dark
(`MONO1 0x2B2B2B`). Every frame therefore differs on ~99% of pixels regardless of layout, and
`layout_similarity` collapses to 0.0 because edge polarity inverts. The MCP numbers are reported faithfully but they
measure the palette gap, not the layout fixes. Layout evidence in this pass is the manual read plus the text-extent
measure in §3.

| Screen | Before (burp vs `wp-*`) diff / layout / perceptual | After (burp vs `v8-*`) diff / layout / perceptual |
|---|---|---|
| Dashboard | 0.9892 / 0.0000 / 0.2542 | 0.9891 / 0.0000 / 0.2519 |
| Proxy | 0.9933 / 0.0000 / 0.2290 | 0.9934 / 0.0000 / 0.2339 |
| Intruder | 0.9936 / 0.0000 / 0.2865 | 0.9935 / 0.0000 / 0.2705 |
| Repeater | 0.9925 / 0.0000 / 0.2933 | 0.9924 / 0.0000 / 0.2768 |

`difference_fraction` (0 = identical), `layout_similarity` (1 = identical structure), `perceptual_similarity` (1 = identical).

## 2. Screen-by-screen diff (all 13 WebProbe tabs)

Global chrome is shared by all 13 rows, so it is stated once:

- **Menu row** — WebProbe: `WebProbe | Project | Intruder | Repeater | View | Help` (y≈13). Burp: `Burp | Project | Intruder | Repeater | View | Help`. Same six slots; first label is branded `WebProbe`; item lists differ (see §4, gap 8). Burp also draws a centred licence title and min/max/close on this row; WebProbe does not.
- **Tab row** — WebProbe (y≈44): `Dashboard Target Proxy Intruder Repeater Collaborator Sequencer Decoder Comparer Scanner Sessions Search Extensions` (13, orange underline on active). Burp: `Dashboard Target Proxy Intruder Repeater Collaborator Sequencer Decoder Comparer Logger Organizer Extensions Discover` (13). Positions 10–12 and 13 differ (see table).
- **Theme** — Burp light; WebProbe dark. WebProbe panel fills are hardcoded `MONO1`/`MONO1X` in `ui.rs`, `table.rs`, `feedback.rs`, `shortcuts.rs`, so `View > Light theme` is incomplete and default stays dark.
- **Right-side globals** — Burp: globe, terminal (Burp AI), proxy, search, gear, `Burp AT` pill. WebProbe: `intercept off`, `127.0.0.1:6566`, `Settings` button. Burp bottom bar: `Event log | All issues | Memory…`; WebProbe: listener dot, intercept, held, history, messages, last request.

| # | WebProbe tab | Burp counterpart | Sub-tabs | Toolbar buttons | Panes | Table columns |
|---|---|---|---|---|---|---|
| 1 | Dashboard | Dashboard | none (Burp: Summary / Audit items / Issues / Event log / Logger / Audit log) | Send sample traffic, Copy/Export CA certificate, Pause live audit | setup checklist, Overview stat cards, Tasks cards, Issues-by-severity | n/a (Burp: issue type / host / time table) |
| 2 | Target | Target | none (Burp: Site map / Scope / Issues; URL view / Crawl paths view) | Add to scope, + scope rule, Filter, Columns | `Target scope` box (repeats inner `Scope`), host chip list, flat table | Host, Method, Path (Burp site-map tree + detail columns) |
| 3 | Proxy | Proxy | Intercept / HTTP history / WebSockets history / Proxy settings (Burp inserts **Match and replace** before Proxy settings) | Intercept bar, Columns, Send to Repeater, Send to Intruder, Clear history; Filter row (Method/Status/MIME/regex/in-scope) | history table + message pane | #, Method, Host, URL, Status, Length, MIME, Extension, Title, TLS, Cookies (Cookies clipped at right edge; Burp has Params/Edited, no horizontal scroll) |
| 4 | Intruder | Intruder | none (Burp: Positions / Payloads / Options) | Sniper / Battering ram / Pitchfork / Cluster bomb, Auto §, Clear §, Start attack, HTTPS, Clear results | Request-with-positions (left), To get started (right), Payload set 1 (bottom) | n/a |
| 5 | Repeater | Repeater | per-pane Pretty / Raw / Hex | numbered tab + `+` + close, Send (Ctrl+Space), Cancel, Target field, HTTPS; wrap/hex/lines/find/Aa | Request \| Response \| Inspector (3 panes) | n/a |
| 6 | Collaborator | Collaborator | none (Burp: single onboarding screen + server config) | Start HTTP, Start DNS, Generate payload | HTTP listener, DNS listener, Generated payloads, Interactions (0/500) | n/a (Burp: interactions table) |
| 7 | Sequencer | Sequencer | none (Burp: Live capture / Manual load / Sequencer settings) | response header / cookie / body regex, Capture stored response, Capture live, Analyze, Clear, Add lines | token-location row, samples editor | n/a (Burp: select-request table # / Host / Request) |
| 8 | Decoder | Decoder | Text \| Hex input toggle | choose, Decode as, Encode as, Hash, Smart decode, Copy, Use output as input | Input editor, Output pane (chained) | n/a |
| 9 | Comparer | Comparer | none | Selected request/response → A/B, Compare, Clear | A/B side-by-side text areas | none (Burp: two item tables # / Length / Data + Paste/Load/Remove/Clear + Words/Bytes) |
| 10 | Scanner | none (Burp folds scanning into Dashboard live audit + context menus; Burp's slot 10 is **Logger**) | none | Run active scan, live passive scan toggle, Clear issues, Columns | issue table + empty state | Severity, Issue, Host, Path |
| 11 | Sessions | none (Burp: Project options > Sessions; Burp's slot 11 is **Organizer**) | none | + session rule, Save macro | session rules, Macros editor | n/a |
| 12 | Search | none (Burp: Burp menu > Search; Burp's slot 12 is Organizer/Extensions area) | none | Search all tools, case sensitive | query row, results area | none (results list only) |
| 13 | Extensions | Extensions | none (Burp: Installed / BApp Store / APIs / Custom scan checks / Bambdas / Extensions settings) | none (static explanation) | explanatory text only | none (Burp: Loaded / Type / Name / AI enabled / AI credits used / System impact / Auto-rel; Details/Output/Errors) |

## 3. Bridged this pass

**a. Repeater/Intruder one-character-per-line (root cause fixed).**
Cause: each of the five pane bodies inherited the parent's horizontal `Ui`, so every `label`/`TextEdit` was laid out
left-to-right as a sibling. Fix: each pane body is wrapped in `ui.vertical(|ui| { … })` and the duplicated
`set_min_width`/`set_max_width` pair became `ui.set_width(...)` (`app/src/ui.rs`). `message_editor` now uses
`.desired_width(ui.available_width().max(120.0))` instead of `f32::INFINITY` (`app/src/editor.rs`).
Verified in `v8-repeater.png`: request text is horizontal, three panes (Request \| Response \| Inspector) are visible,
Inspector lists request line, request headers and response headers. The request line alone spans 268 px and the
editor fills the pane; the pre-fix build collapsed to a single glyph column per row. Intruder is horizontal with two
columns plus a payload-set pane (`v8-intruder.png`).

**b. Menu bar added.** New 26 px `menu_bar` panel above `main_bar`; menu row y≈13, tab row y≈44, Proxy action
buttons moved to y≈245. All six menus open and list the specified items: WebProbe (Settings…, Quit), Project
(Project options…), Intruder (Send to Intruder), Repeater (Send to Repeater, Send request), View (13 tabs + Light
theme checkbox, unchecked), Help (Keyboard shortcuts, About WebProbe).

**c. Proxy sub-tab names.** `Intercept | HTTP history | WebSockets history | Proxy settings` — Burp's wording for the
four tabs WebProbe implements (Burp additionally has `Match and replace`).

**d. Measured before/after.** The MCP whole-frame numbers are in §1: Repeater 0.9925→0.9924 diff,
0.2933→0.2768 perceptual; Dashboard 0.9892→0.9891, 0.2542→0.2519. They do not move because the reference is
light-themed; they are recorded as the requested objective baseline, not as evidence of the layout fix. The layout
fix is evidenced by the manual read and the 268 px request-line extent above.

## 4. Still open (ranked)

1. **Light palette incomplete.** `View > Light theme` exists but panel fills are hardcoded `MONO1`/`MONO1X`
   (`ui.rs` ~12 sites, `table.rs:171`, `feedback.rs:86`, `shortcuts.rs:727,847`), so switching yields dark panels
   with light widgets. Default deliberately stays dark.
2. **Three Burp tools missing.** Burp has **Logger**, **Organizer** and **Discover**; WebProbe substitutes
   **Scanner**, **Sessions** and **Search** in those slots. No log capture, collection/inbox, or Discover surface.
3. **Proxy has no Match and replace.** Burp's fourth sub-tab (between WebSockets history and Proxy settings) is absent.
4. **Dashboard has no sub-tabs.** Burp: Summary / Audit items / Issues / Event log / Logger / Audit log, plus a
   task-configuration / progress / task-log rail and a `Task execution is paused` banner. WebProbe is one scrolling page.
5. **Intruder has no Positions / Payloads / Options sub-tabs.** It is a single page with attack-type radios, one
   request pane and one payload set. `Auto §` itself works — verified: it produced
   `GET /login?user=§admin§&pw=§test§ HTTP/1.1` with `2 position(s), 1 payload set(s), 6 request(s)`.
6. **HTTP history columns.** Missing `Params` and `Edited`; the trailing `Cookies` column is clipped at the right
   edge and there is no horizontal scroll, so later columns are unreachable. Host:port is packed into `Host`.
7. **Repeater dock and history.** No back/forward history, no `Target: Not specified` + edit action, no right
   vertical dock (Inspector / Notes / Explanations / Custom actions), no line numbers, no per-pane status line.
8. **Burp menu items incomplete.** Burp lists Search, Settings, Configuration library, User settings >, Log in,
   Burp Infiltrator, Burp Clickbandit, Exit. WebProbe lists Settings… and Quit only.
9. **Seeded requests are malformed.** Host header is literally `h`; bodies repeat the id (`118118118…`); the
   response advertises `Content-Length: 24` over a 24-char id body. Every seeded screenshot looks wrong even when
   the layout is right.
10. **Target duplicates its scope label.** `Target scope` header repeats an inner `Scope` line; no Site map / Scope /
    Issues sub-tabs, no URL view / Crawl paths toggle, and the site map is a flat host-chip list plus a 3-column
    table rather than a tree.

Also open, below the top 10: Comparer lacks the two `# / Length / Data` item tables and Words/Bytes modes; Collaborator
is loopback-only (no public relay/SMTP); Extensions is a static explanation with no host; no global search / gear /
browser-launcher icons; no Event log / All issues / memory in the status bar.

## 5. Verification appendix

- `cargo build` — clean (37 warnings, 0 errors).
- `cargo test` — **127 passed; 0 failed; 0 ignored** (132.98 s).
- Shots: `v8-dashboard`, `v8-proxy`, `v8-intruder`, `v8-repeater`, `v8-target`, `v8-collaborator`,
  `v8-sequencer`, `v8-decoder`, `v8-comparer`, `v8-scanner`, `v8-sessions`, `v8-search`, `v8-extensions`,
  `v8-intruder-auto`, `v8-menu-{WebProbe,Project,Intruder,Repeater,View,Help}`.
