# Burp Suite Pro v2026.7.3 (live, Xvfb) vs WebProbe, gap report

Compared by hand at the same 1440x900. Burp shots: `/root/webprobe-shots/burp-tour/`, WebProbe shots:
`/root/webprobe-shots/pair-wp-*.png`. Four vision-agent attempts were rejected by content safety or
provider limits, so this is a direct read of the screenshots. The Burp HTTP history stayed empty even
though the listener answered, so its populated table was not captured (empty state only).

## Chrome and navigation
| | Burp | WebProbe |
|---|---|---|
| Menu bar | Burp, Project, Intruder, Repeater, View, Help (own window menus) | none; one `Settings` button |
| Tabs | 13 in one row: Dashboard, Target, Proxy, Intruder, Repeater, Collaborator, Sequencer, Decoder, Comparer, Logger, Organizer, Extensions, Discover | 6 + "More tools" menu (Scanner is a first-class tab, Burp has it inside Dashboard tasks) |
| Top right | globe (browser), terminal, search, settings gear, "Burp AT" | `intercept off`, listener address, Settings |
| Theme | light, flat, orange accent on active tab underline | dark, orange text on blue pill for active tab |
| Bottom | Event log / All issues / Memory readout / AI toggle | listener dot, intercept, held, history, messages, last request |

Burp > Burp menu: Search, Settings, Configuration library, User settings >, Log in, Burp Infiltrator,
Burp Clickbandit, Exit.

## Screen by screen
- **Dashboard**: Burp = task cards ("Live audit from Proxy (all traffic)", "Live passive crawl"), issue counters, Summary / Audit items / Issues / Event log / Logger / Audit log tabs, "Task execution is paused / Resume". WebProbe = setup checklist, four counters, listeners, jump buttons, project controls, recent activity. No task model, no event log tab.
- **Proxy**: Burp sub-tabs Intercept | HTTP history | WebSockets history | Match and replace | Proxy settings. Intercept row: `Intercept off`, `Forward` (split button), `Drop` (split button), `Open browser`, help, kebab. WebProbe sub-tabs Intercept | HTTP history | WebSockets | Options; Match and replace lives inside Options.
- **HTTP history**: Burp (docs) columns `# Host Method Params URL Edited Status code Length MIME type Extension Title`, Pretty/Raw/Hex/Renderer. WebProbe `# Method Host URL Status Length MIME TLS`, message pane Request/Response + Raw/Hex/Headers/Params. Missing: Params, Edited, Extension, Title columns; Pretty and Renderer views; split Forward/Drop menu.
- **Repeater**: Burp = numbered tab with close x and "+", `Send` (primary orange), settings, `Cancel`, back/forward history, "Burp AI", `Target: Not specified` with edit pencil, Request | Response | Inspector three-pane layout, Pretty/Raw/Hex, icon toggles (hide non-printables, word wrap, \n, menu), search bar with highlights count, right dock Inspector / Notes / Explanations / Custom actions, `Ready` status line. WebProbe = `Rep 1` pill, `Send (Ctrl+Space)`, HTTPS checkbox, single editor on top, response underneath, no Inspector, no target field, no history arrows, no Cancel, no layout toggle.
- **Intruder**: Burp empty state "To get started, send a request to Intruder from anywhere in Burp." with an illustration of the right-click flow and "Don't show this again". WebProbe shows the old single-pattern form (request box + payload list). No attack-type selector, no positions UI (Auto/Add/Clear), no payload-set types: tasks C-01..C-07, engine core for C-01/C-02 now exists in `src/intruder.rs` (10 tests) but is not wired to the UI yet.
- **Decoder**: Burp = one input area plus right column: Text/Hex radio, `Decode as ...`, `Encode as ...`, `Hash ...` dropdowns, `Smart decode`. WebProbe = editor + eight flat buttons (Encode as Base64, URL encode (key), Hex, HTML encode, Decode as Base64, URL decode, Hex decode, HTML decode). No hashes, no Smart decode, no chained stages (F-01, F-02).
- **Comparer**: Burp = two item tables (`# Length Data`) with Paste / Load / Remove / Clear and Compare Words / Bytes. WebProbe = two text editors, "Selected request/response -> A/B" buttons, line-level diff only (F-03).
- **Settings**: Burp = a real dialog: search box, All/User/Project filter pills, tree (Tools > Proxy, Intruder, Repeater, Sequencer, Comparer, Burp's browser; Project; Sessions; Network; User interface; Suite; AI; Extensions; Configuration library) and a form on the right (Proxy listeners table with Running/Interface/Invisible/Redirect/Certificate/TLS columns, Add/Edit/Remove, CA import/export/regenerate, interception rules table). WebProbe = small window with only Appearance and Hotkeys.

## Ranked gaps (what hurts a tester most)
1. Settings is two panes, Burp has ~15 categories with search (J-03, B-08).
2. Repeater lacks target field, Cancel, history arrows, Inspector, pane layouts, Pretty view (E-01..E-06).
3. Intruder UI has no attack types, positions tools or payload sets (C-01..C-07), engine core now ready.
4. HTTP history lacks Params/Edited/Extension/Title columns and Pretty/Renderer (B-01..B-03).
5. No top menu bar, no global search, no Project menu (J-04), no Logger/Organizer/Discover tabs (L-04).
6. Decoder has no hash, Smart decode or Text/Hex toggle (F-01/F-02).
7. Dashboard has no task model/event log (D-05, D-06).
8. Comparer has no Words/Bytes modes or item tables (F-03).
9. Intercept bar lacks Forward/Drop split actions and Open browser (B-04/L-05).

## Visual defects found in WebProbe (all fixed in this session unless noted)
- Red `First/Second use of ScrollArea ID` overlays on Proxy > Options (match/replace tables) and the Intruder tab: shared scroll ids; fixed with explicit salts.
- Boxes instead of glyphs for arrows and the "More tools" caret: fixed with a fallback font and a glyph-guard test.
- Target host chips ran off the screen: now wrap. Settings window opened over the tab bar: now centred.
- Still open: the Target "Scope" header repeats its own inner label; Dashboard onboarding counts seeded history as real HTTPS traffic; the selection stays on a row the filter hides.
