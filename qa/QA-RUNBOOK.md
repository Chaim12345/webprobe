# WebProbe live QA runbook (agent-driven)

WebProbe is a real desktop window on a private X display. You drive it like a person: look at
a screenshot, decide, click or type, look again. **Use `qa/qa.sh` for everything**, it hides the
display number, window id and renderer environment.

```bash
cd "/root/Documents/Craft Anything/burpsuite"
qa/qa.sh up WEBPROBE_TAB=proxy WEBPROBE_PROXY_SUB=1 WEBPROBE_SEED_HISTORY=200 WEBPROBE_SELECT_ID=199
```

`up` starts the display if needed, launches the app and waits until its window is mapped
(about 6 s). The window is **1440x900** and every coordinate below is **window-relative**:
whatever you read off a screenshot is exactly where a click lands.

**Ports:** the app listens on **127.0.0.1:6566** (collaborator on 6567), never on 8080/8081:
those belong to working tools on this machine (`burpsy`). The status bar therefore reads
`127.0.0.1:6566`. Never start the app on 8080, never kill a process you did not start, and
point any traffic you generate at 6566.

## Primitives

| command | does |
|---|---|
| `qa/qa.sh shot NAME` | window screenshot to `/root/webprobe-shots/NAME.png` (read it with the image reader) |
| `qa/qa.sh click X Y` | left click (also `dclick`, `rclick`, `move`) |
| `qa/qa.sh drag X1 Y1 X2 Y2` | press, glide, release: splitters, column resize |
| `qa/qa.sh type TEXT` | type into the focused widget |
| `qa/qa.sh key COMBO` | `Return`, `Escape`, `Tab`, `ctrl+k`, `ctrl+r`, `ctrl+shift+f`, `Down` ... |
| `qa/qa.sh scroll up\|down N [X Y]` | mouse wheel notches, optionally at a point |
| `qa/qa.sh info` | window size, process, how many colours are on screen (1 means a blank window) |
| `qa/qa.sh down` | stop the app |

Other start-up switches (all `qa/qa.sh up VAR=value ...`): `WEBPROBE_TAB=dashboard|target|proxy|
scanner|intruder|repeater|sequencer|comparer|decoder|search|collaborator|extensions`,
`WEBPROBE_PROXY_SUB=0..3` (Intercept, HTTP history, WebSockets, Options), `WEBPROBE_SETTINGS=hotkeys|appearance`
(opens the Settings window), `WEBPROBE_SEED_REPEATER=<file>` (a raw request for Repeater).

After every action: take a screenshot, **read it**, and only then decide the next action.
Never fire several clicks blind. If the layout moved, re-measure from a fresh screenshot.

## Known coordinates, Proxy > HTTP history (measured on 1440x900)

| control | x,y |
|---|---|
| tabs: Dashboard, Target, Proxy, Scanner, Intruder, Repeater, More tools | 172, 247, 306, 368, 439, 512, 602 at y=17 |
| Settings button | 1402,17 |
| Intercept on/off button | 110,57 |
| sub-tabs: Intercept, HTTP history, WebSockets, Options | 40, 121, 211, 287 at y=91 |
| filter text input | 185,121 |
| regex / in scope checkboxes | 324,121 / 385,121 |
| Method / Status / MIME filter inputs | 131,150 / 246,150 / 385,150 |
| Columns button | 40,181 |
| Send to Repeater / Send to Intruder / Clear history | 89,214 / 251,214 / 375,214 |
| column headers `#`, Method, Host, URL, Status, Length, MIME, TLS | 35, 108, 257, 504, 684, 768, 900, 1024 at y=247 |
| data rows | first at y=279, then every 29 px |
| splitter between table and message pane | about y=648 |
| message pane tabs: Request, Response, Raw, Hex, Headers, Params | 36, 106, 186, 230, 284, 347 at y=666 |
| find-in-message box / font size button | 146,716 / 1395,716 |
| status bar | y=892 |

## Scenarios (record what you see for each, not just pass or fail)

1. Baseline: screenshot, list every visible control and its state.
2. Columns: open the chooser, untick TLS and MIME, confirm the columns disappear and the others
   re-flow; tick them back.
3. Sorting: click Status, then again, then Length: arrow direction, order of rows, stability.
4. Scrolling: wheel over the table, drag the scrollbar (x=1428), page through 200 rows.
5. Filter: type text, toggle regex, type an invalid regex (`(`), set Method/Status/MIME, tick
   "in scope" with zero scope rules, Clear. Watch the `N of M` counter and its colour.
6. Selection: click a row, then the arrow keys, confirm the message pane follows.
7. Message pane: Request/Response, Raw/Hex/Headers/Params, find box, line numbers, font size.
8. Ctrl+R / Ctrl+I from a selected row: lands on Repeater / Intruder with the request filled in.
9. Splitter: drag it up and down, confirm both panes keep sensible minimum sizes.
10. Status bar: counters follow what you do (history, held, last message).
11. Settings (button or `WEBPROBE_SETTINGS=hotkeys`): Appearance (palette, density, scale) and
    Hotkeys (capture a binding, try a duplicate, Esc to cancel).
12. Command palette `ctrl+k`: type to filter, Return to run, Esc to close.
13. Every other tab: open it once, screenshot, compare with the same area in Burp.
14. Resize/overflow: anything clipped, overlapping, unreadably low contrast, or misaligned.

## Report format

Report general UI/UX and behaviour, not true/false: for each area say what it looks like, what
it does, how it differs from Burp, and rank the gaps by how much they hurt a tester. Quote text
you read from screenshots. Say plainly when something could not be done and why.

## Reference material (real Burp Suite, from its own shipped documentation)

Burp itself **cannot be launched on this machine**: the installed build is Burp Suite
Professional and `~/.BurpSuite/UserConfig.json` carries no licence key, so the app stops at the
activation dialog. The reference is therefore Burp's own screenshots, extracted from the shipped
documentation inside `burpsuite.jar`
(`resources/Documentation/burp/documentation/desktop/...`, 2368 images in the jar; 174 extracted
under `/tmp/opencode/burpdoc/`).

`/root/webprobe-shots/burp-ref/` holds the ones that matter for the proxy work:

| file | what it shows |
|---|---|
| `quick-start-pro-proxy-history.png` | the real HTTP history table: columns, filter bar, message panes |
| `setting-target-scope-1-http-history.png` | HTTP history with the Target scope colouring |
| `setting-target-scope-4-filtered-history.png` | the same table after filtering (the filter bar in use) |
| `filter-settings-http.png` | every HTTP history filter field, labelled |
| `quick-start-pro-repeater.png` | Repeater: request editor, response, send |
| `quick-start-pro-send-to-repeater.png` | the send-to-repeater flow from history |
| `getting-started-logger-tab-4-message-editor.png` | the message editor: line numbers, wrap, search, hex |
| `intruder-enumerating-sorting-results.png` | sortable result columns with a sort arrow |
| `Pro-QSG-5-site-map.png` | the site map tree |
| `Pro-QSG-6-view-issues.png` | issue list and severity colouring |
| `viewing-a-custom-http-header-in-burp-proxy.png` | header inspection in the proxy pane |

For any other area, extract more references from the jar:

```bash
unzip -o -q /opt/BurpSuite/burpsuite.jar 'resources/Documentation/burp/documentation/desktop/*' \
  -d /tmp/opencode/burpdoc
```

Read a reference image before judging a WebProbe screen, then say what is the same, what is
missing and what is different. Never claim Burp does something a reference screenshot does not
show; if the reference is silent, say "not shown in the reference".