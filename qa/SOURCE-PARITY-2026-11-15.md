# Source Parity Matrix — WebProbe vs Burp Suite Pro build 52685 (2026-11-15)

Every Burp string below is traced to decompiled source. Primary tree:
`/root/burp-re/out/clean/pristine/` (ZKM-stripped, literals restored via
`tools/StringMap.java` + `apply_strings.py`), plus the runtime-decoded evidence
table `/root/burp-re/out/../../Documents/Craft Anything/burpsuite/re/mapping/string-evidence.tsv`
(runtime-decoded via Burp's own decryptor, `tools/RuntimeStringDump.java`).

WebProbe side read from `app/src/ui.rs` at HEAD, 2026-11-15.

## Main tabs

| Area | Burp string (exact) | Burp source (class.method / jar path) | WebProbe label | WebProbe file:line | Match? |
|---|---|---|---|---|---|
| Main tab | `Target` | `Zg4s.ZF` case 0 (clean/pristine/Zg4s.java:12) | `Target` | app/src/ui.rs:37 | MATCH |
| Main tab | `Proxy` | `Zg4s.ZF` case 1 (Zg4s.java:14) | `Proxy` | app/src/ui.rs:38 | MATCH |
| Main tab | `Scanner` | `Zg4s.ZF` case 2 (Zg4s.java:16) | `Scanner` | app/src/ui.rs:45 | MATCH |
| Main tab | `Intruder` | `Zg4s.ZF` case 3 (Zg4s.java:18) | `Intruder` | app/src/ui.rs:39 | MATCH |
| Main tab | `Repeater` | `Zg4s.ZF` case 4 (Zg4s.java:20) | `Repeater` | app/src/ui.rs:40 | MATCH |
| Main tab | `Sequencer` | `Zg4s.ZF` case 5 (Zg4s.java:22) | `Sequencer` | app/src/ui.rs:42 | MATCH |
| Main tab | `Extensions` | `Zg4s.ZF` case 6 (Zg4s.java:24) | `Extensions` | app/src/ui.rs:48 | MATCH |
| Main tab | `Burp AI` | `Zg4s.ZF` case 7 (Zg4s.java:26) | — (absent) | — | MISSING |
| Main tab | `Dashboard` | `Zrar` ctor setText("Dashboard") (Zrar.java:149); also Zgdu.java:244, Zsq4.java:123 | `Dashboard` | app/src/ui.rs:36 | MATCH |
| Main tab | `Logger` | `Zi96` addTab("Logger", …) (Zi96.java:16); also Zi96.java:41 | — (absent tab) | — | MISSING |
| Main tab | `Organizer` | `Zr86` setText("Organizer") (Zr86.java:612) | — (absent tab) | — | MISSING |
| Main tab | `Decoder` / `Comparer` / `Collaborator` / `Sessions` / `Search` | not found in `Zg4s.ZF` enum for build 52685 | present as WebProbe tabs | app/src/ui.rs:43-47 | UNVERIFIED (may be windows/tools in Burp; do not assume parity) |

Note on order: Burp's `Zg4s.ZF` enum order is Target, Proxy, Scanner, Intruder,
Repeater, Sequencer, Extensions, Burp AI. WebProbe's tab order differs
(ui.rs:35-49). If exact parity is wanted, order should follow Burp's enum.
Caveat: `Zg4s.ZF` may cover only one tab-enumeration context; treat order as
evidence, not as the definitive top-bar order.

## Proxy sub-tabs

| Area | Burp string (exact) | Burp source | WebProbe label | WebProbe file:line | Match? |
|---|---|---|---|---|---|
| Proxy sub-tab 0 | `Intercept` | `Zx5h.ZG` (Zx5h.java:36) | `Intercept` | app/src/ui.rs:1594 | MATCH |
| Proxy sub-tab 1 | `HTTP history` | `Zx5h.Zr` (Zx5h.java:41) | `HTTP history` | app/src/ui.rs:1594 | MATCH |
| Proxy sub-tab 2 | `WebSockets history` | `Zx5h.Zb` (Zx5h.java:46) | `WebSockets history` | app/src/ui.rs:1594 | MATCH |
| Proxy sub-tab 3 | `Match and replace` | `Zx5h.Za` (Zx5h.java:51) | `Proxy settings` | app/src/ui.rs:1594 | **MISMATCH** |
| — | `Proxy settings` | NOT FOUND anywhere in jar trees | `Proxy settings` | app/src/ui.rs:1594 | WebProbe invented label |

Burp sub-tab persistence keys confirm the set:
`subtab.intercept.shown`, `subtab.http_history.shown`,
`subtab.websockets_history.shown`, `subtab.match_and_replace.shown`
(Zx5h.java:36-51). There is no `subtab.proxy_settings.*` key.

## Intruder

| Area | Burp string (exact) | Burp source | WebProbe label | WebProbe file:line | Match? |
|---|---|---|---|---|---|
| Intruder sub-tab | `Payloads` | `Zija` returns "Payloads" (Zija.java:39,44); `Zr7k` (Zr7k.java:90 is Positions sibling) | absent (no sub-tabs) | — | MISSING |
| Intruder sub-tab | `Positions` | `Zr7k` (Zr7k.java:90); `Zruh` setText (Zruh.java:344) | absent | — | MISSING |
| Attack types | `Sniper attack` / `Battering ram attack` / `Pitchfork attack` / `Cluster bomb attack` | runtime-decoded enum constants of `burp.Zgu5` — `re/mapping/`-adjacent dump `/root/burp-re/out/runtime_names/runtime_enums.tsv` (evidence `runtime.enumConstant:Zgu5`); internal names `INTRUDER_POSITIONS_ATTACK_TYPE_*` in `burp.Zpbb` (same dump); live-JVM confirmation in `live_enums.tsv` | — | — | UNMATCHED (WebProbe has no attack-type UI yet; exact Burp display strings include the ` attack` suffix) |

## Repeater

| Area | Burp string (exact) | Burp source | WebProbe label | WebProbe file:line | Match? |
|---|---|---|---|---|---|
| Repeater tab title | `Repeater` | `Zcu0` setText("Repeater") (Zcu0.java:34) | `Repeater` | app/src/ui.rs:40 | MATCH |
| Send action | `Send to Repeater` | `Zcur` (Zcur.java:43); also Zr2s.java:44, Zrp8.java:76 | `Send to Repeater` (with Ctrl+R suffix) | app/src/ui.rs:138 | MATCH |
| Message views | `Pretty` / `Raw` / `Hex` | `Zwsv` (Zwsv.java:21/25/30) | `Pretty` / `Raw` / `Hex` | app/src/ui.rs:1167,1187 | MATCH |
| Send to Intruder | context action (see Zcur neighborhood) | — | `Send to Intruder` (Ctrl+I) | app/src/ui.rs:131 | MATCH (same pattern as Send to Repeater) |

## History table column headers

Burp's exact table-column strings from the column-definition class `Zxwu`
(clean/pristine/Zxwu.java, `ZD(...)` calls): `Host` (:16), `Method` (:20),
`URL` (:24), `Params` (:28), `Status code` (:32), `Length` (:36),
`MIME type` (:40), `Title` (:44), `Notes` (:48), `Time requested` (:52),
`Diff count` (:56).

| WebProbe column | Burp string | Burp source | Match? |
|---|---|---|---|
| `#` | — | — | Burp uses row numbers; label kept |
| `Method` | `Method` | Zxwu.java:20 | MATCH |
| `Host` | `Host` | Zxwu.java:16 | MATCH |
| `URL` | `URL` | Zxwu.java:24 | MATCH |
| ~~`Status`~~ → `Status code` | `Status code` | Zxwu.java:32 | **FIXED 2026-11-15** |
| `Length` | `Length` | Zxwu.java:36 | MATCH |
| ~~`MIME`~~ → `MIME type` | `MIME type` | Zxwu.java:40 | **FIXED 2026-11-15** |
| `Title` | `Title` | Zxwu.java:44 | MATCH |
| `Params` | `Params` | Zxwu.java:28 | MATCH |
| ~~—~~ → `Notes` | `Notes` | Zxwu.java:48 | **ADDED 2026-11-15** (data: history entry notes) |
| ~~—~~ → `Time requested` | `Time requested` | Zxwu.java:52 | **ADDED 2026-11-15** (UTC time-of-day from entry ts) |
| ~~—~~ → `Diff count` | `Diff count` | Zxwu.java:56 | **ADDED 2026-11-15** (net.rs `DiffTracker`: status/length/cookies/response-header changes vs the previous exchange of the same method+host:port+path location; first sighting diffs 0; suite 227) |
| `Extension` / `TLS` / `Cookies` / `Port` / `Edited` | not in Zxwu class | — | UNVERIFIED (likely other classes; do not rename without grounding) |

## WebSockets history

| Area | Burp string | Burp source | WebProbe | Status |
|---|---|---|---|---|
| Sub-tab | `WebSockets history` | `Zx5h.Zb` (Zx5h.java:46) | sub-tab 3 | MATCH |
| Frame table | `Payload` column | `Zbvn.java:9` et al. (`ZwH().Zg(var1, "Payload")`) | 7 columns: #, Time, Host, Direction, Opcode, Length, Payload with clickable rows + payload inspector | **UPGRADED 2026-11-15** (was a bare 5-column list) |
| Frame capture | — | — | plain-HTTP upgrade frames recorded (net.rs `WsEntry`); TLS relay unsupported, stated in-view | honest limitation, open |

## Scanner / audit severities

| Area | Burp string (exact) | Burp source | WebProbe label | WebProbe file:line | Match? |
|---|---|---|---|---|---|
| Severity | `High` | `Ze1r` (Ze1r.java:22) | `High` | app/src/ui.rs:1856 | MATCH |
| Severity | `Medium` | `Ze1r` (Ze1r.java:20) | `Medium` | app/src/ui.rs:1857 | MATCH |
| Severity | `Low` | `Ze1r` (Ze1r.java:18) | `Low` | app/src/ui.rs:1858 | MATCH |
| Severity | `Information` | `Ze1r` (Ze1r.java:16) | absent | — | MISSING |
| Severity | `False positive` | `Ze1r` (Ze1r.java:12,36) | `False positive` — `ScanIssue.false_positive` toggle ("Mark as false positive" button in Scanner detail), dashboard 5th bucket, project round-trip (serde default) | app/src/ui.rs Scanner + Dashboard | **ADDED 2026-11-15** |

## Burp AI

| Area | Burp string | Burp source | WebProbe label | Match? |
|---|---|---|---|---|
| Main tab | `Burp AI` | `Zg4s.ZF` case 7 (Zg4s.java:26) | `Burp AI` tab at end of tab bar with honest placeholder pane ("Not implemented in WebProbe yet") | **ADDED 2026-11-15** (label MATCH; functionality open) |

## Discover

| Area | Burp string | Burp source | WebProbe label | Match? |
|---|---|---|---|---|
| Discover | NOT PRESENT in build 52685 (no `"Discover"` literal in clean/pristine or readable_strict) | — | WebProbe has a Discover placeholder | No Burp counterpart — placeholder should not claim parity |

## Top mismatches (ranked by user visibility)

1. ~~**Proxy sub-tab 4**: Burp = `Match and replace` (Zx5h.java:51); WebProbe = `Proxy settings` (ui.rs:1594).~~ **FIXED 2026-11-15**: sub-tab renamed to `Match and replace`; pane leads with the M&R rules tables, connection options under "Connection and listeners". `match_replace.rs` duplicate engine deleted (String-based, unsafe for binary bodies, 4 regions vs rules.rs's 7 Burp-verified scopes); `rules.rs` is the single live engine.
2. ~~**Missing `Logger` tab**: Burp has a real Logger tab (Zi96.java:16); WebProbe engine exists (`app/src/logger.rs`) but no tab.~~ **FIXED 2026-11-15**: `Tab::Logger` + `logger_view` added (Tab enum, TABS, dispatch, `App.log_sel`).
3. ~~**Missing `Organizer` tab**: Burp confirmed (Zr86.java:612); WebProbe engine exists (`app/src/organizer.rs`) but no tab.~~ **FIXED 2026-11-15**: `Tab::Organizer` + `organizer_view` added (add/remove/rename/note, item list, request/response display).
4. ~~**Missing Intruder sub-tabs `Positions`/`Payloads`** (Zr7k.java:90, Zija.java:39).~~ **FIXED 2026-11-15**: `sub_tabs` "Positions"/"Payloads" added to the Intruder tab (`App.intr_sub`); Positions holds the marker buttons + request editor, Payloads holds the attack-type selector + payload sets. Attack-type labels updated to the runtime-grounded display strings "Sniper attack"/"Battering ram attack"/"Pitchfork attack"/"Cluster bomb attack" (`AttackType::label`, burp.Zgu5).
5. ~~**Missing severities `Information` / `False positive`** (Ze1r.java:12-22).~~ **PARTIALLY FIXED 2026-11-15**: `scan_sev_label` renders Burp's exact names (High/Medium/Low/Information) in the Issues table and dashboard chip ("Info" → "Information"). "False positive" remains open (it is a classification state in Burp, not a severity bucket).
6. **Tab set/order**: Burp enum has `Burp AI` (Zg4s.ZF:26) — **tab ADDED 2026-11-15 at end of bar**; full order alignment still open; WebProbe carries `Sessions`/`Search` without jar grounding.

## Not present in jar / unverified

- Repeater `Send`/`Pretty`/`Hex`/`Raw` — not located yet.
- Logger/Organizer column headers — not yet extracted (classes Zrop / Zr86 neighborhood).
- `Decoder`/`Comparer`/`Collaborator`/`Sessions`/`Search` main-tab names — not in the `Zg4s.ZF` enum; verify before claiming parity.

## Next actions (jar-grounded)

1. ~~Rename WebProbe proxy sub-tab 4 to `Match and replace` (ui.rs:1594)~~ DONE 2026-11-15.
2. ~~Add `Logger` and `Organizer` tabs backed by existing engines~~ DONE 2026-11-15.
3. ~~Add Intruder `Positions`/`Payloads` sub-tabs~~ DONE 2026-11-15 (with runtime-grounded attack-type labels).
4. ~~Add `Information`/`False positive` to severity handling~~ Information DONE; False positive open (classification state).
5. ~~Run `RuntimeStringDump.java` against the attack-type class to ground Intruder attack names~~ DONE — grounded via existing `runtime_enums.tsv` / `live_enums.tsv` (burp.Zgu5: "Sniper attack" etc.).

## Scanner active-check families (runtime-grounded)

Burp's active-check families from `runtime_enums.tsv` (`burp.Zbjf`
`SCANNER_ACTIVE_CHECKS_*`): CSRF, EXTERNAL_INTERACTION (OOB),
FILE_PATH_TRAVERSAL, HEADER_INJECTION, HEADER_MANIPULATION, LDAP_INJECTION,
OPEN_REDIRECTION, OS_COMMAND_INJECTION, REFLECTED_DOM, REFLECTED_INPUT,
REFLECTED_XSS, SERVER_LEVEL_ISSUES, SERVER_SIDE_CODE_INJECTION,
SERVER_SIDE_TEMPLATE_INJECTION, SMTP_INJECTION, SQL_INJECTION, STORED_DOM,
STORED_INPUT, STORED_XSS, XML_INJECTION.

WebProbe light active scan (`scan.rs::start_active_scan`) implements 19/20
(2026-11-15): SQL_INJECTION (error signatures + boolean-based differential AND 1=1/1=2), REFLECTED_INPUT (unencoded
marker), OPEN_REDIRECTION (`is_open_redirect`), HEADER_INJECTION (`%0d%0a`
echo), FILE_PATH_TRAVERSAL (passwd content markers),
SERVER_SIDE_TEMPLATE_INJECTION (`{{7*7}}` -> 49), OS_COMMAND_INJECTION
(time-based blind vs per-scan baseline), LDAP_INJECTION (error signatures), EXTERNAL_INTERACTION (Collaborator-backed:
oob probe embeds the payload, Shared::oob_pending + ui.rs sync_oob_issues
raise the issue when an interaction is observed; loopback-only),
HEADER_MANIPULATION (X-Forwarded-For marker reflection, scan-level),
XML_INJECTION (external-entity DOCTYPE, scan-level, XML requests only),
REFLECTED_XSS (script-context <script> tag echo), SERVER_SIDE_CODE_INJECTION
(EL ${7*7} -> 49 evaluation), REFLECTED_DOM (plain canary reflected
unencoded into script data or a quoted attribute value of an HTML response;
`is_reflected_dom_hit` — text-node reflections and entity-escaped values do
not count; **ADDED 2026-11-15**), STORED_INPUT / STORED_XSS / STORED_DOM
(stored-echo pass: after the per-parameter probes the scan re-fetches the
original URL and classifies surviving markers with `stored_echo_hit` —
persisted `<script>` payload = stored XSS, canary in script data/attribute
= stored DOM, plain echo = stored input; **ADDED 2026-11-15**, suite 229), SERVER_LEVEL_ISSUES
(host-level probes: TRACE echo-back = cross-site tracing `is_trace_hit`,
permissive OPTIONS Allow with PUT/DELETE/TRACE/CONNECT
`risky_methods_allowed`; **ADDED 2026-11-15**, suite 230), SMTP_INJECTION
(error-based: CRLF + Bcc probe per parameter, hit requires a mail-pipeline
error signature the baseline response does not contain
`is_smtp_injection_hit`; **ADDED 2026-11-15**, suite 231).
Passive: 31 checks incl. a CSRF variant (password POST without token field).
19/20 families implemented; the only gap is an *active* CSRF form-probing
variant, judged redundant with the passive CSRF check + crawl-driven form
handling (documented omission).

## Extensions (2026-11-15, wave 20)

Montoya architecture fork resolved to **Path A: Rust-native Montoya-shaped
hook host** (`ext_host.rs`) — WebProbe is a self-contained Rust binary, so
the Montoya proxy hook surface (ProxyRequestHandler /
ProxyResponseHandler) is expressed as Rust traits (`ProxyHooks`) and runs
in-process; no sidecar JVM, no IPC on the hot path. The host
(`ExtensionHost`) runs enabled extensions in registration order on
every proxied message, after session rules and match/replace, at all three
proxy sites (HTTP, plain-WS handshake, TLS-WS handshake); a `Drop` verdict
stops the chain and closes the connection. The Extensions tab now lists the
real registry with enable/disable toggles instead of the placeholder text.
QA hook: `WEBPROBE_EXT_TEST=1` registers the built-in example
(`ExampleHeaderExtension`, adds X-WebProbe-Extension to each request).
4 unit tests: empty host passes, Drop stops the chain, disabled skipped,
example adds its header. Suite 235.

## Java extensions via sidecar JVM (2026-11-15, wave 30 — Path B)

The wave-20 limitation "Burp's Java .jar extensions do not load" is now
closed. `app/sidecar/MontoyaBridge.java` loads a real Montoya .jar
extension against **Burp's own Montoya API classes** from
`/opt/BurpSuite/burpsuite.jar` (the jar bundles the full
`burp.api.montoya` API, 1001 entries incl. sources) and speaks JSON lines
over stdin/stdout: `{type: request|response, id, method, path, headers,
body, ...}` → `{id, action: continue|drop}`. Launch is single-file source
mode — `java -cp burpsuite.jar MontoyaBridge.java <ext.jar>` — no build
step. The bridge:

- loads the extension via ServiceLoader (`burp.api.montoya.BurpExtension`)
  and calls `initialize(MontoyaApi)`;
- backs `MontoyaApi` with dynamic `java.lang.reflect.Proxy` stubs:
  `proxy()` really registers `ProxyRequestHandler`/`ProxyResponseHandler`
  objects, `logging()` writes to stderr, other accessors (http/burpSuite/
  collaborator/utilities) throw UnsupportedOperationException;
- sets `ObjectFactoryLocator.FACTORY` so Montoya's static action factories
  work: `ProxyRequestReceivedAction.drop()` → DROP verdict,
  `continueWith(request)` → CONTINUE;
- stubs `InterceptedRequest`/`InterceptedResponse` from the IPC message
  (method/path/url/headers/headerValue/bodyToString/httpService/
  statusCode(short)/reasonPhrase/messageId).

Rust side: `ext_host.rs::JavaSidecar` implements `ProxyHooks` by parsing
the raw proxied message into the JSON shape, round-tripping through the
JVM, and mapping the verdict onto `ProxyAction`; a dead sidecar degrades
to pass-through instead of breaking the proxy. Registered at startup with
`WEBPROBE_EXT_JAR=path/to/ext.jar` (Burp jar override:
`WEBPROBE_BURP_JAR`). Demo extension: `app/sidecar/demo-ext/`
(`DemoExtension.java` + `build-demo-ext.sh`, ServiceLoader-registered jar)
which drops any path containing `/admin-drop`.

Verified end-to-end three ways: (1) standalone bridge smoke test (ping →
drop on `/admin-drop` → continue on `/normal` → response hook → exit 0);
(2) suite test `java_sidecar_runs_a_real_montoya_extension` (real JVM,
242 passed / 0 failed); (3) live proxy QA on :99 — `curl -x
127.0.0.1:8123 http://127.0.0.1:8130/normal` → 404 from the target
(passed through), `.../admin-drop/panel` → curl rc=52 empty reply
(dropped by the extension inside the JVM); Extensions tab screenshot
shows "Montoya bridge (demo-ext.jar) — ProxyRequestHandler +
ProxyResponseHandler (sidecar JVM)" with a live enable toggle.

Honest v1 scope (documented in the Extensions tab, not silent): the
*Received halves run (matching WebProbe's ProxyHooks), the *ToBeSent
halves do not; message editing (withUpdatedBody / utilities()-built
requests) and UI-coupled APIs throw; request bodies travel as JSON
strings (lossy for binary). Suite 242.

## WebSockets message interception (2026-11-15, wave 21)

Burp's Proxy settings > WebSockets has "Intercept client-to-server messages"
/ "Intercept server-to-client messages" (default off). WebProbe implements
both (net.rs `intercept_ws_stream`, flags `ws_intercept_client` /
`ws_intercept_server`, checkboxes under Proxy options > WebSockets): text
and binary frames of a plain-HTTP WebSocket upgrade are queued in the
regular Intercept tab — Forward rewrites the payload, Drop skips the frame;
control frames relay untouched. Client frames are rebuilt masked (server
requirement), server frames unmasked; `build_ws_frame` re-encodes 7-bit /
16-bit / 64-bit lengths. Frame rewrite caught a real bug via test: the
first header encoding put the length in a third header byte (RFC says the
7-bit length lives in byte 1 with the mask bit). 3 unit tests (roundtrip
across all three length encodings, off-passthrough + control frames,
queue-edit + drop). Suite 238. **Wave 22**: the same interception is wired
into the TLS WebSocket relay (`relay_ws_tls` shares the frame buffer with
the recorder — record drains complete frames, the leftover joins the next
chunk), so TLS WebSocket frames are now intercepted in both directions as
well; masking flags are preserved per frame. Suite 238 (green).

## Populated-project UI (2026-11-15, wave 26)

Probes executed against the live reference (traffic + screenshots in
/root/webprobe-shots/burp-populated/): HTTP history populates and the
right-click context menu was captured item-for-item; the Target site map
stays empty while crawl tasks are paused ("Task execution is paused - Site
map will not be populated" + Resume banner) — proxy traffic alone does not
populate it on the reference either, matching WebProbe's history-built site
map when tasks run; Repeater shows per-tab history pager and an Inspector
sidebar. New grounding: the reference history table has an "IP" column
(104.20.23.154 for example.com) that WebProbe lacks — recorded as the next
parity gap. WebProbe's history context menu is now implemented with the
exact captured item set and order: Add to scope / Scan / Passive scan
selected message (disabled) / Active scan selected message / Send to
Intruder (Ctrl+I) / Send to Repeater (Ctrl+R) / Send to Sequencer
(disabled) / Send to Organizer (Ctrl+O) / Send to Comparer (request) /
Send to Comparer (response) / Open response in browser (disabled) /
Request in browser (disabled) / Send to Burp AT (disabled) / Engagement
tools (disabled) / Show new history window (disabled) / Add notes
(disabled) / Highlight (disabled) / Delete item / Clear history / Copy URL
/ Copy as curl command (bash) / Copy links in response / Save item
(disabled) / Proxy history documentation (disabled) — items without a
WebProbe backend are disabled, not pretended away. Wired actions verified
end-to-end in the QA rig (Xvfb :99): Send to Repeater opened a new Repeater
tab with the request. New helpers: run_active_scan_on (shared with the
scanner button), history_url, curl_command_of, links_in_response.
Suite 238 (green).

## History IP column (2026-11-15, wave 27)

The live reference history table shows an "IP" column (104.20.23.154 for
example.com) that WebProbe lacked. Implemented: `HistEntry.ip` stamped in
`record()` via `resolve_ip` — a host -> IP cache (Shared.ip_cache, cleared
past 4096 hosts) backed by a blocking getaddrinfo resolution done once per
host on the proxy worker thread; empty host or unresolvable host yields an
empty cell. UI: "IP" column inserted after TLS (index 12), sortable, right
of TLS and left of Cookies matching the reference order; downstream column
indices shifted (Cookies 13, Port 14, Params 15, Edited 16, Diff count 17).
Unit test: empty host resolves to nothing; a cache entry answers without
DNS. Verified live in the QA rig: real traffic through the listener
(example.com GET / 200 577 text/html "Example Domain") recorded into
history (burp-waves/15-ip.png); the IP cell itself sits beyond the visible
table width in the synthetic pass, the data path is covered by the unit
test. Suite 239 (green).

## Open browser (2026-11-15, wave 28)

Burp's "Open browser" is grounded at Zrxt.java:217 (Intercept view) and
Zw5t.java:63; the reference drives chrome/chromium itself (Zrg5.java:38 /
Zrgu.java:28 mention "chrome", "chromium", "without sandbox"). WebProbe
implements `launch_preconfigured_browser` (tools.rs): finds a system
Chrome/Chromium (preference order google-chrome-stable, google-chrome,
chromium-browser, chromium), launches it with the proxy preconfigured
(--proxy-server=http://127.0.0.1:<port>), an isolated temp profile
(--user-data-dir=/tmp/webprobe-browser-profile), no first-run/default-check
prompts, and starts on the onboarding page (http://webprobe/ served through
the proxy). Buttons placed where Burp has them: the Intercept view's
"Nothing held." state (Zrxt) and the Target view header (Zw5t). Honest
scope: Burp bundles its own Chromium; WebProbe launches the system browser
— no embedded runtime is bundled and the difference is stated. Verified
live: clicking Open browser launched google-chrome-stable with
--proxy-server=http://127.0.0.1:8123 (process check + success toast,
burp-waves/22-24). Unit test: candidate order + argument builder (proxy
flag, isolated profile, onboarding start URL). Suite 240 (green).

## BApp Store (2026-11-15, wave 23)

Burp build 52685 does ship a BApp Store: the "BApp Store" sub-tab is
grounded at burp.Zg26.java:47 (telemetry key `subtab.bapp_store.shown`) and
the welcome-card copy at burp.Zmx_.java:28 ("Customize Burp with
extensions" / "Explore extensions in the BApp Store to customize Burp's
behavior and add extra capabilities."). WebProbe's Extensions tab now has a
BApp Store section with those exact strings and a static offline catalog of
8 well-known BApps (name + one-line description each). Honest scope: the
live store is not fetched and ratings are not shown — the parity surface is
the tab and its copy, not the network content; installing Java BApps is
unsupported under the Rust-native extension host (stated in the tab).
Suite 238 (green, UI-only change).

## Session handling (2026-11-15)

Grounded on runtime-decoded session actions (`string-evidence.tsv`:
`burp.Z_0a` "Set the header: %s: %s" (name/value/add_if_not_present),
`burp.Z_00`/`Z_0h` macros). WebProbe `net.rs::apply_session_rules` (:172)
implements all three actions — set header, use cookie (auth-token
extraction via `latest_cookie` + replay), run macro — host-matched, applied
at all three proxy sites (:1418/:1518/:1812), persisted via
`ProjectSessionRule`. Residual: multi-step macro parameter chains.

## Wave 31 (2026-11-16): logic ported from Burp's code, not names

| Item | Burp source | WebProbe | Status |
|---|---|---|---|
| Active CSRF | `burp.Zg8u` (APR_CrossSiteRequestForgery), `Zg8w.Zi` (token value length ≥ 6, per `Zwwc.toString`: name=Za, value=ZO), `Zm9o.ZP` | `scan.rs` `csrf_applicable` / `strip_csrf_params` | Ported, drops tokens and resends |
| Embedded browser flags | `Zi9a.java:57` `--class=burp-browser --ignore-certificate-errors` | `tools.rs` `browser_args` | Ported; Burp's bundled Chromium preferred |
| File path traversal | `Zp3a` flow, `Zscp.ZL` (27 payloads), `Zw_c.ZE` markers, `Zco6` filenames, `Zp3a.ZJ` tier rule. Tables decoded from Burp's decrypted classes (`/root/burp-re/in/extract/burp`) | `scan.rs` `run_traversal_check` | Ported with negative control, baseline suppression and shadow escalation |
| XXE file read | `Zge7.Ze/Za/ZC` (4 DOCTYPE variants incl. `X` controls, `&xxe?????;` after an element value) | `scan.rs` `run_xxe_check` | Ported. The old probe never referenced its entity and sent a stale Content-Length |
| Remaining 15 families | per-family check classes | name-grounded only | **Open:** craft `unk_e8d35ba47ccfba29` |

Not ported: `Zw4k.ZI` viewstate-region exclusion. Burp's audit-speed setting (`Zsv7`) is also missing, so WebProbe scans run at NORMAL.

Test build: `Cargo.toml` now sets `[profile.dev.package."*"] opt-level = 2`. Every `Shared::new()` generates an RSA CA key, and unoptimized bigint code made six tests take 64–118 s each. Suite time dropped from 92–176 s to 5.6 s (251 passed).

## Wave 39 (2026-11-16): real-app parity (Juice Shop) + UI/UX clone pass

### Scanner: Juice Shop vs Burp 52685 (REST oracle scans 7 and 8)

Result: given the same audited URLs (`/tmp/parity-juice/paths.txt`, built from
Burp's own crawl + targeted scan; WebProbe has no crawler), WebProbe reproduces
Burp's issue set exactly: **75/75 on (issue type, path, severity, confidence)**,
no Burp-only and no WebProbe-only issues (`/tmp/parity-juice/diff-final.txt`).
Coverage parity (crawling) is still open.

Ported from the decompiled source this wave:

- CORS (`APR_CrossOriginResourceSharing`): burp.Zx8s / Zidt / Zmsy / Zmsq /
  Zmsd / Zmsc / Zmsg / Zmsz over burp.Zu8t origin variants, burp.Zpqe
  evaluation, burp.Zmpk collection, burp.Zrbl flags, burp.Zwfk text.
  Zwo8.Zw strings ZKM-decoded (`null`, `http://null`, `https://null`).
  No-credentials variants report as Information (live oracle: flags 65569).
- OpenAPI active (burp.Zh0b, path lists Zk/ZB/ZF runtime-dumped,
  swagger-ui-init markers Zbhe.ZQ/Zn) and passive (burp.Zge_, suffix lists).
- Path-relative style sheet import (burp.Zwza).
- SQL injection "general error" path (burp.Zxp6 -> Zbpt with Ze27.Za words
  dumped by reflection: error, exception, illegal, invalid, fail, stack; plus
  new-5xx), Zh6 flag-64 description.
- URL path insertion points ("URL path filename", "URL path folder N").
- Email parser burp.Zflt with Burp's 251-entry TLD list; request exclusion.
- Credit-card scanner burp.Zu0p.
- Issue path = URL path without query (Burp keying); non-KB passive checks
  gated behind "WebProbe extra checks" (default off).

Bugs found by the real app: h2c upgrade attempted on every cleartext upstream
(Node drops the socket; now opt-in), extension parsed from absolute-form URLs,
request-level checks nested inside the per-parameter loop (never ran without
parameters), lab harness Content-Length off by one. Lab capstone re-run:
identical to wave 38 (18 = 18), no regressions.

### UI/UX clone

Light theme default (UserDefaults look_and_feel=Light; LightTheme.json
colours), Burp's 13-tool tab row and right-hand icons, View menu, status bar
(Event log, All issues, Memory), Settings window with left nav (Appearance,
Hotkeys, Proxy, Sessions). Rebuilt to Burp's live layouts: Proxy HTTP history
(columns, filter bar with Burp's default filter, panes, Inspector + Notes dock,
highlight/notes/sequencer menu items), Intercept (toolbar, empty states; fixed
a bug that silently dropped every held request after one frame), Repeater
(tabs, Send/Cancel, history arrows, Target dialog, Update Content-Length,
status line), Intruder (2026 layout, Add §, payload panel, results window),
Dashboard (tasks rail, task cards, Summary/Audit items/Issues/Event log/Logger/
Audit log, New scan), Target (site map tree with live passive crawl,
Site map/Scope/Issues), Logger, Organizer, Comparer, Decoder. Idle CPU: the
app no longer repaints continuously (was ~580% CPU under the software
renderer, starving network threads).

### Wave 39b: crawler coverage, context menu, AI slot

- Crawl and audit (crawl.rs, CrawlDefaults.json: link depth 4, 1500
  locations, robots.txt + sitemap.xml): crawling Juice Shop from `/` only,
  WebProbe reaches all 25 locations Burp's crawl audited and reproduces
  **all 58 issues of Burp scan 7** (58/58, none missing). Extras: 4 CORS issues
  on `/ftp/legal.md` and `/ftp/announcement_encrypted.md`, which Burp's
  browser crawler deterministically does not visit (repeat scan 10: same 25
  locations; targeted scan 9 of those two URLs: 0 crawl locations, 0 audit
  items, i.e. Burp does not treat these Markdown downloads as locations while
  it does audit `acquisitions.md`). No source-level rule was found for that
  pruning, so it is not imitated.
- Every Proxy history context-menu item now works: Passive scan selected
  message, Open response / Request in browser (http://webprobe/show/N and
  /repeat/N served by the proxy, like http://burpsuite/...), Send to WebProbe
  AI, Engagement tools (Find references, Generate CSRF PoC), Show new history
  window, Save item, documentation.
- Burp AI slot: WebProbe AI chat against a user-configured OpenAI-compatible
  endpoint (Burp's own runs on PortSwigger's cloud). Off until configured.
- Not pursued: the time-based detection family (halted by a safety stop
  earlier in the work).

## Wave 40 (2026-11-16): browser crawler, forms, second-app coverage

Correction to waves 39/39b: those oracle scans ran Burp's *legacy* crawler
(the embedded browser refused to start as root) and reused one Burp project.
Burp's REST `issue_events` list only issues new to the project, so issues
already in a reused project are missing from later scans. The "Burp does
not report X" conclusions drawn from those runs were unreliable (the header-only
reflection rule, link manipulation, and the `/ftp/*.md` question
unk_f6ea7405b0962869). From this wave, every oracle scan runs on a fresh
project with the browser crawler enabled
(`embedded_browser.allow_running_without_sandbox`).

Ported or fixed this wave, each checked against the live oracle:

- Headless-Chromium crawl over DevTools (tungstenite): links, router links,
  hash routes. The browser resolves only the target host, so no other host
  gets traffic. The responses the browser itself received
  (Network.responseReceivedExtraInfo `headersText` + Network.getResponseBody)
  are what the passive checks see, as in Burp. Replay is only the fallback,
  for redirect chains and evicted bodies.
- Clickable elements, like Burp's browser crawler: buttons, ARIA buttons,
  menu items, tabs and onclick handlers, each clicked once per crawl
  (keyed by tag + label) on a fresh load of its page. The requests a click
  triggers are captured, and the route and links it reveals are queued.
- Forms are filled and submitted *in the browser*. Values are set with native
  setters plus input/change/blur events, so framework-bound controls react,
  and the form is submitted through its own submit button. The application's
  JS therefore sends the real request: on Juice, POST /rest/user/login,
  POST /api/Feedbacks/, POST /rest/user/reset-password and
  /rest/user/security-question. Reconstructing the request outside the
  browser had produced nonsense for SPA forms (`GET /?ng.form0.email=...`).
- Form fill values follow Burp's crawler (observed on build 52685): each form is
  sent filled and as-is. Fill values are random letters, number 40434, tel
  521-547-2839, date 1965-3-6, and a password like `j9S!s2k!F6`. Select gets
  its first option, hidden and prefilled values are kept, and checkboxes and
  the first radio are on in the filled submission. The url-encoded, text/plain,
  multipart and GET encodings are all handled. Burp's email and URL values
  point at burpcollaborator.net; WebProbe uses example.com and the target
  origin, so the target is never steered at an out-of-scope host.
- Body MIME sniffer gate (burp.Zh63.Zi, Zmb7, Zm5t, Zh0p), probed by reflection
  against the real classes:
  - Bytes below 32 as a *signed* Java byte count as control bytes, other than
    tab, LF and CR, so every UTF-8 byte from 0x80 up counts.
  - When the count reaches 10 + len/100, the body is binary (length capped at
    head + 10000, BOM skipped).
  - A binary body still sniffs as HTML (starts with `<!doctype html`, `<html`
    or `<head`) or XML (`<?xml`); anything else becomes unknown.
  - For JSON, HTML, XML and JS, Burp audits the sniffed type (Zh63.Zj). With an
    unknown type, the information-disclosure checks search the headers only
    (burp.Zbz9). This explains why Burp does not report the emails in Juice
    `/rest/memories/`: 91 multi-byte bytes against a threshold of 71.
- Frameable response (burp.Zm7y.ZL, issue Zpe_): info / firm. It requires a
  GET, a non-3xx status, sniffed HTML, a URL-bearing element (burp.Zeyc) and no
  X-Frame-Options DENY or SAMEORIGIN. CSP frame-ancestors does not suppress it.
- Link manipulation (burp.Zb_5): a bare random 10-character token *replaces*
  the value, and a Location or Refresh target counts as a link. WebProbe's
  old value+marker probe got past allowlisting redirectors such as Juice
  `/redirect`, and that was the real cause of the Juice false positive.
- Input returned in response: reflection anywhere in the response, headers
  included (fresh-project scan 5 reports lab `/redirect`, which echoes the
  value only in Location).
- One SQL injection issue per insertion point: after an error-based hit, the
  boolean test is skipped. Burp reports only the "general error" issue on lab
  `/user`.
- Insertion points: query, URL-encoded body, JSON leaves.
- MIME / charset passive checks (burp.Zf9p) and private-IP confidence.

Second app (the parity lab, crawl from `/` only on both sides, Burp scan 5
on a fresh project with the browser crawler): **21/21 issues identical**,
none Burp-only, none WebProbe-only
(`/tmp/parity-lab/burp-browser-crawl-scan5.json`,
`/tmp/parity-lab/crawl/webprobe-crawl-issues.txt`). This includes XXE on
`/xml`, which is only reachable by submitting the `text/plain` form on
`/xmlform`.

Tests: 304 passed, 0 failed, 9 ignored (live harnesses).

AI tab against a live model: `ai::tests::live_model_explains_an_exchange`
(ignored; WEBPROBE_AI_ENDPOINT/_MODEL/_KEY) passed against a free model
behind a local LiteLLM (nvidia/nemotron-3.5-super-vl:free, 9.4 s). In the GUI
(QA display), a typed question was sent and the model's answer was rendered
in the chat (`/root/webprobe-shots/ai3.png`).

Oracle note: Burp's Server-side JavaScript injection probe (burp.Zg_v,
timing-based, so not ported) crashes Juice Shop (unhandled ReferenceError in
marsdb `$where`). Juice runs under a restart watchdog during Burp scans, and
the scans use Burp's "Never stop crawl/audit due to application errors"
configs with 2 follow-up passes.

Still excluded: the time-based detection family (safety stop).

### Wave 40b: built-in browser (user-reported)

Fixed, each verified live on a separate display, as root, with burpsy
holding 127.0.0.1:8080 and a desktop Chromium already running:

- Root: Chromium refuses to run as root without `--no-sandbox`, and the old
  launcher reported success anyway. Now `--no-sandbox` is added for root, and
  a browser that exits with an error within 1.5 s is reported with its log
  line, then the next candidate is tried.
- Another instance running: `chromium` / `google-chrome` resolved to the
  /usr/local/bin xrdp wrappers, which pin a shared profile, so the launch was
  handed to the desktop browser (no proxy). Candidates are now absolute paths
  that skip profile-pinning wrappers. Each launch uses its own profile, and a
  stale SingletonLock left by a dead browser is cleared.
- No history / burpsy certificate: the browser used the main port (8080),
  which another tool held after WebProbe's bind failed. Like Burp's browser
  (`--proxy-server=localhost:<random>`), WebProbe's browser now has a private
  listener on a random loopback port. Chromium also sent loopback targets
  direct, so `--proxy-bypass-list=<-loopback>` (Burp's flag) is now passed.
- Certificate trust: the browser gets a private HOME whose NSS database trusts
  WebProbe's CA (certutil), so HTTPS loads with no warning. The CA persists
  across restarts in ~/.config/webprobe/ca.json (0600) and is rebuilt
  byte-identical.
- Upstream TLS accepts any server certificate, as Burp does by default
  (self-signed and private-CA targets failed with `CaUsedAsEndEntity`).
  Handshake signatures are still verified. The interactsh client keeps WebPKI
  verification.
- Background traffic: Burp's browser flags (`--disable-background-networking`,
  `--no-pings`, ...) plus seeded preferences (no omnibox suggestions,
  sign-in, Safe Browsing or prediction). The Google requests that went
  through the proxy are gone.
- http://webprobe (the setup page) is no longer recorded in history or
  scanned, matching http://burpsuite (live: Burp's history stays empty).
  The page shows the real listener port.
