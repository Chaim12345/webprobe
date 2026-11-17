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

### Wave 41 (2026-11-16): review fixes and Intruder payload types

- **Intruder payload types**: Burp's "Payload type" dropdown is wired to the existing generators, with per-type panels using Burp's wording: Simple list, Runtime file, Numbers, Dates, Brute forcer and Character blocks. Verified live with a Numbers 1–10 attack on the Juice bench.
- **Repeater**:
  - Tabs have stable ids and are numbered 1, 2, 3, ... without reuse, as in Burp.
  - Cancel now works: the in-flight send is abandoned.
  - Ctrl+I and Ctrl+R act on the current Repeater tab, as in Burp.
- **Project file**:
  - Autoloaded at startup, autosaved every 60 s when changed and on exit, like Burp's disk project.
  - Binary messages are stored byte-exact.
  - Restore no longer reuses ids.
- **Intruder results window**: now bounded to the screen. It used to grow off-screen and move under the first clicks.
- **Issue #2 medium items**, all verified first and then fixed:
  - Toasts drawn twice.
  - Onboarding Hide.
  - Stale Notes cache.
  - Collaborator start errors.
  - Inspector collapse state keyed by name instead of position.
  - Case-sensitive search in the Hex and Render views.
  - Header-line cap.
  - CA-step wording.
  - Orphaned settings modules deleted.
- **Not fixed, because they aren't bugs**: Comparer (one shared list with two selections is Burp's design) and the finished-scan card (it stays selectable).
- The sample-traffic test is now hermetic: a local upstream replaces example.com.

## Wave 42 (2026-11-16): four parallel agents, then a visual pass

Suite after the wave: 423 tests, 413 pass, 0 fail, 10 ignored. Screenshots: `/root/webprobe-parity/qa-w42/`.

| Area | Landed | Checked on the QA display | Open |
|---|---|---|---|
| Scanner | cookie/header/multipart/path insertion points with the 30-point cap; PHP code injection (echo), stored XSS, client-side template injection, XML injection out-of-band half (`active_checks.rs`) | not GUI work; loopback end-to-end scan test | entire-body/nested/XML-tag/parameter-name points; out-of-band resource load; Collaborator-everywhere; lab parity figure is stale |
| Intruder | all 19 payload types, Grep Match/Extract/Payloads, 10-worker runner with pause/throttle/retry, CSV and row menu | type list, Resource pool and Settings docks, a 3-request attack on local Juice Shop, row menu | grep columns, Pause/Resume, CSV save not exercised; payload processing rules not wired |
| Repeater / Proxy | follow redirects, paste URL, change method, tab management, editor context menu, Intercept held-messages table and Options menu, WebSocket hold/edit/forward, WebSockets history | context menu, settings menu, Follow redirection button, Options menu, WebSockets history (empty) | follow-and-enumerate; Copy as Python; Intercept-off empty state; clipboard root cause (UAT-06) |
| Project / tools | HTML and XML report, Logger CSV export, crash recovery, engagement tools, content discovery, fuller project file | Report issues window, an HTML report generated and inspected, site-map menu, Logger Export button | discovery/find/recovery windows unseen; report CSV; Logger shows Proxy traffic only |

Defects found and fixed in the pass: seeded history reused the last seeded id for the first real exchange (`main.rs`, test hook only); the Intercept Options button rendered as a missing glyph (`ui.rs`, now the phosphor icon).

QA rig note: a synthetic click that presses and releases inside one frame does not register on table rows; `/root/webprobe-parity/sclick.sh` holds the button for 0.25 s.

## Wave 43 (2026-11-17): architecture

Suite: 434 tests, 424 pass, 0 fail, 10 ignored, built with rustc 1.100 (`app/.cargo/config.toml`). Screenshots: `/root/webprobe-parity/qa-egui37-merged/`.

- **egui/eframe 0.29 -> 0.37.** Ported in an isolated copy and three-way merged. `theme.rs` restores the 0.29 look (button padding, text-edit margin, corner radius, glyph rasterisation, animation time). Eight main screens compared against the wave 42 screenshots. One regression found and fixed: the Intruder results window opened over the tab bar.
- **Scanner.** `scan_checks.rs` holds a `PointCheck`/`RequestCheck` registry; `start_active_scan` is a 44-line driver. `ScanIssue` gained `type_id` and `evidence` (confirming request/response, capped at 256 KB each); `report.rs` uses it. Guarded by `characterisation_active_scan_issue_list`.
- **Layering.** Engine modules no longer name UI modules: toast queue -> `notice.rs`, MIME families -> `mime.rs`, setup page -> `setup_page.rs`, `history_host` -> `net.rs`, Collaborator table state -> egui memory. Enforced by `layering_tests::engine_modules_do_not_depend_on_the_ui`.
- **Locking.** `sync::Mutex` hands out the guard after a panic on another thread; used by `net::Shared`, `App`, TLS, Intruder runner, discovery, extension host.
- **Logger.** `net::tool_scope("Repeater" | "Intruder" | "Scanner" | "Target" | "Sequencer")` tags a worker thread; `send_raw`/`send_tls_raw` record tagged exchanges in `Shared::tool_log`; the Logger collects them each frame.

Open: physical split into core and UI crates; splitting `Shared`/`App` by subsystem; disk-backed history; evidence in the project file; Collaborator ids on non-UI scan paths; `egui-mcp-client` hook. Build note: `wp-queue` always builds the live crate unless `WP_APP_DIR` is set.

## Wave 44 (2026-11-17): gaps from the QA passes

- Logger detail: tool rows carry their request/response (newest 500), proxy rows point at their history item; the old lookup compared Logger ids with history ids.
- Crawl & Audit scans draw Collaborator payloads from `Shared::oob_pool`, refilled on the UI thread while `oob_wanted`.
- Issue evidence and type id persist in the project file.
- HTTP history: Time column fits, request/response side by side.
- Intruder results window opens below the tab bar on egui 0.37.
Screenshots: `/root/webprobe-parity/qa-egui37-merged/13-history-layout.png`, `16c.png`.

## Wave 45 (2026-11-17): issue activity view

- `issue_view.rs`: Advisory / Request N / Response N tabs for the selected issue, fed by `ScanIssue.evidence` and the Burp knowledge base; severity, confidence and false-positive filter bar; selected-row highlight.
- Scan progress no longer shows more done than total (`scan_checks::bump_progress`).
- Checked with an active scan of `/rest/products/search?q=` on local Juice Shop: six issues, SQL injection with two evidence pairs (probe `q=apple'`, 500 response).
Suite: 441 tests, 431 pass, 0 fail, 10 ignored.

## Wave 46 (2026-11-17): issue grouping

Issues can be grouped by issue type or host (`issue_view::group_issues`, `grouped_list`): collapsible headers with counts, the most severe group first. Suite: 442 tests, 432 pass, 0 fail, 10 ignored.

## Wave 47 (2026-11-17): Sequencer depth

- `seq_bits.rs`: bit-level randomness analysis with Burp's rating thresholds (`Zr8b.ZF`) and summary wording; characters are converted to bits by the character set seen at each position.
- `analysis.rs`: `ln_gamma` had its leading terms negated, so every chi-square p-value was wrong; fixed with known-value tests.
- Sequencer tab scrolls; the manual-load box has a fixed height; Save tokens / Export analysis (CSV, JSON).
Suite: 448 tests, 438 pass, 0 fail, 10 ignored. Screenshot: `qa-egui37-merged/30c.png`.

## Wave 48 (2026-11-17): session-handling cookie jar

`cookie_jar.rs` (RFC 6265 storage and matching), `Shared::cookie_jar`, proxy feed in `net::record`, tool feed/apply in `send_raw`/`send_tls_raw` by `tool_scope`, Sessions settings panel. Defaults as in Burp: Proxy updates the jar, Scanner requests use it. Suite: 456 tests, 446 pass, 0 fail, 10 ignored.

## Wave 49 (2026-11-17): cookie jar persistence and editing

The cookie jar is saved in the project file (`ProjectCookieJar`, absent in older files) and can be edited by hand (Add cookie, Remove, Clear). Suite: 457 tests, 447 pass, 0 fail, 10 ignored.

## Wave 50 (2026-11-17): session rule actions

`net::apply_session_rules_for(tool, …)`: tool-scoped rules with set header, set cookie, use cookie jar, run macro, check session and post-request macro; applied in `send_raw`/`send_tls_raw` for the tool on the current thread and on proxy traffic for rules scoped to Proxy. Old project rules load as Proxy-only. Suite: 460 tests, 450 pass, 0 fail, 10 ignored.

## Wave 51 (2026-11-17): macro recorder and recorded logins

- `macros.rs`: multi-step macro text format with `derive=` (values from the prior response into query, form or JSON parameters).
- `net::run_macro_text`: steps run through the cookie jar; `Shared::macro_last_response` feeds `{name}` placeholders in session rule values.
- Sessions panel: "Add step" from the selected history item, "Test macro" with per-step results. The default macro text is empty (it used to name example.com).
Suite: 467 tests, 457 pass, 0 fail, 10 ignored. Screenshot: `qa-egui37-merged/39c.png`.

## Wave 52 (2026-11-17): menu bar

`menus.rs`: the six top-level menus follow Burp's item lists (decompiled Zc6t, Zpn_, Zcur, Zcu0, Zupi, Zup4); items with no backend are disabled. The Project file window (save / restore, previously unreachable from the UI) opens from the Project menu. Thirteen windows that had no explicit position now open below the tab bar (`theme::window_pos`); egui 0.37 put them over the menu bar. Suite: 469 tests, 459 pass, 0 fail, 10 ignored.

## Wave 53 (2026-11-17): site-map context menu

`engagement::site_map_menu` gained scope, passive/active scan of a host or branch (`scan::audit_entries`), Issues > Report/Delete, and Delete host/branch, with scan item names from `burp.Zeem`. Suite: 470 tests, 460 pass, 0 fail, 10 ignored.

## Wave 54 (2026-11-17): Repeater copy and compare

Request menu: Copy as Python requests, Copy raw request, Send request and response to Comparer, Compare response/request with the previous one. Suite: 472 tests, 462 pass, 0 fail, 10 ignored.

## Wave 55 (2026-11-17): Settings dialog

`settings_dialog.rs`: search, All/User/Project pills and Burp's category tree; pages reuse the existing panels (proxy options, session handling, scope editor, Collaborator settings, upstream proxy, appearance, hotkeys, project file, extensions) plus new Intruder, Repeater, Sequencer and Tasks pages. Suite: 474 tests, 464 pass, 0 fail, 10 ignored.

## Wave 56 (2026-11-17): Proxy settings page

- `intercept_rules.rs`: Burp's request interception rule table as an engine (operator, match type, relationship, condition; rows combined top to bottom), replacing the hard-coded extension list in `net::intercept_request`; saved in the project file.
- `proxy_settings.rs`: listeners table (Running, Interface, Invisible, Redirect, Certificate, TLS protocols; Add/Edit/Remove), CA export and regenerate (`tls::retire_ca`), rules table with Up/Down.
Suite: 478 tests, 468 pass, 0 fail, 10 ignored. Screenshots: `qa-egui37-merged/52c.png`, `53c.png`.

## Wave 57 (2026-11-17): settings save, load and restore defaults

Settings dialog > Manage settings. Implemented over the project format: a settings file is a project file with the data sections empty. Suite: 479 tests, 469 pass, 0 fail, 10 ignored.

## Wave 58 (2026-11-17): listener redirect

A listener can redirect every request to a fixed host and port (Burp's "Redirect to host / port"); origin-form plain HTTP requests are routed by their Host header on any listener. Suite: 481 tests, 471 pass, 0 fail, 10 ignored.

## Wave 59 (2026-11-17): response views and small defects

- Render tab shows PNG/JPEG/GIF responses as pictures (`image` crate, direct dependency); Pretty indents XML.
- Fixed: duplicate "Scope" label, seeded rows counted by onboarding, selection staying on a row the filter hides.
Suite: 484 tests, 474 pass, 0 fail, 10 ignored. Screenshot: `qa-egui37-merged/62c.png`.

## Wave 60 (2026-11-17): engine crate split and headless runner

- `app/core` is a new library crate, `webprobe-core`, holding the 33 engine modules (proxy, TLS, HTTP/2, scanner and its check registry, Intruder engine and runner, session handling, cookie jar, macros, project format, report generators, Collaborator, Logger store, Sequencer analysis). It has no GUI dependency; `layering_tests::engine_crate_has_no_gui_dependency` guards its manifest.
- `app` (the desktop app) depends on it; `app/Cargo.toml` is a workspace with `default-members = [".", "core"]`, so `wp-queue build|test` cover both crates.
- Moved into the engine: project-file conversions (`ProjectHistory::from_entry/to_entry`, `ProjectIssue::from_issue/to_issue`) and the report generators; the desktop crate keeps only the report options window.
- `webprobe-headless` (core/src/bin): `proxy` runs the intercepting proxy with the live passive scan and saves a project; `scan` audits URLs and prints JSON issues, `--report` writes the HTML report or XML export. Checked against local Juice Shop: 8 issues in 10-14 s; three proxied exchanges saved; the binary links no X11/GL library.
- Scans without a payload supplier no longer wait for Collaborator payloads (`Shared::oob_supplier`).
Suite: 486 tests (core 360, desktop 126), 476 pass, 0 fail, 10 ignored.

## Wave 61-62 (2026-11-17): multi-select and scan configuration

- `table::MultiSelect`: click / Ctrl / Shift / Ctrl+A selection in Proxy history; menu commands act on the whole selection.
- `scan_config.rs`: insertion point types and per-check switches, applied in `start_active_scan` / `run_point_checks` / `run_request_checks`, saved in the project, shown in Settings > Project > Tasks.
Suite: 488 tests (core 361, desktop 127), 478 pass, 0 fail, 10 ignored.

## Wave 63 (2026-11-17): fuzzing the parsers

`core/src/fuzz_tests.rs` (3000 seeded cases per run) found three panics and one wrong-output bug, all fixed with regression tests: `url_decode`, `parse_http_date`, `patch_header` (empty message; blank line re-emitted before the patched header, which broke upstream proxy authentication). Suite: 491 tests (core 364, desktop 127), 481 pass.

## Wave 64 (2026-11-17): robustness and performance

- Proxy connections are capped at 1024 per instance (`net::MAX_CONNECTIONS`); extras get a 503 (`Shared::active_connections`).
- Event-driven redraws: the engine calls `Shared::wake` on log lines, new history, held messages and WebSocket frames, `notice::toast` wakes too; the UI redraws every 1 s when idle (200 ms while a tool works). Idle CPU with 10k rows: 142 -> 28 ticks / 5 s.
- History shows every row (the 1,000-row cap is gone); the filtered view is shared per frame and grows incrementally.
Suite: 492 tests (core 365, desktop 127), 482 pass, 0 fail, 10 ignored.

## Wave 65 (2026-11-17): build speed and site map

- Build speed: a from-scratch build is ~474 s even with no queue at 12 jobs (the queues add ~1 s; incremental edit-and-build is 2-12 s). sccache was disabled by `rustc-wrapper = ""` in `app/.cargo/config.toml`; it is now enabled, and a warm-cache from-scratch build takes 96 s (257/257 dependency crates from cache). The remaining time is proc-macro crates (uncacheable) and the two workspace crates. Stripping dependencies is not needed for speed. A 434 s test build seen earlier was a one-off: a `RUSTC_BOOTSTRAP=1` profiling run had invalidated every dependency.
- Site map: filter bar, scope colouring, issue markers, Comment column; contents cached by input key.

## Wave 66 (2026-11-17): queue flow, Inspector editing, private Collaborator, extension API

- Scan queue: "Do active scan" (Repeater, history menus) is now a queued task (`TaskKind::Single`, with the Collaborator and SMTP payloads prepared by the UI). Before, `start_active_scan` silently refused it while any queued task was running. The direct-scan card is numbered after the task numbers; it used to share "3." with the first task.
- Inspector editing (E-01): `core/src/inspector.rs` models the sections and applies an edit, add or remove to the raw request (attributes, query, form body with Content-Length restamped, cookies, headers; keeps bare-LF requests as LF). Repeater's Inspector has Apply changes / Remove / Cancel / Add. The request editor's Hex tab is editable (virtualized byte cells; the cell after the last byte appends).
- Private Collaborator (I-04): interactsh server given as `host[:port]` with an optional auth token (`Authorization` header), live poll interval, interaction retention, settings saved with the project (not the token), `docs/collaborator-private-server.md`.
- Extension API (K-01): WebProbe extension API v1, any executable speaking JSON lines (`docs/extensions.md`). It covers hooks that edit or drop messages, issue definitions and reported issues, a custom tab, a 2 s deadline per call, and a stop after 3 failures or on exit with pass-through afterwards. stderr goes to Errors. Example: `extensions/examples/marker_reflection.py`. Hooks for all extensions now run on a snapshot outside the registry lock, so a slow extension no longer serializes every proxied connection.
- Extension manager (K-03, partial): load in the background (the dialog used to block the UI while a JVM started), list saved to `extensions.json` in the config dir and reloaded at start-up, Details show source, status, issue types and the extension's tab. Sidecar JVM stderr is captured (K-02).
- Warnings: unused imports and needless `mut` removed, deprecated `Id::new` replaced.

Suite: 519 tests (core 388, desktop 131), 509 pass, 0 fail, 10 ignored.

## Wave 67 (2026-11-17): egui MCP made fully usable; more flow fixes

UI automation over egui-mcp now works end to end against WebProbe on Xvfb. Checked tool by tool on :97: check_connection, get_ui_tree, find_by_label / find_by_label_exact, get_bounds, is_visible, click_element, set_text, get_text, click_at, keyboard_input, scroll, drag, take_screenshot, screenshot_element.

- **Widget tree was empty.** AccessKit names the app after its executable (`webprobe`). The server matched "WebProbe" case-sensitively. The match is now case-insensitive.
- **Every node had id 0.** AccessKit 0.25 puts 128-bit node ids in AT-SPI paths, and the server parsed them as `u64`. Ids are now folded to 53 bits so JavaScript clients keep them exact. All lookups use the same function, so the tree has no zero ids and the element tools work. The server is vendored at `vendor/egui-mcp-server`, with a test.
- **Keyboard lost characters.** The stock client turned single letters into key presses with no text, and named keys (`space`) were typed literally. `mcp_hook::key_events` now handles:
  - text, which types itself, so a whole string can be typed in one call;
  - key names, including X11 spellings;
  - `ctrl+a` / `shift+Tab` combos, with ctrl+c and ctrl+x as Copy and Cut;
  - `text:` for literal words that are also key names.
  - All agent inputs share one ordered queue, one step per frame, so a key never overtakes the click that focused its field. 3 tests.
- **Socket stolen.** A second app instance deleted and rebound the shared `egui-mcp.sock`, cutting the first app off. It now refuses with a message. `EGUI_MCP_SOCKET` (client and server) gives each app its own socket.
- **Unnamed fields.** The request editor and the search boxes now carry accessible names ("Request", "Search").
- **Card clicks stolen.** The Dashboard task card's click area was registered after its menu and pause buttons and took their clicks. It is now registered first. Long titles are truncated before the buttons.
- **Phantom card.** Deleting a task brought back a stale "Active scan" card; that card now only shows direct (non-queued) scans (`Shared::direct_scan`). A cancelled item no longer counts as done.
- **Proxy bind failure.** It now raises an error toast with Burp's wording.
- **Background loading.** Collaborator server registration runs in the background (it used to freeze the UI for up to 10 s on a slow server). Extension start-up gets its own 20 s deadline, separate from the 2 s hook deadline.
- **QA rig.** `qa/qa.sh` tracks the app by PID file and stops its process group; matching by name missed `QA_BIN` copies and left orphans holding the proxy port.

GUI-verified this wave over MCP:
- Inspector parameter edit: `q=a%20b%26c` in the request line, decoded value shown;
- hex byte edit;
- loading a process extension: header added, `/blocked` dropped, issue reported, custom tab counters;
- queued "Active scan selected message" task, then pause, cancel and delete from its card.

Suite: core 390 (380 pass, 10 ignored), desktop 134, 0 fail.

## Wave 68 (2026-11-17): GUI verification sweep, save deadlock, site map compare, session recovery

- **Save deadlock (critical).** `tools::save_project` locked `scan_config` twice inside one struct literal. Rust keeps the first guard until the end of the statement, so every save hung the UI: New project, Save, autosave. It also held about 17 shared locks at once, in an order opposite to the scan task runner (issues then tasks here, tasks then issues there).
  - Each locked field is now computed in its own statement.
  - A scan of the whole tree finds no other statement that locks one mutex twice.
  - Regression test `project_save_completes_and_restores` (60 s timeout). It runs through the new `App::new(shared)` constructor; the App literal moved out of `main()`, so desktop flows can be tested.
- **Accessibility for automation.** Hand-painted widgets now carry accessible names and roles: main tool tabs, sub-tab strips, side docks, the filter bar, toggles and table column headers. Agents can click a tool tab by name (`/root/webprobe-parity/egui-click.sh LABEL ROLE`).
- **Comparer (F-03).** The results window has Text|Hex views (`compare::hex_spans`) and Sync views; Sync views is off by default, as in Burp's `user_options.comparer.sync_views`. A Bytes compare opens in Hex. Merge and three-way compare are dropped: Burp's Comparer documentation lists only Words, Bytes, Sync views, Text and Hex.
- **Compare site maps (Target).** New feature, matching Burp's wizard:
  - sources: current site map, a project file, or site map 1 re-requested in the current session context as the Target tool;
  - request matching: path, method, query/body by names or names and values with ignore lists, headers;
  - response comparison: ignored headers and form fields, whitespace, text-only;
  - a results table (Deleted / Added / Modified / Unmodified) with both responses diffed.
  - Engine in `core/src/sitemap_compare.rs`, 4 tests.
- **Session handling (H-04).** "Check session" gains Burp's "Prompt for in-browser session recovery". The request waits, a Session recovery window offers Open browser / Done / Cancel, and the request continues with the cookies the proxied login put in the jar. Test `browser_recovery_waits_for_the_login_and_uses_the_new_cookie`.
- **Settings (J-03).** Per-page "Restore defaults" (`project::with_section_defaults`, test).
- **Intruder (C-07).** Results save as XML with base64 messages, alongside CSV (test).
- **Sequencer (G-01).** The cookie list selects a cookie the response actually sets; it used to stay on a stale "session".
- **GUI-verified over MCP this wave:**
  - D-05: card pause, menu cancel and delete; no phantom card.
  - F-03: character and byte compares, Hex view.
  - G-01: live capture over HTTP and TLS, stop after 200, auto analyse.
  - J-04: corrupt file rejected; New project written and added to the recent list.
  - Site map comparison run.
- **N-05.** Release startup to a mapped window takes 871 ms cold and about 410 ms warm. An incremental release rebuild takes 65 s (the desktop crate is 58 s of it). The cache misses after a target-dir change: sccache keys include the target directory.
- **Proxy listener restart (fix).** The listener only re-read its port after the next client connected (blocking accept). A restored project with port 8080 would therefore have moved the proxy onto 8080 at the next request. It now polls a non-blocking accept and moves at once (test `primary_listener_moves_on_restart_without_a_connection`). An explicit `WEBPROBE_PORT` now wins over a project's saved port.
- **GUI-verified:** H-04 in-browser session recovery end to end, and J-02 crash recovery prompt then restore.
- **Repeater destination (fix).** Requests went wherever the Host header pointed, ignoring the tab's Target. Burp sends to the Target, so Host-header attacks reach the real server. A tab without a target now takes it from the Host header. GUI-verified: Target 127.0.0.1:18780 with `Host: evil.example` got the lab's page.
- **Clean shutdown on SIGTERM/SIGINT** (signal-hook): the app closes through `on_exit` (project saved, session marker removed), so a terminated instance no longer triggers the crash-recovery prompt. Verified: stopped in under 1 s, next start had no prompt.
- **Accessibility.** Repeater tabs are now exposed as Tab elements.
- **GUI-verified:** E-04 duplicate, rename and drag-reorder of Repeater tabs, persisted in order by autosave; E-02 redirect handling; UAT-06 clipboard paste.
- Find references resolves relative links like the crawler (fix; L-02). GUI-verified L-02 Find references and L-03 Discover content (no false finds on a catch-all host; real files and directories found and recursed on a static lab server).
- **MCP idle CPU.** The MCP hook's 100 ms polling repaint is gone. The vendored client wakes the UI when an IPC request arrives (`McpClient::set_waker`). Idle CPU on Xvfb software GL dropped from ~110% of a core to ~11%.
