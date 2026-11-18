# R-07 WebSocket research — Burp Suite vs WebProbe

> **Delegated research (2026-11-18), not fully reviewed.** Written by free models (some sections re-verified by a second model) as leads for the task in the title; confirm each class:line before relying on it.

## Verification pass — 2026-11-18

**Claims checked: 67 — 15 right, 47 corrected, 0 deleted, 5 still not established.** The unit is one
original research paragraph/bullet, settings item, comparison row, robustness point, work item, test
reference, or open question; scope/provenance boilerplate is excluded. Corrections to subordinate
wording are counted within their claim unit; no whole original claim unit had to be deleted. This was
a static source/citation review: no build, test, git, or network operation was performed.

The five still-open claim units are the Repeater/connection/algorithm defaults in §2 and §6 items 1
(permessage-deflate implementation), 3 (Burp continuation reassembly), 5 (Burp numeric history cap),
and 7 (additional specific tool destinations). Narrower open questions inside corrected claims are
recorded in §6.

**Corrections made (old -> new; related corrections grouped):**

1. **Proxy documentation anchors:** §1.2 `proxy.html:91-96` and rule-builder `:75-81` ->
   `settings/tools/proxy.html:304-320` and `:229-271`; §1.3 settings `:113-116` -> `:374-382`; §1.6
   strip-header `:184` -> `:597`; §2 display-option docs `:155-159` -> `:493-526`. The cited sections
   now contain the claimed WS controls, match/replace settings, extension stripping, and display
   options respectively.
2. **Burp class anchors and WS directions:** §1.5 `Zs7j.java:18-49` -> `buildMenu` at `:24-49` (with
   Edit at 28, Repeater at 33, Decoder at 38, documentation at 49); `Zxvb.java:14-16` -> `:19-21`
   for `CLIENT_TO_SERVER`/`SERVER_TO_CLIENT`/`BOTH_DIRECTIONS`.
3. **Unsupported compression-search/location wording -> bounded search result:** the "~80" class
   count and guessed implementation location were removed. The permitted class-tree search actually
   found no `permessage` literal and no WebSocket-mentioning class also using
   `java.util.zip`/`Inflater`/`Deflater`; `settings/tools/proxy.html:597`, `Zrv7.java:218`, and
   `Zw9d.java:105-106` remain the positive evidence.
4. **Two payload slots and "flags/length" -> three slots and identified metadata:**
   `Zxrm.java:11-27` has `ZcL`, `Zce`, and `Zc1`; `Zf9v.java:62-64` constructs the original from
   bytes; `Zpai.java:23-54` uses `ZcF()` as the connection identifier. The old `ZcY()`/`ZcF()`
   description was wrong.
5. **Blanket Burp control/masking unknowns -> limited positive evidence plus narrower unknowns:**
   `Zh98.java:10-17` establishes frame kinds, `Zprb.java:21-29` a Repeater PING->PONG path, and
   `Zs8.java:11-12` + `Zb60.java:19-21` masking of locally generated client-to-server frames. Proxy
   control behavior, continuation reassembly, incoming mask validation, and fresh-mask-on-edit remain
   unproven. Corresponding §3 rows and §6 items 2/4 were narrowed.
6. **"Persistence mechanism not established" -> project serialization/import established:**
   `Zuwa.java:28-40`, `Zf9f.java:71-85`, and `Zf9v.java:122-165`. Only exact physical format and
   rolling retention policy remain open (§6.6).
7. **Defaults search wording -> complete accounting:** display-filter citation `:582-601` ->
   `ProjectDefaults.json:582-603`. The literal `socket` hits are now listed as the five locations
   `ProjectDefaults.json:23,441,547,582` and `UserDefaults.json:491`; the two separate `ws_` keys are
   at `ProjectDefaults.json:537-538`.
8. **Stale WebProbe anchors with unchanged verdicts -> current anchors:** examples include
   `ws_history_view` `src/repeater_ops.rs:1714-1828` -> `:1719-1846`, `WsFilter` `:975-984` ->
   `:977-986`, `ws_should_hold` `core/src/net.rs:2669-2676` -> `:2790-2797`, and default interception
   `core/src/project.rs:650-651` -> `:682-697`. The same refresh was applied to the related history,
   filter, logging, direction, edit, send-to, masking, close, and persistence citations; evidence is
   inline in §3-§4.
9. **History-column assessment -> one additional concrete gap:** the fixed header is now cited at
   `src/repeater_ops.rs:1779-1780`, and the URL cell is specifically host-only at `:1801`; the other
   missing Notes/TLS/listener/WebSocket-ID columns and extra Opcode remain.
10. **HTTP annotation citation -> proof of WS absence:** `src/ui.rs:869/937` -> the HTTP menu and its
    `shared.history` update at `src/ui.rs:876-956,1078-1085`, together with annotation-free
    `core/src/ws_history.rs:15-28`.
11. **Only-in-scope interception Missing -> Covered:** `core/src/net.rs:2916`,
    `src/ui.rs:1192-1196`, and `src/tools.rs:1861,2129`.
12. **WS match/replace Missing -> Partial:** ordered text/binary rules and scope exist at
    `core/src/ws_rules.rs:12-77`, `core/src/net.rs:2931-2938`, and `src/proxy_settings.rs:398-460`;
    only Both-directions is still absent (`ws_rules.rs:16-17,43-50`; `proxy_settings.rs:419-424`).
13. **Binary/text Partial with String history -> Covered with byte history:** both opcodes reach
    `ws_message` (`core/src/net.rs:2853-2888`) and payloads are `Body` (`core/src/ws_history.rs:15-35`).
    §4.1 was correspondingly changed from "history corrupts all binary payloads" to raw-byte history
    plus base64 persistence (`core/src/project.rs:353-387`), with only invalid-UTF-8 Intercept editing
    still lossy (`core/src/net.rs:2939-2957`).
14. **History storage/UI review -> current implementation:** the old `Mutex<Vec<WsEntry>>` description
    is now unbounded `RwLock` rows with file-backed body spill (`core/src/ws_history.rs:42-80`;
    `core/src/body.rs:243-271`) and project save/load (`src/tools.rs:1834,2049`). The old full-clone
    finding is now stamp/filter-key invalidation plus visible-window reads
    (`src/repeater_ops.rs:1765-1797`); cross-tool text copies occur on Search-button clicks
    (`src/tools.rs:824-825,858-868`), not every query/repaint.
15. **Oversize raw relay -> close 1009:** `core/src/net.rs:2526-2528,2617-2619,2823-2837,2853-2857`.
    The old `raw_left` and placeholder-account claims were removed; `parse_ws_frame`'s separate
    oversize branch is explicitly distinguished at `:2562-2567`.
16. **No fragmentation/compression handling -> both implemented, validation narrowed:**
    continuation assembly and 1002 errors are at `core/src/net.rs:2806-2814,2844-2888`; RSV1
    inflation is at `:2715-2742,2904-2915`. Reserved opcodes, RSV2/3, control FIN/length, and mask
    direction remain the specifically cited validation gaps. §3 and §4.5/4.7 were updated together.
17. **"Compression not implemented"/"passes through" -> default strip plus optional inflate:** plain
    and TLS stripping is at `core/src/net.rs:2691-2713,3071-3073,3199-3201`; agreement and
    decompression are at `:2677-2689,2715-2742,2904-2915,2981-3000`; forwarded changed messages are
    plain at `:2967-2973`. Burp algorithm parity remains unassessable.
18. **Masking review -> current raw/rebuild paths, same validation gap:** unmasking is
    `core/src/net.rs:2562-2578`, fresh changed-frame masking `:2585-2614,2971-2973`, and unchanged
    raw forwarding `:2967-2969`. Burp generated-frame evidence was added as in correction 5; incoming
    validation was not invented for either implementation.
19. **Close/stall absolutes -> current behavior:** ordinary close frames still record/forward without
    a proxy echo (`core/src/net.rs:2844-2851`), while error closes use `:2823-2833`. Plain relay now
    requests 120-second write timeouts (`:18,3003-3008`) but retains blocking reads/join
    (`:3016-3061`); TLS has per-write deadlines (`:3114-3186`) but no overall idle deadline.
20. **Completed or overbroad work items -> remaining-work plan:** former raw-byte, repaint,
    scope-interception, extension/deflate, fragmentation, and oversize steps are marked implemented
    by the evidence above; WS rules and stall hardening are partial. "Mirror Burp's bounded model" was
    replaced with a WebProbe policy choice because Burp has no established cap. Repeater and send-to
    remain, now ordered as Steps 4-5 with the current HTTP sender (`src/repeater_ops.rs:379-395`) and
    loopback fixture (`core/src/net.rs:5110-5207`). Test anchors `core/src/net.rs:4751+` and
    `src/repeater_ops.rs:2208+` were replaced with `core/src/ws_tests.rs:22-216`,
    `core/src/ws_history.rs:125-163`, `src/repeater_ops.rs:1848+`, and the loopback fixture above.
21. **Open-question cleanup:** §6.2, §6.4, §6.6, and §6.8 were narrowed using the new evidence above.
    In particular, `Zb7v.java:37-85` identifies qualified `net.portswigger.Zqb` readers and
    `Zpqr.java:12-25` qualified `net.portswigger.Zkn` output, without pretending their unavailable
    implementations establish fragmentation, validation, or limits. Unrelated `strings/*.tsv` search
    narration and speculative package-location claims were removed inside the corrected units.

Line numbers are a snapshot taken during the 2026-11-18 verification pass; the code is being edited
concurrently by other agents, so function names are the stable anchor.

Read-only research. Documentation paths are relative to
`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/`; Burp class paths are
relative to `/root/burp-re/out/readable_strict/root/`; WebProbe paths are relative to
`/root/Documents/Craft Anything/burpsuite/app/`. Anything not established is marked explicitly.

## 1. Burp WebSocket features (documentation / class evidence)

### 1.1 WebSockets history
`tools/proxy/websockets-history/index.html:37-50` says that the Proxy WebSockets history records
messages exchanged by Burp's browser, supports viewing/interception/modification, and can send
messages to other tools. Its documented columns (`:53-85`) are `#`, `URL`, `Direction`, `Edited`,
`Length`, `Notes`, `TLS`, `Time`, `Listener port`, and `WebSocket ID`; the descriptions identify
length in bytes and the ID as Burp's internal connection ID. The history "is always updated, even
if Intercept is off" (`:87-89`). Right-click actions, table sorting/customization/copying, custom
columns, pop-up and extra history windows, Inspector, and notes are documented at `:91-162`.

`tools/proxy/websockets-history/filter-settings.html:51-54,62-107` documents Settings and Script
modes, with Settings filters for scope, incoming/outgoing direction, literal/regex search,
case-sensitivity, negative search, annotations, and listener port. Java scripts use
`ProxyWebSocketMessage` and `Utilities` (`tools/proxy/websockets-history/scripts.html:206-220`);
the example at `:271-291` is
`return message.payload().length() > 300 && message.direction() == Direction.SERVER_TO_CLIENT;`.
Java-based custom columns are Professional-only
(`tools/proxy/websockets-history/custom-columns.html:36-41`). Notes and highlights, including
annotations made in Intercept and propagated to history, are documented at
`filter-settings.html:113-146`.

### 1.2 Interception of WebSocket messages
`settings/tools/proxy.html:304-320` defines the project settings `Intercept client-to-server
messages`, `Intercept server-to-client messages`, and `Only intercept in-scope messages`; the
scope check is based on the upgrade request. The AND/OR, match-type, relationship, and condition
rule builder is in the separate request/response interception section (`:229-271`), not in the
WebSocket section. Defaults are in §2.

### 1.3 Match and replace for WebSocket messages
`tools/proxy/match-and-replace/creating.html:41-99` documents Settings-mode rules for HTTP and
WebSocket messages. WS fields are `Direction` (Client to server / Server to client / Both
directions), `Match`, `Replace`, optional `Comment`, and `Regex match`; `Type` is for HTTP requests.
Script mode is HTTP-only (`:146-149`). Enabled rules run in order and can be reordered, with an
optional `Only apply to in-scope items` setting (`tools/proxy/match-and-replace/index.html:39-57`;
also `settings/tools/proxy.html:374-382`). Class evidence agrees: `Zxvb.java:19-21` declares the
three WS directions, `Zg5h.java:163-239` builds the field editor, and `Zrdi.java:63-66,91-105`
links the two WS settings keys and the in-scope checkbox.

### 1.4 WebSocket Repeater
`tools/repeater/websocket-messages.html:47-75` documents Send to Repeater, editing/resending, and
choosing server or client as destination; sending to a client requires a connection still open via
Burp Proxy. The tab has an editor, an automatically selected connection, disconnect/reconnect and
connection editing, negotiation-request manipulation, a sent/received history, `Select next message
received`, and a selected-message viewer (`:78-114`). Connection editing supports Clone, Attach,
new connections, and reconnecting closed ones. `Zrs9.java:356-427` independently shows the
WebSocket ID header, Send/Reconnect controls, and the checkbox.

The handshake workflow is explicit at
`testing-workflow/vulnerabilities/websockets/manipulating-websocket-handshakes.html:64-108`:
Send to Repeater → edit icon → Clone → change Host/Port/Use HTTPS and the request → Connect →
select the new connection → Attach.

### 1.5 Sending WebSocket messages to other tools
The documentation evidence is `tools/proxy/websockets-history/index.html:49,91` and
`tools/repeater/websocket-messages.html:51-55`. `Zs7j.java:24-49` builds the WS-history menu with
`Edit and resend`, `Send to Repeater`, `Send to Comparer`, `Send to Decoder`, extension items under
`CONTEXT_WS_HISTORY`, deletion, Clear history, and Repeater documentation. Telemetry names exist
for Send WebSocket to Repeater (`Zpbb.java:15`), WS-history item added (`:60`), and WS notes side
panel/table cell clicks (`:65-66`). No additional specific destination is established here.

### 1.6 Compression / permessage-deflate
`settings/tools/proxy.html:597` says that Burp strips `Sec-WebSocket-Extensions` by default because
some encodings cause processing problems, and that the setting can be disabled. The UI label is at
`Zrv7.java:218`; `Zw9d.java:105-106` removes `sec-websocket-extensions` from the request when the
corresponding setting is enabled. Its default is true in `ProjectDefaults.json:547` (§2).

Burp's own permessage-deflate decompression/recompression implementation is **not established**.
A recursive search of the permitted class tree found no `permessage` literal and no
WebSocket-mentioning class that also referenced `java.util.zip`, `Inflater`, or `Deflater`; this is
a search result, not proof that the implementation is absent.

### 1.7 Binary vs text frames, control frames, limits, masking, and storage
- **Text, binary, and frame kinds:** `Zsdk.java:43-46,71-73` imports the Montoya text/binary action
  types. Factory methods at `:499-525` create text/binary continue/drop/actions, and `:529-585`
  exposes initial/final proxy lifecycle actions including follow-user-rules, intercept,
  do-not-intercept, continue, and drop. The lower-level enum `Zh98.java:10-17` declares `TEXT`,
  `BINARY`, `PONG`, `PING`, `CONTINUATION`, `CLOSE`, and `EXTENSION`. These citations establish the
  exposed payload types and frame taxonomy, not fragmentation reassembly.
- **Payload and metadata storage:** `Zxrm.java:11-27` has three `Zx9j` payload slots (`ZcL`, `Zce`,
  `Zc1`) rather than two. `Zx9j.java:12-16,39-41` exposes bytes and only converts to a String when
  asked; `Zf9v.java:62-64` constructs the original payload directly from `byte[]`. `Zs5z.java:29-39`
  stores the original bytes, byte frame type, and connection integer; `:101-143` returns the three
  payloads and metadata. `ZcF()` is used as a WebSocket connection identifier by
  `Zpai.java:23-54`, not as the payload length. The original note's "flags/length" description of
  `ZcY()`/`ZcF()` was therefore incorrect.
- **History model, project import, and bounds:** `Zf9v.java:14` extends `Zf9f<Zxrm>`;
  `Zf9f.java:10-32` extends the list-backed `Zf9_` and owns a `CopyOnWriteArrayList` of listeners,
  with add/remove/clear at `:45-61,88-105`. Index counters are at `Zf9v.java:93-114`. This shows a
  list-backed live model; no numeric cap appears in these cited classes, but a suite-wide numeric
  cap is **not established** either way. Project persistence is not wholly unknown:
  `Zuwa.java:28-40` serializes a `wsHistoryItem`, while `Zf9f.java:71-85` and `Zf9v.java:122-165`
  load imported items into the model. The exact on-disk representation and any rolling-log policy
  remain **not established**. Shutdown entry-count telemetry is at `Zpk5.java:497-499` and
  `Zbtp.java:16-17`.
- **Ping/pong and masking evidence:** in the Repeater receive path, `Zprb.java:21-29` explicitly
  responds to a `PING` by sending `PONG` with the same payload. For locally generated frames,
  `Zs8.java:11-12` chooses a random four-byte mask for client-to-server and no mask for
  server-to-client; `Zb60.java:19-21` puts that metadata into the frame. The Proxy edit path does
  not generate a fresh mask: `Zcng.java:44-50` carries the existing mask flag/key into a payload
  replacement, and `Zbz5.java:148-156` reuses `this.ZP.ZT()`/`this.ZP.ZR()` with the edited payload.
  Incoming mask validation and any fresh-random-mask-on-edit policy are **not established**. Burp's
  Proxy-side close-handshake behavior, continuation reassembly, and frame/message size limits are
  also **not established** from the permitted sources.
- **Handshake detection:** `Zfw5.java:20-22` lowercases the request bytes and checks for both
  `connection: upgrade` and `upgrade: websocket`.

## 2. WebSocket settings keys and defaults

Sources: `/root/burp-re/in/extract/resources/Preferences/ProjectDefaults.json` and
`/root/burp-re/in/extract/resources/Preferences/UserDefaults.json`, checked by full JSON-path walk.

Project settings (`ProjectDefaults.json`):
- `bambda.web_sockets_history_display_filter` = `{"bambda":"return true;","bambda_id":"","bambda_name":""}`
  (`:23-27`), a pass-through Script-mode history filter.
- `proxy.intercept_web_sockets_messages` =
  `{"client_to_server_messages":true,"server_to_client_messages":true,"intercept_in_scope_only":false}`
  (`:441-445`).
- `proxy.miscellaneous.strip_sec_websocket_extensions_headers_in_incoming_requests` = `true` (`:547`).
- `proxy.web_sockets_history_display_filter` (`:582-603`) =
  `{"by_annotation":{"show_only_commented_items":false,"show_only_highlighted_items":false},"by_listener":{"listener_port":""},"by_request_type":{"hide_incoming_messages":false,"hide_outgoing_messages":false,"show_only_in_scope_items":false},"by_search":{"case_sensitive":false,"negative_search":false,"regex":false,"term":""},"filter_disabled":false,"filter_mode":"SETTINGS"}`.
- `proxy.ws_match_replace_rules` = `[]` and `proxy.ws_match_replace_disable_out_of_scope` = `false`
  (`:537-538`).
- Non-WS context: `proxy.match_replace_rules` is a list of disabled HTTP rules (`:446-535`) and
  `proxy.match_replace_disable_out_of_scope` = `false` (`:536`).

User setting (`UserDefaults.json`):
- `user_options.proxy.default_display_message.websocket` = `"original"` (`:487-492`). The documented
  choices are Original, Edited, and Auto-modified (`settings/tools/proxy.html:493-526`).

A literal case-insensitive `socket` search of both JSON files finds only the five key locations at
`ProjectDefaults.json:23,441,547,582` and `UserDefaults.json:491`. The two abbreviated `ws_` keys do
not contain `socket`; they are separately visible in the complete `proxy` object at
`ProjectDefaults.json:309-604`. Thus the original broad-search wording was incomplete, but the six
project WS keys and one user WS key above are accounted for.

No dedicated WS-Repeater, WS connection-limit, or permessage-deflate algorithm key appears in the
`repeater` object (`ProjectDefaults.json:605-616`) or the WS keys above. Defaults for those specific
features are **not established** from these files; this does not negate the extension-stripping
default at `:547`.

## 3. Feature comparison: Burp vs WebProbe

All WebProbe locations below are relative to the app root named above. "Missing" refers to the
located implementation, not a claim that no unexamined code could exist.

| Feature | Burp (evidence) | WebProbe (file:line) | Gap / verdict |
|---|---|---|---|
| WS history view | `tools/proxy/websockets-history/index.html`; model `Zf9v.java:14` | `src/repeater_ops.rs:1719-1846` (`ws_history_view`) | Partial |
| History columns | `index.html:53-85` | Fixed header at `src/repeater_ops.rs:1779-1780`; cells at `:1799-1807` | Missing Notes, TLS, Listener port, WebSocket ID; URL cell contains only `e.host` (`:1801`); extra Opcode |
| History filter (Settings) | `filter-settings.html:62-107`; `proxy.web_sockets_history_display_filter` | `src/repeater_ops.rs:977-986,998-1022`; UI `:1725-1763` | Partial: scope/direction/search/regex/case/negative covered; annotation and listener-port filters missing |
| History filter (Script/Bambda) + custom columns | `scripts.html:206-220`; `custom-columns.html:36-41` | Bambdas explicitly unsupported at `src/tools.rs:1232-1233`; fixed WS header at `src/repeater_ops.rs:1779` | Missing |
| History annotations (notes/highlight) | `filter-settings.html:113-146` | `WsEntry` has no annotation fields (`core/src/ws_history.rs:15-28`); the notes/highlight menu updates HTTP `shared.history` (`src/ui.rs:876-956,1078-1085`) | Missing |
| Logging while Intercept is off | `index.html:87-89` | `ws_should_hold` only gates the hold (`core/src/net.rs:2790-2797`); control and data recording is unconditional at `:2846-2850,2967` | Covered |
| WS interception: client→server / server→client | `settings/tools/proxy.html:304-320`; `Zrd9.java:54,78,86` | `core/src/net.rs:2790-2797`; flags `:871-878`; UI `src/ui.rs:1182-1190` | Covered |
| WS interception "Only in-scope" | `settings/tools/proxy.html:315-320`; `ProjectDefaults.json:441-445` | Scope condition at `core/src/net.rs:2916`; UI `src/ui.rs:1192-1196`; persistence `src/tools.rs:1861,2129` | Covered |
| Intercept editing / drop / forward | `index.html:37-50`; `Zsdk.java:529-585` | Queue/edit/drop at `core/src/net.rs:2939-2957`; unchanged raw forward and changed-frame rebuild at `:2967-2973` | Covered; interactive text editing is still lossy for invalid UTF-8 (§4.1) |
| WS match & replace | `creating.html:41-99`; `Zxvb.java:19-21`; `Zrdi.java:63-66` | Ordered byte/text rules at `core/src/ws_rules.rs:12-77`; application and scope at `core/src/net.rs:2931-2938`; editor `src/proxy_settings.rs:398-460` | Partial: two directions, match/replace/regex/comment/reorder/scope covered; Both directions is absent from model and UI (`ws_rules.rs:16-17,43-50`; `proxy_settings.rs:419-424`) |
| WS Repeater: send-to/clone/attach/reconnect, handshake editing, history, select-next | `tools/repeater/websocket-messages.html`; `manipulating-websocket-handshakes.html`; `Zrs9.java:356-427` | Existing send path is HTTP (`src/repeater_ops.rs:379-395`); WS history view has no Repeater action (`:1719-1846`) | Missing |
| Send WS message to Repeater/Comparer/Decoder | `Zs7j.java:24-49` | No context menu in `src/repeater_ops.rs:1719-1846`; cross-tool search includes WS rows at `src/tools.rs:858-868` | Missing except search |
| Binary vs text messages | `Zsdk.java:43-46,499-585`; `Zh98.java:10-17` | Types at `core/src/net.rs:2514-2523`; both opcodes enter `ws_message` (`:2853-2888`); byte payloads at `core/src/ws_history.rs:15-35` | Covered for capture, history, rules and interception; invalid-UTF-8 interactive edit caveat (§4.1) |
| Fragmentation / continuation | `Zh98.java:15` establishes the kind only; reassembly not established | Reassembly and protocol errors at `core/src/net.rs:2806-2814,2853-2888` | WebProbe covered; Burp reassembly not established |
| Control frames ping/pong/close | `Zh98.java:13-16`; Repeater PING→PONG at `Zprb.java:21-29`; Proxy behavior not established | Names at `core/src/net.rs:2514-2523`; immediate record/forward at `:2846-2851` | WebProbe recording covered; Burp Proxy behavior not established |
| Permessage-deflate / extension negotiation | Strip behavior `settings/tools/proxy.html:597` and `Zw9d.java:105-106`; Burp algorithm not established | Strip helper `core/src/net.rs:2691-2713`, calls `:3071-3073,3199-3201`; agreement/inflation `:2677-2742,2904-2915` | Documented strip behavior covered; WebProbe also inflates for history/edit and forwards plain; Burp algorithm parity not assessable |
| Masking / fresh mask on changed client frames | Locally generated masking `Zs8.java:11-12` and `Zb60.java:19-21`; Proxy edit preserves existing mask metadata (`Zcng.java:44-50`, `Zbz5.java:148-156`); validation/fresh random mask not established | Unmask `core/src/net.rs:2562-2578`; rebuild `:2585-2614`; changed client messages `:2971-2973` | WebProbe rebuilds changed client frames with a fresh mask; Burp edit path preserves mask metadata; incoming mask validation missing in WebProbe and not established in Burp |
| History persistence / bounds | Project import `Zuwa.java:28-40`, `Zf9f.java:71-85`, `Zf9v.java:122-165`; numeric cap not established | Row vector has no eviction (`core/src/ws_history.rs:42-48,63-80`); body spill `:63-68` and `core/src/body.rs:243-271`; project save/load `src/tools.rs:1834,2049` and `core/src/project.rs:353-387` | Both have project-persistence evidence; WebProbe row count is unbounded; numeric caps not established for Burp |
| Default WS interception state | Both true (`ProjectDefaults.json:441-445`) | Both true (`core/src/project.rs:682-697`; runtime `core/src/net.rs:1009-1010`) | Covered |

## 4. Robustness review of WebProbe WebSocket code

This is a static review of the current source, not a claim that tests were run in this pass.

**1. Raw bytes are preserved; interactive invalid-UTF-8 editing remains lossy.** `WsEntry.payload`
is now `Body` (`core/src/ws_history.rs:15-28`), and `push_ws_in` stores `payload.into()` without a
String conversion (`core/src/net.rs:689-700`). History length is `Body::len()`
(`src/repeater_ops.rs:1804`), so the old lossy-String length bug is gone. Project persistence keeps
valid UTF-8 as text and stores other bytes as base64 (`core/src/project.rs:353-387`). The remaining
risk is the Intercept UI: it queues `String::from_utf8_lossy(&payload)` and replaces the whole
payload with edited String bytes only when the returned text differs (`core/src/net.rs:2939-2957`).
An untouched message preserves its bytes; an actual edit of invalid UTF-8 cannot preserve arbitrary
original byte sequences through that representation.

**2. Row count is unbounded; large bodies are file-backed; projects are durable.**
`WsHistory` owns `RwLock<Vec<WsEntry>>` and `push` has no eviction (`core/src/ws_history.rs:42-48,63-80`),
so row metadata and inline payloads still grow with message count. Payloads of at least 256 bytes are
spilled to memory-mapped segments when the store works; small payloads and store-failure fallback
stay inline (`core/src/body.rs:146-149,243-271`). Segments are unlinked immediately, so this is not a
durable rolling log (`core/src/body.rs:185-205`). Durable persistence is the project save/load at
`src/tools.rs:1834,2049`, using the byte-preserving conversion at `core/src/project.rs:375-387`.

**3. The history view no longer deep-clones every row on each repaint.** It recomputes matching row
positions only when the history stamp or filter hash changes (`src/repeater_ops.rs:1765-1776`) and
fetches only the visible window (`:1792-1797`). The backing APIs borrow rows or clone selected
handles (`core/src/ws_history.rs:94-122`). Cross-tool search still iterates all WS rows and creates a
text copy for each, but only when `Search all tools` is clicked (`src/tools.rs:824-825,858-868`), not
on every query edit or egui frame.

**4. Oversized input now closes with 1009 instead of being relayed raw.** `MAX_WS_FRAME` is 16 MiB
(`core/src/net.rs:2526-2528`) and `MAX_WS_MESSAGE` has the same value (`:2617-2619`).
`ws_relay_chunk` rejects a declared oversized frame and an oversized fragmented message
(`:2834-2837,2853-2857`). Its `fail` path sends a close to each side, marks the stream closed, and
clears buffered state (`:2823-2833`). The old `raw_left` passthrough and placeholder-history behavior
are absent. `parse_ws_frame` still has an empty-payload oversize branch (`:2562-2567`), but the relay
performs its own length check before calling it, so that branch does not restore the old wire
behavior. There is no separate `buf` cap, but a completed header is checked before the relay waits
for the declared payload (`:2834-2843`).

**5. Fragmentation is implemented; some protocol validation remains absent.** Data frames are
assembled across continuations, interleaved control frames pass immediately, and one logical data
message reaches hooks/rules/interception/history (`core/src/net.rs:2806-2814,2844-2888`). A stray
continuation or a new data frame before the prior message finishes produces close 1002
(`:2862-2870`). Unchanged messages forward their original frames; changed messages become one final
frame (`:2967-2973`). However, reserved opcodes are relayed (`:2871-2875`), and this loop does not
validate RSV2/RSV3 or control-frame FIN/maximum-payload rules (`:2834-2851`). RSV1 is meaningful for
permessage-deflate (§4.7), so the old blanket "no compression flag handling" statement is false.

**6. Masking is regenerated for changed client messages, but incoming mask rules are not validated.**
The parser unmasks whenever the mask bit is set (`core/src/net.rs:2562-2578`). Changed messages are
rebuilt with `masked = client_to_server` (`:2971-2973`); `build_ws_frame` creates a fresh
xorshift-derived key seeded from time and length (`:2585-2614`). Unchanged messages return the raw
original frames (`:2967-2969`). No check requires client frames to be masked or server frames to be
unmasked; the parser and relay simply honor the supplied bit.

**7. Extension stripping and permessage-deflate are implemented.** The default-on setting removes
all `Sec-WebSocket-Extensions` lines on both plain and TLS upgrade paths
(`core/src/net.rs:2691-2713,3071-3073,3199-3201`; default `core/src/project.rs:677-696`). If the
header is allowed and the 101 response agrees to permessage-deflate, `ws_deflate_agreed` reads the
context-takeover flags and `WsSetup::streams` creates per-direction decompressors
(`core/src/net.rs:2677-2689,2981-3000`). RSV1 messages are inflated with a 16 MiB bound
(`:2715-2742,2904-2915`); history/editing sees inflated bytes and the forwarded changed frame is
plain with RSV bits clear (`:2967-2973`). Invalid compressed data closes 1009, and RSV1 without a
negotiated inflater closes 1002 (`:2909-2914`). The former claim that compressed bytes pass untouched
into a lossy String is obsolete.

**8. Received close frames are relayed; proxy-generated closes are for errors.** Opcode 8 is named
`close` (`core/src/net.rs:2514-2523`) and all control-class frames are recorded and forwarded without
parsing a close code/reason or setting `closed` (`:2844-2851`). Proxy-generated close frames are used
by the protocol/oversize `fail` path (`:2823-2833`). Plain relay teardown follows read EOF/error and
`shutdown(Write)` (`:3016-3061`); the TLS loop tracks read-side open flags (`:3133-3186`) and sends
TLS close_notify after the loop (`:3252-3256`). `WsWatch::drop` notifies extension hooks
(`:2780-2785`). There is still no proxy-initiated echo of an ordinary peer close frame.

**9. Stall handling is improved but not fully bounded.** The plain relay leaves reads blocking with
no read timeout, requests 120-second write timeouts (ignoring set-errors), and still uses an
unbounded `client_thread.join()` (`core/src/net.rs:18,3003-3008,3016-3061`). Thus a non-reading peer
has a configured write timeout, but a peer that stops sending can still leave the join waiting on a
blocking read. TLS uses nonblocking reads and a `write_nonblocking` loop with a 120-second deadline
per write (`:3114-3186`), sleeping 2 ms on WouldBlock or lack of progress. It has no overall idle or
absolute connection deadline. Both relays use 16 KiB read chunks (`:3017,3040,3140`).

## 5. Proposed order of work (smallest useful step first)

The earlier raw-byte, repaint-clone, scope-interception, extension/deflate, fragmentation, and
oversize proposals are now implemented (§3-§4); WS match/replace and stall hardening are partially
implemented. Existing test code relevant to new acceptance checks is at `core/src/ws_tests.rs:22-216`,
`core/src/ws_history.rs:125-163`, `src/repeater_ops.rs:1848+`, and the loopback WS fixture at
`core/src/net.rs:5110-5207`. These are source references, not tests run in this verification pass.

**Step 1 — Complete history metadata, annotations, and filters.** Add the missing full URL, TLS,
listener-port, Notes, and displayed WebSocket ID data to `WsEntry`/capture (`core/src/ws_history.rs:15-28`),
then expose them and annotation/listener filters in `src/repeater_ops.rs:1719-1846`. The existing
`socket` field already supplies a connection ID; `src/ui.rs:876-956,1078-1085` is HTTP-only and must
not be reused as proof of WS annotations. *Acceptance:* plain and TLS rows on different listeners
retain the new fields through project save/load; notes/highlights and both missing filters select the
expected rows.

**Step 2 — Make Intercept editing byte-safe.** Replace the lossy `Option<String>` payload editing
boundary at `core/src/net.rs:2939-2957` with a raw-byte/hex-capable representation while retaining
the unchanged-message fast path. *Acceptance:* edit one ASCII byte in a binary payload containing
invalid UTF-8 and assert every other original byte survives, in both directions and after project
persistence of the history row.

**Step 3 — Add the missing Both-directions match/replace mode.** `WsRule` and its editor currently
offer only client-to-server and server-to-client (`core/src/ws_rules.rs:16-17,43-50`;
`src/proxy_settings.rs:419-424`), while Burp documents all three at `creating.html:77-79` and declares
them at `Zxvb.java:19-21`. *Acceptance:* a Both-directions rule rewrites one message in each
direction, in rule order, for text and binary payloads, and survives project save/load.

**Step 4 — Implement WebSocket Repeater.** The current send path is HTTP-only
(`src/repeater_ops.rs:379-395`). Implement Send to Repeater, connect/clone/attach/reconnect,
handshake editing, destination selection, message history, and select-next-received per
`tools/repeater/websocket-messages.html:47-114` and
`testing-workflow/vulnerabilities/websockets/manipulating-websocket-handshakes.html:64-108`.
*Acceptance:* extend the loopback pattern at `core/src/net.rs:5110-5207`: edit a handshake, connect,
send/edit a message, verify its echo and history, and verify reconnect retains the edited handshake.

**Step 5 — Add WS-history send-to actions.** Add the Repeater/Comparer/Decoder context actions
represented by `Zs7j.java:24-49` to `src/repeater_ops.rs:1719-1846`. *Acceptance:* each action sends
the exact raw payload and direction to the intended destination; the Repeater case uses Step 4 rather
than the HTTP request sender.

**Step 6 — Add Script-mode filtering and custom columns, if Java Bambda support is in scope.** These
are explicitly unsupported at `src/tools.rs:1232-1233`; Burp's contracts are at `scripts.html:206-220`
and `custom-columns.html:36-41,175-188`. *Acceptance:* the documented direction/payload example
filters existing and new rows, and a custom column computes the same value after project reload.

**Step 7 — Finish protocol validation and ordinary-close policy.** Continuation reassembly already
exists (`core/src/net.rs:2853-2888`). Add mask-direction, RSV2/RSV3, control-FIN and control-length
validation at `:2834-2851`, and define close code/reason handling at `:2670-2675,2844-2851`; Burp's
corresponding Proxy behavior is not established, so this is robustness work, not claimed parity.
*Acceptance:* malformed mask/RSV/control inputs produce the chosen protocol error, and an ordinary
close with code 1000 follows the chosen close policy without leaving either relay thread stuck.

**Step 8 — Finish resource/stall hardening without inventing a Burp cap.** WebProbe's WS row vector
has no eviction (`core/src/ws_history.rs:42-48,63-80`), while Burp has no established numeric cap
(§1.7). Choose and document a WebProbe row/memory bound rather than claiming to copy Burp. Plain
relay reads and its final join remain unbounded (`core/src/net.rs:3003-3061`), and TLS has no overall
idle deadline (`:3133-3186`). *Acceptance:* N+100 rows enforce the chosen policy; a peer that stops
sending or reading lets each relay exit within its configured deadline; declared-oversize input
closes before buffering the declared body.

## 6. Points marked "not established"

Only the remaining Burp-side open items are listed here. Evidence found during verification has been
moved into §1 and §3 instead of retaining the old blanket "not established" statements. Permitted
recursive searches covered only `/root/burp-re/out/readable_strict/root/` and
`/root/burp-re/in/extract/resources/`.

1. **Burp's permessage-deflate decompression/recompression implementation** (§1.6). Header stripping
   is established; the algorithm is not. No `permessage` literal was found in the permitted class
   tree, and no WebSocket-mentioning class there also referenced `java.util.zip`, `Inflater`, or
   `Deflater`.
2. **Burp Proxy's ping/pong/close handling and whether those control frames appear in Proxy history**
   (§1.7, §3). `Zh98.java:10-17` establishes their frame kinds and `Zprb.java:21-29` establishes a
   Repeater PING→PONG path; neither proves the Proxy behavior.
3. **Burp's continuation-frame reassembly** (§1.7). `Zh98.java:15,35` names `CONTINUATION`, but no
   reassembly algorithm was located in the permitted sources.
4. **Burp's incoming mask validation and any fresh-random-mask-on-Proxy-edit policy** (§1.7). Locally
   generated client-to-server masking is established by `Zs8.java:11-12` and `Zb60.java:19-21`.
   `Zcng.java:44-50` and `Zbz5.java:148-156` instead establish preservation of the existing mask
   flag/key on payload edits. Incoming validation and generation of a fresh random mask on edit are
   not established.
5. **A numeric entry/byte limit for Burp's WS history** (§1.7). No cap is visible in the cited
   `Zf9f`/`Zf9v` model or the WS defaults keys, but that is not proof of absence. Burp must not be
   described as "bounded" on this evidence.
6. **The exact on-disk representation and any rolling-log policy for old Burp WS history** (§1.7).
   Project serialization/import is now established by `Zuwa.java:28-40`, `Zf9f.java:71-85`, and
   `Zf9v.java:122-165`; the original claim that the persistence mechanism was wholly unknown was
   too broad and has been narrowed. The physical format and retention policy remain open.
7. **Specific WS-history destinations beyond Repeater/Comparer/Decoder and extension items** (§1.5).
   `Zs7j.java:24-49` proves that enumerated set, not the absence of every other action elsewhere.
8. **The implementation of Burp's wire frame reader/writer and its size limits** (§1.7). The
   pipeline bytecode in `Zb7v.java:37-85` constructs qualified `net.portswigger.Zqb` readers, and
   `Zpqr.java:12-25` uses qualified `net.portswigger.Zkn` for output. Their `net.portswigger`
   implementations are not present under the permitted root, so parsing, fragmentation, validation,
   and frame/message-limit internals remain **not established**; the similarly named top-level
   `burp.Zqb`/`burp.Zkn` classes are different packages and are not evidence of those internals.
