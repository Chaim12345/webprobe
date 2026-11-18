# R-03: Montoya bridge broad enough for real BApps (spec)

Today: `app/sidecar/MontoyaBridge.java:276-287` answers only `proxy()` and `logging()`; every other
`MontoyaApi` call throws, so real BApps fail at load. Host side: `app/core/src/ext_host.rs`.

## What real BApps call (static survey, 2026-11-18)
`python3 -I scripts/bapp_montoya_survey.py <jar>` counts `InterfaceMethod burp/api/montoya/*`
call sites in the extension's own classes. The four BApps installed locally (`~/.BurpSuite/bapps`):

| BApp | Own classes | Distinct Montoya methods | `MontoyaApi` accessors used |
|---|---|---|---|
| JWT Monitor 1.1.1 | 3 | 21 | burpSuite, extension, http, logging, userInterface |
| JSON Web Tokens (JWT4B) | 82 | 55 | extension, http, logging, userInterface |
| JWT Editor 2.6.2 | 1452 | 86 | burpSuite, collaborator, extension, intruder, logging, persistence, proxy, scanner, userInterface, utilities |
| MCP Server | 1835 | 116 | burpSuite, collaborator, extension, http, intruder, logging, organizer, persistence, proxy, repeater, siteMap, userInterface, utilities |

Accessor frequency (of 4): extension 4, logging 4, userInterface 4, http 3, burpSuite 3, persistence 2,
proxy 2, collaborator 2, intruder 2, utilities 2, scanner 1, organizer 1, repeater 1, siteMap 1.
Most-used value types: HttpRequest, HttpRequestResponse, HttpResponse, HttpHeader, ByteArray, Annotations,
HttpService, HttpRequestToBeSent / RequestToBeSentAction / ResponseReceivedAction, PersistedObject, Preferences.
Caveat: four BApps, three of them JWT tools; rerun the survey on more jars before finalising the later stages.

## Build order
1. **Load path**: `extension()` (setName, registerUnloadingHandler, filename), `logging()` (done),
   `burpSuite()` (version, taskExecutionEngine state, commandLineArguments, export/import project options
   may throw UnsupportedOperation with a clear message). Target: JWT Monitor loads without error.
2. **`http()`**: registerHttpHandler (HttpRequestToBeSent / HttpResponseReceived with actions, annotations),
   sendRequest, plus the message value types (HttpRequest/HttpResponse/HttpHeader/HttpService/ByteArray,
   parameters). Target: JWT Monitor does its job on proxied traffic (check what it does first; it highlights
   or logs requests carrying JWTs).
3. **`userInterface()`**: registerSuiteTab, registerContextMenuItemsProvider, registerHttpRequestEditorProvider /
   ResponseEditorProvider, createRawEditor, swingUtils, applyThemeToComponent. The UI is Swing in the sidecar
   JVM; decide and document how it is shown (own window per extension tab on the same display is the
   simple honest answer; embedding in egui is out of scope). Target: JWT4B's editor tab opens.
4. **`persistence()`** (extensionData PersistedObject, preferences), **`utilities()`** (base64, url, byte, html,
   number, random, compression, crypto), **`proxy()`** rest (history, websocket handlers), **`collaborator()`**
   (createClient, payloads, interactions; via `core/src/oob.rs`), **`intruder()`** (payload processors /
   generator providers; also closes part of R-17), **`scanner()`** (registerScanCheck, insertion point provider,
   audit issues). Target: JWT Editor loads and its tab works.
5. **`siteMap()`, `repeater()`, `organizer()`, `scope()`, `comparer()`, `decoder()`**. Target: MCP Server loads.

## Constraints
- Build against the published `net.portswigger.burp.extensions:montoya-api` artifact, not
  `/opt/BurpSuite/burpsuite.jar` (`core/src/ext_host.rs:332`). Check the artifact's licence text before
  vendoring it; if it cannot be redistributed, fetch-at-build or require the user to supply it, and say so.
- Unsupported calls must fail with `UnsupportedOperationException("<interface>.<method> is not supported by
  WebProbe")` and be logged once in the extension's error tab, never a bare throw.
- Protocol: the id-matched request/reply framing in `ext_host.rs` stays; each new API is a message family.
  Hook timeout 15 s and first-load 180 s stay.
- Tests: the real-extension sidecar test pattern (`java_sidecar_runs_a_real_montoya_extension`) with a small
  purpose-built test extension per stage; the BApp targets above are checked manually and recorded in the ledger.
