# R-13: How Burp Suite finds DOM-based issues, and options for WebProbe

> **Delegated research (2026-11-18), not fully reviewed.** Written by free models (some sections re-verified by a second model) as leads for the task in the title; confirm each class:line before relying on it.

**Scope and evidence.** Read-only research. Burp claims below cite the opened decompiled class and line, or an opened resource. Paths are abbreviated as `resources/` = `/root/burp-re/in/extract/resources/`, `burp/` = `/root/burp-re/out/readable_strict/root/`, and `app/` = `/root/Documents/Craft Anything/burpsuite/app/`. The earlier partial draft was checked and its inferred IDs/source-sink descriptions were discarded.

## 1. Configuration

`resources/Preferences/AuditDefaults.json:220-227` contains exactly six keys under `scanner.javascript_analysis`:

| Key | Default | Evidence / meaning visible in Burp |
|---|---:|---|
| `max_dynamic_time_per_item` | `30` | JSON default; the UI calls this “Maximum dynamic analysis time per item” and “seconds” (`burp/Zrde.java:191-209`). |
| `max_static_time_per_item` | `30` | JSON default; “Maximum static analysis time per item” and “seconds” (`burp/Zrde.java:217-235`). |
| `request_missing_dependencies` | `true` | “Make requests for missing site resources” (`burp/Zrde.java:170-177`). |
| `fetch_out_of_scope_resources` | `true` | “Fetch previously undiscovered resources and data from out-of-scope hosts” (`burp/Zrde.java:182-190`). |
| `use_dynamic_analysis` | `true` | “Use dynamic analysis techniques” (`burp/Zrde.java:154-161`). |
| `use_static_analysis` | `false` | “Use static analysis techniques” (`burp/Zrde.java:162-169`). |

The load/save interface reads and writes the same six keys (`burp/Zxc3.java:24-41`). It also attempts to read legacy `scanner.javascript_analysis.max_time_per_item` into the static-time setter before reading `max_static_time_per_item` (`Zxc3.java:30-31`), but that legacy key is **not** present in `AuditDefaults.json` and is not counted as a seventh current key. The UI prevents both techniques being disabled at once (`Zrde.java:257-279`). Turning “make requests” off also disables the out-of-scope checkbox; turning it on selects and enables that checkbox (`Zrde.java:245-255`).

### Built-in configurations that change these keys

A search of every file in `resources/BuiltInConfigs/` found a `javascript_analysis` block in exactly four files:

| Built-in config | Values in its block | Evidence |
|---|---|---|
| `Audit coverage - maximum.json` | dynamic `600`, static `600`, request missing `true`, fetch out of scope `true`, dynamic `true`, static `true` | `resources/BuiltInConfigs/Audit coverage - maximum.json:39-46` |
| `Crawl and Audit - CICD Optimized.json` | only `max_static_time_per_item: 10` | `resources/BuiltInConfigs/Crawl and Audit - CICD Optimized.json:49-51` |
| `Crawl and Audit - Fast.json` | only `max_static_time_per_item: 10` | `resources/BuiltInConfigs/Crawl and Audit - Fast.json:42-44` |
| `Crawl and Audit - Lightweight.json` | only `max_static_time_per_item: 10` | `resources/BuiltInConfigs/Crawl and Audit - Lightweight.json:51-53` |

All other built-in configs have no `javascript_analysis` block and therefore do not override these six values. Separately, `Audit checks - all except JavaScript analysis.json:12` and `Audit checks - passive.json:12` set `scanner.issues_reported.scan_type_javascript_analysis` to `false`; that is an issue-category gate, not a `javascript_analysis` key. Other audit-check configs may set that category gate to `true`.

## 2. Static analysis

### Parser and taint machinery

* Static analysis is scheduled only when static analysis is enabled, the JavaScript-static-analysis detection method is enabled, a JavaScript audit item exists, and static time is positive (`burp/Zhgz.java:31-41`).
* `burp/Zpet.java:13-16` constructs the lexer/parser front end (`Zflp`), and `Zflp.java:16-19` invokes `Zbty.ZG` on the token list. `Zptd.java:9-47` is a concrete JavaScript lexical preprocessing class: it handles automatic semicolon insertion around line terminators and comments.
* `burp/Ziww.java:19-30` turns input into an AST/graph and creates `Zhpe`; `burp/Zhpe.java:17-60` iterates taint-path results.
* Source and sink markers are `Zpvp` and `Zpv2` (`burp/Zpvp.java:3-10`, `burp/Zpv2.java:5-24`). Their common `Zpvh` base stores an integer flag, a display string, and a `Zsyr` context (`burp/Zpvh.java:3-27`). Taint metadata keys are literally `TaintHops`, `TaintSource`, `TaintSink`, and `TaintPreserver` (`burp/Zgpy.java:5-9`).
* `burp/Zi4t.java:14-34` matches either an exact identifier or a wildcard-aware property expression. `Zi4s.java:15-22` and `Zi4x.java:15-21` attach source markers; `Zi47.java:11-20` and `Zi43.java:13-24` attach sink markers; `Zeyi.java:13-30,48-56` detects a node carrying both source and sink and records taint hops. `Zbv0.java:55-147` (decompiler bytecode comments) is the factory for property/function/string-literal source, sink, and preserver visitors.
* `burp/Zf59.java:75-118` (retained bytecode because Java decompilation failed) takes the first path node's `TaintSource`, the last node's `TaintSink`, validates the path with `Zw9i`, and passes it to issue creation. `Zw9i.java:6-22` rejects a same-non-`NONE` source/sink context unless the path contains a `Zu6h` hop.
* `burp/Zgs3.java:16-37` combines source/sink flags, maps the base sink issue through `Zf24`, and assigns confidence and severity through `Zwf8`. `Zf24.java:6-224` maps each base issue plus `Zb7n.DOM`, `REFLECTED`, or `STORED` to the corresponding three issue constants.

### Literal source and sink tables

The dynamic result decoder has a literal sink-to-issue table in `burp/Zcwh.java:118-1258`; its complete grouped contents are reproduced in §6. It is direct evidence of the sink names Burp recognizes when dynamic results arrive. `Zcwh.java:72-115` specially classifies source strings `window.name`, `input.value`, `textarea.value`, and `document.cookie`; other source strings take the default flag `0`.

**Static source/sink declaration tables: not established.** `burp/Zeys.java:8-30` declares five static `List<Zx3j>` tables but the readable output has no static initializer populating them. `burp/Zx16.java:9-14` likewise declares a parser-rule list without its initializer. Searches for `new Zpvp`, `new Zpv2`, `new Zbv0`, `document.URL`, `document.referrer`, `location.hash`, `localStorage`, and related names across `burp/` found the generic builder and dynamic decoder, but not a surviving static declaration table. The scanner's dynamic `window.name`/`document.cookie` source names and the DOM Invader resources must not be silently presented as proof of the missing **static** table.

## 3. Dynamic analysis

Burp injects JavaScript into its embedded browser. `burp/Zel5.java:48-57` creates a browser session and calls `runAnalysis().Zw(...)` with `Zm1x.ZD()`, the per-item configuration script, and `window.BurpDynamicJavaScriptAnalysis.invade()`. Navigation occurs at `Zel5.java:190-196`; completion is obtained from `window.BurpDynamicJavaScriptAnalysis.deferredComplete` (`Zel5.java:194-196`) and results from `window.BurpDynamicJavaScriptAnalysis.getVulns()` (`Zel5.java:198-226`). The latter must return a string parseable as an array.

`burp/Zp7.java:59-83` builds the configuration. The literal options at `Zp7.java:62` include `invadeSources`, `invadeSinks`, `postMessageEnabled:true`, `sinkCheckEnabled:true`, `sourceMutationEnabled`, `angularCheckEnabled:false`, `prototypePollutionEnabled`, `htmlCheckEnabled:true`, `checkEventsEnabled:true`, `tracing`, `checkReadyAndInvade:true`, a security token, and a base value. Lines 66-73 configure a completion promise, multi-context injection, GET/POST and POST parameters, and optionally a custom token. `Zx5w.java:10-18` names the modes `TRACING_DISABLED`, `TRACING`, `TRACING_FOLLOWUPS`, and `CONTEXT_BREAKOUT`.

`burp/Zcwh.java:14-69` decodes each result's `source`, `sink`, `context`, `sourceValue`, `sinkValue`, `poc`, `origin`, data/manipulated data, origin-check flag, element details, three stack traces, quote context, and fired-event details. It maps sink to base issue (`Zcwh.java:34-35,118-1258`) and then adds DOM/reflected/stored variant via `Zf24.Zw` (`Zcwh.java:35`; `Zf24.java:6-224`). Dynamic hits become issues in `burp/Zbzk.java:20-78`, which preserves dynamic evidence in `Zwtg` and calls the same `Zwf8` confidence/severity functions as static analysis.

The injected script body itself is **not established**: `burp/Zm1x.java:7-26` concatenates an array `Zb`, but that array is absent from the readable class. No `BurpDynamicJavaScriptAnalysis` script exists under `resources/`; only the Java references in `Zp7.java` and `Zel5.java` were found.

### Confirmation and reporting

`burp/Zgfj.java:49-53,62-124` waits up to the configured dynamic timeout, obtains the result array, and passes it to the reporter at bytecode lines 112-116. `burp/Zphn.java:21-27` runs the result decoder and forwards each decoded record. Dynamic evidence includes the generated PoC, values and stack traces (`burp/Zcwh.java:14-69`). The report renderer distinguishes unchanged source-to-sink propagation from modified values: `burp/Zsmx.java:99-115` says when a value reached the sink without modification and otherwise prints source, manipulated event-handler data, and final sink value; lines 118-124 print stack traces and whether the listener checked origin; lines 126-161 print fired-event details, origin, and the generated PoC.

Eligible hits receive a second, context-specific dynamic pass. `burp/Zbzr.java:23-51` selects follow-ups for JavaScript injection, XSS, client-side JSON injection, open redirection, and link manipulation, except suppressed records and `url` context for the latter two. `burp/Zbzk.java:20-38` creates a `Zp0q` follow-up plan from the result context and quote context. `burp/Zbjx.java:19-200` maps contexts including `eval`, `JSON.parse`, `url.start`, XHR/fetch positions, HTML attributes, `webdatabase.executeSql`, and `jquery_html` to payload families; `Zw7w.java:8-20` names those families. `burp/Zpld.java:41-67` launches the follow-up-capable reporter and queues payloads. `burp/Zriu.java:29-91` turns each payload into a request, and `burp/Zexn.java:57-76` invokes another browser analysis with `NO_FOLLOWUPS`, preventing unbounded recursion. This is confirmation by executing a tailored payload, not just matching a static string.

Prototype-pollution results use a separate decoder: `burp/Zcwm.java:9-15` accepts records whose source is `Prototype pollution` and retains technique, type, and PoC. `burp/Zfk8.java:63-77` schedules that analysis when the issue is enabled.

### Sources observed by instrumentation

The shipped DOM Invader file `resources/Browser/DomInvader/content-scripts/augmented-dom.js:1` contains a `sourcesList`. Decoding its own string table (without executing it) yields this literal set:

`location`, `location.href`, `location.hash`, `location.search`, `location.pathname`, `document.URL`, `window.name`, `document.referrer`, `document.documentURI`, `document.baseURI`, `document.cookie`, `URLSearchParams`.

That file also has `jsSinks`, `htmlSinks`, `urlSinks`, and `sinkRanking` tables on the same line. Notable additions to the result decoder are `serviceWorker.register`, `navigation.navigate`, `webdatabase.executeSql`, `fetch`, and `fetch.header`. These are shipped instrumentation tables, **not** proof of the missing static declarations. `resources/Browser/DomInvader/manifest.json:6-32` injects `postmessage-instrumentation.js` and `augmented-dom-instrumentation.js` at `document_start` in the `MAIN` world in all frames, plus isolated-world connection/UI scripts. The manifest identifies DOM Invader version `2.0.10` (`manifest.json:3-5`). Post-message evidence is separately represented in scanner results by `origin`, `data`, `manipulatedData`, and `originChecked` (`burp/Zcwh.java:22-26,36-48`), and rendered with origin-validation text (`burp/Zsmx.java:121-124`).

### Does the scanner use DOM Invader?

Burp ships the full extension under `resources/Browser/DomInvader/`: manifest, MAIN-world instrumentation, isolated content scripts, service worker, DevTools page/panels, settings, CSS, images, and libraries. `burp/Zi9a.java:39-61` launches the embedded browser with `--load-extension=...`. `burp/Zugr.java:50-124` builds/extracts browser resources; its decoded strings include `resources/Browser/DomInvader` and `dom-invader` (`/root/burp-re/out/strings/map_merged.tsv:30169-30171`).

The scanner path shown above instead evaluates `Zm1x.ZD()` and calls `window.BurpDynamicJavaScriptAnalysis` (`burp/Zel5.java:56,194-226`). No reference from these scanner classes to the DOM Invader extension path was found. **Not established:** that the scanner uses the DOM Invader extension/resources for analysis, or that the missing `Zm1x` payload was generated from those resources. The evidence instead shows an embedded-browser extension for interactive use and a separate scanner-injected API/result pipeline.

## 4. Merge and confidence

Static and dynamic paths converge on the same issue record type and the same two functions, rather than on separate confidence algorithms: static issue construction calls `Zwf8.Zd` and `Zwf8.Zt` at `burp/Zgs3.java:36-38`; dynamic construction calls them at `burp/Zbzk.java:39-75` (and passive dynamic conversion at `burp/Zxex.java:13-54`).

`Zwf8.Zd(flags, issue)` implements confidence at `burp/Zwf8.java:212-228`; `Zwf8.Zt` implements severity at `Zwf8.java:14-83`. The flag bits are cookie source `1`, `window.name` source `2`, and jQuery-related `4` from `burp/Ze_z.java:28-45`; dynamic source flag `8` for `input.value`/`textarea.value` is assigned at `burp/Zcwh.java:87-114` and used for the self-XSS Tentative rule at `Zwf8.java:152-154,219-225,231-243`.

The confidence byte mapping is explicit in `burp/Zeue.java:8-18,28-61`: `0 = Undefined`, `1 = Tentative`, `2 = Firm`, and `3 = Certain`. `Zwf8.Zd` returns only `1` or `2` (`burp/Zwf8.java:212-228`):

* every open-redirection variant is Tentative (`1`);
* a jQuery-dependent result (flag `4`) is Tentative;
* DOM-based XSS/JavaScript injection from `input.value` or `textarea.value` (flag `8`) is Tentative, and `Zwf8.java:152-154` appends a long warning that exploitation may require the victim to exploit themselves;
* Ajax request-header manipulation from `document.cookie` (flag `1`) is Tentative;
* all other cases in this function are Firm (`2`). Thus static-only analysis cannot reach Certain through `Zwf8.Zd`; no general dynamic-hit-to-Certain upgrade was found in the inspected creation or merge code. **Not established:** a rule that makes every dynamically confirmed issue Certain.

Static and dynamic evidence have different concrete types: static `Zw8k` and dynamic `Zhr5` (`burp/Zw8k.java:9-59`, `burp/Zhr5.java:9-94`). `burp/Zev6.java:142-171,201-240,307-310` stores, visits, merges, and deduplicates these evidence objects. `Zwf8.identityOf` builds identity from issue type, origin, path, variant, location, and source/sink captions (`burp/Zwf8.java:89-139`), while `burp/Zgfm.java:34-109,112-197` performs issue consolidation. The static-detail renderer includes code snippets (`burp/Zr1p.java:74-90,114-139`), and the dynamic renderer includes source/sink values, stack traces, origin checks, and PoC (`burp/Zsmx.java:20-44,57-162`), so merged issues can retain both forms of proof. **Not established:** the exact `Zwf8.ZE` consolidation delegate and winner formula, because its initializer is absent from the readable output (`burp/Zwf8.java:12,142-144`). `burp/Zxlq.java:33-51` demonstrates the generic rule that a newer higher confidence replaces a lower one, but it is not claimed here to be the missing DOM-specific delegate.

## 5. Issue-detail template

For ordinary DOM source-to-sink results, `burp/Zhp.java:28-31,46-49` emits the literal pattern:

> `The application may be vulnerable to %s. Data is read from <b>%s</b> and passed to <b>%s</b>.`

The family-specific first `%s` comes from `burp/Zwf8.java:164-186` (for example `DOM-based cross-site scripting` or `DOM-based open redirection`). `burp/Zwf8.java:189-209` drives the visitor and appends source-specific notes from `burp/Ze_z.java:9-21`: cookie exploitability, `window.name` as an attack vector, and jQuery-version dependence.

Reflected input uses this literal prefix (`burp/Zhp.java:54-57`):

> `The application may be vulnerable to reflected %s.<br><br>The %s is copied into a JavaScript string literal. The payload <b>%s</b> was submitted in the %s.<br><br>The string containing the payload is then passed to `

Stored input uses (`burp/Zhp.java:61-74`):

> `The application may be vulnerable to stored %s.<br><br>The %s submitted to the URL %s is copied into a JavaScript string literal at the URL %s. The payload <b>%s</b> was submitted in the %s.<br><br>The string containing the payload is then passed to `

Static evidence is rendered as `Data is read from <b>source</b> and passed to <b>sink</b> via the following statement(s):` followed by a list of code snippets (`burp/Zr1p.java:114-139`). Dynamic evidence is headed `<h2>Dynamic analysis</h2>` (`burp/Zsmx.java:53-55`) and starts `Data is read from <b>source</b> and passed to <b>sink</b>.` (`Zsmx.java:71-73`), followed by the value/stack/origin/PoC details cited in §3.

Prototype pollution has a distinct template. `burp/Zwud.java:13-24` says that the source was found, the payload was injected into a named URL part and later detected in `Object.prototype`, prints the PoC URL, and recommends DOM Invader to confirm the issue and scan for gadgets.

The generic background text is a resource, not generated taint evidence. For example, `resources/KnowledgeBase/Issues/00200310_CrossSiteScriptingDomBased.json:4` says Burp uses dynamic and static analysis and warns that static-only results can be false positives requiring manual review when no dynamic evidence is supplied.

## 6. DOM issue types and sink mapping

There are 49 relevant resource definitions: 16 families × DOM/reflected-DOM/stored-DOM = 48, plus client-side prototype pollution. Every ID below was read from the named JSON resource, not inferred. `resources/KnowledgeBase/Issues/00200316_ClientSidePrototypePollution.json:2-5` gives prototype pollution ID `2097942`, its user-controlled JSON/query/hash source concept, and merge/`__proto__` behavior.

The base sink groups below are literal mappings from `burp/Zcwh.java:1129-1255`. `iframe.src` is context-sensitive: `url.start` gives XSS, otherwise link manipulation (`Zcwh.java:1129-1132`). Dynamic `webdatabase.executeSql` is confirmed by `burp/Zbjx.java:157-164,193-195`. Absence of a family from `Zcwh` is not treated as absence from static analysis.

| Base family | Literal sink names / source evidence established so far |
|---|---|
| XSS | `Unknown`, `document.write`, `document.writeln`, `element.innerHTML`, `jQuery.$`, `jQuery.constructor`, `jQuery.index`, `jQuery.replaceAll`, `jQuery.prependTo`, `jQuery.appendTo`, `jQuery.init`, `jQuery.add`, `jQuery.has`, `jQuery.wrapAll`, `jQuery.wrapInner`, `jQuery.wrap`, `jQuery.html`, `jQuery.insertBefore`, `jQuery.insertAfter`, `jQuery.parseHTML`, `jQuery.append`, `jQuery.prepend`, `jQuery.replaceWith`, `jQuery.before`, `jQuery.after`, `jQuery.prop.innerHTML`, `jQuery.prop.outerHTML`, `jQuery.attr.onclick`, `jQuery.attr.onClick`, `element.setAttribute.onClick`, `element.setAttribute.onclick`, `script.innerHTML`, `element.outerHTML`, `jQuery`, `element.insertAdjacentHTML`, `script.src`; plus context-dependent `iframe.src` (`Zcwh.java:124-449,1130-1168`). |
| JavaScript injection | `eval`, `setInterval`, `execScript`, `jQuery.globalEval`, `createContextualFragment`, `Function`, `setTimeout`, `setImmediate`, `msSetImmediate`, `javascriptURL` (`Zcwh.java:457-545,1169-1179`). |
| Open redirection | `location.protocol`, `location.host`, `location.hostname`, `location.assign`, `location.replace`, `location`, `window.open`, `location.href`, `xhr.open`, `xhr.send`, `fetch.url`, `fetch.body`, `iframe.srcdoc`, `location.hash`, `location.pathname` (`Zcwh.java:547-681,1180-1195`). |
| Link manipulation | `input.formaction`, `jQuery.prop.action`, `form.action`, `button.formaction`, `jQuery.prop.src`, `jQuery.prop.href`, `anchor.href`, `jQuery.attr.href`, `element.setAttribute.href`; plus non-`url.start` `iframe.src` (`Zcwh.java:682-762,1130-1132,1196-1205`). |
| DOM data manipulation | `document.title`, `history.pushState`, `history.replaceState`, `window.name`, `element.style.cssText`, `input.type`, `location.search`, `element.textContent`, `element.innerText`, `element.outerText`, `element.backgroundImage`, `input.value`, `document.implementation.createHTMLDocument`, `script.appendChild`, `script.textContent`, `script.innerText`, `script.text`, `script.append`, `element.setAttribute.action`, `anchor.target`, `button.value`, `jQuery.prop.data`, `jQuery.attr.data`, `element.setAttribute.src`, `jQuery.attr.src`, `element.setAttribute.data`, `element.setAttribute.formaction`, `jQuery.attr.action` (`Zcwh.java:763-1014,1206-1234`). |
| Ajax request header manipulation | `xhr.setRequestHeader.value`, `xhr.setRequestHeader.name` (`Zcwh.java:1015-1031,1235-1237`). |
| WebSocket URL poisoning | `websocket` (`Zcwh.java:1033-1040,1238-1239`). |
| Cookie manipulation | `document.cookie` (`Zcwh.java:1042-1050,1240-1241`). |
| Denial of service | `RegExp` (`Zcwh.java:1051-1059,1242-1243`). |
| Client-side JSON injection | `JSON.parse` (`Zcwh.java:1060-1068,1244-1245`). |
| Client-side XPath injection | `document.evaluate`, `jQuery.parseXML` (`Zcwh.java:1069-1085,1246-1248`). |
| Document domain manipulation | `document.domain` (`Zcwh.java:1087-1095,1249-1250`). |
| HTML5 storage manipulation | `sessionStorage.setItem.name`, `sessionStorage.setItem.value`, `localStorage.setItem.value`, `localStorage.setItem.name` (`Zcwh.java:1096-1126,1251-1255`). |
| HTML5 web message manipulation | Sending a web message to another document (`postMessage` kind), established by `resources/KnowledgeBase/Issues/00500e00_Html5WebMessageManipulationDomBased.json:4`; no literal sink-to-issue mapping in `Zcwh`. |
| Local file path manipulation | Filename parameter to a file-handling API, established by `resources/KnowledgeBase/Issues/00200350_LocalFilePathManipulationDomBased.json:4-5`; no literal sink-to-issue mapping in `Zcwh`. |
| Client-side SQL injection | Client-side SQL query. `webdatabase.executeSql` is established at `burp/Zbjx.java:157-164,193-195`, and `executeSql()` at `resources/KnowledgeBase/Issues/00200330_ClientSideSqlInjectionDomBased.json:5`; no literal sink-to-issue mapping in `Zcwh`. |
| Client-side prototype pollution | Source/behavior in the JSON above; `burp/Zcwm.java:9-15` separately parses dynamic records whose `source` is `Prototype pollution`, with `technique`, `type`, and `poc`. |

### All 49 issue types

Source shorthand below: **DOM** = a controllable part of the DOM, with the instrumentation source set listed in §3; **reflected** = input copied from a request into the immediate response; **stored** = input stored and later embedded in a response. The reflected/stored definitions come from each resource's `description` line 4. **These source categories do not prove the missing static declaration table.** Sink shorthand refers to the literal base-family table above. Each cited JSON was opened: `typeIndex` is line 2, `name` line 3, and source/behavior description line 4. The resource column gives the filename under `resources/KnowledgeBase/Issues/`.

| typeIndex | name | source kind(s) | sink kind(s) | resource |
|---:|---|---|---|---|
| 2097936 | Cross-site scripting (DOM-based) | DOM | HTML-writing / DOM XSS sinks | `00200310_CrossSiteScriptingDomBased.json` |
| 2097937 | Cross-site scripting (reflected DOM-based) | reflected | HTML-writing / DOM XSS sinks | `00200311_CrossSiteScriptingReflectedDomBased.json` |
| 2097938 | Cross-site scripting (stored DOM-based) | stored | HTML-writing / DOM XSS sinks | `00200312_CrossSiteScriptingStoredDomBased.json` |
| 2097942 | Client-side prototype pollution | user-controlled JSON property, query string, or hash parameter converted to an object and merged | object merge to `Object.prototype` / other global prototypes; `__proto__`, `constructor`, `prototype` keys | `00200316_ClientSidePrototypePollution.json` |
| 2097952 | JavaScript injection (DOM-based) | DOM | JavaScript execution sinks | `00200320_JavaScriptInjectionDomBased.json` |
| 2097953 | JavaScript injection (reflected DOM-based) | reflected | JavaScript execution sinks | `00200321_JavaScriptInjectionReflectedDomBased.json` |
| 2097954 | JavaScript injection (stored DOM-based) | stored | JavaScript execution sinks | `00200322_JavaScriptInjectionStoredDomBased.json` |
| 2097968 | Client-side SQL injection (DOM-based) | DOM | client-side SQL query / `webdatabase.executeSql`, `executeSql()` | `00200330_ClientSideSqlInjectionDomBased.json` |
| 2097969 | Client-side SQL injection (reflected DOM-based) | reflected | client-side SQL query / `executeSql()` | `00200331_ClientSideSqlInjectionReflectedDomBased.json` |
| 2097970 | Client-side SQL injection (stored DOM-based) | stored | client-side SQL query / `executeSql()` | `00200332_ClientSideSqlInjectionStoredDomBased.json` |
| 2097984 | WebSocket URL poisoning (DOM-based) | DOM | WebSocket target URL (`websocket`) | `00200340_WebSocketUrlPoisoningDomBased.json` |
| 2097985 | WebSocket URL poisoning (reflected DOM-based) | reflected | WebSocket target URL | `00200341_WebSocketUrlPoisoningReflectedDomBased.json` |
| 2097986 | WebSocket URL poisoning (stored DOM-based) | stored | WebSocket target URL | `00200342_WebSocketUrlPoisoningStoredDomBased.json` |
| 2098000 | Local file path manipulation (DOM-based) | DOM | filename parameter to a file-handling API | `00200350_LocalFilePathManipulationDomBased.json` |
| 2098001 | Local file path manipulation (reflected DOM-based) | reflected | filename parameter to a file-handling API | `00200351_LocalFilePathManipulationReflectedDomBased.json` |
| 2098002 | Local file path manipulation (stored DOM-based) | stored | filename parameter to a file-handling API | `00200352_LocalFilePathManipulationStoredDomBased.json` |
| 2098016 | Client-side XPath injection (DOM-based) | DOM | XPath query (`document.evaluate`, `jQuery.parseXML`) | `00200360_ClientSideXPathInjectionDomBased.json` |
| 2098017 | Client-side XPath injection (reflected DOM-based) | reflected | XPath query | `00200361_ClientSideXPathInjectionReflectedDomBased.json` |
| 2098018 | Client-side XPath injection (stored DOM-based) | stored | XPath query | `00200362_ClientSideXPathInjectionStoredDomBased.json` |
| 2098032 | Client-side JSON injection (DOM-based) | DOM | string parsed as JSON (`JSON.parse`) | `00200370_ClientSideJsonInjectionDomBased.json` |
| 2098033 | Client-side JSON injection (reflected DOM-based) | reflected | string parsed as JSON | `00200371_ClientSideJsonInjectionReflectedDomBased.json` |
| 2098034 | Client-side JSON injection (stored DOM-based) | stored | string parsed as JSON | `00200372_ClientSideJsonInjectionStoredDomBased.json` |
| 5243152 | Open redirection (DOM-based) | DOM | redirection target / location, XHR, fetch sinks | `00500110_OpenRedirectionDomBased.json` |
| 5243153 | Open redirection (reflected DOM-based) | reflected | redirection target | `00500111_OpenRedirectionReflectedDomBased.json` |
| 5243154 | Open redirection (stored DOM-based) | stored | redirection target | `00500112_OpenRedirectionStoredDomBased.json` |
| 5245696 | Cookie manipulation (DOM-based) | DOM | cookie value (`document.cookie`) | `00500b00_CookieManipulationDomBased.json` |
| 5245697 | Cookie manipulation (reflected DOM-based) | reflected | cookie value | `00500b01_CookieManipulationReflectedDomBased.json` |
| 5245698 | Cookie manipulation (stored DOM-based) | stored | cookie value | `00500b02_CookieManipulationStoredDomBased.json` |
| 5245952 | Ajax request header manipulation (DOM-based) | DOM | `XMLHttpRequest` header name/value | `00500c00_AjaxRequestHeaderManipulationDomBased.json` |
| 5245953 | Ajax request header manipulation (reflected DOM-based) | reflected | `XMLHttpRequest` header name/value | `00500c01_AjaxRequestHeaderManipulationReflectedDomBased.json` |
| 5245954 | Ajax request header manipulation (stored DOM-based) | stored | `XMLHttpRequest` header name/value | `00500c02_AjaxRequestHeaderManipulationStoredDomBased.json` |
| 5246208 | Denial of service (DOM-based) | DOM | problematic platform API; literal dynamic mapping is `RegExp` | `00500d00_DenialOfServiceDomBased.json` |
| 5246209 | Denial of service (reflected DOM-based) | reflected | problematic platform API | `00500d01_DenialOfServiceReflectedDomBased.json` |
| 5246210 | Denial of service (stored DOM-based) | stored | problematic platform API | `00500d02_DenialOfServiceStoredDomBased.json` |
| 5246464 | HTML5 web message manipulation (DOM-based) | DOM | web message sent to another document (`postMessage` kind; no literal `Zcwh` mapping) | `00500e00_Html5WebMessageManipulationDomBased.json` |
| 5246465 | HTML5 web message manipulation (reflected DOM-based) | reflected | web message sent to another document | `00500e01_Html5WebMessageManipulationReflectedDomBased.json` |
| 5246466 | HTML5 web message manipulation (stored DOM-based) | stored | web message sent to another document | `00500e02_Html5WebMessageManipulationStoredDomBased.json` |
| 5246720 | HTML5 storage manipulation (DOM-based) | DOM | `localStorage` / `sessionStorage` name and value setters | `00500f00_Html5StorageManipulationDomBased.json` |
| 5246721 | HTML5 storage manipulation (reflected DOM-based) | reflected | `localStorage` / `sessionStorage` name and value setters | `00500f01_Html5StorageManipulationReflectedDomBased.json` |
| 5246722 | HTML5 storage manipulation (stored DOM-based) | stored | `localStorage` / `sessionStorage` name and value setters | `00500f02_Html5StorageManipulationStoredDomBased.json` |
| 5246976 | Link manipulation (DOM-based) | DOM | navigation target: link/form/iframe URL attributes | `00501000_LinkManipulationDomBased.json` |
| 5246977 | Link manipulation (reflected DOM-based) | reflected | navigation target | `00501001_LinkManipulationReflectedDomBased.json` |
| 5246978 | Link manipulation (stored DOM-based) | stored | navigation target | `00501002_LinkManipulationStoredDomBased.json` |
| 5247232 | Document domain manipulation (DOM-based) | DOM | `document.domain` setter | `00501100_DocumentDomainManipulationDomBased.json` |
| 5247233 | Document domain manipulation (reflected DOM-based) | reflected | `document.domain` setter | `00501101_DocumentDomainManipulationReflectedDomBased.json` |
| 5247234 | Document domain manipulation (stored DOM-based) | stored | `document.domain` setter | `00501102_DocumentDomainManipulationStoredDomBased.json` |
| 5247488 | DOM data manipulation (DOM-based) | DOM | DOM properties/attributes used by visible UI or client logic | `00501200_DomDataManipulationDomBased.json` |
| 5247489 | DOM data manipulation (reflected DOM-based) | reflected | DOM properties/attributes used by visible UI or client logic | `00501201_DomDataManipulationReflectedDomBased.json` |
| 5247490 | DOM data manipulation (stored DOM-based) | stored | DOM properties/attributes used by visible UI or client logic | `00501202_DomDataManipulationStoredDomBased.json` |

**Corrections to the earlier draft:** local-file IDs are `2098000-2098002`, open-redirection IDs are `5243152-5243154`, cookie IDs are `5245696-5245698`, Ajax-header IDs are `5245952-5245954`, denial-of-service IDs are `5246208-5246210`, web-message IDs are `5246464-5246466`, storage IDs are `5246720-5246722`, link IDs are `5246976-5246978`, and document-domain IDs are `5247232-5247234`. They were not inferred from family spacing; all were read from the JSON.

## 7. Options for WebProbe

WebProbe already has the browser and reporting substrates, but no Burp-style source-to-sink DOM analyzer in the supplied crawler/headless code. `app/core/src/crawl.rs:312-445` owns a CDP websocket, command dispatcher, event pump, and network capture. `Runtime.evaluate` is wrapped at `crawl.rs:645-649`; navigation and settling are at `crawl.rs:715-728`; Chromium is launched headless at `crawl.rs:656-707`; response capture/body retrieval is at `crawl.rs:348-407`. `app/core/src/headless.rs:19-37` defines a separate `HeadlessBrowser` abstraction; its Chromium implementation uses `--dump-dom` rather than CDP (`headless.rs:119-149`), and `js_crawl` renders pages at `headless.rs:248-292`.

### (a) Static taint analysis of fetched JavaScript in Rust — **largest**

**Reuse.** Raw response bodies are retained in `HistEntry.req_raw` / `resp_raw` (`app/core/src/net.rs:22-37`). `static_reference_corpus` already collects JavaScript/HTML/CSS bodies (`app/core/src/crawl.rs:75-90`), while browser responses are normalized and bodies collected at `crawl.rs:318-335,378-407`. Existing JavaScript-selection logic recognizes `.js` and JavaScript content types and extracts script `src` from HTML (`app/core/src/retirejs.rs:345-366`). Findings fit `ScanIssue` with name, detail, confidence, type ID, identity and evidence (`app/core/src/scan.rs:214-249`), and reporting maps them to KnowledgeBase details (`app/core/src/report.rs:324-349`).

**New work.** Extract inline/external/module scripts; add a JavaScript parser and AST; scope and reference resolution; source/sink/preserver declarations; forward taint propagation and path construction; source snippets; issue mapping and static timeouts. There is no JavaScript parser dependency in `app/core/Cargo.toml:6-33`, so parser choice/integration is a substantial part of the cost. A regular-expression-only implementation would not reproduce Burp's AST/taint pipeline in §2.

**Size:** largest of the three. It gives coverage without a browser and produces Burp-like static evidence, but has the highest false-positive and engineering cost and does not by itself establish exploitability.

### (b) Dynamic instrumentation through the existing CDP crawler — **medium**

**Reuse.** Use `Cdp::connect`, `Cdp::call`, and `Cdp::pump` (`app/core/src/crawl.rs:338-445`), `Runtime.evaluate` and `eval_json` (`crawl.rs:645-649,728-747`), navigation (`crawl.rs:715-728`), and browser response capture (`crawl.rs:348-407`). The crawl/audit driver already converts observed browser exchanges to audit items (`app/core/src/scan.rs:1104-1140`). Reuse `ScanIssue` and report generation as above.

**New work.** Add `Page.addScriptToEvaluateOnNewDocument` before navigation (not present in the current CDP setup at `crawl.rs:705-728`); inject canary values into the §3 sources; wrap setters/functions for chosen sinks; correlate source/sink values and capture stacks/context; map sink families to issues; implement dynamic timeouts and optional context-specific payload confirmation. Begin with `document.write`, `element.innerHTML`, `eval`, `Function`, location assignment, `document.cookie`, storage setters, `JSON.parse`, `document.evaluate`, and `webdatabase.executeSql`, then add jQuery and remaining groups. The DOM Invader files are useful evidence for the table shape, but their obfuscated extension/service-worker architecture should not be transplanted wholesale.

**Size:** medium. It avoids building a Rust JavaScript parser and confirms real runtime behavior, but requires robust early injection, frame handling, popup/postMessage coverage, side-effect containment, and anti-recursion controls. It is the smallest useful first increment and the recommended starting point.

### (c) Static and dynamic together — **largest total, closest to Burp**

**Reuse.** Reuse every item in (a) and (b), plus the shared `ScanIssue` evidence vector (`app/core/src/scan.rs:232-249`) and report mapping. Burp's model for keeping static code snippets and dynamic values in one issue is described in §4.

**New work.** Implement (a) and (b), then a common issue key (issue type + origin/path + variant + source/sink), evidence union/deduplication, and confidence merge. Use static candidates to guide dynamic confirmation; retain static snippets when dynamic execution is not reached; upgrade only on an observed sink hit rather than calling every dynamic candidate Certain. Match the six configuration keys and separate static/dynamic deadlines from §1.

**Size:** largest total and closest to Burp's architecture and false-positive controls. It is the appropriate second phase after (b) proves the instrumentation and issue schema, not the cheapest initial implementation.

### Suggested delivery order

1. **(b)** a narrow dynamic vertical slice with source/sink values and issue evidence.
2. Expand dynamic sink families and context-specific confirmation.
3. Add **(a)** for offline coverage and static-only candidates, then the **(c)** merge/confidence policy.

This order reuses the existing CDP crawler immediately while leaving room for Burp-compatible static evidence later.
