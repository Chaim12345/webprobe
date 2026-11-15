# Mechanics sheet — WebProbe (rebuild of Burp Suite Pro build 52685)

Facts below were read from `/opt/BurpSuite/burpsuite.jar`. Nothing here was run against a live
network. The application classes are name-obfuscated; JVM bytecode offsets within each method serve
as function addresses, and evidence is cited as `class.method` (reference, bytecode/disassembly and
built-in pseudo-Java evidence ids from `java_class_users_find` and `java_method_show`) or as the jar's
bundled montoya API sources. Native string/function tools reject JVM bytecode; the built-in Java
method decompiler supplies pseudo-Java plus authoritative disassembly. Behavior that is not
established from the live jar is labeled custom or simplified rather than presented as parity.

## Deep decompilation — live build 52685

The target is JVM bytecode, not native machine code; native string/function tools reject that format.
The addresses below are therefore JVM bytecode offsets inside the named methods. The manifest names
`burp.StartBurp` as the main class, with implementation version 52685.

| Behavior | Decompiled rule | Function address / evidence |
|---|---|---|
| Program entry | `main` parses arguments, selects desktop/headless mode, constructs and starts the suite, and reports categorized startup failures. Argument setup waits up to 200 ms for an OS open-files callback. | `burp.StartBurp.main`: parsing `000e`–`001b`, construction `00f5`–`0117`, launch event `017e`; `ev_df29febb6b075150c0b1d4a5b176d0bbaeac1151c7df10104089c27349fe191d`. `burp.StartBurp.Zc`: wait `0031`–`003b`; `ev_d41695f9f49ed12160f4b3a0b941a2a693acf86d3621ddf9ce61ca2efe97ac5f` |
| Interception enabled | Public enable passes `true` to the proxy model; the model forwards it to the active project. Startup remains disabled by default in this rebuild. | `burp.Za2u.enableIntercept` `0000`–`000a`, `ev_fb6685d12377ea0c5800c71983e9eaccf56161cef494464dc4be3d08bd3ce3f0`; `burp.Zedh.Zz(boolean)` `0000`–`000d`, `ev_d9a3b118b4899c58c42e622b6f70432412103e457223b755ac9ca7a2bc98b4d2` |
| History append, snapshot, and filter | Validate `0 <= index <= size`, insert into the backing list, and return a snapshot containing every entry. The filtered overload maps the complete list, filters that stream, then collects it. WebProbe searches the full history and limits only immediate-mode rendering to 1000 matching rows. | `burp.Za2u.history` `0001`–`0024`, `ev_34fb06dcf943b197818c9348ec6468938526d541667eb83d66cb9c8f20acbcac`; filtered overload `0009`–`0034`, `ev_18d4ee7a2bae6ab08debe9b2eb46eb1423014cb91cd28f80cf54ac1317b54521`; `burp.Zedh.ZZ` `0000`–`000f`, `ev_d16fef8f075594c2981cea07bd12914f35424522b5f3a5614f3d6a5dfe789948`; `burp.Zk8.ZZ` `000b`–`0067`, `ev_9d53433ddf4e3e14072d6df42d53622276cdab0582447d2be171c5b3c8b3585f`; `burp.Zfpb.ZI` `00a0`–`00aa` and `burp.Zkt.doAdd` `0000`–`0016`, `ev_4fb8a872a9f5795fd2692f9e97db4cff441eb185b169571356e09cba568ae944`, `ev_1b2288f3007c84f4fdc2c6d4ce86e5f695b6ff0280ce5e176ffb4ff3bc62fc20` |
| Payload list append | Pass the complete collection to `addAll`; `getRowCount` returns backing size. No slicing or count check. | `burp.Zzg1.lambda$add$1` `0000`–`000b`, `ev_3e9b46ded91252816fca6b8f64451dff14eeec3613207431beec0ce8a88b9bb7`; `getRowCount` `0000`–`0009`, `ev_c322853eca492cf67d7d3468cfc36e616deac0327b2e60d71193d4c5515a64fb` |
| Repeater-style send | Default overload selects `HttpMode.AUTO`; the three-argument overload sets `RedirectionMode.NEVER`. Dispatcher rejects null request/service/mode/redirection and rejects a non-null HTTP/2 version text with `AUTO`. | `burp.Zktc.sendRequest(request)` `0000`–`0008`, `ev_3a4725773a5b9501e0253b2c377943b2dfad49eb9d7b152a6503858f8127e0cb`; three-argument overload `0000`–`000d`, `ev_185892f5ff9b92bbc4db90e3f495f7823c80ba404ba3167e7d8506e1d913517d`; `burp.Zktc.Zn` validation `0003`–`0093`, execution `0094`–`00bd`, `ev_f695b624c861583272e2ed1e7fca04ee081d1c6294fc64358ac08202f0a11adb` |
| Scope API dispatch | Reject null/malformed URLs, construct a URL-backed location, and call scope engine `ZF`. Policy modes are false, true, suite scope, and custom scope for codes 0, 1, 2, 3. | `burp.Z_dm.isInScope` `0000`–`0035`, `ev_7251a41b1ca391bcca15e636bd6f725d74e7c9d5e44184b3b8f23385df38bf84`; `burp.Zjv2.ZF` `0012`–`004f`, `ev_7239f023f5c7ce5cd0704b14105207a192f5dc02a375f01eb158ba16db1a20b0` |
| Match-and-replace defaults | New rules are enabled, have empty match and replacement strings, and use literal matching because the regex boolean defaults to false. | `burp.Zmo7.<init>` `0007`–`0016`; field getters in `burp.Zmo7`; `ev_b17051619a3f3390149bdb6e4b01baebf1f76f1d0ceccd3522969cb3487d28b6`, `ev_20c6089d594d16fe93517aa28a74b4b1b45630eb0cba642d0919de1f024a4aca` |

### Current Deep-mode verification pass

Every method below was read with `java_method_show(decompile=true)` against the open live jar; the
pseudo-Java is inferred, while the cited JVM offsets are observed disassembly. The requested
`native_strings_find` and `native_function_pseudocode` were attempted and returned `not_supported`
because the target is a Java program.

| Behavior | Verified rule and function addresses | Current evidence |
|---|---|---|
| Entry point | `StartBurp.main` parses arguments at `000e`–`001b`, constructs the suite at `00f5`–`010e`, starts it at `0114`–`0117`, and emits the launch event at `017e`–`0181`. `StartBurp.Zc` waits 200 ms at `0031`–`0038` for desktop open-files handling. | `ev_c90e3819941d0b81f38258c84e5392a6ee9ba237e9c3ae64cad6017458307ddf`, `ev_f482a9afbe1b5c16c3fd5989e80a428c32853a07d5957ab1ffe85fc2df86bf98` |
| HTTP history | Full-list map/collect, map/filter/collect for the filtered overload, index-bounds check followed by insertion, and snapshot allocation using the complete backing size. No entry-count truncation. | `ev_d0187af4da0864020ee93de554f4f1ca51ce0b79fb21f11bfcc30efe6dfebcea`, `ev_e7c84a7fded64c346cdb1ff1fe5cc2283690847738dd9f089af3927722404eaf`, `ev_0ad33d982b56fc78d9c871bf1fc987ac144452b3bb325e820e0781b910c48ec4`, `ev_2520984922882af0c75c299b3e7c87c45d17f590a412bb88e2e800111e35d2e6`, `ev_a6132ba8afb689a3eec6b7d53f742d091295d09bf7df45215d8f3fbc9405a5d8` |
| Intruder payloads | `Zzg1.lambda$add$1` calls `addAll` at `0005`; `getRowCount` returns backing `size()` at `0004`. No fixed payload cap. | `ev_0c2d88822b2539c4f8c95933f96df8ffa693939aa84862aa5d120479ca8806ea`, `ev_7f8989bc8e0bfe77378a90b2de37f474f5c9ea09368e53885d31aa291e4f94c6` |
| Interception | `Za2u.enableIntercept` passes true at `0004`–`0005`; `Zcur.ZU` preserves incoming state with no handlers, applies returned request/annotations, and returns immediately for internal action 3 at `00bc`–`00c4`. | `ev_c5225682a55a58c67ce992ff7afcfd223f4d4f39231d33eee92f2fe77718596c`, `ev_bf7b8637ce57bbecdd493b00dd2726a663853f6649441c9a6d7d710714c853fe` |
| Scope | `Z_dm.isInScope` rejects null/malformed URLs; `Zjv2.ZF` dispatches modes 0/1/2/3 at `001b`–`004f`; `Zk1j.ZF` computes include AND NOT exclude at `0001`–`001b`. | `ev_32d8383707509cd47c6dcf729a52d3737a60319063d6e733912fa0beba17ad45`, `ev_be3a362e4ed590a01bb2eef8b3bcc93e98576ae3101cfdee03ae9ab24d98bb66`, `ev_29446127e073a6869304544e805f3afbcc172db2c442262c94f390ab0972e49f` |
| Repeater send | `Zktc.sendRequest(request)` delegates with `HttpMode.AUTO` at `0002`–`0005`; resource defaults independently set `repeater.follow_redirections=never`. | `ev_a38f92af41d01abab1d54e1408f83c8b163190df65259da2271207f156cfc665` |
| Rule model | `Zmo7.<init>` sets enabled=true at `0007`–`0009` and empty match/replacement at `000c`–`0016`. `Zkga.<clinit>` assigns action ordinals 0–8 at `0124`–`01f9`; match-and-replace is ordinal 8. | `ev_d848c7b286716d152aa3c96854c7dfc71256bc4f2de5073a9218b6ee4e7bf540`, `ev_d0dbb8d4afdff7eb109e1f84cabefe37df1db84d44b2251cd2f7ba52ccd7c1ff` |
| WebSocket history | `Za2u.webSocketHistory` maps and collects the full model at `0001`–`0024`; `Zedh.ZB()` maps the backing model to a full immutable snapshot at `000c`–`0024`. WebProbe retains all captured entries. | `ev_67a166383b5bf85200b28340bd3068ab92caa798f88c6a0f1b72f2dd1c41b77a`, `ev_b4208436f0d81fe154fae582f3ed35d22e6ebc17bd0c40c1368f1e6a850d3e4c` |
| Comparer handoff | Legacy `sendToComparer` rejects null input, converts it to one `ByteArray`, and forwards a one-element array at `0019`–`0038`; the Montoya implementation dispatches asynchronously. This verifies handoff, not the original diff algorithm; WebProbe's exact line-LCS diff is a documented simplification. | `ev_6686aa1a97b5189b388a99ea7ca474deeab8ad8af3f73fa659c6f78e24f2b798`, `ev_768e6cefde1f907a708d0c45605b148c2231500016dcc6478c8bcc47bda6f844`, `ev_9ab550632b541fb4087ca4b3936f9a42076431aa115725287a2057b41ba7e714` |

### TLS certificate constants and formulas

Current verification evidence: 2048-bit RSA `burp.Zeq0.ZV` `0000`–`0003`
(`ev_09598efc9dcf75fdb572d9960c1cac06086942bb0d63c5930f0efeaf0055d1e2`); CA serial and
extensions `burp.Zeq0.Zk` `000e`–`0072`
(`ev_bb04deb7d5d179b929eb5d4e27e79fa322df5e55c1ce4c5184ca5f249d8dd7c5`); CA dates
`burp.Zg88.Z_` `0050`–`0084`
(`ev_21ccf9e7a6d835412ed6a3bb7c0b3b011a294ad63dc6d87091d7982936d5a9df`); leaf generation
`burp.Zagi.<init>` `007d`–`01e0`
(`ev_6983dcf85eba65e96b0eac275d331837ed7d2b3f5352b968da00737c47cc11eb`); serial seed/increment
`burp.Zta7.<init>` `0004`–`0010` and `Zta7.Z_` `0000`–`0012`
(`ev_5a81da28092019309e54ce2f00dae9f703e4baf996c42079b4be5b06fc4a3b8d`,
`ev_d301797d7c2be3f51a0cc1dfb42b35d4176b6d9a84c2eb7eccd4e5a0b4177051`).

- **RSA keys and signatures:** 2048-bit RSA with SHA256withRSA (`PKCS_RSA_SHA256` in WebProbe).
  `burp.Zeq0.ZV()` loads 2048 at offset `0000` and has a legacy 1024-bit fallback at `0012`;
  WebProbe deliberately does not weaken keys on failure. Evidence
  `ev_e8237e1786399b68f1e03a2ed55f744d73f6f930ea2b28be10b227b2b1eacd0e`. Live `burp.Zeq0.ZM()`
  retains preferred-plus-fallback algorithm selection (`ev_269324e567e55cb29820fe54ccb713d5235e60c6faf8ff314006cee0a30e2f28`).
- **CA validity:** `notBefore` keeps the current date but sets its year to 2014 only when the
  current year is later than 2014 (equivalently `year = min(currentYear, 2014)`); `notAfter` is
  generation time plus 10 calendar years. `burp.Zg88.Z_()` offsets `0050`–`0084`, evidence
  `ev_7b303a5634e4ae2ac5e2de10d4fa53e96eb4d7ee60df593a259ba7e5bad2d487`.
- **CA serial and extensions:** `new BigInteger(32, SecureRandom)` gives a random non-negative
  32-bit serial (`burp.Zeq0.Zk` offsets `000e`–`0017`); critical CA basic constraints, non-critical
  subject key identifier, and critical key-usage mask 134 (digitalSignature + keyCertSign + cRLSign).
  Offsets `0034`–`0072`, evidence `ev_6739d5c3b3d5db2c27637179b509251eb0646b98b77a182ac65459364ffe7bae`.
- **Per-host validity:** `notBefore = now - 14 days`; `notAfter = notBefore + 199 days`.
  `burp.Zagi.<init>` offsets `007d`–`009c`, evidence
  `ev_c5ad9bed8376dfb4576c9e2838a727b4bc09ca279a9534b91d8fe8c7d37f5b63`.
- **Per-host serial:** constructor seeds an `int` counter from `Date.getTime()` truncated to 32
  bits. Each certificate evaluates `Math.abs(previous)` and then increments with 32-bit wrapping;
  the first serial is time-derived, not 1. `burp.Zta7.<init>` offsets `0004`–`0010` and `Zta7.Z_`
  offsets `0000`–`0012`; evidence `ev_e82cd22057091495c88576003cad01d5138f9d4ccc99f7b9c2e570729633025b`
  and `ev_8cff8a5b19639e537e3a523c6882d1ce0648724f32a5316bef933d263212eaa9`. WebProbe deliberately
  uses `unsigned_abs`; `rcgen` writes only positive serials, so Java's negative MIN_VALUE overflow is
  emitted as positive 2147483648. A signed counter helper would not change the emitted certificate.
- **Per-host certificate:** generated RSA key, host common name and DNS SAN entries (the primary
  host is added first when absent from the supplied SAN list, then the supplied names are appended),
  serverAuth extended usage, subject/authority key identifiers, critical digitalSignature usage
  (mask 128), signed by the local CA, and chain `[leaf, CA]`. `burp.Zagi.<init>` offsets
  `0009`–`0034`, `00c0`–`01e0`, evidence `ev_c5ad9bed8376dfb4576c9e2838a727b4bc09ca279a9534b91d8fe8c7d37f5b63`.
- **Persistence difference:** the original can reload its CA from Java preferences. WebProbe keeps
  the CA and private key in memory for the session and exports only the public PEM.

## Theme (source: `burp/theme/DarkTheme.json`)

| Name | Value | Source |
|---|---|---|
| Accent orange | `#FF6633` (shades `#AD5B28 #DB612F #FF7B4E #FF8D64 #FF9E7A #FFB090 #FFC1A6`) | DarkTheme.json swatch.orange |
| Mono greys | `#000000 #2B2B2B #323334 #424244 #525255 #6A6A6C #C5C7C8 #FFFFFF` | DarkTheme.json swatch.black |
| Editor/message background | `#323334` (`mono[1]`) | DarkTheme.json ui.editor.message.background |
| Message text | `#CECECE` | DarkTheme.json ui.editor.message.text |
| Message editor current line | `#35383A` | DarkTheme.json ui.editor.message.currentLineBackground |
| Selection background | `#2C5175` (`secondary[2]` = blue.shades[1]) | DarkTheme.json ui.editor.message.selectionBackground |
| Header-name/first-line color | `#D1E8F9` | DarkTheme.json ui.editor.message.headerName/httpFirstLine |
| Param/query value color | `#A5C35B` (paramValue), name `#BBCDFF` | DarkTheme.json ui.editor.message.paramValue/paramName |
| Body text | `#FFFFFF` (mono[7]) | DarkTheme.json ui.text.body |
| Disabled text / links | `#C5C7C8` / `#FFB090` / hover `#FF9E7A` | DarkTheme.json ui.text.disabled, link, linkHover |
| HTTP method colors | GET/OPTIONS=`#D37FA4` (magenta[3]), POST=`#9189FE` (purple[3]), HEAD/CONNECT/DELETE/PATCH/PUT/TRACE=`#83CDD1` (teal[3]), unknown=`#C5C7C8` | DarkTheme.json ui.target.method |
| Highlight row colors | `#FF6464 #FFC864 #FFFF64 #64FF64 #64FFFF #6464FF #FFC8C8 #FF64FF #B4B4B4` | DarkTheme.json ui.highlight |
| Compare colors | added `#387723` (green[2]), deleted `#5D3D3F` (red[2]), modified `#323945` (blue[2]) | DarkTheme.json ui.editor.message.compare |

UI base themes: mono[1] used for window/group backgrounds; primary palette = orange.

## UI behavior (source: `resources/Preferences/UserDefaults.json`)

| Name | Value | Source |
|---|---|---|
| Message editor font | monospace, size 13 | display.http_message_display.font_name "Courier", font_size 13 |
| UI font size | 13 | display.user_interface.font_size |
| Default look and feel | Light (build uses its Dark theme; we default dark, both offered) | display.user_interface.look_and_feel |
| Zebra striping in tables | true | display.table_appearance.zebra_striping |
| Pretty-print JSON by default | true | display.http_message_display.pretty_print_by_default |
| Interception at startup | off ("never") | misc.enable_proxy_interception_at_startup |
| Send to Repeater hotkey | Ctrl+R | misc.hotkeys |
| Send to Intruder hotkey | Ctrl+I | misc.hotkeys |
| Forward intercepted message | Ctrl+F | misc.hotkeys |
| Toggle proxy interception | Ctrl+T | misc.hotkeys |
| Issue Repeater request | Ctrl+Space | misc.hotkeys |
| Switch to Proxy / Repeater / Intruder / Dashboard | Ctrl+Shift+P / Ctrl+Shift+R / Ctrl+Shift+I / Ctrl+Shift+D | misc.hotkeys |
| URL decode / encode key characters | Ctrl+Shift+U / Ctrl+U | misc.hotkeys |
| Base64 decode / encode | Ctrl+Shift+B / Ctrl+B | misc.hotkeys |
| Inspector position | right, auto-expand | misc.inspector_* |

## Proxy / connections (source: `resources/Preferences/ProjectDefaults.json`, montoya API sources)

| Name | Value | Source |
|---|---|---|
| Proxy listener interface | 127.0.0.1:8080, running=true, per-host certificates | ProjectDefaults.json `proxy.request_listeners[0]`: `listen_mode=loopback_only`, `listener_port=8080` |
| Default request interception | Enabled rule: file extension does **not** match `(gif|jpg|png|css|js|ico|svg|eot|woff|woff2|ttf)`; response interception=false. WebProbe bypasses the hold queue for these extensions but still records them. | ProjectDefaults.json `proxy.intercept_client_requests.rules[0]` and `intercept_server_responses.do_intercept`; startup master switch remains off per UserDefaults.json |
| Connect timeout | 120000 ms | connections.timeouts.connect_timeout |
| Normal (read) timeout | 120000 ms | connections.timeouts.normal_timeout |
| Open-ended response timeout | 10000 ms | connections.timeouts.open_ended_response_timeout |
| DNS resolution timeout | 300000 ms / failed 60000 ms | connections.timeouts.domain_name_resolution_timeout |
| HTTP/1 keep-alive for outgoing suite requests | disabled (`enable_keep_alive=false`) | http.http1.enable_keep_alive |
| HTTP/2 supported | enabled | http.http2.enable_http2 |
| Understand 3xx redirects | true | http.redirections.understand_3xx_status_code |
| Strip 100-continue | false (keep) | http.status_100_responses |
| Concurrent request limit | 10 | resource_pools.default_resource_pool.concurrent_request_limit |
| Throttle interval | 500 ms (off by default) | resource_pools.default_resource_pool.throttle_interval_millis |
| Back off on 429 | true | resource_pools.default_resource_pool.auto_backoff_after_429_status_returned |
| Cookie jar monitored by | Proxy only | sessions.cookie_jar.monitor_proxy=true |
| Session rule default | use cookies from Burp's cookie jar | sessions.session_handling_rules.rules.0 |
| Default proxy display | original request/response | user_options.proxy.default_display_message |
| HTTP service transport | host + port + protocol; HTTPS is retained across history, Repeater, Intruder and active scans rather than inferred from the port | `burp.IHttpService.getHost/getPort/getProtocol` (ev_598de5b6b61daeca666fa9e63d01f9dc94fb8efc2ba8765b49c29d2bc89afa01); request/attack/issue consumers in ev_79f0e8e0578cbbdc149dd7979650da93e83fa1d37e6ff541fca2a09e8c18cdd5 |

## Scanner (sources: `resources/Preferences/AuditDefaults.json`, `resources/Preferences/CrawlDefaults.json`, `resources/Preferences/LivePassiveCrawlDefaults.json`, bundled montoya API sources)

| Name | Value | Source |
|---|---|---|
| Scan type filters enabled | passive + light active + medium active + intrusive active + JavaScript analysis, individual issue selection off | AuditDefaults.json scanner.issues_reported |
| Scan speed / accuracy | normal | AuditDefaults.json scanner.audit_optimization |
| Consolidate passive issues / skip ineffective checks | true | AuditDefaults.json scanner.audit_optimization |
| Max insertion points per base request | 30 | AuditDefaults.json misc_insertion_point_options.max_insertion_points_per_base_request |
| URL parameter quick scan | true | AuditDefaults.json frequently_occurring_insertion_points.quick_scan_url_params |
| Audit issue issue colors in UI | high=red, medium=orange, low=blue, info=grey | burp/theme/DarkTheme.json ui.issue |
| Crawl: max link depth | 4 | CrawlDefaults.json crawl_limits/optimization |
| Crawl: max unique locations | 1500 (max crawl time 150 min, max request count unlimited) | CrawlDefaults.json crawl_limits |
| Crawl: robots.txt / sitemap.xml / speculative links | requested (on) | CrawlDefaults.json customization.request_robots_txt/request_sitemap/request_speculative |
| Live passive crawl add-policy | item itself + links, same-domain only by default | LivePassiveCrawlDefaults.json crawler.live_passive_crawl |
| Unique locations audited per session | capped at 1500 (CrawlDefaults.json crawl_limits.maximum_unique_locations) | CrawlDefaults.json crawl_limits.maximum_unique_locations |
| Issue severities modeled | high / medium / low / info + confidence | bundled burp.api.montoya.scanner.audit.issues.AuditIssue |
| Severity + confidence enums | severity = HIGH, MEDIUM, LOW, INFORMATION, FALSE_POSITIVE; confidence = CERTAIN, FIRM, TENTATIVE | bundled burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.java / AuditIssueConfidence.java |
| Duplicate issue handling | duplicates get ConsolidationAction KEEP_EXISTING / KEEP_BOTH / KEEP_NEW; passive consolidation is enabled by default | bundled burp.api.montoya.scanner.ConsolidationAction.java + AuditDefaults.json scanner.audit_optimization.consolidate_passive_issues |
| Issue dispatch (decompiled) | burp.Zcur.ZZ(Z_oa) wraps the audit item into burp.Zkfg (AuditIssue adapter with Zj76/Zt08/Zuia services) and calls every registered AuditIssueHandler.handleNewAuditIssue over a snapshot copy of the handler list (java_method_show, evidence ev_2e5d6cee) | java_method_show burp.Zcur.ZZ + java_class_users_find AuditIssueHandler |

## Reference library cross-check (/root/burp-re, deobfuscated build 2026.7.1 / 51467; live target 52685)

- Match-and-replace rule model — now **verified directly in the live 52685 jar**:
  - `burp.Zkga` (live enum, decompiled `burp.Zzyn`/`Z_0x` classes): session/proxy rule actions
    `ACTION_RUN_MACRO, ACTION_SET_PARAM, ACTION_USE_COOKIES, ACTION_VALIDATE_SESSION,
    ACTION_PROMPT_FOR_BROWSER_RECOVERY, ACTION_RUN_POST_REQUEST_MACRO,
    ACTION_INVOKE_BURP_EXTENSION, ACTION_SET_HEADER, ACTION_MATCH_AND_REPLACE` (ordinal 8),
    each with `persistedId: byte`, `configName: String`, `description: String`.
  - `burp.Zmo7 implements Zugb` (live, decompiled): rule store with persisted fields
    `@0 byte` (variant), `@1 boolean enabled`, `@51 String match`, `@52 String replacement`,
    `@53 boolean isRegex`; constructor defaults `enabled = true, match = "", replacement = ""`
    (isRegex defaults false via field init) — identical to WebProbe's `MrRule::new()`.
  - `burp.Z_0x` (live adapter, decompiled): wraps the store with
    `super(Zkga.ACTION_MATCH_AND_REPLACE)`, exposes enabled via `Zg() -> Zo.ZYi()`, prints the
    "Match and replace: match → replacement" description, persists keys + `Zo.ZI6()` etc.
  - Reference-tree corroboration (build 51467, provisional names): separate request/response rule
    lists in `Zb4e` (`MATCH_AND_REPLACE_REQUEST` / `MATCH_AND_REPLACE_RESPONSE`).
  - WebProbe implements this exact model (Proxy options: two rule tables, regex flag included).
- HTTPS MITM: teardown of build 2026.7.1 shows a locally generated CA installed into
  OS trust stores (FINDINGS.md sec 1.3). WebProbe now implements equivalent per-host signing;
  trust setup remains manual (see the verified HTTPS section below).
- Proxy history and Intruder simple-list payload limits: superseded provisional notes removed;
  live 52685 bytecode evidence is documented below.

## Behavior notes

- Intercept decision pipeline (decompiled from the live jar):
  - `burp.Zcur.ZU(Zt_e,int,String,InetAddress)`: an empty handler list returns the incoming state
    unchanged (`0005`–`0012`). Otherwise it iterates a snapshot of `ProxyRequestHandler`s, constructs
    the intercepted request, calls `handleRequestReceived(...)`, applies a returned replacement and
    annotations, and maps `MessageReceivedAction` through `burp.Zeeu.Za(...)`. Internal state 3 is
    **DROP** and returns immediately (`00b7`–`00c4`); other non-null actions replace the carried state
    and processing continues. Evidence `ev_08d25ee3dbbefd82601884933d26b6446c620a566de9e139a1dc9da95f40ef83`.
  - `burp.Z_we.<clinit>` initializes the switch keys as INTERCEPT=1, DO_NOT_INTERCEPT=2, DROP=3,
    CONTINUE=4 (`0240`–`0285`; `ev_8e21bafa90871b6eeaa3a9aae8345e9c67eb594744e236251debc8d370d064a7`).
    `burp.Zeeu.Za` maps these to internal **1, 2, 3, 0** respectively; null also maps to 0
    (`0000`–`004b`; `ev_187544d0c84d390e5fdf496da91496ee4ec0c701c21229c6d2e3d2a2e5b63b6b`).
  - WebProbe's Forward releases the held request (CONTINUE); Drop terminates it (DROP). It does not
    expose a Montoya extension-handler runtime, so INTERCEPT and DO_NOT_INTERCEPT are documented API
    states rather than additional UI buttons.
- Custom scope: `burp.Zk1j.ZF` evaluates include AND NOT exclude at offsets `0001`–`001b`
  (`ev_29446127e073a6869304544e805f3afbcc172db2c442262c94f390ab0972e49f`). WebProbe's empty
  include list admits all locations, then any matching enabled exclusion removes the location.
- Intruder positions: the API represents payload markers as `Marker` ranges
  (`burp/api/montoya/core/Marker.java`, `HttpRequestTemplate.insertionPointOffsets()`); the UI
  template additionally wraps each marked span in § characters (not visible in API sources —
  WebProbe types § around the selected text, which behaves identically: split into segments,
  replace the attacked segment per payload, other markers keep their inner text).
- `AttackConfiguration.httpService()` returns empty when the template contains payload markers
  (bundled source `burp/api/montoya/intruder/AttackConfiguration.java`) — i.e. the request's Host
  header, not a separate target field, carries the upstream target for marker-based attacks.
  WebProbe reads the Host header exactly the same way.
- `--screenshot` mode: ~120 frames are drawn, then the framebuffer is captured (glow paint
  callback) and written as PNG; window opened without focus (`ViewportBuilder::with_active(false)`;
  Windows additionally `WindowLevel::AlwaysOnBottom`).
- Hand-rolled PNG writer + codecs (Base64/URL/Hex/HTML) use no external crates.

## Verified limits and HTTPS decision (live 52685)

- **Proxy history: no fixed entry cap.** `burp.Za2u.history()` maps and collects the complete model list at offsets `0001`–`0024` (`ev_34fb06dcf943b197818c9348ec6468938526d541667eb83d66cb9c8f20acbcac`); `burp.Zedh.ZZ()` reaches `burp.Zk8.ZZ()` (`ev_d16fef8f075594c2981cea07bd12914f35424522b5f3a5614f3d6a5dfe789948`). `Zk8.ZZ()` allocates a snapshot sized to the backing list and adds every element (`ev_9d53433ddf4e3e14072d6df42d53622276cdab0582447d2be171c5b3c8b3585f`). Insertion through `burp.Zfpb.ZI(int,Zfg0)` reaches backing `Zegb.add` at offsets `00a0`–`00aa` without pruning (`ev_4fb8a872a9f5795fd2692f9e97db4cff441eb185b169571356e09cba568ae944`); `burp.Zkt.doAdd` delegates directly to `List.add` (`ev_1b2288f3007c84f4fdc2c6d4ce86e5f695b6ff0280ce5e176ffb4ff3bc62fc20`). The filtered overload maps the complete model list and filters it before collection (`burp.Za2u.history(filter)` offsets `0009`–`0034`, `ev_18d4ee7a2bae6ab08debe9b2eb46eb1423014cb91cd28f80cf54ac1317b54521`). WebProbe likewise filters the complete retained history; because egui's `Grid` is not virtualized like Swing's `JTable`, only the newest 1000 matching rows are rendered.
- **Intruder simple-list payloads: no fixed count cap.** Live factory `burp.Zccb.Zr` case 1 constructs `burp.Zcpf` (`ev_1fcba5ba5fc3bb82202d2b3e56b509296954e22c0813efa7d4374986d3c95a9b`). Its `burp.Zcvd` widget owns `burp.Zzgz` (`ev_04c1ab7392e6a5a6252fd6c2c40ff3c79fb1a1636f357f5e1a9239c67352e692`), extending `burp.Zzg1` (`ev_36627541b2c1c1589223ddbbcd93a466e42e4d7e96eb7dd7ce38a36ec3ae8825`). `Zzg1.lambda$add$1` calls `Zegb.addAll` on the complete collection and `getRowCount` returns its full size (`ev_3e9b46ded91252816fca6b8f64451dff14eeec3613207431beec0ce8a88b9bb7`, `ev_c322853eca492cf67d7d3468cfc36e616deac0327b2e60d71193d4c5515a64fb`). WebProbe therefore runs every supplied payload.
- **HTTPS MITM: implemented and feasible in Rust/egui.** `rcgen` generates an in-memory self-signed CA and signs a cached certificate for each CONNECT host; `rustls` terminates client TLS and opens a separately verified upstream TLS connection using public WebPKI roots. No system trust setting is changed and the CA private key is never written to disk. The Proxy options panel exports only the public CA PEM; the user must trust it in their browser/test profile to avoid warnings. Verified by `net::tests::connect_intercepts_https_with_a_ca_signed_host_certificate`, covering a real CONNECT, client handshake to a CA-signed host certificate, upstream TLS, decrypted response, and history entry.

## Custom / simplified in this rebuild

| Name | Value | Evidence or explicit limit |
|---|---|---|
| Response status colors | 2xx=`#7DC164`, 3xx=`#E1B156`, 4xx/5xx=`#DF4C63`, unknown=`#C5C7C8` | WebProbe-specific mapping to DarkTheme green[4], yellow[3], red[3], mono[6]; no original status-code mapping is claimed |
| Crawler engine | not replicated: scan works on traffic already seen and on selected requests | the original's browser-driven crawler runs an embedded browser; live passive crawl add-policy (links, same-domain) is honored structurally |
| Scanner active checks | light active checks only: 2 probes per URL parameter (SQL error, reflection), max 30 insertion points per request; reflection findings require the full quote/angle-bracket probe to be returned unencoded, not merely its harmless marker | AuditDefaults.json limits the insertion points and enables light active checks; the full original check suite is not replicated |
| Scanner passive checks | WebProbe custom subset: missing security headers, cookie flags, server version disclosure, SQL error signatures, secrets in HTML comments | `scan::passive_check`; the original enables passive scanning, but this custom list is not represented as its complete implementation |
| Params/Headers structured views | read-only table in detail view | WebProbe-specific presentation; no original table-layout parity is claimed |
| Collaborator | local loopback HTTP and DNS listeners (no paid cloud service); generated payloads use loopback URLs | direct HTTP callbacks and DNS A/ANY queries are recorded; SMTP and public DNS callbacks are not implemented |
| WebSocket history / Logger++ | all captured frames retained (direction, opcode, payload); dedicated cross-tool Logger++ view not replicated | full-list history rule verified by `ev_67a166383b5bf85200b28340bd3068ab92caa798f88c6a0f1b72f2dd1c41b77a` and `ev_b4208436f0d81fe154fae582f3ed35d22e6ebc17bd0c40c1368f1e6a850d3e4c` |
| Comparer diff | exact line-level longest-common-subsequence rows; original handoff verified | WebProbe custom algorithm in `analysis::diff_line_rows`; the decompiled handoff does not establish the original diff algorithm |
| Sequencer reports | Shannon character entropy, effective alphabet `2^H`, numeric population statistics, and uniform-alphabet chi-square | WebProbe custom formulas in `analysis.rs`; ProjectDefaults.json enables the original's compression, correlation, count, FIPS, spectral and transition tests, which are not replicated |
| Extensions | extension list UI present; no JVM/Montoya extension runtime is embedded | loading third-party Java extensions is not implemented in this native Rust rebuild |
