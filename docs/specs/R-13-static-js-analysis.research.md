# R-13: How Burp's static JavaScript analysis works, for a WebProbe port

> **Research note (2026-11-24).** Read-only study of the decompiled Burp Suite Pro build in `/root/burp-re`. No WebProbe code was changed. Every claim cites a class and line; statements marked **(inference)** are conclusions drawn from the cited code, not read directly. It builds on [R-13-dom-analysis.research.md](R-13-dom-analysis.research.md) (configuration, detail templates, confidence, merge) and [R-13-dom-coverage-matrix.md](R-13-dom-coverage-matrix.md) (WebProbe's dynamic coverage) and does not repeat them.

**Path abbreviations.** `R/` = `/root/burp-re/out/readable_strict/root/`; `C/` = `/root/burp-re/out/cfr_fixed/burp/`; `X/` = `/root/burp-re/in/extract/` (class files). "javap" means `javap -c -p -constants -cp X burp.<Class>`. Decoded strings come from `/root/burp-re/out/strings/map_merged.tsv` or, for `Zeys`, from the constant-pool decoding in Appendix A.

## 0. Answer in brief

1. Burp parses JavaScript with **its own lexer and its own LR parser**, not Rhino. The grammar is `Zgxb` (180 productions); the parse table is generated from it when `Zpet` loads (`Zpet` → `Zcp3` → `Zwna` → `Zbb9`, driven by `Zbty`). No `burp/` or `net/portswigger/` class references `org/mozilla`; Rhino is there for bundled third-party libraries (§1.3).
2. Inputs: a JavaScript response, or an HTML response's inline scripts, fetched external scripts, `on*` attributes and `javascript:` URLs. All the scripts of one response are merged into one program (§1.2, §1.3).
3. The engine builds a graph of "hops" between AST nodes and symbols, using eight per-node propagation rules (assignment, declaration, `+`/`||`/`&&`/ternary/comma/parentheses, member access, index, call, argument to parameter, return). It then marks sources, sinks and "preservers" from one declarative table (§1.4).
4. Paths run depth-first from each source to a sink. Call and return must match. A path is kept only if its statements can be reached in that order through a control-flow graph (§1.4).
5. **The table has 69 sources, 290 sinks and 51 preservers** (`C/Zeys.java:186-595`, decoded in Appendix A). Sources are URL parts, `document.referrer`, `document.cookie` and `window.name` only (§2).
6. **Local file path manipulation** has 7 static sinks: the five `FileReader.readAs*` calls, and `root.getFile`/`root.getDirectory` (`C/Zeys.java:446-452`). Burp's dynamic decoder maps no sink to that type (§2.4).
7. **Client-side SQL injection has no static sink in this build.** The 566 decoded table strings contain nothing like `executeSql`, `openDatabase` or `transaction`, and no table entry maps to the SQL types. The dynamic decoder `Zcwh` has no SQL mapping either (§2.4). So **of the six "static-only" types, a port of this analyser can produce three (local file path, in DOM, reflected and stored form), not six.**
8. The reflected and stored variants are not decided from the JavaScript. They are found by a separate active stage. A probe payload that came back in a response becomes the only source, as a **string-literal** declaration. Whether the probe record is reflected (`Zec1`) or stored (`Zxqi`) chooses the issue type (§3).
9. The only budget is wall-clock time: `max_static_time_per_item` seconds. The clock starts before parsing, so parse time counts against the budget, but only the taint phases can be interrupted. The limit is checked at the first step and then every 600 steps, and JVM garbage-collection time is subtracted only on some checks. Issues found before the timeout are kept. There is no script-size or path-depth cap in the classes read (§4).
10. Size: about 295 classes and about 15,200 decompiled lines. About 7,000 of these are the front end, which a Rust parser crate would replace. A port can be staged as: script extraction, then parser and scopes, then the intraprocedural taint engine with the table (this makes all 15 families reportable in DOM form), then interprocedural flow with feasibility, then reflected and stored (§5).

## 1. The pipeline, class by class

### 1.1 Scheduling and gates

| Step | Class:line | What happens |
|---|---|---|
| Audit stage S1 | `R/Zwpe.java:79-81` | The JavaScript stage list is built only when `ZL8()` and `ZBA()` hold. `ZL8()` holds when static analysis is on with a positive time, or dynamic analysis is on with a positive time (`R/Zugv.java:16-20`). `ZBA()` holds when any base DOM type is enabled for either method (`R/Zse.java:155-165`). |
| Stage order | `R/Zwpe.java:91-127` | `Zeiz`, then `Zrb6.Zv` (base item), then `Zfl3` (finds external scripts), then `Zq4` (fetches them), then `Zhgz` (the static analysis), then `Zfk8`, `Zs6_` and `Zeh8`. One `Zs10` script cache is shared by `Zfl3`, `Zq4` and `Zhgz` (`Zwpe.java:84`). |
| Static gate | `R/Zhgz.java:31-41` | Runs only when the item is present, `ZLA()` (`scanner.javascript_analysis.use_static_analysis`, `R/Zxc3.java:28`), `Zb(JAVASCRIPT_STATIC_ANALYSIS)` (some type in `Zse.Ze` is enabled for static detection, `R/Zse.java:159-165`) and `ZLw() > 0` (`max_static_time_per_item`, `R/Zxc3.java:30-31`). |
| Task | `R/Zwqm.java:21-30` | Check ID `Zugn.JsAnalysisCheck`. Calls `new Zwrv().ZT(item, cache)`, which gives `Zr1q` (a list of `Zs1_` script units), then `new Zf59(config, Zb7n.DOM, clock, log).ZH(item, scripts, new Zb3f(new Zgs3(new Zh6h())))`. |

The static default is off (`use_static_analysis: false`). Built-in configurations change the time limit (R-13-dom-analysis §1).

### 1.2 Input: which code is analysed

`R/Zwrv.java:13-19` branches on the parsed response `Zuf8` (`R/Zuf8.java:8-49`: content type `Zmlg`, body offset, HTML token list `ZD`):

- **Script responses.** If the stated or inferred type is "script" (`Zmlg.ZG`, type 259, `R/Zmlg.java:120,213-219`) and the response is not an attachment, `ZO` takes the whole body after any byte-order mark as one unit (`R/Zwrv.java:21-28`). The marks checked are UTF-8, UTF-32 BE/LE and UTF-16 BE/LE (`R/Zh0p.java:4-23`). "Not an attachment" means `Zmlg.Zi` is false. That flag is set from `Content-Disposition: attachment` (`R/Zh63.java:53` → `R/Zr9o.java:37-40,52-54`).
- **HTML responses** (`Zmlg.Ze`, type 256, not an attachment): `Zd` walks the HTML tokens (`R/Zwrv.java:30-118`).
  - On a `<script>` start tag without `src`, the next text token becomes a unit if there is no `language` attribute or `language` is `javascript` (case-insensitive) (lines 42-49, 97-101). An end tag resets this (88-89). **The `type` attribute is not examined**, so a `<script type="application/json">` or template block is handed to the parser (inference from the code read; the HTML layer below may filter, see §6).
  - On a `<script src>`, the unit is the fetched body, if the cache `Zs10` holds one for that tag (lines 56-58; `R/Zs10.java:32-38`).
  - On any other start tag, every attribute whose name starts with `on` becomes a unit, and so does every attribute whose value starts with `javascript:`, minus the first 11 characters (lines 66-77). The constant `Zn` = `"javascript:".length()`: the javap static initialiser stores `String.length()` of the string decoded from keys `-30031/-29670`, and `map_merged.tsv` gives that string as `javascript:`. Attribute units are flagged (`Zhdb.Za()` = true) and appended after all script-tag units (lines 110-115).
- **Anything else** gives an empty list (`R/Zwrv.java:17`).

A unit is `Zhdb` (`R/Zhdb.java:3-54`): the text, the response, its start and end offsets in the response, and the attribute flag. The offsets are used later to highlight the evidence (§1.5).

**External scripts.**
- `Zfl3` (`R/Zfl3.java:23-27`) queues `Zif4.ZB` (`R/Zif4.java:16-52`). That is every `<script>` start tag with a `src`, with the URL resolved by `Zcvi.Zd`, and only when the response is not itself a script.
- `Zq4` (`R/Zq4.java:30-60`) fetches each queued script through `Zh7r.Zg`, **only when `request_missing_dependencies` is on** (`ZLu()`, `R/Zxc3.java:25`). It stores the body with `Zs10.ZH`, keyed by tag identity (`R/Zs10.java:20-26`).
- How `fetch_out_of_scope_resources` and response limits are applied inside `Zh7r` was not read (§6).

### 1.3 Front end: lexer, parser, recovery, program

| Step | Class:line | What happens |
|---|---|---|
| Analyser entry | `C/Zf59.java:76-80` | `new Zx7j(config, clock, item.Zn(), 600)` is the timer (§4). `new Ziww(Zpet.ZK, declarations, timer)`, then `ziww.Zb(scripts)`. |
| Language object | javap `burp.Zpet` `static {}` | `Zpet.ZK = new Zpet(new Zcp3(), new Zp5y())` is a singleton built when the class loads. `R/Zpet.java:13-56` supplies the parser (`Zflp`), the lexer rules (`Zx16.Za()`), the token post-processor (`Zptd`), the program merger (`Zpi4`), the scope passes (`Zwoi`), the propagation visitor (`Zurt`), the statement locator (`Zura`) and the control-flow and call passes (`new Zuyl(new Zcad(), new Zb80())`). |
| Parse table | `R/Zcp3.java:5-7`, `R/Zwna.java`, `R/Zbb9.java:15-25,197-213` | `Zwna` builds an LR action/goto table from the grammar when `Zpet` loads. The table generator also uses `Zm59`, `Zpt9`, `Zh4k`, `Zu_u` and `Zxx4` (from `Zwna`'s references). `Zbb9` stores it packed at 1–4 bytes per cell. Whether it is LALR(1) or canonical LR(1) was not established (§6). |
| Grammar | `R/Zgxb.java:13-400` | 180 productions (`grep -c var0.add`), each with a semantic action that builds an AST node. Precedence and associativity lists are at lines 290-397 (left for most operators, right for `=`). Comments and line terminators are skipped by `Zgpv` (`R/Zgpv.java:5-7`, line 398). Error recovery is supplied by `Zbff` → `Zs3s` (line 399, `R/Zbff.java:5-7`). |
| Lexer | `R/Zuf6.java:9-49`, `R/Zex4.java:14-50` | At each position the first rule in `Zx16` that matches wins. **If no rule matches, the position jumps to the end of the unit and the rest of the script is dropped** (`Zuf6.ZE`, lines 47-49). `Zx16`'s rule list is set only in its static initialiser. javap shows eight rules built from `Zev1(Zf8i)`, `Zcls(Zfmv)`, `Zwn(Zcy2)`, `Ziln(Zpoz)`, `Zm57(Zwtr)`, `Zw13(Zhy8, Zbnl)`, `Zczx(Zx24.ZE(), …)` and `Zera(Zxuy, Zpgg)`. `Zbnl` decodes string escapes, including hex (`R/Zbnl.java:9,188-203`), so it is the string-literal rule (inference). The meaning of the other rules was not read (§6). |
| Tokens | `R/Zik5.java:5-98` | 94 token types: ES5 keywords plus `let`, `of`, `get`, `set`, `const`, ES5 punctuators, `=>` (`EQUALS_GREATER`), regex/string/number literals, comments, line terminators, and four constants `A`, `B`, `C`, `D` with no visible use. There are **no tokens** for template literals, `class`, `async`/`await`, `yield`, `...`, `?.`, `??`, `**` or `import`/`export`. |
| Automatic semicolons | `R/Zptd.java:9-53` | When a line terminator separates two tokens, a `;` is inserted after `return`, `break` or `continue`, and before a `++`/`--` that follows an identifier (the restricted productions). Other automatic semicolon insertion happens in recovery (next row). |
| Grammar coverage | `R/Zgxb.java:16-286` | Supported: functions (declarations and expressions), object getters and setters (49-59), `var`/`let`/`const`, `if`, `for`, `for-in`, `for-of` (233,239), `while`, `do`, `with` (145), `switch`, `try`/`catch`/`finally`, labels, `throw`, `return`, `new`, `delete`, `void`, `typeof`, `instanceof`, `in`, the ternary and every compound assignment. Arrow functions are accepted only as `( )` or `(expr)` parameters with a statement body (279-282); a bare `x => …` has no production. Not supported, since neither tokens nor productions exist: template literals, classes, destructuring, spread/rest, default parameters, async/await, generators, optional chaining, nullish coalescing, exponentiation, modules. |
| Parser | `R/Zbty.java:23-77`, `R/Zwni.java:14-59` | A table-driven shift/reduce loop. Reduction calls the production's action (`Zwni.Zd`, 21-27). On an error, `Zwni.ZB` (40-42) calls recovery; if recovery fails, `Zx5j` is thrown (`Zbty.java:45-48`). |
| Error recovery | `R/Zs3s.java:14-76` | Up to three strategies are tried in turn at an error. `Zins` and `Zi42` substitute an `IDENTIFIER` token (`R/Zins.java:36`, `R/Zi42.java:80`). `Zhyg` inserts a `;` at a line break, before a `}` or at the end of input (`R/Zhyg.java:40,54,81`). After a success the counter resets (`ZW`, 71-76). The exact trigger conditions are not fully established (§6). |
| Failure | `R/Zu2c.java:15-41` | Each unit is lexed and parsed separately. A `Zx5e` (a parse failure after recovery) is caught, logged as `IGNORED`, and that unit is skipped. The other units continue. |
| One program | `R/Zpi4.java:9-37`, `R/Zu2c.java:39-40` | The top-level statements of every unit are concatenated into a single `Zctv` program. So **flows across scripts on the same page are analysed**, for example a global set in one script and used in another. |
| Scopes | `R/Zwoi.java:11-46` | Two whole-tree visitor passes, `Zurd` and `Zurv`. They attach symbols to identifiers: `Zct0.ZJ()` returns a `Zbjn` binding, and `CodeSymbols` lists are read in `R/Zimq.java:117-147` (inference from use; the passes themselves were not read line by line). |
| Control flow and calls | `R/Ziww.java:19-31` → `R/Zuyl.java:15-18` | `Zcad` (`R/Zcad.java:21-130`) records `ExecutionHops`, which are successor edges between statements. `Zb80` (`R/Zb80.java:9-71`) records `FunctionCalls` and `FunctionCallers` for calls whose callee resolves to a function definition (`Zct9`). |
| Rhino | grep over `X/` | `grep -rla org/mozilla X/burp X/net` finds nothing. The references outside `X/org/mozilla` are `io/swagger/converter/ModelConverterContextImpl.class` and `ModelConverters.class` (to `org/mozilla/javascript/Zaw`) and `com/github/fge/jsonschema/…/Za.class` and `…/helpers/Zp.class` (to `Za4`, `Zaf`, `Z_s`, `Zw` and `ast/Zo`). Only those third-party libraries use the bundled Rhino. Loading Rhino through reflection under an encrypted class name cannot be excluded, but nothing in the analyser chain above needs it. |

### 1.4 The taint engine

`Ziww.Zb` creates `Zhpe` (`R/Ziww.java:19-31`, `R/Zhpe.java:10-61`). On the first request for a path, `Zr4t.ZD` runs five phases (`R/Zr4t.java:28-35`). Each node visit calls the timer (`Zx7j.ZT`).

**Phase 1: preservers** (`Zr4t.Zb`, 49-63).
- Every preserver declaration is applied to every node (`R/Zeyi.java:34-46` → `R/Zi4a.java:15-42`).
- A matching call node gets a `TaintPreserver` set of `Zsed(argIndex, flag)`.
- For receiver methods (`argIndex == -1`, for example `x.substring()`) the mark goes on the member-name node instead.

**Phase 2: propagation hops** (`Zr4t.Zu` → `R/Zhmz.java:23-38`). Each node is visited by `Zurt` (`R/Zurt.java:8-46`), which dispatches on node type. A hop (`Zp8g`, from `ZN()` to `Zb()`) is stored on both of its ends under `TaintHops` (`R/Zimq.java:102-110`).

The node-type names below are inferred from the rule bodies:

| Node (class) | Rule | Hops created |
|---|---|---|
| assignment (`Zctm`) | `R/Zimt.java:4-52` | right-hand side → target. The target is the identifier's symbol, the symbol of the **last identifier** of a member chain, or the base of an index expression (`R/Zimq.java:149-179`). Also right-hand side → assignment node, and assignment → parent. |
| declaration, for-in/of (`Zctz`) | `R/Zihw.java:4-24` | initialiser or iterated expression → declared identifier, for `=`, `in` and `of`. |
| expression wrapper (`Zct2`) | `R/Zima.java:4-47` | identifier → its symbol (`Zimq.Zm`, 66-77); both operands of **`+`, `||`, `&&`** → expression; right operand of a comma → expression; `(e)` → expression; both branches of `?:` → expression. **No other operator propagates**: arithmetic other than `+`, comparisons and unary operators do not. |
| member access (`Zct_`) | `R/Zims.java:4-10` | node → parent; last identifier segment → node. |
| index access (`Zctk`) | `R/Zimz.java:4-8` | node → parent; base → node. |
| call (`Zct1`) | `R/Zim7.java:6-58` | Only when the callee resolves to a binding (`R/Zgkh.java:4-24`). If the binding is a function definition, the function's return symbol → call (`Zca8`). Each argument preserver gives argument *n* → call, and each receiver preserver gives receiver → call. Both are `Zu6h` hops when the preserver flag is true (`Zimq.java:16-32`). Then call → parent. |
| argument list (`Zct6`) | `R/Zim3.java:4-25` | For a resolved function definition: argument *i* → parameter *i* (`Zey9`, `Zimq.java:34-58,112-115`). |
| return (`Zctn`) | `R/Zimx.java:4-23` | returned expression → enclosing function's symbol. |

A hop between an identifier and its symbol is `Zu_g` instead of `Zu6m` when `Zimq.ZL` cannot find the binding among the code symbols of the enclosing scopes (`R/Zimq.java:83-100,117-147`). **(Inference)** Properties are tracked by name, without regard to the object they belong to: `o.x = t` taints the symbol bound to `x` (`Zimq.java:153-158`).

**Phase 3: sources and sinks** (`Zr4t.ZR`, 69-90).
- Source and sink declarations are applied **only to nodes that already have hops** (`Zeyi.ZH`, `R/Zeyi.java:13-31`).
- A node that is both a source and a sink gets a self-hop (27-30).
- The matchers are described in §2.1.

**Phase 4: pruning** (`R/Zpef.java:18-151`). Hops are removed repeatedly at non-sink nodes with no outgoing hop and at non-source nodes with no incoming hop, until only source-to-sink skeletons are left.

**Phase 5: path enumeration** (`R/Ziid.java:25-66` → `R/Zwk1.java:30-207`).
- For each node marked as a source, a depth-first search runs over a stack of hop iterators.
- A path is emitted each time a hop reaches a node marked as a sink (47-57).
- A hop already on the path is not followed again (75-83).
- **Calls and returns must match.** An argument → parameter hop pushes a call context. A return → call hop must return to that call site, or the path is dropped. A `Zu_g` hop clears the context (173-206).
- At a node with more than one outgoing hop, the partial path must also pass the feasibility test (85-112).

**Feasibility** (`Zwk1.Zt`, 108-112; `R/Zhs9.java:13-95`; `R/Zw_s.java:15-101`; `R/Zejb.java:13-87`; `R/Ze8f.java:18-160`).
- Each hop is mapped to the statement that encloses it. `Zura` captures three statement node types (`R/Zura.java:9-27`). The result is the ordered statement list `Zb2j`.
- `Zw_s` records `ReachableNodes` and propagates them to function callers.
- `Zejb` looks for an entry node from which every statement of the path is reachable.
- `Ze8f` walks the `ExecutionHops` for an execution order that visits the statements in path order. The result is `Zuas`, the "path result" handed to reporting (`R/Zuas.java:14-30`).

### 1.5 From a path to an issue

`C/Zf59.java:83-116` loops over the `Zuas` results:

1. The source declaration `Zpvp` is read from the first hop and the sink declaration `Zpv2` from the last hop (88-89).
2. `Zw9i.ZO` (`R/Zw9i.java:6-23`) rejects the path when the source and sink share a context other than `NONE` (URL, COOKIE or QUERY_STRING), unless the path contains a `Zu6h` hop, that is, a preserver whose flag is true. Example: `location = location.pathname.toLowerCase()` (URL to URL through a `false` preserver) is dropped. `location = location.pathname.substring(1)` is kept (inference from the tables in §2).
3. A filter `Zp9m` is applied to the sink's issue type. For DOM it accepts everything (`C/Zf59.java:47,118-120`). For re-confirmation, `Zi2o` passes `ZN::equals` and keeps only one type (`R/Zi2o.java:37-41`).
4. `Zg3g.ZD` → `Zb3f` → `Zgs3.Zk` (`R/Zb3f.java:16-26`, `R/Zgs3.java:16-38`) builds the issue:
   - **Type** = `Zf24.Zw(sink type, variant)` (line 28; `R/Zf24.java:6-225`). The variant comes from `Zfmi.ZL()`: `Zh6h` returns DOM (`R/Zh6h.java:12-14`); `Zh2b` returns reflected or stored (§3).
   - **Flags** = source flag | sink flag (line 26). The source flags are cookie = 1 and `window.name` = 2; the sink flag is jQuery = 4 on `$()` and `jQuery()` (§2).
   - **Confidence** = `Zwf8.Zd(flags, type)` (`R/Zwf8.java:212-229`). **Severity** = `Zwf8.Zt(flags, type)` (`R/Zwf8.java:14-83`). The rules are in R-13-dom-analysis §4. For local file path manipulation: the severity byte is 4 (`Zwf8.java:19-32`), lowered to 3 when the source is a cookie (`R/Ze_z.java:28-30`); the confidence is 2, Firm (`Zwf8.java:212-229`). The coverage matrix reads the bytes as 4 = High, 3 = Medium, 2 = Low, 1 = Information (inference, consistent with that matrix).
   - **Evidence** = `Zb3r`, holding: the path nodes (`Zgtx`, lines 157-172); highlight ranges per script in each response (79-130), where an attribute script's node offsets are mapped back through the raw attribute text (116-129); and the source and sink display strings (25). The detail text is rendered by `Zhp`/`Zr1p` (R-13-dom-analysis §5).
5. Issues are added to the result list as they are found (`Zb3f.java:20-22`). On a timeout, what was found so far is returned (§4).

**Disabled-type filter.** `Ze66` (`R/Ze66.java:15-121`) collects every DOM-family type (classes `Zwf8`, `Zwf1` and `Zwf6`; `R/Zwf1.java:3`, `R/Zwf6.java:3`) that is not enabled for static detection. It removes a sink declaration (`Zi47`/`Zi43`) when the type it would report for the variant in question (base type plus 0, 1 or 2) is in that set (`Ze66.java:72-126`). Sources and preservers are never removed.

## 2. Sources, sinks and preservers

### 2.1 How a declaration matches

The tables are in `Zeys`'s static initialiser (`C/Zeys.java:181-600`):
- `Zu`: 69 sources, lines 186-254.
- `ZV`: 290 sinks, lines 255-544.
- `Zc`: 51 preservers, lines 545-595.
- DOM analysis uses `ZT = Zu + ZV + Zc` (lines 596-598, used by `Zeys.ZS` at 31-33).
- Reflected and stored analysis uses `ZU = ZV + Zc` plus one string-literal source made per probe (lines 599-600, `Zeys.Zk` at 35-46).
- Javap shows that only `Zeys` and `Zflo` call the constructors of `Zbv0`, `Zpv2` or `Zpvp` (769 and 2 sites). Only `Zbv0` refers to the matcher classes `Zi4s`, `Zi4x`, `Ziiw`, `Zi43`, `Zi47` and `Zi4a`, apart from `Ze66`, which reads `Zi47`/`Zi43` to filter them. The only implementers of `Zx3j`/`Zp9u` are those matchers, `Zi4t` and `Zeyi`. `grep -rla` over `X/burp` finds the `TaintSink` key only in `Zeyi`, `Zf59`, `Zgpy`, `Zi43`, `Zi47`, `Ziiw`, `Zpef` and `Zwk1`, and `TaintSource` only in those classes plus `Zi4s`, `Zi4x` and `Ziid`. The `Zexn`/`Zx5w` matches are the unrelated dynamic `buildTaintSources`. Of these, only the matchers write the keys (`Zi47.java:18`, `Zi43.java:23`, `Zi4s.java:20`, `Zi4x.java:20`, `Ziiw.java:32,39,53`). No other declaration table exists.

**The builder.** `Zbv0(member, kind, role)` (`R/Zbv0.java:5-53`) has these setters: `Z_(receiver)`, `ZE(argIndex)`, `ZX(Zpvp source)`, `ZH(Zpv2 sink)` and `ZB(Zsed preserver)`. `Zy()` creates the matcher (bytecode at `R/Zbv0.java:55-156`):

| Role and kind | Matcher class:line |
|---|---|
| source, property | `Zi4s` (`R/Zi4s.java:15-23`): an expression that is not the callee of a call |
| source, function | `Zi4x` (`R/Zi4x.java:15-23`): a call node |
| source, string literal | `Ziiw` (`R/Ziiw.java:18-87`): a string-literal argument, a string-literal expression, or an identifier, whose token value equals the declaration |
| sink, function | `Zi43` (`R/Zi43.java:13-27`): marks argument *n* of the call. Arguments sit at child index `2n+1` of the argument list |
| sink, property | `Zi47` (`R/Zi47.java:11-22`): marks the **symbol** of the identifier, or of the last identifier of the member chain (`Zgkh.Zu`). A value reaches it through the assignment rule in §1.4 |
| preserver | `Zi4a` (`R/Zi4a.java:14-47`) |

The kind-to-class mapping is read from the node tests each matcher makes, not from the obfuscated switch map `Zgsk` (inference).

**Name and receiver matching** (`R/Zi4t.java:14-41`):
- With no receiver, the member matches a bare identifier whose parent is not a member access, for example the global `eval`.
- With a receiver, the **source text** of the member-access expression must fully match the regex built as `receiver + "." + member`, with each `.` escaped and each `*` turned into `.*`. So `*` means "any receiver", `*.document` means "any prefix, then `.document`", and `*window` also matches `mywindow`.
- Because the match is textual, it is (inference):
  - **sensitive to spelling**: `window["location"]` and `window . location` do not match;
  - **blind to aliasing**: `var d = document; d.URL` is not a source.

**Declaration fields.** A source or sink carries a flag (`Zpvh.Zb`), a display string (`Zpvh.ZZ`) and a context (`Zsyr`: `NONE`, `URL`, `COOKIE` or `QUERY_STRING`; `R/Zsyr.java:5-9`; `R/Zpvh.java:3-29`). A sink also carries its base issue type (`R/Zpv2.java:17-24`). A preserver carries `Zsed(argIndex, flag)`. An argument index of -1 means the receiver (`R/Zsed.java:7-22`).

### 2.2 Sources (all property reads; 12 groups, 69 entries)

| # | Member | Receiver patterns (`Z_`) | Display string(s) | Context | Flag | C/Zeys.java line(s) |
|---|---|---|---|---|---|---|
| 1 | `baseURI` | `*` | `the 'baseURI' property of a DOM element` | URL | 0 | 186 |
| 2 | `URL` | `document` | `document.URL` | URL | 0 | 187 |
| 3 | `documentURI` | `document` | `document.documentURI` | URL | 0 | 188 |
| 4 | `URLUnencoded` | `document` | `document.URLUnencoded` | URL | 0 | 189 |
| 5 | `referrer` | `document` | `document.referrer` | NONE | 0 | 190 |
| 6 | `location` | (none), `document`, `window`, `self`, `parent`, `top`, `*.document`, `*.window`, `*.self`, `*.parent`, `*.top` | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location` | URL | 0 | 191-201 |
| 7 | `href` | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location`, `*.document.location`, `*.window.location`, `*.self.location`, `*.parent.location`, `*.top.location` | `location.href`, `document.location.href`, `window.location.href`, `self.location.href`, `parent.location.href`, `top.location.href` | URL | 0 | 202-212 |
| 8 | `hash` | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location`, `*.document.location`, `*.window.location`, `*.self.location`, `*.parent.location`, `*.top.location` | `location.hash`, `document.location.hash`, `window.location.hash`, `self.location.hash`, `parent.location.hash`, `top.location.hash` | NONE | 0 | 213-223 |
| 9 | `pathname` | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location`, `*.document.location`, `*.window.location`, `*.self.location`, `*.parent.location`, `*.top.location` | `location.pathname`, `document.location.pathname`, `window.location.pathname`, `self.location.pathname`, `parent.location.pathname`, `top.location.pathname` | URL | 0 | 224-234 |
| 10 | `search` | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location`, `*.document.location`, `*.window.location`, `*.self.location`, `*.parent.location`, `*.top.location` | `location.search`, `document.location.search`, `window.location.search`, `self.location.search`, `parent.location.search`, `top.location.search` | QUERY_STRING | 0 | 235-245 |
| 11 | `cookie` | `document` | `document.cookie` | COOKIE | 1 | 246 |
| 12 | `name` | `window`, `self`, `parent`, `top`, `*.window`, `*.self`, `*.parent`, `*.top` | `window.name`, `self.name`, `parent.name`, `top.name` | NONE | 2 | 247-254 |

Flags: 1 = cookie, 2 = `window.name` family. `Ze_z` turns these into notes in the issue detail and into the severity cap (`R/Ze_z.java:9-30`).

**Not sources**: `localStorage` and `sessionStorage` reads, `postMessage` data (`event.data`), `input.value` and other DOM reads, XHR or `fetch` responses. No entry in `C/Zeys.java:186-254` covers them.

### 2.3 Sinks (290 entries in 102 groups)

Sink entries per family:

| Family | Static sinks |
|---|---|
| XSS 2097936 (C/Zcot.java:593) | 28 |
| JavaScript injection 2097952 (:597) | 18 |
| **Local file path manipulation 2098000 (:607)** | 7 |
| WebSocket URL poisoning 2097984 (:604) | 1 |
| Client-side XPath injection 2098016 (:610) | 4 |
| Client-side JSON injection 2098032 (:613) | 3 |
| Open redirection 5243152 (:668) | 140 |
| Cookie manipulation 5245696 (:683) | 1 |
| Ajax request header manipulation 5245952 (:686) | 2 |
| Denial of service 5246208 (:689) | 19 |
| HTML5 web message manipulation 5246464 (:692) | 1 |
| HTML5 storage manipulation 5246720 (:695) | 36 |
| Link manipulation 5246976 (:698) | 3 |
| Document domain manipulation 5247232 (:703) | 1 |
| DOM data manipulation 5247488 (:706) | 26 |

The client-side SQL injection base type (2097968, `C/Zcot.java:601`) and prototype pollution have **no** static sink.

Some entries look odd but are copied exactly as declared:
- the `srcdoc` property maps to open redirection (416);
- `src` is displayed as "the 'source' property" and maps to link manipulation (415);
- XHR `send()` and `jQuery.ajax()`/`$.ajax()` map to open redirection (385-386, 425);
- `open()`/`window.open()` map to open redirection for argument 0 (388-396), but to DOM data manipulation for arguments 1 and 2 (541-544);
- `requestFileSystem` and `requestQuota` map to denial of service (455-472);
- `$()` and `jQuery()` carry flag 4, which makes them Tentative (535-536).

| # | Family: base issue type and ID (constructor line in C/Zcot.java) | Kind | Member | Arg | Receiver patterns | Display string(s) | Ctx | Flag | C/Zeys.java line(s) |
|---|---|---|---|---|---|---|---|---|---|
| 1 | XSS 2097936 (C/Zcot.java:593) | call | `write` | 0 | `document` | `document.write()` | NONE | 0 | 383 |
| 2 | XSS 2097936 (C/Zcot.java:593) | call | `writeln` | 0 | `document` | `document.writeln()` | NONE | 0 | 384 |
| 3 | XSS 2097936 (C/Zcot.java:593) | property | `innerHTML` | - | `*` | `the 'innerHTML' property of a DOM element` | NONE | 0 | 417 |
| 4 | XSS 2097936 (C/Zcot.java:593) | property | `outerHTML` | - | `*` | `the 'outerHTML' property of a DOM element` | NONE | 0 | 418 |
| 5 | XSS 2097936 (C/Zcot.java:593) | call | `insertAdjacentHTML` | 1 | `*` | `the 'insertAdjacentHTML()' function of a DOM element` | NONE | 0 | 419 |
| 6 | XSS 2097936 (C/Zcot.java:593) | property | `on*` | - | `*` | `the 'on event' property of a DOM element` | NONE | 0 | 420 |
| 7 | XSS 2097936 (C/Zcot.java:593) | call | `add` | 0 | `*` | `the 'add()' function of JQuery` | NONE | 0 | 426 |
| 8 | XSS 2097936 (C/Zcot.java:593) | call | `after` | 0 | `*` | `the 'after()' function of JQuery` | NONE | 0 | 427 |
| 9 | XSS 2097936 (C/Zcot.java:593) | call | `append` | 0 | `*` | `the 'append()' function of JQuery` | NONE | 0 | 428 |
| 10 | XSS 2097936 (C/Zcot.java:593) | call | `animate` | 0 | `*` | `the 'animate()' function of JQuery` | NONE | 0 | 429 |
| 11 | XSS 2097936 (C/Zcot.java:593) | call | `insertAfter` | 0 | `*` | `the 'insertAfter()' function of JQuery` | NONE | 0 | 430 |
| 12 | XSS 2097936 (C/Zcot.java:593) | call | `insertBefore` | 0 | `*` | `the 'insertBefore()' function of JQuery` | NONE | 0 | 431 |
| 13 | XSS 2097936 (C/Zcot.java:593) | call | `before` | 0 | `*` | `the 'before()' function of JQuery` | NONE | 0 | 432 |
| 14 | XSS 2097936 (C/Zcot.java:593) | call | `html` | 0 | `*` | `the 'html()' function of JQuery` | NONE | 0 | 433 |
| 15 | XSS 2097936 (C/Zcot.java:593) | call | `prepend` | 0 | `*` | `the 'prepend()' function of JQuery` | NONE | 0 | 434 |
| 16 | XSS 2097936 (C/Zcot.java:593) | call | `replaceAll` | 0 | `*` | `the 'replaceAll()' function of JQuery` | NONE | 0 | 435 |
| 17 | XSS 2097936 (C/Zcot.java:593) | call | `replaceWith` | 0 | `*` | `the 'replaceWith()' function of JQuery` | NONE | 0 | 436 |
| 18 | XSS 2097936 (C/Zcot.java:593) | call | `wrap` | 0 | `*` | `the 'wrap()' function of function of JQuery` | NONE | 0 | 437 |
| 19 | XSS 2097936 (C/Zcot.java:593) | call | `wrapInner` | 0 | `*` | `the 'wrapInner()' function of JQuery` | NONE | 0 | 438 |
| 20 | XSS 2097936 (C/Zcot.java:593) | call | `wrapAll` | 0 | `*` | `the 'wrapAll()' function of JQuery` | NONE | 0 | 439 |
| 21 | XSS 2097936 (C/Zcot.java:593) | call | `has` | 0 | `*` | `the 'has()' function of function of JQuery` | NONE | 0 | 440 |
| 22 | XSS 2097936 (C/Zcot.java:593) | call | `constructor` | 0 | `*` | `the 'constructor()' function of function of JQuery` | NONE | 0 | 441 |
| 23 | XSS 2097936 (C/Zcot.java:593) | call | `init` | 0 | `*` | `the 'init()' function of function of JQuery` | NONE | 0 | 442 |
| 24 | XSS 2097936 (C/Zcot.java:593) | call | `index` | 0 | `*` | `the 'index()' function of function of JQuery` | NONE | 0 | 443 |
| 25 | XSS 2097936 (C/Zcot.java:593) | call | `parseHTML` | 0 | `jQuery`, `\\$` | `jQuery.parseHTML()`, `$.parseHTML()` | NONE | 0 | 444-445 |
| 26 | XSS 2097936 (C/Zcot.java:593) | call | `$` | 0 | (none) | `$()` | NONE | 4 | 535 |
| 27 | XSS 2097936 (C/Zcot.java:593) | call | `jQuery` | 0 | (none) | `jQuery()` | NONE | 4 | 536 |
| 28 | JavaScript injection 2097952 (:597) | call | `execCommand` | 0 | `*` | `The 'execCommand()' function of a DOM element` | NONE | 0 | 397 |
| 29 | JavaScript injection 2097952 (:597) | call | `Function` | 0 | (none) | `the 'Function()' constructor` | NONE | 0 | 398 |
| 30 | JavaScript injection 2097952 (:597) | call | `eval` | 0 | (none), `*` | `eval()`, `the 'eval()' function of a DOM element` | NONE | 0 | 399, 405 |
| 31 | JavaScript injection 2097952 (:597) | call | `setTimeout` | 0 | (none), `*` | `setTimeout()`, `the setTimeout() function of a DOM element` | NONE | 0 | 400, 406 |
| 32 | JavaScript injection 2097952 (:597) | call | `setInterval` | 0 | (none), `*` | `setInterval()`, `the 'setInterval()' function of a DOM element` | NONE | 0 | 401, 407 |
| 33 | JavaScript injection 2097952 (:597) | call | `setImmediate` | 0 | (none), `*` | `setImmediate()`, `the 'setImmediate()' function of a DOM element` | NONE | 0 | 402, 408 |
| 34 | JavaScript injection 2097952 (:597) | call | `execScript` | 0 | (none), `*` | `execScript()`, `the 'execScript()' function of a DOM element` | NONE | 0 | 403, 409 |
| 35 | JavaScript injection 2097952 (:597) | call | `msSetImmediate` | 0 | (none), `*` | `msSetImmediate()`, `the 'msSetImmediate()' function of a DOM element` | NONE | 0 | 404, 410 |
| 36 | JavaScript injection 2097952 (:597) | call | `createContextualFragment` | 0 | `*` | `range.createContextualFragment()` | NONE | 0 | 411 |
| 37 | JavaScript injection 2097952 (:597) | call | `generateCRMFRequest` | 4 | `crypto` | `crypto.generateCRMFRequest()` | NONE | 0 | 412 |
| 38 | JavaScript injection 2097952 (:597) | call | `globalEval` | 0 | `jQuery`, `\\$` | `jQuery.globalEval()`, `$.globalEval()` | NONE | 0 | 413-414 |
| 39 | **Local file path manipulation 2098000 (:607)** | call | `readAsArrayBuffer` | 0 | `*` | `the 'readAsArrayBuffer()' function of a FileReader object` | NONE | 0 | 446 |
| 40 | **Local file path manipulation 2098000 (:607)** | call | `readAsBinaryString` | 0 | `*` | `the 'readAsBinaryString()' function of a FileReader object` | NONE | 0 | 447 |
| 41 | **Local file path manipulation 2098000 (:607)** | call | `readAsDataURL` | 0 | `*` | `the 'readAsDataURL()' function of a FileReader object` | NONE | 0 | 448 |
| 42 | **Local file path manipulation 2098000 (:607)** | call | `readAsText` | 0 | `*` | `the 'readAsText()' function of a FileReader object` | NONE | 0 | 449 |
| 43 | **Local file path manipulation 2098000 (:607)** | call | `readAsFile` | 0 | `*` | `the 'readAsFile()' function of a FileReader object` | NONE | 0 | 450 |
| 44 | **Local file path manipulation 2098000 (:607)** | call | `getFile` | 0 | `*.root` | `the 'root.getFile()' function of a FileSystem object` | NONE | 0 | 451 |
| 45 | **Local file path manipulation 2098000 (:607)** | call | `getDirectory` | 0 | `*.root` | `the 'root.getDirectory()' function of a FileSystem object` | NONE | 0 | 452 |
| 46 | WebSocket URL poisoning 2097984 (:604) | call | `WebSocket` | 0 | (none) | `the WebSocket() constructor` | URL | 0 | 453 |
| 47 | Client-side XPath injection 2098016 (:610) | call | `evaluate` | 0 | `document`, `*` | `document.evaluate()`, `the 'evaluate()' function of a DOM element` | NONE | 0 | 531-532 |
| 48 | Client-side XPath injection 2098016 (:610) | call | `parseXML` | 0 | `jQuery`, `\\$` | `jQuery.parseXML()`, `$.parseXML()` | NONE | 0 | 533-534 |
| 49 | Client-side JSON injection 2098032 (:613) | call | `parse` | 0 | `JSON` | `JSON.parse()` | NONE | 0 | 538 |
| 50 | Client-side JSON injection 2098032 (:613) | call | `parseJSON` | 0 | `jQuery`, `\\$` | `jQuery.parseJSON()`, `$.parseJSON()` | NONE | 0 | 539-540 |
| 51 | Open redirection 5243152 (:668) | property | `location` | - | (none), `document`, `window`, `self`, `parent`, `top`, `*.document`, `*.window`, `*.self`, `*.parent`, `*.top` | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location` | URL | 0 | 257-267 |
| 52 | Open redirection 5243152 (:668) | property | `href` | - | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location`, `*.document.location`, `*.window.location`, `*.self.location`, `*.parent.location`, `*.top.location` | `location.href`, `document.location.href`, `window.location.href`, `self.location.href`, `parent.location.href`, `top.location.href` | URL | 0 | 268-278 |
| 53 | Open redirection 5243152 (:668) | property | `host` | - | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location`, `*.document.location`, `*.window.location`, `*.self.location`, `*.parent.location`, `*.top.location` | `location.host`, `document.location.host`, `window.location.host`, `self.location.host`, `parent.location.host`, `top.location.host` | URL | 0 | 279-289 |
| 54 | Open redirection 5243152 (:668) | property | `hostname` | - | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location`, `*.document.location`, `*.window.location`, `*.self.location`, `*.parent.location`, `*.top.location` | `location.hostname`, `document.location.hostname`, `window.location.hostname`, `self.location.hostname`, `parent.location.hostname`, `top.location.hostname` | URL | 0 | 290-300 |
| 55 | Open redirection 5243152 (:668) | property | `pathname` | - | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location`, `*.document.location`, `*.window.location`, `*.self.location`, `*.parent.location`, `*.top.location` | `location.pathname`, `document.location.pathname`, `window.location.pathname`, `self.location.pathname`, `parent.location.pathname`, `top.location.pathname` | URL | 0 | 301-311 |
| 56 | Open redirection 5243152 (:668) | property | `protocol` | - | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location`, `*.document.location`, `*.window.location`, `*.self.location`, `*.parent.location`, `*.top.location` | `location.protocol`, `document.location.protocol`, `window.location.protocol`, `self.location.protocol`, `parent.location.protocol`, `top.location.protocol` | URL | 0 | 312-322 |
| 57 | Open redirection 5243152 (:668) | call | `assign` | 0 | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location`, `*.document.location`, `*.window.location`, `*.self.location`, `*.parent.location`, `*.top.location` | `location.assign()`, `document.location.assign()`, `window.location.assign()`, `self.location.assign()`, `parent.location.assign()`, `top.location.assign()` | URL | 0 | 323-333 |
| 58 | Open redirection 5243152 (:668) | call | `replace` | 0 | `location`, `document.location`, `window.location`, `self.location`, `parent.location`, `top.location`, `*.document.location`, `*.window.location`, `*.self.location`, `*.parent.location`, `*.top.location` | `location.replace()`, `document.location.replace()`, `window.location.replace()`, `self.location.replace()`, `parent.location.replace()`, `top.location.replace()` | URL | 0 | 334-344 |
| 59 | Open redirection 5243152 (:668) | call | `location` | 0 | (none), `document`, `window`, `self`, `parent`, `top`, `*.document`, `*.window`, `*.self`, `*.parent`, `*.top` | `location()`, `document.location()`, `window.location()`, `self.location()`, `parent.location()`, `top.location()` | URL | 0 | 345-355 |
| 60 | Open redirection 5243152 (:668) | call | `navigate` | 0 | (none), `window`, `self`, `parent`, `top`, `*.window`, `*.self`, `*.parent`, `*.top` | `navigate()`, `window.navigate()`, `self.navigate()`, `parent.navigate()`, `top.navigate()` | URL | 0 | 356-364 |
| 61 | Open redirection 5243152 (:668) | call | `showModalDialog` | 0 | (none), `window`, `self`, `parent`, `top`, `*.window`, `*.self`, `*.parent`, `*.top` | `showModalDialog()`, `window.showModalDialog()`, `self.showModalDialog()`, `parent.showModalDialog()`, `top.showModalDialog()` | URL | 0 | 365-373 |
| 62 | Open redirection 5243152 (:668) | call | `showModelessDialog` | 0 | (none), `window`, `self`, `parent`, `top`, `*.window`, `*.self`, `*.parent`, `*.top` | `showModelessDialog()`, `window.showModelessDialog()`, `self.showModelessDialog()`, `parent.showModelessDialog()`, `top.showModelessDialog()` | URL | 0 | 374-382 |
| 63 | Open redirection 5243152 (:668) | call | `ajax` | 0 | `jQuery`, `\\$` | `jQuery.ajax()`, `$.ajax()` | NONE | 0 | 385-386 |
| 64 | Open redirection 5243152 (:668) | call | `open` | 0 | (none), `window`, `self`, `parent`, `top`, `*window`, `*self`, `*parent`, `*top` | `open()`, `window.open()`, `self.open()`, `parent.open()`, `top.open()` | URL | 0 | 388-396 |
| 65 | Open redirection 5243152 (:668) | property | `srcdoc` | - | `*` | `the 'srcdoc' property of a DOM element` | NONE | 0 | 416 |
| 66 | Open redirection 5243152 (:668) | call | `open` | 1 | `*` | `the 'open()' function of an XMLHttpRequest object` | URL | 0 | 424 |
| 67 | Open redirection 5243152 (:668) | call | `send` | 0 | `*` | `the 'send()' function of an XMLHttpRequest object` | URL | 0 | 425 |
| 68 | Cookie manipulation 5245696 (:683) | property | `cookie` | - | `document` | `document.cookie` | COOKIE | 0 | 387 |
| 69 | Ajax request header manipulation 5245952 (:686) | call | `setRequestHeader` | 0 | `*` | `the 'setRequestHeader()' function of an XMLHttpRequest object` | NONE | 0 | 422 |
| 70 | Ajax request header manipulation 5245952 (:686) | call | `setRequestHeader` | 1 | `*` | `the 'setRequestHeader()' function of an XMLHttpRequest object` | NONE | 0 | 423 |
| 71 | Denial of service 5246208 (:689) | call | `requestFileSystem` | 1 | (none), `window`, `self`, `parent`, `top`, `*.window`, `*.self`, `*.parent`, `*.top` | `requestFileSystem()`, `window.requestFileSystem()`, `self.requestFileSystem()`, `parent.requestFileSystem()`, `top.requestFileSystem()` | NONE | 0 | 455-463 |
| 72 | Denial of service 5246208 (:689) | call | `requestQuota` | 1 | (none), `window`, `self`, `parent`, `top`, `*.window`, `*.self`, `*.parent`, `*.top` | `requestQuota()`, `window.requestQuota()`, `self.requestQuota()`, `parent.requestQuota()`, `top.requestQuota()` | NONE | 0 | 464-472 |
| 73 | Denial of service 5246208 (:689) | call | `RegExp` | 0 | (none) | `the RegExp() constructor` | NONE | 0 | 473 |
| 74 | HTML5 web message manipulation 5246464 (:692) | call | `postMessage` | 0 | `*` | `the 'postMessage()' function of an iframe element` | NONE | 0 | 454 |
| 75 | HTML5 storage manipulation 5246720 (:695) | call | `setItem` | 0 | `sessionStorage`, `window.sessionStorage`, `self.sessionStorage`, `parent.sessionStorage`, `top.sessionStorage`, `*.window.sessionStorage`, `*.self.sessionStorage`, `*.parent.sessionStorage`, `*.top.sessionStorage`, `localStorage`, `window.localStorage`, `self.localStorage`, `parent.localStorage`, `top.localStorage`, `*.window.localStorage`, `*.self.localStorage`, `*.parent.localStorage`, `*.top.localStorage` | `sessionStorage.setItem()`, `window.sessionStorage.setItem()`, `self.sessionStorage.setItem()`, `parent.sessionStorage.setItem()`, `top.sessionStorage.setItem()`, `localStorage.setItem()`, `window.localStorage.setItem()`, `self.localStorage.setItem()`, `parent.localStorage.setItem()`, `top.localStorage.setItem()` | NONE | 0 | 474, 476, 478, 480, 482, 484, 486, 488, 490, 492, 494, 496, 498, 500, 502, 504, 506, 508 |
| 76 | HTML5 storage manipulation 5246720 (:695) | call | `setItem` | 1 | `sessionStorage`, `window.sessionStorage`, `self.sessionStorage`, `parent.sessionStorage`, `top.sessionStorage`, `*.window.sessionStorage`, `*.self.sessionStorage`, `*.parent.sessionStorage`, `*.top.sessionStorage`, `localStorage`, `window.localStorage`, `self.localStorage`, `parent.localStorage`, `top.localStorage`, `*.window.localStorage`, `*.self.localStorage`, `*.parent.localStorage`, `*.top.localStorage` | `sessionStorage.setItem()`, `window.sessionStorage.setItem()`, `self.sessionStorage.setItem()`, `parent.sessionStorage.setItem()`, `top.sessionStorage.setItem()`, `localStorage.setItem()`, `window.localStorage.setItem()`, `self.localStorage.setItem()`, `parent.localStorage.setItem()`, `top.localStorage.setItem()` | NONE | 0 | 475, 477, 479, 481, 483, 485, 487, 489, 491, 493, 495, 497, 499, 501, 503, 505, 507, 509 |
| 77 | Link manipulation 5246976 (:698) | property | `href` | - | `*` | `the 'href' property of a DOM element` | NONE | 0 | 255 |
| 78 | Link manipulation 5246976 (:698) | property | `src` | - | `*` | `the 'source' property of a DOM element` | NONE | 0 | 415 |
| 79 | Link manipulation 5246976 (:698) | property | `action` | - | `*` | `the 'action' property of a DOM element` | NONE | 0 | 511 |
| 80 | Document domain manipulation 5247232 (:703) | property | `domain` | - | `document` | `document.domain` | NONE | 0 | 510 |
| 81 | DOM data manipulation 5247488 (:706) | property | `search` | - | `*` | `the 'search' property of a DOM element` | QUERY_STRING | 0 | 256 |
| 82 | DOM data manipulation 5247488 (:706) | call | `setAttribute` | 1 | `*` | `the 'setAttribute()' function of a DOM element` | NONE | 0 | 421 |
| 83 | DOM data manipulation 5247488 (:706) | property | `text` | - | `*` | `the 'text' property of a DOM element` | NONE | 0 | 512 |
| 84 | DOM data manipulation 5247488 (:706) | property | `textContent` | - | `*` | `the 'textContent' property of a DOM element` | NONE | 0 | 513 |
| 85 | DOM data manipulation 5247488 (:706) | property | `innerText` | - | `*` | `the 'innerText' property of a DOM element` | NONE | 0 | 514 |
| 86 | DOM data manipulation 5247488 (:706) | property | `outerText` | - | `*` | `the 'outerText' property of a DOM element` | NONE | 0 | 515 |
| 87 | DOM data manipulation 5247488 (:706) | property | `value` | - | `*` | `the 'value' property of a DOM element` | NONE | 0 | 516 |
| 88 | DOM data manipulation 5247488 (:706) | property | `values` | - | `*` | `the 'values' property of a DOM element` | NONE | 0 | 517 |
| 89 | DOM data manipulation 5247488 (:706) | property | `name` | - | `*` | `the 'name' property of a DOM element` | NONE | 0 | 518 |
| 90 | DOM data manipulation 5247488 (:706) | property | `target` | - | `*` | `the 'target' property of a DOM element` | NONE | 0 | 519 |
| 91 | DOM data manipulation 5247488 (:706) | property | `method` | - | `*` | `the 'method' property of a DOM element` | NONE | 0 | 520 |
| 92 | DOM data manipulation 5247488 (:706) | property | `type` | - | `*` | `the 'type' property of a DOM element` | NONE | 0 | 521 |
| 93 | DOM data manipulation 5247488 (:706) | property | `backgroundImage` | - | `*` | `the 'backgroundImage' property of a DOM element` | NONE | 0 | 522 |
| 94 | DOM data manipulation 5247488 (:706) | property | `cssText` | - | `*` | `the 'cssText' property of a DOM element` | NONE | 0 | 523 |
| 95 | DOM data manipulation 5247488 (:706) | property | `codebase` | - | `*` | `the 'codebase' property of a DOM element` | NONE | 0 | 524 |
| 96 | DOM data manipulation 5247488 (:706) | property | `title` | - | `document` | `document.title` | NONE | 0 | 525 |
| 97 | DOM data manipulation 5247488 (:706) | call | `createHTMLDocument` | 0 | `document.implementation` | `document.implementation.createHTMLDocument()` | NONE | 0 | 526 |
| 98 | DOM data manipulation 5247488 (:706) | call | `pushState` | 2 | `history`, `*.history` | `history.pushState()`, `window.history.pushState()` | URL | 0 | 527-528 |
| 99 | DOM data manipulation 5247488 (:706) | call | `replaceState` | 2 | `history`, `*.history` | `history.replaceState()`, `window.history.replaceState()` | URL | 0 | 529-530 |
| 100 | DOM data manipulation 5247488 (:706) | call | `text` | 0 | `*` | `the 'text()' function of JQuery` | NONE | 0 | 537 |
| 101 | DOM data manipulation 5247488 (:706) | call | `open` | 1 | (none), `window` | `open()`, `window.open()` | NONE | 0 | 541-542 |
| 102 | DOM data manipulation 5247488 (:706) | call | `open` | 2 | (none), `window` | `open()`, `window.open()` | NONE | 0 | 543-544 |

### 2.4 Which sinks lead to client-side SQL injection and local file path manipulation

- **Local file path manipulation (DOM 2098000, reflected 2098001, stored 2098002; `C/Zcot.java:607-609`)**: sink groups for `readAsArrayBuffer`, `readAsBinaryString`, `readAsDataURL`, `readAsText` and `readAsFile` (receiver `*`, argument 0) and for `root.getFile` and `root.getDirectory` (receiver `*.root`, argument 0), at `C/Zeys.java:446-452`. The variant types come from `Zf24` (`R/Zf24.java:64-73`) and are listed for static and dynamic detection (`C/Zcot.java:607-609`). Burp's dynamic sink decoder never returns this type: no `return Zcot.LOCAL_FILE_PATH_MANIPULATION_DOM_BASED` appears in `R/Zcwh.java`, whose 13 returned types are listed at `R/Zcwh.java:1236-1257` and above. So in Burp these three types come from the static path only (inference: it rests on the literal `return Zcot.*` statements in `Zcwh`).
- **Client-side SQL injection (2097968/2097969/2097970)**: **no sink**.
  - None of the 566 decoded `Zeys` strings matches `sql`, `database`, `transaction` or `executeSql`.
  - `grep -c SQL C/Zeys.java` gives 0.
  - `R/Zcwh.java` (dynamic) returns no SQL type either.
  - The only `webdatabase.executeSql` literal is a follow-up payload context in `R/Zbjx.java:158`.
  - No other class can mark a sink: only the `Zeys` and `Zflo` declarations create matchers, and only the matchers write `TaintSink` (§2.1).
  - The reflected and stored SQL types are absent from `Zse.Zp`/`Zse.ZV` (`R/Zse.java:30-63`), while the base type is in `Zse.Ze` (line 15).
  - The three SQL types are built with an extra constructor flag pair `(false, true)` (`C/Zcot.java:601-603`). The only other types with it are "Password field with autocomplete enabled" and "Browser XSS filter disabled" (`C/Zcot.java:677,681`). The second boolean feeds `Zp9h.Zt()`, and `Zp9h.Z_()` = `!Zt() && !Zn()` (`R/Zp9h.java:20-26`, `C/Zcot.java:358-368`). **(Inference)** The SQL types are kept for compatibility but are not produced by this build. The meaning of the flag is not established (§6).
- The task said six types come only from the static path. **This build supports three of them**: the local file path types. A WebProbe port that copies Burp's tables cannot report client-side SQL injection. Reporting it would need a WebProbe-specific sink (for example `executeSql` argument 0). That is a design decision, not Burp parity.

### 2.5 Preservers (51 entries)

A preserver passes taint from one argument, or from the receiver when the index is -1, to the call result (§1.4). If its flag is `true`, the hop is a `Zu6h`, which makes same-context source and sink pairs reportable (§1.5).

| # | Member | Receiver (`Z_`) | `Zsed` arguments (arg index, flag) | Line |
|---|---|---|---|---|
| 1 | `unescape` | (none) | `0, true` | 545 |
| 2 | `decodeURI` | (none) | `0, true` | 546 |
| 3 | `decodeURIComponent` | (none) | `0, true` | 547 |
| 4 | `anchor` | `*` | `true` | 548 |
| 5 | `big` | `*` | `true` | 549 |
| 6 | `small` | `*` | `true` | 550 |
| 7 | `blink` | `*` | `true` | 551 |
| 8 | `bold` | `*` | `true` | 552 |
| 9 | `fixed` | `*` | `true` | 553 |
| 10 | `fontcolor` | `*` | `true` | 554 |
| 11 | `fontsize` | `*` | `true` | 555 |
| 12 | `italics` | `*` | `true` | 556 |
| 13 | `link` | `*` | `true` | 557 |
| 14 | `strike` | `*` | `true` | 558 |
| 15 | `sub` | `*` | `true` | 559 |
| 16 | `sup` | `*` | `true` | 560 |
| 17 | `substring` | `*` | `true` | 561 |
| 18 | `substr` | `*` | `true` | 562 |
| 19 | `charAt` | `*` | `true` | 563 |
| 20 | `match` | `*` | `true` | 564 |
| 21 | `quote` | `*` | `true` | 565 |
| 22 | `replace` | `*` | `true` | 566 |
| 23 | `slice` | `*` | `true` | 567 |
| 24 | `split` | `*` | `true` | 568 |
| 25 | `replace` | `*` | `1, true` | 569 |
| 26 | `join` | `*` | `true` | 570 |
| 27 | `splice` | `*` | `true` | 571 |
| 28 | `parse` | `JSON` | `0, true` | 572 |
| 29 | `stringify` | `JSON` | `0, true` | 573 |
| 30 | `parseJSON` | `jQuery` | `0, true` | 574 |
| 31 | `parseJSON` | `\\$` | `0, true` | 575 |
| 32 | `evaluate` | `document` | `0, true` | 576 |
| 33 | `evaluate` | `*` | `0, true` | 577 |
| 34 | `parseXML` | `jQuery` | `0, true` | 578 |
| 35 | `parseXML` | `\\$` | `0, true` | 579 |
| 36 | `parseHTML` | `jQuery` | `0, true` | 580 |
| 37 | `parseHTML` | `\\$` | `0, true` | 581 |
| 38 | `concat` | `*` | `false` | 582 |
| 39 | `concat` | `*` | `0, false` | 583 |
| 40 | `toLowerCase` | `*` | `false` | 584 |
| 41 | `toLocaleUpperCase` | `*` | `false` | 585 |
| 42 | `toUpperCase` | `*` | `false` | 586 |
| 43 | `toLocaleLowerCase` | `*` | `false` | 587 |
| 44 | `toLocaleString` | `*` | `false` | 588 |
| 45 | `trimLeft` | `*` | `false` | 589 |
| 46 | `trimRight` | `*` | `false` | 590 |
| 47 | `toString` | `*` | `false` | 591 |
| 48 | `repeat` | `*` | `false` | 592 |
| 49 | `normalize` | `*` | `false` | 593 |
| 50 | `trim` | `*` | `false` | 594 |
| 51 | `valueOf` | `*` | `false` | 595 |

## 3. How the reflected and stored variants are decided

The JavaScript analysis itself never decides "reflected" or "stored". Both variants are separate **active** stages in the scan-phase factory `Zgjl`. The factory constructs one `Zf59` for reflected and one for stored (`R/Zgjl.java:112-113`), and its phases 5 and 6 build them (`R/Zgjl.java:232-289`).

1. **Probe.**
   - **Reflected** (`R/Zwr4.java:37-80`, "buildConfirmDirectDomReflectionsStage"): for each insertion point, `Zhgv.ZG` builds probe requests and `Zi97` sends them. Each reflection is recorded as a `Zgct` (`R/Zgct.java:5-50`): insertion point, payload `Zwe8`, response, parsed response `Zuf8`, attack record `Zh38`. Records are grouped by insertion point in `Zgtn` (`R/Zgtn.java:13-31`).
   - **Stored** (`R/Zh7d.java:41-97`, "buildReconfirmStoredDomReflectionsStage"): for each retrieval location that the scanner's stored-input tracking links to the insertion point (`Zsuv.Zro()`, 75-88), the retrieval request is re-issued after a probe. The record `Zgct.ZK` keeps both the submitting item and the retrieving item (`R/Zgct.java:33-37`).
2. **Scripts of the probe response.** `Zhrb` queues the external scripts of each record's response into a cache for that record (`R/Zhrb.java:31-55`; `Zwjj.Zd`). `Zwjj.ZD` extracts the units with the same `Zwrv.Zf` as the DOM path (`R/Zwjj.java:17-20`).
3. **The only source is the payload.**
   - `Zpwt.Zi` (`R/Zpwt.java:61-65`) passes the payload string (`Zgct.Zu().Z_()` as text) to `Zflo.ZG` (`R/Zflo.java:12-23`).
   - If the probe byte is `1`, the payload is prefixed with the insertion point's `Zf()` value (line 14). **(Inference)** That value is the original value the payload was appended to.
   - The result is decoded as a JavaScript string body by `Zirf.ZB` (`R/Zirf.java:90-106`, using the lexer cursor `Zex4` and the `Zbnl` escape decoder).
   - It becomes a single `STRING_LITERAL` source (`Zpvp(0, text, NONE)`).
   - The declarations are that source plus every sink and preserver (`Zeys.Zk`), filtered by `Ze66` for the variant.
   - **None of the 69 built-in sources is used.**
   - Any string literal, or identifier token, in the response's scripts whose value equals the decoded payload is therefore a source (`R/Ziiw.java:18-77`).
4. **Analysis and variant.**
   - `Zf59.ZN` runs the same engine (`C/Zf59.java:69-71`). It reports through `Zgs3` with `Zh2b` (`R/Zpwt.java:38-46`).
   - `Zh2b.ZL()` returns `Zcrn.ZH(REFLECTED, STORED)` (`R/Zh2b.java:30-32`). The single-message record `Zec1` returns the first argument, so the issue is reflected (`R/Zec1.java:47-49`). The two-message record `Zxqi` (submission and retrieval) returns the second, so the issue is stored (`R/Zxqi.java:53-55`).
   - The type is then `Zf24.Zw(sink type, variant)` (`R/Zgs3.java:28`).
   - The evidence adds the probe request highlights and payload (`R/Zh2b.java:13-21,40-50`).
5. **Re-confirmation.** `Ze12.ZA` → `Zi2o` (`R/Ze12.java:29-31`, `R/Zi2o.java:35-43`) re-runs the analysis on a response held by `Zh2f` (a follow-up exchange). It keeps only the one issue type under test (`this.ZN::equals`). It is reached from `Zbhz`/`Zpzh` (`R/Zbhz.java:32-38`). Exactly when it runs is not established (§6).

So a reflected or stored DOM-based issue means three things: the payload comes back inside a script; it is visible there as a string literal (or identifier) equal to the payload; and a feasible taint path runs from that literal to a sink. **No JavaScript is executed.**

## 4. Limits and budgets

| Limit | Class:line | Behaviour |
|---|---|---|
| Static time per item | `R/Zxc3.java:30-31,41`; `R/Zugv.java:14` | `scanner.javascript_analysis.max_static_time_per_item`, in seconds. The legacy `max_time_per_item` key is read first. Defaults are in R-13-dom-analysis §1: 30 s, 10 s in Fast/Lightweight/CICD, 600 s in "Audit coverage - maximum". |
| Timer | `R/Zx7j.java:19-38,40-155` (bytecode) | **The clock starts when `Zx7j` is constructed** (`Zj = clock.ZR()`, `R/Zx7j.java:22`). That happens at `C/Zf59.java:77`, before parsing. `ZT()` is called once per node visit or path step. **Cancellation** (`Zeaq.ZJ()`) is tested on every call (bytecode 0x00-0x10). The **time** check in `ZF()` reads the step counter before incrementing it (`dup_x1` at 0x05), so it fires at steps 0, 600, 1200, and so on (`Zf59` passes 600, `C/Zf59.java:77`). A limit of 0 or ≥ 2147483 s disables the check (0x19-0x39), although `Zhgz` never schedules a 0. The budget in ms is `limit × 1000`. Elapsed time is wall-clock time since construction. JVM GC time since construction is subtracted **only on a check that re-samples it**, which happens when at least budget/5 ms have passed since the last sample. On other checks the GC term is reset to 0 (`lconst_0; lstore 5` at 0x5c, re-sampling at 0x6e-0x7b). So the limit is in practice wall-clock time. `Zc2u` is thrown when elapsed time minus that term exceeds the budget, or when cancellation is set. |
| What the timer covers | `C/Zf59.java:77-84` | `ziww.Zb(scripts)` runs after the timer is constructed but before the `try`. It does lexing, parsing, scope, control-flow and call-graph passes, which never call `Zx7j` (`R/Zu2c.java`, `R/Zcad.java` and `R/Zb80.java` have no timer field). Their time **counts against the budget, but they cannot be interrupted**. If they use up the budget, the first `ZT()` in taint phase 1 throws and the item reports nothing (inference from the bytecode above). The five taint phases and path enumeration run lazily inside the `try` (`Zhpe.Za` → `Zr4t.ZO`) and are interruptible. |
| On timeout | `C/Zf59.java:110-115` | Logs event `STATIC_CODE_ANALYSIS_TIMEOUT` with the URL and records the metric `SCANNER_STATIC_ANALYSIS_TIMEOUT_DURATION`. **The issues collected so far are returned.** |
| Script size | `R/Zwrv.java`, `R/Zuf6.java`, `R/Zu2c.java` | No size check exists in these classes. Any limit on response size or fetched-script size would sit upstream, in `Zuf8` building or `Zh7r`, which was not read. |
| Depth and path count | `R/Zwk1.java`, `R/Zhpe.java`, `R/Ze8f.java` | No depth, hop-count or path-count cap was found. The bounds are the time budget, cycle avoidance (`Zwk1.java:75-83`) and call/return matching. |
| Unlexable input | `R/Zuf6.java:30-49` | The rest of the unit is dropped. |
| Unparsable unit | `R/Zu2c.java:24-31` | After recovery fails, the unit is skipped and the others are still analysed. |
| Attachments, non-HTML and non-script | `R/Zwrv.java:13-19` | Not analysed. |
| External scripts | `R/Zq4.java:33-35` | Fetched only when `request_missing_dependencies` is on. |

## 5. Size of the Burp implementation and a staged Rust port

### 5.1 Size

The classes were assembled by hand, starting from the analyser entry points and following references until they reached shared scanner infrastructure. The full list is in Appendix B.

The metric is lines in `readable_strict`. This count is skewed in both directions:
- `Zeys` shows 33 lines there, but its declaration table is 420 lines in `C/Zeys.java:181-600`;
- classes the decompiler failed on (`Zf59`, `Zx7j`, `Zbb9`, `Zbv0`) are inflated by bytecode listings.

A cluster heuristic that adds a class when at least half of the classes referencing it are already in the cluster gave 192 classes and 8,388 lines. That missed `Ze8f` and the lexer rules, so the hand list below is the estimate.

| Role | Classes | Lines (readable_strict) |
|---|---|---|
| Front end: lexer, grammar, runtime LR table generator, parser, error recovery, AST node classes | 151 | 6907 |
| Semantic passes and tree utilities: symbols, control flow, call graph, visitors, iterators | 25 | 1021 |
| Taint engine: propagation rules, pruning, path enumeration, feasibility, time budget | 45 | 2907 |
| Declarations: the decoded tables, matchers, variant filter | 23 | 833 |
| Input and orchestration: task, script extraction, external-script cache and fetch, path-to-issue loop | 18 | 812 |
| Issue building and text (shared with the dynamic path) | 12 | 1603 |
| Reflected and stored variants: probe records, string-literal source, stages, re-confirmation | 21 | 1158 |
| **Total** | **295** | **~15,240** (plus ~390 table lines hidden from `Zeys`) |

Reading of the numbers (inference):
- **About 45% is the front end** (151 classes, ~6,900 lines: grammar, runtime LR generator, lexer rules, 31 AST node classes, recovery). A Rust parser crate replaces it.
- **The engine proper** (semantic passes, taint engine, declarations, orchestration) is about 110 classes and ~5,600 lines.
- **The issue-building classes** (`Zwf8`, `Zf24`, `Zhp`, `Zr1p`, `Ze_z`) are shared with the dynamic path. WebProbe already has their equivalents for its dynamic DOM checks (`app/core/src/scan_checks/dom.rs`).
- **The reflected and stored glue** (21 classes, ~1,150 lines) depends on scanner stages (insertion points, stored-input tracking) that are outside the analyser.

### 5.2 What the port needs from a JavaScript parser crate (no crate chosen)

1. **Syntax.** At least the ES5 + `let`/`const`/`for-of`/arrow subset in §1.3 (`R/Zgxb.java:16-286`). Real pages need more (template literals, classes, destructuring, spread, async). Accepting more than Burp does changes coverage relative to Burp, and the port should state that.
2. **Error tolerance.** Burp recovers by inserting a semicolon or an identifier and drops only units that still fail (`R/Zs3s.java`, `R/Zu2c.java:24-31`). The crate must return either a partial AST or an error per unit, without aborting the page.
3. **Spans.** Each node needs a span convertible to response offsets, so that evidence can be highlighted (`R/Zgs3.java:116-130`). It also needs access to the exact source text of a member expression, because receiver matching is a regex over that text (`R/Zi4t.java:30-33`). Attribute scripts need an offset map back to the raw attribute (§1.5).
4. **Several fragments as one program**, or a way to merge their top-level scopes (`R/Zpi4.java`).
5. **Scope analysis.** Bindings for identifiers, function declarations and parameters, and "unresolved/global" as a separate state (`Zu_g` hops, `R/Zimq.java:83-147`).
6. **Something to build a statement-level control-flow graph from** (`ExecutionHops`, `R/Zcad.java`), unless the port drops the feasibility filter.
7. **String-literal values with escapes decoded** (`Zbnl`), used for the reflected/stored source match.
8. **Bounded cost** on large minified bundles. Burp counts parse time against the budget but cannot interrupt a parse (§4). A port should be able to stop parsing too.

### 5.3 Proposed stages

| Stage | Build | Becomes reportable | Depends on |
|---|---|---|---|
| S0: script extraction | The §1.2 rules: script responses after the BOM; HTML inline `<script>` (the `language` test, and **decide** whether to also honour `type`); `on*` attributes; `javascript:` URLs; attachment skip; external scripts gated by `request_missing_dependencies`. | Nothing on its own. | WebProbe's HTML tokenizer and response history (R-13-dom-analysis §7a lists the existing `crawl.rs` and `retirejs.rs` helpers); a fetcher for missing scripts. |
| S1: parse and scopes | Parse every unit, merge the units into one program, resolve symbols, record per-unit failures. | Nothing (diagnostics only). | The parser crate (§5.2 items 1-5, 7, 8). `app/core/Cargo.toml` has no JavaScript parser today. |
| S2: intraprocedural taint and the tables | The decoded table (§2), copied exactly including the odd entries; the matchers (`Zi4t` textual receiver regex); the propagation rules of §1.4 except argument→parameter and return; preservers with the `Zu6h` flag; the `Zw9i` same-context rule; the `Ze66` disabled-type filter; `Zf24`/`Zwf8` mapping; evidence of path statements and source/sink display strings; the time budget (§4). | All **15 DOM families in DOM form** found statically. This includes **Local file path manipulation (DOM-based) 2098000**, which is static-only in Burp. Families WebProbe already covers dynamically gain static candidates, which later need merging (R-13-dom-analysis §4). | S0, S1, the existing `ScanIssue`/report mapping. |
| S3: interprocedural and feasibility | Argument→parameter and return→call hops, call-site matching (`Zwk1.java:173-206`), the statement mapping, `ReachableNodes` and the execution-order check (`Zhs9`, `Zw_s`, `Zejb`, `Ze8f`). | No new types. Flows through user functions are found, and paths whose statements cannot run in order are dropped (fewer false positives). | S2; a statement-level control-flow graph (§5.2 item 6). |
| S4: reflected and stored variants | A string-literal source per probe (`Zflo`): the payload decoded as a JavaScript string body, with the optional base-value prefix; the analysis run on probe responses; the variant from the record type (single message → reflected, submission and retrieval → stored). | The reflected and stored types of every family with a static sink, including **Local file path manipulation (reflected 2098001, stored 2098002)**. | S2 (S3 optional); WebProbe active probing per insertion point (D-11) and stored-input tracking that links a submission to its retrieval URLs; the dynamic path's dormant stored-token design (coverage matrix) does not cover this. |
| S5: settings and merge | `use_static_analysis` (default off), `max_static_time_per_item` (default 30 s), the per-type static detection switch, and merging static with dynamic evidence and confidence. | No new types. Matches Burp's configuration surface. | S2-S4; R-13-dom-analysis §1 and §4. |
| (Outside parity) client-side SQL injection | A WebProbe-specific sink for `executeSql` argument 0 (2097968/9/70). | Only if the maintainers decide to go beyond Burp (§2.4). | S2/S4. |

**(Inference)** The work concentrates in S1 (choosing and adapting a crate, spans, and merging fragments), S2 (about 50 node-type rules and matchers plus the 410-entry table) and S3 (the control-flow graph). Burp's own classes for S2+S3 come to about 5,600 decompiled lines. S0 and S5 are small. S4 is mostly scanner plumbing, not analysis.

## 6. Not established

1. **The LR table algorithm.** Whether it is LALR(1) or canonical LR(1), and its conflict resolution. `Zwna`, `Zm59`, `Zpt9`, `Zh4k`, `Zu_u` and `Zxx4` were identified but not read. This does not matter for a port that uses a crate.
2. **What each lexer rule does.** The eight `Zx16` rules (`Zev1` … `Zera`) were only identified, through javap. Only `Zbnl` (string escapes) was read. It is not known how regex and division are told apart. `Zgxb.java:290` lists tokens passed to `Zxiw.Zp`, possibly for that purpose, but this was not read.
3. **The `Zik5` constants `A`, `B`, `C` and `D`.** No grammar or code use was found.
4. **When each recovery strategy fires.** `Zins`, `Zi42` and `Zhyg` were skimmed only for the token they insert (§1.3).
5. **The exact scope semantics of `Zurd`/`Zurv`.** These cover hoisting, block scope for `let`/`const`, closures and `with`. The engine's use of `CodeSymbols` was read; the passes were not.
6. **The node classes.** The class-to-construct mapping in §1.4 (for example `Zctm` = assignment, `Zctn` = return) was inferred from the rule bodies and the grammar actions, not from a full read of the `Zgxb` semantic-action classes.
7. **Whether properties are tracked by object.** §1.4 infers that they are tracked by name only, from `Zimq.java:153-158`. It was not confirmed with `Zurv`.
8. **The internals of `Ze8f`, `Zc72` and `Ze5y`.** These are the execution-order search and its loop handling. Only the structure was read; whether `Ze5y` bounds loops by count was not determined.
9. **The meaning of the `Zcot` flag `(false, true)`.** It is shared by the three client-side SQL injection types and two legacy passive types (`C/Zcot.java:601-603,677,681`), so it is not known whether those types are formally retired. No class that reads `Zp9h.Zt()` for DOM types was traced.
10. **The HTML layer.** Whether the HTML tokens (`Zbpq` types 0, 1, 3 and 4; `R/Zwrv.java:39-97`) treat `<script type=…>` or `<template>` content specially, whether attribute names are lower-cased (`Zh8o.ZF6()`), and whether attribute values are entity-decoded (`ZFY()`). Not read.
11. **`Zh7r` fetch rules.** How `fetch_out_of_scope_resources`, response size limits, caching and redirects apply to external scripts. Not read.
12. **Size limits upstream.** No script-size cap exists in the analyser classes. A cap in `Zuf8` construction (`Ze2p.ZR`) or in the history was not looked for.
13. **The probe payloads and the `Zwe8.Zs()` byte.** What payloads `Zhgv` sends, and the exact meaning of the byte that prefixes the base value (`R/Zflo.java:14`). The inference that it means "appended to the original value" was not verified.
14. **When re-confirmation (`Zbhz`/`Zpzh` → `Zi2o`) runs**, and what follow-up exchange `Zh2f` holds.
15. **What `Zuwm.Zo(boolean)` records** in `R/Zwqm.java:23` (it receives "no scripts found").
16. **Rhino through reflection.** It cannot be excluded that Rhino is loaded by an encrypted class name through reflection. No constant-pool reference exists in `burp/` or `net/portswigger/` (§1.3).
17. **No runtime confirmation.** Nothing here was checked by running Burp. All of it is read from decompiled code and decoded constants.

## Appendix A: decoding the `Zeys` tables

`readable_strict` strips the initialiser, and `C/Zeys.java:51-180` shows the string decoder only as CFR pseudo-code, with the first ciphertext inside an `AssertionError`. `tools/zkm_static_strings.py` therefore decodes garbage for this class. To recover the 566 strings `var0[0..565]`:

1. Read the class file `X/burp/Zeys.class` and take the two `ldc` string constants of the static initialiser. These are constant-pool entries **#3** and **#4** (javap: `ldc #3` at bytecode 10, `ldc #4` at bytecode 69). Read them as modified UTF-8 from the raw constant pool, not from javap's escaped text.
2. Each constant is a sequence of segments. The first segment's length is a constant: **12** for #3 and **24** for #4 (`C/Zeys.java:58,82`). After each segment, the next character is the length of the following segment (`C/Zeys.java:76-77`).
3. XOR each character at position *j* of a segment with `v0 ^ key[j % 7]`. Here `v0` = **94** for #3 and **126** for #4 (`C/Zeys.java:64,88`), and `key` = **[27, 19, 104, 108, 77, 14, 79]** (`C/Zeys.java:124-151`).
4. The decoded segments, in order, are `var0[0]` … `var0[565]`. Substitute them into `C/Zeys.java:186-595`.

Check: `var0[99]` = `baseURI` and `var0[466]` = `the 'baseURI' property of a DOM element` (line 186), `var0[501]`/`var0[251]` = `URL`/`document` (line 187). The `\$` receiver (`var0[388]`, `var0[455]`) is the two characters backslash-dollar, a regex-escaped `$`.

## Appendix B: classes by role (readable_strict line counts)

- **Front end: lexer, grammar, runtime LR table generator, parser, error recovery, AST node classes** (151 classes, 6907 lines): `Zb2s` 20, `Zb_i` 20, `Zbb9` 218, `Zbf0` 4, `Zbff` 8, `Zbnl` 254, `Zbqs` 4, `Zbry` 65, `Zbty` 82, `Zbuq` 41, `Zbve` 22, `Zc6f` 24, `Zcls` 14, `Zcne` 29, `Zcnf` 20, `Zcp3` 8, `Zct0` 40, `Zct1` 19, `Zct2` 19, `Zct4` 25, `Zct5` 16, `Zct6` 19, `Zct8` 14, `Zct9` 23, `Zct_` 19, `Zctb` 19, `Zctc` 21, `Zctd` 14, `Zcte` 43, `Zctf` 66, `Zctg` 19, `Zcth` 19, `Zcti` 18, `Zctj` 19, `Zctk` 19, `Zctl` 103, `Zctm` 42, `Zctn` 34, `Zcto` 19, `Zctp` 19, `Zctq` 58, `Zctr` 19, `Zctu` 19, `Zctv` 14, `Zctw` 57, `Zcty` 26, `Zctz` 51, `Zcwu` 28, `Zcy2` 438, `Zczx` 28, `Zczy` 41, `Ze0c` 20, `Ze1x` 123, `Zeab` 162, `Zei2` 16, `Zenw` 45, `Zeo9` 20, `Zera` 14, `Zerm` 10, `Zev1` 14, `Zevq` 20, `Zex4` 51, `Zey0` 55, `Zf8i` 74, `Zf9y` 4, `Zflp` 20, `Zfmv` 173, `Zg1q` 11, `Zg80` 98, `Zgpv` 8, `Zgxb` 402, `Zgyn` 20, `Zh4k` 74, `Zh_k` 38, `Zhju` 20, `Zhlt` 30, `Zhsh` 7, `Zhy8` 13, `Zhyg` 83, `Zi0` 16, `Zi42` 100, `Zik5` 211, `Zilk` 9, `Ziln` 14, `Zins` 38, `Zio` 19, `Ziz` 18, `Zm1q` 76, `Zm46` 20, `Zm57` 14, `Zm59` 254, `Zm8y` 11, `Zm9p` 21, `Zmak` 5, `Zmh7` 20, `Zo` 5, `Zp5y` 160, `Zpbe` 124, `Zpet` 58, `Zpgg` 24, `Zpi4` 39, `Zpoz` 27, `Zps_` 5, `Zpt9` 86, `Zptd` 63, `Zr6h` 9, `Zr8v` 64, `Zrk` 22, `Zs3s` 77, `Zsbg` 20, `Zshp` 20, `Zsit` 20, `Zsl` 35, `Zsmb` 32, `Zsnu` 86, `Zstb` 5, `Zsvu` 148, `Zu0n` 20, `Zu2c` 46, `Zu6t` 73, `Zu_u` 34, `Zuf6` 50, `Zuge` 19, `Zums` 20, `Zw0e` 14, `Zw13` 14, `Zw4f` 5, `Zw8p` 13, `Zw_p` 20, `Zwn` 14, `Zwna` 31, `Zwni` 60, `Zwtr` 8, `Zwyr` 11, `Zwz1` 81, `Zx0x` 49, `Zx16` 16, `Zx24` 71, `Zx5e` 10, `Zx5j` 18, `Zx8u` 20, `Zx9h` 7, `Zxa2` 17, `Zxem` 7, `Zxf9` 7, `Zxiw` 92, `Zxl8` 20, `Zxo7` 44, `Zxuy` 22, `Zxx4` 53, `Zxxx` 41
- **Semantic passes and tree utilities: symbols, control flow, call graph, visitors, iterators** (25 classes, 1021 lines): `Zb80` 72, `Zbjn` 7, `Zcad` 132, `Zf57` 12, `Zf5a` 26, `Zfmf` 5, `Zgkh` 25, `Zgmx` 16, `Zhql` 9, `Zmq5` 5, `Zp8b` 16, `Zpfg` 5, `Zrb5` 7, `Zs1t` 169, `Zsmh` 35, `Zurd` 96, `Zuru` 105, `Zurv` 62, `Zuuu` 25, `Zuyl` 28, `Zw64` 13, `Zwei` 16, `Zwo3` 33, `Zwoi` 57, `Zx3r` 45
- **Taint engine: propagation rules, pruning, path enumeration, feasibility, time budget** (45 classes, 2907 lines): `Zb2j` 58, `Zboi` 241, `Zc0v` 34, `Zc2u` 12, `Zc72` 92, `Zca8` 21, `Ze5y` 42, `Ze7p` 18, `Ze8f` 227, `Ze_8` 9, `Zeaq` 5, `Zejb` 88, `Zey9` 21, `Zgpy` 30, `Zhmz` 48, `Zhpe` 62, `Zhs9` 96, `Zihw` 24, `Ziid` 67, `Zim3` 26, `Zim7` 59, `Zima` 76, `Zimq` 194, `Zims` 11, `Zimt` 53, `Zimx` 24, `Zimz` 9, `Ziut` 117, `Ziww` 46, `Zp8g` 7, `Zpef` 161, `Zr4t` 95, `Zrha` 9, `Zsk0` 7, `Zstv` 101, `Zu6h` 7, `Zu6m` 33, `Zu_g` 21, `Zuas` 50, `Zura` 42, `Zurt` 56, `Zw_s` 108, `Zwc3` 19, `Zwk1` 208, `Zx7j` 173
- **Declarations: the decoded tables, matchers, variant filter** (23 classes, 833 lines): `Zbv0` 161, `Ze66` 127, `Zeyi` 57, `Zeys` 33, `Zgse` 10, `Zgsk` 9, `Zi43` 28, `Zi47` 23, `Zi4a` 48, `Zi4s` 24, `Zi4t` 56, `Zi4x` 24, `Ziiw` 88, `Zp9m` 5, `Zp9u` 7, `Zpuj` 8, `Zpv2` 34, `Zpvh` 29, `Zpvp` 11, `Zsed` 23, `Zsyr` 11, `Zw5_` 10, `Zx3j` 7
- **Input and orchestration: task, script extraction, external-script cache and fetch, path-to-issue loop** (18 classes, 812 lines): `Zb3f` 37, `Zf59` 177, `Zfl3` 29, `Zg3g` 9, `Zgdd` 25, `Zh0p` 28, `Zhdb` 54, `Zhgz` 43, `Zif4` 54, `Zm2j` 7, `Zq4` 61, `Zr1q` 46, `Zs10` 48, `Zs1_` 5, `Zsmj` 14, `Zw9i` 24, `Zwqm` 31, `Zwrv` 120
- **Issue building and text (shared with the dynamic path)** (12 classes, 1603 lines): `Zb3r` 31, `Ze_z` 56, `Zf24` 252, `Zfmi` 15, `Zgs3` 173, `Zgtx` 50, `Zh6h` 31, `Zhp` 83, `Zmpy` 18, `Zr1p` 581, `Zw8k` 60, `Zwf8` 253
- **Reflected and stored variants: probe records, string-literal source, stages, re-confirmation** (21 classes, 1158 lines): `Zb5n` 174, `Zbhz` 39, `Zcoe` 33, `Ze12` 41, `Zflo` 24, `Zgct` 60, `Zgtn` 32, `Zh2b` 59, `Zh7d` 98, `Zhrb` 56, `Zht1` 23, `Zi2o` 54, `Zirf` 107, `Zpwt` 66, `Zpzh` 39, `Zrkp` 29, `Zsp8` 40, `Zsyb` 19, `Zwjj` 21, `Zwr4` 85, `Zxdf` 59

The AST node classes listed exclude the `Zct*` classes that are not nodes: `Zctx` (a `ClassLoader`, 5,047 lines), `Zcts`, `Zct7`, `Zct3`, `Zcta` and `Zctt`.
