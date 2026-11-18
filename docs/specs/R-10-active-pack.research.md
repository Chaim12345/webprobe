# Research Note: Porting Burp Suite Active Scanner Checks to WebProbe

> **Delegated research (2026-11-18), not fully reviewed.** Written by free models (some sections re-verified by a second model) as leads for the task in the title; confirm each class:line before relying on it.

## Verification pass

- **Date:** 2026-11-18. **Status:** complete.
- **Counts:** **63 claims checked — 16 right, 28 corrected, 18 deleted, 1 still not established.**
- **Counting method:** the original note had 45 issue-family claims (A.1–A.5, B.1–B.2, C.1, D.1–D.8, E.1–E.3, F.1–F.8, and old G.1–G.18). This pass checked all 45 plus 18 standalone payload/timing assertions that had to be deleted. Its duplicate summary table and stale duplicate “Not Established Items” list are not double-counted. New issue-family research added to finish G is not counted as an original correction. Current-source registry/citation refreshes are listed separately below and are not double-counted. The 16 claims left substantively unchanged were A.1–A.5, B.1, D.3, F.6, and old G.3, G.4, G.5, G.8, G.9, G.11, G.12, G.16; D.6 is the one still-not-established family claim.

### Corrections to the 28 issue-family claims

1. **B.2:** unsupported fixed cache-deception paths -> random six-character value + `.css`, delimiter variants, repeats, and cacheability evidence (`Zum9.java:394-404,682-758,842-858`).
2. **C.1:** “timing is one of several / Collaborator required” -> **no timing / no OOB**; XPath has error and boolean methods, while `TIME_BASED` and Collaborator branches are gated to SQL (`Zppj.java:62-64,193-454`; `Zuuv.java:42-67`).
3. **D.1:** unsupported path claim and incomplete detection -> PUT, non-2xx stop, then retrieval containing marker `Zt`; exact stripped constants remain not established (`Zu8k.java:10-14,42-88`).
4. **D.2:** per-host / unverified generic suffix list -> **per URL**, four mutation classes, recovered literals, random-name controls (`Zcug.java:79-86`; `Zcud.java:57-61`; `Zbdu.java:99-136,138-329`).
5. **D.4:** Web.config / `debug=true` -> `DEBUG /Default.aspx` with `Command: start-debug` and status-specific response strings (`Zihl.java:46-86,171-174`).
6. **D.5:** implementation not traced -> `Zg3y` is a **passive per-request** ViewState check, not an active candidate (`Zsrp.java:79-100`; `Zg3y.java:15-46`).
7. **D.7:** `Zbmt` included and OOB treated as mandatory -> `Zc7h` OOB plus `Zxlc` response diffing, so OOB is one of two methods (`Zcug.java:96-112,138-146`; `Zxld.java:24-46`).
8. **D.8:** class not found / OOB likely -> `Zi6p` -> `Znq` -> `Zbhh`, in-band evaluated marker, no timing or OOB (`Zi6p.java:66-89`; `Znq.java:20-51`; `Zbhh.java:20-50`).
9. **E.1:** per-host and non-timing -> **per request**, with timeout one of several methods and optional intrusive Collaborator confirmation (`Zcug.java:125-134`; `Zg3d.java:195-200,262-368`; `Zpm3.java:5-12`).
10. **E.2:** per-host and non-timing -> **per request and timing only**; attack/follow-up requests use `Duration` and timeout state (`Zcug.java:125-134`; `Zhao.java:401-424,460-482`).
11. **E.3:** generic HTTP/2 tunnelling/downgrade entry -> the actual issue resource is **Hidden HTTP 2**, reported by per-host `Zpfw` when a forced-HTTP/2 replay gets a response (`Zpfw.java:46-125`; `Zhhg.java:10-19`).
12. **F.1:** implementation and timing unknown -> per-IP `Zsn3` / `Zwj_`, **timing only**, with `Zbpb` / `Zho3` evidence and reporting (`Zsn3.java:79-110`; `Zwj_.java:475-539`; `Zho3.java:10-22`).
13. **F.2:** implementation and timing unknown -> the same `Zsn3` / `Zwj_` timing-only path, with Python selection and `Zuu1` / `Zhmt` (`Zfhw.java:47-49,65-69`; `Zhmt.java:10-22`).
14. **F.3:** implementation and timing unknown -> the same timing-only path, with Ruby selection and `Zeel` / `Zua5` (`Zfhw.java:43-45,56-60,65-69`; `Zua5.java:10-22`).
15. **F.4:** calculation-based non-timing claim -> generic `Zfhw.ZK()` payloads confirmed by measured delay, **timing only** (`Zfhw.java:39-41`; `Zxbc.java:41-47,69-91`; `Zwj_.java:475-568`).
16. **F.5:** implementation and timing unknown -> per-IP `Zg_v`, five delay templates, and `Zp0x` time comparison, **timing only** (`Zg_v.java:78-152`; `Zp0x.java:14-25`).
17. **F.7:** ordinary/unspecified second-order registration -> **stored active per insertion point**, with error, boolean, Collaborator, and time-based alternatives (`Zcug.java:256-265`; `Zcud.java:93-97,111-117`; `Zppj.java:193-454`).
18. **F.8:** Collaborator traversal variant -> no OOB in `Zp3a`; the actual missing manipulation work is known-file follow-ups and Thorough path transforms (`Zp3a.java:48-67`; `Zsl1.java:66-128,179-219`).
19. **Old G.1:** catch-all XSS claim -> reflected/stored XSS already reported; DOM variants are separately mapped dynamic-JavaScript-analysis families (`Zcug.java:184,263`; `Zfk8.java:49-83`; `Zf24.java:6-223`).
20. **Old G.2:** LDAP left as a remaining S port -> already registered and reported by WebProbe `LdapInjection` (`app/core/src/scan_checks.rs:349,2930-2994`).
21. **Old G.6:** JWT implementation not found -> `Zu4y` is directly registered for five active JWT issues, all five reported by WebProbe `JwtAttacks` (`Zcug.java:209-216`; `app/core/src/scan_checks.rs:352,845-968`).
22. **Old G.7:** reflected/stored open redirection conflated -> reflected is ported; stored remains a separate `Zuag` stored-IP port (`Zcug.java:191,264`; `Zezc.java:34-45`).
23. **Old G.10:** Burp SSTI class not visible -> `Zi6p.java:92-118` contains the branch, and WebProbe already reports `TemplateInjection` (`app/core/src/scan_checks.rs:2112-2170`).
24. **Old G.13:** React2Shell logic unexamined -> `Zgn0` multipart POST and status-500/marker gates, **no timing/OOB/raw framing** (`Zgn0.java:53-98`; `Zwbs.java:10-23`).
25. **Old G.14:** “simple passive check” -> `Zut6` actively requests `/robots.txt` per host and checks status/type/body markers (`Zcug.java:96-116`; `Zut6.java:50-72,110-121`).
26. **Old G.15:** JWK logic unexamined -> `Zh7b` path probes plus `Zwws` JWKS parsing and `Zbfr` reporting; only path/member literals remain unrecovered (`Zh7b.java:38-57`; `Zbfr.java:17-27`; `Zwws.java:32-115`).
27. **Old G.17:** broken-access-control logic unexamined -> `Zcxn` removes authorization/cookie/X-* headers and compares repeated responses (`Zcxn.java:51-92`; `Zii_.java:25-64`; `Zr0k.java:20-59`).
28. **Old G.18:** vague partial TLS status -> TLS certificate is an active per-host `Zut6` check; unencrypted communications is passive (`Zcug.java:96-116`; `Zut6.java:75-107,167-264`; `Zsrp.java:61-76`).

### The 18 standalone assertions deleted

1. Cache-deception `.js` / `.png` path payloads -> deleted; the recovered path suffix is `.css` (`Zum9.java:394-404`).
2. Literal `/.css` and `/..;.css` cache-deception probes -> deleted; those literal probes are not at the cited locations (`Zum9.java:394-404,727-730,842-858`).
3. XPath `pg_sleep`, `SLEEP`, and `WAITFOR` payload family -> deleted; those are not XPath methods in this engine (`Zppj.java:62-64,365-454`).
4. XPath `concat('a',doc(...))` Collaborator payload -> deleted; the Collaborator branches are SQL-gated (`Zppj.java:193-346`).
5. HTTP PUT “root path” -> deleted; `Zu8k.ZN` is stripped (`Zu8k.java:10-14,60-63`).
6. Backup generic `.bak` / `.backup` / `.old` / `.swp` list -> deleted as unsupported; `Zebr.ZD` is not initialized in readable source, while the other literal mutations are separately cited (`Zxc6.java:60-75`; `Zxfn.java:61-76`).
7. ASP.NET Web.config / `debug=true` detection -> deleted; `Zihl` uses `DEBUG` and response matchers (`Zihl.java:46-86`).
8. Speculative ASP.NET padding-oracle enum names -> deleted; no matching issue or reporter was found in the allowed evidence tree (D.6).
9. `Zbmt` as a spoofable-client-IP class -> deleted; its registration is XXE file retrieval (`Zcug.java:143-146`).
10. Expression-Language `#{...}` example -> deleted; `Zbhh` builds the `${"z…z".toString().replace(...)}` form (`Zbhh.java:20-42`).
11. Expression-Language “OOB likely” -> deleted; the established report is an in-band evaluated marker (`Zbhh.java:40-50`).
12. Client-side desync “malformed responses” -> deleted; the evidence is exact request framing, Content-Length, body bytes, and connection reuse (`Zhao.java:401-432`).
13. Perl backtick / `system()` / `open()` examples -> deleted; the exact table is unrecovered and the established built-in path is timing-only (`Zfhw.java:51-68`; `Zwj_.java:475-539`).
14. Python `__import__` / `eval` / `exec` examples -> deleted for the same evidence reason (`Zfhw.java:47-49,65-69`; `Zwj_.java:475-539`).
15. Ruby `system` / backtick / `eval` examples -> deleted for the same evidence reason (`Zfhw.java:43-45,56-60,65-69`; `Zwj_.java:475-539`).
16. The Bambda `{{1337*1337}}` example as proof of built-in unidentified-code detection -> deleted; `Zht9.java:16` is an example Bambda, not the `Zbls` reporter (`Zbls.java:10-22`).
17. Server-side JavaScript `process.mainModule.require()` / `require('child_process')` examples -> deleted; the five template constants are stripped (`Ze6i.java:15-22`; `Zg_v.java:144-152`).
18. File-path-traversal Collaborator variant / OOB row -> deleted; `Zp3a` registers file retrieval and manipulation, with no Collaborator method (`Zcug.java:192-196`; `Zp3a.java:48-67`).

### Current-source refreshes (not double-counted above)

- WebProbe registry count **21 insertion-point + 10 request checks -> 24 + 20**, with one stored check (`app/core/src/scan_checks.rs:330-378,689-690`).
- GraphQL discovery/introspection/suggestions/content-type, XPath error detection, HTTP PUT, backup file, ASP.NET tracing/debugging, response-diffing spoofable client IP, and Expression Language injection: **candidate / size-only entries -> already ported or partially ported**, with current registry and implementation citations in A–D. The XPath boolean half and spoofable-IP Collaborator verdict remain open.
- WebProbe file:line references were refreshed against the current `scan_checks.rs`, `scan.rs`, and `active_checks.rs`; stale line-only citations are not counted as additional factual corrections.
- PHP's previously blank timing/dependency row was filled as **timing is one of several methods** (`Zsn3.java:79-109`; `Zfhw.java:51-68`; `Zxvv.java:32-87`).
- Missing G families were completed with new evidence (Flash/Silverlight, React2Shell, header-dependent responses, XML entity expansion, suspicious transformations, request URL override, SMTP interaction, stored redirect, `Zb_5` variants, Robots/TLS/JWKS, broken access control, and dynamic JavaScript-analysis families). These additions are not included in the 63 original-claim counts.

## Executive Summary

This note inventories Burp active checks that WebProbe has not ported and separates checks whose detection requires response timing. At the 2026-11-18 verification snapshot, WebProbe's registries contain **24 insertion-point checks and 20 request checks** (`app/core/src/scan_checks.rs:330-378`), plus one separately registered stored-XSS check (`scan_checks.rs:689-690`). The Burp resources contain 183 issue JSON files; an issue's presence there does **not** make it an active check (for example, GraphQL endpoint found is passive, as shown below). “Already ported” below refers to this source snapshot; size estimates describe only the remaining work.

Burp scope labels below come from `Zcud.java`: per URL (`Zcud.java:57-61`), per path (`:63-67`), per host (`:69-73`), per request (`:75-79`), in-session per request (`:81-85`), and per insertion point (`:87-91`). “Size” is a porting estimate, not a Burp fact. WebProbe must not port sleep/delay payloads or response-time comparisons.

---

## A. GraphQL issues

All five GraphQL issue names and typeIndexes are confirmed by `resources/KnowledgeBase/Issues/00200510_GraphqlEndpointFound.json` through `00200514_GraphqlContentTypeNotValidated.json`. No other GraphQL issue JSON exists in that directory.

### A.1 GraphQL endpoint found — typeIndex 2098448

- **Burp class / scope:** `Zwg_`, a **passive per-request** check, not an active insertion-point check: it is constructed in the passive list at `Zsrp.java:79-100`; `Zwg_.java:18-39` examines the existing request/response and reports `GRAPHQL_ENDPOINT_FOUND`.
- **Detection:** `Zeuo.Zd(this.ZF)` classifies the existing exchange (`Zwg_.java:24-39`). The evidence attaches the existing request and response (`Zwg_.java:37-39`); this class sends no probe. The GraphQL response/parameter classification is in `Zeuo.java:131-205`.
- **Timing / OOB / raw framing:** **no / no / no** — the reporting path only parses and attaches the existing exchange (`Zwg_.java:24-39`).
- **Porting:** **not an active-pack candidate.** If a passive port is desired, size **S**; the closest existing response-only pattern is `PathRelativeStyleSheet` (`app/core/src/scan_checks.rs:3202-3225`).

### A.2 GraphQL endpoint discovered — typeIndex 2098449

- **Burp class / scope:** `Zmzj`, **per host**, registered only for `GRAPHQL_ENDPOINT_DISCOVERED` at `Zcug.java:96-116` (host scope is established by `Zcud.java:69-73`). It does not report endpoint found.
- **Detection:** for each known path in `Zeuo.Zc`, it builds GraphQL requests, retains successful GraphQL responses, and reports the successful exchanges for that path (`Zmzj.java:28-58`). The payload table's decoded literals include `query{__typename}`, `GET`, `POST`, and `application/json; charset=utf-8` (`out/strings/map_root.tsv`, `burp.Zmzj` entries at lines 5703-5712). The decoded path table includes `/graphql`, `/api/graphql`, `/graphql/api`, and related variants (`map_root.tsv`, `burp.Zeuo` entries at lines 19884-19911). JSON requests set `Content-Type: application/json; charset=utf-8` (`Zcsb.java:84-110`).
- **Confirmation / report:** a nonempty successful-request list produces `GRAPHQL_ENDPOINT_DISCOVERED` with the path and exchanges (`Zmzj.java:54-58`). Success is a valid GraphQL JSON response, not merely a substring (`Zeuo.java:276-367`).
- **Timing / OOB / raw framing:** **no / no / no** — reporting is driven by parsed response content (`Zmzj.java:28-58`; `Zeuo.java:276-367`).
- **WebProbe status:** **already ported** as `GraphqlEndpointDiscovered`, registered at `app/core/src/scan_checks.rs:377` and implemented at `scan_checks.rs:1382-1426`; no remaining port is estimated here.

### A.3 GraphQL introspection enabled — typeIndex 2098450

- **Burp class / scope:** `Zgd9`, **in-session per request**, registered at `Zcug.java:138-164` (scope mapping: `Zcud.java:81-85`).
- **Detection:** it first requires a GraphQL exchange (`Zgd9.java:21-24`). If the existing response has introspection, it reports immediately (`Zgd9.java:24-26`). Otherwise it obtains the GraphQL query parameter and sends `Zuj2.ZQ(false)` through `Zeuo.Ze` (`Zgd9.java:27-40`). The literal begins `query IntrospectionQuery { __schema { ...` and is quoted in full at `Zuj2.java:9-10`.
- **Report condition:** `Zeuo.Za`/`hasIntrospection` requires a JSON object with `data.__schema` and at least one introspection field (`Zeuo.java:404-436`); a new issue is created only when that validation succeeds (`Zgd9.java:38-45`).
- **Timing / OOB / raw framing:** **no / no / no** — only GraphQL response structure is tested (`Zgd9.java:21-45`; `Zeuo.java:404-440`).
- **WebProbe status:** **already ported** as `GraphqlIntrospection`, registered at `app/core/src/scan_checks.rs:372` and implemented at `scan_checks.rs:1428-1461`.

### A.4 GraphQL suggestions enabled — typeIndex 2098451

- **Burp class / scope:** `Zbop`, **in-session per request** (`Zcug.java:138-164`; `Zcud.java:81-85`).
- **Detection:** on a known GraphQL exchange it sends the exact query `query{__type}` (`Zbop.java:20-23`). It requires a valid GraphQL response whose body contains `must have a selection of subfields. Did you mean` (`Zbop.java:23-26`), then reports through `Zgg2.Zx` (`Zbop.java:30-32`; issue constant at `Zgg2.java:8`).
- **Timing / OOB / raw framing:** **no / no / no** — the decision is the response-validation and string test at `Zbop.java:22-26`.
- **WebProbe status:** **already ported** as `GraphqlSuggestions`, registered at `app/core/src/scan_checks.rs:373` and implemented at `scan_checks.rs:1464-1490`.

### A.5 GraphQL content type not validated — typeIndex 2098452

- **Burp class / scope:** `Zx85`, **in-session per request** (`Zcug.java:138-164`; `Zcud.java:81-85`).
- **Detection:** extract the existing GraphQL query (`Zx85.java:22-25`; extraction at `Zeuo.java:73-95`). For a POST base request, try the same query as a GET URL parameter and remove Content-Type (`Zx85.java:26-28,55-57`). Always also try POST as `BODY_PARAM_URL_ENCODED` (`Zx85.java:30`; that variant sets `application/x-www-form-urlencoded` at `Zcsb.java:126-127`).
- **Confirmation:** the variant must first return a valid GraphQL response (`Zx85.java:35-37`); Burp then repeats it with the exact query `query{__typename}` and requires `Zeuo.Ze(response)` to be present before reporting (`Zx85.java:38-47`). It reports the first variant exchange, not the confirmation exchange (`Zx85.java:40,45-47`).
- **Timing / OOB / raw framing:** **no / no / no** — both gates are parsed response content (`Zx85.java:35-47`).
- **WebProbe status:** **already ported** as `GraphqlContentType`, registered at `app/core/src/scan_checks.rs:374` and implemented at `scan_checks.rs:1492-1540`.

---

## B. Web cache poisoning and web cache deception

TypeIndexes are **2097536** (`resources/KnowledgeBase/Issues/00200180_WebCachePoisoning.json`) and **2098768** (`00200650_WebCacheDeception.json`).

### B.1 Web cache poisoning — typeIndex 2097536

- **Burp classes / scopes:**
  - `Zsz5` (`APR_WebCacheEntanglement`) and `Zp22` (`APR_WebCachePoisoning`) are **in-session per request** (`Zcug.java:138-164`; scope mapping `Zcud.java:81-85`).
  - `Zgux` (`APIP_WebCacheEntanglement`) is **per insertion point**, registered at `Zcug.java:179-216`; it applies to non-`Ziqv` URL parameters (`Zgux.java:22-40`).
- **Request-scoped detection (`Zsz5`):** `Zsz5.java:45-55` runs `Zxyp`, then `Zpiu`, then a Host-specific fallback. `Zxyp` places a random canary through `Zcj_`, requires it in the response, repeats requests to prime a cache, builds a fresh unpoisoned request, and reports only if the canary survives there (`Zxyp.java:25-59`). `Zpiu` injects a random host value through the exact `Host` header (`Zpiu.java:78-84`), requires the canary in both the poisoned and later clean retrieval responses (`Zpiu.java:87-135`), and creates `WEB_CACHE_POISONING` through `Zusn.ZC` (`Zusn.java:39-47`).
- **Request-override / unkeyed-header detection (`Zp22`):** `Zp22.java:35-51` runs two `Zg0y` workflows. `Zfkb` uses `X-Original-URL` and `X-Rewrite-URL` with random paths/query values (`Zfkb.java:75-90`). `Zfki` uses exact headers `X-Forwarded-Host`, `X-Host`, and `X-Forwarded-Server`, with random values or Collaborator values (`Zfki.java:37-100,268-277`). `Zg1g` primes the cache, retrieves without the injected headers, and reports when the canary or poisoned status persists while an independent control does not contain the canary (`Zg1g.java:21-161,284-332`); its cache-header list is literal at `Zg1g.java:196-208`.
- **Insertion-point detection (`Zgux`):** `Zm2r` reflects a random canary through an unkeyed input, primes, and requires it in a later retrieval (`Zm2r.java:26-64`). For GET/HEAD, `Zssf` adds exact headers `X-HTTP-Method-Override: POST` and `X-Method-Override: POST`, plus body parameters including `_method=POST`, then applies the same canary/prime/clean-retrieval test (`Zssf.java:34-80`).
- **Timing:** **no** for all three classes — the report gates are response canaries, status codes, and content comparisons cited above, not elapsed time.
- **OOB:** **optional, not required.** `Zp22` also enables Collaborator-based external-service variants (`Zcug.java:152-158`; `Zfki.java:45-96`), and `Zpiu` may obtain a Collaborator host (`Zpiu.java:35-80`); the Web cache poisoning confirmations above are in-band. `Zsz5` and `Zgux` have non-OOB paths.
- **Raw framing:** **no** — probes are request/header/parameter builders (`Zfki.java:268-277`; `Zssf.java:38-45`).
- **Porting size:** **L** for the full family (three scopes/engines and cache confirmation). The closest starting pattern is the header-variation sender in `Cors` (`app/core/src/scan_checks.rs:3167-3199`), but substantial new cache-state logic is required.

### B.2 Web cache deception — typeIndex 2098768

- **Burp class / scope:** `Zum9` (`APR_WebCacheDeception`), **in-session per request**, not per host (`Zcug.java:138-164`; `Zcud.java:81-85`). It reports `WEB_CACHE_DECEPTION` via `Zx1p.ZI` and `Zm90` (`Zx1p.java:50-52`; `Zm90.java:11-18`).
- **Prefilters / baseline:** skip unsupported methods and non-200 base responses (`Zum9.java:63-99,236-259`). It gathers the base response plus three repeats (four in Thorough mode) (`Zum9.java:649-679`) and excludes responses already classified as cacheable (`Zum9.java:262-338,407-614`).
- **Payloads / comparisons:** the path probes use a random six-character value followed by the exact suffix `.css` (`Zum9.java:394-404`). Delimiter variants are combined with that value/suffix (`Zum9.java:727-730,796-803,842-858`); decoded delimiters include `%2F`, `%3F`, `%23`, `%00`, `%20`, `%0A`, and `%0D%0A` (`out/strings/map_root.tsv`, `burp.Zum9` entries at lines 800-880). A separate mapping probe appends `/` as needed before the random `.css` path (`Zum9.java:400-404,842-854`).
- **Confirmation / report:** for each variant Burp sends three or four repeats (`Zum9.java:682-711`), requires the base status and content not to differ from the dynamic baseline, then requires at least one response with cacheability evidence (`Zum9.java:732-758`). Cacheability includes cache headers and values such as `max-age`, `s-maxage`, `immutable`, `public`, and `private` (`Zum9.java:407-614,826-839`; decoded constants at `out/strings/map_root.tsv:800-880`). Response comparison uses HTML analysis plus ETag, Last-Modified, colon count, and header names (`Zum9.java:643-647,773-785`). An authentication variant removes exact `cookie` and `authentication` headers (`Zum9.java:860-885`). The old note's claims that `.js`/`.png` are path payloads and that `/.css`/`/..;.css` are literal probes are not supported by these locations.
- **Timing / OOB / raw framing:** **no / no / no** — the decision uses repeated response content, status, and cache headers (`Zum9.java:616-647,714-785`).
- **Porting size:** **L**; closest URL-mutation pattern: `OpenRedirect` (`app/core/src/scan_checks.rs:2598-2649`), with new multi-response/cache analysis.

---

## C. XPath injection

### C.1 XPath injection — typeIndex 1050112

TypeIndex and name: `resources/KnowledgeBase/Issues/00100600_XPathInjection.json`.

- **Burp classes / scope:** `Zg_c` (`APIP_SqlAndXPathInjection`) is registered for SQL and XPath at `Zcug.java:179-183`, hence **per insertion point** (`Zcud.java:87-91`). `Zg_c.java:10-17` delegates to the shared `Zw7s` engine; the SQL/XPath implementation is `Zppj`, and XPath issues are materialized by `Zmmf.java:40-46` through `Zs76.java:11-45`.
- **Error-based detection:** `Zppj` explicitly enables the error probe for `XPATH_INJECTION` (`Zppj.java:365-383,429-454`). The visible quote probes include `"` and the Thorough-mode `1=` probe (`Zppj.java:429-454,496-525`). `Zxp6` distinguishes XPath error patterns from SQL patterns and creates a `Zmmf` result only for a new XPath error (`Zxp6.java:116-158,219-225`). Decoded XPath signatures include `System.Xml.XPath`, `javax.xml.xpath.XPathExpressionException`, `A location path was expected`, and `Expression must evaluate to a node-set` (`out/strings/map_root.tsv`, `burp.Ze2s` entries at lines 19314-19392).
- **Boolean detection:** `Zppj` has a separate `XPATH_INJECTION + BOOLEAN_BASED` branch (`Zppj.java:405-425`) and can confirm an initial error result with a boolean probe (`Zppj.java:976-1091`). `Zuuv` generates XPath `true()`, `false()`, and nested `not(...)` expressions, joined by `and` or `or` (`Zuuv.java:42-67`); `Zx4k` sends the positive and negative forms (`Zx4k.java:20-43`). `Zppj.java:857-905` also builds quote-aware boolean variants.
- **Timing:** **no.** This corrects the original note's most important error: the `TIME_BASED` branch at `Zppj.java:390-401` tests `this.ZW`, which is initialized only from `SQL_INJECTION` and `SQL_INJECTION_2ND_ORDER` at `Zppj.java:62-64`; it is not an XPath branch. The XPath-specific dispatch shown at `Zppj.java:365-440` contains error and boolean methods only. The old `pg_sleep`, `SLEEP`, and `WAITFOR` XPath claims were unsupported and are deleted.
- **OOB:** **no.** The Collaborator branches at `Zppj.java:193-346` likewise use `this.ZW` (SQL / second-order SQL), while the XPath result constructors at `Zs76.java:11-45` are in-band/diffable. No XPath Collaborator payload was found in the allowed Burp tree; the old `concat('a',doc(...))` claim is deleted rather than retained as fact.
- **Raw framing:** **no** — probes are ordinary insertion-point payloads (`Zx4k.java:20-43`).
- **WebProbe status / porting size:** the error-based half is **already ported** as `XPathInjection` (`app/core/src/scan_checks.rs:354,1111-1160`), which explicitly leaves the boolean half unported. Remaining boolean work is **M**; combine it with `SqlBooleanInjection` (`scan_checks.rs:2729-2800`) and the XPath payloads/error signatures above.

---

## D. HTTP PUT; backup file; ASP.NET; spoofable client IP; Expression Language

### D.1 HTTP PUT method is enabled — typeIndex 1050880

Resource: `resources/KnowledgeBase/Issues/00100900_HttpPutMethodIsEnabled.json`.

- **Burp class / scope:** `Zu8k` (`APH_HttpPutEnabled`), **per host** (`Zcug.java:96-116`; `Zcud.java:69-73`).
- **Detection:** build and send a request with method enum `Zgs0.PUT` (`Zu8k.java:60-63`). A non-2xx response stops the check (`Zu8k.java:42-52,66-69`). For a 2xx response, Burp sends a second request without the PUT method override (`Zu8k.java:71-74`) and reports only if the second response **does** contain the marker bytes `Zt` (`Zu8k.java:76-88`). The issue is `HTTP_PUT_METHOD_IS_ENABLED` (`Zxhh.java:10-22`). This is not a WebDAV-header test.
- **Payload gap:** the exact path/body constants `ZN` and marker `Zt` are declared but not initialized in the readable `Zu8k.java:10-14`; there are no `burp.Zu8k` entries in `out/strings/map_root.tsv`. Their literal contents are **(not established)**. The old “root path” claim is unsupported and removed.
- **Timing:** **no.** `System.currentTimeMillis()` at `Zu8k.java:63` is stored and later attached to the first evidence item (`Zu8k.java:116-117`); no duration is compared. Reporting depends on status and marker presence (`Zu8k.java:66-88`).
- **OOB / raw framing:** **no / no** — ordinary request construction and response bytes (`Zu8k.java:60-88`).
- **WebProbe status:** **already ported** as `HttpPutEnabled` (`app/core/src/scan_checks.rs:369,1163-1208`), using a random `.txt` path and marker because Burp's constants are unrecovered.

### D.2 Backup file — typeIndex 6291672

Resource: `resources/KnowledgeBase/Issues/006000d8_BackupFile.json`.

- **Burp classes / scope:** `Zem7` (append extension), `Zsro` (replace extension), `Zxc6` (prefix filename), and `Zxfn` (append filename), registered together at `Zcug.java:79-86`. They are **per URL**, not per host and not insertion-point checks (`Zcud.java:57-61`; check names at `Zem7.java:53-56`, `Zsro.java:53-56`, `Zxc6.java:50-53`, `Zxfn.java:51-54`).
- **Payloads:** `Zem7` appends an extension and includes the exact suffix `~` through `Zu7n.java:5-9`; its path transformation is at `Zem7.java:63-79`. `Zsro` replaces extensions and has JSP-specific `.jspa`, `.jspx`, and `.jspf` variants (`Zsro.java:63-85`; `out/strings/map_root.tsv:28217-28220`). `Zxc6` prefixes names with literals including `bak_`, `backup_`, `old_`, `Copy of `, and `Copy (2) of ` (`out/strings/map_root.tsv:25157-25164`; transformation at `Zxc6.java:60-75`). `Zxfn` appends literals including `_bak`, `_backup`, `_old`, ` (copy)`, and ` - Copy` (`out/strings/map_root.tsv:13864-13878`; transformation at `Zxfn.java:61-76`). The complete generic `Zebr.ZD` extension list is not initialized in readable `Zebr.java`; the old unverified `.bak`/`.backup`/`.old`/`.swp` list is not retained as a claim about this check.
- **Detection:** `Zbdu` tries each mutation, rejects status 400+, compares against a random-name control and repeated fingerprints, and reports with both positive and control evidence (`Zbdu.java:99-136,138-329`). The issue constructor is explicitly `BACKUP_FILE` (`Zebr.java:15-31`).
- **Timing / OOB / raw framing:** **no / no / no** — the gates are status and response fingerprints (`Zbdu.java:138-329`).
- **WebProbe status:** **already ported** as `BackupFile` (`app/core/src/scan_checks.rs:376,1623-1711`), including the four recovered mutation families and controls. The generic extension-list gap remains as described above.

### D.3 ASP.NET tracing enabled — typeIndex 1049216

Resource: `resources/KnowledgeBase/Issues/00100280_AspDotNetTracingEnabled.json`.

- **Burp classes / scopes:** `Ze3_` is **per host** (`Zcug.java:96-116`); `Zsqx` is **in-session per request** (`Zcug.java:138-164`), with scope definitions at `Zcud.java:69-85`.
- **Active probe:** `Ze3_` requests the decoded path `/trace.axd` (`Ze3_.java:34-41`; `out/strings/map_root.tsv:10723-10724`). It requires status 200 and HTML analysis, then delegates to `Zsqx.Zh` (`Ze3_.java:40-58`).
- **Report condition:** both paths look for a `span` element whose `class` is exactly `tracecontent` (`Zsqx.java:36-57`). The request-scoped path only runs for an `.aspx` request with an analyzed response and sends no new request (`Zsqx.java:21-34,51-57`).
- **Timing / OOB / raw framing:** **no / no / no** — status and parsed HTML determine reporting (`Ze3_.java:34-58`; `Zsqx.java:36-57`).
- **WebProbe status:** **already ported** as `AspNetTracing` (`app/core/src/scan_checks.rs:370,1211-1260`); the request-scoped passive examination is separate from this active host probe.

### D.4 ASP.NET debugging enabled — typeIndex 1050624

Resource: `resources/KnowledgeBase/Issues/00100800_AspDotNetDebuggingEnabled.json`.

- **Burp class / scope:** `Zihl` (`APH_AspDebuggingEnabled`), **per host** (`Zcug.java:96-116`; `Zcud.java:69-73`).
- **Detection:** send method `DEBUG` to exact path `/Default.aspx`, with header `Command: start-debug` (`Zihl.java:46-56`; literals also at `Zihl.java:171-173`). A 401 response must match `Debug access denied to '/Default.aspx'.`; a 500 response must match `DebugSessionID corrupted or not provided.` (`Zihl.java:59-86,171-174`). Other statuses do not report. The old Web.config/`debug=true` claim is deleted.
- **Timing / OOB / raw framing:** **no / no / no** — only status-specific response matchers (`Zihl.java:59-86`).
- **WebProbe status:** **already ported** as `AspNetDebugging` (`app/core/src/scan_checks.rs:371,1263-1300`).

### D.5 ASP.NET ViewState without MAC enabled — typeIndex 4195840

Resource: `resources/KnowledgeBase/Issues/00400600_AspDotNetViewstateWithoutMacEnabled.json`.

- **Burp class / scope:** `Zg3y` (`PPR_VulnerableViewState`) is a **passive per-request** check, constructed in `Zsrp.java:79-100`; it is not an active `Zcug` check.
- **Detection:** it extracts ViewState from the request and response and highlights values whose parsed flags show MAC protection absent (`Zg3y.java:15-46`); `Zbvv.java:10-22` creates the issue. No probe or follow-up request appears in this path.
- **Timing / OOB / raw framing:** **no / no / no** (`Zg3y.java:15-46`).
- **Porting:** **not an active-pack candidate**; passive size **S**. The old “not established” implementation gap is resolved.

### D.6 ASP.NET padding oracle

**(not established).** No issue whose name contains “padding” or “oracle” exists among the 183 `resources/KnowledgeBase/Issues/*.json` files; the related ViewState resource is only `00400600_AspDotNetViewstateWithoutMacEnabled.json`. A search of `readable_strict/root/` found no padding-oracle `Zcot` constant or reporter. Without an issue type and reporting class there is no evidence-based active check to specify; the speculative enum names in the old note are deleted.

### D.7 Spoofable client IP address — typeIndex 4194576

Resource: `resources/KnowledgeBase/Issues/00400110_SpoofableClientIpAddress.json`.

- **Burp classes / scopes:** `Zc7h` is **per host**, registered for `SPOOFABLE_CLIENT_IP + COLLABORATOR_BASED` and external-interaction issues (`Zcug.java:96-112`). `Zxlc` is **in-session per request**, registered for `SPOOFABLE_CLIENT_IP + RESPONSE_DIFFING` (`Zcug.java:138-146`). `Zbmt` is XXE only (`Zcug.java:143-146`) and is removed from this entry.
- **OOB detection:** `Zc7h.java:25-29` runs `Zs61`/`Zsrh`. The combined request includes `X-Forwarded-For`, `True-Client-IP`, `X-Real-IP`, `Referer`, `X-WAP-Profile`, and `X-Scraped` Collaborator values (`Zcg4.java:39-51`); individual client-IP variants and an `X-Forwarded-For` follow-up appending `, 127.0.0.1` are at `Zcg4.java:118-139` and `Zs61.java:90-113`. `Zf9t.java:32-42` constructs `SPOOFABLE_CLIENT_IP` from interaction evidence.
- **Response-diff detection:** `Zxlc` changes exactly `X-Forwarded-For`, using a remove/empty operation and the literal `127.0.0.1` (`Zxlc.java:9-21`). `Zxld` compares base and changed responses through `Zmaq` and reports paired evidence (`Zxld.java:24-46`; `Zecn.java:22-45,71-82`), with issue construction at `Zf9t.java:11-29`.
- **Timing:** **no** — OOB interaction and response diffing are the two methods (`Zcug.java:106-112,140-146`; `Zxld.java:24-46`).
- **OOB:** **one of two methods, not mandatory** because `Zxlc` is in-band.
- **Raw framing:** **no** — ordinary headers (`Zcg4.java:39-51`; `Zxlc.java:19-21`).
- **WebProbe status / porting size:** the response-diffing half is **already ported** as `SpoofableClientIp` (`app/core/src/scan_checks.rs:375,1564-1620`). The remaining Collaborator-specific verdict is **M**; the nearest OOB delivery pattern is `CollaboratorEverywhere` (`scan_checks.rs:453-504`), which currently registers external-interaction findings rather than the spoofable-IP verdict.

### D.8 Expression Language injection — typeIndex 1052448

Resource: `resources/KnowledgeBase/Issues/00100f20_ExpressionLanguageInjection.json`.

- **Burp classes / scope:** `Zi6p` (`APIP_XssAndTemplateInjection`) is **per insertion point** (`Zcug.java:179-185`; `Zcud.java:87-91`). Its EL branch calls `Znq` (`Zi6p.java:66-89`), which selects `Zbhh` specifically for `EXPRESSION_LANGUAGE_ENGINE_INJECTION` (`Znq.java:20-51`).
- **Detection / payload:** `Zbhh` generates random delimiters and sends the exact EL form `${"z<random>z".toString().replace("<random>", "<random>")}` with prefix/suffix context (`Zbhh.java:20-42`; decoded fragments at `out/strings/map_root.tsv:9175-9178`). It requires the evaluated `z<random>z` marker in the response through `Ziqe.ZT` (`Zbhh.java:41-50`) and reports `EXPRESSION_LANGUAGE_ENGINE_INJECTION` through `Zelb.java:10-22`. No `#{...}` probe is present in this implementation; that old example is removed.
- **Timing / OOB / raw framing:** **no / no / no** — one in-band evaluated-marker comparison (`Zbhh.java:40-50`). The old “OOB likely” statement was speculation and is deleted.
- **WebProbe status:** **already ported** as `ExpressionLanguageInjection` (`app/core/src/scan_checks.rs:353,1013-1083`).

---

## E. HTTP request smuggling; client-side desync; HTTP/2

### E.1 HTTP request smuggling — typeIndex 2097472

Resource: `resources/KnowledgeBase/Issues/00200140_HttpRequestSmuggling.json`.

- **Burp class / scope:** `Zg3d` (`APR_RequestSmuggling`), **per request**, not per host (`Zcug.java:125-134`; `Zcud.java:75-79`). It is registered for both `REQUEST_SMUGGLING_NORMAL` and `REQUEST_SMUGGLING_INTRUSIVE` (`Zcug.java:128-132`).
- **Payload construction:** `Zpmx` combines a header mutation (`Zbbj`) with a framing style (`Zwro`). The framing enum is exactly `CL_TE`, `H2_TE`, and `TE_CL` (`Zwro.java:6-9,93-95`); header techniques are `NO_MODIFICATION`, `SINISTER_SPACE`, `WICKED_WRAP`, `LETHAL_LF`, `GANGSTER_GARETH`, `KILLER_CHUNKS`, `BOURNE_IDENTITY`, and `HTTP2_CRLF_BOOGALOO` (`Zbbj.java:16-24,135-137`). `Zqv` forces POST when needed, creates a chunked body ending in exact `0\r\n\r\n`, sets `Transfer-Encoding: chunked`, removes/replaces Content-Length, and sets `Connection: keep-alive` (`Zqv.java:38-58,65-67`). Literal mutations include `Transfer-Encoding: chunked, identity`, `1\r\nZ\r\nF\r\n\r\n`, `1\r\nZ\r\nQ\r\n\r\n`, and an appended `GET <path> HTTP/1.1\r\nX-Ignore: X` (`Zbbj.java:71-73`; `Zwro.java:52-90`).
- **Initial detection / timeout evidence:** for each permutation Burp sends attack/control variants in a fixed sequence (`Zg3d.java:168-215`). One variant gets the configured `Duration` timeout (`Zg3d.java:195-200`), and `Zuox.Zp`/`Zx5i.Zp` distinguish missing from present responses (`Zuox.java:23-26`; `Zx5i.java:28-31`). Follow-up evidence starts as `Zpm3.TIMEOUT` (`Zg3d.java:262-330`). This directly refutes the old “timing no” claim.
- **Non-timing confirmations:** `Zpm3` enumerates `DESYNC_GUARDIAN`, `REQUEST_TUNNELLING`, `FLIP_STATUS_CODE`, `INTERESTING_REFLECTION`, `TRIGGERS_INTERACTION`, and `CL_0` in addition to `TIMEOUT` (`Zpm3.java:5-12,49-51`). Examples: Desync Guardian requires exact `connection: keep-alive` in a follow-up response (`Ziux.java:41-63`); request tunnelling parses a second HTTP response in the response bytes (`Zsbm.java:66-106`); flipped status and reflected interaction IDs are confirmed at `Zsft.java:75-132`; CL.0 has its own issue path at `Zc_q.java:28-37`.
- **Timing:** **timing is one of several methods.** Non-timing methods are Desync Guardian, request tunnelling, flipped status, interesting reflection, triggered interaction, and CL.0, cited above. A WebProbe port must exclude the timeout technique rather than describe the whole check as non-timing.
- **OOB:** **optional / intrusive only.** `Zg3d` invokes `Zsft` for the intrusive method (`Zg3d.java:331-368`), which builds a Collaborator value and looks for interaction IDs (`Zsft.java:33-69,75-113,134-137`). Normal in-band methods do not require OOB.
- **Raw framing / HTTP/2:** **raw framing yes** — conflicting lengths and hand-built chunk boundaries are essential (`Zqv.java:38-58`; `Zwro.java:52-90`). **HTTP/2 is needed only for H2 variants**: `H2_TE` exists (`Zwro.java:6-9`), and technique filtering checks `MUST_USE_HTTP2` (`Zg3d.java:519-569`).
- **Porting size:** **L**, even after excluding timing, because WebProbe would need controlled framing and several confirmation engines. No existing WebProbe check is a close functional match; `TraceEnabled` (`app/core/src/scan_checks.rs:3228-3270`) is only the closest host/request probe skeleton, not a framing implementation.

### E.2 Client-side desync — typeIndex 2097473

Resource: `resources/KnowledgeBase/Issues/00200141_ClientSideDesync.json`.

- **Burp class / scope:** `Zhao` (`APR_ClientSideDesync`), **per request** (`Zcug.java:125-134`; `Zcud.java:75-79`).
- **Detection / payloads:** the ordinary path is `checkForClientSideDesync`, with a separate pause-based fallback (`Zhao.java:201-207`). It builds a POST request with attacker-controlled body length and exact headers `Content-Length: <body length>`, `Content-Type: application/x-www-form-urlencoded`, and `Connection: keep-alive` (`Zhao.java:401-432,487-489`). It sends attack and follow-up requests with the supplied `Duration` (`Zhao.java:401-421`) and classifies an exchange as timed out when it is absent or has `Zq1.TIMED_OUT` (`Zhao.java:460-482`). A gadget response can be used for confirmation (`Zhao.java:209-337`), and pause-based and ordinary issue variants are distinguished at `Zhao.java:435-457` / `Zg2f.java:14`.
- **Timing:** **timing only** for the detection methods shown: both ordinary and pause-based paths pass a `Duration` into the sender and use timeout state to form the desync result (`Zhao.java:201-207,401-424,460-482`). The old “no timing” statement is incorrect; this check must not be ported under WebProbe's rule.
- **OOB:** **no** — the follow-up is a gadget request/response (`Zhao.java:387-399`), not a Collaborator interaction.
- **Raw framing:** **yes** — the attack depends on exact method, Content-Length, body bytes, and connection reuse (`Zhao.java:401-432`). The old claim about malformed **responses** is unsupported and removed.
- **HTTP/2:** **not required by the shown HTTP/1.1 POST/header construction** (`Zhao.java:428-432,487-489`).
- **Porting size:** **L and excluded by the timing rule**; no close WebProbe pattern.

### E.3 Hidden HTTP 2 — typeIndex 16778496

Resource: `resources/KnowledgeBase/Issues/01000500_HiddenHttp2.json`. There is no separate issue JSON named “HTTP/2 request tunnelling” or “HTTP/2 downgrade”; `REQUEST_TUNNELLING` is instead a request-smuggling evidence mode (`Zpm3.java:5-12`).

- **Burp class / scope:** `Zpfw` (`APH_HiddenHttp2`), **per host** (`Zcug.java:96-116`; `Zcud.java:69-73`).
- **Detection:** require HTTPS, a target not already known to use HTTP/2, and HTTP/2 support enabled (`Zpfw.java:46-90`). Replays the base request with `FORCE_HTTP2_NON_POOLED` (`Zpfw.java:90-107`). Any nonempty response is reported as `HIDDEN_HTTP2` with that exchange (`Zpfw.java:108-125,161-164`; `Zhhg.java:10-19`). There is no HTTP/1.1-with-HTTP/2-features comparison in this class.
- **Timing / OOB / raw framing:** **no / no / no** — only presence of a response is tested (`Zpfw.java:108-125`). The sender uses the standard forced-HTTP/2 mode, not hand-built malformed frames (`Zpfw.java:100-106`).
- **HTTP/2 dependency:** **yes, mandatory** (`Zpfw.java:72-106`).
- **Porting size:** **S once an HTTP/2 sender exists; otherwise blocked by transport support.** No existing WebProbe check supplies the required HTTP/2 pattern; `TraceEnabled` (`app/core/src/scan_checks.rs:3228-3270`) is only a host-probe skeleton.

---

## F. Code injection variants; second-order SQL; file paths

### Shared registration and timing engine for F.1–F.4

`Zsn3` (`APIP_CodeInjection`) is registered as a **per-insertion-point** check (`Zcug.java:179-186`; `Zcud.java:87-91`). After the upload-specific PHP path, it invokes `Zwj_` (`Zsn3.java:79-110`). `Zfhw` selects the language-specific payload tables (`Zfhw.java:39-69`), `Zbyb` exposes them to `Zxbc`/`Zwj_` (`Zbyb.java:14-57`), and `Zwj_` compares attack/control elapsed times repeatedly (`Zwj_.java:475-539`). `Zp0x.ZL` is the actual time test: it requires a difference of at least 75% of the target delay and a response time greater than target-minus-1000 ms (`Zp0x.java:14-25`). The standard delay pair is 0/20 seconds and the OS-command pair is 1/21 seconds, each with jitter (`Zse1.java:6-14`). The complete literal payload tables in `Zfhw` are stripped from readable source and have no `burp.Zfhw` TSV entries, so exact language payload strings are **(not established)** below rather than guessed.

### F.1 Perl code injection — typeIndex 1052160

Resource: `resources/KnowledgeBase/Issues/00100e00_PerlCodeInjection.json` (the same numeric typeIndex is also used by the distinct React2Shell resource; names and filenames are therefore the safe keys).

- **Classes / scope:** per-insertion-point `Zsn3` as above; payload selection includes Perl at `Zfhw.java:51-68`; `Zbpb.java:10-14` creates evidence and `Zho3.java:10-22` reports `PERL_CODE_INJECTION`.
- **Detection:** `Zsn3` sends the selected payloads through `Zwj_`; a report follows only after the attack/control time comparisons in `Zwj_.java:475-539`. The evidence includes baseline and measured times (`Zbpb.java:11-13`; `Zho3.java:17`). The old backtick/`system()`/`open()` literals are not evidenced and are deleted.
- **Timing:** **timing only** for the established built-in path (`Zsn3.java:100-109`; `Zwj_.java:475-539`; `Zp0x.java:14-25`). **OOB:** no established Collaborator branch in this path. **Raw framing:** no (`Zsn3` uses insertion-point payloads).
- **Porting size:** **excluded by the timing rule** (implementation would otherwise be M). `OsCommandInjection` is only the nearest insertion-point structure (`app/core/src/scan_checks.rs:1781-1855`), not a timing pattern to copy.

### F.2 Python code injection — typeIndex 1052432

Resource: `resources/KnowledgeBase/Issues/00100f10_PythonCodeInjection.json`.

- **Classes / scope:** per-insertion-point `Zsn3`; Python payload selection is `Zfhw.java:47-49,65-69`; `Zuu1.java:10-14` and `Zhmt.java:10-22` report `PYTHON_CODE_INJECTION` with timing evidence.
- **Detection:** the same `Zwj_` attack/control repeats and `Zp0x` threshold as F.1 (`Zsn3.java:100-109`; `Zwj_.java:475-539`; `Zp0x.java:14-25`). Old `__import__`, `eval`, and `exec` examples are unsupported and removed.
- **Timing / OOB / raw framing:** **timing only / no established OOB / no** (same evidence as F.1).
- **Porting size:** **excluded by the timing rule** (otherwise M); nearest structural pattern: `OsCommandInjection` (`app/core/src/scan_checks.rs:1781-1855`).

### F.3 Ruby code injection — typeIndex 1052416

Resource: `resources/KnowledgeBase/Issues/00100f00_RubyCodeInjection.json`.

- **Classes / scope:** per-insertion-point `Zsn3`; Ruby selection is `Zfhw.java:43-45,56-60,65-69`; `Zeel.java:10-15` and `Zua5.java:10-22` report `RUBY_CODE_INJECTION` with timing evidence.
- **Detection:** the same `Zwj_` attack/control repeats and `Zp0x` threshold as F.1 (`Zsn3.java:100-109`; `Zwj_.java:475-539`; `Zp0x.java:14-25`). The old `system`, backtick, and `eval` examples are unsupported and removed.
- **Timing / OOB / raw framing:** **timing only / no established OOB / no** (same evidence as F.1).
- **Porting size:** **excluded by the timing rule** (otherwise M); nearest structural pattern: `OsCommandInjection` (`app/core/src/scan_checks.rs:1781-1855`).

### F.4 Unidentified code injection — typeIndex 1052672

Resource: `resources/KnowledgeBase/Issues/00101000_UnidentifiedCodeInjection.json`.

- **Classes / scope:** per-insertion-point `Zsn3`; `Zfhw.ZK()` selects `UNIDENTIFIED_CODE_INJECTION` (`Zfhw.java:39-41`), `Zxbc.java:41-47,69-91` enables the generic payloads, and `Zewt.java:10-14` / `Zbls.java:10-22` report with timing evidence.
- **Detection:** `Zwj_.Zq` tries generic payloads and then performs the same measured-delay confirmation (`Zwj_.java:57-315,475-568`). The actual issue carries `Ziug` timing evidence (`Zbls.java:17`).
- **Timing / OOB / raw framing:** **timing only / no established OOB / no** (`Zwj_.java:475-539`; `Zp0x.java:14-25`).
- **Bambda correction:** the `{{1337*1337}}` → `1787569` text in `Zht9.java:16` is an **example Bambda**, not the built-in `UNIDENTIFIED_CODE_INJECTION` reporter. It does not establish a non-timing variant of this issue and is removed from this entry.
- **Porting size:** **excluded by the timing rule** (otherwise M); nearest structural pattern: `OsCommandInjection` (`app/core/src/scan_checks.rs:1781-1855`).

### F.5 Server-side JavaScript code injection — typeIndex 1051904

Resource: `resources/KnowledgeBase/Issues/00100d00_ServerSideJavaScriptCodeInjection.json`.

- **Burp class / scope:** `Zg_v` (`APIP_ServerSideJavaScriptInjection`), **per insertion point**, directly registered at `Zcug.java:179-203`.
- **Payload generation:** `Ze6i.java:15-22` supplies five templates (`Zm5i`, `Zcvj`, `Zesj`, `Zi8w`, `Zr4w`). `Zg_v` substitutes a random value for `$$` and the delay in milliseconds for `%%` (`Zg_v.java:144-152`). The template constants are stripped and have no TSV entries, so the old `process.mainModule.require()` / `require('child_process')` examples are **not established** and are removed.
- **Detection:** send the initial payload and then two comparison payloads, repeating according to accuracy (`Zg_v.java:78-147`). `Zp0x.Zq` compares their response times using the 75% rule (`Zp0x.java:14-25`; call site `Zg_v.java:123-141`). `Zc8d.java:10-22` reports `SERVER_SIDE_JAVASCRIPT_CODE_INJECTION` with baseline/observed times.
- **Timing:** **timing only** (`Zg_v.java:144-152`; `Zp0x.java:14-25`). **OOB:** no established OOB branch. **Raw framing:** no (`Zg_v.java:144-147` sends ordinary insertion-point payloads).
- **Porting size:** **excluded by the timing rule** (otherwise M); nearest structural pattern: `OsCommandInjection` (`app/core/src/scan_checks.rs:1781-1855`).

### F.6 PHP code injection — typeIndex 1051648

Resource: `resources/KnowledgeBase/Issues/00100c00_PhpCodeInjection.json`. **Already ported:** `PhpCodeInjection` is registered at `app/core/src/scan_checks.rs:341` and implemented at `scan_checks.rs:2374-2467`; the non-timing echo engine is `app/core/src/active_checks.rs:90-161`.

- **Burp timing / dependencies:** **timing is one of several methods**. The non-timing methods are upload echo evaluation (`Zsn3.java:79-98`; `Zxvv.java:32-57`) and optional Collaborator interaction (`Zxvv.java:53-87`); the shared `Zsn3` path also invokes `Zwj_` (`Zsn3.java:100-109`), and PHP is present in the generic delay-payload selection (`Zfhw.java:51-68`). **OOB:** optional, not mandatory. **Raw framing:** no.
- **Remaining work:** none for the permitted echo/OOB methods: WebProbe implements both (`app/core/src/scan_checks.rs:2415-2464`). The delay branch remains excluded and is not ported (`scan_checks.rs:2374-2376`).

### F.7 SQL injection (second order) — typeIndex 1049104

Resource: `resources/KnowledgeBase/Issues/00100210_SqlInjectionSecondOrder.json`.

- **Burp classes / scope:** `Zg_c`/`Zppj`, but registered separately as `SQL_INJECTION_2ND_ORDER` in the **stored active per-insertion-point** list (`Zcug.java:256-265`; factory semantics at `Zcud.java:93-97,111-117`). This is not merely the ordinary first-order registration at `Zcug.java:182`.
- **Detection:** the stored phase receives the injection and retrieval contexts (`Zcud.java:111-117`) and runs the same `Zppj` engine with `this.ZW` selecting SQL or second-order SQL (`Zppj.java:62-64`). Error and boolean branches are at `Zppj.java:348-383,405-454`; `Zxp6.java:116-158` matches new SQL errors; `Zuuv.java:42-67` and `Zx4k.java:20-43` supply true/false comparisons. Collaborator variants for Oracle, MSSQL, and MySQL are at `Zppj.java:193-346`. Delay payloads in the shared SQL provider include exact `waitfor delay'0:0:%%'--` (`out/strings/map_root.tsv:18826-18827`) and `pg_sleep(%%)--` (`Zxpy.java:58`; also `out/strings/map_root.tsv:26184-26186`).
- **Timing:** **timing is one of several methods.** `TIME_BASED` is selected for `this.ZW` at `Zppj.java:390-401`, and `Zse.java:223-234` explicitly includes second-order time-based checks. Non-timing methods are error-based, boolean-based, and database-specific Collaborator interaction (`Zppj.java:193-383,405-454`).
- **OOB:** **one of several methods, not mandatory** (`Zppj.java:193-346`; `Zse.java:180-185`). **Raw framing:** no.
- **Porting size:** **M** for non-timing methods only; closest stored-pair pattern: `StoredXss` (`app/core/src/scan_checks.rs:2233-2234`; stored engine `app/core/src/active_checks.rs:173-197`). Do not port the delay branch.

### F.8 File path traversal and manipulation — typeIndexes 1049344 and 1051392

Resources: `resources/KnowledgeBase/Issues/00100300_FilePathTraversal.json` and `00100b00_FilePathManipulation.json`.

- **Burp class / scope:** `Zp3a`, **per insertion point** (`Zcug.java:179-197`). It reports file retrieval only with `PATH_TRAVERSAL_FILE_RETRIEVAL`, and manipulation as a separate issue (`Zp3a.java:48-67`; constructors `Zurx.java:10-22` and `Zgzb.java:10-37`). **No Collaborator method is registered or implemented here**; the old “Collaborator-based variant” and `Zp3a` OOB row are deleted.
- **Traversal detection:** `Zscp.Za` builds replacement, appended, and NUL-prefixed variants (`Zscp.java:33-59`). `Zp3a` requires file markers absent from baseline and absent from an `X`-suffixed negative control (`Zp3a.java:118-175`). Unix passwd hits get a shadow follow-up (`Zp3a.java:105-115`). WebProbe already ports this flow and all 27 table rows: `app/core/src/scan.rs:1454-1486`, matching engine `scan.rs:1568-1605`, wrapper `scan_checks.rs:1858-1925`. No additional traversal variant is established as missing.
- **Manipulation already ported:** Burp's generic same-file/bogus-path differential is `Zsl1.java:41-63,130-176`; WebProbe implements it at `app/core/src/scan.rs:2081-2152` and `scan_checks.rs:1987-2047`.
- **Manipulation variants still missing:** Burp additionally tries exact `Web.config` with `<system.web>`, `WEB-INF/web.xml` with `<web-app`, and `.htaccess` with `Options `, `AddHandler`, or `RewriteRule`, then applies an `X` negative control (`Zsl1.java:111-128,179-203`). Thorough mode also adds base-path/prefix transformations (`Zsl1.java:66-103,209-219`). These strings and flows do not occur in WebProbe's `run_file_path_manip_check` (`app/core/src/scan.rs:2081-2152`).
- **Timing / OOB / raw framing:** **no / no / no** for both issues — detection uses response markers and differential responses (`Zp3a.java:118-175`; `Zsl1.java:105-203`).
- **Porting size:** **S** for the three known-file follow-ups, **M** if the Thorough path-prefix transformations are included. Closest existing pattern: `FilePathManipulation` (`app/core/src/scan_checks.rs:1987-2047`).

---

## G. Other Active Checks Not in WebProbe

The active registry, not the mere presence of an issue enum or JSON file, is the inclusion test used here: `Zcug.java:79-265` and the JavaScript-analysis registry evidence in G.17. The old note's string-literal test also needs qualification: WebProbe now has a KB name/type-id catalog, so a name in that catalog alone does not prove that a check reports it. The entries below use report/call sites, not just catalog entries. Extension-, BCheck-, and Bambda-generated issue types are extension points rather than separate built-in checks (`Zcug.java:207,232-253,268-289`).

### G.1 Flash cross-domain policy — typeIndex 2098176

Resource: `resources/KnowledgeBase/Issues/00200400_FlashCrossDomainPolicy.json`.

- **Class / scope:** `Zm24` (`APH_FlashCrossdomainPolicy`), **per host** (`Zcug.java:96-116`; `Zcud.java:69-73`).
- **Detection:** request the decoded path `/crossdomain.xml` (`Zm24.java:34-40`; `out/strings/map_root.tsv`, `burp.Zudv` entries). `Zudv` requires status 200 and the same analyzed content-type code 262 used by its parser (`Zudv.java:26-42`). It examines `allow-access-from` elements and their `domain` attributes (`Zudv.java:45-66`), reporting `*`, wildcard-containing domains, a domain matching the target, or a related parent domain (`Zudv.java:68-121`). `Ziim.java:10-23` constructs `FLASH_CROSS_DOMAIN_POLICY`; there is no follow-up request.
- **Timing / OOB / raw framing:** **no / no / no** — the decision is status plus parsed policy content (`Zudv.java:26-42,45-141`).
- **Porting size:** **S**; closest host path probe: `OpenApiDefinition` (`app/core/src/scan_checks.rs:3273-3309`).

### G.2 Silverlight cross-domain policy — typeIndex 2098432

Resource: `resources/KnowledgeBase/Issues/00200500_SilverlightCrossDomainPolicy.json`.

- **Class / scope:** `Zbtu` (`APH_SilverlightCrossdomainPolicy`), **per host** (`Zcug.java:96-116`; `Zcud.java:69-73`).
- **Detection:** request `/clientaccesspolicy.xml` (`Zbtu.java:34-40`; `out/strings/map_root.tsv`, `burp.Zebv` entries). Require status 200 and analyzed content-type code 262 (`Zebv.java:26-42`), then inspect `domain` elements' `uri` attributes (`Zebv.java:45-67`). The report gates are `*`, wildcard URIs, target-domain matches, and related parent domains (`Zebv.java:69-139`); optional `http://` / `https://` prefixes are stripped first (`Zebv.java:69-83`). `Zipz.java:11-24` constructs the issue. No confirmation request follows.
- **Timing / OOB / raw framing:** **no / no / no** — parsed response content only (`Zebv.java:26-34,45-158`).
- **Porting size:** **S**; closest pattern: `OpenApiDefinition` (`app/core/src/scan_checks.rs:3273-3309`).

### G.3 React Server Components remote code execution (React2Shell) — typeIndex 1052160

Resource: `resources/KnowledgeBase/Issues/00101200_ReactServerComponentsRemoteCodeExecutionReact2shell.json`. This is the second, distinct issue with this numeric typeIndex; the other is Perl code injection.

- **Class / scope:** `Zgn0` (`APH_React2ShellRce`), **per host** (`Zcug.java:96-116`; `Zcud.java:69-73`).
- **Detection:** POST to `/` with random `Next-Action` and `X-Nextjs-Request-Id` values, `Next-Router-State-Tree: [""]`, and `Content-Type: multipart/form-data; boundary=<random>` (`Zgn0.java:53-71`). The multipart body has part `1` containing `{}`, part `0` containing the exact `["$1:a:a"]`, and the terminating boundary (`Zgn0.java:57-80`). A report requires status 500 and either marker `Z_`, or both markers `Zy` and `Zi`, in the response (`Zgn0.java:83-98`). The decoded strings associated with these marker fields include `Error`, `E{"digest"`, and `digest` (`out/strings/map_root.tsv`, `burp.Zgn0` entries), but their stripped field-to-literal assignments are **(not established)**. `Zwbs.java:10-23` constructs `NEXTJS_REACT2SHELL_RCE`; no second request is sent.
- **Timing / OOB / raw framing:** **no / no / no** — one ordinary multipart request followed by status/content checks (`Zgn0.java:53-98`).
- **Porting size:** **S**; closest custom-method/header host-probe skeleton: `HttpPutEnabled` (`app/core/src/scan_checks.rs:1163-1208`).

### G.4 Referer-dependent response — typeIndex 4194560

Resource: `resources/KnowledgeBase/Issues/00400100_RefererDependentResponse.json`.

- **Class / scope:** `Zxlg` (`APR_RefererDependentResponse`), **in-session per request** (`Zcug.java:138-164`; `Zcud.java:81-85`).
- **Detection:** `Zxlg` selects the exact header `Referer`, removes it for one variant, and replaces/adds it for another (`Zxlg.java:10-22`; removal `Zg4d.java:8-21`, replacement `Zptj.java:15-27`). The replacement's decoded fragments are `http://` and `.com/`, but the complete static `Zx` value is not initialized in readable source, so the full literal is **(not established)** (`Zxlg.java:7-8`; `out/strings/map_root.tsv`, `burp.Zxlg` entries). `Zxld` sends base and changed requests through `Zmaq`, repeating 4, 6, or 10 times by accuracy, and emits paired evidence when the response-attribute comparison remains positive (`Zxld.java:24-46`; `Zmaq.java:38-79,85-217,219-233`). `Zb2d` is called to construct the issue (`Zxlg.java:24-32`).
- **Timing / OOB / raw framing:** **no / no / no** — repeated response attributes, not elapsed time (`Zxld.java:24-46`; `Zsnr.java:35-61,76-80`).
- **Porting size:** **S**; closest response-diff pattern: `SpoofableClientIp` (`app/core/src/scan_checks.rs:1564-1620`).

### G.5 User agent-dependent response — typeIndex 4194592

Resource: `resources/KnowledgeBase/Issues/00400120_UserAgentDependentResponse.json`.

- **Class / scope:** `Zxly` (`APR_UserAgentDependentResponse`), **in-session per request** (`Zcug.java:138-164`; `Zcud.java:81-85`).
- **Detection:** read the existing `User-Agent`; if it does not look mobile, replace it with exact `Mozilla/5.0 (iPhone; CPU iPhone OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B176 Safari/7534.48.3`, otherwise use exact `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)` (`Zxly.java:29-46`). The mobile test checks for `iphone`, `android`, `blackberry`, `htc`, `symbian`, `nokia`, `samsung`, `mot`, and `sonyericsson` (`Zxly.java:34-45`). `Zxly` compares changing versus replacing the header and uses the same `Zxld`/`Zmaq` repeated response comparison as G.4 (`Zxly.java:20-26`; `Zxld.java:24-46`). `Zfb4` constructs the issue (`Zxly.java:48-56`).
- **Timing / OOB / raw framing:** **no / no / no** — response diffing only (`Zxld.java:24-46`; `Zsnr.java:35-61`).
- **Porting size:** **S**; closest pattern: `SpoofableClientIp` (`app/core/src/scan_checks.rs:1564-1620`).

### G.6 XML entity expansion — typeIndex 4196096

Resource: `resources/KnowledgeBase/Issues/00400700_XmlEntityExpansion.json`.

- **Classes / scopes:** `Ze3z` (`APR_XmlEntityExpansion`) is **in-session per request** for an XML base request, and `Zin9` (`APIP_XmlEntityExpansion`) is **per insertion point** (`Zcug.java:138-164,179-216`; `Zcud.java:81-91`; `Ze3z.java:24-36`; `Zin9.java:28-40`). Both invoke `Zgij`.
- **Detection:** create random entity-name and seed strings, then inject a DOCTYPE whose first entity is the seed and whose following entities contain two references to the preceding entity (`Zgij.java:26-38,108-150`). The literal framing begins `<!DOCTYPE foo [<!ENTITY ` and ends `]>` (`Zgij.java:125-145`). The insertion also contains `&<entity>;` (`Zgij.java:66-71`). Burp tries expansion depth 2 and, if that succeeds, depth 3 (`Zgij.java:38-47`). It reports when the response contains the corresponding exponentially repeated seed, with depth 3 supplying the confirmation (`Zgij.java:77-105,108-123,152-164`). `Zh6l` constructs the issue (`Zgij.java:162-164`).
- **Timing / OOB / raw framing:** **no / no / no** — expanded response text is the evidence; no external entity or elapsed-time comparison is used (`Zgij.java:66-105`).
- **Porting size:** **S**; closest XML response-marker pattern: `XmlInjectionError` (`app/core/src/scan_checks.rs:2867-2927`).

### G.7 Suspicious input transformation (reflected and stored) — typeIndexes 4197632 and 4197888

Resources: `resources/KnowledgeBase/Issues/00400d00_SuspiciousInputTransformationReflected.json` and `00400e00_SuspiciousInputTransformationStored.json`.

- **Class / scopes:** `Zeo6` (`APIP_SuspiciousInputTransformation`) is **per insertion point** for reflected input and **stored active per insertion point** for stored input (`Zcug.java:179-186,256-265`; `Zcud.java:87-97,111-117`). `Zppb.java:3-8` constructs the reflected issue and `Zc6w.java:10-14` the stored issue.
- **Detection:** initialize the reflection/transformation engine, try invalid UTF-8 first, then the other transformation maps (`Zeo6.java:39-54`). The ten maps cover overlong UTF-8, invalid UTF-8, URL decoding, backslash unescaping, and HTML decoding, each with ordinary and unexpected-transformation forms (`Zm26.java:7-17,28-40`). For each map, Burp tries its `Zwe8` operations and reports when the resulting `Zh38.Zh()` is true (`Zeo6.java:61-70`). The maps' exact byte/payload tables are stripped from readable `Zm26`, and there are no `burp.Zm26` TSV entries, so exact literal payloads are **(not established)** rather than guessed.
- **Timing / OOB / raw framing:** **no / no / no** for the reporting decision — it is the transformation result `Zh38.Zh()` and response evidence (`Zeo6.java:61-70`; `Zppb.java:5-8`; `Zc6w.java:11-14`). Invalid bytes in a parameter do not imply malformed HTTP framing.
- **Porting size:** **M** for reflected, **M** for stored. Closest patterns: `InputReflected` (`app/core/src/scan_checks.rs:2472-2535`) and `StoredXss` (`scan_checks.rs:2233-2234`; stored engine `active_checks.rs:173-197`).

### G.8 Request URL override — typeIndex 4198144

Resource: `resources/KnowledgeBase/Issues/00400f00_RequestUrlOverride.json`.

- **Class / scope:** `Zp22` runs the `Zfkb` workflow **in-session per request** (`Zcug.java:138-158`; `Zcud.java:81-85`). `Zfkb.java:68-72` reports `REQUEST_URL_OVERRIDE` through `Zegi.java:12-32`.
- **Detection:** send exact `X-Original-URL` and `X-Rewrite-URL` headers with a random path and query (`/<random>?<random>=1`), or `/?<random>=1` when the base status is 404 (`Zfkb.java:31-43,75-86`). Burp then repeats with the original request path as the header value (`Zfkb.java:51-55,88-91`). It tracks attack/control status and canary evidence and reports through the two paths at `Zfkb.java:58-72`; the shared cache workflow's repeated retrieval and independent control are at `Zg1g.java:21-161,284-332`. The issue evidence records the request headers, base status, canary presence, and resulting status (`Zegi.java:12-27`).
- **Timing / OOB / raw framing:** **no / no / no** — header probes and response status/canary comparisons (`Zfkb.java:31-72`; `Zg1g.java:284-332`).
- **Porting size:** **M**; closest header-variation sender: `Cors` (`app/core/src/scan_checks.rs:3167-3199`), with the additional control workflow from B.1.

### G.9 External service interaction (SMTP) — typeIndex 3146272

Resource: `resources/KnowledgeBase/Issues/00300220_ExternalServiceInteractionSmtp.json`.

- **Class / scope:** `Zc4x` (`APIP_EmailSendingCapability`), **per insertion point** (`Zcug.java:179-216`; `Zcud.java:87-91`). It applies to email-shaped values, or every applicable value in Thorough mode (`Zc4x.java:28-35,46-93`).
- **Detection:** when Collaborator is available, build one `EMAIL_SENDING_CAPABILITY_PAYLOAD` and send it without following redirects (`Zc4x.java:38-43`; `Zcoc.java:22-33`). The ordinary address form is `<Collaborator-id>@<Collaborator-domain>`; the minimize-false-negatives branch instead prefixes `var0.Zk(var2)` with the stripped static `a` (`Zbzl.java:8-15`), whose literal is **(not established)**. The response is not inspected. An SMTP interaction reaches `Z_e`, which constructs `EXTERNAL_SERVICE_INTERACTION_SMTP` (`Z_e.java:10-19`).
- **Timing / OOB / raw framing:** **no / yes, mandatory / no** — the verdict comes from the SMTP interaction, not response content or response time (`Zc4x.java:38-43`; `Z_e.java:10-19`).
- **Porting size:** **S**; closest OOB email pattern: `SmtpHeaderInjection` (`app/core/src/scan_checks.rs:2997-3060`), changing the payload shape and reported issue.

### G.10 Open redirection (stored) — typeIndex 5243137

Resource: `resources/KnowledgeBase/Issues/00500101_OpenRedirectionStored.json`.

- **Class / scope:** `Zuag` (`APIP_OpenRedirection`), **stored active per insertion point** (`Zcug.java:256-265`; `Zcud.java:93-97,111-117`). `Zezc.java:34-45` chooses `OPEN_REDIRECTION_REFLECTED` versus `OPEN_REDIRECTION_STORED` from the insertion/retrieval context.
- **Detection:** use an append reflection, falling back to replacement (`Zuag.java:214-220`). Try absolute URLs beginning `http://a<random>/` and `https://a<random>/`, with Thorough-mode `Http://a<random>/` (`Zuag.java:126-144`); domain-suffix variants use `.a<random>` (`Zuag.java:60-99,146-179`). A hit requires the resulting Location/redirection target to start with the injected target (`Zuag.java:223-236,270-292`). For applicable POSTs, Burp repeats through a second sender/confirmation path (`Zuag.java:106-116,239-251`). Additional prefix-table variants are tried at `Zuag.java:181-211`; the stripped table's complete literals are **(not established)**.
- **Timing / OOB / raw framing:** **no / no / no** — reflected Location/redirection content determines the result (`Zuag.java:223-292`).
- **Porting size:** **M**; combine `OpenRedirect` (`app/core/src/scan_checks.rs:2598-2649`) with the injection/retrieval pattern of `StoredXss` (`active_checks.rs:173-197`).

### G.11 Link manipulation (stored); CSS injection; client-side HTTP parameter pollution; form action hijacking

Resources and typeIndexes:

- `00501004_LinkManipulationStored.json` — **5246980**.
- `00501300_CssInjectionReflected.json` / `00501301_CssInjectionStored.json` — **5247744 / 5247745**.
- `00501400_ClientSideHttpParameterPollutionReflected.json` / `00501401_ClientSideHttpParameterPollutionStored.json` — **5248000 / 5248001**.
- `00501500_FormActionHijackingReflected.json` / `00501501_FormActionHijackingStored.json` — **5248256 / 5248257**.

**Shared class / scopes:** `Zb_5` runs **per insertion point** and **stored active per insertion point** (`Zcug.java:179-216,256-265`; `Zcud.java:87-97,111-117`). Its partially decompiled selector pairs each reflected issue with its stored counterpart and with a `Zbes` reporter (`Zb_5.java:46-90,211-225`). The constructors are explicit at `Ze20.java:42-56` (link), `Zw0x.java:12-26` (CSS), `Zi4q.java:35-47` (parameter pollution), and `Zc51.java:12-26` (form action). WebProbe already reports only link manipulation (reflected), at `app/core/src/scan_checks.rs:1927-1936`; the other seven issue types are missing.

**Shared detection:** start with REPLACE and APPEND reflections, identify applicable HTML/header/JavaScript contexts, then select `Zpyp`, `Zpy1`, or `Zpy8` according to the reflection location (`Zb_5.java:24-43,233-268`; `Zcpt.java:14-34,43-88`). Evidence of the probes and report conditions:

- **Link manipulation (stored):** use random host/path values with exact prefixes `http://`, `https://`, `//`, and `\\/` (`Zpyp.java:13-33`), and require the transformed reflection to match the injected URL (`Zpy2.java:27-55`; `Zsrd.java:3-20`). The stored registry plus `Ze20`'s reflected/stored selector is what makes this the stored issue; it is not established by merely rerunning WebProbe's reflected check.
- **CSS injection (reflected/stored):** the same selector uses the CSS issue as the primary type and `Zif` as reporter (`Zb_5.java:76-83,146-170`; `Zif.java:5-25`). A matching transformed reflection is reported through `Zw0x`; no CSS-specific fixed payload literal is visible outside the stripped `Zi9s` initializer. The applicable tag/attribute map's decoded entries include `link`, `rel`, and `stylesheet` (`out/strings/map_root.tsv`, `burp.Zi9s` entries), but the complete map is **(not established)**.
- **Client-side HTTP parameter pollution (reflected/stored):** `Zpy1` builds `<random3>&<random3><suffix>`, optionally prefixed by `?`, and requires a matching transformed reflection (`Zpy1.java:15-27`; `Zpy2.java:27-40`). The static suffix `a` is stripped and has no TSV entry, so it is **(not established)**. `Zpyp.java:67-74` also constructs a query followed by `&<random3>=<random3>`. Reports preserve HTML attribute, header, or JavaScript context through `Zbf4.java:25-35` and `Zi4q.java:12-47`.
- **Form action hijacking (reflected/stored):** the selector pairs the form issue with `Ziu` (`Zb_5.java:69-75,118-139`); matching transformed reflections are reported by `Ziu.java:5-38` / `Zc51.java:12-26`. The decoded `Zi9s` entries include `form`, `action`, and `input` (`out/strings/map_root.tsv`, `burp.Zi9s` entries); the complete applicable-attribute table is **(not established)**.

**Timing / OOB / raw framing:** **no / no / no** for all seven — the report gates are transformed reflection/context matches (`Zcpt.java:43-88`; `Zpy2.java:27-55,95-98`), not elapsed time or external interactions.

**Porting size:** **M** for each issue type, **L** if implemented as one shared engine for all seven. Closest patterns: `LinkManipulation` (`app/core/src/scan_checks.rs:1927-1978`) and `StoredXss` (`active_checks.rs:173-197`).

### G.12 Robots.txt file — typeIndex 6292992

Resource: `resources/KnowledgeBase/Issues/00600600_RobotsDotTxtFile.json`.

- **Class / scope:** `Zut6` (`APH_RobotsTxtAndTlsConfig`), **per host** (`Zcug.java:96-116`; `Zcud.java:69-73`). This is an active check; WebProbe's `CH_ROBOTS` at `app/core/src/scan.rs:124` is only passive evidence and does not port this host probe.
- **Detection:** request exact `/robots.txt`, selecting HTTP/1.1 and the literal connection option `close` (`Zut6.java:64-67`; decoded path and option in `out/strings/map_root.tsv`, `burp.Zut6` entries). Report only for status 200, an allowed response content type, and both robots markers (`Zut6.java:69-72,110-121`). The decoded markers are `user-agent:` and `allow:` (`map_root.tsv`, `burp.Zut6` entries). The accepted numeric content-type set `ZQ` is stripped and therefore **(not established)**. `Zak.java:11-20` constructs `ROBOTS_TXT_FILE`; there is no follow-up request.
- **Timing / OOB / raw framing:** **no / no / no** — status, type, and body markers only (`Zut6.java:64-72,110-121`).
- **Porting size:** **S**; closest host path probe: `OpenApiDefinition` (`app/core/src/scan_checks.rs:3273-3309`).

### G.13 TLS certificate — typeIndex 16777472

Resource: `resources/KnowledgeBase/Issues/01000100_TlsCertificate.json`.

- **Class / scope:** the TLS half of `Zut6`, **per host**, registered alongside Robots at `Zcug.java:96-116` (`Zcud.java:69-73`).
- **Detection:** the `/robots.txt` exchange captures the `SSLSession` (`Zut6.java:50-66`). For HTTPS, obtain peer certificates and build certificate details for the chain and a matching accepted issuer (`Zut6.java:75-107,130-165`). Flags cover not-yet-valid/expired certificates, hostname mismatch (including wildcard handling), and trust failure (`Zut6.java:167-196,202-264`). `Zp64.java:12-52` always constructs `TLS_CERTIFICATE` when this path returns, combining flags and choosing severity 3 for hostname/trust failures, 2 for validity dates, and 1 otherwise. No separate confirmation request exists beyond the shared Robots/TLS exchange.
- **Timing / OOB / raw framing:** **no / no / no** — certificate metadata and trust-manager results determine the report (`Zut6.java:75-107,167-264`). This needs access to the negotiated TLS peer certificate chain, not raw framing.
- **Porting size:** **M**; no close WebProbe active-check pattern. `OpenApiDefinition` (`app/core/src/scan_checks.rs:3273-3309`) supplies only the per-host skeleton; certificate-chain access is new transport work.

### G.14 Json Web Key Set disclosed — typeIndex 6293248

Resource: `resources/KnowledgeBase/Issues/00600700_JsonWebKeySetDisclosed.json`.

- **Class / scope:** `Zh7b` (`APH_JwkDisclosed`), **per host** (`Zcug.java:96-116`; `Zcud.java:69-73`). It does not run in Fast mode (`Zh7b.java:38-42`).
- **Detection:** request every path in static list `ZA`, parse each response with `Zwws`, and report every nonempty parsed key set (`Zh7b.java:38-57`; `Zbfr.java:17-27`; `Zwws.java:32-42,44-115`). Private-material names are collected from the parsed keys, highlighted, and recorded in the issue (`Zbfr.java:22-27,35-52`; `Zmir.java:56-68`). The `Zh7b.ZA` path list is stripped and there are no `burp.Zh7b` TSV entries, so the paths are **(not established)**. The JSON member literals used by `Zwws.Zp` are also still encoded and have no TSV entries, so they are **(not established)**. No confirmation request follows.
- **Timing / OOB / raw framing:** **no / no / no** — parsed JWKS response content is the report gate (`Zbfr.java:17-27`; `Zwws.java:32-42`).
- **Porting size:** **M** once the path list is recovered; closest multi-path host probe: `OpenApiDefinition` (`app/core/src/scan_checks.rs:3273-3309`).

### G.15 Broken access control — typeIndex 1050704

Resource: `resources/KnowledgeBase/Issues/00100850_BrokenAccessControl.json`.

- **Class / scope:** `Zcxn` (`APR_BrokenAccessControl`), **in-session per request** (`Zcug.java:138-164`; `Zcud.java:81-85`). It runs only in the minimize-false-negatives or false-positive-reduction configurations and has content-type/status/session preconditions (`Zcxn.java:51-67,70-115`; accepted content-type set `ZP` is stripped and **not established**).
- **Detection:** add the same random URL parameter to two requests; for the second, remove `authorization`, `cookie`, and `x-*` headers except `x-requested-with`, recording what was removed (`Zii_.java:25-64`). Compare the responses over eight rounds using status code plus page title and JSON node count for HTML, or status plus line count and JSON node count otherwise (`Zcxn.java:74-92,117-123`). The report branch runs when `responsesHaveDifferences` returns false (`Zcxn.java:52-65`); `Zsnr` tracks the remaining differing response attributes (`Zsnr.java:35-61,64-80`; `Zr2x.java:24-44,47-73,97-99`). `Zr0k.java:20-59` constructs `BROKEN_ACCESS_CONTROL` with both exchanges. The false-positive-reduction branch additionally consults browser/session information through `Zbwz.java:17-118`; the exact meaning of its three external verdict cases is **(not established)** from the decompiled switch alone.
- **Timing / OOB / raw framing:** **no / no / no** — authorization-header removal and response comparison (`Zcxn.java:52-92`; `Zii_.java:25-64`).
- **Porting size:** **L**; closest response-diff skeleton: `SpoofableClientIp` (`app/core/src/scan_checks.rs:1564-1620`), but session/browser handling and false-positive reduction are substantial new work.

### G.16 Old G entries that are already reported or are not separate active candidates

- **LDAP injection:** `Zwkf` is per insertion point with `BOOLEAN_BASED` (`Zcug.java:197`); WebProbe registers and reports `LdapInjection` (`app/core/src/scan_checks.rs:349,2930-2994`). The old S estimate is therefore not a remaining port.
- **JWT active issues:** `Zu4y` is directly registered per insertion point for signature-not-verified, none-alg, JWK, JKU, and X5U (`Zcug.java:209-216`). WebProbe reports all five in `JwtAttacks` (`app/core/src/scan_checks.rs:845-968`; registry at `scan_checks.rs:352`). JWT weak HMAC secret is instead in the passive registry (`Zsrp.java:79-100`), not another missing `Zu4y` method.
- **Already reported and not remaining G candidates:** reflected/stored XSS (`Zcug.java:184,263`; WebProbe `ReflectedXss` / `StoredXss`, `scan_checks.rs:2173-2241`), reflected open redirection (`Zcug.java:191`; `OpenRedirect`, `scan_checks.rs:2598-2649`), response-header injection (`Zcug.java:189`; `HeaderInjection`, `scan_checks.rs:2538-2595`), OS command injection (`Zcug.java:190`; `OsCommandInjection`), server-side template injection (`Zi6p.java:92-118`; `TemplateInjection`), SSI injection (`Zcug.java:202`; `SsiInjection`), XML injection / XXE (`Zcug.java:143-146,198-200`; `XmlInjectionOob`, `XmlInjectionError`, `XxeFileRead`), SMTP header injection (`Zcug.java:203`; `SmtpHeaderInjection`), CORS and its variants (`Zcug.java:148`; `Zx8s.java:20-44`; WebProbe `Cors`, `scan_checks.rs:3167-3199`), and active OpenAPI discovery (`Zcug.java:116`; `OpenApiDefinition`, `scan_checks.rs:3273-3309`). The named WebProbe checks are registered at `scan_checks.rs:330-378`; implementations not separately cited above are `OsCommandInjection` (`scan_checks.rs:1781-1855`), `TemplateInjection` (`scan_checks.rs:2112-2170`), `SsiInjection` (`scan_checks.rs:2049-2149`), `XmlInjectionOob` / `XmlInjectionError` (`scan_checks.rs:2803-2927`), `XxeFileRead` (`scan_checks.rs:3468-3527`), and `SmtpHeaderInjection` (`scan_checks.rs:2997-3060`).
- **Passive rather than missing active checks:** ASP.NET ViewState without MAC (`Zsrp.java:90`) and file-upload functionality (`Zxro.java:50`, constructed in the passive list at `Zsrp.java:86`). Unencrypted communications is also passive (`Zsrp.java:61-76`); TLS certificate is different and remains G.13.

### G.17 JavaScript static/dynamic-analysis issue families

These are not ordinary `Zcug` HTTP insertion-point/request/host checks. `Zse.java:11-62` enumerates the DOM, reflected-DOM, and stored-DOM sets, and `Zse.java:139-164` distinguishes JavaScript static from dynamic analysis. The **active-check inclusion evidence used here is the dynamic path**: dynamic work items are created by `Zfk8.java:49-83`; the separate static reporting path (`Zphn.java:12-27`) is not treated as proof of another active HTTP check. `Zf24.java:6-223` maps 16 issue families to their DOM/reflected/stored variants, while `Zbzk.java:20-83` and `Zxex.java:12-75` turn analysis events into issues. Client-side prototype pollution has its own dynamic work item and event path (`Zfk8.java:63-77`; `Zwq_.java:23-30`; `Zcyv.java:3-26`).

| Issue family (DOM / reflected DOM / stored DOM typeIndexes) | Mapping / reporting evidence |
|---|---|
| Cross-site scripting — **2097936 / 2097937 / 2097938** | `Zf24.java:11-24` |
| JavaScript injection — **2097952 / 2097953 / 2097954** | `Zf24.java:25-37` |
| Client-side SQL injection — **2097968 / 2097969 / 2097970** | `Zf24.java:38-50` |
| WebSocket URL poisoning — **2097984 / 2097985 / 2097986** | `Zf24.java:51-63` |
| Local file path manipulation — **2098000 / 2098001 / 2098002** | `Zf24.java:64-76` |
| Client-side XPath injection — **2098016 / 2098017 / 2098018** | `Zf24.java:77-89` |
| Client-side JSON injection — **2098032 / 2098033 / 2098034** | `Zf24.java:90-102` |
| Open redirection — **5243152 / 5243153 / 5243154** | `Zf24.java:103-115` |
| Cookie manipulation — **5245696 / 5245697 / 5245698** | `Zf24.java:116-128` |
| Ajax request header manipulation — **5245952 / 5245953 / 5245954** | `Zf24.java:129-141` |
| Denial of service — **5246208 / 5246209 / 5246210** | `Zf24.java:142-154` |
| HTML5 web message manipulation — **5246464 / 5246465 / 5246466** | `Zf24.java:155-167` |
| HTML5 storage manipulation — **5246720 / 5246721 / 5246722** | `Zf24.java:168-180` |
| Link manipulation — **5246976 / 5246977 / 5246978** | `Zf24.java:181-193` |
| Document domain manipulation — **5247232 / 5247233 / 5247234** | `Zf24.java:194-206` |
| DOM data manipulation — **5247488 / 5247489 / 5247490** | `Zf24.java:207-218` |
| Client-side prototype pollution — **2097942** (single type) | `Zfk8.java:63-77`; `Zcyv.java:3-26`; `Zxex.java:57-75` |

The names/typeIndexes are in the corresponding `resources/KnowledgeBase/Issues/*.json` files listed by `Zc84.java:47-76,117-175`. For all rows, the active detection input is a JavaScript dynamic-analysis event rather than an HTTP status/body comparison; dynamic reports are gated by `JAVASCRIPT_DYNAMIC_ANALYSIS` (`Zfk8.java:49-83`; `Zwq_.java:13-30`). The issue-specific taint source/sink names are partly visible in `Zcwh.java:1087-1258`, but the complete payload/source/sink specifications for every row are **(not established)** from the inspected mapper/reporting classes. No response-time comparison appears in those reporting paths, so **timing: no for the reporting decision**. **OOB: no; raw framing: no** — these require JavaScript analysis/browser instrumentation instead. **Porting size: L per family**, with no close WebProbe HTTP-check pattern; `ReflectedXss` is only a payload-breakout pattern, not a JavaScript taint-analysis engine.

---

## Summary Table

“IP” means per insertion point; “stored IP” means the stored-active injection/retrieval variant. “Ported” in the size column means no remaining port is estimated for the methods WebProbe already implements; it does not claim that every Burp variant is ported.

| Issue | Burp Class | Scope | Timing | Needs OOB | Needs Raw Framing | Size |
|-------|-----------|-------|--------|-----------|-------------------|------|
| GraphQL endpoint found | `Zwg_` | Passive per request | no | no | no | not active (passive S) |
| GraphQL endpoint discovered | `Zmzj` | Host | no | no | no | ported |
| GraphQL introspection enabled | `Zgd9` | In-session request | no | no | no | ported |
| GraphQL suggestions enabled | `Zbop` | In-session request | no | no | no | ported |
| GraphQL content type not validated | `Zx85` | In-session request | no | no | no | ported |
| Web cache poisoning | `Zsz5`, `Zp22`, `Zgux` | In-session request + IP | no | optional | no | L |
| Web cache deception | `Zum9` | In-session request | no | no | no | L |
| XPath injection | `Zg_c`, `Zppj` | IP | no | no | no | M for boolean half (error half ported) |
| HTTP PUT method is enabled | `Zu8k` | Host | no | no | no | ported |
| Backup file | `Zem7`, `Zsro`, `Zxc6`, `Zxfn` | URL | no | no | no | ported; generic extension list unrecovered |
| ASP.NET tracing enabled | `Ze3_`, `Zsqx` | Host + in-session request | no | no | no | active host probe ported |
| ASP.NET debugging enabled | `Zihl` | Host | no | no | no | ported |
| ASP.NET ViewState without MAC | `Zg3y` | Passive per request | no | no | no | not active |
| ASP.NET padding oracle | none found | not established | not established | not established | not established | not established |
| Spoofable client IP address | `Zc7h`, `Zxlc` | Host OOB + in-session request diff | no | one of two methods | no | M for OOB verdict (diff ported) |
| Expression Language injection | `Zi6p`, `Zbhh` | IP | no | no | no | ported |
| HTTP request smuggling | `Zg3d` | Request | one of several (guardian, tunnelling, status, reflection, interaction, CL.0) | optional / intrusive | yes; H2 variants need HTTP/2 | L after excluding timeout |
| Client-side desync | `Zhao` | Request | only | no | yes | L; excluded |
| Hidden HTTP 2 | `Zpfw` | Host | no | no | no; requires HTTP/2 transport | S once transport exists |
| Perl code injection | `Zsn3`, `Zwj_` | IP | only | no established OOB | no | M; excluded |
| Python code injection | `Zsn3`, `Zwj_` | IP | only | no established OOB | no | M; excluded |
| Ruby code injection | `Zsn3`, `Zwj_` | IP | only | no established OOB | no | M; excluded |
| Unidentified code injection | `Zsn3`, `Zwj_` | IP | only | no established OOB | no | M; excluded |
| Server-side JavaScript code injection | `Zg_v` | IP | only | no established OOB | no | M; excluded |
| PHP code injection | `Zsn3`, `Zxvv` | IP (file upload) | one of several (echo, Collaborator) | optional | no | echo/OOB ported; delay excluded |
| SQL injection (second order) | `Zg_c`, `Zppj` | Stored IP | one of several (error, boolean, Collaborator) | one of several methods | no | M without delay |
| File path traversal | `Zp3a` | IP | no | no | no | ported; no extra variant established |
| File path manipulation | `Zp3a`, `Zsl1` | IP | no | no | no | S known files / M with Thorough transforms |
| Flash cross-domain policy | `Zm24`, `Zudv` | Host | no | no | no | S |
| Silverlight cross-domain policy | `Zbtu`, `Zebv` | Host | no | no | no | S |
| React2Shell RCE | `Zgn0` | Host | no | no | no | S |
| Referer-dependent response | `Zxlg` | In-session request | no | no | no | S |
| User agent-dependent response | `Zxly` | In-session request | no | no | no | S |
| XML entity expansion | `Ze3z`, `Zin9`, `Zgij` | In-session request + IP | no | no | no | S |
| Suspicious input transformation (reflected / stored) | `Zeo6` | IP + stored IP | no | no | no | M / M |
| Request URL override | `Zp22`, `Zfkb` | In-session request | no | no | no | M |
| External service interaction (SMTP) | `Zc4x`, `Zcoc` | IP | no | yes | no | S |
| Open redirection (stored) | `Zuag` | Stored IP | no | no | no | M |
| Link manipulation (stored) | `Zb_5`, `Ze20` | Stored IP | no | no | no | M |
| CSS injection (reflected / stored) | `Zb_5`, `Zif`, `Zw0x` | IP + stored IP | no | no | no | M / M |
| Client-side HTTP parameter pollution (reflected / stored) | `Zb_5`, `Zi4q` | IP + stored IP | no | no | no | M / M |
| Form action hijacking (reflected / stored) | `Zb_5`, `Ziu`, `Zc51` | IP + stored IP | no | no | no | M / M |
| Robots.txt file | `Zut6` | Host | no | no | no | S |
| TLS certificate | `Zut6`, `Zp64` | Host | no | no | no; needs peer certificate chain | M |
| Json Web Key Set disclosed | `Zh7b`, `Zbfr` | Host | no | no | no | M once paths are recovered |
| Broken access control | `Zcxn` | In-session request | no | no | no | L |
| XSS / JavaScript injection / client-side SQL injection (DOM families) | `Zf24`, `Zbzk`, `Zxex` | JavaScript analysis (DOM / reflected / stored) | no for reporting | no | no | L per family |
| WebSocket URL poisoning / local file path manipulation (DOM families) | `Zf24`, `Zbzk`, `Zxex` | JavaScript analysis | no for reporting | no | no | L per family |
| Client-side XPath / JSON injection (DOM families) | `Zf24`, `Zbzk`, `Zxex` | JavaScript analysis | no for reporting | no | no | L per family |
| Open redirection / cookie manipulation (DOM families) | `Zf24`, `Zbzk`, `Zxex` | JavaScript analysis | no for reporting | no | no | L per family |
| Ajax request header manipulation / denial of service (DOM families) | `Zf24`, `Zbzk`, `Zxex` | JavaScript analysis | no for reporting | no | no | L per family |
| HTML5 web message / storage manipulation (DOM families) | `Zf24`, `Zbzk`, `Zxex` | JavaScript analysis | no for reporting | no | no | L per family |
| Link / document-domain / DOM-data manipulation (DOM families) | `Zf24`, `Zbzk`, `Zxex` | JavaScript analysis | no for reporting | no | no | L per family |
| Client-side prototype pollution | `Zfk8`, `Zcyv`, `Zxex` | Dynamic JavaScript analysis | no for reporting | no | no | L |
| LDAP injection | `Zwkf` | IP | no | no | no | ported |
| JWT active issues (signature / none / JWK / JKU / X5U) | `Zu4y` | IP | no | required only for JKU/X5U | no | ported |
| XXE file retrieval | `Zbmt` | In-session request | no | no | no | ported |
| SMTP header injection | `Zgcg`, `Zrok` | IP | no | yes | no | ported |
| CORS and variants | `Zx8s` | In-session request | no | no | no | ported |
| OpenAPI definition found (active) | `Zh0b` | Host | no | no | no | ported |

---

## Not Established Items

These are the remaining evidence gaps, not unexamined classes. Each item identifies what was inspected in the cited section.

1. **ASP.NET padding oracle (D.6):** no matching issue JSON, enum constant, or reporter was found in the allowed resources and `readable_strict/root/`; an active check cannot be specified from the available evidence.
2. **HTTP PUT literals (D.1):** `Zu8k.ZN` and `Zu8k.Zt` are declared but not initialized in readable source, and there are no `burp.Zu8k` TSV entries.
3. **Backup generic extensions (D.2):** `Zebr.ZD` is not initialized in readable source; only the recovered mutation literals are listed.
4. **Code-injection payload tables (F.1–F.5):** `Zfhw` and the five server-side JavaScript template constants are stripped and have no corresponding TSV entries. Their timing engines and issue reporters are established, but their exact language payload strings are not.
5. **React2Shell marker assignments (G.3):** status 500 and the `Z_` / `Zy`+`Zi` gates are visible, but the stripped fields cannot be mapped confidently to the decoded `Error`, `E{"digest"`, and `digest` candidates.
6. **Referer replacement (G.4):** only the decoded `http://` and `.com/` fragments were recovered; the complete static `Zxlg.Zx` value is unavailable.
7. **Suspicious-transformation payloads (G.7):** `Zm26`'s exact byte/payload tables are stripped and have no TSV entries.
8. **Stored-open-redirect prefix table (G.10):** `Zuag.Zl` is stripped; only the separately visible URL forms are quoted.
9. **Reflected/stored client-side issue tables (G.11):** the `Zpy1` suffix and complete `Zi9s` applicable-context maps are stripped; the report selectors and probe shapes are nevertheless visible.
10. **SMTP minimize-false-negatives prefix (G.9):** the static `Zbzl.a` prefix is stripped; the ordinary `<Collaborator-id>@<Collaborator-domain>` form is established, but this alternate complete payload is not.
11. **Robots content types (G.12):** the accepted numeric set `Zut6.ZQ` is stripped; `/robots.txt`, `user-agent:`, and `allow:` were recovered.
12. **JWKS paths and JSON members (G.14):** `Zh7b.ZA` and the encoded member names in `Zwws.Zp` are unavailable in readable source and TSV.
13. **Broken-access-control filters / browser verdicts (G.15):** `Zcxn.ZP` is stripped, and the three `Zbwz` switch outcomes cannot be named from the decompiled switch alone.
14. **JavaScript-analysis payloads (G.17):** the active work-item, issue-mapping, and reporting paths are established, but the complete per-family taint source/sink and dynamic-payload specifications were not recovered from the inspected classes.