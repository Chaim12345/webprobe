# D-11: remaining Burp insertion points (spec from decompiled source)

Sources: `/root/burp-re/out/readable_strict/root/Zuq.java` (builder), `Zsg0.java` (wording),
`Zbg8.java` / `Zg6r.java` (types), `/root/burp-re/in/extract/resources/Preferences/AuditDefaults.json`.
Bytecode fallbacks: `javap -c -p -classpath /root/burp-re/in/extract burp.Zuq`;
CFR: `java -jar /root/burp-re/in/cfr-0.152.jar <class file> --silent true`.
Target code: `app/core/src/scan.rs` (`IpKind`, `InsertionPoint`, `insertion_points`, `inject`,
`inject_payload`, `insertion_type`), `app/core/src/scan_config.rs` (`INSERTION_TYPES`),
`app/core/src/scan_checks.rs` / `active_checks.rs` (`applies_to`, `burp_label` users).

## Build order (Zuq.Zs, line 70) — verified
1. `ZT()` entire body
2. URL + body params (form, multipart, JSON, and XML params/attributes from the request parser)
3. `Zy()` cookies
4. `ZP()` `X-*` headers
5. nested points for everything added so far via `Zc` (list `ZA`)
6. `Za()` XML standalone tags
7. `Zp()` parameter-name points
8. `Zb()` User-Agent, Referer (existing or synthesised)
9. URL path folders, 10. URL path filename
11. `ZG()` moved-parameter points: all `scanner.modifying_parameter_locations.*` are false by default → do not build.
Cap stays 30 (`max_insertion_points_per_base_request`), applied after skip-list vetoes.

## Entire body (Zuq.ZT, line 444)
Only when the request body type is XML or JSON. Type `ENTIRE_BODY`, name `""`, base value = whole body,
payload replaces the whole body. Wording (Zsg0): "request body" / "value of the request body".
Default `insert_entire_body: true`.

## XML parameters / attributes
Burp's request parser yields `XML_PARAM` (element text) and `XML_ATTR` points for XML bodies
(labels "XML parameter", "XML attribute"). WebProbe has none as general points (`xml_value_points`
exists only for XXE). `skip_all_tests_for_parameters` drops xml attributes named `version`, `encoding`,
`standalone`, `xml:lang`, `lang`, and regex `xmlns.*`. Check `Zeq.java` / `Zsf0.java`
(`put(Zbg8.XML_PARAM, Zrwd.ZV(10).Zh(5))`, `ZV(2).Zh(2)`) to see whether these are per-type caps before porting.

## XML standalone tags (Zuq.Za line 419, addStandaloneTagInsertionPoint line 463, ZN line 477)
For an XML body, each self-closing element (`<tag/>`, spaces before `/` allowed, token type 4).
Point type `XML_PARAM`, name = tag name, base value `""`. Building the request replaces `/>` (from the
position of `/`, after trimming spaces before it) with `></tag>` and the payload goes between: `<tag>PAYLOAD</tag>`.
Added with `Zc`, but after the nested pass, so standalone tags get no nested children.

## Nested points (Zuq.ZV line 563; `use_nested_insertion_points: true`)
For each base point (params, cookies, X-* headers), DFS with a stack over `value.trim()`:
1. Detect content (`Zuq.ZP` line 655: `Zxb0.Zh`, and when NONE, `Zi5p.Zx` → URL-encoded). If it parses to
   URL-encoded / XML / JSON parameters, each parameter becomes a nested point (type of that parameter),
   pushed in order; continue (no base64 test).
2. Else if Base64 (`net.portswigger.Zq0.ZC`): type `BASE64_ENCODED`, name = parent name, value = decoded text; recurse.
3. Else if Base64url (`net.portswigger.Zan.ZG`): type `BASE64URL_ENCODED`; recurse.
Base64 test (`Zq4`): length ≥ 4; length % 4 != 1; if last byte is `=` then length % 4 == 0, else the
second-to-last byte must not be `=`; no `=` before the last two positions; every byte in the alphabet
(`A-Za-z0-9+/=`; url variant `-_`); AND the decoded bytes are all printable ASCII
(`Zyn.Za`: 32..126 or \t \n \r). Standard decode strips \t \n \r space first.
JSON nested values that are not quoted (numbers etc., `Zuq.Zm` line 685) are rewritten quoted when injected.
Payload encoding composes outward: payload → nested encoding (base64 / url / json) → parent point encoding.
Wording (Zsg0 lines 59-114): "Base64-decoded value" + " of the " + parent description; other nested: child + " within the " + parent.

## Parameter-name points (Zuq.Zp line 696 bytecode, addNewParameterNameInsertionPoint line 764)
- If the request has a url-encoded or multipart body parameter (`Zm` flag): one body name point
  (`PARAM_NAME_BODY_MULTIPART` if body is multipart, else `PARAM_NAME_BODY_URL_ENCODED`).
- Always one URL name point (`PARAM_NAME_URL`).
- Each is built by adding parameter `1=1`; the point covers the NAME; base value "1". Injected request: `PAYLOAD=1` appended.
- If the URL file extension equalsIgnoreCase `php` (decoded string -11279/3883 = "php"): `ZD` adds a path-info
  point: path becomes `<path>/1`, the `1` is the point (type `PARAM_NAME_URL`, base "1").
Wording: "name of an arbitrarily supplied URL parameter" / "name of an arbitrarily supplied body parameter".
Default `insert_param_name: true`.

## skip_server_side_injection_for_parameters (AuditDefaults.json)
cookie regex `aspsessionid.*`; cookie `asp.net_sessionid`; body `__eventtarget`, `__eventargument`,
`__viewstate`, `__eventvalidation`; any parameter `jsessionid`; cookies `cfid`, `cftoken`, `PHPSESSID`, `session_id`.
Config read in `Zwh1.java`; predicate `Zb1q.Ze(type, name, value)` (`Zs4k.java:199`, `Zmye.java:251`).
Lead: the only direct caller is `Ziqf.java:53` (`Zgx0.Zr(Ze9d cfg)` on the insertion point: "is this point
server-side-skipped"). Still to find: who calls `Zgx0.Zr(...)`, i.e. which checks count as "server-side injection". Find it (grep
`readable_strict/root` for `.Ze(` with three args on a `Zb1q`-typed value, or javap callers) and tag the
matching WebProbe checks so they skip these points while client-side checks (XSS etc.) still run.
Matching is case-insensitive? Verify in `Zemi.Zp`.

## Scan configuration
`INSERTION_TYPES` gains "entire body" and "parameter name" keys (Burp: `insert_entire_body`, `insert_param_name`),
plus a nested-points toggle (`use_nested_insertion_points`). Existing saved configs must still load.

## Tests wanted (unit, no network)
- order + cap test extended with the new kinds (JSON body → entire-body point first)
- nested: `data=<base64 of "a=1&b=2">` yields Base64 point then nested a, b; injection round-trips (decode shows payload)
- base64 heuristic: positive and each negative rule
- standalone tag: `<a><b/></a>` → point b; injected body `<a><b>PAYLOAD</b></a>`
- name points: GET, POST form, POST multipart, `.php` path-info
- server-side skip: PHPSESSID cookie gets XSS checks but not SQLi/command injection etc.
