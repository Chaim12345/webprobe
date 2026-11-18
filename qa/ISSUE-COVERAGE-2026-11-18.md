# WebProbe issue-type coverage against Burp's scanner issue types

> **Delegated research (2026-11-18), not reviewed.** Written by a free model as leads for the task named in the title; confirm each class:line before relying on it.

Date: 2026-11-18. Inputs: Burp KnowledgeBase issue definitions in `burp-re/in/extract/resources/KnowledgeBase/Issues/*.json` (read-only) and WebProbe scanner code in `app/core/src/` (read-only). This file is the only artefact.

## Summary

- Total Burp issue types (one JSON each): **183**
- Reported by WebProbe (name appears as a string literal in code that creates/returns an issue, or a CORS `kb_name()` setter): **70**
- Not reported **113**, of which:
  - name present only in a lookup table (`KB_ISSUE_TYPES` at scan_checks.rs:2763-2838, or `kb_issue_names.txt`): **113** (all of the not-reported ones are of this kind)
  - name absent everywhere (after a case-insensitive search for a distinctive part): **0**

Method notes:

- Scripted first pass: every JSON `name` searched for as an exact quoted literal per source file, with the `KB_ISSUE_TYPES` table (scan_checks.rs:2763-2838) and `#[cfg(test)]` hits flagged separately.
- Every **yes** was confirmed by reading the code at the hit. The creating call is one of: a `CheckDef` (scan.rs:79) whose check is in `PASSIVE_CHECKS` (passive_checks.rs) - the check's own `run` emits it through `mk_check`/`issue`; a `PointCheck`/`RequestCheck` in `POINT_CHECKS`/`REQUEST_CHECKS` (scan_checks.rs:330/355) whose `issue()`/`mk_burp`/`mk_point` carries the name; an OOB matcher rename (oob.rs:195/215); a CORS `CorsKind::kb_name()` setter (burp_checks.rs:245-248) used by `Cors::run` (scan_checks.rs:2304).
- Lookup-table-only names: `KB_ISSUE_TYPES`/`kb_issue_names.txt` are the type-id/name registry used by `is_burp_issue` (scan.rs:345) and `issue_type_id` (scan.rs:255); per the task definition they do not count as reporting, so they are marked **table-only**.
- Context literals that look like issue names but are not creators were excluded: the `CHARACTERISATION_ISSUES` expectation list in `#[cfg(test)]` (scan.rs:4944), test assertions, comments, and the doc comments / `CHARACTERISATION_ISSUES` expectation rows.
- No cargo/build/test/network was run. Code was read as of 2026-11-18 ~09:20 local; another agent is editing the repo (h2/net/streaming files changed during the read), but none of those touch the issue-creating code listed below.

## Table

| id | Burp issue name | Burp sev | reported | evidence (file:line) | group |
|---|---|---|---|---|---|
| 00100100 | OS command injection | high | yes | scan_checks.rs:941 (OsCommandInjection::run -> mk_point); reg scan_checks.rs:334 | active |
| 00100200 | SQL injection | high | yes | scan_checks.rs:1828 (SqlErrorInjection::run -> mk); scan_checks.rs:1890 (SqlBooleanInjection::run -> mk_point) | active |
| 00100210 | SQL injection (second order) | high | table-only |  | other |
| 00100280 | ASP.NET tracing enabled | high | table-only |  | other |
| 00100300 | File path traversal | high | yes | scan_checks.rs:1018 (PathTraversal::run -> mk_point) | active |
| 00100400 | XML external entity injection | high | yes | scan_checks.rs:2614 (XxeFileRead::run -> mk_burp); scan_checks.rs:2585 (XxeFileRead::issue) | active |
| 00100500 | LDAP injection | high | yes | scan_checks.rs:2088 (LdapInjection::run -> mk_point) | active |
| 00100600 | XPath injection | high | table-only |  | other |
| 00100700 | XML injection | medium | yes | scan_checks.rs:1962 (XmlInjectionOob::run -> mk_point); scan_checks.rs:2027 (XmlInjectionError::run -> mk_point) | active |
| 00100800 | ASP.NET debugging enabled | medium | table-only |  | other |
| 00100850 | Broken access control | info | table-only |  | other |
| 00100900 | HTTP PUT method is enabled | high | table-only |  | other |
| 00100a00 | Out-of-band resource load (HTTP) | high | yes | scan_checks.rs:507 (oob_resource_load_issue -> mk) | active |
| 00100b00 | File path manipulation | high | yes | scan_checks.rs:1146 (FilePathManipulation::run -> mk_point) | active |
| 00100c00 | PHP code injection | high | yes | scan_checks.rs:1543 (PhpCodeInjection::run -> mk_point); scan_checks.rs:1560 | active |
| 00100d00 | Server-side JavaScript code injection | high | table-only |  | other |
| 00100e00 | Perl code injection | high | table-only |  | other |
| 00100f00 | Ruby code injection | high | table-only |  | other |
| 00100f10 | Python code injection | high | table-only |  | other |
| 00100f20 | Expression Language injection | high | table-only |  | other |
| 00101000 | Unidentified code injection | high | table-only |  | other |
| 00101080 | Server-side template injection | high | yes | scan_checks.rs:1270 (TemplateInjection::run -> mk_point) | active |
| 00101100 | SSI injection | high | yes | scan_checks.rs:1208 (SsiInjection::run -> mk_point) | active |
| 00101200 | React Server Components remote code execution (React2Shell) | high | table-only |  | other |
| 00200100 | Cross-site scripting (stored) | high | yes | scan_checks.rs:1395 (StoredEcho::run -> mk_point); STORED_CHECKS &StoredXss scan_checks.rs:678 | active |
| 00200140 | HTTP request smuggling | high | table-only |  | other |
| 00200141 | Client-side desync | high | table-only |  | other |
| 00200180 | Web cache poisoning | high | table-only |  | other |
| 00200200 | HTTP response header injection | high | yes | scan_checks.rs:1695 (HeaderInjection::run -> mk_point) | active |
| 00200300 | Cross-site scripting (reflected) | high | yes | scan_checks.rs:1330 (ReflectedXss::run -> mk_point) | active |
| 00200308 | Client-side template injection | high | yes | scan_checks.rs:1465 (ClientTemplateInjection::run -> mk_point) | active |
| 00200310 | Cross-site scripting (DOM-based) | high | table-only |  | DOM-based |
| 00200311 | Cross-site scripting (reflected DOM-based) | high | table-only |  | DOM-based |
| 00200312 | Cross-site scripting (stored DOM-based) | high | table-only |  | DOM-based |
| 00200316 | Client-side prototype pollution | info | table-only |  | other |
| 00200320 | JavaScript injection (DOM-based) | high | table-only |  | DOM-based |
| 00200321 | JavaScript injection (reflected DOM-based) | high | table-only |  | DOM-based |
| 00200322 | JavaScript injection (stored DOM-based) | high | table-only |  | DOM-based |
| 00200328 | Path-relative style sheet import | info | yes | scan_checks.rs:2331 (PathRelativeStyleSheet::run -> mk); issue() scan_checks.rs:2321 | active |
| 00200330 | Client-side SQL injection (DOM-based) | high | table-only |  | DOM-based |
| 00200331 | Client-side SQL injection (reflected DOM-based) | high | table-only |  | DOM-based |
| 00200332 | Client-side SQL injection (stored DOM-based) | high | table-only |  | DOM-based |
| 00200340 | WebSocket URL poisoning (DOM-based) | high | table-only |  | DOM-based |
| 00200341 | WebSocket URL poisoning (reflected DOM-based) | high | table-only |  | DOM-based |
| 00200342 | WebSocket URL poisoning (stored DOM-based) | high | table-only |  | DOM-based |
| 00200350 | Local file path manipulation (DOM-based) | high | table-only |  | DOM-based |
| 00200351 | Local file path manipulation (reflected DOM-based) | high | table-only |  | DOM-based |
| 00200352 | Local file path manipulation (stored DOM-based) | high | table-only |  | DOM-based |
| 00200360 | Client-side XPath injection (DOM-based) | low | table-only |  | DOM-based |
| 00200361 | Client-side XPath injection (reflected DOM-based) | low | table-only |  | DOM-based |
| 00200362 | Client-side XPath injection (stored DOM-based) | low | table-only |  | DOM-based |
| 00200370 | Client-side JSON injection (DOM-based) | low | table-only |  | DOM-based |
| 00200371 | Client-side JSON injection (reflected DOM-based) | low | table-only |  | DOM-based |
| 00200372 | Client-side JSON injection (stored DOM-based) | low | table-only |  | DOM-based |
| 00200400 | Flash cross-domain policy | high | table-only |  | other |
| 00200500 | Silverlight cross-domain policy | high | table-only |  | other |
| 00200503 | Content security policy: allowlisted script resources | info | yes | csp.rs:16 (CSP_ALLOWLISTED_SCRIPTS CheckDef) reported via csp.rs:384 issue(), registered passive_checks.rs:110 | passive |
| 00200504 | Content security policy: allows untrusted script execution | info | yes | csp.rs:14 (CSP_UNTRUSTED_SCRIPTS CheckDef) reported via csp.rs:384 issue() | passive |
| 00200505 | Content security policy: allows untrusted style execution | info | yes | csp.rs:15 (CSP_UNTRUSTED_STYLES CheckDef) reported via csp.rs:384 issue() | passive |
| 00200506 | Content security policy: malformed syntax | info | yes | csp.rs:19 (CSP_MALFORMED CheckDef) reported via csp.rs:384 issue() | passive |
| 00200507 | Content security policy: allows clickjacking | info | yes | csp.rs:17 (CSP_CLICKJACKING CheckDef) reported via csp.rs:384 issue() | passive |
| 00200508 | Content security policy: allows form hijacking | info | yes | csp.rs:18 (CSP_FORM_HIJACKING CheckDef) reported via csp.rs:384 issue() | passive |
| 00200509 | Content security policy: not enforced | info | yes | csp.rs:13 (CSP_NOT_ENFORCED CheckDef) reported via csp.rs:384 issue() | passive |
| 00200510 | GraphQL endpoint found | info | table-only |  | other |
| 00200511 | GraphQL endpoint discovered | info | table-only |  | other |
| 00200512 | GraphQL introspection enabled | low | table-only |  | other |
| 00200513 | GraphQL suggestions enabled | low | table-only |  | other |
| 00200514 | GraphQL content type not validated | low | table-only |  | other |
| 00200600 | Cross-origin resource sharing | info | yes | scan_checks.rs:2304 (Cors::run -> mk(f.kind.kb_name())); name burp_checks.rs:245; issue() scan_checks.rs:2285 | active |
| 00200601 | Cross-origin resource sharing: arbitrary origin trusted | high | yes | burp_checks.rs:246 (CorsKind::kb_name) used by Cors::run scan_checks.rs:2304 | active |
| 00200602 | Cross-origin resource sharing: unencrypted origin trusted | low | yes | burp_checks.rs:248 (CorsKind::kb_name) used by Cors::run scan_checks.rs:2304 | active |
| 00200603 | Cross-origin resource sharing: all subdomains trusted | low | yes | burp_checks.rs:247 (CorsKind::kb_name) used by Cors::run scan_checks.rs:2304 | active |
| 00200650 | Web cache deception | medium | table-only |  | other |
| 00200700 | Cross-site request forgery | medium | yes | scan_checks.rs:2682 (CsrfTokenNotEnforced::run -> mk_burp); issue() scan_checks.rs:2645 | active |
| 00200800 | SMTP header injection | medium | yes | scan_checks.rs:2160 (SmtpHeaderInjection::run -> mk_point); issue() scan_checks.rs:2118 | active |
| 00200900 | JWT signature not verified | high | table-only |  | other |
| 00200901 | JWT none algorithm supported | high | table-only |  | other |
| 00200902 | JWT self-signed JWK header supported | high | table-only |  | other |
| 00200903 | JWT weak HMAC secret | high | table-only |  | other |
| 00200904 | JWT arbitrary jku header supported | high | table-only |  | other |
| 00200905 | JWT arbitrary x5u header supported | high | table-only |  | other |
| 00300100 | Cleartext submission of password | high | yes | scan.rs:110 (CH_LOGIN_HTTP CheckDef) via mk_check passive_checks.rs:786 | passive |
| 00300200 | External service interaction (DNS) | info | yes | scan_checks.rs:454 (EverywhereProbe from CollaboratorEverywhere); oob.rs:195/215 (match_interactions rename to "External service interaction ({kind})") | active |
| 00300210 | External service interaction (HTTP) | high | yes | scan_checks.rs:454 (EverywhereProbe slot labels); oob.rs:195/215 (match_interactions, kind from collaborator.rs:72-77 yields HTTP) | active |
| 00300220 | External service interaction (SMTP) | info | table-only |  | other |
| 00400100 | Referer-dependent response | info | table-only |  | other |
| 00400110 | Spoofable client IP address | info | table-only |  | other |
| 00400120 | User agent-dependent response | info | table-only |  | other |
| 00400200 | Password returned in later response | medium | yes | passive_pack.rs:16 (CH_PASSWORD_LATER CheckDef) reported via passive_pack.rs:22 issue() | passive |
| 00400300 | Password submitted using GET method | low | yes | passive_checks.rs:160 (CH_PASSWORD_GET CheckDef) via mk_check passive_checks.rs:434 | passive |
| 00400400 | Password returned in URL query string | low | yes | passive_pack.rs:15 (CH_PASSWORD_URL_QUERY CheckDef) via passive_pack.rs:22 issue() | passive |
| 00400480 | SQL statement in request parameter | medium | table-only |  | other |
| 00400500 | Cross-domain POST | info | table-only |  | other |
| 00400600 | ASP.NET ViewState without MAC enabled | high | table-only |  | other |
| 00400700 | XML entity expansion | medium | table-only |  | other |
| 00400800 | Long redirection response | info | table-only |  | other |
| 00400900 | Serialized object in HTTP message | high | yes | passive_pack.rs:19 (CH_SERIALIZED CheckDef) via passive_pack.rs:22 issue() | passive |
| 00400a00 | Duplicate cookies set | info | yes | passive_pack.rs:12 (CH_DUPLICATE_COOKIES CheckDef) via passive_pack.rs:22 issue() | passive |
| 00400b00 | Input returned in response (stored) | info | yes | scan_checks.rs:654 (stored_input_issue -> mk, STORED_INPUT_ISSUE scan_checks.rs:623) | active |
| 00400c00 | Input returned in response (reflected) | info | yes | scan_checks.rs:1638 (InputReflected::run -> mk) | active |
| 00400d00 | Suspicious input transformation (reflected) | info | table-only |  | other |
| 00400e00 | Suspicious input transformation (stored) | info | table-only |  | other |
| 00400f00 | Request URL override | info | table-only |  | other |
| 00500080 | Vulnerable JavaScript dependency | low | yes | retirejs.rs:14 (CH_VULNERABLE_JS CheckDef) reported by retirejs::run, registered passive_checks.rs:120 | passive |
| 00500100 | Open redirection (reflected) | low | yes | scan_checks.rs:1755 (OpenRedirect::run -> mk_point); issue() scan_checks.rs:1716 | active |
| 00500101 | Open redirection (stored) | medium | table-only |  | other |
| 00500110 | Open redirection (DOM-based) | low | table-only |  | DOM-based |
| 00500111 | Open redirection (reflected DOM-based) | low | table-only |  | DOM-based |
| 00500112 | Open redirection (stored DOM-based) | medium | table-only |  | DOM-based |
| 00500200 | TLS cookie without secure flag set | medium | yes | scan.rs:99 (CH_COOKIE_SECURE CheckDef) via mk_check (pack::cookie_flag) | passive |
| 00500300 | Cookie scoped to parent domain | low | yes | passive_pack.rs:14 (CH_COOKIE_PARENT_DOMAIN CheckDef) via passive_pack.rs:22 issue() | passive |
| 00500400 | Cross-domain Referer leakage | info | table-only |  | other |
| 00500500 | Cross-domain script include | info | yes | passive_pack.rs:13 (CH_CROSS_DOMAIN_SCRIPT CheckDef) via passive_pack.rs:22 issue() | passive |
| 00500600 | Cookie without HttpOnly flag set | low | yes | scan.rs:97 (CH_COOKIE_HTTPONLY CheckDef) via mk_check (pack::cookie_flag) | passive |
| 00500700 | Session token in URL | medium | yes | passive_pack.rs:11 (CH_SESSION_TOKEN_URL CheckDef) via passive_pack.rs:22 issue() | passive |
| 00500800 | Password field with autocomplete enabled | low | yes | scan.rs:113 (CH_AUTOCOMPLETE CheckDef) via mk_check passive_checks.rs:800 | passive |
| 00500900 | Password value set in cookie | medium | yes | passive_pack.rs:17 (CH_PASSWORD_COOKIE CheckDef) via passive_pack.rs:22 issue() | passive |
| 00500980 | File upload functionality | info | table-only |  | other |
| 005009a0 | Frameable response (potential Clickjacking) | info | yes | scan.rs:90 (CH_FRAME CheckDef) via mk_check passive_checks.rs:498 | passive |
| 005009b0 | Browser cross-site scripting filter disabled | info | table-only |  | other |
| 00500a00 | HTTP TRACE method is enabled | info | yes | scan_checks.rs:2346 (TraceEnabled::issue); reported via mk at TraceEnabled::run | active |
| 00500b00 | Cookie manipulation (DOM-based) | low | table-only |  | DOM-based |
| 00500b01 | Cookie manipulation (reflected DOM-based) | low | table-only |  | DOM-based |
| 00500b02 | Cookie manipulation (stored DOM-based) | low | table-only |  | DOM-based |
| 00500c00 | Ajax request header manipulation (DOM-based) | low | table-only |  | DOM-based |
| 00500c01 | Ajax request header manipulation (reflected DOM-based) | low | table-only |  | DOM-based |
| 00500c02 | Ajax request header manipulation (stored DOM-based) | low | table-only |  | DOM-based |
| 00500d00 | Denial of service (DOM-based) | info | table-only |  | DOM-based |
| 00500d01 | Denial of service (reflected DOM-based) | info | table-only |  | DOM-based |
| 00500d02 | Denial of service (stored DOM-based) | low | table-only |  | DOM-based |
| 00500e00 | HTML5 web message manipulation (DOM-based) | info | table-only |  | DOM-based |
| 00500e01 | HTML5 web message manipulation (reflected DOM-based) | info | table-only |  | DOM-based |
| 00500e02 | HTML5 web message manipulation (stored DOM-based) | info | table-only |  | DOM-based |
| 00500f00 | HTML5 storage manipulation (DOM-based) | info | table-only |  | DOM-based |
| 00500f01 | HTML5 storage manipulation (reflected DOM-based) | info | table-only |  | DOM-based |
| 00500f02 | HTML5 storage manipulation (stored DOM-based) | info | table-only |  | DOM-based |
| 00501000 | Link manipulation (DOM-based) | low | table-only |  | DOM-based |
| 00501001 | Link manipulation (reflected DOM-based) | low | table-only |  | DOM-based |
| 00501002 | Link manipulation (stored DOM-based) | low | table-only |  | DOM-based |
| 00501003 | Link manipulation (reflected) | info | yes | scan_checks.rs:1083 (LinkManipulation::run -> mk_point); issue() scan_checks.rs:1045 | active |
| 00501004 | Link manipulation (stored) | info | table-only |  | other |
| 00501100 | Document domain manipulation (DOM-based) | medium | table-only |  | DOM-based |
| 00501101 | Document domain manipulation (reflected DOM-based) | medium | table-only |  | DOM-based |
| 00501102 | Document domain manipulation (stored DOM-based) | medium | table-only |  | DOM-based |
| 00501200 | DOM data manipulation (DOM-based) | info | table-only |  | DOM-based |
| 00501201 | DOM data manipulation (reflected DOM-based) | info | table-only |  | DOM-based |
| 00501202 | DOM data manipulation (stored DOM-based) | info | table-only |  | DOM-based |
| 00501300 | CSS injection (reflected) | medium | table-only |  | other |
| 00501301 | CSS injection (stored) | medium | table-only |  | other |
| 00501400 | Client-side HTTP parameter pollution (reflected) | low | table-only |  | other |
| 00501401 | Client-side HTTP parameter pollution (stored) | low | table-only |  | other |
| 00501500 | Form action hijacking (reflected) | medium | table-only |  | other |
| 00501501 | Form action hijacking (stored) | medium | table-only |  | other |
| 00600080 | Database connection string disclosed | medium | yes | passive_pack.rs:20 (CH_DB_CONNECTION CheckDef) via passive_pack.rs:22 issue() | passive |
| 006000b0 | Source code disclosure | low | yes | passive_pack.rs:18 (CH_SOURCE_CODE CheckDef) via passive_pack.rs:22 issue() | passive |
| 006000d8 | Backup file | info | table-only |  | other |
| 00600100 | Directory listing | info | yes | scan.rs:107 (CH_DIR_LISTING CheckDef) via mk_check passive_checks.rs:714 | passive |
| 00600200 | Email addresses disclosed | info | yes | scan.rs:115 (CH_EMAIL CheckDef) via mk_check passive_checks.rs:746 | passive |
| 00600300 | Private IP addresses disclosed | info | yes | scan.rs:117 (CH_PRIVATE_IP CheckDef) via mk_check passive_checks.rs:751 | passive |
| 00600400 | Social security numbers disclosed | info | yes | passive_checks.rs:271 (CH_SSN CheckDef) via mk_check passive_checks.rs:403 | passive |
| 00600500 | Credit card numbers disclosed | info | yes | scan.rs:118 (CH_CREDIT_CARD CheckDef) via mk_check passive_checks.rs:756 | passive |
| 00600550 | Private key disclosed | info | yes | passive_checks.rs:269 (CH_PRIVATE_KEY CheckDef) via mk_check passive_checks.rs:341 | passive |
| 00600600 | Robots.txt file | info | yes | scan.rs:124 (CH_ROBOTS CheckDef) via mk_check passive_checks.rs:723 | passive |
| 00600700 | Json Web Key Set disclosed | info | table-only |  | other |
| 00600800 | JWT private key disclosed | high | table-only |  | other |
| 00600900 | OpenAPI definition found (active scan check) | info | yes | scan_checks.rs:2392 (OpenApiDefinition::issue), reported in OpenApiDefinition::run | active |
| 00600901 | OpenAPI definition found (passive scan check) | info | yes | scan.rs:119 (CH_OPENAPI_PASSIVE CheckDef) via mk_check passive_checks.rs:473 | passive |
| 00700100 | Cacheable HTTPS response | info | yes | scan.rs:112 (CH_CACHE CheckDef) via mk_check passive_checks.rs:650 | passive |
| 00700200 | Base64-encoded data in parameter | info | table-only |  | other |
| 00800100 | Multiple content types specified | info | yes | scan.rs:123 (CH_CT_MULTI CheckDef) via mk_check | passive |
| 00800200 | HTML does not specify charset | info | yes | scan.rs:120 (CH_HTML_NO_CHARSET CheckDef) via mk_check | passive |
| 00800300 | HTML uses unrecognized charset | info | yes | scan.rs:121 (CH_HTML_BAD_CHARSET CheckDef) via mk_check | passive |
| 00800400 | Content type incorrectly stated | low | table-only |  | other |
| 00800500 | Content type is not specified | info | yes | scan.rs:122 (CH_CT_MISSING CheckDef) via mk_check | passive |
| 01000100 | TLS certificate | medium | table-only |  | other |
| 01000200 | Unencrypted communications | low | yes | scan.rs:88 (CH_CLEARTEXT CheckDef) via mk_check passive_checks.rs:482 | passive |
| 01000300 | Strict transport security not enforced | low | yes | scan.rs:87 (CH_HSTS CheckDef) via mk_check passive_checks.rs:505 | passive |
| 01000400 | Mixed content | info | yes | scan.rs:111 (CH_MIXED CheckDef) via mk_check passive_checks.rs:771 | passive |
| 01000500 | Hidden HTTP 2 | info | table-only |  | other |
| 08000000 | Extension generated issue | info | table-only |  | other |
| 08008000 | Manually generated issue | info | table-only |  | other |
| 09000000 | BCheck generated issue | info | table-only |  | other |
| 09008000 | Bambda generated issue | info | table-only |  | other |

Group key: `DOM-based` = name carries the DOM-based family tag (Burp's DOM-invader issue types - none are reported); `passive`/`active` = the check that would emit it; `other` = everything else (request/host-level probes, extension/manual/BCheck types, and non-DOM types with no check).

## WebProbe-only issue names (not Burp issue types)

These strings are used as issue names/`CheckDef.name` in WebProbe but do not appear as a Burp issue type. Burp-named issues whose WebProbe check is off by default (`extra_checks`) are not in this list; these are the extra/own checks.

| issue name | evidence (file:line) | kind |
|---|---|---|
| Session cookie sent on cross-host redirect | scan.rs:113 (CH_REDIRECT_COOKIE CheckDef) via mk_check passive_checks.rs:634 | passive |
| CSRF token missing on form with password field | scan.rs:125 (CH_CSRF CheckDef) via mk_check passive_checks.rs:447 | passive |
| CORS misconfiguration: wildcard origin | scan.rs:102 (CH_CORS_WILDCARD CheckDef) reported by passive_checks.rs:576 cors() | passive |
| CORS misconfiguration: wildcard origin with credentials | scan.rs:103 (CH_CORS_WILDCARD_CREDS CheckDef) reported by passive_checks.rs:576 | passive |
| CORS misconfiguration: arbitrary origin reflected | scan.rs:104 (CH_CORS_REFLECT CheckDef) reported by passive_checks.rs:576 | passive |
| CORS misconfiguration: reflected origin with credentials | scan.rs:105 (CH_CORS_CREDS CheckDef) reported by passive_checks.rs:576 | passive |
| CORS misconfiguration: null origin allowed | scan.rs:106 (CH_CORS_NULL CheckDef) reported by passive_checks.rs:576 | passive |
| Cookie without SameSite attribute | scan.rs:100 (CH_COOKIE_SAMESITE CheckDef) reported by passive_checks.rs:564 cookie_flags() | passive |
| SameSite=None cookie without Secure attribute | scan.rs:101 (CH_COOKIE_SAMESITE_NONE CheckDef) reported by passive_checks.rs:564 | passive |
| Server header discloses version | scan.rs:94 (CH_SERVER CheckDef) via mk_check passive_checks.rs:540 | passive |
| X-Powered-By header discloses technology | scan.rs:95 (CH_XPB CheckDef) via mk_check passive_checks.rs:548 | passive |
| ASP.NET version disclosure | scan.rs:96 (CH_ASPNET CheckDef) via mk_check passive_checks.rs:559 | passive |
| Content security policy (CSP) header not set | scan.rs:89 (CH_CSP CheckDef) via mk_check passive_checks.rs:511 | passive |
| Exposed .git directory | scan.rs:108 (CH_GIT CheckDef) via mk_check passive_checks.rs:692 | passive |
| Exposed .env file | scan.rs:109 (CH_ENV CheckDef) via mk_check passive_checks.rs:704 | passive |
| Possible credential reference in HTML comment | scan.rs:64 (SECRET_KEYWORDS entry) via mk passive_checks.rs:679 | passive |
| Possible secret reference in HTML comment | scan.rs:66 (SECRET_KEYWORDS entry) via mk passive_checks.rs:679 | passive |
| Possible API key reference in HTML comment | scan.rs:67-68 (SECRET_KEYWORDS entries) via mk passive_checks.rs:679 | passive |
| Developer note in HTML comment | scan.rs:69 (SECRET_KEYWORDS entry) via mk passive_checks.rs:679 | passive |
| SQL error message in response | scan.rs:49 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| SQLite error message in response | scan.rs:50 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| Oracle database error message in response | scan.rs:51 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| PHP runtime warning in response | scan.rs:52 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| Server exception message in response | scan.rs:53 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| Stack trace disclosed in response | scan.rs:54 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| MySQL warning in response | scan.rs:55 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| Python stack trace disclosed in response | scan.rs:56 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| Java stack trace disclosed in response | scan.rs:57 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| Go stack trace disclosed in response | scan.rs:58 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| PHP fatal error disclosed in response | scan.rs:59 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| PHP notice disclosed in response | scan.rs:60 (ERROR_SIGNATURES) via mk passive_checks.rs:661 | passive |
| Out-of-band payload embedded via parameter <name> | scan_checks.rs:801 (ExternalInteraction::run -> mk(format!)) | active |
| Out-of-band payload embedded via the <label> | scan_checks.rs:477 (CollaboratorEverywhere::run -> mk(format!)) | active |
| Active probe: DOM-based cross-site scripting (reflected) | scan_checks.rs:834 (LightProbes::issue); reported scan_checks.rs:873 | active |
| Active probe: value of parameter appears stored | scan_checks.rs:2187 (StoredEcho::issue); reported scan_checks.rs:2231 | active |
| Active probe: TRACE method enabled (cross-site tracing) | scan_checks.rs:2453 (ServerTrace::issue); reported scan_checks.rs:2474 | active |
| Active probe: permissive HTTP methods advertised via OPTIONS | scan_checks.rs:2494 (ServerOptions::issue); reported scan_checks.rs:2516 | active |
| Active probe: attacker-set header value reflected (header manipulation) | scan_checks.rs:2537 (HeaderManipulation::issue); reported scan_checks.rs:2554 | active |

## Caveats / unsure

- None marked `unsure`: every type was decided from a read code hit or from an exhaustive case-insensitive literal search that found no creator (only the lookup table).
- Two Burp ids share the same `typeIndex` in the source table (`BCheck generated issue` and `Bambda generated issue` both `0x09000000`; `React Server Components ...` reuses `0x00100e00`). This does not change the reported/not-reported verdicts.
- `External service interaction (HTTP)` is reached through the OOB rename (`format!("External service interaction ({kind})")`, oob.rs:195/215) with `kind` from `collaborator.rs:72-77`; it is counted as reported, same as `(DNS)`, since that is where the literal is produced at runtime. `(SMTP)` is produced by the same code path only if an SMTP interaction is observed; the string literal never appears, so it is counted as **table-only** per the literal rule.
- `Cross-origin resource sharing: arbitrary origin trusted / unencrypted origin trusted / all subdomains trusted` are reported through the `kb_name()` match arms (burp_checks.rs:246-248), not a bare `mk_burp` literal; they are counted as reported because `Cors::run` (scan_checks.rs:2304) passes `f.kind.kb_name()` into `mk`.
