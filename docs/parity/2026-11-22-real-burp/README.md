# Real Burp / WebProbe parity check

Date: 2026-11-22. All HTTP test traffic used loopback only.

## Result

The measured WebProbe build passes the basic proxy, Repeater, Intruder, Base64 Decoder, and byte Comparer fixtures. It is not equivalent to Burp in the measured extension and Sequencer paths. The largest observed gaps are the constant-token Sequencer result, missing Repeater HTTP-handler dispatch, keyword case handling, and unsupported response-variation analysis.

This is a bounded comparison, not certification of full Burp parity. No application code is changed by this report.

## Exact baseline

| Component | Measured version |
| --- | --- |
| Burp | Community Edition 2026.11.2, official executable JAR, temporary project |
| WebProbe | PR #99 head `cc7407d579046da45c84b7f2beb69982b3b388e5` |
| Report branch base | `parity/2026-11-17` at `7be2efd` when created |
| Java | Local JDK 25 for the running applications |
| Craft Anything | Official v0.6.1 Linux release; actual MCP stdio interface used |
| Fixture | HTTP server at `127.0.0.1:18765`; proxies at `127.0.0.1:18080` and `127.0.0.1:18081` |

The executable tested is the R-20 PR build, **not** a merge of every roadmap PR or the current parity branch. A gap here may be fixed elsewhere; that has not been established by this run. The report branch contains evidence only and does not pull PR #99's implementation changes into parity.

Burp's terms were accepted with approval. No PortSwigger account, license key, purchase, or login was used. Neither the vendor JAR nor the extracted API subset is included in this repository or uploaded with this report.

## Parity table

`Works` means the stated fixture passed in both. `Differs` means a measured behavior differs. `Missing` means the tested WebProbe entry point explicitly reports that capability unsupported. It does not imply an exhaustive absence across the product.

| Area / fixture | Status | Real Burp result | Measured WebProbe result | Evidence |
| --- | --- | --- | --- | --- |
| Proxy HTTP history and forwarding | Works | GET reached origin; JSON 200 recorded | Same; response body byte-identical | [01](screenshots/01-proxy.png), `evidence/proxy-*.body` |
| Montoya HTTP handler on proxy traffic | Works | Adds `X-Parity-Probe: 1` | Same | Echoed header is `1` in both proxy bodies |
| Repeater send | Works | Same manually entered request returns 200 | Same | [02](screenshots/02-repeater.png) |
| Montoya HTTP handler on Repeater traffic | Differs | Registered handler adds the probe header | Header absent from origin echo | [02](screenshots/02-repeater.png) |
| Intruder Sniper, one insertion point, simple list `one`, `two` | Works | Both payload requests return 200 | Both return 200 | [05](screenshots/05-intruder.png) |
| Intruder baseline request | Differs | Sends baseline plus two payload requests | Two payload requests only | [05](screenshots/05-intruder.png) |
| Decoder Base64 | Works | `SGVsbG8=` becomes `Hello` | Same | [03](screenshots/03-decoder.png) |
| Comparer byte difference | Works | `alpha` vs `alpHa`: one changed byte, hex `68` to `48` | Same | [04](screenshots/04-comparer.png) |
| Sequencer manual-load constant tokens | Differs | Extremely poor; effective entropy 0 bits at 1% significance | Character entropy 4.3219 bits/char; total entropy 88,513.09 bits; no equivalent overall result displayed | [06](screenshots/06-sequencer.png), `evidence/tokens.txt` |
| Sequencer bit-level path after manual load | Differs | Shows effective-entropy analysis | Says at least 100 non-empty tokens are needed, despite displaying 1,024 tokens of length 20 | [06](screenshots/06-sequencer.png) |
| Same custom Montoya extension loads and populates tools | Works | Loads, sends a direct HTTP request, populates Repeater/Intruder/Decoder/Comparer | Same | [07](screenshots/07-montoya.png), probe logs and source |
| Keyword analyzer case behavior | Differs | Both `token` and `TOKEN` become variant after lowercase count changes | Only `token` becomes variant | Probe logs |
| Empty keyword accepted | Differs | Analyzer construction succeeds | `IllegalArgumentException` | Probe logs |
| Response variations analyzer | Missing | Factory returns an object | `UnsupportedOperationException` | Probe logs |
| Existing repository demo extension, request/response mutation | Works | Origin sees demo header `1`; client sees `X-Montoya-Seen: 1` | Same | [08](screenshots/08-demo-extension.png), `evidence/demo-*` |
| Existing demo extension, dropped request | Differs | Origin not contacted; client receives HTTP 200 HTML error page | Origin not contacted; client gets empty reply, curl exit 52 | `evidence/drop-summary.json` |

## Details that affect interpretation

### Proxy and Repeater

The custom probe registers an HTTP request handler that adds `X-Parity-Probe: 1`. A GET through each proxy produced exactly the same JSON body, including the echoed header. This verifies actual forwarding and hook mutation, not just matching screen layout.

Repeater was then given the same raw request in each application:

```http
GET /echo?value=repeater HTTP/1.1
Host: 127.0.0.1:18765
Connection: close

```

Both return 200, but the echoed probe header is `1` in Burp and empty in WebProbe. The hook result is therefore a behavior gap even though basic Repeater sending works.

The probe's own `api.http().sendRequest(...)` returns 200 in both, with the probe header absent in both. That direct-extension-send result must not be confused with the different Repeater behavior.

### Intruder

Both applications use the same extension-created URL, insertion range, Sniper mode, and two simple payloads. Burp's URL factory adds browser-style default headers while WebProbe's factory produces a shorter request. Thus these are the same functional input and payloads, not byte-identical generated requests. Burp sends an additional baseline request. The Community edition shows an informational notice about demo functionality and throttling; no Professional behavior is claimed.

No exhaustive payload processor, encoding, resource-pool, or scheduling parity was measured.

### Sequencer

The file contains 1,024 identical lines of `ABCD0123456789abcdef`, not random samples. Both applications load the same file. Burp reports zero effective entropy at 1% significance and an extremely poor result.

WebProbe displays one unique token, but also 4.3219 bits/character and 88,513.09 total entropy bits. These are pooled-character statistics, not an equivalent estimate of token unpredictability. The screenshot also records the contradictory minimum-sample message in the bit-level path. Do not use the displayed character entropy as evidence that a token generator is random.

This run tested manual loading, not live capture or all significance levels. The source tree contains bit-level analysis code; the finding is that this manual-load workflow did not produce it successfully, not that no such code exists.

### Keyword analysis

The same probe feeds three synthetic responses to an analyzer initialized with `token`, `TOKEN`, `absent`, and `X-Flag`:

1. Header present; body `token token TOKEN`.
2. Header present; body `token TOKEN`.
3. Header removed; body restored to `token token TOKEN`.

After step 2, Burp marks both spellings variant; WebProbe marks only lowercase `token` variant. After step 3, Burp's variant set is `TOKEN, X-Flag, token`; WebProbe's is `X-Flag, token`. This supports case-insensitive matching in Burp for this ASCII fixture versus case-sensitive matching in the tested WebProbe implementation. Unicode and locale behavior were not measured.

Both start with empty sets. After one response all configured terms, including absent terms, are invariant. Both treat `aa` as invariant across `aaaa` and `aaaaa`, consistent with non-overlapping counting for this fixture. Neither observation fixes the case mismatch.

### Existing demo extension

The unchanged `app/sidecar/demo-ext/demo-ext.jar` from the measured checkout was loaded into both applications, in addition to the custom probe. Its request mutation and response mutation work in both. A second fixture variant adds the demo request header to the origin echo for direct confirmation.

For `/admin-drop`, neither request reached the origin. The client-facing drop behavior differs as listed above. Burp's HTTP 200 is its local error page, not a successful origin response.

## Craft Anything: actual MCP use

The release checksum was verified before use. Craft ran with a private writable investigation directory, read-only input mounts, an empty environment, and no network access. No credentials, repository checkout, or account session was exposed to it.

The full vendor JAR is 768,535,248 bytes (about 733 MiB) and contains 64,993 ZIP entries, including 58,303 raw `.class` entries. Two initial full-archive CLI inspection attempts ended with exit 137 while the GUI applications were also resident. The environment's memory ceiling was 1,944,928,256 bytes.

The full archive subsequently succeeded through MCP after the GUI processes were stopped and the native parser was bounded. The successful run used a 1,900,000,000-byte address-space ceiling, a 1 MiB main-thread stack, `MALLOC_ARENA_MAX=1`, `TOKIO_WORKER_THREADS=1`, and `RUST_MIN_STACK=262144`. Lower 1.7 GB and 1.85 GB ceilings returned allocation failures rather than a kernel OOM kill. The successful run sampled a peak RSS of 1,496,676 KiB (about 1.43 GiB) and completed in about 1.3 seconds. The MCP server was intentionally stopped after its successful response.

Craft's built-in parser is native Rust, not Java. JVM flags alone cannot limit it. Burp's initial JVM was capped at `-Xmx768m`; after evidence capture it was restarted with `-Xmx384m -Xss256k`, and WebProbe's Java extension launcher was bounded with `-Xmx128m -Xss256k`. WebProbe itself is native. The parity screenshots record the earlier measured sessions, not a repeat of every workflow after restarting.

Before that successful full-archive retry, a local archive of 282 unmodified Montoya API class entries was extracted for bounded inspection. It is not redistributed. The actual MCP server was initialized, its tool list discovered, and these calls completed:

| MCP call | Returned result |
| --- | --- |
| `core_target_open` | Recognized the 173,991-byte subset as a Java archive |
| `java_archive_show` on API subset | 282 classes, 52 packages, all class files Java 17; complete coverage of this subset only |
| `java_archive_show` on full vendor JAR | 64,993 entries; 58,021 non-package-info classes in 1,719 packages; 35 nested JARs, 33 native libraries, 4,571 resources; main class `burp.StartBurp` |
| `java_class_show` on `ResponseKeywordsAnalyzer` | Three abstract methods: update, variant set, invariant set |
| `java_class_show` on `HttpHandler` | Two abstract request/response handler methods |
| `core_brief_write` and `core_finding_record` | Stored the scoped question and one evidence-backed subset finding |
| `core_report_write` | Wrote a bounded static report with three evidence records and one finding |

Evidence IDs, memory measurements, and input hashes are in `evidence/manifest.json`. The full archive call inventories every ZIP entry but samples class-file versions from at most 512 classes. Its class total excludes `package-info.class`, explaining the difference from the raw ZIP class count. It does not decompile or establish the behavior of every implementation method. The static interface facts do not determine case sensitivity or hook dispatch. Those conclusions come from the runtime comparison above. No AI service, MCP network endpoint, or external decompiler was required.

## Evidence and reproduction

All numbered screenshots are original side-by-side captures, WebProbe left and Burp right. Each was visually inspected. The custom probe source, fixture source, output logs, constant-token file, response bodies, selected HTTP headers, and a hash manifest are under `evidence/`. Saved header text is normalized from CRLF to LF for the report; bodies are unchanged.

To repeat within a local temporary project:

1. Obtain the official Burp version separately; do not add it to git.
2. Build the stated WebProbe commit and configure distinct loopback proxy ports.
3. Start `evidence/fixture.py`; compile `evidence/ParityProbe.java` against the local Burp JAR, package it as a Montoya extension, and load that same extension JAR into both applications.
4. Send GET `/echo?value=identical` through each proxy. In Repeater, enter the raw request above with real CRLF or line breaks and send it.
5. In Intruder use the populated insertion point and add `one`, `two`; run a Sniper attack. Decode the populated Base64 input and byte-compare the two populated strings.
6. Load `evidence/tokens.txt` into each Sequencer and analyze.
7. For the existing demo extension test, switch the server to `evidence/fixture-demo.py`, load the same existing repository demo JAR into both apps, then request `/echo?value=demo` and `/admin-drop` through each proxy.

The first automated Repeater text entry lost newlines in WebProbe and caused a malformed request. It was corrected with explicit Return events before the recorded comparison. That automation artifact is excluded from product findings.

## Follow-up order

1. Fix or isolate the Sequencer manual-load bit-level path and make the entropy labels unambiguous.
2. Route Repeater through the expected Montoya HTTP-handler pipeline, then add a real-Burp-backed regression fixture.
3. Match keyword case and empty-term behavior, with edge-case tests before claiming compatibility.
4. Fill the tested response-variation factory gap or document it explicitly as unsupported.
5. Decide whether baseline Intruder requests and client-facing proxy-drop behavior should match Burp exactly.

These are recommendations, not implementation changes in this PR. Repeat against the final merged roadmap build before closing any parity claim.

## Sources

- Official Community download: https://portswigger.net/burp/communitydownload
- Official release: https://portswigger.net/burp/releases/professional-community-2026-11-2
- Official downloads: https://portswigger.net/burp/downloads
- Craft Anything source and documented MCP entry point: https://github.com/storytold/craft-anything
- Craft Anything v0.6.1 release: https://github.com/storytold/craft-anything/releases/tag/v0.6.1
- Measured WebProbe implementation PR: https://github.com/Chaim12345/webprobe/pull/99

The runtime findings are primary local observations, not claims copied from these vendor pages. This report is intentionally bounded to the tested version and fixtures.
