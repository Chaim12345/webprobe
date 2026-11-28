# Montoya API coverage (2026-11-18)

Burp extensions (`.jar`, Montoya API) run in a sidecar JVM (`app/sidecar/*.java`, host side
`app/core/src/ext_host.rs` and `ext_calls.rs`). A call WebProbe does not support throws
`UnsupportedOperationException("<Interface>.<method> is not supported by WebProbe")` and is logged
once in the extension's Errors pane.

Requirements: a JDK 17 or later, and the Montoya API jar, which the user supplies (found in `~/.m2`,
a Burp install, or `WEBPROBE_BURP_JAR`). Its POM names the Burp Suite Professional Licence Agreement,
so WebProbe does not ship it.

| `MontoyaApi` accessor | State | Missing |
|---|---|---|
| ai | partial | `isEnabled` returns false; `prompt` unsupported |
| bambda | unsupported | |
| burpSuite | partial | `exportProjectOptionsAsJson` returns only the proxy listener and the HTTP/2 switch (other paths come back empty); import of project options, user options and `shutdown` are unsupported; setting the task engine state is recorded only |
| collaborator | full | custom-data payloads |
| comparer | full | |
| decoder | full | |
| extension | full | |
| http | partial | response variation analyzer; `HttpMode` and `RequestOptions` are ignored |
| intruder | full | generator sees the first position's base value for every position; copy-other and recursive-grep sets are not processed; `sendToIntruder` replaces the current request and ignores the tab name |
| logging | full | |
| organizer | full | |
| persistence | full | |
| project | partial | `name` is fixed and `id` is new for each session: the sidecar is not told which project is open |
| proxy | full | a message an extension sends over a proxied WebSocket is written as given: it is not shown to message handlers, the intercept or WebSockets history |
| repeater | full | |
| scanner | partial | `startAudit`, `startCrawl`, `bChecks`; `generateReport` writes the issues it is given without their requests and responses; an audit issue handler hears of a new issue within about a second (the issue list is polled) |
| scope | full | the change handler fires only for changes made through the API |
| siteMap | full | |
| userInterface | partial | `registerHotKeyHandler` is accepted but the hotkey is never bound, so it does not fire; WebSocket message editors are accepted but not shown; Swing shows in the extension's own window, not inside WebProbe's |
| utilities | partial | `rankingUtils`, `shellUtils`, Brotli |
| websockets | partial | `createWebSocket` connects from the sidecar itself: not through WebProbe's upstream proxy settings, not listed in WebSockets history, and `upgradeResponse` is empty |

Session handling: extension actions are available as the rule action "invoke extension"; they receive
an empty macro list.

Proxy WebSocket handlers run in Burp's order: "received" handlers before interception (their verdict
can force or skip it), "to be sent" handlers after the user's edit. Calls into an extension's JVM
(payload generation and processing, context-menu items, extension editors) never run on the UI thread.

## Unmodified BApps checked on the QA display (screenshots in `qa/r03-2026-11-18/`)

| BApp | Result |
|---|---|
| JWT Monitor 1.1.1 | Loads; with a JWT entered in its window, proxied requests get the Authorization header replaced |
| JSON Web Tokens (JWT4B) | Loads; suite tab, context menu, editor tab and history notes work; a payload edit comes back into Repeater |
| JWT Editor 2.6.2 | Loads; Keys tab works (key created), editor tab shows the token, a token signed in the editor comes back into Repeater, its Intruder payload processor is listed |
| MCP Server | Loads with no unsupported call and listens on 127.0.0.1:9876; its tools were not exercised |

The sample is four BApps, three of them JWT tools. Other BApps may hit the unsupported calls above.

## Static survey of 13 more BApps (2026-11-28)

Not a load test. Each BApp was downloaded from the BApp Store and its bytecode read with `javap` for
the Montoya interface methods it references (`scripts/bapp_montoya_survey.py` does the same for one
jar). Nothing was run, so this says which unsupported calls a BApp can reach, not whether it loads or
works. Loading them unmodified is still to do.

| BApp (store version) | `MontoyaApi` accessors used | Unsupported calls it references |
|---|---|---|
| Reshaper (28) | comparer decoder extension http intruder logging organizer persistence proxy repeater scope siteMap userInterface utilities websockets | WebSocket `sendTextMessage` / `sendBinaryMessage` (proxy and created sockets) |
| Hackvertor (68) | ai burpSuite http intruder logging persistence repeater userInterface utilities websockets | `ai` (reports itself switched off); hotkey registration (accepted, not bound) |
| InQL (27) | burpSuite extension http intruder logging persistence proxy repeater scanner userInterface | `burpSuite().exportProjectOptionsAsJson` |
| Param Miner (39) | burpSuite http logging organizer scope userInterface utilities websockets | `exportProjectOptionsAsJson`, `importProjectOptionsFromJson`, `websockets().createWebSocket`; hotkey registration (accepted, not bound) |
| Turbo Intruder (69) | collaborator http organizer userInterface utilities | `utilities().rankingUtils`; hotkey registration (accepted, not bound) |
| HTTP Request Smuggler (52) | burpSuite http organizer scanner scope siteMap userInterface utilities websockets | `websockets().createWebSocket` |
| Stepper (10) | burpSuite extension http intruder logging persistence project repeater userInterface | none known (`project()` now answers) |
| Backslash Powered Scanner (29) | http organizer scope userInterface utilities websockets | `websockets().createWebSocket` |
| Sharpener (45) | burpSuite extension http logging persistence proxy userInterface | none known |
| WebSocket Turbo Intruder (5) | ai extension logging organizer persistence userInterface websockets | `ai`, `websockets().createWebSocket` |
| SAML Raider (29) | collaborator extension http logging userInterface utilities | none known |
| Collaborator Everywhere (11), Bypass Bot Detection (2) | not read: their classes sit under a package the survey skips | not known |

"None known" means none of the calls listed as missing in the table above; a call missing from that
table would not show here. The most common gap is `websockets().createWebSocket` (4 of 11), then the
options export (2).

## R-20 keyword analysis slice (2026-11-22)

`http().createResponseKeywordsAnalyzer` tracks case-insensitive (Locale.ROOT
folding), non-overlapping keyword counts across the complete response (headers
and body), matching real Burp 2026.11.2 as measured in
docs/parity/2026-11-22-real-burp. Before the first response, both result sets
are empty. The first response seeds invariant keywords, including keywords
with zero occurrences. Once a count changes, that keyword remains variant.
Result sets are immutable snapshots and analyzers do not retain response
bodies. Empty keywords are accepted, as in Burp; an empty keyword counts
length + 1 positions, so it tracks response length changes.

`http().createResponseVariationsAnalyzer` returns an analyzer over every
Montoya `AttributeType` (the factory previously threw
UnsupportedOperationException; real Burp 2026.11.2 returns an object). The
first response seeds each attribute's extracted value; a later difference
marks the attribute variant permanently. Header, status and body metrics are
direct; HTML-derived attributes come from a small deterministic tag scan.
INITIAL_CONTENT (256 chars) and LIMITED_BODY_CONTENT (4096 chars) prefixes
are WebProbe's documented choices, not measured Burp constants. Body-derived
analysis is limited to the first 1 MiB (1,048,576 bytes), decoded as ISO-8859-1.
Changes beyond that prefix are ignored by body-derived attributes.
CONTENT_LENGTH still compares the complete body byte length. HTML/comment
extraction uses forward-only scans to avoid repeated suffix searches on
hostile bodies. Regression cases include roughly one MiB of repeated comment
openers, malformed quoted tags, and unterminated scripts, each required to
finish within five seconds.

Purpose-built extensions exercise both analyzers through the public Montoya
API, loaded by the real sidecar JVM with JDK 21 and the published Montoya
2026.7 API jar. They check case-insensitive counts, absent keywords, headers,
repeated keywords, empty keywords, independent analyzers, immutable
snapshots, invalid inputs, per-attribute variation and variant persistence.
This establishes WebProbe's behavior against the measured Burp fixture, not
full parity against a running Burp installation. The ten additional
unmodified BApps required by R-20 have not been checked in this slice; R-20
remains open.

`CollaboratorPayload.server()` now returns an empty Optional when
`WITHOUT_SERVER_LOCATION` was requested, matching the API contract. This applies
to both a client and the default payload generator. A second purpose-built
extension checks the default and bare forms, their ids, and independent metadata
with deterministic host-provided payloads. It fails before the fix and passes
after it on JDK 25 with Montoya 2026.7. No live Collaborator server is needed.

CI now sets up Temurin 21, downloads the pinned Montoya 2026.7 jar with a SHA-256
check, and runs both new regressions with `WEBPROBE_REQUIRE_JAVA=1`. When that
variable is set, a missing JDK or API jar fails these tests instead of silently
skipping. For a local required run, set `WEBPROBE_JAVA` and `WEBPROBE_BURP_JAR`
to the JDK's `bin/java` and API jar paths, then run:

```
WEBPROBE_REQUIRE_JAVA=1 cargo test -p webprobe-core --locked ext_host::tests::montoya_ -- --test-threads=1
```

The API jar is downloaded only into the runner's temporary directory, not
vendored or shipped in WebProbe. The older checked-in demo extension jar needs
Java 25; the two new regressions compile from source and work on Java 21.
