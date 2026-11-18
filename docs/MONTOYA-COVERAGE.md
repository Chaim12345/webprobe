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
| burpSuite | partial | export / import of project and user options, `shutdown`; setting the task engine state is recorded only |
| collaborator | full | custom-data payloads |
| comparer | full | |
| decoder | full | |
| extension | full | |
| http | partial | response keyword / variation analyzers; `HttpMode` and `RequestOptions` are ignored |
| intruder | full | generator sees the first position's base value for every position; copy-other and recursive-grep sets are not processed; `sendToIntruder` replaces the current request and ignores the tab name |
| logging | full | |
| organizer | partial | status is always NEW |
| persistence | full | |
| project | unsupported | |
| proxy | full | WebSocket `send*` / `close`; "to be sent" WebSocket handlers run before the user's intercept edit (Burp: after) |
| repeater | full | |
| scanner | partial | `startAudit`, `startCrawl`, `generateReport`, `registerAuditIssueHandler`, `bChecks` |
| scope | full | the change handler fires only for changes made through the API |
| siteMap | full | |
| userInterface | partial | `registerHotKeyHandler`; WebSocket message editors are accepted but not shown; Swing shows in the extension's own window, not inside WebProbe's |
| utilities | partial | `rankingUtils`, `shellUtils`, Brotli |
| websockets | partial | `createWebSocket` |

Session handling: extension actions are available as the rule action "invoke extension"; they receive
an empty macro list.

## Unmodified BApps checked on the QA display (screenshots in `qa/r03-2026-11-18/`)

| BApp | Result |
|---|---|
| JWT Monitor 1.1.1 | Loads; with a JWT entered in its window, proxied requests get the Authorization header replaced |
| JSON Web Tokens (JWT4B) | Loads; suite tab, context menu, editor tab and history notes work; a payload edit comes back into Repeater |
| JWT Editor 2.6.2 | Loads; Keys tab works (key created), editor tab shows the token, a token signed in the editor comes back into Repeater, its Intruder payload processor is listed |
| MCP Server | Loads with no unsupported call and listens on 127.0.0.1:9876; its tools were not exercised |

The sample is four BApps, three of them JWT tools. Other BApps may hit the unsupported calls above.
