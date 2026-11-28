# R-16: compiled Java batch evaluator

## Status

This file describes the evaluator backend. The next milestone adds a library/editor and explicit preview, documented in [R-16-bambda-library-preview.md](R-16-bambda-library-preview.md). Table application landed 2026-11-28 (#253): `Program::apply` and `Outcome::interpret` fold one batch into a filter verdict or a custom-column cell per row, and `webprobe_core::bambda_rows` builds the bounded per-table snapshots. Automatic execution on new traffic is still not implemented: a table run is explicit and covers the newest 200 rows.

## Contract

PortSwigger documents Java snippets, not JavaScript:

- Filter: `boolean evaluate(ProxyHttpRequestResponse requestResponse, Utilities utilities)`.
- Custom column: `Object evaluate(ProxyHttpRequestResponse requestResponse, Utilities utilities)`.

`webprobe_core::bambda::Program::compile` wraps the snippet, compiles it with a real JDK against the supplied Montoya API jar and WebProbe's existing bridge, and returns javac diagnostics on failure. Annotation processing is disabled. Compilation does not evaluate the snippet. The same compiled program can evaluate multiple snapshots.

`Program::evaluate` starts a fresh JVM per batch and returns one `RowResult` per input, in input order. Booleans, finite numbers and null retain their JSON types; other column objects become strings. A row exception is reported for that row and does not stop later rows. A process failure, incomplete result set, deadline or output limit fails the entire batch instead of returning a partial table.

The input explicitly contains host, port, TLS flag, row id, raw request bytes and an optional raw response. Byte arrays are not converted through UTF-8. Row ids cross the wire as decimal strings to avoid the existing bridge JSON parser's floating-point number precision limit. The Montoya `id()` accessor is an int and reports an error when the recorded id does not fit it.

Missing metadata is not invented. In particular, this milestone does not claim original-versus-final request/response, annotations, listener port, timing or MIME classification. Unsupported bridge calls fail as row errors. Other Montoya methods retain the existing bridge's coverage and limitations.

The documented redirect/session-cookie filter exposed a missing `HttpResponse.hasCookie` implementation. That prerequisite is kept in its own commit. String lookup is case-sensitive on cookie names and ignores malformed Set-Cookie headers. Cookie-object lookup compares name, value, domain and path; expiration is not compared in this initial bridge implementation.

## Runtime and safety

Use a JDK 17 or newer and a compatible Montoya API jar. Tested with Temurin JDK 21 and Montoya API 2026.7.

Scripts are trusted local Java code. The JVM can access the user's files and network. This is not a security sandbox, and a UI must explain that before executing imported code. Do not execute a downloaded script automatically.

Call compilation/evaluation from a worker, never from an egui frame or proxy callback. A JVM has a 256 MiB heap cap; each stdout/stderr stream is capped at 8 MiB, source at 128 KiB, batches at 10,000 rows and JSON input at 16 MiB. The aggregate raw request/response/host cap is 1 MiB, reduced from the initial 4 MiB proposal to leave room for the JSON parser and message copies inside the 256 MiB heap. A real-JVM regression evaluates a near-cap batch of 0xFF bytes (worst-case four-character JSON byte tokens) under that heap cap and rejects an over-cap batch before launch. Column strings are capped at 65,536 characters; row error messages at 4,096 characters. Compilation and evaluation take separate explicit process deadlines. The evaluation deadline is per batch, across all rows, not per row. A slow row can exhaust the whole batch deadline; in that case the entire batch fails with Timeout and no partial results are returned. Bounded serialization and temporary-file writing occur before the JVM deadline starts. On Unix, cleanup stops the process group; other platforms also kill the direct child. Temporary source/classes/input live under owner-only directories on Unix and are removed when their owner drops.

A heap cap does not bound native allocations or all effects of trusted Java code. A program that deliberately escapes its process group can outlive Unix group cleanup. Windows descendant-process cleanup has not been verified.

## Verification

Run the ordinary workspace gates, then the opt-in live-JVM suite:

```sh
cd app
cargo test --workspace --locked --no-run
cargo test --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
WEBPROBE_BAMBDA_TEST_JAVA=/path/to/jdk/bin/java \
WEBPROBE_BAMBDA_TEST_API=/path/to/montoya-api.jar \
cargo test -p webprobe-core --test bambda --locked -- --ignored --test-threads=2
```

The live-JVM tests are explicitly ignored by the ordinary suite, not silently passed when prerequisites are missing. They fail if explicitly requested without the required paths. CI has a separate job that supplies both prerequisites and runs them.

Coverage: documented filter and column examples, pending responses, Java compile/type diagnostics, Utilities, row-level errors, accidental stdout, execution timeout and reuse, exact large ids, binary bodies, cookie overloads, and bounded runaway output. Red tests first exposed the missing module, missing cookie method, and large-id precision defect.

## Sources

Official PortSwigger pages, both read November 22, 2026; pages last updated November 17, 2026:

- https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history/scripts
- https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history/custom-columns

API method signatures were checked against the Maven Central Montoya API 2026.7 jar and its source archive. No claim of complete Montoya or Bambda API coverage is made.

## S-03: passive scan checks (2026-11-28)

A Bambda with function `SCAN_CHECK_PASSIVE_PER_REQUEST` is a passive scan
check. Its body sees `requestResponse` and `utilities` and returns an
`AuditResult` (or `null` for nothing found). `AuditResult`, `AuditIssue`,
`AuditIssueSeverity`, `AuditIssueConfidence`, `List` and `ArrayList` are
imported. Each issue is reported as Burp's type "Bambda generated issue"
(`0x09008000`) on the exchange it was raised for; the script's own issue name
heads the detail and keeps two findings on one location apart.

Where it runs:

- Desktop: Bambda library, "New passive scan check", then "Run check on HTTP
  history and report issues" (newest 200 exchanges).
- `webprobe-headless proxy --bambda-check FILE`: every recorded exchange.
- `webprobe-headless scan URL --bambda-check FILE`: every exchange the scan
  recorded, after the audit ends.

Not done: active (per insertion point) checks, running a saved check
automatically during a desktop scan or live audit, and the `api` variable Burp
gives a scan-check Bambda.
