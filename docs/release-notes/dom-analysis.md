# Dynamic DOM checks

Fourteen DOM families share one instrumented Chromium visit per URL in a scan run. Production currently reports the plain (DOM-based) or reflected (reflected DOM-based) variant per hit. Stored-variant classification remains in the testable code path, but is disabled in production: the scanner supplies an empty stored token and sends no stored submission because authenticated payloads can mutate server-side state. A hit holding the query token present in script text of the exact navigation response fulfilled to Chromium is the reflected variant; anything else is the plain variant. Only GET history entries with HTML baselines containing a script tag, inline event handler or javascript: URL are visited. Inert HTML is skipped. A fresh standalone scan or outer batch clears the cache, and crawl runs get a new cache by construction. No process-global result cache is used.

Chromium use is bounded per run: at most 2 concurrent browsers and 100 navigations (DOM_MAX_CONCURRENT_BROWSERS / DOM_MAX_PROBES_PER_RUN in webprobe-support). Over budget the DOM checks fail closed: no browser is launched and no hits are reported. Each admitted operation forwards at most 64 same-origin GET/HEAD browser requests. The baseline is outside this operation; no stored-token submission is sent. A simple page needs two requests including baseline; there is no reflected re-request. Each forwarded request accepts at most 128 DevTools-intercepted header entries; up to 3 fixed fields (Host, Connection, Accept-Encoding) plus up to 4 missing template fields (Cookie, Authorization, User-Agent, Accept-Language) are then appended, so an emitted request can carry up to 135 header lines. The assembled request is capped at 64 KiB before it enters the scanner transport; session rules may alter it afterwards, so this is not a final on-the-wire size. Admission includes budget, browser slot, successful startup and DevTools setup before navigation; cancellation or an incomplete navigation response stops further traffic without retry.

All intercepted HTTP requests use the scanner transport, including its configured upstream route, cookie jar, session rules and pause handling. Only exact same-origin GET/HEAD requests are allowed. Recorded Cookie/Authorization headers are supplied when the browser has not already supplied them. Responses are normalized before delivery to Chromium, with a 4 MiB body cap and a 32 KiB response-header cap. No arbitrary POSTs, form submissions or off-origin requests are forwarded.

Nothing leaves Chromium's own network stack: on top of Fetch interception, the browser's proxy is a closed loopback port, so traffic that bypasses interception (speculative preconnect/prefetch, background services) has no route out. Workers and off-origin frames/connections are restricted by an added CSP. Service workers are bypassed; WebSocket URLs are blocked, non-proxied WebRTC UDP is disabled, DNS prefetch and hyperlink pings are off. These restrictions can change application behavior and miss findings. Chromium is launched with a fresh temporary profile, not the user's browser profile, and it is removed when the probe ends. Only hits on the exact probed origin are retained.

The instrumentation records a canary reaching a wrapped sink, with two distinct run-owned tokens per navigation: one in the query string and one in the fragment. A hit's active source attribution is based on which URL token the recorded evidence contains (location.hash, location.search, both, or unknown when a single-token probe cannot attribute; never guessed). Stored-token attribution remains a fixture-only path until an explicit safe opt-in is designed. The burp.Zwf8 confidence mapping is established for the location.hash source only; search, mixed and unknown provenance are reported as Tentative. Recorded values are capped (50 hits per page, 300 chars per value). This establishes data flow, not necessarily an exploitable breakout. JavaScript wrappers are not engine hooks: eval becomes indirect/global, popups are swallowed with a stub handle, and Location's non-configurable setters are not covered. Storage, cookie and document-domain setters can mutate the temporary browser profile, which is discarded. Existing page JS may make GET requests with application effects, as in any active scan.

Requires an available Chromium binary. The family labs, source-provenance matrix, reflected-variant and cache-refresh labs have been exercised with an actual browser. Stored-variant classification is exercised only by fixtures; production does not submit a stored token. Broader application compatibility is not established.

Coverage boundary: docs/specs/R-13-dom-coverage-matrix.md lists the proved source/sink/family cells and the known gaps. Fourteen wrapped families is not blanket DOM analysis.

Variant labels describe token observations, not proven storage mechanisms or JavaScript string-literal origins. Response/sink co-occurrence does not prove the sink read that response text. The reflected variant is Tentative; stored classification is not enabled in production. Failed/unknown outcomes are logged and cached for this run, not treated as successful clean probes.

Submission acknowledgement requires a complete, strictly self-delimited final
2xx-5xx response. Short Content-Length bodies, incomplete chunked bodies,
interim-only responses and EOF-delimited responses without a reliable
completion signal remain unknown, with no replay or navigation.
Retained navigation evidence is a fulfilled view reconstructed from actual
status, bounded filtered headers including injected CSP and capped body.
Original upstream headers are not retained. Response completeness is checked
before normalization; unconfirmed navigation evidence is withheld.
Cancellation/evaluation failure retains a previously confirmed bounded hit
snapshot, with explicit incomplete/cancelled status and diagnostic in the
scan record and Scanner UI. Missing source/provenance or missing confirmed
navigation evidence is withheld. Stop prevents new sends but does not
interrupt synchronous in-flight transport I/O; no latency bound is claimed.
## Client-side prototype pollution addition

A fifteenth family shares the same browser operation: client-side prototype
pollution (KB 00200316, Information). It observes new own properties on
Object.prototype whose key or value carries a dedicated run-owned query or
fragment token. Hash-only evidence is Firm; query or mixed evidence is
Tentative. Findings use the base pollution name only, never reflected/stored
pollution variants. A reflected string without new own-key evidence is not
pollution.

Coverage is addition-only. Existing-property overwrites and stored pollution
are not covered. No generic stored-submission token is generated or sent in production. Pollution evidence is limited to the query and fragment tokens.
Polling can miss short-lived additions. The loopback labs use inert random
tokens and temporary browser profiles. A combined fixture proves independent
query/hash pollution alongside stored DOM-XSS, source/family dedup, negative
cases, a shared two-request simple-page count, and the shared 64-intercepted-request
operation cap (plus baseline).
