# Dynamic DOM checks

Eight DOM families share one instrumented Chromium visit per URL in a scan run. Only GET history entries with HTML baselines containing a script tag, inline event handler or javascript: URL are visited. Inert HTML is skipped. A fresh standalone scan or outer batch clears the cache, and crawl runs get a new cache by construction. No process-global result cache is used.

All intercepted HTTP requests use the scanner transport, including its configured upstream route, cookie jar, session rules and pause handling. Only exact same-origin GET/HEAD requests are allowed, with a 64-request budget per browser probe. Recorded Cookie/Authorization headers are supplied when the browser has not already supplied them. Responses are normalized before delivery to Chromium. No arbitrary POSTs, form submissions or off-origin requests are forwarded.

Workers and off-origin frames/connections are restricted by an added CSP. Service workers are bypassed; WebSocket URLs are blocked and non-proxied WebRTC UDP is disabled. These restrictions can change application behavior and miss findings. Chromium is launched with a fresh temporary profile, not the user's browser profile, and it is removed when the probe ends. Only hits on the exact probed origin are retained.

The instrumentation records a location.hash canary reaching a wrapped sink. This establishes data flow, not necessarily an exploitable breakout. JavaScript wrappers are not engine hooks: eval becomes indirect/global, popups are swallowed with a stub handle, and Location's non-configurable setters are not covered. Storage, cookie and document-domain setters can mutate the temporary browser profile, which is discarded. Existing page JS may make GET requests with application effects, as in any active scan.

Requires an available Chromium binary. The three original family labs and the cache-refresh lab have been exercised with an actual browser; broader application compatibility is not established.
