# Operational diagnostics

Operational events go to stderr through tracing. Both executables install a subscriber, without replacing a subscriber already installed by an embedding application. Only WebProbe diagnostic targets are enabled. Headless CLI issue JSON remains on stdout.

Stable event codes identify operations such as `scan.started`, `scan.failed`, `crawl.finished`, `tls.ca.save_failed` and `oast.poll.received`. Set `WB_TRACE` or `WB_INTERACTSH_DEBUG` to include debug-level timing and OAST size/status events. Those modes no longer print request lines or OAST response bodies.

Use `diagnostics::emit` for standalone operations or `Shared::event` for events also needed in the UI. Supply a static event code and message. Context accepts only counts, flags and static labels. Do not attach raw requests, responses, URLs, headers, cookie values, authentication material, exception strings or extension text. Add a new safe categorical label or count instead.

The HTTP Logger is a separate, deliberate traffic capture tool. This policy does not remove its request/response capture. The legacy `Shared::log` API is UI-only and may contain traffic or arbitrary extension text. It is not exported to the diagnostic subscriber. Migrating those remaining UI callers requires explicit safe event fields, never forwarding their formatted strings wholesale.

A panic's location is diagnostic metadata; its arbitrary payload is omitted from stderr. The existing in-app panic notice remains local to preserve the containment policy.
