# R-13 dynamic DOM coverage matrix (2026-11-23)

Scope of the landed runtime: one instrumented headless-Chromium probe per
URL per scan run, shared by every DOM family check through the run-owned
`ScanDedup.dom_hits` cache. This matrix is the acceptance boundary: only
the cells marked **covered** are proved by live-browser lab tests. Eight
families wrapped is not blanket DOM analysis; everything below the line is
explicitly not established.

## Source

One navigation carries two distinct run-owned tokens: the query-string
payload `__proto__[tok_s]=tok_s` and the fragment payload
`__proto__[tok_h]=tok_h`. A hit is attributed by which token the
recorded evidence contains; a transformed value that loses the tokens is
not reported.

| Source | Status | Confidence mapping |
| --- | --- | --- |
| `location.hash` (fragment token) | **covered** - labs prove detection and attribution per family | the family's burp.Zwf8 mapping (Firm for the wrapped families, Tentative for open redirection) |
| `location.search` (query token) | **covered** - same sinks, proved by the provenance lab | Tentative: the Zwf8 mapping is established for the hash source only, so search provenance is reported conservatively |
| both tokens in one value | **covered** | Tentative (mixed provenance) |
| token present but part not attributable (single-token probe) | reported as source `unknown` | Tentative (inconclusive, never guessed) |
| `document.URL`, `document.referrer`, `window.name`, `localStorage`/`sessionStorage` reads, `postMessage` | not covered - no instrumentation emits them as sources | - |

## Families and sinks (burp.Zcwh dynamic decoder, docs/specs/R-13 section 6)

| Family (issue) | KB | Severity | Confidence | Wrapped sinks (covered) | Known uncovered sinks |
| --- | --- | --- | --- | --- | --- |
| Cross-site scripting (DOM-based) | 00200310 | High | Firm | `document.write`, `document.writeln`, `element.innerHTML`, `element.outerHTML`, `element.insertAdjacentHTML` | jQuery groups, custom setters |
| JavaScript injection (DOM-based) | 00200320 | High | Firm | `eval`, `Function`, string handlers of `setTimeout`/`setInterval` | `execScript` (gone from Chromium), `javascript:` URLs (not wrappable) |
| Open redirection (DOM-based) | 00500110 | Low | Tentative | `window.open` | `location.href/assign/replace/host/hostname/protocol` - LegacyUnforgeable in Chromium, cannot be wrapped |
| Cookie manipulation (DOM-based) | 00500b00 | Low | Firm | `document.cookie` setter | - |
| HTML5 storage manipulation (DOM-based) | 00500f00 | Information | Firm | `localStorage.setItem` name and value, `sessionStorage.setItem` name and value | - |
| Client-side JSON injection (DOM-based) | 00200370 | Low | Firm | `JSON.parse` | - |
| Client-side XPath injection (DOM-based) | 00200360 | Low | Firm | `document.evaluate` | `jQuery.parseXML` |
| Document domain manipulation (DOM-based) | 00501100 | Medium | Firm | `document.domain` setter | - |
| Client-side SQL injection (DOM-based) | - | - | - | not ported | `webdatabase.executeSql`: `openDatabase` is gone from current Chromium |

Generic `storage.setItem.*` hits (a Storage object that is neither the
local nor the session area) are recorded but reported by no family.

## Runtime guarantees (tested)

- One browser probe per URL per run; all families read the same result
  (`dom_families_share_one_probe_and_refresh_on_the_next_run`: 8 issues,
  1 baseline + 1 DOM navigation; a fresh run re-probes).
- Source provenance: `dom_source_provenance_matrix_against_a_live_lab`
  proves hash-only (Firm), search-only (Tentative), mixed (Tentative),
  and the negatives: reflected token without a sink, a pre-existing
  unrelated Object.prototype property, and a benign page.
- `dom_probe_tokens_are_distinct_and_substituted` pins the two-token
  substitution (drift test).
- Budgets: at most `DOM_MAX_CONCURRENT_BROWSERS` (2) live Chromium
  instances per run and `DOM_MAX_PROBES_PER_RUN` (100) navigations; over
  budget fails closed (no browser, no hits). Unit-tested in
  webprobe-support (`dedup::tests`).
- Per-probe request budget: `DOM_MAX_REQUESTS_PER_PROBE` (64) same-origin
  GET/HEAD through the scanner transport; everything else fails closed
  (`dom_route_tests`).
- Egress isolation: Fetch interception answers every page request; a
  dead-loopback `--proxy-server` removes the route for anything that
  bypasses interception (speculative preconnect/prefetch, background
  services); DNS confined by `--host-resolver-rules`; WebSocket URLs
  blocked; service workers bypassed; WebRTC non-proxied UDP disabled;
  `--dns-prefetch-disable --no-pings`.
- Evidence caps: 50 hits per page, 300 chars per recorded value, 500 chars
  page URL (instrumentation), 4 MiB fulfilled body, 32 KiB fulfilled
  response headers (`crawl.rs` constants).
- Hits kept only on the exact probed origin; one report per sink
  (burp.Zwf8.identityOf merge rule).
- Sink-set drift: `dom_sink_sets_match_the_instrumentation` and
  `dom_family_sinks_are_wrapped` pin the JS literal sink names to the
  Rust family tables.

## Instrumentation caveats (detection limits, by design)

- JavaScript wrappers are not engine hooks: `eval` becomes indirect/global,
  so page code relying on direct-eval local scope behaves differently under
  the probe (Burp patches Chromium; documented gap).
- A canary reaching a sink proves data flow, not an exploitable breakout.
- Only GET history entries with executable HTML baselines are probed;
  inert HTML is skipped.
