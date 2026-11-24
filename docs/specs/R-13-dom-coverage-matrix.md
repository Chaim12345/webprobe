# R-13 dynamic DOM coverage matrix (2026-11-23)

Scope of the landed runtime: one instrumented headless-Chromium probe per
URL per scan run, shared by every DOM family check through the run-owned
`ScanDedup.dom_hits` cache. This matrix is the acceptance boundary: only
the cells marked **covered** are proved by live-browser lab tests.
Fourteen wrapped families plus addition-only prototype pollution is not blanket DOM analysis; everything below
the line is explicitly not established.

The lab evidence below was recorded on 2026-11-23 at source pins up to
72382c6. It is a historical record, not a per-candidate guarantee: cells are
not re-executed on every later composition, and the Current inconsistency
section lists what is known to have drifted since.

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
| stored token (submitted in an earlier request, re-embedded by the application) | **not enabled in production** - no stored-token submission is sent; fixture-only classification remains | - |
| `document.URL`, `document.referrer`, `window.name` reads, `localStorage`/`sessionStorage` reads | not covered - no instrumentation emits them as sources | - |

## Families and sinks (burp.Zcwh dynamic decoder, docs/specs/R-13 section 6)

| Family (issue) | KB | Severity | Confidence | Wrapped sinks (covered) | Known uncovered sinks |
| --- | --- | --- | --- | --- | --- |
| Cross-site scripting (DOM-based) | 00200310 | High | Firm | `document.write`, `document.writeln`, `element.innerHTML`, `element.outerHTML`, `element.insertAdjacentHTML`, `element.setAttribute.onclick`, `jQuery.html`, `jQuery.append`, `jQuery.prepend`, `jQuery.before`, `jQuery.after`, `jQuery.wrap`, `jQuery.replaceWith`, `jQuery.parseHTML` | other jQuery groups, `iframe.srcdoc`, custom setters |
| JavaScript injection (DOM-based) | 00200320 | High | Firm | `eval`, `Function`, string handlers of `setTimeout`/`setInterval`, `jQuery.globalEval` | `execScript` (gone from Chromium), `javascript:` URLs (not wrappable) |
| Open redirection (DOM-based) | 00500110 | Low | Tentative | `window.open` | `location.href/assign/replace/host/hostname/protocol` - LegacyUnforgeable in Chromium, cannot be wrapped |
| DOM data manipulation (DOM-based) | 00501200 | Information | Firm | `element.textContent`, `element.innerText`, `input.value`, `document.title`, `window.name`, `history.pushState`, `history.replaceState`, `script.text`, `anchor.target`, `element.setAttribute.action/src/data/formaction` | - |
| Link manipulation (DOM-based) | 00501000 | Low | Firm | `form.action`, `anchor.href`, `button.formaction`, `input.formaction`, `element.setAttribute.href`, `jQuery.attr/prop.href`, `jQuery.attr/prop.action` | - |
| WebSocket URL poisoning (DOM-based) | 00200340 | High | Firm | `websocket` (the constructor URL) | - |
| Denial of service (DOM-based) | 00500d00 | Information | Firm | `RegExp` (the pattern argument) | - |
| Ajax request header manipulation (DOM-based) | 00500c00 | Low | Firm | `xhr.setRequestHeader` name and value | - |
| Cookie manipulation (DOM-based) | 00500b00 | Low | Firm | `document.cookie` setter | - |
| HTML5 storage manipulation (DOM-based) | 00500f00 | Information | Firm | `localStorage.setItem` name and value, `sessionStorage.setItem` name and value | - |
| Client-side JSON injection (DOM-based) | 00200370 | Low | Firm | `JSON.parse` | `jQuery.parseJSON` not covered |
| Client-side XPath injection (DOM-based) | 00200360 | Low | Firm | `document.evaluate` | `jQuery.parseXML` |
| Document domain manipulation (DOM-based) | 00501100 | Medium | Firm | `document.domain` setter | - |
| HTML5 web message manipulation (DOM-based) | 00500e00 | Information | Firm | `postMessage` (the message argument) | - |
| Client-side prototype pollution | 00200316 | Information | Firm for hash-only, Tentative for query/mixed | new own properties on `Object.prototype` containing a dedicated query/hash token | existing-property overwrites, stored pollution, transient additions missed between polls |
| Client-side SQL injection (DOM-based) | - | - | - | not ported | `webdatabase.executeSql`: `openDatabase` is gone from current Chromium |

Generic `storage.setItem.*` hits (a Storage object that is neither the
local nor the session area) are recorded but reported by no family.

## Recorded checks and evidence (2026-11-23, pins up to 72382c6; not re-executed at the current candidate)

- One browser probe per URL per run; all families read the same result
  (`dom_families_share_one_probe_and_refresh_on_the_next_run`: 8 issues
  from one probe; a fresh run re-probes). Production sends 2 requests per
  simple page per run (1 baseline outside the DOM operation budget and 1 DOM
  navigation; no stored-token submission), but this test's pinned counts
  predate the disable; see Current inconsistency below.
- Source provenance: `dom_source_provenance_matrix_against_a_live_lab`
  proves hash-only (Firm), search-only (Tentative), mixed (Tentative),
  and the negatives: reflected token without a sink, a pre-existing
  unrelated Object.prototype property, and a benign page.
- Variants (burp.Zf24): production currently emits the reflected or base
  label only. The stored-label code path remains fixture-testable but is
  dormant because production passes an empty stored token and sends no
  stored submission. The query token present in script text of the exact
  navigation response fulfilled to Chromium and also observed at a sink
  selects the reflected label. This is token co-occurrence, not proof of
  JavaScript string-literal origin or the path from response text to sink.
  The reflected variant is Tentative. The G.11 parser classifies response
  context only; no later re-request supplies evidence.
- Admission and failures: probe allowance, browser slot, binary startup and
  DevTools setup must succeed before navigation. Production sends no stored
  submission. Stop is checked before sends and navigation. An incomplete or
  invalid navigation response is not retained as evidence and does not cause
  a retry. The failed result is cached for the URL for this run.
- New labs pin denied admission with zero target connections; cancellation
  before navigation; effect-then-drop with no replay; safe session headers
  on captured wire; fixture-level stored/plain classification; and
  classification from the actual fulfilled response without later traffic.
  The stored-submission fixture is not the production path.
- `dom_probe_tokens_are_distinct_and_substituted` pins the two-token
  substitution (drift test).
- Budgets: at most `DOM_MAX_CONCURRENT_BROWSERS` (2) live Chromium
  instances per run and `DOM_MAX_PROBES_PER_RUN` (100) navigations; over
  budget fails closed (no browser, no hits). Unit-tested in
  webprobe-support (`dedup::tests`).
- Per-operation request budget: `DOM_MAX_REQUESTS_PER_PROBE` (64) covers
  intercepted same-origin GET/HEAD requests, consumed before sends. There is
  no outer stored submission in production. Baseline is outside this operation.
  A resource-heavy live lab pins exactly 1 baseline + 64 operation requests.
  Each forwarded request accepts at most 128 DevTools-intercepted header
  entries, then up to 3 fixed fields and up to 4 missing template fields are
  appended (at most 135 header lines emitted). Its assembled bytes are capped
  at 64 KiB before the scanner transport; session rules may alter it
  afterwards, so this is not a final on-the-wire size.
- Egress isolation: Fetch interception answers every page request; a
  dead-loopback `--proxy-server` removes the route for anything that
  bypasses interception (speculative preconnect/prefetch, background
  services); DNS confined by `--host-resolver-rules`; WebSocket URLs
  blocked; service workers bypassed; WebRTC non-proxied UDP disabled;
  `--dns-prefetch-disable --no-pings`.
- Evidence caps: 50 hits per page, 300 chars per recorded value, 500 chars
  page URL (instrumentation), 4 MiB fulfilled body, 32 KiB fulfilled
  response headers (`crawl.rs` constants).
- Hits kept only on the exact probed origin; one report per sink, variant
  and source. The stored variant is retained in the reporting code but
  unreachable while the submission is disabled.
- Sink-set drift: `dom_sink_sets_match_the_instrumentation` and
  `dom_family_sinks_are_wrapped` pin the JS sink names to the Rust
  family tables, including the runtime-built name prefixes
  (`element.setAttribute.`, `history.`, `jQuery.`).

## Instrumentation caveats (detection limits, by design)

- JavaScript wrappers are not engine hooks: `eval` becomes indirect/global,
  so page code relying on direct-eval local scope behaves differently under
  the probe (Burp patches Chromium; documented gap).
- A canary reaching a sink proves data flow, not an exploitable breakout.
- Only GET history entries with executable HTML baselines are probed;
  inert HTML is skipped.

Navigation evidence requires a complete, strictly self-delimited final
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
## Prototype-pollution boundary

`dom_prototype_pollution_against_a_live_lab` proves query and fragment
additions and rejects reflection and filtered keys. The multi-family lab
proves query pollution and fragment DOM-XSS keep separate sources/confidence.
`dom_pollution_stored_exclusion_and_combined_budget_against_a_live_lab`
is coupled to the disabled stored submission and was observed failing on
2026-11-24 (historical; exact run provenance unresolved); its pollution-only
assertions (stored-only pollution exclusion, reflection/unchanged negatives)
remain the intended contract. Production does not send the stored-token
submission.

Stored-source classification remains fixture-only; it is not active in the
production fourteen-family probe. Prototype pollution uses only the base
issue name and dedicated URL-part token evidence on new own keys. It does not
use a stored token. This is addition-only coverage, not an overwrite detector
or stored-pollution detector. Those remain follow-ups.

## Current inconsistency (2026-11-24)

The stored-token submission is disabled in production
(`app/core/src/scan_checks/dom.rs`: the instrumentation token is empty and
the submission closure is a no-op; no setting re-enables it). The disable
landed while the lab tests still described the active submission. Seven test
definitions in `app/core/src/scan_checks/tests.rs` are coupled to the
submission:

- `dom_families_share_one_probe_and_refresh_on_the_next_run`: observed
  failing on 2026-11-24 (historical; exact run provenance unresolved):
  its per-run request counts include the submission.
- `dom_xss_stored_variant_against_a_live_lab`: observed failing on
  2026-11-24 (historical; exact run provenance unresolved): stored
  findings can no longer be produced.
- `dom_session_headers_and_mixed_same_sink_against_a_live_lab`: observed
  failing on 2026-11-24 (historical; exact run provenance unresolved):
  stored-finding and wire-count assertions.
- `dom_pollution_stored_exclusion_and_combined_budget_against_a_live_lab`:
  observed failing on 2026-11-24 (historical; exact run provenance
  unresolved): submission indexing and stored-finding assertions.
- `dom_unknown_submission_outcome_is_not_replayed_against_a_live_lab`: not
  executed; source-derived hypothesis: it may pass without exercising its
  intended effect-then-drop contract, because its lab classifies any
  request carrying a query string as the submission.
- `dom_reflection_uses_only_fulfilled_navigation_response_against_a_live_lab`:
  not executed; source-derived hypothesis: without the submission its
  adversarial response beginning on the fourth nonempty request is never served, so the reflected-negative
  assertion loses discriminating power even where its count still holds.
- `dom_outer_submission_and_resources_share_request_cap_against_a_live_lab`:
  not executed; source-derived hypothesis: its request-total assertion may
  still hold because the operation cap is exhausted with or without the
  submission; only its wording is stale.

The plain and reflected production reporting paths are retained in the
candidate source; their lab evidence is part of the historical record
above, not a re-verification at this revision. The stored contract is
under review; this section is removed when the tests and this
documentation are re-aligned with the decided contract.
