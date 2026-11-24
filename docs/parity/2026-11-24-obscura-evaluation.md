# Obscura as a Chromium replacement — evaluation (2026-11-24)

**Question:** can [Obscura](https://github.com/h4ckf0r0day/obscura) (Rust headless browser, V8, CDP server,
Apache-2.0) replace the Chromium that WebProbe launches for the browser crawl (`crawl.rs` `browser_crawl`)
and the dynamic DOM probe (`crawl.rs` `dom_analysis_probe`, R-13)?

**Answer:** not today. It runs the page JavaScript correctly, but it fails three things WebProbe depends on,
one of them a safety guarantee. Chromium stays the only engine; nothing in the product was switched.

## What was tested

- Obscura **v0.2.7** release binary (`obscura-x86_64-linux.tar.gz`, sha256 `11b53d27…baf9cad`),
  `obscura serve --allow-private-network`.
- Baseline: the Chromium WebProbe already uses on this box (147.0.7727.101, `--headless=new`).
- Two loopback lab probes, kept in `qa/obscura-eval/` with their raw results. They issue the same DevTools
  calls WebProbe makes: `Page.enable`, `Network.enable`, `Page.addScriptToEvaluateOnNewDocument`,
  `Page.navigate`, `Runtime.evaluate`, `Network.getResponseBody`, `Network.setBypassServiceWorker`,
  `Network.setBlockedURLs`, `Fetch.enable` + `Fetch.fulfillRequest` / `Fetch.failRequest`.

## Results

| Capability WebProbe needs | Chromium 147 | Obscura 0.2.7 |
| --- | --- | --- |
| Page socket from `/json/list` (WebProbe's connect flow) | works | **fails**: `No page for session`; needs `Target.createTarget` + `attachToTarget` and `sessionId` framing |
| Page JS, `fetch`, XHR, links and forms via `Runtime.evaluate` | works | works |
| Init-script sink hooks (`addScriptToEvaluateOnNewDocument`), `innerHTML` sink capture, `__proto__` pollution | works | works |
| `Network.requestWillBeSent` / `loadingFinished` / `getResponseBody` | works | works (every event delivered twice) |
| POST body on `requestWillBeSent` (`postData`) | present | **absent** — crawled POSTs would lose their bodies |
| `Network.responseReceivedExtraInfo` (raw response head) | emitted | **not emitted** |
| `Fetch` interception of the document | fulfilled | fulfilled |
| `Fetch` interception of sub-resources | all 6 requests paused, **0** reached the server | paused events arrive, but `/s.css` and `/app.js` **still went to the server directly** and the fulfilled script body was ignored |
| `Network.setBypassServiceWorker` | works | **unknown method** |
| `Network.setBlockedURLs` | works | works (off-target script and image were not fetched) |
| Self-signed / untrusted HTTPS target | works with `--ignore-certificate-errors` | **fails** (`invalid peer certificate`), no flag to accept it |
| Host confinement (`--host-resolver-rules`) | available | no equivalent |
| Startup on this box | ~0.2 s to DevTools ready | ~instant; 26 MB RSS idle |

## Why this blocks replacement

1. **DOM probe safety.** The DOM probe forwards every same-origin request through the scanner transport and
   fails everything else closed (`DomRoute`, budget `DOM_MAX_REQUESTS_PER_PROBE`). With Obscura, sub-resources
   bypass interception, so the "zero direct egress" property proved by
   `host_probe_unknown_routed_batch_has_zero_direct_egress` and the DOM route tests would not hold.
2. **Untrusted certificates.** Test targets routinely present self-signed or internal-CA certificates.
   Obscura refuses them and offers no override, so both the crawl and the DOM probe would silently lose
   HTTPS targets.
3. **Fidelity.** DOM-based findings are compared against Burp, whose embedded browser is Chromium. Obscura is
   an independent engine (its README lists long-tail CSS and Web API differences), so sink reachability can
   differ from what a real victim browser does.

The crawl alone is closer (it needs no interception), but it still loses POST bodies, raw response heads and
HTTPS targets with untrusted certificates, and would need a second CDP connection flow.

## What would change the answer

Re-run `qa/obscura-eval/*.py` against a newer Obscura when it has: enforced sub-resource `Fetch`
interception, a certificate-error override, and `postData` on requests. Until then an Obscura backend would
be a weaker, separately-maintained path for no user-visible gain: Chromium start-up measured here is 0.2 s.

## Limits of this evaluation

One Obscura version, one Linux x86_64 box, loopback labs only. The stealth build, proxy mode and the
multi-worker server were not exercised. The Chromium self-signed row rests on WebProbe's existing
live-browser tests rather than the second probe, whose Chromium run was cut short.
