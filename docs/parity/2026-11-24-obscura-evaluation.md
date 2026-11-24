# Obscura as a Chromium replacement — evaluation (2026-11-24)

**Question:** can [Obscura](https://github.com/h4ckf0r0day/obscura) (Rust headless browser, V8, CDP server,
Apache-2.0) replace the Chromium that WebProbe launches for the browser crawl (`crawl.rs` `browser_crawl`)
and the dynamic DOM probe (`crawl.rs` `dom_analysis_probe`, R-13)?

**Answer:** not today, for these two DevTools-driven paths. It runs the page JavaScript correctly, but over
DevTools it fails three things those paths depend on, one of them a safety guarantee. Chromium stays the only
engine for `browser_crawl` and `dom_analysis_probe`; nothing in the product was switched.

**Scope.** WebProbe already uses Obscura elsewhere, and this document does not change that.
`app/core/src/headless.rs` has a `HeadlessBrowser` trait whose first choice is Obscura (then Lightpanda, then
Chromium) for the JS-aware crawl (`headless::js_crawl`, task P-16, `docs/EVAL-OBSCURA.md`). That path runs
`obscura fetch --dump html` as a one-shot process through the WebProbe proxy with the WebProbe CA in
`SSL_CERT_FILE`, so it needs none of the DevTools features measured here. The results below apply only to the
two paths in `crawl.rs` that drive a browser over DevTools.

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
| Self-signed / untrusted HTTPS target, direct | works with `--ignore-certificate-errors` | **fails** (`invalid peer certificate`), no flag to accept it; a custom CA can be trusted through `SSL_CERT_FILE` |
| Egress with `--proxy` (`fetch` mode) | not measured here | document, stylesheet, script, image, `fetch` and XHR POST all went through the proxy, none direct; the proxy saw the POST body |
| Host confinement (`--host-resolver-rules`) | available | no equivalent |
| Startup on this box | ~0.2 s to DevTools ready | ~instant; 26 MB RSS idle |

## Why this blocks replacement

1. **DOM probe safety.** The DOM probe forwards every same-origin request through the scanner transport and
   fails everything else closed (`DomRoute`, budget `DOM_MAX_REQUESTS_PER_PROBE`). With Obscura, sub-resources
   bypass interception, so the "zero direct egress" property proved by
   `host_probe_unknown_routed_batch_has_zero_direct_egress` and the DOM route tests would not hold.
2. **Untrusted certificates.** Test targets routinely present self-signed or internal-CA certificates.
   Connecting directly, Obscura refuses them and offers no override, so both paths would silently lose
   HTTPS targets. This does not affect the existing `headless.rs` crawl: there Obscura talks to the WebProbe
   proxy and trusts the WebProbe CA, and WebProbe makes the connection to the target.
3. **Fidelity.** DOM-based findings are compared against Burp, whose embedded browser is Chromium. Obscura is
   an independent engine (its README lists long-tail CSS and Web API differences), so sink reachability can
   differ from what a real victim browser does.

The crawl alone is closer (it needs no interception), but it still loses POST bodies, raw response heads and
HTTPS targets with untrusted certificates, and would need a second CDP connection flow.

## What would change the answer

Re-run `qa/obscura-eval/*.py` against a newer Obscura when it has: enforced sub-resource `Fetch`
interception, a certificate-error override, and `postData` on requests. Until then an Obscura backend for
these two paths would be a weaker, separately-maintained path for no user-visible gain: Chromium start-up
measured here is 0.2 s.

Two things were measured that shorten the distance, neither of them built into WebProbe:

- **Proxy routing.** With `--proxy`, all six request classes of a test page went through the proxy and none
  went direct (`proxy-egress-probe.py`, result in `obscura-0.2.7-proxy.json`). A design that points Obscura
  at the WebProbe proxy, as `headless.rs` already does, could therefore take egress control, POST bodies and
  raw response heads from the proxy instead of from DevTools. This was measured in `fetch` mode only, not
  under `serve`.
- **Certificate override.** A 13-line source patch (`obscura-ignore-cert.patch`, against commit `0ecc417`)
  adds `OBSCURA_IGNORE_CERT_ERRORS=1`. Built without the render feature and run under `serve`, navigation
  to the self-signed lab returned no error with the variable set and `invalid peer certificate` without it.
  Using it means maintaining a fork.

Sub-resource `Fetch` interception stays open: script and stylesheet loads call the HTTP client directly at
about 13 places in `obscura-browser/src/page.rs`.

## Limits of this evaluation

One Obscura version, one Linux x86_64 box, loopback labs only. The stealth build and the multi-worker server were not exercised;
proxy mode was exercised for `fetch` only. In `egress-and-tls-probe.py` read `nav_err` for the certificate
result: its `self_signed_https` value can repeat the marker of the page loaded just before. The Chromium self-signed row rests on WebProbe's existing
live-browser tests rather than the second probe, whose Chromium run was cut short.
