# Evaluation: Obscura as the "bundled browser" alternative (task L-05)

Date: 2026-11-15 · Project: https://github.com/h4ckf0r0day/obscura (Apache-2.0, Rust + V8, v0.2.7 released 2026-11-13,
35.5k stars, 256 open issues, created 2026-04-13) · Tested: official `obscura-x86_64-linux.tar.gz`, SHA-256
`11b53d27cd743e00e196e216920e7f3f794cf378e3f1792b8d25d3beabaf9cad` (matches GitHub's published digest), run as the unprivileged
`nobody` user against WebProbe on proxy 6566 and a local origin on 6580 (never 8080/8081).

## Verdict
**Not a replacement for Burp's browser, a good candidate for a headless engine.** Burp's browser is an interactive Chromium
window the tester drives. Obscura has no window, no DevTools UI and no extensions, so it cannot fill that role. It fits the
*automation* jobs Burp also uses its embedded browser for. Recommendation: split L-05 in two.

1. **Interactive "Open browser"**: launch the user's Chrome/Chromium (or a downloaded Chrome for Testing) with a throwaway
   profile, `--proxy-server=127.0.0.1:<listener>` and the WebProbe CA trusted for that profile only. Task P-15.
2. **Headless engine** behind a `HeadlessBrowser` trait with Obscura as the first implementation, used for JS-aware crawling
   (D-01), Render view of a stored response (UI-ME-01), recorded-login replay (H-03) and scan verification. Task P-16.

## What was measured
| Test | Result |
|---|---|
| Default fetch of `http://127.0.0.1:6580/...` | Blocked by its SSRF guard (`Access to private/internal IP address 127.0.0.1 is not allowed`); needs `--allow-private-network` |
| Same with the flag | Works, page text returned |
| Plain HTTP through `--proxy http://127.0.0.1:6566` | Works; the request appears in WebProbe history |
| HTTPS through our intercepting proxy, no CA | **Fails**: `invalid peer certificate: UnknownIssuer`; no CA flag in `--help` |
| Same with `SSL_CERT_FILE=<webprobe-ca.pem>` | **Works**; WebProbe history shows `example.com:443 GET / 200 text/html https` |
| `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE` | Ignored (still `UnknownIssuer`) |
| JavaScript | `document.title`, `querySelectorAll` work (`Example Domain | links=1`) |
| Screenshot `-s page.png` of https://example.com | 63,715-byte PNG in 0.66 s, **peak RSS 47 MB** |
| Size | `obscura` 81 MB + `obscura-worker` 76 MB (default variant: rendering, no stealth) |

## Fit by job
| Job | Fit | Notes |
|---|---|---|
| Interactive manual browsing | ❌ | headless only |
| JS-aware crawl (`--dump links|assets`, CDP) | ✅ likely | traffic can be routed through the proxy so crawls appear in history; CDP `Fetch` interception covers main-document requests only |
| Render a stored response as an image | ✅ likely | serve the body via CDP `Fetch.fulfillRequest` (main document) or a temp local origin, then `Page.captureScreenshot` |
| Recorded login replay, form flows | 🚧 | `Input.*`, `Runtime.evaluate` exist; long-tail Web APIs may differ from Chromium |
| DOM XSS verification | 🚧 | depends on engine parity; needs a fixture suite |
| Anti-detect / stealth | ⛔ | never enabled: a testing tool must show every request, and tracker blocking (3,520 domains) would hide traffic |

## Risks and mitigations
- **Maturity**: 7 months old, 256 open issues, independent engine; "long-tail CSS, some Web APIs, media playback" differ from Chromium
  (its own README). Mitigate with a fixture suite (SPA, form login, iframe, fetch/XHR) as the P-16 gate.
- **Supply chain**: 157 MB of prebuilt binaries. Pin the version, verify the release digest, run unprivileged, never bundle
  the stealth variant. Rebuild from source (V8 compiles ~5 min) only if we decide to ship it.
- **Project orientation**: marketing is scraping/anti-detect with proxy-vendor sponsors. Irrelevant to the engine licence, but
  we use none of those features and do not depend on its cloud product.
- **CDP exposure**: bind loopback only and set `OBSCURA_CDP_TOKEN`; Docker docs warn that `-p 9222:9222` exposes every interface.
- **Private targets**: pentest targets are often on private ranges, so the SSRF guard needs `--allow-private-network`. WebProbe's
  own scope rules stay the authority; pass the flag only for in-scope private hosts.
- **TLS interception**: supply the CA through `SSL_CERT_FILE` (tested) in a per-process environment, never system-wide.

## Integration shape
Sidecar process, not a linked library (V8 + build time + 150 MB). Two levels: (a) CLI `fetch`/`scrape` for simple cases (no new
dependency); (b) `obscura serve --port <free>` driven over CDP WebSocket for sessions (needs a small WebSocket client). Spawn
per task, kill on cancel, capture stderr into the event log.

## Acceptance for the P-16 spike (all must pass to adopt)
1. A JS-rendered fixture page yields more links than a non-JS fetch of the same page.
2. Every request, including HTTPS, appears in WebProbe's history through the proxy with the CA supplied via `SSL_CERT_FILE`.
3. A stored response renders to PNG in under 2 s at under 150 MB peak RSS.
4. With stealth and tracker blocking off, no request leaves except to targets (verified from proxy history).
5. Version pinned and digest verified at install.

## Alternatives considered
| Option | For interactive use | Notes |
|---|---|---|
| System Chrome/Chromium launcher | ✅ best | matches Burp's "Open browser"; throwaway `--user-data-dir`, `--proxy-server`, SPKI pinning flag for the CA |
| Chrome for Testing download | ✅ | reproducible version, ~150 MB download on first use |
| Firefox with a policies file | ✅ | CA via `policies.json`, proxy via prefs |
| Embedded WebView (wry/tauri) | 🚧 | no reliable per-profile proxy/CA control on Linux |
| CEF | ✅ but heavy | large build, licence and packaging cost |
| Lightpanda (Zig headless) | ❌ headless | alternative headless engine to compare in the same spike |
