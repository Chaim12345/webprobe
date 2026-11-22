# Loaded-proxy harness (perf lane, 2026-11-22)

Sustained-load measurement for the WebProbe proxy, in the style of
`qa/async-benchmark` (#88) and `qa/accept-readiness` (#89): owned loopback
fixture only, exact response validation, raw JSON per run.

## Layout

- `app/core/examples/loaded_proxy.rs` — headless proxy: boots the engine
  listener on a fresh in-memory project, prints `READY <port>`, idles. A
  counting waker stands in for the front end and STATS lines on stderr
  record `messages` (proxied exchanges), `wakes` (repaint requests
  delivered) and `coalesced` (wake-ups skipped by the 50 ms window).
- `qa/perf-load/drive.py` — threaded Python stdlib origin (keep-alive,
  fixed 1000-byte body) plus load client. Every request is a fresh TCP
  connection through the proxy (the proxy serves one request per client
  connection), absolute-form GET, status and full body validated.
  `PERF_CONC` / `PERF_REPEATS` / `PERF_REQUESTS` override the defaults
  (16,64,128 / 3 / 2048, warmup 288).

Run: `python3 qa/perf-load/drive.py <path-to-loaded_proxy> <label> <outdir>`

## Baseline at PR #45 head 4cddee0 (this box, debug build)

2-core sandbox, Python fixture/driver. Full default run, 3 repeats of 2048
requests per concurrency, zero errors except where noted:

| Concurrency | conn/s (3 repeats) | p50 ms | p95 ms |
| --- | --- | --- | --- |
| 16 | 144.8 / 145.5 / 145.1 | 50.1 | ~1055 |
| 64 | 141.0 / 188.3 / 190.2 | 50.3 | ~1078 |
| 128 | 67.0 (34 err) / 74.0 / 66.7 (42 err) | 50.5 | ~1080-1446 |

p50 = 50 ms at every concurrency: the main accept loop's fixed sleep
dominates per-connection latency. That bottleneck is #89's and #106's
(readiness wait); this lane deliberately does not touch it. Saturation and
errors at concurrency 128 are the same accept backlog; the Python fixture
and the 2-core shared host also dominate tails (same caveat as #106).

## Wake coalescing before/after (one 2048-request run at concurrency 64)

The example's counting waker records how many repaints the engine would
have requested from the UI:

| Build | messages | wakes | wakes/message |
| --- | --- | --- | --- |
| Baseline (4cddee0) | 2332 | 4665 | 2.00 (log line + history push) |
| This branch | 2279 | 476 (4083 coalesced) | 0.21 |

~90% of repaint requests eliminated under load, while slow traffic (below
~20 events/s) still wakes per event, so single exchanges appear at once.
Throughput in the same quick runs: 140.7 vs 191.5 conn/s — inside the
baseline's own repeat spread (141-190 at c64); claimed as no regression,
not as an improvement.

## UI-thread cost (Logger mirror)

`ProxyHistory::rows_since` replaces the per-frame whole-history scan with
an incremental cursor: O(new rows) per frame instead of O(history), and
the history lock is held only for the copy of the new rows. Diagnostic
timing:

`cargo test -p webprobe-core benchmark_mirror_history_access -- --ignored --nocapture`

## Limits

Loopback only; no TLS/h2/intercept/scan-active measurement (passive audit
on by default). Debug build. Thread-per-connection scaling unchanged. The
egui desktop app itself was not driven under load in this lane: the UI
fixes are verified by unit tests, the counting-waker evidence above, and
the desktop suite.
