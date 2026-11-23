# Main listener readiness change

Baseline: exact parity `7be2efd`. After: same revision plus readiness wait in the main accept loop. No async/TLS/h2 migration.

The main listener retains nonblocking accept and bounded restart-flag checks. On an empty queue it waits for OS readability, returning immediately for new clients. The 50 ms timeout now only bounds idle restart checks. If readiness setup or waiting fails, the listener logs it and falls back to the prior sleep behavior.

## Measured before/after

Rust 1.100, same dev profile, optimized dependencies and compiler flags. Owned Python stdlib loopback origin with 1000-byte response and backlog 256. 128 new HTTP connections/sample, concurrency 1/16/64, 3 repeats per binary, alternating order. Eight warmup exchanges per fresh proxy. Responses verified for status and full body. Proxy-only RSS/thread sampling at 5 ms. Medians of per-run metrics below. All 2304 measured requests passed.

| Concurrency | Version | Conn/s | p50 ms | p95 ms | Idle/peak RSS KiB | Idle/peak threads |
|---|---|---:|---:|---:|---:|---:|
| 1 | accept-before | 19.95 | 50.09 | 50.38 | 6436/6568 | 3/5 |
| 1 | accept-after | 511.48 | 1.92 | 2.04 | 6264/6392 | 3/5 |
| 16 | accept-before | 308.25 | 50.17 | 60.90 | 6388/7360 | 3/25 |
| 16 | accept-after | 1046.23 | 14.28 | 19.43 | 6256/7332 | 3/21 |
| 64 | accept-before | 733.73 | 67.82 | 100.72 | 6364/8108 | 3/72 |
| 64 | accept-after | 865.04 | 46.65 | 69.96 | 6228/8336 | 3/66 |

## Reproduce and limits

Copy the committed `app/core/examples/proxy_bench.rs` to baseline and changed core examples directories. Build each with `cargo build -p webprobe-core --example proxy_bench`, preserving binaries as accept-before and accept-after. Run `python3 scripts/bench-proxy.py /path/accept-before /path/accept-after --main > results.json`. Raw samples include platform metadata.

Linux-only performance evidence. The polling dependency has cross-platform backends but Windows/macOS were not run. Small shared host, short runs and Python client/origin can affect throughput/tails. No HTTPS, HTTP/2, slow/idle connection or mixed scanner/OAST benchmark claim. Per-connection worker threads remain unchanged. This is evidence for removing accept latency, not for starting #44.

Focused readiness tests cover idle timeout, repeated rearming, accepted socket reuse and unregister-without-close. Existing primary-listener restart without client connection passes.
