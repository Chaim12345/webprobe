# Async-stack local proxy benchmark

Baseline: PR45 `4cddee0`. Async stack: PR49 plus PR68 `7bdf2c95e7b85c12eb5b4070676378418af271c8`.

## Method

Rust 1.100.0, dev profile with dependency opt-level 2, local cc linker, same compiler/flags/shared dependency cache. Linux, 2 GiB RAM. Python stdlib driver and owned 1000-byte loopback HTTP fixture, backlog 256. No public traffic. Each sample starts a fresh proxy, warms with 8 validated exchanges, then makes 128 new connections at concurrency 1, 16 or 64. Three repeats, alternating baseline/stack order. Every response status and complete body is checked. RSS and thread count sampled every 5 ms from the proxy process only. Table gives medians across three repeats, not pooled-request percentiles. Raw samples are in `results.json`.

| Concurrency | Version | Conn/s | p50 ms | p95 ms | Idle/peak RSS KiB | Idle/peak threads |
|---|---|---:|---:|---:|---:|---:|
| 1 | proxy-baseline | 1331.96 | 0.72 | 0.80 | 5772/5912 | 2/3 |
| 1 | proxy-stack | 1342.16 | 0.72 | 0.81 | 5576/5712 | 2/4 |
| 16 | proxy-baseline | 1998.42 | 7.41 | 8.55 | 5864/6732 | 2/19 |
| 16 | proxy-stack | 2065.57 | 7.15 | 8.20 | 5648/6532 | 2/18 |
| 64 | proxy-baseline | 1580.34 | 25.05 | 39.12 | 5720/7288 | 2/72 |
| 64 | proxy-stack | 1736.71 | 22.45 | 30.63 | 5700/7408 | 2/68 |

## Interpretation and limits

Do not start #44 on this evidence alone. The async stack has not changed the proxy connection worker implementation, and both versions still grow OS threads with concurrent clients. Phase 1/2 runtime startup is lazy and this proxy-only workload does not activate scans, attacks or remote Collaborator polling. Similar measurements therefore establish a proxy-path regression control, not a measurement of active Phase 1/2 benefits or runtime memory overhead.

The harness uses the private browser listener, which feeds the same proxy connection worker but has a blocking accept loop. It intentionally excludes the main listener's fixed 50 ms accept polling delay. A separate main-listener measurement is below. Neither measurement represents HTTPS, HTTP/2, long-lived sockets, scanning, extensions or mixed workloads. Python origin/client scheduling and the small shared machine can dominate high-concurrency tails. No statistical significance or production capacity claim is made.

Before #44, add sustained idle/slow connections plus TLS/h2, activate the Phase 1 engine and Phase 2 scheduler against owned fixtures, and profile where CPU/thread/memory pressure actually lies. A migration should have an explicit improvement target and correctness/cancellation gates; this small run cannot choose it.

## Reproduce

At each exact revision, copy `app/core/examples/proxy_bench.rs` into the core examples directory and run `cargo build -p webprobe-core --example proxy_bench` from app. Save each resulting executable under a distinct name. Run:

```sh
python3 scripts/bench-proxy.py /path/to/proxy-baseline /path/to/proxy-stack > results.json
```

The script fails on network errors, incorrect status, truncated body or child-process failure instead of counting them as successful connections.

## Main proxy listener control

Same fixture/sample counts, invoked with `--main`. This includes the main listener's 50 ms accept polling cadence.

| Concurrency | Version | Conn/s | p50 ms | p95 ms | Idle/peak RSS KiB | Idle/peak threads |
|---|---|---:|---:|---:|---:|---:|
| 1 | proxy-baseline | 19.95 | 50.08 | 50.24 | 5740/5876 | 3/5 |
| 1 | proxy-stack | 19.96 | 50.08 | 50.25 | 5676/5812 | 3/5 |
| 16 | proxy-baseline | 312.78 | 50.00 | 55.24 | 5752/6584 | 3/26 |
| 16 | proxy-stack | 313.49 | 50.21 | 54.99 | 5636/6452 | 3/26 |
| 64 | proxy-baseline | 935.88 | 52.50 | 75.80 | 5740/7308 | 3/72 |
| 64 | proxy-stack | 924.42 | 52.87 | 82.18 | 5768/7268 | 3/73 |

Append `--main` to the driver command to reproduce. The main listener shows the expected polling bottleneck, largely absent in the private browser listener. This supplies a concrete smaller optimization candidate, but does not establish that converting the entire proxy/TLS/h2 stack to Tokio is necessary. Profile and test the accept strategy first. All 4,608 measured exchanges across both listener modes completed with verified status/body and no failures.
