# Sustained proxy load and readiness port on the async stack

## What changed

Port the existing PR #89 readiness fix from pre-L8 `net.rs` into the split `net/engine.rs` layout on PR #88. This is integration of an existing fix, not a new async proxy implementation. The port preserves the fallback polling path and bounded idle restart checks.

This branch includes PR #45, #49, #68 and #88. Its new work starts after #88 head `49f0b4e`: readiness port `09dec25` and this benchmark/documentation follow-up. Existing branches are unchanged. Land the dependencies first or extract the follow-up commits onto the integrated tree; do not merge this cumulative diff blindly.

## Revisions and reproducibility

- `proxy-baseline`: PR #45 head `4cddee0f8149c6629dc0d49673443dc87ba87a0a`.
- `proxy-stack`: PR #88 head `49f0b4eb8070745a4eb50dbd3e3c4fdb8df5f086`, including Phase 1/2.
- `proxy-stack-accept`: readiness port `09dec25` on that stack.

Build each with the same `app/core/examples/proxy_bench.rs` from #88 and `cargo build -p webprobe-core --example proxy_bench` from `app/`. Preserve each binary under the names above. All builds here used Rust 1.100.0, dev profile with dependency opt-level 2, cc linker and the same shared dependency cache. The tracked machine-specific cargo config was overridden locally for the available compiler/linker and was not committed.

For each concurrency of 16, 64 and 128, run:

```sh
python3 scripts/bench-proxy-loaded.py /path/proxy-stack /path/proxy-stack-accept --concurrency 64 > c64.json
python3 scripts/bench-proxy-loaded.py /path/proxy-baseline /path/proxy-stack --concurrency 64 > control-c64.json
```

Each invocation alternates binary order over three repeats. Each sample starts a fresh process, validates eight warmup exchanges, then completes 2,048 requests at the specified maximum concurrency. This is a closed-loop connection-per-request load, not a fixed offered-rate test. The fixture and every client are owned loopback processes. Each response must have an exact successful status line and the complete expected 1,000-byte body. Network failures, framing/body mismatches and process failures abort the run. Raw JSON includes platform and binary SHA-256 hashes.

Proxy-only RSS and thread counts are sampled every 5 ms. The Python client and origin are outside those resource numbers. Main-listener mode is used throughout. Tables contain medians of per-run metrics, not percentiles pooled across runs. All six invocations together completed 73,728 measured requests with zero failures, plus 288 warmups.

## Results

### Readiness port before/after

| Concurrency | Binary | Conn/s | p50 ms | p95 ms | p99 ms | Peak RSS KiB | Peak threads |
|---|---|---:|---:|---:|---:|---:|---:|
| 16 | proxy-stack | 318.19 | 50.03 | 54.40 | 56.10 | 7744 | 29 |
| 16 | proxy-stack-accept | 2154.09 | 7.17 | 9.13 | 14.87 | 8148 | 29 |
| 64 | proxy-stack | 1223.50 | 51.83 | 64.45 | 70.79 | 8640 | 96 |
| 64 | proxy-stack-accept | 2197.67 | 27.82 | 36.75 | 45.67 | 9892 | 106 |
| 128 | proxy-stack | 1983.88 | 60.82 | 87.03 | 103.20 | 9920 | 175 |
| 128 | proxy-stack-accept | 2140.66 | 56.75 | 71.64 | 81.71 | 12260 | 136 |

### PR45 baseline vs Phase 1/2 stack control

| Concurrency | Binary | Conn/s | p50 ms | p95 ms | p99 ms | Peak RSS KiB | Peak threads |
|---|---|---:|---:|---:|---:|---:|---:|
| 16 | proxy-baseline | 318.26 | 49.99 | 54.28 | 56.33 | 7844 | 31 |
| 16 | proxy-stack | 318.17 | 49.98 | 54.24 | 55.85 | 7816 | 31 |
| 64 | proxy-baseline | 1219.82 | 51.89 | 67.64 | 73.61 | 8720 | 96 |
| 64 | proxy-stack | 1233.83 | 51.56 | 65.63 | 80.13 | 8808 | 92 |
| 128 | proxy-baseline | 1798.79 | 67.50 | 95.02 | 110.43 | 9744 | 202 |
| 128 | proxy-stack | 1823.77 | 66.77 | 94.01 | 107.76 | 9916 | 172 |

## Interpretation and limits

The direct baseline-versus-stack control shows no material proxy-only throughput regression in this run: about 318 conn/s at concurrency 16, 1,220 versus 1,234 at 64, and 1,799 versus 1,824 at 128. This is a regression control, not proof of equal performance or statistical significance.

On the async stack, the readiness port removes the fixed accept-sleep floor. At concurrency 16, median throughput rises about 6.8x and p95 falls from 54.40 to 9.13 ms. The relative gain shrinks as concurrency increases and client/origin scheduling dominates. The changed binary's median peak RSS is higher in all three comparisons, especially at concurrency 128 (9,920 versus 12,260 KiB). These sampled small-process values and run-order effects need longer independent measurement before treating the difference as a leak or a memory regression. Thread counts still scale with load; there is no claim of bounded connection-worker resources.

The host has two visible CPUs and about 2 GiB RAM, shared by the Python origin/client and proxy. The compiler was idle during measurements. Each sample lasts roughly 1 to 7 seconds, so these runs extend the earlier 128-request benchmark but are not a long-duration soak test. RSS/thread samples can miss short peaks. HTTP plain loopback only: no TLS, HTTP/2, extensions, slow/idle clients, mixed workloads or remote services. Phase 1/2 runtime startup is lazy; scans, Intruder attacks and Collaborator polling were not activated here. The existing synchronous connection workers are still the proxy data path. This work does not justify starting optional Phase 3 (#44).

## Verification

- Full workspace `cargo test --workspace --no-run`: passes.
- Full workspace `cargo test --workspace`: 792 passed, 12 ignored, zero failures (desktop 136, core 560, report 12, support 84).
- Full workspace `cargo clippy --workspace --all-targets -- -D warnings`: passes with zero warnings.
- Workspace formatting: passes after sorting the new module declaration.
- Python harness syntax check: passes on Python 3.10.

The workspace count is distinct from the earlier core-only checks and includes all executable non-ignored tests. The ignored tests were not run. No UI visual validation is claimed for this non-UI change.
