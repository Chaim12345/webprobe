# Instructions for coding agents

## Branches
- **The working branch is `parity/2026-11-17`.** Branch from its current head and open every pull request against it.
- **Never open a pull request against `master`.** `master` is one old snapshot commit and shares no history with `parity/2026-11-17`; a PR against it shows hundreds of unrelated files and cannot be merged.
- Before describing or fixing a gap, check it against `parity/2026-11-17`, not `master`.

## Before pushing
Run from `app/`, and do not hand off with any of them failing:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
python3 ../scripts/arch-gate.py
cargo test --workspace --locked
```

`app/.cargo/config.toml` pins machine-local tool paths. On another machine set
`CARGO_BUILD_RUSTC=rustc CARGO_BUILD_RUSTC_WRAPPER="" CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc RUSTFLAGS=""`
and use Rust 1.100.0.

## Rules
- Do not add fields to `net::Shared` or `App` beyond what `scripts/arch-gate.py` allows (ADR 0002). Use an existing tool-state slot.
- A setting or feature must work from every entry point: the desktop app, `webprobe-headless proxy` and `webprobe-headless scan`.
- New project-file fields need `#[serde(default)]` so older projects still load.
- `tasks.json` is UTF-8. Change only the entries you mean to; never re-encode it with `\uXXXX` escapes. Keep `summary.by_status` in step.
- In the pull request description, list what you ran and what you did not verify.
