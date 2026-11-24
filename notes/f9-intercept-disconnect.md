# F9 — intercept disconnect liveness: findings and proposed patch (not applied)

Source pin: `692f09728039884c59a676ff314879c06dcb1cf5` (parity/2026-11-17).
This note is a review artifact. No shared `net/` code was edited in this branch; the only
change is the new integration test `app/core/tests/f9_intercept_disconnect.rs`.

## Observed defect (executed, loopback only)

```
cargo test -p webprobe-core --test f9_intercept_disconnect -- --exact control_normal_request_reaches_the_origin_and_returns
  -> 1 passed; 0 failed  (control: request -> origin -> client response)

cargo test -p webprobe-core --test f9_intercept_disconnect -- --ignored --exact held_request_is_released_when_the_client_disconnects
  -> FAILED: released=false after 3.001026125s (deadline 3s); origin connections after cancel=1
```

So with interception on, a held HTTP request:
1. is **not** released when the client disconnects (it stays in `shared.queue` indefinitely), and
2. once the UI forwards it, the request **is sent to the origin** although the client is gone.

## Production call sites

- `app/core/src/net/intercept.rs:55` `intercept_request` — blocking `rx.recv()`, no liveness.
- `app/core/src/net/intercept.rs:119` `intercept_response` — same.
- `app/core/src/net/intercept.rs:149-172` `intercept_wait(shared, id, rx, alive)` — the liveness
  wait that already exists: polls every 200 ms, and when `alive()` is false it removes the item
  from `shared.queue`, wakes the UI and returns `None`.
- `app/core/src/net/ws.rs:606` — the WebSocket path already uses `intercept_wait`.
- Callers of `intercept_request`: `engine.rs:490` (`serve_plain`, has the client `TcpStream`),
  `engine.rs:734` (`serve_mitm_conn`, `S: ProxyIo`), `engine.rs:776` (HTTP/2 pipeline handler).
  `ProxyIo::peer_closed()` exists (`support/src/io_traits.rs:37-43`), and `tcp_closed` too.

## Minimal patch sketch (for review; do not apply here)

1. Give `intercept_request`/`intercept_response` an `alive: &dyn Fn() -> bool` parameter and
   replace `match rx.recv()` with `match intercept_wait(shared, id, &rx, alive)`; `None` already
   means "drop", and `serve_plain` already returns without sending upstream
   (`engine.rs:491` `let Some(req) = req else { return };`).
2. Pass `&|| !stream.peer_closed()` from `serve_plain` and from `serve_mitm_conn`'s client socket.
3. HTTP/2: the pipeline handler needs a per-stream reset flag (the `ResponseWriter`/h2 server
   exposes no socket peek); that call site needs its own liveness source before wiring.
4. Keep the existing 200 ms poll; no parser, pool or protocol change.

Residual race after the patch: a forward issued at the same instant as the disconnect can still
reach the origin (the item is removed by `intercept_forward` before the liveness check). A second
liveness check inside `upstream_and_deliver` would close that window and is out of this scope.

## Environment note

The workspace had no Rust toolchain installed. I installed rustup 1.100.0 (minimal profile) to
`~/.cargo` / `~/.rustup` and overrode the repo's pinned `rustc`/`sccache`/`clang`/`lld-22` paths
with environment variables (`RUSTC`, `RUSTC_WRAPPER=""`, `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc`,
`RUSTFLAGS=""`); no repository config file was edited. Build artifacts live in `/tmp/f9-target`,
outside the repository.
