# F9 — intercept disconnect liveness: findings and fix

Source pin: `692f09728039884c59a676ff314879c06dcb1cf5` (parity/2026-11-17).
The defect below was reproduced first with a test-only change
(`app/core/tests/f9_intercept_disconnect.rs`); the fix in "Fix (applied)" followed, and the
repro test now runs un-ignored.

## Observed defect before the fix (executed, loopback only)

```
cargo test -p webprobe-core --test f9_intercept_disconnect -- --exact control_normal_request_reaches_the_origin_and_returns
  -> 1 passed; 0 failed  (control: request -> origin -> client response)

cargo test -p webprobe-core --test f9_intercept_disconnect -- --ignored --exact held_request_is_released_when_the_client_disconnects
  -> FAILED: released=false after 3.001026125s (deadline 3s); origin connections after cancel=1
```

So with interception on, a held HTTP request:
1. is **not** released when the client disconnects (it stays in `shared.queue` indefinitely), and
2. once the UI forwards it, the request **is sent to the origin** although the client is gone.

## Production call sites (line numbers at the source pin)

- `app/core/src/net/intercept.rs:55` `intercept_request` — blocking `rx.recv()`, no liveness.
- `app/core/src/net/intercept.rs:119` `intercept_response` — same.
- `app/core/src/net/intercept.rs:149-172` `intercept_wait(shared, id, rx, alive)` — the liveness
  wait that already exists: polls every 200 ms, and when `alive()` is false it removes the item
  from `shared.queue`, wakes the UI and returns `None`.
- `app/core/src/net/ws.rs:606` — the WebSocket path already uses `intercept_wait`.
- Callers of `intercept_request`: `engine.rs:490` (`serve_plain`, has the client `TcpStream`),
  `engine.rs:734` (`serve_mitm_conn`, `S: ProxyIo`), `engine.rs:776` (HTTP/2 pipeline handler).
  `ProxyIo::peer_closed()` exists (`support/src/io_traits.rs:37-43`), and `tcp_closed` too.

## Fix (applied)

1. `intercept_request` and `intercept_response` take `alive: &dyn Fn() -> bool` and wait through
   `intercept_wait` (200 ms poll). When the client is gone the item leaves `shared.queue`, the UI
   is woken and the message is dropped: nothing is sent upstream.
2. `client_gone` (`net/intercept.rs`) is the liveness source for blocking HTTP/1 streams: a
   non-blocking peek through `ProxyIo::peer_closed`, used by `serve_plain`, `serve_mitm_conn`
   and the response hold in `upstream_and_deliver`.
3. HTTP/2: `h2_server::ResponseWriter` now reports `peer_closed()` from its existing `closed`
   flag (set on RST_STREAM and connection close), so the per-stream pipeline has liveness too.

Executed after the fix: `cargo test -p webprobe-core --test f9_intercept_disconnect` -> 2 passed,
0 ignored; `cargo test --workspace --locked` -> 0 failed.

## Limits (not covered by the fix or the test)

- Only the cleartext HTTP/1 request hold is exercised by a test. The TLS, HTTP/2 and
  response-hold call sites are wired but have no disconnect test.
- Liveness is a peek for EOF. A client that half-closes after its request (FIN, still reading)
  looks the same as a client that left, so its held request is dropped; the WebSocket path
  already behaves this way.
- Over TLS a clean close leaves the peer's close_notify record unread in the socket buffer, so
  the peek sees data, not EOF: a clean TLS close is not detected, only a reset or a FIN without
  close_notify. Detecting it needs a different primitive (for example POLLRDHUP).
- A forward racing the disconnect can still reach the origin: the UI removes the item before
  the next liveness poll. A further liveness check before the upstream write would narrow that
  window but cannot close it, because the client can still leave between the check and the write.

## Environment note

For the original repro run, the workspace had no Rust toolchain installed. I installed rustup 1.100.0 (minimal profile) to
`~/.cargo` / `~/.rustup` and overrode the repo's pinned `rustc`/`sccache`/`clang`/`lld-22` paths
with environment variables (`RUSTC`, `RUSTC_WRAPPER=""`, `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc`,
`RUSTFLAGS=""`); no repository config file was edited. Build artifacts live in `/tmp/f9-target`,
outside the repository.
