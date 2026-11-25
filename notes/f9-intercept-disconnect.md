# F9 — intercept disconnect liveness: findings and fix

Source pin: `692f09728039884c59a676ff314879c06dcb1cf5` (parity/2026-11-17).
Branch: `goal/f9-intercept-disconnect-20261125`.

## Status: fixed on the integration branch, fixture executed

The fixture revision below was written source-only on `goal/f9-intercept-disconnect-20261125`.
On the integration branch it was formatted with `cargo fmt`, built and run together with the
production fix in "Fix (applied)"; the held case is promoted out of `#[ignore]` and passes. The
numbers in the next section are the pre-fix measurements, kept as recorded.

## What the pre-fix run measured

- the held queue entry was still present 3.001 s after the client closed (`released=false`);
- after the explicit forward, one origin connection appeared (`origin connections after
  cancel=1`).

What this does and does not show:

- it shows a held HTTP request outlives its client and is still deliverable afterwards;
- it does **not** show next-request desync, connection-reuse corruption, or any behaviour on a
  pooled connection. No such claim is made anywhere.

## Corrections in this revision (fixture only)

- Each case is now a parent wrapper that never constructs `Shared`. The parent creates a unique
  tempdir with a fake HOME, a fake XDG_CONFIG_HOME and an explicit CA dir, writes non-secret
  sentinels at `fakeHOME/.config/webprobe/ca.json` and `fakeXDG/webprobe/ca.json`, and spawns
  this test binary with `--exact <case> --nocapture --test-threads=1` (plus `--ignored` for the
  draft case). The isolated paths are set in the CHILD environment only; no process-wide env
  mutation, no `set_var`, no chdir.
- The child branch validates that HOME, XDG_CONFIG_HOME and WEBPROBE_CA_DIR are absolute and
  inside the owned tempdir, then runs exactly one case.
- The parent requires: the child finished inside a 60 s budget (`try_wait` with a deadline,
  kill and reap on timeout), exactly one reported case, an explicit per-case
  `CASE-COMPLETE:` record, unchanged sentinels, and no new files under the fake HOME or XDG.
- The held case is no longer `#[ignore]`d: its parent requires the child to pass, to print
  `F9-EVIDENCE released=true` and its `CASE-COMPLETE:` record.
- TCP accepts, fully parsed requests and retained wire bytes are separate counters, so a
  connection that never parses is not counted as a request.
- The held entry is established (queue length 1) before the cancel.
- Cancellation is a fully sent request followed by `Shutdown::Both`, not a write-half close.
- The observation is bounded to 3 s and the queue/accept/parsed/retained snapshot is taken
  before any cleanup.
- Teardown always drops held entries (`intercept_release_all(_, true)`) and never forwards.
  Forwarding is a separate, explicitly recorded characterisation action.
- Every spawned worker is owned: nonblocking accept loops with stop flags, per-stream read
  timeouts, stored join handles; finished handlers are joined, and any handler that cannot be
  time-bounded is reported as `F9-PROXY-WORKERS-DETACHED` with the parent's child kill as the
  containment.

## Formatting

The source-only revision was formatted by hand and still differed from rustfmt in 7 hunks of
the fixture. `cargo fmt --all` was run on the integration branch; `cargo fmt --all -- --check`
is clean there.

## CA isolation status

Earlier run: unknown and uncontrolled — the fixtures constructed `Shared::new()` directly, so a
test binary could resolve the real user CA through `WEBPROBE_CA_DIR`, `XDG_CONFIG_HOME` or
`HOME`. The wrapper above was executed on the integration branch: both cases passed, including
its sentinel and no-new-file assertions. That run was in a throwaway container with no real
user CA, so it shows the wrapper works, not that a real CA was ever at risk or protected.

## Fix (applied)

1. `intercept_request` and `intercept_response` take `alive: &dyn Fn() -> bool` and wait through
   `intercept_wait` (200 ms poll). When the client is gone the item leaves `shared.queue`, the UI
   is woken and the message is dropped: nothing is sent upstream.
2. `client_gone` (`net/intercept.rs`) is the liveness source for blocking HTTP/1 streams: a
   non-blocking peek through `ProxyIo::peer_closed`, used by `serve_plain`, `serve_mitm_conn`
   and the response hold in `upstream_and_deliver`.
3. HTTP/2: `h2_server::ResponseWriter` now reports `peer_closed()` from its existing `closed`
   flag (set on RST_STREAM and connection close), so the per-stream pipeline has liveness too.

Executed after the fix, with the isolated-child fixture described above:
`cargo test -p webprobe-core --test f9_intercept_disconnect` -> 2 passed, 0 ignored.

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

## CA inspection scope

If CA state is ever inspected: path, existence, mtime, size/hash and permissions only. Never
certificate or private-key contents. No deletion or repair. No inspection was performed here.
