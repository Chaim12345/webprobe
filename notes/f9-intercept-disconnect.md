# F9 — a held intercept request outlived its client: findings and fix

Source pin: `692f09728039884c59a676ff314879c06dcb1cf5` (parity/2026-11-17).
Branch: `goal/f9-intercept-disconnect-20261125`.

## Status: fixed and executed on the integration branch

The fixture below was written source-only on `goal/f9-intercept-disconnect-20261125` as a
characterisation of the defect. On the integration branch the production fix in "Fix (applied)"
was added, and the fixture was built and run with it. The numbers in the next section are the
pre-fix measurements, kept as recorded.

## What the case is

`held_request_is_released_when_the_client_disconnects` is the target-behaviour regression that
replaced the characterisation case once the fix landed:

1. precondition: the held entry is established before the cancel, and the origin has seen
   nothing;
2. after a full client close: the entry leaves the queue within the 3 s window, and the origin
   saw zero accepts and zero complete requests at the cancel and again 300 ms later;
3. nothing is left in the queue to forward or drop;
4. the proxy worker exits within the settle window (a detached worker fails the parent).

## Pre-fix measurements

- the held queue entry was still present 3.001 s after the client closed (`released=false`);
- after the explicit forward, one origin connection appeared.

Limits: retention and later deliverability only. No claim about next-request desync (the origin
closed its side) and no claim about connection-reuse corruption.

## Consolidated blocker pass A-F

- **A — case binding.** Every case constant is checked statically against the real test fn name,
  including the app module prefix (`ar09_binary_tool_state_tests::…`) in the 233 files. At this
  HEAD `CONTROL` and `HELD` already matched their fns; the check is now reproducible
  (`python3 /tmp/case_binding_check.py`, 0 failures, script reads only `git show HEAD:` output).
  As a runtime backstop each parent also requires the child-only `F9-ISOLATION-OK` line, so a
  stale constant fails with "the case never ran" instead of a bare test-count mismatch.
- **B — teardown and drop order.** `HeldQueueGuard` is declared after the proxy, so on any exit
  path — including a panic before the explicit teardown — the queue is dropped first and the
  proxy settle runs second. The guard only ever calls `intercept_release_all(.., true)`; teardown
  never forwards. `Proxy::drop` now runs the whole ordered sequence: shut down cloned client
  handles, stop and join the acceptor, drop held entries, then give workers a **bounded**
  `PROXY_SETTLE` (3 s) window in which finished handles are joined. Anything still running at the
  end prints `F9-PROXY-WORKERS-DETACHED` and the parent rejects it: child termination is
  containment, not clean worker termination. A finished worker whose join returns a panic
  payload prints `F9-PROXY-WORKER-PANICKED`, which the parent rejects too.
- **C — evidence before the pass/fail assertions.** The target-behaviour regression prints
  `F9-EVIDENCE released=…`, `held_after` and the origin counters before asserting. The parent
  requires `F9-ISOLATION-OK`, `F9-EVIDENCE released=true` and the per-case
  `CASE-COMPLETE: {HELD}` line (and `CASE-COMPLETE` for the control case). A failure is reported
  by the assertions themselves (`F9-TARGET-FAILURE: …`); there is no expected-failure match
  anymore, because the case now passes only when the held request is released and the origin
  was never contacted.
- **D/E — not applicable to this branch** (233 capture fixture work; see that branch's note).
- **F — retained.** Guarded child through `finish`, file-backed child logs, exact one-case summary
  checks, canonicalised child environment plus sentinels plus the `ca.json` artefact, fail-closed
  inspection, and parent rejection of non-clean worker outcomes.

## Formatting

`cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` are
clean on the integration branch.

## CA inspection scope

Path, existence, mtime, size/hash and permissions only; never certificate or private-key
contents; no deletion or repair. This revision reads only names and existence under the owned
tempdir.

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
  already behaves this way. Accepted by the owner on 2026-11-26 (issue #241): the
  alternative keeps requests from departed clients queued and forwardable.
- Over TLS a clean close leaves the peer's close_notify record unread in the socket buffer, so
  the peek sees data, not EOF: a clean TLS close is not detected, only a reset or a FIN without
  close_notify. Detecting it needs a different primitive (for example POLLRDHUP).
- A forward racing the disconnect can still reach the origin: the UI removes the item before
  the next liveness poll. A further liveness check before the upstream write would narrow that
  window but cannot close it, because the client can still leave between the check and the write.
