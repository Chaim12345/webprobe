# F9 — intercept disconnect liveness: findings and pending proposal

Source pin: `692f09728039884c59a676ff314879c06dcb1cf5` (parity/2026-11-17).
Branch: `goal/f9-intercept-disconnect-20261125`.

## Status: source-only revision, nothing executed

This revision touches only the fixture (`app/core/tests/f9_intercept_disconnect.rs`) and this
note. No build, test run or test binary was executed for it. The numbers quoted below are the
earlier run's measurements, kept as recorded; they are not re-measured here, and CI is not
treated as proof while the CA isolation design is unreviewed.

## What the earlier run measured (not re-run)

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
- The draft regression stays `#[ignore]` until a production fix exists. The control stays the
  intended pass. The draft's parent accepts only the assertion-specific failure
  (`F9-EVIDENCE` plus `released=false`); a bare exit code 101 is not accepted.
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

## Hand-formatting in this revision (rustfmt not run)

Formatting was applied by hand because this goal forbids running any binary, including the
formatter: import order inside brace groups (`{Shared, handle_conn, ...}`), one-line calls for
evidence lines that were split to stay under 100 columns, trailing commas in vertical macro
arguments, short struct literals collapsed to one line, and short method chains joined. These
hunks are hand-formatting only; the reviewer should validate them with `cargo fmt --check`
before any rerun.

## CA isolation status

Earlier run: unknown and uncontrolled — the fixtures constructed `Shared::new()` directly, so a
test binary could resolve the real user CA through `WEBPROBE_CA_DIR`, `XDG_CONFIG_HOME` or
`HOME`. The wrapper above is designed to prevent that, but it has not been executed; isolation
remains unproven until an independent reviewer runs it.

## Proposed production change (unapproved, proposal only)

`intercept_request` (`app/core/src/net/intercept.rs:55`) and `intercept_response` (`:119`) block
on `rx.recv()` with no liveness check, while `intercept_wait` (`:149-172`) already implements
one and the WebSocket path uses it (`ws.rs:606`). A fix would pass an `alive` closure and send
through `intercept_wait`; the exact closure is unapproved and must be reviewed against the
call sites (`engine.rs:490`, `:734`, `:776`).

## CA inspection scope

If CA state is ever inspected: path, existence, mtime, size/hash and permissions only. Never
certificate or private-key contents. No deletion or repair. No inspection was performed here.
