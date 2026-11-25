# F9 — a held intercept request outlives its client: characterisation

Source pin: `692f09728039884c59a676ff314879c06dcb1cf5` (parity/2026-11-17).
Branch: `goal/f9-intercept-disconnect-20261125`.

## Status: source-only artifact, runtime HOLD still in force

Nothing in this revision was built, linked, executed or checked. The only tool run was a
standalone `rustfmt` on copies of the changed test files in `/tmp` (see "Formatting"). No cargo
command of any kind, no test binary, no script touching project code.

## What the case is

`characterisation_held_request_is_retained_after_the_client_cancels` is a CHARACTERISATION of
the current defect, not a desired failing regression and not a fix guard:

- the child body asserts the target behaviour (held request released after the client closes,
  nothing sent upstream);
- the child therefore fails today;
- the parent passes because it expects that specific failure and checks the assertion-specific
  evidence (`F9-EVIDENCE` plus `released=false` in the child stderr).

A future target-behaviour regression (expected to pass once a fix is approved) is planned and is
deliberately not written here. The control case stays an intended pass.

## Earlier run's measurements (not re-run, kept as recorded)

- the held queue entry was still present 3.001 s after the client closed (`released=false`);
- after the explicit forward, one origin connection appeared.

Limits: this shows retention and later deliverability. It does **not** show next-request
desync, connection-reuse corruption or anything about a pooled connection. No such claim is made.

## Corrections applied in this revision (mapped to the review)

1. RAII ownership through finish — `Isolation::finish` moves the child into a `ChildGuard` whose
   `Drop` always kills and reaps; `wait_bounded` kills on timeout and reports
   `F9-CLEANUP-TIMEOUT`. `verify_layout` runs before every status assertion, so sentinel and CA
   facts are checked even when the child fails unexpectedly. A
   `F9-PROXY-WORKERS-DETACHED` record is rejected by the parent: child termination is
   containment, not clean worker termination.
2. Origin capture — `read_request` returns `complete` only when the head and every declared
   `Content-Length` byte arrived; a head seen at EOF or on error is never complete. It has an
   absolute `CONNECTION_BUDGET` deadline, a `MAX_REQUEST_BYTES` cap and a stop-flag check, so
   dribbled bytes cannot keep it alive. The origin also sets a write timeout before replying.
3. Child output — stdout and stderr are redirected to files under the owned tempdir and read
   after exit, so a verbose child cannot block on an undrained pipe. On success the parent prints
   both streams (`F9-CHILD-STDOUT-BEGIN/END`, then stderr).
4. (Applies to the AR09 Intruder case; see that branch's note.)
5. Sentinel and CA layout — only the exact fake-HOME and fake-XDG sentinel files may exist, and
   inspection fails closed (`list_files` propagates `read_dir` errors). The child validates
   `HOME`, `XDG_CONFIG_HOME` and `WEBPROBE_CA_DIR` as the exact `root/home`, `root/xdg`,
   `root/ca` children of the canonical, symlink-free root, and each path must canonicalise to
   itself. Because `Shared::new()` builds `MitmAuthority` (`load_or_create(default_ca_dir())`,
   which writes `ca.json` when absent), the parent also asserts that `ca.json` exists inside the
   owned CA dir: an empty dir is not proof. CA artefacts are limited to `ca.json` and
   `ca.json.retired-*`; contents are never read.
6. Honest labelling — the case is named and documented as a characterisation; notes state it
   passes because the defect exists.
7. Runner contract — `Isolation::spawn` refuses to run when `WEBPROBE_F9_CHILD_CASE` or
   `WEBPROBE_F9_CHILD_ROOT` is already inherited, and the child refuses any marker that does not
   match the running case. A future validation runner must clear both variables before spawning.

## Formatting

The three changed test files were copied to `/tmp`, formatted there with
`rustfmt 1.11.0-stable (0ef1bc3860 2026-11-09)` under `--edition 2024`, and the resulting diff
was folded back by copying the formatted copies into the worktrees. The files are now
`rustfmt --check` clean on copies outside the repository. To make that possible the rustfmt
component was installed for the local `rustc 1.100.0` toolchain (the version CI pins); this is
the only environment change.

## CA inspection scope

If CA state is ever inspected: path, existence, mtime, size/hash and permissions only. Never
certificate or private-key contents. No deletion or repair. This revision reads only file names
and existence under the owned tempdir.

## Proposed production change (unapproved, proposal only)

`intercept_request` (`app/core/src/net/intercept.rs:55`) and `intercept_response` (`:119`) block
on `rx.recv()` with no liveness check, while `intercept_wait` (`:149-172`) already implements one
and the WebSocket path uses it (`ws.rs:606`). A fix would pass an `alive` closure and send
through `intercept_wait`; the exact closure is unapproved and must be reviewed against the call
sites (`engine.rs:490`, `:734`, `:776`).
