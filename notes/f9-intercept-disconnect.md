# F9 — a held intercept request outlives its client: characterisation

Source pin: `692f09728039884c59a676ff314879c06dcb1cf5` (parity/2026-11-17).
Branch: `goal/f9-intercept-disconnect-20261125`.

## Status: source-only artifact, runtime HOLD still in force

Nothing in this revision was built, linked, executed or checked. No cargo command, no test
binary, no script touching project code, no installs. The only tool run was a standalone
`rustfmt` on copies of the changed test file in `/tmp` (formatter already present from the
earlier, recorded deviation).

## What the case is

`characterisation_held_request_is_retained_after_the_client_cancels` is a CHARACTERISATION of
the current defect, not a desired failing regression and not a fix guard. The child first
asserts its narrow facts and then, as a distinct last step, the target behaviour:

1. precondition: the held entry is established before the cancel;
2. after a full client close and a 3 s observation window: `released=false`, the queue still
   holds exactly one entry, and the origin saw zero accepts and zero complete requests before
   and at cancel;
3. manual forward: exactly one entry released, and exactly one *complete* parsed request at the
   origin afterwards (the only delivery claim made);
4. `F9-CASE-EVIDENCE-COMPLETE` is printed, then the distinct target check,
   `F9-TARGET-CHECK`;
5. only then the target assertion fails, with `F9-TARGET-FAILURE: ...`.

A fix turns step 5 into a pass; steps 1-3 stay valid as the regression.

## Earlier run's measurements (not re-run)

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
  containment, not clean worker termination.
- **C — positive evidence before expected failure.** The characterisation asserts
  `released=false`, `held_after_3s == 1`, `accepts_before == 0`, `parsed_before == 0`,
  `accepts_at_cancel == 0`, `parsed_at_cancel == 0`, `forwards == 1` and
  `parsed_after_forward == parsed_at_cancel + 1` before the final target assertion. The parent
  requires `F9-CASE-EVIDENCE-COMPLETE` and `F9-TARGET-CHECK` in the child stdout, in that order,
  plus `F9-TARGET-FAILURE` on stderr, so an unrelated assertion failure cannot satisfy the
  expected-failure match. The characterisation label is unchanged.
- **D/E — not applicable to this branch** (233 capture fixture work; see that branch's note).
- **F — retained.** Guarded child through `finish`, file-backed child logs, exact one-case summary
  checks, canonicalised child environment plus sentinels plus the `ca.json` artefact, fail-closed
  inspection, and parent rejection of non-clean worker outcomes.

## Formatting

The changed test file was copied to `/tmp`, formatted there with
`rustfmt 1.11.0-stable (0ef1bc3860 2026-11-09)` under `--edition 2024`, and the copy was folded
back. `rustfmt --check` on a copy of the committed blob exits 0.

## CA inspection scope

Path, existence, mtime, size/hash and permissions only; never certificate or private-key
contents; no deletion or repair. This revision reads only names and existence under the owned
tempdir.

## Proposed production change (unapproved, proposal only)

`intercept_request` (`app/core/src/net/intercept.rs:55`) and `intercept_response` (`:119`) block
on `rx.recv()` with no liveness check, while `intercept_wait` (`:149-172`) already implements one
and the WebSocket path uses it (`ws.rs:606`). A fix would pass an `alive` closure and send
through `intercept_wait`; the exact closure is unapproved and must be reviewed against the call
sites (`engine.rs:490`, `:734`, `:776`).
