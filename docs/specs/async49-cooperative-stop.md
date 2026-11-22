# Async Phase 1: honest cooperative Stop (#49 follow-up)

Based on the original #49 head78af246. This bounded follow-up does not replace blocking network I/O or add forced cancellation of extension hooks.

## Runtime contract

A Tokio abort can prevent an unstarted blocking job from running. It cannot interrupt a blocking body that has already started. The engine wrapper awaits the body, and that body must observe the shared stop flag between blocking calls. An in-flight socket operation or extension hook can continue until it returns or hits its existing timeout. Dropping/aborting the async wrapper is not proof that the blocking body stopped.

The former sleep/abort test checked that a delayed side effect had not happened yet, without asking the sleeping body to cooperate. Its replacement first receives a started-body handshake, sets Stop, unparks that body, and requires an early-exit acknowledgement instead of waiting for its30-second natural deadline.

## Intruder

Matrix backpressure now checks Stop while waiting for a probe completion, with a25ms polling slice. This is a cooperative polling interval, not a hard latency guarantee. Stop can end that capacity wait even if no probe completes.

Before submitting a blocking probe, the runner counts it. Its guard and semaphore permit stay inside the blocking closure even when its async wrapper is aborted. Stop checks after permit acquisition and inside the closure avoid knowingly starting another request after Stop. A request already past the check is in flight and is not forcibly interrupted.

`RunState.running` still records dispatcher activity. `RunState::is_running()` includes submitted blocking work, so the UI cannot treat a detached probe as finished or offer a fresh start while it is draining. Status changes to Stopping while in-flight work remains, then Stopped after it drains. In-flight results are retained, and the final log is delayed until those blocking bodies finish. Pause/Resume/Stop buttons are hidden once Stop has been requested.

The existing Instant subtraction in production delay code is unchanged.

## Regression coverage

- Started runtime body acknowledges cooperative early exit.
- Two never-finishing probe futures fill the matrix queue; Stop must end backpressure without any completion.
- A loopback server holds the first response. Stop ends the dispatcher while the blocking request remains active. The test requires Stopping and an active run, releases the response, then requires Stopped, the retained HTTP200 row, and no queued request at the server.
- Disabling Stop-aware capacity waiting makes its regression fail. Removing blocking-work accounting from is_running makes the in-flight regression fail. Restoring both passes. The started/in-flight regression passed10 consecutive runs.

Full local gates:787 passed,12 baseline ignored; test build, rustfmt and all-target clippy passed. Real desktop QA started a50-payload attack against a gated loopback server, clicked Stop, inspected Stopping while responses were held, then released them and inspected Stopped with all10 in-flight HTTP200 rows retained. No external service was contacted for this QA.
