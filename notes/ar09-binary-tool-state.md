# AR-09 — bytes vs lossy text in Repeater/Intruder tool state

Source pin: `692f09728039884c59a676ff314879c06dcb1cf5` (parity/2026-11-17).
Branch: `goal/ar09-binary-tool-state-20261125`.

## Status: source-only revision, nothing executed

This revision touches the test files and this note only. No build, test run or test binary was
executed for it. The coverage and byte figures below are the earlier run's records.

## Coverage at the earlier run (a3345a2)

- `app/core/tests/ar09_binary_tool_state.rs`: 2 cases passed (transport control and the lossy
  characterisation).
- `app/src/ar09_binary_tool_state_tests.rs`: 2 cases passed, driving the real app code
  (`request_for_tools` -> `send_following`/`send_once`; `request_for_tools` -> template ->
  `intruder_run::start` -> `execute_probe`). The Repeater case was named
  `repeater_send_once_sends_the_lossy_body_with_a_stale_content_length` then; this revision
  shortens it to `repeater_send_once_sends_the_lossy_body` and adds a third, non-isolated
  split-delivery fixture self-check, so the next run reports 3 app cases + 2 core cases.
- Total: 4 passing cases; 0 failing; 0 ignored. These are characterisations of the current code
  and a transport control — **not** a fix, not GUI evidence, and not proof of correct binary
  handling.

Observed then: body `00 ff fe 00 c3 28` (6 bytes) arrived as `00 ef bf bd ef bf bd 00 ef bf bd
28` (12 bytes) under `Content-Length: 6` in the Repeater chain; the Intruder chain sent the same
12 bytes with Content-Length restamped to 12.

## Corrections in this revision (fixtures and this note only)

- Each case that constructs `Shared` is now a parent wrapper that never constructs it. The
  parent creates a unique tempdir with a fake HOME, a fake XDG_CONFIG_HOME and an explicit CA
  dir, writes non-secret sentinels at `fakeHOME/.config/webprobe/ca.json` and
  `fakeXDG/webprobe/ca.json`, and spawns this binary with `--exact <case> --nocapture
  --test-threads=1`. Isolated paths go to the CHILD environment only; no `set_var`, no chdir,
  no inherited-HOME reliance, no shell prefixes.
- The child validates that the three paths are absolute and inside the owned tempdir, and runs
  exactly one case.
- The parent requires: child finished inside a 120 s budget (`try_wait` with a deadline, kill
  and reap on timeout), exactly one reported case, an explicit `CASE-COMPLETE:` record,
  unchanged sentinels, and no new files under the fake HOME or XDG.
- The capture fixture records every byte under a bounded idle deadline and never stops early on
  the declared Content-Length, so header length, body length and trailing bytes are reported
  separately.
- A split-delivery self-check (head, 50 ms gap, body) asserts the fixture captures the known
  byte length; it constructs neither `Shared` nor `App`, so it needs no child-process isolation.
- The Intruder case asserts the run finishes inside 15 s and carries a guard that stops the run
  and waits for it to settle during failure cleanup.
- No subsequent-request desync and no connection-reuse claim is made; the observed facts are a
  converted body and a declared-length mismatch on one connection. The risk is described as
  malformed framing and data loss only.

## Hand-formatting in this revision (rustfmt not run)

Formatting was applied by hand because this goal forbids running any binary, including the
formatter: import order inside brace groups (`{Shared, send_raw_with}`), the long `INTRUDER`
constant broken after `=`, one-line calls for split evidence lines, trailing commas in vertical
macro arguments, short struct literals collapsed to one line, and short method chains joined.
These hunks are hand-formatting only; the reviewer should validate them with
`cargo fmt --check` before any rerun.

## CA isolation status

Earlier run: unknown and uncontrolled — the fixtures constructed `Shared::new()` directly, so a
test binary could resolve the real user CA through `WEBPROBE_CA_DIR`, `XDG_CONFIG_HOME` or
`HOME`. The wrapper above is designed to prevent that, but it has not been executed; isolation
remains unproven until an independent reviewer runs it.

## Proposed production change (unapproved, proposal only)

The raw-bytes fallback sketch in the earlier revision is withdrawn. Binary body handling needs a
byte-backed tool-state design of its own (capture bytes beside the text, transport from the
bytes, an explicit hex/binary editor decision) and must be reviewed before any edit. No
production file is touched here.

## CA inspection scope

If CA state is ever inspected: path, existence, mtime, size/hash and permissions only. Never
certificate or private-key contents. No deletion or repair. No inspection was performed here.
