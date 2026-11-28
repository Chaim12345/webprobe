# AR-09 — bytes vs lossy text in Repeater/Intruder tool state

Source pin: `692f09728039884c59a676ff314879c06dcb1cf5` (parity/2026-11-17).
Branch: `goal/ar09-binary-tool-state-20261125`.

## Status: merged; the fixtures run in CI

This note was written on `goal/ar09-binary-tool-state-20261125` before its cases had run. #236
integrated the branch; `cargo test --workspace --locked` in CI now builds and runs both the core
and app cases. Nothing here was re-measured for this note.

## What the cases are

- `control_transport_preserves_nul_and_non_utf8_body_bytes` — control: the real send path
  (`send_raw_with`) carries the captured bytes and declared length exactly.
- `characterisation_repeater_text_state_is_lossy_for_non_utf8_bodies` (core) and
  `repeater_send_once_sends_the_lossy_body` / `intruder_attack_sends_the_lossy_template_body`
  (app) — CHARACTERISATIONS: they assert the CURRENT lossy outcome, so they pass while the
  defect exists. They are not a fix, not a fix guard and not GUI proof.
- `capture_fixture_records_a_split_delivery_without_trusting_content_length` (app) — fixture
  self-check that constructs neither `Shared` nor `App`.

## Consolidated blocker pass A-F

- **A — case binding.** Every case constant is checked statically against the real test fn name,
  including the module prefix the app binary needs: `INTRUDER` and `REPEATER` are
  `ar09_binary_tool_state_tests::…` and that module is declared in `app/src/main.rs`. The check
  runs from `git show HEAD:` output (`python3 /tmp/case_binding_check.py`, 0 failures) and also
  asserts each spawned constant is used by `child_branch`.
- **B — teardown order.** Not applicable here (no held-queue/intercept path); this branch keeps
  the child guard, bounded Intruder settle and parent rejection from the earlier pass.
- **C — labelling.** The lossy cases remain CHARACTERISATIONS; no indefinite-wait or
  next-request-desync claim is made.
- **D — capture regression fixed.** Both `read_client` implementations again stop hiding data at
  the declared length: `complete` is set when head plus declared body have arrived, but reading
  continues through a bounded trailing drain — 150 ms quiet window after the last byte or a hard
  400 ms drain cap, whichever comes first — inside the absolute `CONNECTION_BUDGET`, the
  `MAX_REQUEST_BYTES` cap and the stop flag, with a write timeout on every reply. The record
  exposes declared length and captured bytes separately, so declared 6 versus captured 12 with
  trailing 6 is asserted rather than assumed. No test depends on one socket read coalescing.
- **E — discriminating self-check.** The split fixture now sends `Content-Length: 6` plus the
  first 6 bytes, waits 50 ms, then the last 6 bytes of an actual 12-byte body, and asserts: all
  12 bytes captured, `trailing == 6`, and the wire length equals head plus the full body. A
  capture that stopped at the declared length would record 6 bytes and no trailing data and
  would fail this fixture.
- **F — retained.** Guarded child through `finish`, file-backed child logs, exact one-case
  summary checks, canonicalised child environment plus sentinels plus the `ca.json` artefact,
  fail-closed inspection, and parent rejection of an Intruder settle failure
  (`AR09-INTRUDER-CLEANUP-FAILED`).

## Coverage at the earlier run (`a3345a2`), not re-measured here

- `app/core/tests/ar09_binary_tool_state.rs`: 2 cases passed (control plus characterisation).
- `app/src/ar09_binary_tool_state_tests.rs`: 2 send-path cases passed driving the real app code
  (`request_for_tools` -> `send_following`/`send_once`; `request_for_tools` -> template ->
  `intruder_run::start` -> `execute_probe`).
- Observed then: body `00 ff fe 00 c3 28` (6 bytes) arrived as
  `00 ef bf bd ef bf bd 00 ef bf bd 28` (12 bytes) under `Content-Length: 6`; the Intruder chain
  sent the same 12 bytes with Content-Length restamped to 12.

CI now runs 3 app cases (two isolated send-path cases plus the discriminating split fixture)
and 2 core cases.

Claim limits: a converted body plus a declared-length mismatch on one connection. Malformed
framing and data loss only; no desync or connection-reuse claim.

## Formatting

The changed test files were copied to `/tmp`, formatted there with
`rustfmt 1.11.0-stable (0ef1bc3860 2026-11-09)` under `--edition 2024`, and the copies were
folded back. `rustfmt --check` on copies of the committed blobs exits 0.

## CA inspection scope

Path, existence, mtime, size/hash and permissions only; never certificate or private-key
contents; no deletion or repair. This revision reads only names and existence under the owned
tempdir.

## Proposed production change (unapproved, proposal only)

Binary body handling needs a byte-backed tool-state design of its own (capture bytes beside the
text, transport from the bytes, an explicit hex/binary editor decision) and must be reviewed
before any edit. No production file is touched here.
