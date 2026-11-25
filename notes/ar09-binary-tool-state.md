# AR-09 — bytes vs lossy text in Repeater/Intruder tool state

Source pin: `692f09728039884c59a676ff314879c06dcb1cf5` (parity/2026-11-17).
Branch: `goal/ar09-binary-tool-state-20261125`.

## Status: source-only artifact, runtime HOLD still in force

Nothing in this revision was built, linked, executed or checked. The only tool run was a
standalone `rustfmt` on copies of the changed test files in `/tmp` (see "Formatting"). No cargo
command of any kind, no test binary, no script touching project code.

## What the cases are

- `control_transport_preserves_nul_and_non_utf8_body_bytes` — control: the real send path
  (`send_raw_with`) carries the captured bytes and declared length exactly.
- `characterisation_repeater_text_state_is_lossy_for_non_utf8_bodies` (core) and
  `repeater_send_once_sends_the_lossy_body` / `intruder_attack_sends_the_lossy_template_body`
  (app) — CHARACTERISATIONS: they assert the CURRENT lossy outcome, so they pass while the
  defect exists. They are not a fix, not a fix guard and not GUI proof. Each must be inverted
  when a byte-backed tool-state design lands.

## Coverage at the earlier run (`a3345a2`), not re-run

- `app/core/tests/ar09_binary_tool_state.rs`: 2 cases passed (control plus characterisation).
- `app/src/ar09_binary_tool_state_tests.rs`: 2 cases passed driving the real app code
  (`request_for_tools` -> `send_following`/`send_once`; `request_for_tools` -> template ->
  `intruder_run::start` -> `execute_probe`). The Repeater case was then named
  `repeater_send_once_sends_the_lossy_body_with_a_stale_content_length`.
- Observed then: body `00 ff fe 00 c3 28` (6 bytes) arrived as
  `00 ef bf bd ef bf bd 00 ef bf bd 28` (12 bytes) under `Content-Length: 6`; the Intruder chain
  sent the same 12 bytes with Content-Length restamped to 12.

The next run is expected to report 3 app cases (two isolated send-path cases plus one
split-delivery fixture self-check) and 2 core cases.

Claim limits: this is a converted body plus a declared-length mismatch on one connection. No
subsequent-request desync and no connection-reuse claim is made; the risk is described as
malformed framing and data loss only.

## Corrections applied in this revision (mapped to the review)

1. RAII ownership through finish — `Isolation::finish` moves the child into a `ChildGuard` whose
   `Drop` always kills and reaps; `wait_bounded` kills on timeout and reports
   `AR09-CLEANUP-TIMEOUT` / `AR09-APP-CLEANUP-TIMEOUT`. `verify_layout` runs before every status
   assertion, so sentinel and CA facts are checked even when the child fails unexpectedly.
   Forced child termination is recorded as containment, never as clean worker termination.
2. Capture fixture — `read_client` returns `complete` only when the head and every declared
   `Content-Length` byte arrived; a head seen at EOF or on error is never complete. Both
   capture paths have an absolute `CONNECTION_BUDGET` deadline, a `MAX_REQUEST_BYTES` cap and a
   stop-flag check, and set a write timeout before replying, so dribbled bytes cannot keep a
   connection alive. `first_complete` waits only for a complete record.
3. Child output — stdout and stderr go to files under the owned tempdir and are printed by the
   parent (`AR09-CHILD-STDOUT-BEGIN/END`, `AR09-APP-...`), so a verbose child cannot block on an
   undrained pipe and the byte proof is never swallowed.
4. Intruder lifecycle — `RunGuard::stop_and_settle` stops the run and waits a bounded 5 s. If the
   run is still active it prints `AR09-INTRUDER-CLEANUP-FAILED`, and the parent rejects that
   record; `Drop` is only a backstop and never panics. The normal assertion that the run
   finished inside 15 s is unchanged.
5. Sentinel and CA layout — only the exact fake-HOME and fake-XDG sentinel files may exist, and
   inspection fails closed (`list_files` propagates `read_dir` errors). The child validates
   `HOME`, `XDG_CONFIG_HOME` and `WEBPROBE_CA_DIR` as the exact `root/home`, `root/xdg`,
   `root/ca` children of the canonical, symlink-free root. Because `Shared::new()` builds
   `MitmAuthority` (`load_or_create(default_ca_dir())`, which writes `ca.json` when absent), the
   parent also asserts that `ca.json` exists inside the owned CA dir: an empty dir is not proof.
   CA artefacts are limited to `ca.json` and `ca.json.retired-*`; contents are never read.
6. Honest labelling — the lossy cases are named and documented as characterisations; the core
   split-delivery case is a fixture self-check, not a product claim.
7. Runner contract — `Isolation::spawn` refuses to run when `WEBPROBE_AR09_CHILD_CASE`,
   `WEBPROBE_AR09_CHILD_ROOT`, `WEBPROBE_AR09_APP_CHILD_CASE` or `WEBPROBE_AR09_APP_CHILD_ROOT`
   is already inherited, and each child refuses a marker that does not match the running case.
   A future validation runner must clear all four variables before spawning.

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

The earlier raw-bytes fallback sketch is withdrawn. Binary body handling needs a byte-backed
tool-state design of its own (capture bytes beside the text, transport from the bytes, an
explicit hex/binary editor decision) and must be reviewed before any edit. No production file is
touched here.
