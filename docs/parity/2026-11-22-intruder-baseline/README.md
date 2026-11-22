# Intruder request 0

Specification: the bounded real-Burp comparison in PR #112 shows an unmodified baseline followed by two Sniper payload requests. This fix is based on PR #45 head `4cddee0`, not on the measured PR #99 build. It targets `parity/2026-11-17` and must land after the hardening base.

The runner sends request 0 and records its response before starting concurrent payload workers. All original insertion values are preserved and no payload encoding or Content-Length repair is applied to the baseline. Existing transport/session behavior is unchanged. Payload requests still start at number 1. The baseline uses the same target, retry, throttle, analysis, pause and stop paths; finite progress totals include it. Recursive-grep attacks display baseline extracts but do not feed them into the payload walk.

The existing results table already renders request number 0, an empty payload cell, status, length, elapsed time, request/response panes and analysis columns. CSV/XML export and numeric sorting use the same result rows. No UI layout or project schema changes were needed.

## Verification

Rust 1.100.0 on Linux. `cargo test --workspace --no-run`, full workspace tests, `cargo fmt --all -- --check`, and `cargo clippy --workspace --all-targets -- -D warnings` pass. Full suite: 785 passed, 12 pre-existing ignored, 0 failed (136 desktop, 550 existing core, 3 new core integration, 12 report, 84 support).

The new regression file is `app/core/tests/intruder_baseline.rs`:

- Actual loopback HTTP requests cover the measured single-position/two-payload Sniper shape plus all four attack types with two positions. The fixture holds the baseline response open and rejects any overtaking payload connection. It verifies baseline bytes, zero numbering, analysis, progress, sorting and CSV/XML export.
- A refused loopback connection verifies that baseline and payload failures both retain their rows and configured retry count.
- A channel-gated fixture verifies that stopping during the baseline does not launch payloads.

The existing recursive-grep fixture now gives the baseline a distinct extracted value and proves the initial payload remains unchanged. The extension-generator integration expectation includes the original baseline separately from extension-processed payloads.

Red/green proof: the new baseline-failure regression fails on unmodified `4cddee0` with one result where two are required, then passes with this implementation. The accompanying log records fresh network-fixture output and workspace gates. These are real loopback engine runs, not a new Burp comparison or a desktop pixel-verification claim. Repeat against the final merged roadmap build before claiming broader parity.
