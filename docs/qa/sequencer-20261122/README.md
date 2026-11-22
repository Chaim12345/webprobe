# Sequencer constant-token regression

Base: PR #45 at `4cddee0`, the clean hardening baseline. Implementation commit: `9c182f8`.

The real-Burp comparison in PR #112 found that loading 1,024 identical 20-byte tokens reported an insufficient-samples error and misleading total entropy in WebProbe, while Burp reported extremely poor and zero effective bits at 1%.

## Fix

- Constant non-empty samples now produce a valid bit-level report with zero variable positions, zero effective bits at all five significance levels, and an extremely poor result.
- Each manual, live and auto Analyze action computes its bit report from the actual samples. Replacing a batch with the same number of tokens cannot reuse the previous bit report.
- Remove the misleading pooled-byte-count times character-entropy total from the UI. Label pooled entropy explicitly and explain that it describes the alphabet, not token unpredictability.
- Explain the implemented statistical tests and missing tests in the summary. This is not a claim of full Burp statistical equivalence or cryptographic security.

## Live UI proof

Built and launched the actual desktop application on an isolated X display, using local ports 18991 and 18992 and a temporary project. Loaded the token file through Manual load's file path and Load button, then clicked Analyze now. The file was checked byte-for-byte against PR #112's `evidence/tokens.txt`. `manual-load.png` is the original screenshot, visually checked for readable summary text, all five significance rows, and absence of the old sample-count error.

The screenshot shows 1,024 tokens, 1 unique token, length 20, extremely poor, and zero effective bits at every level. The pooled entropy remains 4.3219 bits/byte, now explicitly separated from effective entropy, and there is no 88,513-bit total claim.

This run repeats WebProbe's manual-load workflow. It does not rerun Burp or certify all statistical behavior. The original Burp observation remains PR #112's evidence.

## Verification

Rust 1.100.0. Local Cargo overrides selected the installed compiler and system linker instead of the checkout's machine-specific `/usr/local` tools. No build configuration changes were committed.

- `cargo test --workspace --no-run`: pass.
- `cargo test --workspace`: **785 passed, 12 ignored, 0 failed** (136 app, 550 core, 12 report, 87 support).
- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass, zero warnings.
- `cargo test -p webprobe-support seq_bits:: -- --nocapture`: **8 passed**, including three new regressions. Output is in `tests.txt`.

The pre-existing tests also cover balanced-but-alternating bits, repeated four-bit patterns, counters, random binary tokens, hex encoding, fixed prefixes, exports and minimum sample handling. The existing monobit, poker, runs and approximate long-run tests are retained. Spectral, cross-bit correlation and compression testing remain unimplemented and are now explicitly disclosed in the summary. Variable-length analysis uses only the common prefix. Passing these tests does not prove unpredictability.
