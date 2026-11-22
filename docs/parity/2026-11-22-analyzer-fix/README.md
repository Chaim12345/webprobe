# Montoya analyzer fixes, 2026-11-22

Base: PR #99, `cc7407d579046da45c84b7f2beb69982b3b388e5`.

This change addresses gaps 3 and 4 from the real-Burp comparison in PR #112.
It does not modify that comparison or claim full Montoya parity.

## Changes

- Keyword counts are case-insensitive, so `token` and `TOKEN` vary together in the recorded three-response fixture. Configured spellings are preserved in result sets. Empty entries are accepted. WebProbe defines their count as the response string length plus one; only acceptance, not that counting rule, was measured against Burp.
- The response-variations factory returns a stateful analyzer instead of throwing. It seeds all 33 API attributes on the first response, then permanently records changes. Returned sets are immutable snapshots and instances have independent state.
- HTML-derived metrics use WebProbe's own extraction rules. They are not verified replicas of Burp's metrics. INITIAL_CONTENT and LIMITED_BODY_CONTENT use 256- and 4096-character body prefixes. The first extracted attribute values, including body content, are retained. No full HttpResponse objects are retained.
- A long unquoted HTML attribute regression guards against recursive-regex stack exhaustion during tag scanning.

## Verification

Environment: Linux x86_64, Rust 1.100.0, Temurin JDK 25.0.5.1, published Montoya API 2026.7. The committed demo extension requires Java class version 69, so the full suite needs JDK 25 here.

`WEBPROBE_REQUIRE_JAVA=1` was set, ensuring the analyzer regressions did not silently skip. The test extensions were compiled and loaded by the actual JVM sidecar through the public Montoya API.

- `cargo test --workspace --no-run`: passed.
- `cargo test --workspace`: 785 passed, 0 failed, 12 ignored. Breakdown: desktop 136, core 553, report 12, support 84. Existing ignored tests remain ignored.
- `cargo fmt --check`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed, 0 warnings.

The attached test and clippy logs are real command output. Local compiler/linker overrides were necessary because the checked-in Cargo configuration names compiler-cache/linker paths absent on this machine; repository configuration was not changed.

No vendor JARs are included. No running Burp installation was used for this fix verification. The evidence in PR #112 remains the source for the bounded Burp behavior described above.
