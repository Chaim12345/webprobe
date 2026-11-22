# Repeater Montoya HTTP-handler fix

2026-11-22. Based on PR #99 at `cc7407d579046da45c84b7f2beb69982b3b388e5`.

## Contract and change

The real-Burp comparison in [PR #112](https://github.com/Chaim12345/webprobe/pull/112) observed that a registered Montoya HTTP handler adds the probe header to Burp Repeater sends, but not to WebProbe Repeater sends. This fix addresses that measured gap. The original full comparison was not rerun for this change. An independent redirect-only follow-up on 2026-11-22 used real Burp Community 2026.11.2 with Follow redirections set to Always: the origin saw one probe header on `/start` and two on the next hop, and both HTTP callbacks ran once per hop with tool `REPEATER`. This confirms the inherited-header behavior tested here. That follow-up also found byte-identical editor text after Send, including after following the redirect; the existing WebProbe redirect editor write-back remains a separate mismatch pending adjustment.

Repeater now dispatches HTTP request and response handlers for each send, including redirect hops. The bridge receives `Repeater` as the tool instead of the proxy path's hardcoded `Proxy`. Proxy-only handlers and process-extension proxy hooks remain excluded. Direct `api.http().sendRequest(...)` behavior is unchanged because dispatch is added to Repeater, not the shared raw sender.

The request mutation reaches the TCP origin. The response handler receives the mutated initiating request, and its response mutation reaches the final Repeater result. Without redirects, the editor and its history keep the original user request, so repeated Send does not accumulate extension headers. Extension-produced bytes are passed to transport without a UTF-8 round trip; the existing Repeater editor/history remain text-based. For followed redirects, `from_utf8_lossy` can replace non-UTF-8 bytes in the displayed/stored request and the text-based next-hop builder; binary redirect-body fidelity is not claimed.

## Regression and real-environment proof

`app/sidecar/stage-tests/RepeaterHttpExtension.java` registers one HTTP handler plus proxy-only request and response handlers. The Rust regression compiles and loads that extension into a real JVM, then uses the actual Repeater `send_following` path against a loopback TCP origin.

- Origin receives the HTTP handler's `X-Parity-Probe: 1` header.
- Both HTTP callbacks run exactly once per hop with tool name `Repeater`.
- The response handler sees the initiating request's probe header.
- Both redirect hops are checked. The extension deliberately adds rather than replaces its header: the same-site second hop retains the first probe header and gets one more from its own callback.
- Registered proxy-only callbacks do not run.
- A separate regression verifies an extension request-drop verdict prevents any origin connection.

[Before log](evidence/before.log): the same new JVM regression, temporarily using only the unchanged baseline `send_once` implementation, fails because the origin sees zero probe headers. This is a controlled dispatch rollback, not a separate full-baseline test-suite run.

[After log](evidence/after.log): real JVM callback output, origin observations, and 29 passing targeted Repeater tests. These logs are the real-environment proof; no GUI screenshot is claimed.

## Verification

Rust 1.100.0, Montoya API 2026.7, Linux. The targeted JVM regression passed with JDK 21 and JDK 25. Full workspace checks used JDK 25 because the repository's existing demo extension JAR contains newer class files that JDK 21 cannot load. No vendor binaries are added or changed.

| Check | Result | Evidence |
| --- | --- | --- |
| `cargo test --workspace --locked --no-run` | All workspace test targets compiled | [Build](evidence/no-run.log) |
| `cargo test --workspace --locked -- --test-threads=2` | 787 passed, 0 failed, 12 ignored | [Tests](evidence/workspace-tests.log) |
| `cargo test --locked --bin webprobe repeater_ -- --test-threads=1 --nocapture` | 29 passed, 0 failed | [Real-JVM proof](evidence/after.log) |
| `cargo clippy --workspace --locked --all-targets -- -D warnings` | Clean | [Clippy](evidence/clippy.log) |
| `cargo fmt --all -- --check` and `git diff --check` | Clean | Run locally |

Fresh-machine build overrides, matching the existing CI approach:

```sh
export CARGO_BUILD_RUSTC=rustc CARGO_BUILD_RUSTC_WRAPPER=''
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc RUSTFLAGS=''
export WEBPROBE_REQUIRE_JAVA=1
export WEBPROBE_JAVA=/path/to/jdk/bin/java
export WEBPROBE_BURP_JAR=/path/to/montoya-api-2026.7.jar
```

The new `Repeater Montoya regression` workflow requires the JVM regression, format check, test compilation and zero-warning clippy on pull requests. Missing JDK/API prerequisites fail the required regression instead of silently skipping it.

The 12 ignored workspace tests retain their existing opt-in status, including live services and timing-sensitive checks. This change does not claim full Burp parity, UI pixel verification, TLS-origin coverage, or a repeat of the other findings in PR #112.
