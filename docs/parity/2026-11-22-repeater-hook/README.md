# Repeater Montoya HTTP-handler fix

2026-11-22. Based on PR #99 at `cc7407d579046da45c84b7f2beb69982b3b388e5`.

## Contract and change

The real-Burp comparison in [PR #112](https://github.com/Chaim12345/webprobe/pull/112) observed that a registered Montoya HTTP handler adds the probe header to Burp Repeater sends, but not to WebProbe Repeater sends. This fix addresses that measured gap. The original full comparison was not rerun for this change. An independent redirect-only follow-up on 2026-11-22 used real Burp Community 2026.11.2 with Follow redirections set to Always: the origin saw one probe header on `/start` and two on the next hop, and both HTTP callbacks ran once per hop with tool `REPEATER`. This confirms the inherited-header behavior tested here. That follow-up also found byte-identical editor text after Send, including after following the redirect; this fix now preserves the editor for redirect sends too. This intentionally changes the pre-existing WebProbe behavior, which wrote the final redirected request back into the editor.

Repeater now dispatches HTTP request and response handlers for each send, including redirect hops. The bridge receives `Repeater` as the tool instead of the proxy path's hardcoded `Proxy`. Proxy-only handlers and process-extension proxy hooks remain excluded. Direct `api.http().sendRequest(...)` behavior is unchanged because dispatch is added to Repeater, not the shared raw sender.

The request mutation reaches the TCP origin. The response handler receives the mutated initiating request, and its response mutation reaches the final Repeater result. The editor and its history keep the original user request, including after following redirects, so repeated Send does not accumulate extension headers. Extension-produced bytes are passed to transport without a UTF-8 round trip; the existing Repeater editor/history remain text-based. For followed redirects, `from_utf8_lossy` can replace non-UTF-8 bytes in the internal text-based next-hop builder; binary redirect-body fidelity is not claimed.

## Traceable Burp redirect evidence

The independent Burp Community 2026.11.2 follow-up is included byte-for-byte under [burp-redirect/](burp-redirect/): [handler callbacks](burp-redirect/handler.log), [origin requests](burp-redirect/origin.jsonl), [editor before](burp-redirect/request-before.txt), [editor after](burp-redirect/request-after.txt), [checks](burp-redirect/checks.json), plus the authored fixture and extension source. No vendor JAR is included. The copied requests are 648 identical bytes, SHA256 `21b5b390c8ce5f0b5d1e627bd2c53cfaf05cb34df1532c819d97c2c62fcaff8b`. Original CRLF bytes are preserved without text normalization. The reproduction sources retain the local evidence directory used by the measurement and need that directory adjusted or created before reuse.

## Stopped chains and manual Follow

Keeping the editor at hop 0 must not make a subsequent manual Follow resolve the final response's relative Location against hop 0. Response-bound request/target metadata is now kept alongside each tab's in-memory history, independent of the editor, and survives close/reopen. The Follow button uses the metadata at the selected history position. Session history and this metadata are not added to the saved-project format; entries without metadata fall back to the editor's context.

A UI-action regression follows an in-scope redirect from origin A to origin B, stops on B's relative `Location: next`, leaves the editor on A, then manually follows to B's `/b/next`. Both host/port and relative path are asserted against real TCP requests. A second mode of the same UI regression uses On-site only: Send stops on A's cross-origin response; manual Follow changes the editor/target to B's clicked `/b/step` request; the automatic relative hop reaches B's `/b/next` while the editor stays on `/b/step`. Each wire hop has the expected probe counts 1, 1, 2. This matches the independent Burp follow-up below.

The real-Burp manual-Follow follow-up is committed under [burp-manual-follow/](burp-manual-follow/), including origin/handler logs, checks, exact editor copies, authored sources, and screenshots. Burp Community 2026.11.2 with On-site only stopped at A's cross-origin 302. Manual Follow changed the editor and target to `localhost:18769/middle`, then automatically followed `/finish` there while leaving the editor on `/middle`. The probe counts were 1, 1, 2, and the editor had no probe header. Visually inspected evidence: [stopped 302](burp-manual-follow/after-send.png), [after manual Follow](burp-manual-follow/after-follow1.png), [On-site-only setting](burp-manual-follow/onsite-confirmed.png). The local regression uses different paths and ephemeral ports but checks the same request/target transition.

## Regression and real-environment proof

`app/sidecar/stage-tests/RepeaterHttpExtension.java` registers one HTTP handler plus proxy-only request and response handlers. The Rust regression compiles and loads that extension into a real JVM, then uses the actual Repeater `send_following` path against a loopback TCP origin.

- Origin receives the HTTP handler's `X-Parity-Probe: 1` header.
- Both HTTP callbacks run exactly once per hop with tool name `Repeater`.
- The response handler sees the initiating request's probe header.
- Both redirect hops are checked. The extension deliberately adds rather than replaces its header: the same-site second hop retains the first probe header and gets one more from its own callback.
- Registered proxy-only callbacks do not run.
- A separate regression verifies an extension request-drop verdict prevents any origin connection.
- UI-action regressions press Send twice with Follow Never and Follow Always. Each keeps the editor byte-identical; the redirect test verifies the 1-then-2 header pattern resets correctly on the next Send.

[Before log](evidence/before.log): the same new JVM regression, temporarily using only the unchanged baseline `send_once` implementation, fails because the origin sees zero probe headers. This is a controlled dispatch rollback, not a separate full-baseline test-suite run.

[After log](evidence/after.log): real JVM callback output, origin observations, and 31 passing targeted Repeater tests. These logs are the real-environment proof; no GUI screenshot is claimed.

## Verification

Rust 1.100.0, Montoya API 2026.7, Linux. The targeted JVM regression passed with JDK 21 and JDK 25. Full workspace checks used JDK 25 because the repository's existing demo extension JAR contains newer class files that JDK 21 cannot load. No vendor binaries are added or changed.

| Check | Result | Evidence |
| --- | --- | --- |
| `cargo test --workspace --locked --no-run` | All workspace test targets compiled | [Build](evidence/no-run.log) |
| `cargo test --workspace --locked -- --test-threads=2` | 789 passed, 0 failed, 12 ignored | [Tests](evidence/workspace-tests.log) |
| `cargo test --locked --bin webprobe repeater_ -- --test-threads=1 --nocapture` | 31 passed, 0 failed | [Real-JVM proof](evidence/after.log) |
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
