# AR-09 — bytes vs lossy text in Repeater/Intruder tool state

Pin: `692f09728039884c59a676ff314879c06dcb1cf5`. New test only:
`app/core/tests/ar09_binary_tool_state.rs`. No production code edited.

## Trace: history bytes → socket write

| Step | Site |
|---|---|
| raw capture | `HistEntry.req_raw: Vec<u8>` |
| lossy conversion | `app/src/ui/actions.rs:204` — `String::from_utf8_lossy(&util::origin_form(raw))` inside `request_for_tools` (203-214) |
| Repeater tab | `app/src/ui/actions.rs:234` — `request: request_for_tools(&e.req_raw)`; `RepTab.request: String` (`core/src/net/types.rs:318`) |
| Repeater send | `app/src/repeater_ops.rs:502` `send_once(..., req: &mut String, ...)` → `:514` `let mut bytes = req.as_bytes().to_vec()` → `:532/534` `send_tls_raw_with`/`send_raw_with` → socket (`core/src/net/send.rs:10,17`) |
| Intruder template | `app/src/ui/actions.rs:298` and `app/src/tools.rs:2818` — `request_for_tools(...)`; `Attack.request: String` (`core/src/intruder.rs:187`), payloads `&str` |
| Intruder send | `core/src/intruder_run.rs:1054` — `update_content_length(request.as_bytes())` (CL recomputed from the lossy text) |

The extension branch of `send_once` (`repeater_ops.rs:514-523`) keeps the exact bytes for
transport but still stores the lossy text in `*req` — the comment there says so.

## Executed evidence (loopback only)

```
cargo test -p webprobe-core --test ar09_binary_tool_state --locked -- --nocapture
  test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Control (transport is byte-clean):
```
sent     : ... 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 36 0d 0a 0d 0a 00 ff fe 00 c3 28
received : ... Content-Length: 6 \r\n Connection: close \r\n \r\n 00 ff fe 00 c3 28
```
Only `Connection: close` is added; the 6 body bytes are intact.

Characterisation of the tool-state conversion (exact production expression):
```
original body    : 00 ff fe 00 c3 28                     (6 bytes)
stored text body : 00 ef bf bd ef bf bd 00 ef bf bd 28   (12 bytes)
Content-Length header: 6   actual body: 12
```
NUL survives (valid UTF-8). Every invalid byte becomes U+FFFD (`ef bf bd`).

## Consequence

- **Repeater**: Content-Length is not recomputed, so the wire request declares 6 and carries 12
  bytes. A server reads 6 bytes of body; the remaining 6 desync the next request on a reused
  connection. The captured request is no longer the request sent.
- **Intruder**: CL is recomputed (`intruder_run.rs:1054`), so it stays consistent, but the bytes
  still differ from the capture, and binary payloads cannot be expressed at all (`&str`).
- NUL bytes are fine; only invalid UTF-8 is lossy.

## Minimal fix proposal (for review; not applied)

1. Keep the captured bytes: add `raw: Option<Vec<u8>>` to `RepTab`, set by
   `send_entry_to_repeater` (`actions.rs:234`). In `send_once`, send `raw` when the editor text
   still equals `String::from_utf8_lossy(raw)` (unedited), else send the edited text bytes.
2. Clear `raw` on any edit (`ui/repeater.rs` text change) so an edited tab behaves as today.
3. Intruder needs its own change (bytes template or a hex payload mode); that is a larger
   redesign and is out of this scope.
4. No parser rewrite and no text-loss removal: the text editor stays; the bytes are preserved
   beside it.

Limitations: the app crate has no library target, so the app-layer conversion cannot be driven
from a core integration test; the characterisation test applies the exact production expression
(`String::from_utf8_lossy(...).into_owned().into_bytes()`) over the real socket path instead.
Intruder's send path was audited, not executed.
