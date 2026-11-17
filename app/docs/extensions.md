# WebProbe extension API v1

A WebProbe extension is any program that reads JSON lines on stdin and
writes JSON lines on stdout. Write it in any language. Add it under
Extensions > Installed > Add > "WebProbe (process)" with its command line,
for example:

```
python3 -I extensions/examples/marker_reflection.py
```

The extension list, with its order and enabled flags, is saved in the user
config directory (`extensions.json`, next to `recent-projects.json`). It is
loaded again at start-up. Set `WEBPROBE_NO_EXTENSIONS=1` to skip that.

Montoya `.jar` extensions are a separate path. They run against Burp's own
API classes in a sidecar JVM; choose "Java" in the same dialog.

## Isolation and failure handling

- The extension runs as its own process, started with a cleared environment
  (only `PATH`, `HOME`, `LANG` and `WEBPROBE_EXT_API=1` are set) and the
  system temp directory as its working directory.
- Every call has a 2 s deadline. A call that fails (timeout, bad JSON, exit)
  lets the message through unchanged. After 3 failures in a row, or once the
  process has exited, the extension is stopped and shows as "(stopped)". Its
  hooks then pass everything through.
- stderr lines and protocol errors are kept (last 200) and shown under
  Errors for the extension.
- Calls to one extension are serialized. Different extensions, and the rest
  of the proxy, are not blocked by it.

## Protocol

One JSON object per line in each direction. Binary messages are base64.

### Start-up

WebProbe sends:

```json
{"type":"hello","api":1}
```

The extension answers with its registration:

```json
{"type":"register","api":1,"name":"My extension",
 "hooks":["request","response"],
 "tab":"My tab",
 "issues":[{"name":"Thing found","severity":"low",
            "description":"What it means.","remediation":"How to fix it."}]}
```

| Field | Meaning |
|---|---|
| `api` | Must be 1. Any other value is refused. |
| `name` | Shown in the extension table. |
| `hooks` | Which messages to receive: `request` (before it goes upstream) and/or `response` (before it goes back to the client). |
| `tab` | Optional. Title of the extension's own tab in its detail pane. |
| `issues` | Optional. The issue types it reports (shown under Details). |

### Hooks

```json
{"type":"request","id":7,"method":"GET","path":"/a?b=1","raw":"R0VUIC9hP2I9MSBIVFRQLzEuMQ0K..."}
{"type":"response","id":8,"method":"GET","path":"/a?b=1","raw":"SFRUUC8xLjEgMjAwIE9LDQo..."}
```

Reply with the same `id`:

```json
{"id":7,"action":"continue"}
{"id":7,"action":"continue","raw":"<base64 of the edited message>"}
{"id":7,"action":"drop"}
{"id":8,"action":"continue","issues":[{"name":"Thing found","severity":"low",
  "confidence":"Firm","detail":"Seen in the body."}]}
```

- `raw` replaces the message. Keep Content-Length right if you change a body.
- `drop` stops the message. Later extensions do not run.
- `issues` go to the Dashboard / Target issue list.
  - `severity`: high, medium, low or info.
  - `confidence`: Certain, Firm or Tentative.
  - `host` and `path` default to the message's own.

### Tab

While the extension's tab is open, WebProbe asks for its text about once a
second:

```json
{"type":"tab","id":9}
```

Reply with plain text:

```json
{"id":9,"text":"requests seen: 12"}
```

### Unknown messages

Answer any message carrying an `id` that you don't recognise with
`{"id":N,"action":"continue"}`. That keeps the extension compatible with
later additions to v1.

## Rust extensions

Inside the WebProbe binary, implement `webprobe_core::ext_host::ProxyHooks`
and push a `LoadedExtension::new(...)` into `shared.ext_host`. The trait has
the same surface as the process API: request/response hooks,
`issue_definitions`, `take_issues`, `tab_title`/`tab_content`/`refresh_tab`,
`errors` and `healthy`.
