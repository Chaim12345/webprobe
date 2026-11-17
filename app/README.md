# WebProbe

A web security testing workbench in Rust, modelled on Burp Suite's workflow. It has an intercepting proxy with HTTPS
interception, plus Target, Repeater, Intruder, Scanner, Sequencer, Decoder, Comparer, Logger, Organizer, Collaborator and
Extensions.

## Layout

| Path | What |
|---|---|
| `core/` | `webprobe-core`: the engine, with no GUI dependency (proxy, TLS MITM, HTTP/2, scanner and checks, Intruder runner, session handling, project files, reports, Collaborator, extensions, headless engines) |
| `core/src/bin/webprobe-headless.rs` | `webprobe-headless`: `proxy` (records traffic, live passive audit, saves a project) and `scan` (audits URLs, prints JSON issues, writes HTML/XML reports) |
| `src/` | the desktop app (egui 0.37) on top of the engine |
| `extensions/` | extension catalogue and example extensions (see `docs/extensions.md`) |
| `sidecar/` | JVM bridge that runs Burp Montoya `.jar` extensions |
| `docs/` | `extensions.md` (extension API v1), `collaborator-private-server.md` |

## Build and run

Cargo jobs on this machine go through the shared queue:

```
WP_APP_DIR=$PWD wp-queue build                  # desktop app + engine (debug)
WP_APP_DIR=$PWD wp-queue run -- cargo build --release
./target/release/webprobe                        # proxy listener on 127.0.0.1:8080 by default
```

A first start shows the project chooser. Projects are single files (header `WEBPROBE PROJECT 2`) and autosave every
minute when they change.

Useful environment variables:

| Variable | Effect |
|---|---|
| `WEBPROBE_PORT`, `WEBPROBE_COLLAB_PORT` | proxy and local Collaborator ports (override the project's) |
| `WEBPROBE_TAB=repeater` etc. | open on a tool; also skips the start screen |
| `WEBPROBE_NO_AUTOSAVE=1`, `WEBPROBE_NO_EXTENSIONS=1` | scripted runs |
| `WEBPROBE_CONFIG_DIR` | where recent projects and the extension list live |
| `WEBPROBE_EXTENSIONS_DIR` | extension catalogue location |

SIGTERM or SIGINT closes the app cleanly: the project is saved and no crash-recovery prompt appears next time.

## UI automation

Build with `--features mcp` to drive the app through [egui-mcp]. The vendored server and client are in
`../vendor/egui-mcp-{server,client}`. The app publishes its widget tree and accepts:

- clicks and drags;
- typed text and named keys (`Enter`, `ctrl+a`);
- screenshots;
- frame statistics.

`EGUI_MCP_SOCKET` gives each instance its own socket.

## Tests and CI

```
WP_APP_DIR=$PWD wp-queue test                    # engine + desktop suites
../scripts/ci.sh                                 # suites, headless binary, MCP build, vendored server tests
```

The suites include parser fuzzing (3000 seeded cases) and a live-proxy test with hostile connections.

[egui-mcp]: https://github.com/dijdzv/egui-mcp
