# WebProbe

A web security testing workbench in Rust, modelled on Burp Suite's workflow. It has an intercepting proxy with HTTPS
interception, plus Target, Repeater, Intruder, Scanner, Sequencer, Decoder, Comparer, Logger, Organizer, Collaborator and
Extensions.

## Layout

| Path | What |
|---|---|
| `core/` | `webprobe-core`: the engine, with no GUI dependency (proxy, TLS MITM, HTTP/2, scanner and checks, Intruder runner, session handling, project files, reports, Collaborator, extensions, headless engines) |
| `src/bin/webprobe-headless.rs` | `webprobe-headless`: `proxy` (records traffic, live passive audit, saves a project) and `scan` (audits URLs, prints JSON issues, writes HTML/XML reports) |
| `src/` | the desktop app (egui 0.37) on top of the engine |
| `extensions/` | extension catalogue and example extensions (see `docs/extensions.md`) |
| `sidecar/` | JVM bridge that runs Burp Montoya `.jar` extensions (one source per API area, run with Java's multi-file source launcher) |
| `docs/` | `extensions.md` (extension API v1), `collaborator-private-server.md` |

## Build and run

From the `app/` directory, install Rust 1.95 or later (including Cargo), a C
compiler and linker, and the platform's desktop development libraries. On
Debian/Ubuntu, for example:

```sh
sudo apt-get install build-essential pkg-config libx11-dev libxi-dev libxcursor-dev libxrandr-dev libgl1-mesa-dev
cargo build --workspace
cargo build --release --bin webprobe
./target/release/webprobe                       # proxy on 127.0.0.1:8080 by default
```

Chromium is needed for browser-based scans; Java 22+ is needed only for
Montoya extensions. `sccache`, an alternative linker, and `wp-queue` are
optional local optimizations, not build prerequisites.

A first start shows the project chooser. Projects are single files (header `WEBPROBE PROJECT 2`) and autosave every
minute, including settings and same-length edits. Autosave writes on a
background thread and retries on the next interval after a failure.

While the app runs, Proxy history keeps message bodies in mapped files under `~/.cache/webprobe`, not in memory. The
files are unlinked as soon as they are created, so nothing is left behind after exit.

Useful environment variables:

| Variable | Effect |
|---|---|
| `WEBPROBE_PORT`, `WEBPROBE_COLLAB_PORT` | proxy and local Collaborator ports (override the project's) |
| `WEBPROBE_TAB=repeater` etc. | open on a tool; also skips the start screen |
| `WEBPROBE_NO_AUTOSAVE=1`, `WEBPROBE_NO_EXTENSIONS=1` | scripted runs |
| `WEBPROBE_CONFIG_DIR` | where recent projects and the extension list live |
| `WEBPROBE_EXTENSIONS_DIR` | extension catalogue location |
| `WEBPROBE_BODY_DIR` | where history bodies are kept while running (default `$XDG_CACHE_HOME/webprobe`; avoid tmpfs) |
| `WEBPROBE_VERIFY_UPSTREAM_TLS=1` | verify upstream certificates, validity and hostnames using WebPKI roots instead of the compatibility default |
| `WEBPROBE_UPSTREAM_CA_FILE` | additional PEM trust roots for verified upstream TLS; requires `WEBPROBE_VERIFY_UPSTREAM_TLS=1` |

External resources (`support/src/paths.rs`). Nothing of PortSwigger's is bundled; where a resource is missing, the
feature that needs it says what is missing, where it looked and how to provide it.

| Variable | Resource | Then tried |
|---|---|---|
| `WEBPROBE_BURP_RESOURCES` | a `resources/` directory extracted from burpsuite.jar (`unzip burpsuite.jar 'resources/*'`) | — |
| `WEBPROBE_KB_DIR` | issue texts for reports | `$WEBPROBE_BURP_RESOURCES/KnowledgeBase/Issues`, `~/.config/webprobe/KnowledgeBase/Issues`, `<data>/KnowledgeBase/Issues` |
| `WEBPROBE_WORDLIST_DIR` | content discovery wordlists (`*.pay`) | `…/PayloadStrings` in the same places |
| `WEBPROBE_RETIREJS` | a retire.js `jsrepository.json` | `…/RetireJS/retirejs_repository.json` or `jsrepository.json` in the same places |
| `WEBPROBE_BURP_JAR` | Montoya API classes for Java extensions (burpsuite.jar or montoya-api.jar; not shipped, its licence is PortSwigger's) | `~/.config/webprobe/montoya-api.jar`, `~/.m2/.../montoya-api/<newest>/`, `$WEBPROBE_BURP_HOME`, `/opt/BurpSuite*`, `~/BurpSuite*` |
| `WEBPROBE_JAVA` | `java` 22+ for Java (Montoya) extensions | `$JAVA_HOME/bin/java`, `java` on `$PATH` |
| `WEBPROBE_CHROMIUM`, `WEBPROBE_BURP_BROWSER` | browser for the crawler / Open browser | `/usr/bin/chromium` etc., Burp's `burpbrowser/` |
| `WEBPROBE_DATA_DIR` | where WebProbe writes out its own embedded files (Montoya bridge, extension catalogue) | `$XDG_DATA_HOME/webprobe`, `~/.local/share/webprobe` |

SIGTERM or SIGINT closes the app through the normal save path. If the final
save fails, the recovery marker is retained instead of reporting a clean exit.

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
cargo test --workspace --locked                  # engine + desktop suites
../scripts/ci.sh                                 # gates, headless binary, MCP and vendored server tests
# Optional: WP_QUEUE=wp-queue ../scripts/ci.sh
```

The suites include parser fuzzing (3000 seeded cases) and a live-proxy test with hostile connections.

[egui-mcp]: https://github.com/dijdzv/egui-mcp

### Real Burp application smoke test

`WEBPROBE_BURP_JAR` remains the Montoya extension API source. The library
smoke uses only `WEBPROBE_BURP_APP_JAR` (the full application jar) or
`WEBPROBE_BURP_BUILTINS` (an extracted BuiltInConfigs tree with sibling
Preferences). Explicit missing or wrong paths fail. Without either source,
the optional smoke prints `BURP_APP_SMOKE_NOT_RUN`. Set
`WEBPROBE_REQUIRE_BURP_APP=1` for a required gate; it fails if no source is
configured and prints `BURP_APP_SMOKE_EXECUTED` only after loading succeeds.

Run `python3 scripts/test-burp-app-smoke.py PATH_TO_CORE_TEST_BINARY` to
exercise variable isolation and valid/invalid resource fixtures. Synthetic
fixtures test the harness, not compatibility with an actual Burp release.

### Options import and startup settings

Project and user options imports update stored settings and scan settings.
They do not live-rebind an already running proxy listener or restart an
already running REST server. Restart WebProbe for changed listener address,
port, API keys or API enable/disable settings to replace an existing server.
Enabling an API for the first time can start it immediately.
Headless `--project` and `--project-file` are aliases; the last occurrence
in argument order wins, including repeated uses of the same alias. Headless
proxy output must use a new path: an existing project is never overwritten,
since the headless proxy does not restore all of its desktop state.

### Security and coverage notes

The REST API serves plain HTTP and places API keys in URL paths, including the
returned Location header. Prefer a loopback listener; if remote access is
necessary, use authenticated TLS termination and take care not to log
credential-bearing URLs. Never expose an insecure-mode listener to an
untrusted network.

By default, target TLS certificates are not verified (including hostname and
expiry), to allow testing self-signed targets. This exposes credentials and
traffic to a network attacker. Set `WEBPROBE_VERIFY_UPSTREAM_TLS=1` to require
normal verification, and optionally add private CA roots through
`WEBPROBE_UPSTREAM_CA_FILE`. Invalid configuration fails closed. The local
MITM CA directory should be accessible only to its owner.

The issue-type gate measures source-code **name coverage**, not confirmed
runtime detection. In particular, stored DOM-based submission is currently
disabled to avoid authenticated state changes; the presence of those issue
names does not mean they can be raised. Behavioural lab tests are needed to
establish actual detection.
