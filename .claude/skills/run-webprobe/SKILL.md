---
name: run-webprobe
description: Build, launch, drive and screenshot the WebProbe desktop app (Rust/egui web security workbench), run its headless scanner, or run its tests. Use when asked to run, start, build, test, screenshot or click through WebProbe, or to confirm a UI or proxy change works in the real app.
---

# Run WebProbe

WebProbe is a Burp-style workbench in Rust: `app/core` (engine, headless binary `webprobe-headless`) and `app/src`
(egui desktop app). The desktop app has no useful headless mode, so it is driven through its built-in automation
socket: build with `--features mcp`, run under Xvfb, and send requests with `driver.py` (stdlib Python, no MCP client
needed). All paths below are relative to the repo root. Verified in a headless Ubuntu container on 2026-11-19.

## Prerequisites

Runtime libraries for the GUI under Xvfb (installed together; the crash named `libxkbcommon-x11`, the rest are
the usual GL/X11 companions), plus Xvfb itself:

```bash
apt-get update -q && apt-get install -y -q xvfb libxkbcommon-x11-0 libgl1 libegl1 libgl1-mesa-dri libxcursor1 libxrandr2 libxi6
```

`app/.cargo/config.toml` pins a machine-local `rustc`, `sccache` and `ld.lld-22`, which do not exist on a fresh
machine. Override them with env vars (an empty `RUSTFLAGS` replaces the linker flags) for every cargo command here:

```bash
export CARGO_BUILD_RUSTC=rustc CARGO_BUILD_RUSTC_WRAPPER= RUSTFLAGS=""
```

## Build

```bash
cd app && cargo build --features mcp          # first build took 5m45s; later ones are incremental
cargo build -p webprobe-core --bin webprobe-headless   # headless engine binary, seconds once core is built
cd ..
```

Outputs: `app/target/debug/webprobe` and `app/target/debug/webprobe-headless`.

## Run (agent path): desktop app via the driver

`driver.py` starts Xvfb on `:99` and the app (autosave, extensions and config isolated under
`/tmp/webprobe-driver`, proxy on port 18080, Collaborator on 18081), then sends one request per call.

```bash
D=.claude/skills/run-webprobe/driver.py
python3 $D launch proxy            # prints "up: pid ..." when the app answers; optional tab name instead of proxy
python3 $D ss /tmp/webprobe.png    # screenshot of the app window (1440x900 here); look at it
python3 $D click 300 191           # window pixels; also: click X Y right
python3 $D key Tab                 # also Enter, Escape, "ctrl+a", single characters
python3 $D scroll 700 300 0 3      # x y dx dy
python3 $D stats                   # frame statistics (fps, frame time)
python3 $D quit                    # SIGTERM to the app and Xvfb
```

`logs` is also accepted but returned nothing in my run. `python3 $D` with no arguments prints the help.

### Worked flow: proxy a request and inspect it in HTTP history

```bash
D=.claude/skills/run-webprobe/driver.py
echo '<html><title>lab</title><body>hello webprobe</body></html>' > /tmp/hello.html
(cd /tmp && python3 -m http.server 18090 --bind 127.0.0.1 >/dev/null 2>&1 &)
python3 $D launch proxy
curl -s --noproxy '' -x http://127.0.0.1:18080 http://127.0.0.1:18090/hello.html   # --noproxy '' is required, see Gotchas
python3 $D click 1315 127          # turn the history filter off (it is on by default)
python3 $D click 300 191           # select row 1; request and response appear below
python3 $D ss /tmp/webprobe.png    # row "GET /hello.html 200", request and response panes filled
python3 $D quit; pkill -f "http.server 18090"
```

Coordinates above are for the Proxy > HTTP history layout at 1440x900; take a screenshot first and read positions
from it, they change between tabs.

## Run (agent path): headless scanner

No GUI and no Xvfb needed. Prints one JSON issue per line, then a summary:

```bash
(cd /tmp && python3 -m http.server 18090 --bind 127.0.0.1 >/dev/null 2>&1 &)
app/target/debug/webprobe-headless scan http://127.0.0.1:18090/hello.html --speed fast
```

Output on the lab above: two issues ("HTML does not specify charset", "Unencrypted communications") in 0.5 s. A
warning that no retire.js repository was found is normal; set `WEBPROBE_RETIREJS` to silence it.

## Tests

```bash
cd app && cargo test -p webprobe-core --lib scan_library    # 6 tests, instant once built; omit the filter for all 657
```

`scripts/ci.sh` is the project's own gate, but it goes through `wp-queue`, which only exists on the original box.

## Run (human path)

`cd app && cargo run --features mcp` (or the release binary) opens a window and the project chooser. Useless
headless. Env vars (`WEBPROBE_TAB`, `WEBPROBE_PORT`, `WEBPROBE_NO_AUTOSAVE`, ...) are listed in `app/README.md`.

## Gotchas

- **`no_proxy` swallows localhost.** This sandbox sets `no_proxy` to include `127.0.0.1`, so a plain
  `curl -x http://127.0.0.1:18080 http://127.0.0.1:...` bypasses the proxy and history stays empty ("no matching
  entries") although curl prints the page. Pass `--noproxy ''`.
- **History filter is on by default** ("Hiding CSS and image content; hiding specific extensions"). If a request
  is missing, toggle it (click at 1315,127) before assuming the proxy lost it.
- **Screenshots are the app window, not the Xvfb screen** (1440x900 inside a 1600x1000 display), and coordinates
  for `click` are window pixels.
- **The app only repaints on events**, so take the screenshot a moment (about 1 s) after the action.
- **Default ports**: the driver forces 18080/18081 so it will not collide with a real instance on 8080; override
  with `WEBPROBE_PORT` / `WEBPROBE_COLLAB_PORT` in your shell before `launch`.
- `quit` leaves Xvfb as a defunct (zombie) entry in `ps` until the shell exits; harmless.
- The window title shows `webprobe-project.json` but nothing is written: the driver sets `WEBPROBE_NO_AUTOSAVE=1`.
- `ss` (the socket tool) is not installed here, so do not rely on it to check listeners.

## Troubleshooting

- `Library libxkbcommon-x11.so could not be loaded` (app exits with 101 right after launch, in
  `/tmp/webprobe-driver/app.log`): install the packages under Prerequisites.
- `app exited with ...; see /tmp/webprobe-driver/app.log`: read that log; it is the app's stdout and stderr.
- `no answer on /tmp/webprobe-mcp.sock after 60 s`: the binary was built without `--features mcp`. Rebuild with it.
- `connection refused` from `ss`/`click` when nothing is running: run `launch` first.
- Build error about `/usr/local/bin/rustc` or `ld.lld-22` not found: the env overrides under Prerequisites are
  missing in this shell.
