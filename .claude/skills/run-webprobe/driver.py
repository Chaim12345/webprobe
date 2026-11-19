#!/usr/bin/env python3
"""Drive the WebProbe desktop app (egui) headlessly. Stdlib only.

The app, built with `--features mcp`, listens on a unix socket (EGUI_MCP_SOCKET) and speaks a tiny protocol:
4-byte big-endian length + JSON ({"type": "Ping"}, {"type": "ClickAt", ...}). This script launches Xvfb and the
app, and sends one request per invocation. Run from the repo root:

  python3 .claude/skills/run-webprobe/driver.py launch [tab]     # start Xvfb + app, wait until it answers
  python3 .claude/skills/run-webprobe/driver.py ss out.png       # screenshot of the app window
  python3 .claude/skills/run-webprobe/driver.py click X Y [left|right|middle]
  python3 .claude/skills/run-webprobe/driver.py key Enter        # also "ctrl+a", "Tab", a single character
  python3 .claude/skills/run-webprobe/driver.py scroll X Y DX DY
  python3 .claude/skills/run-webprobe/driver.py ping | logs | stats
  python3 .claude/skills/run-webprobe/driver.py quit             # SIGTERM: saves nothing (autosave off) and exits
Coordinates are in the app window's own pixels (see the screenshot size).
"""
import base64, json, os, signal, socket, struct, subprocess, sys, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
APP = os.environ.get("WEBPROBE_BIN", os.path.join(ROOT, "app", "target", "debug", "webprobe"))
SOCK = os.environ.get("EGUI_MCP_SOCKET", "/tmp/webprobe-mcp.sock")
DISPLAY = os.environ.get("WP_DISPLAY", ":99")
STATE = "/tmp/webprobe-driver"  # pid files and the app log


def rpc(req, timeout=30):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(timeout)
    s.connect(SOCK)
    body = json.dumps(req).encode()
    s.sendall(struct.pack(">I", len(body)) + body)
    hdr = b""
    while len(hdr) < 4:
        chunk = s.recv(4 - len(hdr))
        if not chunk:
            raise SystemExit("connection closed before a reply")
        hdr += chunk
    n = struct.unpack(">I", hdr)[0]
    buf = b""
    while len(buf) < n:
        chunk = s.recv(min(65536, n - len(buf)))
        if not chunk:
            raise SystemExit("connection closed mid-reply")
        buf += chunk
    s.close()
    return json.loads(buf)


def ok(resp):
    if resp.get("type") == "Error":
        raise SystemExit("app error: " + resp.get("message", "?"))
    return resp


def launch(tab):
    os.makedirs(STATE, exist_ok=True)
    if not os.path.exists(APP):
        raise SystemExit(f"{APP} missing: build first (cd app && cargo build --features mcp)")
    xvfb = subprocess.Popen(["Xvfb", DISPLAY, "-screen", "0", "1600x1000x24", "-nolisten", "tcp"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    open(f"{STATE}/xvfb.pid", "w").write(str(xvfb.pid))
    time.sleep(1)
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    env = dict(os.environ, DISPLAY=DISPLAY, EGUI_MCP_SOCKET=SOCK, LIBGL_ALWAYS_SOFTWARE="1",
               WEBPROBE_NO_AUTOSAVE="1", WEBPROBE_NO_EXTENSIONS="1", WEBPROBE_TAB=tab,
               WEBPROBE_PORT=os.environ.get("WEBPROBE_PORT", "18080"),
               WEBPROBE_COLLAB_PORT=os.environ.get("WEBPROBE_COLLAB_PORT", "18081"),
               WEBPROBE_CONFIG_DIR=f"{STATE}/config", WEBPROBE_BODY_DIR=f"{STATE}/bodies",
               WEBPROBE_DATA_DIR=f"{STATE}/data", XDG_RUNTIME_DIR=STATE)
    log = open(f"{STATE}/app.log", "w")
    app = subprocess.Popen([APP], env=env, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT, start_new_session=True)
    open(f"{STATE}/app.pid", "w").write(str(app.pid))
    for _ in range(120):
        if app.poll() is not None:
            raise SystemExit(f"app exited with {app.returncode}; see {STATE}/app.log")
        try:
            if rpc({"type": "Ping"}, timeout=2).get("type") == "Pong":
                print("up: pid", app.pid, "display", DISPLAY, "socket", SOCK)
                return
        except (OSError, SystemExit):
            pass
        time.sleep(0.5)
    raise SystemExit(f"no answer on {SOCK} after 60 s; see {STATE}/app.log")


def quit_all():
    for name in ("app", "xvfb"):
        try:
            pid = int(open(f"{STATE}/{name}.pid").read())
            os.killpg(pid, signal.SIGTERM)
        except (FileNotFoundError, ProcessLookupError, ValueError):
            pass
    print("stopped")


def main(a):
    if not a:
        print(__doc__)
        return
    c, rest = a[0], a[1:]
    if c == "launch":
        launch(rest[0] if rest else "proxy")
    elif c == "ss":
        r = ok(rpc({"type": "TakeScreenshot"}))
        out = rest[0] if rest else "/tmp/webprobe.png"
        open(out, "wb").write(base64.b64decode(r["data"]))
        print(out)
    elif c == "click":
        btn = (rest[2] if len(rest) > 2 else "left").capitalize()
        print(ok(rpc({"type": "ClickAt", "x": float(rest[0]), "y": float(rest[1]), "button": btn}))["type"])
    elif c == "key":
        print(ok(rpc({"type": "KeyboardInput", "key": rest[0]}))["type"])
    elif c == "scroll":
        x, y, dx, dy = map(float, rest[:4])
        print(ok(rpc({"type": "Scroll", "x": x, "y": y, "delta_x": dx, "delta_y": dy}))["type"])
    elif c == "ping":
        print(ok(rpc({"type": "Ping"}))["type"])
    elif c == "logs":
        for e in ok(rpc({"type": "GetLogs", "level": None, "limit": 50})).get("entries", []):
            print(e)
    elif c == "stats":
        print(json.dumps(ok(rpc({"type": "GetFrameStats"})), indent=1))
    elif c == "quit":
        quit_all()
    else:
        raise SystemExit("unknown command; run without arguments for help")


if __name__ == "__main__":
    main(sys.argv[1:])
