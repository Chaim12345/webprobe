#!/usr/bin/env bash
# Live-window QA driver for WebProbe on a private Xvfb. One tool for the whole
# loop, so an agent (or a human) never has to remember display numbers, window
# ids or env fixes.
#
#   qa.sh up [VAR=val ...]    start Xvfb (GLX) + openbox if needed, launch WebProbe on proxy
#                             port 6566 (QA_PORT) and collaborator port 6567 (QA_COLLAB_PORT),
#                             wait until its window is mapped
#                             e.g. qa.sh up WEBPROBE_TAB=proxy WEBPROBE_PROXY_SUB=1 WEBPROBE_SEED_HISTORY=200
#   qa.sh down                stop the app (Xvfb stays up for reuse)
#   qa.sh info                window id, size, process state, how many colours are on screen
#   qa.sh shot NAME           window screenshot -> $QA_SHOTS/NAME.png (prints the path)
#   qa.sh click X Y           left click          (also: dclick, rclick, move)
#   qa.sh drag X1 Y1 X2 Y2    press, glide, release (splitters, column resize)
#   qa.sh type TEXT...        type into the focused widget
#   qa.sh key COMBO...        xdotool key syntax: Return Escape Tab ctrl+k ctrl+shift+f ...
#   qa.sh scroll up|down N [X Y]   wheel notches, optionally at a point
#
# Coordinates are the window's own pixels: whatever you read off a `shot` is
# exactly where `click` lands. Why the env fix is not needed here: the app
# repairs its own renderer environment (src/gl_env.rs).

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DISP="${QA_DISPLAY:-:97}"
SCREEN="${QA_SCREEN:-1920x1080x24}"
SHOTS="${QA_SHOTS:-/root/webprobe-shots}"
BIN="${QA_BIN:-$ROOT/app/target/debug/webprobe}"
LOG="${QA_LOG:-/tmp/webprobe-qa.log}"
WIDFILE=/tmp/webprobe-qa.wid
export DISPLAY="$DISP"

x_up() { xdpyinfo >/dev/null 2>&1; }

ensure_x() {
  if ! x_up; then
    (Xvfb "$DISP" -screen 0 "$SCREEN" -nolisten tcp -ac +extension GLX +extension XTEST \
        +extension RANDR +render -noreset >/tmp/webprobe-xvfb.log 2>&1 &)
    for _ in $(seq 1 20); do x_up && break; sleep 0.5; done
    x_up || { echo "Xvfb $DISP did not start, see /tmp/webprobe-xvfb.log" >&2; exit 1; }
  fi
  # A window manager gives the app real focus, which keyboard input needs.
  if ! xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null | grep -q 'window id'; then
    (openbox >/tmp/webprobe-openbox.log 2>&1 &)
    sleep 1
  fi
}

find_wid() { xdotool search --onlyvisible --name '^WebProbe$' 2>/dev/null | head -1; }

wid() {
  local w
  w=$(cat "$WIDFILE" 2>/dev/null || true)
  if [ -z "$w" ] || ! xwininfo -id "$w" >/dev/null 2>&1; then
    w=$(find_wid)
    [ -n "$w" ] && echo "$w" >"$WIDFILE"
  fi
  [ -n "$w" ] || { echo "no WebProbe window on $DISP; run: qa.sh up" >&2; return 1; }
  echo "$w"
}

app_pid() { pgrep -f 'debug/webprobe$' | head -1; }

cmd_up() {
  ensure_x
  pkill -f 'debug/webprobe$' 2>/dev/null
  sleep 1
  rm -f "$WIDFILE"
  [ -x "$BIN" ] || { echo "build first: (cd $ROOT/app && cargo build)" >&2; exit 1; }
  # Test ports, never the defaults: 8080/8081 belong to working tools on this
  # machine. Later assignments win, so an explicit VAR=val argument overrides.
  env WEBPROBE_PORT="${QA_PORT:-6566}" WEBPROBE_COLLAB_PORT="${QA_COLLAB_PORT:-6567}" \
      "$@" setsid nohup "$BIN" >"$LOG" 2>&1 </dev/null &
  local w="" start=$SECONDS
  while [ $((SECONDS - start)) -lt 60 ]; do
    w=$(find_wid)
    [ -n "$w" ] && break
    if [ -z "$(app_pid)" ]; then
      echo "app exited before mapping a window:" >&2
      tail -8 "$LOG" >&2
      exit 1
    fi
    sleep 1
  done
  [ -n "$w" ] || { echo "no window after 60s; log tail:" >&2; tail -8 "$LOG" >&2; exit 1; }
  echo "$w" >"$WIDFILE"
  sleep 2 # let the first frames settle
  xdotool windowfocus "$w" 2>/dev/null
  echo "up: window $w, $(xwininfo -id "$w" | awk '/Width:/{w=$2} /Height:/{h=$2} END{print w"x"h}') on $DISP, mapped in $((SECONDS - start))s"
}

cmd_down() { pkill -f 'debug/webprobe$' 2>/dev/null && echo "stopped" || echo "was not running"; rm -f "$WIDFILE"; }

cmd_info() {
  local w
  w=$(wid) || exit 1
  xwininfo -id "$w" | awk '/Absolute upper-left X|Absolute upper-left Y|Width:|Height:/'
  echo "pid: $(app_pid)  display: $DISP  window: $w"
  import -window "$w" /tmp/webprobe-qa-info.png 2>/dev/null &&
    python3 -I -c "from PIL import Image; im=Image.open('/tmp/webprobe-qa-info.png').convert('RGB'); print('colours on screen:', len(im.getcolors(500000) or []))"
}

cmd_shot() {
  local name="${1:?usage: qa.sh shot NAME}" w
  w=$(wid) || exit 1
  mkdir -p "$SHOTS"
  import -window "$w" "$SHOTS/$name.png" && echo "$SHOTS/$name.png"
}

cmd_move() { xdotool mousemove --window "$(wid)" "${1:?x}" "${2:?y}"; }

cmd_click() {
  local w; w=$(wid) || exit 1
  xdotool mousemove --window "$w" "${1:?x}" "${2:?y}"
  sleep 0.15 # egui needs a hover frame before the press
  xdotool mousedown "${3:-1}"; sleep 0.08; xdotool mouseup "${3:-1}"
  sleep 0.3
}

cmd_dclick() {
  local w; w=$(wid) || exit 1
  xdotool mousemove --window "$w" "${1:?x}" "${2:?y}"; sleep 0.15
  xdotool click --repeat 2 --delay 90 1; sleep 0.3
}

cmd_rclick() { cmd_click "$1" "$2" 3; }

cmd_drag() {
  local w x1="${1:?x1}" y1="${2:?y1}" x2="${3:?x2}" y2="${4:?y2}"
  w=$(wid) || exit 1
  xdotool mousemove --window "$w" "$x1" "$y1"; sleep 0.15
  xdotool mousedown 1; sleep 0.1
  for i in 1 2 3 4 5 6 7 8; do
    xdotool mousemove --window "$w" $((x1 + (x2 - x1) * i / 8)) $((y1 + (y2 - y1) * i / 8))
    sleep 0.04
  done
  xdotool mouseup 1; sleep 0.3
}

cmd_type() { local w; w=$(wid) || exit 1; xdotool windowfocus "$w" 2>/dev/null; xdotool type --delay 40 -- "$*"; sleep 0.3; }
cmd_key() { local w; w=$(wid) || exit 1; xdotool windowfocus "$w" 2>/dev/null; xdotool key --delay 60 -- "$@"; sleep 0.3; }

cmd_scroll() {
  local dir="${1:?up|down}" n="${2:-3}" btn=5
  [ "$dir" = up ] && btn=4
  if [ $# -ge 4 ]; then cmd_move "$3" "$4"; sleep 0.1; fi
  xdotool click --repeat "$n" --delay 60 "$btn"; sleep 0.3
}

sub="${1:-}"; [ $# -gt 0 ] && shift
case "$sub" in
  up) cmd_up "$@" ;;
  down) cmd_down ;;
  info) cmd_info ;;
  shot) cmd_shot "$@" ;;
  move) cmd_move "$@" ;;
  click) cmd_click "$@" ;;
  dclick) cmd_dclick "$@" ;;
  rclick) cmd_rclick "$@" ;;
  drag) cmd_drag "$@" ;;
  type) cmd_type "$@" ;;
  key) cmd_key "$@" ;;
  scroll) cmd_scroll "$@" ;;
  *) sed -n '2,22p' "${BASH_SOURCE[0]}"; exit 2 ;;
esac
