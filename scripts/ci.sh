#!/usr/bin/env bash
# ci.sh — the project's CI gate, run locally (the tree has no hosted CI).
#
# Steps, each through wp-queue so it never fights other builds on this box:
#   1. engine and desktop test suites (parsers: chunked, gzip/brotli, keep-alive,
#      HTTP/2, TLS MITM, proxy; fuzz_tests' 3000 seeded malformed inputs)
#   2. headless binary builds without GUI libraries (layering test guards it)
#   3. the desktop app builds with the egui MCP automation feature
#   4. the vendored egui-mcp-server's tests
# Exit status is the first failing step's; a summary line per step is printed.
#
# Usage: scripts/ci.sh            run everything
#        CI_SKIP_MCP=1 scripts/ci.sh   skip steps 3-4
set -uo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
APP="$ROOT/app"
Q=${WP_QUEUE:-wp-queue}
status=0
step() {
    local name=$1; shift
    local log; log=$(mktemp -t ci-XXXX.log)
    local t0=$SECONDS
    if "$@" >"$log" 2>&1; then
        printf 'ok    %-34s %4ss  %s\n' "$name" $((SECONDS - t0)) "$(grep -E '^tests:' "$log" | head -1 | cut -c11-)"
    else
        printf 'FAIL  %-34s %4ss  (log: %s)\n' "$name" $((SECONDS - t0)) "$log"
        grep -E '^errors:|error\[|panicked|FAILED' "$log" | head -10 | sed 's/^/      /'
        [ $status -eq 0 ] && status=1
    fi
}

step "architecture ratchet self-test" python3 "$ROOT/scripts/test-arch-gate.py"
step "architecture ratchet (ADR 0002)" python3 "$ROOT/scripts/arch-gate.py"
step "issue-type coverage (F-08)" python3 "$ROOT/scripts/issue-coverage.py"
step "test suites (core + desktop)" env WP_APP_DIR="$APP" "$Q" test
step "headless engine binary" env WP_APP_DIR="$APP" "$Q" run -- cargo build --bin webprobe-headless
if [ -z "${CI_SKIP_MCP:-}" ]; then
    step "desktop with egui MCP" env WP_APP_DIR="$APP" "$Q" run -- cargo build --features mcp
    step "vendored egui-mcp-server tests" env WP_APP_DIR="$ROOT/vendor/egui-mcp-server" "$Q" test
fi
exit $status
