#!/usr/bin/env bash
# ci.sh — run the project gates locally with plain Cargo by default.
#
# Steps (set WP_QUEUE to opt in to a local build queue):
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

cargo_in() {
    local dir=$1; shift
    if [ -n "${WP_QUEUE:-}" ]; then
        env WP_APP_DIR="$dir" "$WP_QUEUE" run -- cargo "$@"
    else
        (cd "$dir" && cargo "$@")
    fi
}

step "architecture ratchet self-test" python3 "$ROOT/scripts/test-arch-gate.py"
step "architecture ratchet (ADR 0002)" python3 "$ROOT/scripts/arch-gate.py"
step "issue-type coverage (F-08)" python3 "$ROOT/scripts/issue-coverage.py"
step "test suites (core + desktop)" cargo_in "$APP" test --workspace --locked
step "headless engine binary" cargo_in "$APP" build --locked --bin webprobe-headless
if [ -z "${CI_SKIP_MCP:-}" ]; then
    step "desktop with egui MCP" cargo_in "$APP" build --locked --features mcp
    step "vendored egui-mcp-server tests" cargo_in "$ROOT/vendor/egui-mcp-server" test
fi
exit $status
