#!/usr/bin/env bash
# Usage: run_juice.sh <app-dir> <out-dir>. Crawl-and-audit of Juice Shop
# through the counting forwarder on 127.0.0.1:3101.
set -u
APP=$1; OUT=$2; mkdir -p "$OUT"
COUNT=/root/webprobe-parity/parity-2026-11-18/after-d09/requests.count
cp "$COUNT" "$OUT/count.start"
cd "$APP" && WB_JUICE=127.0.0.1:3101 WB_OUT="$OUT" WP_APP_DIR="$APP" WP_QUEUE_TIMEOUT=3500 \
  wp-queue test -p webprobe-core live_juice_crawl_scan -- --include-ignored > "$OUT/run.log" 2>&1
cp "$COUNT" "$OUT/count.end"
echo "requests: $(( $(cat "$OUT/count.end") - $(cat "$OUT/count.start") ))" | tee "$OUT/requests.txt"
