#!/usr/bin/env bash
# Cache contents are untrusted. Verify on every use, including cache hits.
set -euo pipefail
url=$1
expected=$2
destination=$3
if [[ -e "$destination" || -L "$destination" ]]; then
  [[ -f "$destination" && -r "$destination" && ! -L "$destination" ]]
  printf '%s  %s\n' "$expected" "$destination" | sha256sum --check -
  echo 'Verified existing Montoya API; download skipped.'
else
  temporary=$(mktemp "${destination}.download.XXXXXX")
  trap 'rm -f "$temporary"' EXIT
  curl --fail --location --retry 3 "$url" -o "$temporary"
  printf '%s  %s\n' "$expected" "$temporary" | sha256sum --check -
  mv "$temporary" "$destination"
  echo 'Downloaded and verified pinned Montoya API.'
fi
