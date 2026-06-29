#!/usr/bin/env bash
# Generate release artifact inventory checksum rows.
set -euo pipefail

if (($# == 0)); then
  echo "artifact-checksums: pass one or more file paths" >&2
  exit 1
fi

echo "| Path | SHA-256 | Bytes |"
echo "| --- | --- | ---: |"
for path in "$@"; do
  if [[ ! -f "$path" ]]; then
    echo "artifact-checksums: missing file $path" >&2
    exit 1
  fi
  abs_path="$(python3 - "$path" <<'PY'
import os
import sys

print(os.path.abspath(sys.argv[1]))
PY
)"
  hash="$(sha256sum "$path" | awk '{print $1}')"
  bytes="$(python3 - "$path" <<'PY'
import os
import sys

print(os.path.getsize(sys.argv[1]))
PY
)"
  echo "| \`$abs_path\` | \`$hash\` | $bytes |"
done
