#!/usr/bin/env bash
# B-34 wrapper — delegates to watch-ci-stall.py
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/watch-ci-stall.py" "$@"
