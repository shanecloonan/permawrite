#!/usr/bin/env bash
# B-93 wrapper — delegates to post-push-ci-watch.py
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/post-push-ci-watch.py" "$@"
