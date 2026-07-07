#!/usr/bin/env bash
# B7: short public-devnet soak with Dandelion++ relay enabled (local rehearsal).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/soak.sh" --dandelion "$@"
