#!/usr/bin/env bash
# Lane 7 / TL-4: start full public-devnet mesh on one Linux VPS (public P2P, loopback RPC).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export MFN_VPS_MODE=1
export MFN_VPS_BIND_FILE="${MFN_VPS_BIND_FILE:-$SCRIPT_DIR/vps-bind.env}"
exec bash "$SCRIPT_DIR/start-all.sh" "$@"
