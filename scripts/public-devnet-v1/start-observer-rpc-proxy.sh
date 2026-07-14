#!/usr/bin/env bash
# Lane 7: start public-safe observer HTTP→TCP JSON-RPC proxy on a VPS.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
export MFND_RPC="${MFND_RPC:-127.0.0.1:18734}"
export PROXY_HOST="${PROXY_HOST:-0.0.0.0}"
export PROXY_PORT="${PROXY_PORT:-8787}"

if ! command -v node >/dev/null 2>&1; then
  echo "start-observer-rpc-proxy: install Node.js 20+ first" >&2
  exit 1
fi

exec node "$SCRIPT_DIR/observer-rpc-proxy.mjs"
