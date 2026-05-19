#!/usr/bin/env bash
# Query get_tip on hub RPC; optional follower RPCs from devnet-ports.env (M2.4.3).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"
if [[ ! -f "$PORTS_FILE" ]]; then
  echo "missing $PORTS_FILE — run start-all.sh first" >&2
  exit 1
fi
# shellcheck source=/dev/null
source "$PORTS_FILE"
REQ='{"jsonrpc":"2.0","method":"get_tip","id":1}'
query() {
  local name="$1" addr="$2"
  local host port
  host="${addr%:*}"
  port="${addr##*:}"
  local line
  line=$(echo "$REQ" | nc -w 2 "$host" "$port" 2>/dev/null || true)
  echo "$name $line"
}
query hub "${HUB_RPC:?}"
if [[ -f "$SCRIPT_DIR/logs/v1.log" ]]; then
  V1_RPC=$(grep -m1 mfnd_serve_listening= "$SCRIPT_DIR/logs/v1.log" | sed 's/.*=//' || true)
  [[ -n "$V1_RPC" ]] && query v1 "$V1_RPC"
fi
if [[ -f "$SCRIPT_DIR/logs/v2.log" ]]; then
  V2_RPC=$(grep -m1 mfnd_serve_listening= "$SCRIPT_DIR/logs/v2.log" | sed 's/.*=//' || true)
  [[ -n "$V2_RPC" ]] && query v2 "$V2_RPC"
fi
