#!/usr/bin/env bash
# Query get_tip on hub + voters; require matching tip_height/tip_id and public genesis_id (M2.4.3 / M2.4.6).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORTS_FILE="$SCRIPT_DIR/devnet-ports.env"
EXPECTED_GENESIS_ID="7fef4492dba32d7ba652cceb5465cae86d6630a9e0a4855adf3acdc5f6b2a2df"
if [[ ! -f "$PORTS_FILE" ]]; then
  echo "missing $PORTS_FILE — run start-all.sh first" >&2
  exit 1
fi
# shellcheck source=/dev/null
source "$PORTS_FILE"
REQ='{"jsonrpc":"2.0","method":"get_tip","id":1}'
query_tip() {
  local name="$1" addr="$2"
  local host port line
  host="${addr%:*}"
  port="${addr##*:}"
  line=$(echo "$REQ" | nc -w 3 "$host" "$port" 2>/dev/null || true)
  if [[ -z "$line" ]]; then
    echo "health-check: $name RPC unreachable at $addr" >&2
    return 1
  fi
  local height id genesis
  height=$(echo "$line" | sed -n 's/.*"tip_height":\([0-9]*\).*/\1/p')
  if [[ -z "$height" ]] && echo "$line" | grep -q '"tip_height":null'; then
    height=0
  fi
  id=$(echo "$line" | sed -n 's/.*"tip_id":"\([^"]*\)".*/\1/p')
  genesis=$(echo "$line" | sed -n 's/.*"genesis_id":"\([^"]*\)".*/\1/p')
  if [[ -z "$id" || "$id" == "none" ]]; then
    echo "health-check: $name returned no tip_id (line=$line)" >&2
    return 1
  fi
  if [[ "$genesis" != "$EXPECTED_GENESIS_ID" ]]; then
    echo "health-check: $name genesis_id=$genesis expected $EXPECTED_GENESIS_ID" >&2
    return 1
  fi
  echo "$name tip_height=$height tip_id=$id genesis_id=$genesis"
  TIP_HEIGHT="$height"
  TIP_ID="$id"
}
TIP_HEIGHT=""
TIP_ID=""
HUB_LINE=""
HUB_LINE=$(query_tip hub "${HUB_RPC:?}") || exit 1
REF_HEIGHT="$TIP_HEIGHT"
REF_ID="$TIP_ID"
echo "$HUB_LINE"
for v in 1 2; do
  rpc=""
  log="$SCRIPT_DIR/logs/v$v.log"
  if [[ -f "$log" ]]; then
    rpc=$(grep -m1 mfnd_serve_listening= "$log" 2>/dev/null | sed 's/.*=//' || true)
  fi
  if [[ -z "$rpc" ]]; then
    echo "health-check: skip v$v (no RPC in $log)" >&2
    continue
  fi
  line=""
  line=$(query_tip "v$v" "$rpc") || exit 1
  echo "$line"
  if [[ "$TIP_HEIGHT" != "$REF_HEIGHT" || "$TIP_ID" != "$REF_ID" ]]; then
    echo "health-check: FAIL v$v diverged from hub (hub height=$REF_HEIGHT id=$REF_ID; v$v height=$TIP_HEIGHT id=$TIP_ID)" >&2
    exit 1
  fi
done
if [[ -n "${OBSERVER_RPC:-}" ]]; then
  line=""
  line=$(query_tip observer "$OBSERVER_RPC") || exit 1
  echo "$line"
  if [[ "$TIP_HEIGHT" != "$REF_HEIGHT" || "$TIP_ID" != "$REF_ID" ]]; then
    echo "health-check: FAIL observer diverged from hub" >&2
    exit 1
  fi
else
  obs_log="$SCRIPT_DIR/logs/observer.log"
  if [[ -f "$obs_log" ]]; then
    obs_rpc=$(grep -m1 mfnd_serve_listening= "$obs_log" 2>/dev/null | sed 's/.*=//' || true)
    if [[ -n "$obs_rpc" ]]; then
      line=""
      line=$(query_tip observer "$obs_rpc") || exit 1
      echo "$line"
      if [[ "$TIP_HEIGHT" != "$REF_HEIGHT" || "$TIP_ID" != "$REF_ID" ]]; then
        echo "health-check: FAIL observer diverged from hub" >&2
        exit 1
      fi
    else
      echo "health-check: skip observer (no RPC in $obs_log)" >&2
    fi
  fi
fi
echo "health-check: PASS shared tip height=$REF_HEIGHT id=$REF_ID"
