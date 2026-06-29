#!/usr/bin/env bash
# Query get_status on hub + voters; require matching tip, public genesis_id, and live P2P sessions.
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
REQ='{"jsonrpc":"2.0","method":"get_status","id":1}'
validate_health_int() {
  local name="$1" value="$2" min="$3"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < min )); then
    echo "health-check: $name must be an integer >= $min" >&2
    exit 1
  fi
}
MFN_HEALTH_STALL_SAMPLES="${MFN_HEALTH_STALL_SAMPLES:-1}"
MFN_HEALTH_STALL_INTERVAL_SECONDS="${MFN_HEALTH_STALL_INTERVAL_SECONDS:-30}"
MFN_HEALTH_MIN_HEIGHT_DELTA="${MFN_HEALTH_MIN_HEIGHT_DELTA:-1}"
MFN_HEALTH_MIN_P2P_SESSIONS="${MFN_HEALTH_MIN_P2P_SESSIONS:-1}"
validate_health_int MFN_HEALTH_STALL_SAMPLES "$MFN_HEALTH_STALL_SAMPLES" 1
validate_health_int MFN_HEALTH_STALL_INTERVAL_SECONDS "$MFN_HEALTH_STALL_INTERVAL_SECONDS" 0
validate_health_int MFN_HEALTH_MIN_HEIGHT_DELTA "$MFN_HEALTH_MIN_HEIGHT_DELTA" 1
validate_health_int MFN_HEALTH_MIN_P2P_SESSIONS "$MFN_HEALTH_MIN_P2P_SESSIONS" 0
query_status() {
  local name="$1" addr="$2"
  local host port line
  host="${addr%:*}"
  port="${addr##*:}"
  line=$(echo "$REQ" | nc -w 3 "$host" "$port" 2>/dev/null || true)
  if [[ -z "$line" ]]; then
    echo "health-check: $name RPC unreachable at $addr" >&2
    return 1
  fi
  local height id genesis sessions peers
  height=$(echo "$line" | sed -n 's/.*"tip_height":\([0-9]*\).*/\1/p')
  if [[ -z "$height" ]] && echo "$line" | grep -q '"tip_height":null'; then
    height=0
  fi
  id=$(echo "$line" | sed -n 's/.*"tip_id":"\([^"]*\)".*/\1/p')
  genesis=$(echo "$line" | sed -n 's/.*"genesis_id":"\([^"]*\)".*/\1/p')
  sessions=$(echo "$line" | sed -n 's/.*"session_count":\([0-9]*\).*/\1/p')
  peers=$(echo "$line" | sed -n 's/.*"peer_count":\([0-9]*\).*/\1/p')
  if [[ -z "$id" || "$id" == "none" ]]; then
    echo "health-check: $name returned no tip_id (line=$line)" >&2
    return 1
  fi
  if [[ "$genesis" != "$EXPECTED_GENESIS_ID" ]]; then
    echo "health-check: $name genesis_id=$genesis expected $EXPECTED_GENESIS_ID" >&2
    return 1
  fi
  if (( MFN_HEALTH_MIN_P2P_SESSIONS > 0 )); then
    if [[ ! "$sessions" =~ ^[0-9]+$ ]]; then
      echo "health-check: $name returned no p2p.session_count (line=$line)" >&2
      return 1
    fi
    if (( sessions < MFN_HEALTH_MIN_P2P_SESSIONS )); then
      echo "health-check: FAIL $name p2p sessions=$sessions min=$MFN_HEALTH_MIN_P2P_SESSIONS" >&2
      return 1
    fi
  fi
  echo "$name tip_height=$height tip_id=$id genesis_id=$genesis p2p_sessions=${sessions:-null} p2p_peers=${peers:-null}"
  TIP_HEIGHT="$height"
  TIP_ID="$id"
}
TIP_HEIGHT=""
TIP_ID=""
SNAPSHOT_HEIGHT=""
SNAPSHOT_ID=""
run_convergence_check() {
  query_status hub "${HUB_RPC:?}" || exit 1
  local ref_height="$TIP_HEIGHT"
  local ref_id="$TIP_ID"
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
    query_status "v$v" "$rpc" || exit 1
    if [[ "$TIP_HEIGHT" != "$ref_height" || "$TIP_ID" != "$ref_id" ]]; then
      echo "health-check: FAIL v$v diverged from hub (hub height=$ref_height id=$ref_id; v$v height=$TIP_HEIGHT id=$TIP_ID)" >&2
      exit 1
    fi
  done
  if [[ -n "${OBSERVER_RPC:-}" ]]; then
    query_status observer "$OBSERVER_RPC" || exit 1
    if [[ "$TIP_HEIGHT" != "$ref_height" || "$TIP_ID" != "$ref_id" ]]; then
      echo "health-check: FAIL observer diverged from hub" >&2
      exit 1
    fi
  else
    obs_log="$SCRIPT_DIR/logs/observer.log"
    if [[ -f "$obs_log" ]]; then
      obs_rpc=$(grep -m1 mfnd_serve_listening= "$obs_log" 2>/dev/null | sed 's/.*=//' || true)
      if [[ -n "$obs_rpc" ]]; then
        query_status observer "$obs_rpc" || exit 1
        if [[ "$TIP_HEIGHT" != "$ref_height" || "$TIP_ID" != "$ref_id" ]]; then
          echo "health-check: FAIL observer diverged from hub" >&2
          exit 1
        fi
      else
        echo "health-check: skip observer (no RPC in $obs_log)" >&2
      fi
    fi
  fi
  SNAPSHOT_HEIGHT="$ref_height"
  SNAPSHOT_ID="$ref_id"
}
run_convergence_check
first_height="$SNAPSHOT_HEIGHT"
for ((sample = 2; sample <= MFN_HEALTH_STALL_SAMPLES; sample++)); do
  echo "health-check: waiting ${MFN_HEALTH_STALL_INTERVAL_SECONDS}s before sample $sample/$MFN_HEALTH_STALL_SAMPLES"
  if (( MFN_HEALTH_STALL_INTERVAL_SECONDS > 0 )); then
    sleep "$MFN_HEALTH_STALL_INTERVAL_SECONDS"
  fi
  run_convergence_check
done
if (( MFN_HEALTH_STALL_SAMPLES > 1 )); then
  delta=$((SNAPSHOT_HEIGHT - first_height))
  if (( delta < MFN_HEALTH_MIN_HEIGHT_DELTA )); then
    echo "health-check: FAIL stalled height first=$first_height last=$SNAPSHOT_HEIGHT samples=$MFN_HEALTH_STALL_SAMPLES min_delta=$MFN_HEALTH_MIN_HEIGHT_DELTA" >&2
    exit 1
  fi
  echo "health-check: PASS shared tip height=$SNAPSHOT_HEIGHT id=$SNAPSHOT_ID advanced_by=$delta samples=$MFN_HEALTH_STALL_SAMPLES"
else
  echo "health-check: PASS shared tip height=$SNAPSHOT_HEIGHT id=$SNAPSHOT_ID"
fi
