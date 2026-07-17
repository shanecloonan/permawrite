#!/usr/bin/env bash
# Merge operator faucet UTXOs via self-sends (run weekly when owned_count grows).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=ports-env-lib.sh
source "$SCRIPT_DIR/ports-env-lib.sh"
RPC="${RPC:-$(resolve_rpc 2>/dev/null || echo 127.0.0.1:18731)}"
FAUCET_WALLET="${FAUCET_WALLET:-/root/testnet-wallets/validator0-faucet.json}"
MFN_CLI="${MFN_CLI:-$(resolve_mfn_cli 2>/dev/null || echo "$REPO_ROOT/target/release/mfn-cli")}"
TARGET_OWNED="${TARGET_OWNED:-3}"
FEE="${FEE:-10000}"
RING="${RING_SIZE:-16}"
MAX_ROUNDS="${MAX_ROUNDS:-50}"
WAIT_SEC="${WAIT_SEC:-35}"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="$2"; shift 2 ;;
    --wallet|--faucet-wallet) FAUCET_WALLET="$2"; shift 2 ;;
    --target-owned) TARGET_OWNED="$2"; shift 2 ;;
    --max-rounds) MAX_ROUNDS="$2"; shift 2 ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help)
      echo "usage: faucet-consolidate.sh [--rpc HOST:PORT] [--wallet FILE] [--target-owned N] [--max-rounds N] [--plan-only]"
      exit 0 ;;
    *) echo "faucet-consolidate: unknown arg $1" >&2; exit 1 ;;
  esac
done
if (( PLAN_ONLY )); then
  echo "faucet-consolidate: plan rpc=$RPC wallet=$FAUCET_WALLET target_owned=$TARGET_OWNED max_rounds=$MAX_ROUNDS"
  echo "  flow=light-scan -> self-send (balance-2*fee) -> wait -> repeat until owned_count <= target"
  exit 0
fi
[[ -f "$FAUCET_WALLET" ]] || { echo "faucet-consolidate: missing wallet $FAUCET_WALLET" >&2; exit 1; }
parse_kv() { sed -n "s/^$1=//p" | head -1; }
light_scan() { "$MFN_CLI" --rpc "$RPC" --wallet "$FAUCET_WALLET" wallet light-scan >/dev/null; }
status_field() { "$MFN_CLI" --rpc "$RPC" --wallet "$FAUCET_WALLET" wallet status 2>&1 | parse_kv "$1"; }
light_scan
OWNED="$(status_field owned_count_cached)"
[[ -n "$OWNED" ]] || OWNED="$(status_field owned_count)"
BAL="$(status_field balance_cached)"
[[ -n "$BAL" ]] || BAL="$(status_field balance)"
echo "faucet-consolidate: start owned=${OWNED:-?} balance=${BAL:-?} target_owned=$TARGET_OWNED"
if [[ -n "$OWNED" && "$OWNED" -le "$TARGET_OWNED" ]]; then
  echo "faucet-consolidate: PASS already at or below target (owned=$OWNED)"
  exit 0
fi
ADDR="$("$MFN_CLI" --wallet "$FAUCET_WALLET" wallet address 2>&1 | parse_kv address)"
[[ -n "$ADDR" ]] || { echo "faucet-consolidate: could not read faucet address" >&2; exit 1; }
round=0
while [[ -n "$OWNED" && "$OWNED" -gt "$TARGET_OWNED" && "$round" -lt "$MAX_ROUNDS" ]]; do
  round=$((round + 1))
  BAL="$(status_field balance_cached)"
  [[ -n "$BAL" ]] || BAL="$(status_field balance)"
  SEND=$((BAL - FEE * 2))
  if (( SEND < 10000 )); then
    echo "faucet-consolidate: balance too low to consolidate (balance=$BAL)" >&2
    exit 1
  fi
  echo "faucet-consolidate: round $round send $SEND to self (owned=$OWNED)"
  "$MFN_CLI" --rpc "$RPC" --wallet "$FAUCET_WALLET" wallet send "$ADDR" "$SEND" --fee "$FEE" --ring-size "$RING" --json >/dev/null
  sleep "$WAIT_SEC"
  light_scan
  OWNED="$(status_field owned_count_cached)"
  [[ -n "$OWNED" ]] || OWNED="$(status_field owned_count)"
  echo "faucet-consolidate: round $round done owned=${OWNED:-?}"
done
if [[ -n "$OWNED" && "$OWNED" -le "$TARGET_OWNED" ]]; then
  echo "faucet-consolidate: PASS owned=$OWNED"
  exit 0
fi
echo "faucet-consolidate: WARN still owned=${OWNED:-?} after $round rounds (run again or raise --max-rounds)" >&2
exit 0
