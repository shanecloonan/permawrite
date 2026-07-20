#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
needles=(bootstrap-wallet-from-checkpoint-log B-50 get_light_snapshot checkpoint-log honesty f67 f45)
[[ -f "$SCRIPT_DIR/light-scan-checkpoint-soft.sh" ]] || { echo "missing light-scan-checkpoint-soft.sh (B-59/F45)" >&2; exit 1; }
grep -q f45-soft "$SCRIPT_DIR/light-scan-checkpoint-soft.sh" || { echo "missing f45-soft needle" >&2; exit 1; }
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/bootstrap-wallet-from-checkpoint-log.sh" || { echo "missing needle $n" >&2; exit 1; }
done
[[ -f "$SCRIPT_DIR/bootstrap-wallet-from-checkpoint-log.ps1" ]] || {
  echo "missing Windows twin bootstrap-wallet-from-checkpoint-log.ps1 (B-52/F56)" >&2
  exit 1
}
grep -q "HEAVY_RPC_TIMEOUT_MS" "$SCRIPT_DIR/observer-rpc-proxy.mjs" || {
  echo "missing HEAVY_RPC_TIMEOUT_MS in observer-rpc-proxy.mjs (B-52/F54)" >&2
  exit 1
}
grep -q "F67 pin-then-fund" "$SCRIPT_DIR/fund-wallet-http.sh" || {
  echo "missing F67 pin-then-fund in fund-wallet-http.sh (B-54)" >&2
  exit 1
}
grep -q "keepaliveTick" "$SCRIPT_DIR/faucet-http.mjs" || {
  echo "missing keepaliveTick tip-first keepalive in faucet-http.mjs (B-56)" >&2
  exit 1
}
plan="$(bash "$SCRIPT_DIR/bootstrap-wallet-from-checkpoint-log.sh" --plan-only)"
[[ "$plan" == *"bootstrap-wallet-from-checkpoint-log: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "bootstrap-wallet-from-checkpoint-log-rehearsal-smoke: PASS plan-only"
