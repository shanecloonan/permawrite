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

# B-164/B-165: Windows F45 soft twin + B-161 in-CLI needles must not rot.
[[ -f "$SCRIPT_DIR/light-scan-checkpoint-soft.ps1" ]] || {
  echo "missing Windows twin light-scan-checkpoint-soft.ps1 (B-164/F45)" >&2
  exit 1
}
grep -q "B-161" "$SCRIPT_DIR/light-scan-checkpoint-soft.sh" || {
  echo "missing B-161 note in light-scan-checkpoint-soft.sh" >&2
  exit 1
}
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
grep -q "MFN_HEAVY_RPC_TIMEOUT_MS" "$REPO_ROOT/mfn-cli/src/rpc.rs" || {
  echo "missing MFN_HEAVY_RPC_TIMEOUT_MS in mfn-cli rpc.rs (B-161)" >&2
  exit 1
}
grep -q "checkpoint_log_f45_soft_pass" "$REPO_ROOT/mfn-cli/src/light_wallet.rs" || {
  echo "missing checkpoint_log_f45_soft_pass in light_wallet.rs (B-161)" >&2
  exit 1
}
soft_plan="$(bash "$SCRIPT_DIR/light-scan-checkpoint-soft.sh" --plan-only)"
[[ "$soft_plan" == *"light-scan-checkpoint-soft: PASS plan-only"* ]] || { printf '%s\n' "$soft_plan" >&2; exit 1; }
plan="$(bash "$SCRIPT_DIR/bootstrap-wallet-from-checkpoint-log.sh" --plan-only)"
[[ "$plan" == *"bootstrap-wallet-from-checkpoint-log: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "bootstrap-wallet-from-checkpoint-log-rehearsal-smoke: PASS plan-only"
