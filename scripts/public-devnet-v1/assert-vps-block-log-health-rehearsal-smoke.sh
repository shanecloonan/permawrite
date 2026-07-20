#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
needles=(assert-vps-block-log-health B-53 F62 get_block tip_height)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/assert-vps-block-log-health.sh" || { echo "missing needle $n" >&2; exit 1; }
done
grep -q "wallet_lock_held" "$SCRIPT_DIR/faucet-http.mjs" || {
  echo "missing wallet_lock_held in faucet-http.mjs (B-53 non-blocking health)" >&2
  exit 1
}
plan="$(bash "$SCRIPT_DIR/assert-vps-block-log-health.sh" --plan-only)"
[[ "$plan" == *"assert-vps-block-log-health: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "assert-vps-block-log-health-rehearsal-smoke: PASS plan-only"