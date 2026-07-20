#!/usr/bin/env bash
# CI plan gate for assert-public-testnet-health.sh (B-91).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) shift ;;
    -h|--help) echo "usage: assert-public-testnet-health-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "assert-public-testnet-health-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done
needles=(assert-public-testnet-health B-91 never=faucet-http tip-ckpt-lag hub_tip_rpc assert-path-a-near-tip-timer)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/assert-public-testnet-health.sh" || { echo "missing needle $n" >&2; exit 1; }
done
plan="$(bash "$SCRIPT_DIR/assert-public-testnet-health.sh" --plan-only)"
[[ "$plan" == *"assert-public-testnet-health: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "assert-public-testnet-health-rehearsal-smoke: PASS plan-only"