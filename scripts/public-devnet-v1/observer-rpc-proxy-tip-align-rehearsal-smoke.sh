#!/usr/bin/env bash
# CI plan gate for B-90 observer tip-align (F105).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) shift ;;
    -h|--help) echo "usage: observer-rpc-proxy-tip-align-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "observer-rpc-proxy-tip-align-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done
mjs="$SCRIPT_DIR/observer-rpc-proxy.mjs"
svc="$SCRIPT_DIR/observer-rpc-proxy.service"
needles_mjs=(PROXY_HUB_TIP_RPC tipAlignBeforeUploads list_recent_uploads B-90 F105 tip_align_waits)
for n in "${needles_mjs[@]}"; do
  grep -q "$n" "$mjs" || { echo "missing needle $n in mjs" >&2; exit 1; }
done
grep -q 'PROXY_HUB_TIP_RPC=127.0.0.1:18731' "$svc" || { echo "missing hub tip env in service" >&2; exit 1; }
grep -q 'PROXY_TIP_ALIGN_MS=45000' "$svc" || { echo "missing tip align ms in service" >&2; exit 1; }
deploy="$SCRIPT_DIR/vps-update-observer-rpc-proxy.sh"
grep -q 'B-90' "$deploy" || { echo "missing B-90 in deploy" >&2; exit 1; }
grep -q 'never=faucet-http' "$deploy" || { echo "missing never=faucet-http in deploy" >&2; exit 1; }
plan="$(bash "$deploy" --plan-only)"
[[ "$plan" == *"vps-update-observer-rpc-proxy: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "observer-rpc-proxy-tip-align-rehearsal-smoke: plan"
echo "  unit=B-90"
echo "  never=faucet-http mfnd restart join-testnet-rehearsal"
echo "observer-rpc-proxy-tip-align-rehearsal-smoke: PASS plan-only"