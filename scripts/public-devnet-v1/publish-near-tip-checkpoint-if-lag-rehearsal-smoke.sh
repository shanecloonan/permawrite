#!/usr/bin/env bash
# CI plan gate for publish-near-tip-checkpoint-if-lag.sh (B-85).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) echo "usage: publish-near-tip-checkpoint-if-lag-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "publish-near-tip-checkpoint-if-lag-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done
needles=(publish-near-tip-checkpoint-if-lag B-85 lag_threshold never=faucet-http bootstrap-path-a-checkpoint-signer)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/publish-near-tip-checkpoint-if-lag.sh" || { echo "missing needle $n" >&2; exit 1; }
done
plan="$(bash "$SCRIPT_DIR/publish-near-tip-checkpoint-if-lag.sh" --plan-only)"
[[ "$plan" == *"publish-near-tip-checkpoint-if-lag: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "publish-near-tip-checkpoint-if-lag-rehearsal-smoke: PASS plan-only"