#!/usr/bin/env bash
# CI plan gate for assert-b32-arm-ready.sh (B-79).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) echo "usage: b32-arm-ready-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "b32-arm-ready-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done
needles=(assert-b32-arm-ready B-79 B-32 distinct_hosts never=faucet-http lib-ci-roll-gate)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/assert-b32-arm-ready.sh" || { echo "missing needle $n" >&2; exit 1; }
done
plan="$(bash "$SCRIPT_DIR/assert-b32-arm-ready.sh" --plan-only)"
[[ "$plan" == *"assert-b32-arm-ready: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "b32-arm-ready-rehearsal-smoke: PASS plan-only"