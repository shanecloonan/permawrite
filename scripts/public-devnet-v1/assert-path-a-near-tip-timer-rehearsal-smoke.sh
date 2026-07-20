#!/usr/bin/env bash
# CI plan gate for assert-path-a-near-tip-timer.sh (B-89).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) shift ;;
    -h|--help) echo "usage: assert-path-a-near-tip-timer-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "assert-path-a-near-tip-timer-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done
needles=(assert-path-a-near-tip-timer B-89 never=faucet-http path-a-near-tip-ckpt.timer)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/assert-path-a-near-tip-timer.sh" || { echo "missing needle $n" >&2; exit 1; }
done
plan="$(bash "$SCRIPT_DIR/assert-path-a-near-tip-timer.sh" --plan-only)"
[[ "$plan" == *"assert-path-a-near-tip-timer: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "assert-path-a-near-tip-timer-rehearsal-smoke: PASS plan-only"