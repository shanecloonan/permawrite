#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
needles=(bootstrap-wallet-from-checkpoint-log B-50 get_light_snapshot checkpoint-log honesty)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/bootstrap-wallet-from-checkpoint-log.sh" || { echo "missing needle $n" >&2; exit 1; }
done
plan="$(bash "$SCRIPT_DIR/bootstrap-wallet-from-checkpoint-log.sh" --plan-only)"
[[ "$plan" == *"bootstrap-wallet-from-checkpoint-log: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "bootstrap-wallet-from-checkpoint-log-rehearsal-smoke: PASS plan-only"
