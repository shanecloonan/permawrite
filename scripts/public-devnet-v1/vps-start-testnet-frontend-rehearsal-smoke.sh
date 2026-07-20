#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
needles=(vps-start-testnet-frontend B-55 testnet-frontend 3000)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/vps-start-testnet-frontend.sh" || { echo "missing needle $n" >&2; exit 1; }
done
[[ -f "$SCRIPT_DIR/testnet-frontend.service" ]] || { echo "missing testnet-frontend.service" >&2; exit 1; }
plan="$(bash "$SCRIPT_DIR/vps-start-testnet-frontend.sh" --plan-only)"
[[ "$plan" == *"vps-start-testnet-frontend: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "vps-start-testnet-frontend-rehearsal-smoke: PASS plan-only"