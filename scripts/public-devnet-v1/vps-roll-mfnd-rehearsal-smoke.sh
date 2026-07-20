#!/usr/bin/env bash
# CI plan gate for vps-roll-mfnd.sh (B-49).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) echo "usage: vps-roll-mfnd-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "vps-roll-mfnd-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done

needles=(vps-roll-mfnd B-49 mfnd faucet-http vps-soften-mfnd-requires MFN_P2P_DIAL_EXTRA voters hub)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/vps-roll-mfnd.sh" || { echo "missing needle $n" >&2; exit 1; }
done

plan="$(bash "$SCRIPT_DIR/vps-roll-mfnd.sh" --plan-only)"
[[ "$plan" == *"vps-roll-mfnd: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
[[ "$plan" == *"never=faucet-http"* ]] || { echo "plan missing faucet never-touch" >&2; exit 1; }
echo "vps-roll-mfnd-rehearsal-smoke: PASS plan-only"
