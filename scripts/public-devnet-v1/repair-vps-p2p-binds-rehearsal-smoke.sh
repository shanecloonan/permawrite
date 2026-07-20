#!/usr/bin/env bash
# CI/plan gate for B-41 repair-vps-p2p-binds (no VPS mutation).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) echo "usage: repair-vps-p2p-binds-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "repair-vps-p2p-binds-rehearsal-smoke: unknown argument $1" >&2; exit 1 ;;
  esac
done
needles=(repair-vps-p2p-binds B-41 socat 19101 19102 19002 faucet MFN_P2P_DIAL_EXTRA write_local_peers)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/repair-vps-p2p-binds.sh" || { echo "missing needle $n" >&2; exit 1; }
done
grep -qE '^MFN_P2P_LISTEN_HUB=0\.0\.0\.0:' "$SCRIPT_DIR/vps-bind.env.example" || { echo "example hub P2P must be 0.0.0.0" >&2; exit 1; }
plan_out="$(bash "$SCRIPT_DIR/repair-vps-p2p-binds.sh" --plan-only)"
[[ "$plan_out" == *"repair-vps-p2p-binds: PASS plan-only"* ]] || { printf '%s\n' "$plan_out" >&2; exit 1; }
echo "repair-vps-p2p-binds-rehearsal-smoke: PASS plan-only"