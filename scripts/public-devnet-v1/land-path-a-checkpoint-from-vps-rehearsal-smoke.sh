#!/usr/bin/env bash
# CI plan gate for land-path-a-checkpoint-from-vps.sh (B-89).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) shift ;;
    -h|--help) echo "usage: land-path-a-checkpoint-from-vps-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "land-path-a-checkpoint-from-vps-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done
needles=(land-path-a-checkpoint-from-vps B-89 never=faucet-http git-commit tip_height)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/land-path-a-checkpoint-from-vps.sh" || { echo "missing needle $n" >&2; exit 1; }
done
# B-97 Windows apply twin must stay in tree
[[ -f "$SCRIPT_DIR/land-path-a-checkpoint-from-vps.ps1" ]] || { echo "missing land-path-a-checkpoint-from-vps.ps1 (B-97)" >&2; exit 1; }
ps1_needles=(land-path-a-checkpoint-from-vps B-97 never=faucet-http "PASS plan-only")
for n in "${ps1_needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/land-path-a-checkpoint-from-vps.ps1" || { echo "missing ps1 needle $n" >&2; exit 1; }
done
plan="$(bash "$SCRIPT_DIR/land-path-a-checkpoint-from-vps.sh" --plan-only)"
[[ "$plan" == *"land-path-a-checkpoint-from-vps: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "land-path-a-checkpoint-from-vps-rehearsal-smoke: PASS plan-only"