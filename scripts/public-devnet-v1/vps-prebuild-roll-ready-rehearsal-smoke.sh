#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) shift ;;
    -h|--help) echo "usage: vps-prebuild-roll-ready-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "vps-prebuild-roll-ready-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done
for f in vps-prebuild-mfnd.sh assert-vps-roll-ready.sh; do
  [[ -f "$SCRIPT_DIR/$f" ]] || { echo "missing $f" >&2; exit 1; }
done
grep -q 'never=systemctl' "$SCRIPT_DIR/vps-prebuild-mfnd.sh"
grep -q 'B-62' "$SCRIPT_DIR/assert-vps-roll-ready.sh"
plan="$(bash "$SCRIPT_DIR/vps-prebuild-mfnd.sh" --plan-only)"
[[ "$plan" == *"PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
plan2="$(bash "$SCRIPT_DIR/assert-vps-roll-ready.sh" --plan-only)"
[[ "$plan2" == *"PASS plan-only"* ]] || { printf '%s\n' "$plan2" >&2; exit 1; }
echo "vps-prebuild-roll-ready-rehearsal-smoke: PASS plan-only"