#!/usr/bin/env bash
# CI plan gate for B-89 Path A timer assert + VPS land helper.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) shift ;;
    -h|--help) echo "usage: path-a-near-tip-ops-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "path-a-near-tip-ops-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done
bash "$SCRIPT_DIR/assert-path-a-near-tip-timer-rehearsal-smoke.sh" --plan-only
bash "$SCRIPT_DIR/land-path-a-checkpoint-from-vps-rehearsal-smoke.sh" --plan-only
echo "path-a-near-tip-ops-rehearsal-smoke: PASS plan-only"