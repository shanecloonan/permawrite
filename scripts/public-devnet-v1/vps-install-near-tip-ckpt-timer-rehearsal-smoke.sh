#!/usr/bin/env bash
# CI plan gate for vps-install-near-tip-ckpt-timer.sh (B-88).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) echo "usage: vps-install-near-tip-ckpt-timer-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "vps-install-near-tip-ckpt-timer-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done
needles=(vps-install-near-tip-ckpt-timer B-88 path-a-near-tip-ckpt.timer never=faucet-http publish-near-tip-checkpoint-if-lag)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/vps-install-near-tip-ckpt-timer.sh" || { echo "missing needle $n" >&2; exit 1; }
done
test -f "$SCRIPT_DIR/systemd/path-a-near-tip-ckpt.service" || { echo "missing service unit" >&2; exit 1; }
test -f "$SCRIPT_DIR/systemd/path-a-near-tip-ckpt.timer" || { echo "missing timer unit" >&2; exit 1; }
grep -q 'publish-near-tip-checkpoint-if-lag.sh --apply' "$SCRIPT_DIR/systemd/path-a-near-tip-ckpt.service"
grep -q 'OnUnitActiveSec=30min' "$SCRIPT_DIR/systemd/path-a-near-tip-ckpt.timer"
plan="$(bash "$SCRIPT_DIR/vps-install-near-tip-ckpt-timer.sh" --plan-only)"
[[ "$plan" == *"vps-install-near-tip-ckpt-timer: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "vps-install-near-tip-ckpt-timer-rehearsal-smoke: PASS plan-only"