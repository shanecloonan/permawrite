#!/usr/bin/env bash
# CI plan gate for B-34 watch-ci-stall.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) echo "usage: watch-ci-stall-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "watch-ci-stall-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done
for f in "$SCRIPT_DIR/watch-ci-stall.py" "$SCRIPT_DIR/watch-ci-stall.sh" "$SCRIPT_DIR/watch-ci-stall.ps1"; do
  [[ -f "$f" ]] || { echo "missing $f" >&2; exit 1; }
done
for n in B-34 all_jobs_queued_empty_steps never=cancel_healthy_in_progress; do
  grep -qF -- "$n" "$SCRIPT_DIR/watch-ci-stall.py" || { echo "missing needle $n" >&2; exit 1; }
done
plan="$(python3 "$SCRIPT_DIR/watch-ci-stall.py" --plan-only)"
[[ "$plan" == *"watch-ci-stall: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "watch-ci-stall-rehearsal-smoke: plan"
echo "  unit=B-34"
echo "  tool=watch-ci-stall.py"
echo "watch-ci-stall-rehearsal-smoke: PASS plan-only"
