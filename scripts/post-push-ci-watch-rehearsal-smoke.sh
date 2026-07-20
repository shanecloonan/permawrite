#!/usr/bin/env bash
# CI plan gate for B-93 post-push-ci-watch.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) echo "usage: post-push-ci-watch-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "post-push-ci-watch-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done
for f in "$SCRIPT_DIR/post-push-ci-watch.py" "$SCRIPT_DIR/post-push-ci-watch.sh" "$SCRIPT_DIR/post-push-ci-watch.ps1" "$SCRIPT_DIR/watch-ci-stall.py"; do
  [[ -f "$f" ]] || { echo "missing $f" >&2; exit 1; }
done
for n in B-93 wraps=watch-ci-stall.py never=cancel_healthy_in_progress after_push; do
  grep -qF -- "$n" "$SCRIPT_DIR/post-push-ci-watch.py" || { echo "missing needle $n" >&2; exit 1; }
done
plan="$(python3 "$SCRIPT_DIR/post-push-ci-watch.py" --plan-only)"
[[ "$plan" == *"post-push-ci-watch: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
echo "post-push-ci-watch-rehearsal-smoke: plan"
echo "  unit=B-93"
echo "  tool=post-push-ci-watch.py"
echo "post-push-ci-watch-rehearsal-smoke: PASS plan-only"
