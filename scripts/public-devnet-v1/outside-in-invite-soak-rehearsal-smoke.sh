#!/usr/bin/env bash
# CI plan gate for B-27 outside-in invite-head soak tooling.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) echo "usage: outside-in-invite-soak-rehearsal-smoke.sh [--plan-only]"; exit 0 ;;
    *) echo "outside-in-invite-soak-rehearsal-smoke: unknown $1" >&2; exit 1 ;;
  esac
done

for f in \
  "$SCRIPT_DIR/outside-in-invite-soak.sh" \
  "$SCRIPT_DIR/assert-outside-in-invite-soak-evidence.sh" \
  "$SCRIPT_DIR/fixtures/outside-in-invite-soak-evidence-v1/outside-in-invite-soak-20260720T000000Z.txt"
do
  [[ -f "$f" ]] || { echo "outside-in-invite-soak-rehearsal-smoke: missing $f" >&2; exit 1; }
done

needles=(B-27 outside-in-invite-soak never=faucet-http assert-outside-in-invite-soak-evidence)
for n in "${needles[@]}"; do
  grep -qF -- "$n" "$SCRIPT_DIR/outside-in-invite-soak.sh" || {
    echo "outside-in-invite-soak-rehearsal-smoke: outside-in-invite-soak.sh missing $n" >&2
    exit 1
  }
done

plan="$(bash "$SCRIPT_DIR/outside-in-invite-soak.sh" --plan-only)"
[[ "$plan" == *"outside-in-invite-soak: PASS plan-only"* ]] || {
  printf '%s\n' "$plan" >&2
  exit 1
}

assert_out="$(bash "$SCRIPT_DIR/assert-outside-in-invite-soak-evidence.sh" \
  "$SCRIPT_DIR/fixtures/outside-in-invite-soak-evidence-v1/outside-in-invite-soak-20260720T000000Z.txt")"
[[ "$assert_out" == *"assert-outside-in-invite-soak-evidence: OK"* ]] || {
  printf '%s\n' "$assert_out" >&2
  exit 1
}

echo "outside-in-invite-soak-rehearsal-smoke: plan"
echo "  unit=B-27"
echo "  soak=outside-in-invite-soak.sh"
echo "  assert=assert-outside-in-invite-soak-evidence.sh"
echo "  fixture_assert=true"
if (( PLAN_ONLY )); then
  echo "outside-in-invite-soak-rehearsal-smoke: PASS plan-only"
  exit 0
fi
echo "outside-in-invite-soak-rehearsal-smoke: PASS plan-only"
