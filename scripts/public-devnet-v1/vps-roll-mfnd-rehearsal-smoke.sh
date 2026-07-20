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

needles=(vps-roll-mfnd B-49 B-60 B-61 B-65 B-78 mfnd faucet-http vps-soften-mfnd-requires MFN_P2P_DIAL_EXTRA voters hub MFN_ROLL_ALLOW_RED_CI lib-ci-roll-gate lib-cargo-env)
for n in "${needles[@]}"; do
  grep -q "$n" "$SCRIPT_DIR/vps-roll-mfnd.sh" || { echo "missing needle $n" >&2; exit 1; }
done
[[ -f "$SCRIPT_DIR/lib-ci-roll-gate.sh" ]] || { echo "missing lib-ci-roll-gate.sh" >&2; exit 1; }
grep -q "docs-equivalent" "$SCRIPT_DIR/lib-ci-roll-gate.sh" || { echo "lib-ci-roll-gate missing docs-equivalent" >&2; exit 1; }

plan="$(bash "$SCRIPT_DIR/vps-roll-mfnd.sh" --plan-only)"
[[ "$plan" == *"vps-roll-mfnd: PASS plan-only"* ]] || { printf '%s\n' "$plan" >&2; exit 1; }
[[ "$plan" == *"never=faucet-http"* ]] || { echo "plan missing faucet never-touch" >&2; exit 1; }
[[ "$plan" == *"docs-equivalent"* ]] || { echo "plan missing B-78 docs-equivalent gate" >&2; exit 1; }
echo "vps-roll-mfnd-rehearsal-smoke: PASS plan-only"
