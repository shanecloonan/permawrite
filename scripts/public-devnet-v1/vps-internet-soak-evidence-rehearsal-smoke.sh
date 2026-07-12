#!/usr/bin/env bash
# Lane 7 / TL-5: plan-only VPS soak evidence assert + launch-status PASS detection gate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OPS="$REPO_ROOT/scripts/public-devnet-v1/OPERATORS.md"
ASSERT="$SCRIPT_DIR/assert-vps-internet-soak-evidence.sh"
LAUNCH_STATUS="$SCRIPT_DIR/launch-status.sh"
FIXTURE="$SCRIPT_DIR/fixtures/vps-internet-soak-evidence-v1/vps-internet-soak-linux-30s-slot-20260712T000000Z.txt"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates assert-vps-internet-soak-evidence + launch-status soak PASS wiring (no VPS).
EOF
}

PLAN_ONLY=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$(basename "$0"): unknown argument $1" >&2; exit 1 ;;
  esac
done

for f in "$OPS" "$ASSERT" "$LAUNCH_STATUS" "$FIXTURE"; do
  if [[ ! -f "$f" ]]; then
    echo "vps-internet-soak-evidence-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

if ! grep -qF -- "assert-vps-internet-soak-evidence" "$OPS"; then
  echo "vps-internet-soak-evidence-rehearsal-smoke: OPERATORS.md missing assert-vps-internet-soak-evidence" >&2
  exit 1
fi
if ! grep -qF -- "soak: SUMMARY status=PASS" "$LAUNCH_STATUS"; then
  echo "vps-internet-soak-evidence-rehearsal-smoke: launch-status.sh must detect soak: SUMMARY status=PASS" >&2
  exit 1
fi

bash "$ASSERT" "$FIXTURE"

tmp_evidence="$(mktemp -d)"
trap 'rm -rf "$tmp_evidence"' EXIT
cp "$FIXTURE" "$tmp_evidence/"
export MFN_PUBLIC_DEVNET_EVIDENCE_DIR="$tmp_evidence"
json="$(bash "$LAUNCH_STATUS" --json)"
export JSON="$json"
python3 - <<'PY'
import json, os, sys
doc = json.loads(os.environ["JSON"])
if not doc.get("vps_soak_evidence"):
    sys.exit("vps-internet-soak-evidence-rehearsal-smoke: launch-status must set vps_soak_evidence=true for fixture")
print("vps-internet-soak-evidence-rehearsal-smoke: plan")
print("  assert=assert-vps-internet-soak-evidence.sh")
print("  fixture=fixtures/vps-internet-soak-evidence-v1/")
print("  launch-status=vps_soak_evidence=true on fixture")
PY

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "vps-internet-soak-evidence-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "vps-internet-soak-evidence-rehearsal-smoke: live mode not implemented" >&2
exit 1
