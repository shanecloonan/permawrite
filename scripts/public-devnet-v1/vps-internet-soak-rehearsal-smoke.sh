#!/usr/bin/env bash
# Lane 7 / TL-5: plan-only vps-internet-soak rehearsal gate (no VPS required).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/VPS_SINGLE_BOX_LAUNCH.md"
OPS="$REPO_ROOT/scripts/public-devnet-v1/OPERATORS.md"
SOAK="$SCRIPT_DIR/vps-internet-soak.sh"
PREFLIGHT="$SCRIPT_DIR/vps-preflight.sh"
ASSERT="$SCRIPT_DIR/assert-vps-internet-soak-evidence.sh"
FIXTURE="$SCRIPT_DIR/fixtures/vps-internet-soak-evidence-v1/vps-internet-soak-linux-30s-slot-20260712T000000Z.txt"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates TL-5 VPS internet soak docs + script wiring (no live mesh).
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

for f in "$DOC" "$OPS" "$SOAK" "$PREFLIGHT" "$ASSERT" "$FIXTURE"; do
  if [[ ! -f "$f" ]]; then
    echo "vps-internet-soak-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

for needle in \
  "vps-internet-soak.sh" \
  "vps-preflight.sh" \
  "vps-internet-soak-linux-" \
  "MFN_VPS_SOAK_MIN_HEIGHT" \
  ; do
  if ! grep -qF -- "$needle" "$DOC"; then
    echo "vps-internet-soak-rehearsal-smoke: VPS_SINGLE_BOX_LAUNCH.md missing: $needle" >&2
    exit 1
  fi
done

if ! grep -qF -- "vps-internet-soak" "$OPS"; then
  echo "vps-internet-soak-rehearsal-smoke: OPERATORS.md missing vps-internet-soak" >&2
  exit 1
fi

if ! grep -qF -- "vps-preflight.sh" "$SOAK"; then
  echo "vps-internet-soak-rehearsal-smoke: vps-internet-soak.sh must invoke vps-preflight.sh" >&2
  exit 1
fi
if ! grep -qF -- "soak.sh" "$SOAK" || ! grep -qF -- "--vps" "$SOAK"; then
  echo "vps-internet-soak-rehearsal-smoke: vps-internet-soak.sh must delegate to soak.sh --vps" >&2
  exit 1
fi
if ! grep -qF -- "--archive-evidence" "$SOAK"; then
  echo "vps-internet-soak-rehearsal-smoke: vps-internet-soak.sh must pass --archive-evidence" >&2
  exit 1
fi
if ! grep -qF -- "assert-vps-internet-soak-evidence" "$OPS"; then
  echo "vps-internet-soak-rehearsal-smoke: OPERATORS.md missing assert-vps-internet-soak-evidence" >&2
  exit 1
fi
bash "$ASSERT" "$FIXTURE" >/dev/null

echo "vps-internet-soak-rehearsal-smoke: plan"
echo "  flow=vps-preflight.sh -> soak.sh --vps --archive-evidence"
echo "  evidence=vps-internet-soak-linux-*.txt"
echo "  assert=assert-vps-internet-soak-evidence.sh"
echo "  docs=docs/VPS_SINGLE_BOX_LAUNCH.md"
echo "  live_rehearsal=human VPS (TL-5 execution)"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "vps-internet-soak-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "vps-internet-soak-rehearsal-smoke: live mode not implemented; run vps-internet-soak.sh on VPS" >&2
exit 1
