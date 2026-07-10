#!/usr/bin/env bash
# Lane 7 / TL-6: plan-only vps-participant-rehearsal rehearsal gate (no VPS required).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/VPS_SINGLE_BOX_LAUNCH.md"
OPS="$REPO_ROOT/scripts/public-devnet-v1/OPERATORS.md"
REHEARSAL="$SCRIPT_DIR/vps-participant-rehearsal.sh"
SMOKE="$SCRIPT_DIR/participant-rehearsal-smoke.sh"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates TL-6 VPS participant rehearsal docs + script wiring (no live mesh).
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

for f in "$DOC" "$OPS" "$REHEARSAL" "$SMOKE"; do
  if [[ ! -f "$f" ]]; then
    echo "vps-participant-rehearsal-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

for needle in \
  "vps-participant-rehearsal.sh" \
  "vps-participant-rehearsal-observer-linux-" \
  "--no-start" \
  "--no-stop" \
  ; do
  if ! grep -qF -- "$needle" "$DOC"; then
    echo "vps-participant-rehearsal-rehearsal-smoke: VPS_SINGLE_BOX_LAUNCH.md missing: $needle" >&2
    exit 1
  fi
done

if ! grep -qF -- "vps-participant-rehearsal" "$OPS"; then
  echo "vps-participant-rehearsal-rehearsal-smoke: OPERATORS.md missing vps-participant-rehearsal" >&2
  exit 1
fi

if ! grep -qF -- "participant-rehearsal-smoke.sh" "$REHEARSAL"; then
  echo "vps-participant-rehearsal-rehearsal-smoke: wrapper must delegate to participant-rehearsal-smoke.sh" >&2
  exit 1
fi
for flag in --vps --with-observer --archive-evidence; do
  if ! grep -qF -- "$flag" "$REHEARSAL"; then
    echo "vps-participant-rehearsal-rehearsal-smoke: vps-participant-rehearsal.sh missing $flag" >&2
    exit 1
  fi
done

echo "vps-participant-rehearsal-rehearsal-smoke: plan"
echo "  flow=vps-participant-rehearsal.sh -> participant-rehearsal-smoke.sh --vps --with-observer"
echo "  evidence=vps-participant-rehearsal-observer-linux-*.txt"
echo "  docs=docs/VPS_SINGLE_BOX_LAUNCH.md"
echo "  live_rehearsal=human VPS after TL-5 soak PASS"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "vps-participant-rehearsal-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "vps-participant-rehearsal-rehearsal-smoke: live mode not implemented; run on VPS after TL-5" >&2
exit 1
