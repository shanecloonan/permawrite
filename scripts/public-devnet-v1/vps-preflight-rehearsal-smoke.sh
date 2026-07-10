#!/usr/bin/env bash
# Lane 7 / TL-5: plan-only vps-preflight rehearsal gate (no VPS required).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/VPS_SINGLE_BOX_LAUNCH.md"
OPS="$REPO_ROOT/scripts/public-devnet-v1/OPERATORS.md"
PREFLIGHT="$SCRIPT_DIR/vps-preflight.sh"
BIND_EXAMPLE="$SCRIPT_DIR/vps-bind.env.example"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates TL-5 vps-preflight docs + script wiring (no live mesh).
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

for f in "$DOC" "$OPS" "$PREFLIGHT" "$BIND_EXAMPLE"; do
  if [[ ! -f "$f" ]]; then
    echo "vps-preflight-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

for needle in \
  "vps-preflight.sh" \
  "vps-internet-soak.sh" \
  "vps-bind.env" \
  ; do
  if ! grep -qF -- "$needle" "$DOC"; then
    echo "vps-preflight-rehearsal-smoke: VPS_SINGLE_BOX_LAUNCH.md missing: $needle" >&2
    exit 1
  fi
done

if ! grep -qF -- "vps-preflight" "$OPS"; then
  echo "vps-preflight-rehearsal-smoke: OPERATORS.md missing vps-preflight" >&2
  exit 1
fi

for needle in \
  "vps-bind-lib.sh" \
  "mfn-storage-operator" \
  "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005" \
  "vps-internet-soak.sh" \
  ; do
  if ! grep -qF -- "$needle" "$PREFLIGHT"; then
    echo "vps-preflight-rehearsal-smoke: vps-preflight.sh missing: $needle" >&2
    exit 1
  fi
done

echo "vps-preflight-rehearsal-smoke: plan"
echo "  flow=vps-preflight.sh -> vps-internet-soak.sh"
echo "  bind_template=vps-bind.env.example"
echo "  docs=docs/VPS_SINGLE_BOX_LAUNCH.md"
echo "  live_rehearsal=human VPS before TL-5 soak"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "vps-preflight-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "vps-preflight-rehearsal-smoke: live mode not implemented; run vps-preflight.sh on VPS" >&2
exit 1
