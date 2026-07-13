#!/usr/bin/env bash
# Lane 7 / TL-5: plan-only VPS_PROVISION.md rehearsal gate (no VPS required).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/VPS_PROVISION.md"
OPS="$SCRIPT_DIR/OPERATORS.md"
BIND_EXAMPLE="$SCRIPT_DIR/vps-bind.env.example"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates VPS_PROVISION.md cross-links for TL-5/TL-8 operator path.
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

for f in "$DOC" "$OPS" "$BIND_EXAMPLE"; do
  if [[ ! -f "$f" ]]; then
    echo "vps-provision-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

LAUNCH_DOC="$REPO_ROOT/docs/TESTNET_LAUNCH.md"
if [[ ! -f "$LAUNCH_DOC" ]]; then
  echo "vps-provision-rehearsal-smoke: missing $LAUNCH_DOC" >&2
  exit 1
fi
if ! grep -qF "Software-ready pin" "$LAUNCH_DOC"; then
  echo "vps-provision-rehearsal-smoke: TESTNET_LAUNCH.md missing Software-ready pin" >&2
  exit 1
fi

for needle in \
  "vps-preflight.sh" \
  "vps-execution-checklist" \
  "vps-internet-soak.sh" \
  "vps-launch-ceremony" \
  "publish-seed-nodes" \
  "TESTNET_INVITE.md" \
  "VPS_SINGLE_BOX_LAUNCH.md" \
  "TESTNET_LAUNCH.md" \
  "Software-ready pin" \
  "vps-participant-rehearsal.sh" \
  ; do
  if ! grep -qF -- "$needle" "$DOC"; then
    echo "vps-provision-rehearsal-smoke: VPS_PROVISION.md missing: $needle" >&2
    exit 1
  fi
done

if ! grep -qF "VPS_PROVISION.md" "$OPS"; then
  echo "vps-provision-rehearsal-smoke: OPERATORS.md missing VPS_PROVISION.md cross-link" >&2
  exit 1
fi

if ! grep -qF "MFND_PM23_HARD_FAIL=1" "$BIND_EXAMPLE"; then
  echo "vps-provision-rehearsal-smoke: vps-bind.env.example missing MFND_PM23_HARD_FAIL=1" >&2
  exit 1
fi

validator_tpl="$SCRIPT_DIR/vps-role-validator.env.example"
operator_tpl="$SCRIPT_DIR/vps-role-operator.env.example"
for tpl in "$validator_tpl" "$operator_tpl"; do
  if [[ ! -f "$tpl" ]]; then
    echo "vps-provision-rehearsal-smoke: missing $tpl" >&2
    exit 1
  fi
done
if ! grep -qF "MFND_PM23_HARD_FAIL=1" "$validator_tpl"; then
  echo "vps-provision-rehearsal-smoke: validator template missing MFND_PM23_HARD_FAIL=1" >&2
  exit 1
fi
if ! grep -qE "MFN_STORAGE_OPERATOR_PM23_HARD_FAIL=1|MFND_PM23_HARD_FAIL=1" "$operator_tpl"; then
  echo "vps-provision-rehearsal-smoke: operator template missing PM23 hard-fail env" >&2
  exit 1
fi

echo "vps-provision-rehearsal-smoke: plan"
echo "  docs=docs/VPS_PROVISION.md"
echo "  flow=provision -> preflight -> soak -> ceremony -> TL-8"
echo "  pm23=vps-bind + vps-role-validator MFND_PM23_HARD_FAIL=1; operator MFN_STORAGE_OPERATOR_PM23_HARD_FAIL=1"
echo "  live_rehearsal=human VPS provision before TL-5"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "vps-provision-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "vps-provision-rehearsal-smoke: live mode not implemented" >&2
exit 1
