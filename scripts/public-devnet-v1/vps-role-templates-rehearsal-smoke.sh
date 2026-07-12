#!/usr/bin/env bash
# P32 / Lane 7: plan-only role-separated VPS env template rehearsal (no VPS required).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/REFERENCE_TOPOLOGY.md"
PROVISION="$REPO_ROOT/docs/VPS_PROVISION.md"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates vps-role-*.env.example separation + REFERENCE_TOPOLOGY cross-links.
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

for f in "$DOC" "$PROVISION"; do
  if [[ ! -f "$f" ]]; then
    echo "vps-role-templates-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

validator_tpl="$SCRIPT_DIR/vps-role-validator.env.example"
observer_tpl="$SCRIPT_DIR/vps-role-observer.env.example"
operator_tpl="$SCRIPT_DIR/vps-role-operator.env.example"
wallet_tpl="$SCRIPT_DIR/vps-role-wallet.env.example"

for tpl in "$validator_tpl" "$observer_tpl" "$operator_tpl" "$wallet_tpl"; do
  if [[ ! -f "$tpl" ]]; then
    echo "vps-role-templates-rehearsal-smoke: missing $tpl" >&2
    exit 1
  fi
  base="$(basename "$tpl")"
  if ! grep -qF -- "$base" "$DOC"; then
    echo "vps-role-templates-rehearsal-smoke: REFERENCE_TOPOLOGY.md missing $base" >&2
    exit 1
  fi
done

if ! grep -qF -- "vps-role-" "$PROVISION"; then
  echo "vps-role-templates-rehearsal-smoke: VPS_PROVISION.md missing vps-role- cross-link" >&2
  exit 1
fi

if ! grep -qF -- "MFND_PM23_HARD_FAIL=1" "$validator_tpl"; then
  echo "vps-role-templates-rehearsal-smoke: validator template missing MFND_PM23_HARD_FAIL=1" >&2
  exit 1
fi
if ! grep -qF -- "MFND_PM23_HARD_FAIL=1" "$observer_tpl"; then
  echo "vps-role-templates-rehearsal-smoke: observer template missing MFND_PM23_HARD_FAIL=1" >&2
  exit 1
fi
if ! grep -qE -- "MFN_STORAGE_OPERATOR_PM23_HARD_FAIL=1|MFND_PM23_HARD_FAIL=1" "$operator_tpl"; then
  echo "vps-role-templates-rehearsal-smoke: operator template missing PM23 hard-fail env" >&2
  exit 1
fi

for forbidden in MFND_VALIDATOR_INDEX MFND_VRF_SEED MFND_BLS_SEED; do
  if grep -qiF -- "$forbidden" "$observer_tpl"; then
    echo "vps-role-templates-rehearsal-smoke: observer template must not include $forbidden" >&2
    exit 1
  fi
done
for forbidden in MFN_WALLET mfn-storage-operator MFN_OPERATOR_DATA; do
  if grep -qiF -- "$forbidden" "$validator_tpl"; then
    echo "vps-role-templates-rehearsal-smoke: validator template must not reference $forbidden" >&2
    exit 1
  fi
done
for forbidden in mfn-storage-operator manifest-info MFN_OPERATOR_DATA; do
  if grep -qiF -- "$forbidden" "$wallet_tpl"; then
    echo "vps-role-templates-rehearsal-smoke: wallet template must not reference $forbidden" >&2
    exit 1
  fi
done

echo "vps-role-templates-rehearsal-smoke: plan"
echo "  docs=docs/REFERENCE_TOPOLOGY.md docs/VPS_PROVISION.md"
echo "  templates=validator observer operator wallet"
echo "  pm23=validator+observer MFND_PM23_HARD_FAIL=1; operator storage-operator hard-fail"
echo "  separation=observer no validator seeds; validator no wallet/operator paths"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "vps-role-templates-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "vps-role-templates-rehearsal-smoke: live mode not implemented" >&2
exit 1
