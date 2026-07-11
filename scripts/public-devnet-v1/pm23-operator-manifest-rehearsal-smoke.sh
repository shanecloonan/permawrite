#!/usr/bin/env bash
# P32 phase 4a / PM23: plan-only operator-manifest separation rehearsal.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/REFERENCE_TOPOLOGY.md"
PRIV="$REPO_ROOT/docs/PRIVACY_HARDENING.md"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates PM23 operator-manifest separation docs + role env templates (no live mesh).
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

for f in "$DOC" "$PRIV"; do
  if [[ ! -f "$f" ]]; then
    echo "pm23-operator-manifest-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

for needle in \
  "PM23" \
  "Operator manifests" \
  "stay off wallet machines" \
  "operator-manifest separation" \
  ; do
  if ! grep -qF -- "$needle" "$DOC"; then
    echo "pm23-operator-manifest-rehearsal-smoke: REFERENCE_TOPOLOGY.md missing: $needle" >&2
    exit 1
  fi
done

if ! grep -qF -- "PM23" "$PRIV"; then
  echo "pm23-operator-manifest-rehearsal-smoke: PRIVACY_HARDENING.md missing PM23" >&2
  exit 1
fi

wallet_tpl="$SCRIPT_DIR/vps-role-wallet.env.example"
validator_tpl="$SCRIPT_DIR/vps-role-validator.env.example"
operator_tpl="$SCRIPT_DIR/vps-role-operator.env.example"

for tpl in "$wallet_tpl" "$validator_tpl" "$operator_tpl"; do
  if [[ ! -f "$tpl" ]]; then
    echo "pm23-operator-manifest-rehearsal-smoke: missing $tpl" >&2
    exit 1
  fi
done

for forbidden in mfn-storage-operator manifest-info MFN_OPERATOR_DATA; do
  if grep -qiF -- "$forbidden" "$wallet_tpl"; then
    echo "pm23-operator-manifest-rehearsal-smoke: wallet template must not reference $forbidden" >&2
    exit 1
  fi
done

for forbidden in MFN_WALLET mfn-storage-operator MFN_OPERATOR_DATA; do
  if grep -qiF -- "$forbidden" "$validator_tpl"; then
    echo "pm23-operator-manifest-rehearsal-smoke: validator template must not reference $forbidden" >&2
    exit 1
  fi
done

if ! grep -qF -- "MFN_OPERATOR_DATA" "$operator_tpl"; then
  echo "pm23-operator-manifest-rehearsal-smoke: operator template missing MFN_OPERATOR_DATA" >&2
  exit 1
fi
if grep -qiF -- "MFND_VALIDATOR_INDEX" "$operator_tpl" || grep -qiF -- "MFND_VRF_SEED" "$operator_tpl"; then
  echo "pm23-operator-manifest-rehearsal-smoke: operator template must not include validator seeds" >&2
  exit 1
fi

topology="$REPO_ROOT/mfn-node/src/role_topology.rs"
pm23_rs="$REPO_ROOT/mfn-storage-operator/src/pm23.rs"
if ! grep -qF -- "mfnd_pm23_warning" "$topology"; then
  echo "pm23-operator-manifest-rehearsal-smoke: role_topology.rs missing mfnd_pm23_warning lint" >&2
  exit 1
fi
if [[ ! -f "$pm23_rs" ]] || ! grep -qF -- "mfn_storage_operator_pm23_warning" "$pm23_rs"; then
  echo "pm23-operator-manifest-rehearsal-smoke: mfn-storage-operator missing PM23 runtime lint" >&2
  exit 1
fi

echo "pm23-operator-manifest-rehearsal-smoke: plan"
echo "  flow=REFERENCE_TOPOLOGY PM23 rules + vps-role-*.env.example separation"
echo "  wallet=no operator manifest / mfn-storage-operator paths"
echo "  validator=no wallet or operator manifest paths"
echo "  operator=operator data only; no validator seeds"
echo "  runtime=mfnd_pm23_warning + mfn_storage_operator_pm23_warning (warn-only; MFND_PM23_HARD_FAIL=1)"
echo "  docs=docs/REFERENCE_TOPOLOGY.md docs/PRIVACY_HARDENING.md"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "pm23-operator-manifest-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "pm23-operator-manifest-rehearsal-smoke: live mode not implemented" >&2
exit 1
