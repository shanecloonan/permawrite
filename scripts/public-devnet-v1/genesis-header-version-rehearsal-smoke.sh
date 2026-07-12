#!/usr/bin/env bash
# Lane 4 / TL-7 Path B: plan-only genesis header_version rehearsal gate (PROBLEMS.md §12).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/TESTNET_GENESIS_CEREMONY.md"
SECURITY="$REPO_ROOT/docs/SECURITY_CONSIDERATIONS.md"
PROBLEMS="$REPO_ROOT/docs/PROBLEMS.md"
GENESIS="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.json"
HEADER_RS="$REPO_ROOT/mfn-consensus/src/block/header.rs"
GENESIS_RS="$REPO_ROOT/mfn-consensus/src/block/genesis.rs"
GENESIS_SPEC="$REPO_ROOT/mfn-runtime/src/genesis_spec.rs"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates Path B header_version 1/2 docs + public devnet v1 stays on v1 (no VPS).
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

for f in "$DOC" "$SECURITY" "$PROBLEMS" "$GENESIS" "$HEADER_RS" "$GENESIS_RS" "$GENESIS_SPEC"; do
  if [[ ! -f "$f" ]]; then
    echo "genesis-header-version-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

for needle in \
  "header_version: 2" \
  "utxo_root" \
  ; do
  if ! grep -qF -- "$needle" "$DOC"; then
    echo "genesis-header-version-rehearsal-smoke: TESTNET_GENESIS_CEREMONY.md missing: $needle" >&2
    exit 1
  fi
done

if ! grep -qF -- "header_version: 2" "$SECURITY"; then
  echo "genesis-header-version-rehearsal-smoke: SECURITY_CONSIDERATIONS.md missing header_version: 2" >&2
  exit 1
fi
if ! grep -qF -- "genesis-threaded" "$PROBLEMS"; then
  echo "genesis-header-version-rehearsal-smoke: PROBLEMS.md missing genesis-threaded status" >&2
  exit 1
fi
if ! grep -qF -- "HEADER_VERSION_UTXO_QUORUM" "$HEADER_RS"; then
  echo "genesis-header-version-rehearsal-smoke: header.rs missing HEADER_VERSION_UTXO_QUORUM" >&2
  exit 1
fi
if ! grep -qF -- "header_version" "$GENESIS_RS"; then
  echo "genesis-header-version-rehearsal-smoke: genesis.rs missing header_version field" >&2
  exit 1
fi
if ! grep -qF -- "accepts_header_version_two" "$GENESIS_SPEC"; then
  echo "genesis-header-version-rehearsal-smoke: genesis_spec.rs missing accepts_header_version_two test" >&2
  exit 1
fi

if grep -qF -- '"header_version": 2' "$GENESIS"; then
  echo "genesis-header-version-rehearsal-smoke: public_devnet_v1.json must stay header v1 (Path A)" >&2
  exit 1
fi

echo "genesis-header-version-rehearsal-smoke: plan"
echo "  path_a=public_devnet_v1.json defaults header v1"
echo "  path_b=optional header_version: 2 in fresh genesis JSON"
echo "  consensus=HEADER_VERSION_UTXO_QUORUM signing bytes"
echo "  docs=TESTNET_GENESIS_CEREMONY.md SECURITY_CONSIDERATIONS.md PROBLEMS.md"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "genesis-header-version-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "genesis-header-version-rehearsal-smoke: live mode not implemented" >&2
exit 1
