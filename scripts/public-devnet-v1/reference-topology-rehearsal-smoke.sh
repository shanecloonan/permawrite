#!/usr/bin/env bash
# P32: plan-only reference topology rehearsal (B8.3 parity).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/REFERENCE_TOPOLOGY.md"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates P32 reference topology doc + harness strings (no live mesh).
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

if [[ ! -f "$DOC" ]]; then
  echo "reference-topology-rehearsal-smoke: missing $DOC" >&2
  exit 1
fi

for needle in \
  "mfnd_role_topology_warning" \
  "Loopback devnet" \
  "Wallet keys never on validator" \
  "mfn-cli --tor" \
  ; do
  if ! grep -q "$needle" "$DOC"; then
    echo "reference-topology-rehearsal-smoke: REFERENCE_TOPOLOGY.md missing: $needle" >&2
    exit 1
  fi
done

echo "reference-topology-rehearsal-smoke: plan"
echo "  flow=read REFERENCE_TOPOLOGY.md -> verify P32 harness + separation rules"
echo "  docs=docs/REFERENCE_TOPOLOGY.md"
echo "  lint=mfnd_role_topology_warning (phase 0 shipped f76991a)"
echo "  live_rehearsal=deferred (VPS TL-5/TL-6 uses separated observer + validators)"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "reference-topology-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "reference-topology-rehearsal-smoke: live mode not implemented; use VPS TL-6" >&2
exit 1
