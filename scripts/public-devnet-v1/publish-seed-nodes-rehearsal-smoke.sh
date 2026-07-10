#!/usr/bin/env bash
# Lane 7 / TL-8: plan-only publish-seed-nodes rehearsal gate (no VPS required).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/VPS_SINGLE_BOX_LAUNCH.md"
INVITE="$REPO_ROOT/docs/TESTNET_INVITE.md"
OPS="$REPO_ROOT/scripts/public-devnet-v1/OPERATORS.md"
PUBLISH="$SCRIPT_DIR/publish-seed-nodes.sh"
MANIFEST="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.manifest.json"
BIND_EXAMPLE="$SCRIPT_DIR/vps-bind.env.example"
FIXTURE_IP="203.0.113.1"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates TL-8 publish-seed-nodes docs + dry-run with vps-bind.env.example (no live VPS).
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

for f in "$DOC" "$INVITE" "$OPS" "$PUBLISH" "$MANIFEST" "$BIND_EXAMPLE"; do
  if [[ ! -f "$f" ]]; then
    echo "publish-seed-nodes-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

for needle in \
  "publish-seed-nodes.sh" \
  "TL-8" \
  "Never publish RPC" \
  "seed_nodes" \
  ; do
  if ! grep -qF -- "$needle" "$DOC"; then
    echo "publish-seed-nodes-rehearsal-smoke: VPS_SINGLE_BOX_LAUNCH.md missing: $needle" >&2
    exit 1
  fi
done

for needle in \
  "seed_nodes" \
  "public_devnet_v1.manifest.json" \
  "checkpointLogVerify" \
  ; do
  if ! grep -qF -- "$needle" "$INVITE"; then
    echo "publish-seed-nodes-rehearsal-smoke: TESTNET_INVITE.md missing: $needle" >&2
    exit 1
  fi
done

if ! grep -qF -- "publish-seed-nodes" "$OPS"; then
  echo "publish-seed-nodes-rehearsal-smoke: OPERATORS.md missing publish-seed-nodes" >&2
  exit 1
fi
if ! grep -qF -- "Never put RPC" "$PUBLISH"; then
  echo "publish-seed-nodes-rehearsal-smoke: publish-seed-nodes.sh must warn against RPC in seed_nodes" >&2
  exit 1
fi

preview="$(MFN_VPS_BIND_FILE="$BIND_EXAMPLE" bash "$PUBLISH" --public-ip "$FIXTURE_IP" 2>&1)" || {
  echo "publish-seed-nodes-rehearsal-smoke: dry-run failed" >&2
  exit 1
}
if [[ "$preview" != *"dry-run only"* ]]; then
  echo "publish-seed-nodes-rehearsal-smoke: expected dry-run output from publish-seed-nodes.sh" >&2
  exit 1
fi
for port in 19001 19002 19003; do
  if [[ "$preview" != *"${FIXTURE_IP}:${port}"* ]]; then
    echo "publish-seed-nodes-rehearsal-smoke: preview missing ${FIXTURE_IP}:${port}" >&2
    exit 1
  fi
done

echo "publish-seed-nodes-rehearsal-smoke: plan"
echo "  flow=publish-seed-nodes.sh --public-ip VPS_IP [--apply]"
echo "  fixture_bind=$BIND_EXAMPLE"
echo "  fixture_preview=${FIXTURE_IP}:19001,19002,19003"
echo "  manifest=mfn-node/testdata/public_devnet_v1.manifest.json"
echo "  invite=docs/TESTNET_INVITE.md"
echo "  live_rehearsal=human VPS after TL-7 sign-off"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "publish-seed-nodes-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "publish-seed-nodes-rehearsal-smoke: live mode not implemented; run publish-seed-nodes.sh on VPS" >&2
exit 1
