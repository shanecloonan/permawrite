#!/usr/bin/env bash
# Lane 7 / TL-8: preview or apply seed_nodes for internet-facing VPS (P2P only).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
MANIFEST="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.manifest.json"
BIND="${MFN_VPS_BIND_FILE:-$SCRIPT_DIR/vps-bind.env}"
PUBLIC_IP=""
APPLY=0

usage() {
  cat <<'EOF'
usage: publish-seed-nodes.sh [--public-ip IP] [--apply]

Reads vps-bind.env P2P ports and prints seed_nodes JSON for TL-8.
Default is dry-run (stdout only). --apply writes manifest seed_nodes in place.

Never put RPC addresses in seed_nodes.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-ip) PUBLIC_IP="${2:?}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "publish-seed-nodes: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$BIND" ]]; then
  echo "publish-seed-nodes: missing $BIND (copy vps-bind.env.example)" >&2
  exit 1
fi
# shellcheck source=/dev/null
source "$BIND"

if [[ -z "$PUBLIC_IP" ]]; then
  if command -v curl >/dev/null 2>&1; then
    PUBLIC_IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  elif command -v wget >/dev/null 2>&1; then
    PUBLIC_IP="$(wget -qO- --timeout=5 https://api.ipify.org 2>/dev/null || true)"
  fi
fi
if [[ -z "$PUBLIC_IP" ]]; then
  echo "publish-seed-nodes: set --public-ip or ensure curl/wget can reach api.ipify.org" >&2
  exit 1
fi

port_from_bind() {
  local var="$1"
  local listen="${!var:-}"
  if [[ -z "$listen" ]]; then
    echo "publish-seed-nodes: missing $var in $BIND" >&2
    exit 1
  fi
  printf '%s\n' "${listen##*:}"
}

HUB_PORT="$(port_from_bind MFN_P2P_LISTEN_HUB)"
V1_PORT="$(port_from_bind MFN_P2P_LISTEN_V1)"
V2_PORT="$(port_from_bind MFN_P2P_LISTEN_V2)"

SEEDS=(
  "${PUBLIC_IP}:${HUB_PORT}"
  "${PUBLIC_IP}:${V1_PORT}"
  "${PUBLIC_IP}:${V2_PORT}"
)

echo "publish-seed-nodes: TL-8 preview public_ip=$PUBLIC_IP"
echo "publish-seed-nodes: seeds=${SEEDS[*]}"
echo ""
echo '"seed_nodes": ['
for i in "${!SEEDS[@]}"; do
  comma=","
  if (( i == ${#SEEDS[@]} - 1 )); then comma=""; fi
  echo "  \"${SEEDS[$i]}\"$comma"
done
echo ']'

if (( APPLY == 0 )); then
  echo ""
  echo "publish-seed-nodes: dry-run only; re-run with --apply after TL-7 sign-off"
  exit 0
fi

if [[ ! -f "$MANIFEST" ]]; then
  echo "publish-seed-nodes: missing manifest $MANIFEST" >&2
  exit 1
fi

export MANIFEST PUBLIC_IP HUB_PORT V1_PORT V2_PORT
python3 - <<'PY'
import json, os, sys

path = os.environ["MANIFEST"]
with open(path, encoding="utf-8") as f:
    doc = json.load(f)
ip = os.environ["PUBLIC_IP"]
seeds = [
    f"{ip}:{os.environ['HUB_PORT']}",
    f"{ip}:{os.environ['V1_PORT']}",
    f"{ip}:{os.environ['V2_PORT']}",
]
doc["seed_nodes"] = seeds
with open(path, "w", encoding="utf-8", newline="\n") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print(f"publish-seed-nodes: applied seed_nodes to {path}", file=sys.stderr)
PY

echo "publish-seed-nodes: OK applied - commit manifest + share docs/TESTNET_INVITE.md + run launch-go-no-go.sh"
