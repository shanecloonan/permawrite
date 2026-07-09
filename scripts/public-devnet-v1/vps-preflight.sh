#!/usr/bin/env bash
# Lane 7 / TL-5: preflight checks before internet-facing VPS mesh + soak.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
# shellcheck source=vps-bind-lib.sh
source "$SCRIPT_DIR/vps-bind-lib.sh"

SKIP_UFW=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-ufw) SKIP_UFW=1; shift ;;
    -h|--help)
      echo "usage: vps-preflight.sh [--skip-ufw]" >&2
      exit 0
      ;;
    *)
      echo "vps-preflight: unknown argument $1" >&2
      exit 1
      ;;
  esac
done

load_vps_bind_file "$SCRIPT_DIR" || exit 1
vps_assert_public_devnet_policy "$REPO_ROOT" || exit 1
vps_assert_public_p2p_binds || exit 1
vps_assert_loopback_rpc_binds || exit 1

for bin in mfnd mfn-cli mfn-storage-operator; do
  if [[ ! -x "$REPO_ROOT/target/release/$bin" ]]; then
    echo "vps-preflight: missing target/release/$bin — build release binaries first" >&2
    exit 1
  fi
done

public_ip=""
if command -v curl >/dev/null 2>&1; then
  public_ip="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
elif command -v wget >/dev/null 2>&1; then
  public_ip="$(wget -qO- --timeout=5 https://api.ipify.org 2>/dev/null || true)"
fi
if [[ -n "$public_ip" ]]; then
  echo "vps-preflight: detected_public_ip=$public_ip (use for TL-8 seed_nodes)"
else
  echo "vps-preflight: WARN could not detect public IP (curl/wget unavailable or blocked)"
fi

if (( SKIP_UFW == 0 )) && command -v ufw >/dev/null 2>&1; then
  if ufw status 2>/dev/null | grep -qi "inactive"; then
    echo "vps-preflight: WARN ufw inactive — open only P2P 19001-19004 before advertising seeds" >&2
  fi
fi

echo "vps-preflight: OK genesis_id=454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005 require_endowment_range_proof=1"
echo "vps-preflight: next=bash scripts/public-devnet-v1/vps-internet-soak.sh"
