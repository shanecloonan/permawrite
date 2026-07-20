#!/usr/bin/env bash
# B-62 / B-65 / lane 7: release-build mfnd + mfn-cli on the VPS without restarting any unit.
# Use while waiting for CI GREEN so vps-roll-mfnd.sh --apply --skip-build is fast.
# B-65: source lib-cargo-env.sh (non-interactive PATH lacks cargo).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PLAN_ONLY=0
APPLY=0
STATUS_FILE="${MFN_PREBUILD_STATUS:-/tmp/mfn-prebuild.status}"

usage() {
  cat <<'EOF'
usage: vps-prebuild-mfnd.sh [--plan-only|--apply]

Builds target/release/mfnd and mfn-cli. Never restarts mfnd/faucet/proxy.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "vps-prebuild-mfnd: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "vps-prebuild-mfnd: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "vps-prebuild-mfnd: plan"
  echo "  unit=B-62/B-65"
  echo "  flow=cargo build mfnd + mfn-cli (release)"
  echo "  never=systemctl restart / faucet-http / observer-rpc-proxy"
  echo "  follow=vps-roll-mfnd.sh --apply --skip-build after CI GREEN"
  echo "vps-prebuild-mfnd: PASS plan-only"
  exit 0
fi

cd "$REPO_ROOT"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib-cargo-env.sh"
echo "vps-prebuild-mfnd: HEAD=$(git rev-parse --short HEAD) cargo=$(command -v cargo)"
cargo build -p mfn-node --release --bin mfnd
cargo build -p mfn-cli --release --bin mfn-cli
echo "PREBUILD_OK $(date -u +%Y%m%dT%H%M%SZ) HEAD=$(git rev-parse --short HEAD)" | tee "$STATUS_FILE"
echo "vps-prebuild-mfnd: OK"