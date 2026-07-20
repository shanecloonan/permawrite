#!/usr/bin/env bash
# B-55: build + install + start the public testnet frontend on the VPS.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
FRONT="$REPO_ROOT/testnet-frontend"
PLAN_ONLY=0
APPLY=0
OPEN_UFW=1

usage() {
  cat <<'EOF'
usage: vps-start-testnet-frontend.sh [--plan-only|--apply] [--no-ufw]

Builds Next.js testnet-frontend, installs systemd unit, opens UFW :3000,
restarts testnet-frontend.service. Does not touch mfnd or faucet-http.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    --no-ufw) OPEN_UFW=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "vps-start-testnet-frontend: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "vps-start-testnet-frontend: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "vps-start-testnet-frontend: plan"
  echo "  unit=B-55"
  echo "  flow=npm ci/install -> npm run build -> install systemd -> ufw allow 3000/tcp -> restart"
  echo "  url=http://5.161.201.73:3000/testnet"
  echo "  never=mfnd faucet-http"
  echo "vps-start-testnet-frontend: PASS plan-only"
  exit 0
fi

if [[ ! -d "$FRONT" ]]; then
  echo "vps-start-testnet-frontend: missing $FRONT" >&2
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "vps-start-testnet-frontend: npm required" >&2
  exit 1
fi

cd "$FRONT"
# Full install: next build needs typescript / types from devDependencies.
if [[ -f package-lock.json ]]; then
  npm ci
else
  npm install
fi
npm run build

install -m 644 "$SCRIPT_DIR/testnet-frontend.service" /etc/systemd/system/testnet-frontend.service
systemctl daemon-reload
systemctl enable testnet-frontend.service
if (( OPEN_UFW )) && command -v ufw >/dev/null 2>&1; then
  ufw allow 3000/tcp comment 'permawrite-testnet-frontend' || true
  ufw status | head -20 || true
fi
systemctl restart testnet-frontend.service
sleep 2
systemctl is-active testnet-frontend.service
curl -fsS --max-time 10 http://127.0.0.1:3000/testnet >/dev/null
echo "vps-start-testnet-frontend: OK http://127.0.0.1:3000/testnet"