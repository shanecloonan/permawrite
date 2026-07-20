#!/usr/bin/env bash
# B-90 / lane 7: install+restart observer-rpc-proxy with tip-align (F105).
# B-15-safe: never touches faucet/mfnd. Restarts observer-rpc-proxy only.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
APPLY=0

usage() {
  cat <<'EOF'
usage: vps-update-observer-rpc-proxy.sh [--plan-only|--apply]

Installs observer-rpc-proxy.service and restarts the proxy unit only.
Never restarts faucet-http or mfnd.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "vps-update-observer-rpc-proxy: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "vps-update-observer-rpc-proxy: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "vps-update-observer-rpc-proxy: plan"
  echo "  unit=B-90"
  echo "  flow=install service -> daemon-reload -> restart observer-rpc-proxy"
  echo "  never=faucet-http mfnd restart join-testnet-rehearsal"
  echo "vps-update-observer-rpc-proxy: PASS plan-only"
  exit 0
fi

install -m 644 "$SCRIPT_DIR/observer-rpc-proxy.service" /etc/systemd/system/observer-rpc-proxy.service
systemctl daemon-reload
systemctl restart observer-rpc-proxy.service
sleep 1
systemctl is-active observer-rpc-proxy.service
systemctl is-active faucet-http.service >/dev/null
curl -fsS --max-time 8 http://127.0.0.1:8787/health | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d.get("ok") is True; print("health_ok hub_tip_rpc=", d.get("hub_tip_rpc"), "tip_align_ms=", d.get("tip_align_ms"))'
echo "vps-update-observer-rpc-proxy: OK"