#!/usr/bin/env bash
# B-41: expose published seed_nodes while keeping mfnd P2P on loopback (lane 7).
#
# Direct mfnd --p2p-listen 0.0.0.0 hangs on this VPS before RPC bind (observed
# 2026-07-20). Working posture: mfnd listens on 127.0.0.1; socat forwards
# 0.0.0.0:1900x -> loopback. Hub uses internal :19101 so public :19001 can bind.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLY=0
PLAN_ONLY=0
PUBLIC_IP="${MFN_VPS_PUBLIC_IP:-}"

usage() {
  cat <<'EOF'
usage: repair-vps-p2p-binds.sh [--plan-only|--apply] [--public-ip IP]

B-41 — public seed reachability without binding mfnd on 0.0.0.0.

  --plan-only     CI-safe preview
  --apply         install/enable socat forwards + hub :19101 remap (systemd)
  --public-ip IP  probe TCP IP:19001 after apply
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    --public-ip) PUBLIC_IP="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "repair-vps-p2p-binds: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "repair-vps-p2p-binds: specify --plan-only or --apply" >&2
  exit 1
fi
if (( PLAN_ONLY && APPLY )); then
  echo "repair-vps-p2p-binds: --plan-only and --apply are mutually exclusive" >&2
  exit 1
fi

echo "repair-vps-p2p-binds: B-41"

if (( PLAN_ONLY )); then
  echo "  flow=hub P2P 127.0.0.1:19101 + socat 0.0.0.0:19001->19101; voters/observer 127.0.0.1:1900x + socat 0.0.0.0:1900x"
  echo "  rpc_unchanged=127.0.0.1"
  echo "  faucet=not restarted"
  echo "  note=do not bind mfnd directly on 0.0.0.0 (startup hang observed)"
  echo "  docs=scripts/public-devnet-v1/vps-bind.env.example"
  echo "repair-vps-p2p-binds: PASS plan-only"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "repair-vps-p2p-binds: --apply must run as root on the VPS" >&2
  exit 1
fi

if ! command -v socat >/dev/null 2>&1; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq socat
fi

if [[ -f /etc/systemd/system/mfnd-hub.service ]]; then
  cp -a /etc/systemd/system/mfnd-hub.service "/etc/systemd/system/mfnd-hub.service.bak.b41-$(date -u +%Y%m%d%H%M%S)"
  sed -i 's|Environment=MFN_P2P_LISTEN=127.0.0.1:19001|Environment=MFN_P2P_LISTEN=127.0.0.1:19101|' /etc/systemd/system/mfnd-hub.service
  sed -i 's|Environment=MFN_P2P_LISTEN=0.0.0.0:19001|Environment=MFN_P2P_LISTEN=127.0.0.1:19101|' /etc/systemd/system/mfnd-hub.service
  for u in mfnd-v1 mfnd-v2 mfnd-observer; do
    f=/etc/systemd/system/${u}.service
    [[ -f "$f" ]] || continue
    sed -i 's|Environment=HUB_P2P=127.0.0.1:19001|Environment=HUB_P2P=127.0.0.1:19101|' "$f"
  done
fi

cat >/etc/systemd/system/mfn-p2p-forward@.service <<'UNIT'
[Unit]
Description=Permawrite public P2P forward %i -> 127.0.0.1:%i
After=network.target mfnd-hub.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:%i,fork,reuseaddr,bind=0.0.0.0 TCP:127.0.0.1:%i
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/mfn-p2p-forward-hub.service <<'UNIT'
[Unit]
Description=Permawrite public P2P forward 19001 -> 127.0.0.1:19101 (hub)
After=network.target mfnd-hub.service
Requires=mfnd-hub.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:19001,fork,reuseaddr,bind=0.0.0.0 TCP:127.0.0.1:19101
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl restart mfnd-hub.service
echo "repair-vps-p2p-binds: waiting for hub RPC (chain replay can take ~2m)..."
for i in $(seq 1 90); do
  if command -v mfn-cli >/dev/null 2>&1; then
    mcli=mfn-cli
  elif [[ -x /root/permawrite/target/release/mfn-cli ]]; then
    mcli=/root/permawrite/target/release/mfn-cli
  else
    mcli=""
  fi
  if [[ -n "$mcli" ]] && "$mcli" --rpc 127.0.0.1:18731 tip >/dev/null 2>&1; then
    echo "repair-vps-p2p-binds: hub_ready attempt=$i"
    break
  fi
  sleep 2
done
systemctl restart mfnd-v1.service mfnd-v2.service 2>/dev/null || true
sleep 3
systemctl restart mfnd-observer.service 2>/dev/null || true
systemctl disable --now mfn-p2p-forward@19001.service 2>/dev/null || true
systemctl enable --now mfn-p2p-forward-hub.service
for p in 19002 19003 19004; do
  systemctl enable --now "mfn-p2p-forward@${p}.service"
done

ss -lntp | grep -E ':1900|:1910|:1873' || true

if [[ -n "$PUBLIC_IP" ]]; then
  if timeout 3 bash -c "echo >/dev/tcp/${PUBLIC_IP}/19001" 2>/dev/null; then
    echo "repair-vps-p2p-binds: probe ${PUBLIC_IP}:19001 OPEN"
  else
    echo "repair-vps-p2p-binds: probe ${PUBLIC_IP}:19001 FAILED" >&2
    exit 1
  fi
fi

echo "repair-vps-p2p-binds: OK"
