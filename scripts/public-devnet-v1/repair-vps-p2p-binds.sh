#!/usr/bin/env bash
# B-41: expose published seed_nodes while keeping mfnd P2P on loopback (lane 7).
#
# Direct mfnd --p2p-listen 0.0.0.0 hangs on this VPS before RPC bind (observed
# 2026-07-20). Linux also cannot bind socat 0.0.0.0:PORT while mfnd holds
# 127.0.0.1:PORT — remap mfnd to 1910x and forward public 1900x -> 1910x.
set -euo pipefail

APPLY=0
PLAN_ONLY=0
PUBLIC_IP="${MFN_VPS_PUBLIC_IP:-}"

usage() {
  cat <<'EOF'
usage: repair-vps-p2p-binds.sh [--plan-only|--apply] [--public-ip IP]

B-41 — public seed reachability without binding mfnd on 0.0.0.0.

  --plan-only     CI-safe preview
  --apply         remap mfnd to 1910x + enable socat 1900x->1910x (systemd)
  --public-ip IP  probe TCP IP:19001-19003 after apply
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
  echo "  flow=mfnd P2P 127.0.0.1:19101-19104 + socat 0.0.0.0:19001-19004 -> 19101-19104"
  echo "  rpc_unchanged=127.0.0.1"
  echo "  faucet=not restarted"
  echo "  note=do not bind mfnd on 0.0.0.0 (startup hang); do not socat same port as mfnd loopback"
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

patch_unit() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "${f}.bak.b41-$(date -u +%Y%m%d%H%M%S)"
}

patch_unit /etc/systemd/system/mfnd-hub.service
patch_unit /etc/systemd/system/mfnd-v1.service
patch_unit /etc/systemd/system/mfnd-v2.service
patch_unit /etc/systemd/system/mfnd-observer.service

[[ -f /etc/systemd/system/mfnd-hub.service ]] && sed -i \
  -e 's|Environment=MFN_P2P_LISTEN=127.0.0.1:19001|Environment=MFN_P2P_LISTEN=127.0.0.1:19101|' \
  -e 's|Environment=MFN_P2P_LISTEN=0.0.0.0:19001|Environment=MFN_P2P_LISTEN=127.0.0.1:19101|' \
  /etc/systemd/system/mfnd-hub.service
[[ -f /etc/systemd/system/mfnd-v1.service ]] && sed -i \
  -e 's|Environment=MFN_P2P_LISTEN=127.0.0.1:19002|Environment=MFN_P2P_LISTEN=127.0.0.1:19102|' \
  -e 's|Environment=HUB_P2P=127.0.0.1:19001|Environment=HUB_P2P=127.0.0.1:19101|' \
  /etc/systemd/system/mfnd-v1.service
[[ -f /etc/systemd/system/mfnd-v2.service ]] && sed -i \
  -e 's|Environment=MFN_P2P_LISTEN=127.0.0.1:19003|Environment=MFN_P2P_LISTEN=127.0.0.1:19103|' \
  -e 's|Environment=HUB_P2P=127.0.0.1:19001|Environment=HUB_P2P=127.0.0.1:19101|' \
  /etc/systemd/system/mfnd-v2.service
[[ -f /etc/systemd/system/mfnd-observer.service ]] && sed -i \
  -e 's|Environment=MFN_P2P_LISTEN=127.0.0.1:19004|Environment=MFN_P2P_LISTEN=127.0.0.1:19104|' \
  -e 's|Environment=HUB_P2P=127.0.0.1:19001|Environment=HUB_P2P=127.0.0.1:19101|' \
  /etc/systemd/system/mfnd-observer.service

write_forward() {
  local pub="$1" int="$2" name="$3"
  cat >"/etc/systemd/system/${name}.service" <<UNIT
[Unit]
Description=Permawrite public P2P forward ${pub} -> 127.0.0.1:${int}
After=network.target mfnd-hub.service
Wants=mfnd-hub.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:${pub},fork,reuseaddr,bind=0.0.0.0 TCP:127.0.0.1:${int}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
}

write_forward 19001 19101 mfn-p2p-forward-hub
write_forward 19002 19102 mfn-p2p-forward-19002
write_forward 19003 19103 mfn-p2p-forward-19003
write_forward 19004 19104 mfn-p2p-forward-19004

systemctl daemon-reload
systemctl disable --now \
  mfn-p2p-forward@19001.service \
  mfn-p2p-forward@19002.service \
  mfn-p2p-forward@19003.service \
  mfn-p2p-forward@19004.service 2>/dev/null || true

# B-46: keep quoted MFN_P2P_DIAL_EXTRA on hub (avoids 300s voter quarantine after remap).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -x "$SCRIPT_DIR/vps-soften-mfnd-requires.sh" ]]; then
  bash "$SCRIPT_DIR/vps-soften-mfnd-requires.sh" || true
fi

systemctl restart mfnd-hub.service
echo "repair-vps-p2p-binds: waiting for hub RPC (chain replay can take ~2m)..."
mcli=""
if command -v mfn-cli >/dev/null 2>&1; then mcli=mfn-cli
elif [[ -x /root/permawrite/target/release/mfn-cli ]]; then mcli=/root/permawrite/target/release/mfn-cli
fi
for i in $(seq 1 90); do
  if [[ -n "$mcli" ]] && "$mcli" --rpc 127.0.0.1:18731 tip >/dev/null 2>&1; then
    echo "repair-vps-p2p-binds: hub_ready attempt=$i"
    break
  fi
  sleep 2
done
systemctl restart mfnd-v1.service mfnd-v2.service 2>/dev/null || true
sleep 4
systemctl restart mfnd-observer.service 2>/dev/null || true
systemctl enable --now \
  mfn-p2p-forward-hub.service \
  mfn-p2p-forward-19002.service \
  mfn-p2p-forward-19003.service \
  mfn-p2p-forward-19004.service

ss -lntp | grep -E ':1900|:1910|:1873' || true

if [[ -n "$PUBLIC_IP" ]]; then
  fail=0
  for p in 19001 19002 19003; do
    if timeout 3 bash -c "echo >/dev/tcp/${PUBLIC_IP}/${p}" 2>/dev/null; then
      echo "repair-vps-p2p-binds: probe ${PUBLIC_IP}:${p} OPEN"
    else
      echo "repair-vps-p2p-binds: probe ${PUBLIC_IP}:${p} FAILED" >&2
      fail=1
    fi
  done
  (( fail == 0 )) || exit 1
fi


# Persist loopback committee dials for hub (B-46) — peers file for ops/debug.
write_local_peers() {
  local out="${1:-/root/.mfn/local-committee-peers.txt}"
  mkdir -p "$(dirname "$out")"
  cat >"$out" <<'PEERS'
127.0.0.1:19101
127.0.0.1:19102
127.0.0.1:19103
127.0.0.1:19104
PEERS
  echo "repair-vps-p2p-binds: write_local_peers -> $out"
}
write_local_peers

echo "repair-vps-p2p-binds: OK"