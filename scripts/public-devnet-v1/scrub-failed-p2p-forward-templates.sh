#!/usr/bin/env bash
# B-253 / lane 7: scrub failed mfn-p2p-forward@* template instances (B-15-safe).
#
# A leftover template unit maps %i -> 127.0.0.1:%i (same public port), so
# mfn-p2p-forward@19001 fails while the correct dedicated units
# (mfn-p2p-forward-hub / 19002 / 19003 / 19004 -> 1910x) keep seeds OPEN.
# systemctl --failed then looks like a P2P outage during JOIN.
#
# Never restarts faucet/mfnd. Only disables template instances, resets failed
# state, and removes the broken template unit file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
APPLY=0
PUBLIC_IP="${MFN_VPS_PUBLIC_IP:-5.161.201.73}"

usage() {
  cat <<'EOF'
usage: scrub-failed-p2p-forward-templates.sh [--plan-only|--apply]

B-253 — clear failed mfn-p2p-forward@* units without touching mfnd/faucet.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    --public-ip) PUBLIC_IP="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "scrub-failed-p2p-forward-templates: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "scrub-failed-p2p-forward-templates: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "scrub-failed-p2p-forward-templates: plan"
  echo "  unit=B-253"
  echo "  flow=disable@instances -> reset-failed -> remove broken mfn-p2p-forward@.service"
  echo "  keep=mfn-p2p-forward-hub + mfn-p2p-forward-19002/3/4 (1900x->1910x)"
  echo "  prove=hub get_tip + seeds OPEN + systemctl --failed has no mfn-p2p-forward@"
  echo "  never=faucet-http mfnd restart join-testnet-rehearsal"
  echo "scrub-failed-p2p-forward-templates: PASS plan-only"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "scrub-failed-p2p-forward-templates: --apply must run as root on the VPS" >&2
  exit 1
fi

# Keep production forwards; only kill the broken template family.
for u in \
  mfn-p2p-forward@19001.service \
  mfn-p2p-forward@19002.service \
  mfn-p2p-forward@19003.service \
  mfn-p2p-forward@19004.service
do
  systemctl disable --now "$u" 2>/dev/null || true
  systemctl reset-failed "$u" 2>/dev/null || true
done

if [[ -f /etc/systemd/system/mfn-p2p-forward@.service ]]; then
  # Refuse same-port template forever (B-41 posture is dedicated 1900x->1910x units).
  mv -f /etc/systemd/system/mfn-p2p-forward@.service \
    "/etc/systemd/system/mfn-p2p-forward@.service.bak.b253-$(date -u +%Y%m%d%H%M%S)"
  echo "scrub-failed-p2p-forward-templates: removed broken template (same-port %i->%i)"
fi

systemctl daemon-reload

# Ensure dedicated forwards are up (no mfnd restart).
systemctl enable --now \
  mfn-p2p-forward-hub.service \
  mfn-p2p-forward-19002.service \
  mfn-p2p-forward-19003.service \
  mfn-p2p-forward-19004.service

sleep 1
for u in \
  mfn-p2p-forward-hub.service \
  mfn-p2p-forward-19002.service \
  mfn-p2p-forward-19003.service \
  mfn-p2p-forward-19004.service
do
  systemctl is-active --quiet "$u" || {
    echo "scrub-failed-p2p-forward-templates: FAIL $u not active" >&2
    exit 2
  }
done

# Hub RPC prove (F114): Connection refused must not recur for local faucet target.
python3 - <<'PY'
import json, socket
s = socket.create_connection(("127.0.0.1", 18731), 8)
s.sendall(b'{"jsonrpc":"2.0","id":1,"method":"get_tip","params":[]}\n')
buf = b""
while b"\n" not in buf:
    buf += s.recv(65536)
s.close()
tip = int(json.loads(buf.decode().split("\n", 1)[0])["result"]["tip_height"])
assert tip > 0, tip
print(f"scrub-failed-p2p-forward-templates: hub_tip={tip} F114_hub_rpc=ok")
PY

fail=0
for p in 19001 19002 19003; do
  if timeout 3 bash -c "echo >/dev/tcp/${PUBLIC_IP}/${p}" 2>/dev/null; then
    echo "scrub-failed-p2p-forward-templates: seed ${PUBLIC_IP}:${p} OPEN"
  else
    echo "scrub-failed-p2p-forward-templates: seed ${PUBLIC_IP}:${p} FAIL" >&2
    fail=1
  fi
done
(( fail == 0 )) || exit 3

# No leftover failed template units.
failed="$(systemctl list-units --failed --no-legend --no-pager 2>/dev/null || true)"
if echo "$failed" | grep -q 'mfn-p2p-forward@'; then
  echo "scrub-failed-p2p-forward-templates: FAIL template still failed:" >&2
  echo "$failed" >&2
  exit 4
fi
echo "scrub-failed-p2p-forward-templates: failed_units_clean"

# Soft note if faucet can still reach hub (no restart).
if curl -fsS --max-time 5 http://127.0.0.1:8788/health >/tmp/b253-faucet.json 2>/dev/null; then
  python3 - <<'PY'
import json
d=json.load(open("/tmp/b253-faucet.json", encoding="utf-8"))
assert d.get("ok") is True
print(f"scrub-failed-p2p-forward-templates: faucet ok busy={d.get('busy')} pending={d.get('pending_jobs')}")
PY
else
  echo "scrub-failed-p2p-forward-templates: WARN faucet /health unreachable (not fatal)"
fi

echo "scrub-failed-p2p-forward-templates: OK"
