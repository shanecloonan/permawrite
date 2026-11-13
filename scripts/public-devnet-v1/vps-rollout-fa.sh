#!/usr/bin/env bash
# Replace the live Path A chain on this host with public-devnet-fa (F-A).
#
# Run on the VPS as root. No SSH from the repo. Path A data is copied to a
# dated backup and left in place. The new chain uses .permawrite-devnet-fa.
#
#   bash scripts/public-devnet-v1/vps-rollout-fa.sh --plan-only
#   bash scripts/public-devnet-v1/vps-rollout-fa.sh --apply
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PLAN_ONLY=0
APPLY=0
BACKUP_ROOT="${MFN_FA_BACKUP_ROOT:-/root/permawrite-backups}"

usage() {
  cat <<'EOF'
usage: vps-rollout-fa.sh [--plan-only|--apply]

--plan-only   Print the rollout. Does not stop services or write backups.
--apply       Root on the VPS. Pull main, build, archive Path A data, start F-A.

Leaves .permawrite-devnet-v1 on disk and copies it to
$MFN_FA_BACKUP_ROOT/path-a-<UTC>/. Does not delete chain data.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "vps-rollout-fa: unknown $1" >&2; usage >&2; exit 2 ;;
  esac
done

if (( PLAN_ONLY == APPLY )); then
  echo "vps-rollout-fa: pass exactly one of --plan-only or --apply" >&2
  usage >&2
  exit 2
fi

# shellcheck source=/dev/null
source "$SCRIPT_DIR/config.fa.env"

plan() {
  cat <<EOF
vps-rollout-fa: PLAN
  repo=$REPO_ROOT
  genesis=$GENESIS_SPEC
  genesis_id=$GENESIS_ID
  data_root=$DATA_ROOT
  backup_root=$BACKUP_ROOT
  steps:
    1. git pull --ff-only origin main
    2. cargo build -p mfn-node -p mfn-cli --release (old chain still running)
    3. stop testnet-frontend, faucet-http, observer-rpc-proxy, mfnd-observer, mfnd-v1, mfnd-v2, mfnd-hub, path-a-near-tip-ckpt.timer
    4. cp -a .permawrite-devnet-v1 to $BACKUP_ROOT/path-a-<UTC>/ after the stop (original dir stays)
    5. systemd drop-in Environment=MFN_DEVNET_PROFILE=fa on mfnd-hub, mfnd-v1, mfnd-v2, mfnd-observer
    6. install testnet-frontend/public/testnet/config.fa.json as config.json
    7. start hub, voters, observer, faucet-http, observer-rpc-proxy, testnet-frontend
    8. health: hub tip advances, faucet :8788/health, observer :8787/rpc, frontend :3000/testnet
  manual after health:
    - Path A faucet UTXOs are not on this genesis. Fund the faucet wallet from validator 0 coinbase.
    - Tell peers to use public_devnet_fa.json. Path A checkpoints do not apply.
    - Leave path-a-near-tip-ckpt.timer disabled.
EOF
}

if (( PLAN_ONLY == 1 )); then
  plan
  echo "vps-rollout-fa: PASS plan-only"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "vps-rollout-fa: --apply must run as root" >&2
  exit 1
fi

cd "$REPO_ROOT"
if [[ -n "$(git status --porcelain)" ]]; then
  echo "vps-rollout-fa: working tree is dirty; stash or commit before --apply" >&2
  exit 1
fi

echo "vps-rollout-fa: pull origin/main"
git fetch origin main
git pull --ff-only origin main

if [[ -f /root/.cargo/env ]]; then
  # shellcheck source=/dev/null
  source /root/.cargo/env
fi
export PATH="/root/.cargo/bin:$PATH"
echo "vps-rollout-fa: cargo build release mfnd mfn-cli"
cargo build -p mfn-node -p mfn-cli --release

units=(testnet-frontend faucet-http observer-rpc-proxy mfnd-observer mfnd-v2 mfnd-v1 mfnd-hub)
for unit in "${units[@]}"; do
  systemctl stop "$unit.service" || true
done
systemctl disable --now path-a-near-tip-ckpt.timer || true

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
dest="$BACKUP_ROOT/path-a-$stamp"
mkdir -p "$dest"
if [[ -d "$REPO_ROOT/.permawrite-devnet-v1" ]]; then
  echo "vps-rollout-fa: archive $REPO_ROOT/.permawrite-devnet-v1 -> $dest"
  cp -a "$REPO_ROOT/.permawrite-devnet-v1" "$dest/permawrite-devnet-v1"
else
  echo "vps-rollout-fa: no .permawrite-devnet-v1 directory to archive"
fi
cp -a "$REPO_ROOT/mfn-node/testdata/public_devnet_v1.json" "$dest/" || true
cp -a "$REPO_ROOT/mfn-node/testdata/public_devnet_v1.manifest.json" "$dest/" || true
echo "vps-rollout-fa: backup kept at $dest (live Path A dir not removed)"

for unit in mfnd-hub mfnd-v1 mfnd-v2 mfnd-observer; do
  drop="/etc/systemd/system/$unit.service.d"
  mkdir -p "$drop"
  cat > "$drop/fa-profile.conf" <<'EOF'
[Service]
Environment=MFN_DEVNET_PROFILE=fa
EOF
done
systemctl daemon-reload

fa_cfg="$REPO_ROOT/testnet-frontend/public/testnet/config.fa.json"
served="$REPO_ROOT/testnet-frontend/public/testnet/config.json"
if [[ -f "$fa_cfg" ]]; then
  cp -a "$fa_cfg" "$served"
fi

echo "vps-rollout-fa: start mfnd-hub"
systemctl start mfnd-hub.service
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if curl -sf -m 2 "http://127.0.0.1:18731" >/dev/null 2>&1 || \
     "$REPO_ROOT/target/release/mfn-cli" --rpc 127.0.0.1:18731 tip >/dev/null 2>&1; then
    break
  fi
  sleep 5
done
systemctl start mfnd-v1.service mfnd-v2.service
sleep 8
systemctl start mfnd-observer.service
systemctl start faucet-http.service observer-rpc-proxy.service testnet-frontend.service

# shellcheck source=/dev/null
source "$SCRIPT_DIR/ports-env-lib.sh"
hub_line=""
for _ in $(seq 1 24); do
  hub_line="$(query_get_status_compat_line "127.0.0.1:18731" "$REPO_ROOT" || true)"
  height="$(printf '%s' "$hub_line" | sed -n 's/.*"tip_height":\([0-9]*\).*/\1/p')"
  genesis="$(printf '%s' "$hub_line" | sed -n 's/.*"genesis_id":"\([^"]*\)".*/\1/p')"
  if [[ "$genesis" == "$GENESIS_ID" && -n "$height" ]]; then
    break
  fi
  sleep 5
done
if [[ "${genesis:-}" != "$GENESIS_ID" ]]; then
  echo "vps-rollout-fa: hub genesis mismatch line=$hub_line" >&2
  exit 1
fi
first_height="${height:-0}"
sleep 35
hub_line2="$(query_get_status_compat_line "127.0.0.1:18731" "$REPO_ROOT")"
height2="$(printf '%s' "$hub_line2" | sed -n 's/.*"tip_height":\([0-9]*\).*/\1/p')"
if [[ -z "$height2" || "$height2" -le "$first_height" ]]; then
  echo "vps-rollout-fa: tip did not advance ($first_height -> ${height2:-none})" >&2
  exit 1
fi

faucet_code="$(curl -s -o /dev/null -w '%{http_code}' -m 10 http://127.0.0.1:8788/health || true)"
if [[ "$faucet_code" != "200" ]]; then
  echo "vps-rollout-fa: faucet /health HTTP $faucet_code" >&2
  exit 1
fi
obs_code="$(curl -s -o /dev/null -w '%{http_code}' -m 20 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_tip"}' \
  http://127.0.0.1:8787/rpc || true)"
if [[ "$obs_code" != "200" ]]; then
  echo "vps-rollout-fa: observer proxy HTTP $obs_code" >&2
  exit 1
fi
front_code="$(curl -s -o /dev/null -w '%{http_code}' -m 20 http://127.0.0.1:3000/testnet || true)"
if [[ "$front_code" != "200" ]]; then
  echo "vps-rollout-fa: frontend /testnet HTTP $front_code" >&2
  exit 1
fi

echo "vps-rollout-fa: OK genesis_id=$GENESIS_ID tip $first_height -> $height2 backup=$dest"
echo "vps-rollout-fa: manual: fund the faucet from validator 0. Path A UTXOs are not on this chain."
echo "vps-rollout-fa: manual: peers must switch to mfn-node/testdata/public_devnet_fa.json"
