#!/usr/bin/env bash
# B-49 / lane 7: rebuild + roll mfnd on hub+voters (B-45 salted SPoRA; B-48 when on main).
# Never restarts faucet-http. Prefer after CI GREEN. Softens Requires→Wants + dial env (B-46).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PLAN_ONLY=0
APPLY=0
SKIP_PULL=0
SKIP_BUILD=0
RPC_HUB="${MFN_ROLL_RPC:-127.0.0.1:18731}"

usage() {
  cat <<'EOF'
usage: vps-roll-mfnd.sh [--plan-only|--apply] [--skip-pull] [--skip-build] [--rpc HOST:PORT]

Rebuild target/release/mfnd (+ mfn-cli for tip wait), apply B-46 soften, restart
voters then hub only. Does NOT restart faucet-http or observer-rpc-proxy.

Gates:
  - Prefer CI GREEN on the head before --apply
  - Do not thrash while tip is mid-seal; wait for tip advance after hub restart
  - B-48 soft-EAGAIN quarantine must be on main before claiming tip-stall immunity
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    --skip-pull) SKIP_PULL=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --rpc) RPC_HUB="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "vps-roll-mfnd: unknown argument $1" >&2; usage >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "vps-roll-mfnd: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "vps-roll-mfnd: plan"
  echo "  unit=B-49"
  echo "  flow=git pull -> cargo build mfnd/mfn-cli -> vps-soften-mfnd-requires -> restart voters -> restart hub -> wait tip advance"
  echo "  never=faucet-http observer-rpc-proxy"
  echo "  gate=CI GREEN preferred; B-45 on binary; B-48 only if commit on main"
  echo "  docs=scripts/public-devnet-v1/OPERATORS.md"
  echo "vps-roll-mfnd: PASS plan-only"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "vps-roll-mfnd: --apply must run as root on the VPS" >&2
  exit 1
fi

cd "$REPO_ROOT"
MCLI="$REPO_ROOT/target/release/mfn-cli"
MFND="$REPO_ROOT/target/release/mfnd"

tip_height() {
  if [[ -x "$MCLI" ]]; then
    "$MCLI" --rpc "$RPC_HUB" tip 2>/dev/null | sed -n 's/.*tip_height=\([0-9]*\).*/\1/p' | head -1
  else
    echo ""
  fi
}

BEFORE="$(tip_height || true)"
echo "vps-roll-mfnd: apply start tip_before=${BEFORE:-unknown} rpc=$RPC_HUB"

if (( SKIP_PULL == 0 )); then
  git fetch origin main
  git pull --ff-only origin main
fi
echo "vps-roll-mfnd: HEAD=$(git rev-parse --short HEAD)"

if (( SKIP_BUILD == 0 )); then
  echo "vps-roll-mfnd: building mfnd + mfn-cli (release)..."
  cargo build -p mfn-node --release --bin mfnd
  cargo build -p mfn-cli --release --bin mfn-cli
fi

if [[ ! -x "$MFND" ]]; then
  echo "vps-roll-mfnd: missing $MFND" >&2
  exit 1
fi

bash "$SCRIPT_DIR/vps-soften-mfnd-requires.sh" || true

echo "vps-roll-mfnd: restart voters first (avoid hub early-dial quarantine)"
systemctl restart mfnd-v1.service mfnd-v2.service
sleep 6

echo "vps-roll-mfnd: restart hub only (quoted MFN_P2P_DIAL_EXTRA expected)"
systemctl restart mfnd-hub.service

echo "vps-roll-mfnd: waiting for hub tip advance..."
deadline=$((SECONDS + 180))
advanced=0
while (( SECONDS < deadline )); do
  if [[ -n "${BEFORE:-}" && "$BEFORE" =~ ^[0-9]+$ ]]; then
    NOW="$(tip_height || true)"
    if [[ -n "$NOW" && "$NOW" =~ ^[0-9]+$ ]] && (( NOW > BEFORE )); then
      echo "vps-roll-mfnd: tip advanced ${BEFORE} -> ${NOW}"
      advanced=1
      break
    fi
  else
    NOW="$(tip_height || true)"
    if [[ -n "$NOW" ]]; then
      echo "vps-roll-mfnd: hub tip readable tip_height=$NOW"
      advanced=1
      break
    fi
  fi
  sleep 3
done

systemctl is-active mfnd-hub mfnd-v1 mfnd-v2 >/dev/null
systemctl is-active faucet-http >/dev/null

if (( advanced == 0 )); then
  echo "vps-roll-mfnd: WARN tip did not advance within 180s — check hub dials / quarantine (B-46)" >&2
  journalctl -u mfnd-hub -n 40 --no-pager || true
  exit 2
fi

echo "vps-roll-mfnd: OK faucet untouched HEAD=$(git rev-parse --short HEAD) tip=$(tip_height)"
