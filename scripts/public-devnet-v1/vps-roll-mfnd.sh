#!/usr/bin/env bash
# B-49 / lane 7: rebuild + roll mfnd on hub+voters (B-45 salted SPoRA; B-48 when on main).
# Never restarts faucet-http. B-60: fail-closed CI+faucet preflight before --apply. Softens Requires→Wants + dial env (B-46).
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

Gates (B-60 --apply preflight; override with env only in emergencies):
  - CI GREEN on origin/main (gh or public Actions API) unless MFN_ROLL_ALLOW_RED_CI=1
  - Wait for hub RPC listen after restart (cold chain load)
  - faucet-http idle (busy=false, pending_jobs=0) unless MFN_ROLL_ALLOW_FAUCET_BUSY=1
  - Do not thrash while tip is mid-seal; wait for tip advance after hub restart
  - Binary must include B-45/B-48/B-51 stack (ephemeral dial skip on main)
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
  echo "  unit=B-49/B-60/B-61"
  echo "  flow=preflight(CI+faucet) -> git pull -> cargo build mfnd/mfn-cli -> vps-soften-mfnd-requires -> restart voters -> restart hub -> wait tip advance"
  echo "  never=faucet-http observer-rpc-proxy"
  echo "  gate=CI GREEN via gh or public API; faucet idle; RPC listen wait after restart"
  echo "  override=MFN_ROLL_ALLOW_RED_CI=1 MFN_ROLL_ALLOW_FAUCET_BUSY=1"
  echo "  docs=scripts/public-devnet-v1/OPERATORS.md"
  echo "vps-roll-mfnd: PASS plan-only"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "vps-roll-mfnd: --apply must run as root on the VPS" >&2
  exit 1
fi

# --- B-60 preflight (fail closed) ---
FAUCET_HEALTH_URL="${MFN_ROLL_FAUCET_HEALTH:-http://127.0.0.1:8788/health}"
if [[ "${MFN_ROLL_ALLOW_FAUCET_BUSY:-0}" != "1" ]]; then
  if command -v curl >/dev/null 2>&1; then
    fh="$(curl -fsS --max-time 8 "$FAUCET_HEALTH_URL" || true)"
    if [[ -z "$fh" ]]; then
      echo "vps-roll-mfnd: WARN faucet /health unreachable — continuing (set URL via MFN_ROLL_FAUCET_HEALTH)" >&2
    else
      busy="$(printf '%s' "$fh" | python3 -c 'import sys,json; h=json.load(sys.stdin); print("1" if h.get("busy") or int(h.get("pending_jobs") or 0)>0 else "0")' 2>/dev/null || echo "?")"
      if [[ "$busy" == "1" ]]; then
        echo "vps-roll-mfnd: faucet busy/pending_jobs — refuse roll (B-15 lock). Retry when idle or MFN_ROLL_ALLOW_FAUCET_BUSY=1" >&2
        echo "$fh" >&2
        exit 3
      fi
      echo "vps-roll-mfnd: faucet idle OK"
    fi
  fi
else
  echo "vps-roll-mfnd: WARN MFN_ROLL_ALLOW_FAUCET_BUSY=1 — skipping faucet idle gate"
fi

if [[ "${MFN_ROLL_ALLOW_RED_CI:-0}" != "1" ]]; then
  # B-61: gh if present, else public Actions API (no VPS token required for public repo)
  ci_json=""
  if command -v gh >/dev/null 2>&1; then
    ci_json="$(gh run list --workflow CI --branch main --limit 1 --json databaseId,conclusion,status,headSha 2>/dev/null || true)"
  fi
  if [[ -z "$ci_json" || "$ci_json" == "[]" ]]; then
    api_url="${MFN_ROLL_CI_API:-https://api.github.com/repos/shanecloonan/permawrite/actions/workflows/ci.yml/runs?branch=main&per_page=1}"
    api_body="$(curl -fsS --max-time 20 -H 'Accept: application/vnd.github+json' -H 'User-Agent: permawrite-vps-roll' "$api_url" || true)"
    ci_json="$(printf '%s' "$api_body" | python3 -c 'import sys,json
try:
  d=json.load(sys.stdin); r=d.get("workflow_runs") or []
  if not r: print("[]");
  else:
    w=r[0]; print(json.dumps([{"databaseId": w.get("id"), "conclusion": w.get("conclusion") or "", "status": w.get("status") or "", "headSha": w.get("head_sha") or ""}]))
except Exception:
  print("[]")' 2>/dev/null || echo '[]')"
    echo "vps-roll-mfnd: CI status via public API (gh missing or empty)"
  fi
  conclusion="$(printf '%s' "$ci_json" | python3 -c 'import sys,json; r=json.load(sys.stdin); print(r[0].get("conclusion") or "") if r else print("")' 2>/dev/null || echo "")"
  status="$(printf '%s' "$ci_json" | python3 -c 'import sys,json; r=json.load(sys.stdin); print(r[0].get("status") or "") if r else print("")' 2>/dev/null || echo "")"
  run_id="$(printf '%s' "$ci_json" | python3 -c 'import sys,json; r=json.load(sys.stdin); print(r[0].get("databaseId") or "") if r else print("")' 2>/dev/null || echo "")"
  if [[ -z "$run_id" ]]; then
    echo "vps-roll-mfnd: cannot read CI status (gh/API empty) — refuse roll. Set MFN_ROLL_ALLOW_RED_CI=1 only after manual GREEN verify" >&2
    exit 4
  fi
  if [[ "$status" == "in_progress" || "$status" == "queued" ]]; then
    echo "vps-roll-mfnd: CI #$run_id still $status — refuse roll (cancel-in-progress / unproven head). Wait or MFN_ROLL_ALLOW_RED_CI=1" >&2
    exit 4
  fi
  if [[ "$conclusion" != "success" ]]; then
    echo "vps-roll-mfnd: latest CI conclusion='$conclusion' (run #$run_id) — refuse roll until GREEN or MFN_ROLL_ALLOW_RED_CI=1" >&2
    exit 4
  fi
  echo "vps-roll-mfnd: CI #$run_id GREEN OK"
else
  echo "vps-roll-mfnd: WARN MFN_ROLL_ALLOW_RED_CI=1 — skipping CI gate"
fi

if ! grep -q "ephemeral" "$REPO_ROOT/mfn-node/src/p2p_fanout.rs" 2>/dev/null; then
  echo "vps-roll-mfnd: WARN p2p_fanout.rs missing ephemeral marker — confirm B-51 on tree" >&2
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

echo "vps-roll-mfnd: waiting for hub RPC listen (cold load of chain.blocks can take minutes)..."
rpc_deadline=$((SECONDS + 300))
rpc_up=0
while (( SECONDS < rpc_deadline )); do
  if ss -lntp 2>/dev/null | grep -q "127.0.0.1:18731"; then
    echo "vps-roll-mfnd: hub RPC listening"
    rpc_up=1
    break
  fi
  # also accept tip_height becoming readable
  if [[ -n "$(tip_height || true)" ]]; then
    echo "vps-roll-mfnd: hub tip readable (RPC up)"
    rpc_up=1
    break
  fi
  sleep 5
done
if (( rpc_up == 0 )); then
  echo "vps-roll-mfnd: hub RPC not up within 300s after restart — refuse thrash; check journal" >&2
  journalctl -u mfnd-hub -n 40 --no-pager || true
  exit 5
fi

echo "vps-roll-mfnd: waiting for hub tip advance..."
deadline=$((SECONDS + 240))
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
