#!/usr/bin/env bash
# Recover a stalled public-devnet validator set after a partial redeploy.
#
# The live mesh at 5.161.201.73 stopped sealing at height 53728 with
# transactions left in the mempool: hub, voters, and the observer were not
# the same binary, so the committee stopped producing. The site allowlist
# advertises get_block_txs_range, which only the observer proxy implements.
# An old proxy forwards list_methods unchanged, so that name is missing.
#
# This script is idempotent and is meant to be run ON the VPS as root.
# It does not SSH, does not delete chain data, and does not reset genesis.
#
#   bash scripts/public-devnet-v1/vps-recover-validators.sh --plan-only
#   bash scripts/public-devnet-v1/vps-recover-validators.sh --apply
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PLAN_ONLY=0
APPLY=0
SKIP_PULL=0
SKIP_BUILD=0
RPC_HUB="${MFN_RECOVER_RPC:-127.0.0.1:18731}"
OBSERVER_RPC="${MFN_RECOVER_OBSERVER_RPC:-127.0.0.1:18734}"
PROXY_URL="${MFN_RECOVER_PROXY_URL:-http://127.0.0.1:8787}"
FAUCET_HEALTH="${MFN_RECOVER_FAUCET_HEALTH:-http://127.0.0.1:8788/health}"
RPC_WAIT_SEC="${MFN_RECOVER_RPC_WAIT_SEC:-1200}"
TIP_WAIT_SEC="${MFN_RECOVER_TIP_WAIT_SEC:-900}"

usage() {
  cat <<'EOF'
usage: vps-recover-validators.sh [--plan-only|--apply] [--skip-pull] [--skip-build]
       [--rpc HOST:PORT] [--observer-rpc HOST:PORT] [--proxy-url URL]

Pull origin/main, rebuild release mfnd and mfn-cli, scrub peers.json, then
restart the committee in order: voters, hub, observer, observer-rpc-proxy,
faucet-http. Start the public P2P forwards if those units exist. Succeeds
only when the hub tip is higher than it was before the restart and the
proxy list_methods includes get_block_txs_range.

Does not delete chain data. A second run is safe: pull is a fast-forward,
the build is cached, and the tip must move again.

Env:
  MFN_REPO_ROOT, MFN_RECOVER_RPC, MFN_RECOVER_OBSERVER_RPC, MFN_RECOVER_PROXY_URL
  MFN_RECOVER_RPC_WAIT_SEC (default 1200), MFN_RECOVER_TIP_WAIT_SEC (default 900)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    --skip-pull) SKIP_PULL=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --rpc) RPC_HUB="${2:?}"; shift 2 ;;
    --observer-rpc) OBSERVER_RPC="${2:?}"; shift 2 ;;
    --proxy-url) PROXY_URL="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "vps-recover-validators: unknown argument $1" >&2; usage >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "vps-recover-validators: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "vps-recover-validators: plan"
  echo "  unit=stall-53728 partial-redeploy version-skew"
  echo "  flow=git pull origin/main -> cargo build mfnd+mfn-cli -> scrub-vps-peers-json -> restart mfnd-v1 mfnd-v2 -> restart mfnd-hub -> wait hub RPC -> restart mfnd-observer -> restart observer-rpc-proxy -> restart faucet-http -> start mfn-p2p-forward-* -> tip must advance -> proxy list_methods includes get_block_txs_range"
  echo "  order=voters then hub then observer then proxy then faucet"
  echo "  never=delete chain data; never reset genesis; never SSH"
  echo "  verify=hub tip_height increases; proxy list_methods has get_block_txs_range; get_block_txs_range is answered by the proxy (not method-not-found)"
  echo "  rpc=$RPC_HUB observer=$OBSERVER_RPC proxy=$PROXY_URL"
  echo "  wait=rpc ${RPC_WAIT_SEC}s tip ${TIP_WAIT_SEC}s (tall-tip replay)"
  echo "vps-recover-validators: PASS plan-only"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "vps-recover-validators: --apply must run as root on the VPS" >&2
  exit 1
fi

cd "$REPO_ROOT"
MCLI="$REPO_ROOT/target/release/mfn-cli"
MFND="$REPO_ROOT/target/release/mfnd"

tip_height() {
  local rpc="$1"
  if [[ ! -x "$MCLI" ]]; then
    echo ""
    return 0
  fi
  "$MCLI" --rpc "$rpc" tip 2>/dev/null | sed -n 's/.*tip_height=\([0-9][0-9]*\).*/\1/p' | head -1
}

port_listening() {
  local hostport="$1"
  local host="${hostport%%:*}"
  local port="${hostport##*:}"
  ss -lnt 2>/dev/null | grep -q "${host}:${port}" || ss -lnt 2>/dev/null | grep -q ":${port}"
}

wait_until() {
  local label="$1" seconds="$2"
  shift 2
  local deadline=$((SECONDS + seconds))
  while (( SECONDS < deadline )); do
    if "$@"; then
      return 0
    fi
    sleep 5
  done
  echo "vps-recover-validators: timed out after ${seconds}s waiting for ${label}" >&2
  return 1
}

hub_rpc_up() {
  port_listening "$RPC_HUB" || [[ -n "$(tip_height "$RPC_HUB")" ]]
}

echo "vps-recover-validators: apply repo=$REPO_ROOT rpc=$RPC_HUB"

branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$branch" != "main" ]]; then
  echo "vps-recover-validators: checkout is '$branch', expected main" >&2
  exit 1
fi
if ! git diff-index --quiet HEAD --; then
  echo "vps-recover-validators: tracked files are dirty; refusing to pull over local edits" >&2
  git status --short >&2 || true
  exit 1
fi

BEFORE="$(tip_height "$RPC_HUB" || true)"
echo "vps-recover-validators: tip_before=${BEFORE:-unread} (stall example is 53728)"

if (( SKIP_PULL == 0 )); then
  git fetch origin main
  git pull --ff-only origin main
fi
echo "vps-recover-validators: HEAD=$(git rev-parse --short HEAD)"

if (( SKIP_BUILD == 0 )); then
  echo "vps-recover-validators: building release mfnd + mfn-cli..."
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/lib-cargo-env.sh"
  cargo build -p mfn-node --release --bin mfnd
  cargo build -p mfn-cli --release --bin mfn-cli
fi

if [[ ! -x "$MFND" || ! -x "$MCLI" ]]; then
  echo "vps-recover-validators: missing $MFND or $MCLI" >&2
  exit 1
fi

bash "$SCRIPT_DIR/vps-soften-mfnd-requires.sh" || true
bash "$SCRIPT_DIR/scrub-vps-peers-json.sh" --apply

echo "vps-recover-validators: restart voters first (mfnd-v1 mfnd-v2)"
systemctl restart mfnd-v1.service mfnd-v2.service
sleep 6
systemctl is-active mfnd-v1.service mfnd-v2.service >/dev/null

echo "vps-recover-validators: restart hub"
systemctl restart mfnd-hub.service
echo "vps-recover-validators: waiting up to ${RPC_WAIT_SEC}s for hub RPC (tall-tip replay)..."
if ! wait_until "hub RPC $RPC_HUB" "$RPC_WAIT_SEC" hub_rpc_up; then
  journalctl -u mfnd-hub -n 40 --no-pager || true
  exit 5
fi
echo "vps-recover-validators: hub RPC is up"

echo "vps-recover-validators: restart observer"
systemctl restart mfnd-observer.service
if ! wait_until "observer RPC $OBSERVER_RPC" "$RPC_WAIT_SEC" port_listening "$OBSERVER_RPC"; then
  # tip_height on the observer is enough if the listen line uses a different address
  if [[ -z "$(tip_height "$OBSERVER_RPC")" ]]; then
    journalctl -u mfnd-observer -n 40 --no-pager || true
    exit 5
  fi
fi

echo "vps-recover-validators: restart observer-rpc-proxy and faucet-http"
systemctl restart observer-rpc-proxy.service
systemctl restart faucet-http.service
sleep 2

# Public seeds. start (not restart) so a second run does not flap an open forward.
for unit in mfn-p2p-forward-hub mfn-p2p-forward-19002 mfn-p2p-forward-19003 mfn-p2p-forward-19004; do
  if systemctl cat "${unit}.service" >/dev/null 2>&1; then
    systemctl start "${unit}.service" || echo "vps-recover-validators: WARN ${unit} did not start" >&2
  else
    echo "vps-recover-validators: ${unit} is not installed (skipped)"
  fi
done

systemctl is-active mfnd-hub.service mfnd-v1.service mfnd-v2.service mfnd-observer.service >/dev/null
systemctl is-active observer-rpc-proxy.service faucet-http.service >/dev/null

proxy_base="${PROXY_URL%/}"
methods_json="$(curl -fsS --max-time 30 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"list_methods","params":{}}' \
  "${proxy_base}/rpc")"
python3 - "$methods_json" <<'PY'
import json, sys
body = json.loads(sys.argv[1])
result = body.get("result")
names = result if isinstance(result, list) else (result or {}).get("methods")
if not isinstance(names, list) or "get_block_txs_range" not in names:
    raise SystemExit("proxy list_methods is missing get_block_txs_range: " + sys.argv[1][:500])
if "get_tx_count_totals" not in names:
    raise SystemExit("proxy list_methods is missing get_tx_count_totals")
print("vps-recover-validators: proxy list_methods includes get_block_txs_range")
PY

# A range the proxy rejects locally (code -32602) proves the method is not
# forwarded to an observer that has never heard of it (that would be -32601).
range_json="$(curl -fsS --max-time 30 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"get_block_txs_range","params":{"from_height":0,"to_height":0}}' \
  "${proxy_base}/rpc")"
python3 - "$range_json" <<'PY'
import json, sys
body = json.loads(sys.argv[1])
err = body.get("error") or {}
code = err.get("code")
message = str(err.get("message") or "")
if code == -32601 or "not found" in message.lower() or "not allowed" in message.lower():
    raise SystemExit("get_block_txs_range is not implemented on the proxy: " + sys.argv[1][:500])
if code != -32602:
    raise SystemExit("expected invalid-params -32602 from the proxy, got: " + sys.argv[1][:500])
print("vps-recover-validators: proxy answers get_block_txs_range locally")
PY

echo "vps-recover-validators: waiting up to ${TIP_WAIT_SEC}s for the hub tip to advance..."
deadline=$((SECONDS + TIP_WAIT_SEC))
advanced=0
seen=""
while (( SECONDS < deadline )); do
  NOW="$(tip_height "$RPC_HUB" || true)"
  if [[ -n "$NOW" && "$NOW" =~ ^[0-9]+$ ]]; then
    if [[ -n "$BEFORE" && "$BEFORE" =~ ^[0-9]+$ ]]; then
      if (( NOW > BEFORE )); then
        echo "vps-recover-validators: tip advanced ${BEFORE} -> ${NOW}"
        advanced=1
        break
      fi
    else
      # Tip was unreadable before the restart. Seeing a height only proves
      # RPC came back. Wait until that height increases.
      if [[ -z "$seen" ]]; then
        seen="$NOW"
        echo "vps-recover-validators: hub tip readable tip_height=$NOW; waiting for the next block"
      elif (( NOW > seen )); then
        echo "vps-recover-validators: tip advanced ${seen} -> ${NOW}"
        advanced=1
        break
      fi
    fi
  fi
  sleep 5
done

if (( advanced == 0 )); then
  echo "vps-recover-validators: tip did not advance (before=${BEFORE:-unread} now=${NOW:-unread})" >&2
  journalctl -u mfnd-hub -n 30 --no-pager || true
  journalctl -u mfnd-v1 -n 20 --no-pager || true
  journalctl -u mfnd-v2 -n 20 --no-pager || true
  exit 2
fi

curl -fsS --max-time 8 "$FAUCET_HEALTH" >/dev/null || echo "vps-recover-validators: WARN faucet /health not ready yet" >&2

echo "vps-recover-validators: OK HEAD=$(git rev-parse --short HEAD) tip=$(tip_height "$RPC_HUB") tip_before=${BEFORE:-unread}"
