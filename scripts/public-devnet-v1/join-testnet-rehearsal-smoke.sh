#!/usr/bin/env bash
# B-15 smoke wrapper: run join-testnet-rehearsal against live testnet services.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RPC=""
FAUCET_URL="http://127.0.0.1:8788"
OBSERVER_PROXY_URL="http://127.0.0.1:8787/rpc"
SMOKE_ROOT="$SCRIPT_DIR/join-testnet-rehearsal-smoke"
EVIDENCE_DIR=""
NO_BUILD=0
PLAN_ONLY=0
ARCHIVE_EVIDENCE=0
NO_START=0
LIVE_FAUCET_URL="http://5.161.201.73:8788"
LIVE_OBSERVER_PROXY_URL="http://5.161.201.73:8787/rpc"
USE_LIVE_URLS=0

usage() {
  cat <<'EOF'
usage: join-testnet-rehearsal-smoke.sh [options]

Options:
  --rpc HOST:PORT             synced local mfnd JSON-RPC (default on VPS: 127.0.0.1:18734)
  --faucet-url URL            HTTP faucet (default: http://127.0.0.1:8788)
  --observer-proxy-url URL    observer read-RPC proxy (default: http://127.0.0.1:8787/rpc)
  --use-live-urls             use public 5.161.201.73 faucet + observer proxy URLs
  --smoke-dir DIR             smoke state directory
  --evidence-dir DIR          evidence directory (default: <smoke-dir>/evidence)
  --no-start                  require --rpc; do not start mfnd (default on VPS)
  --no-build                  use existing release binaries
  --archive-evidence          write PASS transcript to scripts/public-devnet-v1/evidence/
  --plan-only                 print flow without network I/O
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="${2:-}"; shift 2 ;;
    --faucet-url) FAUCET_URL="${2:-}"; shift 2 ;;
    --observer-proxy-url) OBSERVER_PROXY_URL="${2:-}"; shift 2 ;;
    --use-live-urls) USE_LIVE_URLS=1; shift ;;
    --smoke-dir) SMOKE_ROOT="${2:-}"; shift 2 ;;
    --evidence-dir) EVIDENCE_DIR="${2:-}"; shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --no-build) NO_BUILD=1; shift ;;
    --archive-evidence) ARCHIVE_EVIDENCE=1; shift ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "join-testnet-rehearsal-smoke: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$EVIDENCE_DIR" ]]; then
  EVIDENCE_DIR="$SMOKE_ROOT/evidence"
fi
REHEARSAL_DIR="$SMOKE_ROOT/run"

if (( USE_LIVE_URLS )); then
  FAUCET_URL="$LIVE_FAUCET_URL"
  OBSERVER_PROXY_URL="$LIVE_OBSERVER_PROXY_URL"
fi

if [[ -z "$RPC" && -n "${MFN_JOIN_TESTNET_RPC:-}" ]]; then
  RPC="$MFN_JOIN_TESTNET_RPC"
fi
if [[ -z "$RPC" && -f /root/permawrite/scripts/public-devnet-v1/devnet-ports.env ]]; then
  # shellcheck disable=SC1091
  source /root/permawrite/scripts/public-devnet-v1/devnet-ports.env 2>/dev/null || true
  if [[ -n "${OBSERVER_RPC:-}" ]]; then
    RPC="$OBSERVER_RPC"
    NO_START=1
  fi
fi
if [[ -z "$RPC" ]]; then
  RPC="127.0.0.1:18734"
  NO_START=1
fi

archive_evidence() {
  local path tip_height genesis_id
  tip_height="$("$REPO_ROOT/target/release/mfn-cli" --rpc "$RPC" tip 2>/dev/null | sed -n 's/^tip_height=//p' | head -1 || echo unknown)"
  genesis_id="$("$REPO_ROOT/target/release/mfn-cli" --rpc "$RPC" tip 2>/dev/null | sed -n 's/^genesis_id=//p' | head -1 || echo unknown)"
  local ts os_tag
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  os_tag="linux"
  if [[ "$(uname -s 2>/dev/null || echo unknown)" == MINGW* ]] || [[ "$(uname -s 2>/dev/null || echo unknown)" == *NT* ]]; then
    os_tag="windows"
  fi
  path="$SCRIPT_DIR/evidence/join-testnet-rehearsal-${os_tag}-${ts}.txt"
  {
    echo "# B-15 live testnet JOIN_TESTNET participant rehearsal"
    echo "# utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# docs=docs/JOIN_TESTNET.md"
    echo ""
    echo "SUMMARY: PASS"
    echo ""
    echo "RPC=$RPC"
    echo "faucet_url=$FAUCET_URL"
    echo "observer_proxy_url=$OBSERVER_PROXY_URL"
    echo "genesis_id=$genesis_id"
    echo "tip_height=$tip_height"
    echo ""
    echo "join-testnet-rehearsal-smoke: PASS faucet_http=true light_scan_checkpoint=true observer_proxy=true"
    if [[ -f "$EVIDENCE_DIR/join-testnet-rehearsal.log" ]]; then
      echo ""
      cat "$EVIDENCE_DIR/join-testnet-rehearsal.log"
    fi
  } >"$path"
  echo "join-testnet-rehearsal-smoke: EVIDENCE archived=$path"
}

if (( PLAN_ONLY )); then
  echo "join-testnet-rehearsal-smoke: plan"
  echo "  rpc=$RPC"
  echo "  faucet_url=$FAUCET_URL"
  echo "  observer_proxy_url=$OBSERVER_PROXY_URL"
  echo "  smoke_dir=$SMOKE_ROOT"
  echo "  rehearsal_dir=$REHEARSAL_DIR"
  echo "  evidence_dir=$EVIDENCE_DIR"
  echo "  no_start=$NO_START"
  echo "  flow=synced local observer RPC -> fund-wallet-http -> light-scan --checkpoint-log -> observer proxy cross-check -> permanence-demo"
  echo "  docs=docs/JOIN_TESTNET.md"
  echo "  assert=assert-join-testnet-rehearsal-evidence.sh"
  exit 0
fi

cd "$REPO_ROOT"
mkdir -p "$SMOKE_ROOT" "$EVIDENCE_DIR" "$REHEARSAL_DIR"

rehearsal_args=(
  --rpc "$RPC"
  --faucet-url "$FAUCET_URL"
  --observer-proxy-url "$OBSERVER_PROXY_URL"
  --rehearsal-dir "$REHEARSAL_DIR"
  --evidence-dir "$EVIDENCE_DIR"
  --evidence-log "$EVIDENCE_DIR/join-testnet-rehearsal.log"
)
if (( NO_BUILD )); then rehearsal_args+=(--no-build); fi

bash "$SCRIPT_DIR/join-testnet-rehearsal.sh" "${rehearsal_args[@]}"

if (( ARCHIVE_EVIDENCE )); then
  archive_evidence
fi

echo "join-testnet-rehearsal-smoke: PASS"
