#!/usr/bin/env bash
# B8.3: document optional participant JSON-RPC over Tor (plan-only; no live SOCKS5 required).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RPC="${RPC:-YOURSEED.onion:18731}"
SOCKS5="${MFND_TOR_SOCKS5:-127.0.0.1:9050}"
PLAN_ONLY=1

usage() {
  cat <<'EOF'
usage: tor-rpc-rehearsal-smoke.sh [--rpc HOST.onion:PORT] [--live] [--help]

Plan-only smoke for B8.3: mfn-cli --tor against an onion RPC endpoint.
Default is --plan-only (CI-safe). Pass --live only on a host with Tor SOCKS5 up.

Environment:
  MFND_TOR_SOCKS5   SOCKS5 proxy (default 127.0.0.1:9050)
  MFN_CLI_RPC_TOR   set to 1 to enable Tor mode without --tor flag
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="${2:?}"; shift 2 ;;
    --live) PLAN_ONLY=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "tor-rpc-rehearsal-smoke: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$RPC" != *".onion:"* ]]; then
  echo "tor-rpc-rehearsal-smoke: --rpc must be a v3 .onion:PORT dial string (got ${RPC})" >&2
  exit 1
fi

echo "tor-rpc-rehearsal-smoke: plan"
echo "  flow=mfn-cli --tor --rpc ${RPC} status -> tip"
echo "  tor_socks5=${SOCKS5}"
echo "  env=MFN_CLI_RPC_TOR=1 MFN_CLI --tor-socks5 ${SOCKS5}"
echo "  docs=docs/TOR_P2P.md#wallet-json-rpc-over-tor-b83"
echo "  note=cleartext mfn-cli rejects .onion without --tor (B8.3)"

if (( PLAN_ONLY )); then
  echo "tor-rpc-rehearsal-smoke: PASS plan-only"
  exit 0
fi

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

MCLI="${MCLI:-./target/release/mfn-cli}"
if [[ ! -x "$MCLI" ]]; then
  echo "tor-rpc-rehearsal-smoke: build mfn-cli release first or set MCLI=" >&2
  exit 1
fi

export MFN_CLI_RPC_TOR=1
export MFND_TOR_SOCKS5="$SOCKS5"

"$MCLI" --tor --rpc "$RPC" --tor-socks5 "$SOCKS5" status
"$MCLI" --tor --rpc "$RPC" --tor-socks5 "$SOCKS5" tip
echo "tor-rpc-rehearsal-smoke: PASS live"
