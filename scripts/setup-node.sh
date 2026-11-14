#!/usr/bin/env bash
# Write a Tor-only Permawrite observer layout.
# The node binds loopback, dials only onion peers, and the unit denies
# every address that is not localhost (IPAddressDeny=any).
#
#   scripts/setup-node.sh --plan-only
#   scripts/setup-node.sh --out ./observer
set -euo pipefail

MODE=plan
OUT=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) MODE=plan; shift ;;
    --out) OUT="${2:-}"; shift 2 ;;
    -h|--help)
      echo "usage: $0 --plan-only | --out DIR"
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

plan() {
  echo "MFND_P2P_TRANSPORT=tor"
  echo "MFND_P2P_OVERLAY_ONLY=1"
  echo "MFND_TOR_SOCKS5=127.0.0.1:9050"
  echo "rpc=127.0.0.1:18731"
  echo "p2p=127.0.0.1:8333"
  echo "IPAddressDeny=any"
  echo "IPAddressAllow=localhost"
  echo "container=--network=none"
}

case "$MODE" in
  plan) plan ;;
esac

if [[ -n "$OUT" ]]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  cargo run -q -p mfn-node-setup --manifest-path "$ROOT/Cargo.toml" -- --out "$OUT"
fi
