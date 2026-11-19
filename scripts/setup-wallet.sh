#!/usr/bin/env bash
# Create a wallet and print the next command.
# Does not start a node, touch a faucet, or restart a service.
set -euo pipefail

if [[ "${1:-}" == "--self-test" ]]; then
  echo "setup_mode=offline"
  echo "creates=wallet file when missing"
  echo "tor=probe 127.0.0.1:9050"
  echo "next=mfn-cli --wallet ./wallet.json wallet ready"
  echo "seed_restores=money, not uploaded files"
  exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WALLET="${MFN_WALLET_PATH:-$ROOT/wallet.json}"
if [[ ! -x "$ROOT/target/release/mfn-cli" ]]; then
  echo "building mfn-cli (release)"
  (cd "$ROOT" && cargo build -p mfn-cli --release)
fi
exec "$ROOT/target/release/mfn-cli" --wallet "$WALLET" wallet setup
