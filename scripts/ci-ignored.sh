#!/usr/bin/env bash
# Run slow P2P / multi-validator smokes and ignored consensus harnesses.
# Mirrors .github/workflows/nightly.yml locally.
set -euo pipefail
cd "$(dirname "$0")/.."
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
cargo build -p mfn-node --bin mfnd --release
cargo test -p mfn-node --release -- --ignored --test-threads=1
cargo test -p mfn-consensus --release --test emission_simulation -- --ignored --test-threads=1
cargo test -p mfn-consensus --release --test apply_block_proptest -- --ignored --test-threads=1
echo "ci-ignored: participant-rehearsal-smoke (slow public-devnet mesh; mirrors nightly.yml)"
cargo build -p mfn-cli --release --bin mfn-cli
cargo build -p mfn-storage-operator --release --bin mfn-storage-operator
export SLOT_MS="${SLOT_MS:-10000}"
export MFN_DEVNET_NO_OBSERVER=1
bash scripts/public-devnet-v1/participant-rehearsal-smoke.sh
