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
