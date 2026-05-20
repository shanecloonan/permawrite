#!/usr/bin/env bash
# Run slow P2P / multi-validator smokes (same as nightly workflow).
set -euo pipefail
cd "$(dirname "$0")/.."
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"
cargo build -p mfn-node --bin mfnd --release
cargo test -p mfn-node -p mfn-cli --release -- --ignored --test-threads=1
