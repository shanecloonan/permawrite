#!/usr/bin/env bash
# Mirror .github/workflows/ci.yml locally before pushing to main.
set -euo pipefail
cd "$(dirname "$0")/.."

export CARGO_TERM_COLOR=always
export RUSTFLAGS="-D warnings"

echo "==> rustfmt"
cargo fmt --all --check

echo "==> clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> build mfnd + mfn-storage-operator (mfn-cli integration tests)"
cargo build -p mfn-node --bin mfnd --release
cargo build -p mfn-storage-operator --bin mfn-storage-operator --release

echo "==> test (release)"
cargo test --workspace --release

echo "==> cargo audit (optional; install with: cargo install cargo-audit)"
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  echo "skip: cargo-audit not installed"
fi

echo "ci-check: OK"
