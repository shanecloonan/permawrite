#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack not found; install: cargo install wasm-pack --locked" >&2
  exit 1
fi

rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

wasm-pack --log-level warn build mfn-wasm \
  --target web \
  --out-dir demo/web/pkg \
  --release \
  --features wasm-full

echo "WASM demo built -> demo/web/pkg/"
