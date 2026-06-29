#!/usr/bin/env bash
# Mirror .github/workflows/ci.yml locally before pushing to main.
set -euo pipefail
cd "$(dirname "$0")/.."

export CARGO_TERM_COLOR=always
export RUSTFLAGS="-D warnings"

missing_tools=()
add_missing_command() {
  local name="$1"
  local hint="$2"
  if ! command -v "$name" >/dev/null 2>&1; then
    missing_tools+=("missing required command '$name'. $hint")
  fi
}

add_missing_command cargo "Install Rust from https://rustup.rs/ and reopen the shell."
add_missing_command rustup "Install Rust from https://rustup.rs/ and reopen the shell."
add_missing_command pwsh "Install PowerShell 7+ to parse-check Windows helper scripts."
add_missing_command wasm-pack "Install with: cargo install wasm-pack --locked."
add_missing_command cargo-audit "Install with: cargo install cargo-audit --locked."
if ((${#missing_tools[@]} > 0)); then
  printf '%s\n' "${missing_tools[@]}" >&2
  exit 127
fi

echo "==> public-devnet scripts"
for script in scripts/*.sh scripts/public-devnet-v1/*.sh; do
  bash -n "$script"
done
pwsh -NoProfile -Command '
  $errors = @()
  foreach ($script in Get-ChildItem scripts -Filter *.ps1 -Recurse) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count -gt 0) {
      $errors += $parseErrors | ForEach-Object { "$($script.FullName): $_" }
    }
  }
  if ($errors.Count -gt 0) {
    $errors | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 1
  }
'

echo "==> rustfmt"
cargo fmt --all --check

echo "==> clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> build mfnd + mfn-storage-operator (mfn-cli integration tests)"
cargo build -p mfn-node --bin mfnd --release
cargo build -p mfn-storage-operator --bin mfn-storage-operator --release

echo "==> test (release)"
cargo test --workspace --release -- --test-threads=4

echo "==> wasm32 build"
rustup target add wasm32-unknown-unknown
cargo build -p mfn-wasm --target wasm32-unknown-unknown --release --features wasm-full
cargo test -p mfn-wasm --release --features wasm-full
wasm-pack build mfn-wasm --target web --out-dir demo/web/pkg --release --features wasm-full

echo "==> cargo audit"
cargo audit

echo "ci-check: OK"
