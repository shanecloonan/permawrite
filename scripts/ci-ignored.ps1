# Run slow P2P / multi-validator smokes (same as nightly workflow).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (-not $env:RUSTFLAGS) { $env:RUSTFLAGS = "-D warnings" }
cargo build -p mfn-node --bin mfnd --release
cargo test -p mfn-node -p mfn-cli --release -- --ignored --test-threads=1
