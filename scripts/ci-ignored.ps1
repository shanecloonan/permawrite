# Run slow P2P / multi-validator smokes and ignored consensus harnesses.
# Mirrors .github/workflows/nightly.yml locally.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (-not $env:RUSTFLAGS) { $env:RUSTFLAGS = "-D warnings" }
if (-not $env:CARGO_TERM_COLOR) { $env:CARGO_TERM_COLOR = "always" }
cargo build -p mfn-node --bin mfnd --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test -p mfn-node --release -- --ignored --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test -p mfn-consensus --release --test emission_simulation -- --ignored --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test -p mfn-consensus --release --test apply_block_proptest -- --ignored --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
