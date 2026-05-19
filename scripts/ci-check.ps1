# Mirror .github/workflows/ci.yml locally before pushing to main.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$env:CARGO_TERM_COLOR = "always"
$env:RUSTFLAGS = "-D warnings"

Write-Host "==> rustfmt"
cargo fmt --all --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> clippy"
cargo clippy --workspace --all-targets --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> test (release)"
cargo test --workspace --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> cargo audit (optional)"
if (Get-Command cargo-audit -ErrorAction SilentlyContinue) {
    cargo audit
} else {
    Write-Host "skip: cargo-audit not installed"
}

Write-Host "ci-check: OK"
