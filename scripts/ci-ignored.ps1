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
Write-Host "ci-ignored: participant-rehearsal-smoke (slow public-devnet mesh; mirrors nightly.yml)"
cargo build -p mfn-cli --release --bin mfn-cli
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo build -p mfn-storage-operator --release --bin mfn-storage-operator
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (-not $env:SLOT_MS) { $env:SLOT_MS = "10000" }
$env:MFN_DEVNET_NO_OBSERVER = "1"
powershell -NoProfile -File scripts/public-devnet-v1/participant-rehearsal-smoke.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "ci-ignored: participant-rehearsal-smoke-observer (mirrors nightly observer job)"
Remove-Item Env:MFN_DEVNET_NO_OBSERVER -ErrorAction SilentlyContinue
powershell -NoProfile -File scripts/public-devnet-v1/participant-rehearsal-smoke.ps1 -WithObserver -MinHubHeight 5 -WaitMinHubHeightSeconds 300
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
