# Plan-only gate: genesis validator BLS PoP ceremony tooling (PROBLEMS.md § 13).
param([switch]$PlanOnly)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$Doc = Join-Path $RepoRoot "docs\TESTNET_GENESIS_CEREMONY.md"
$Genesis = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.json"
$Tool = Join-Path $ScriptDir "genesis-validator-bls-pop.ps1"

foreach ($f in @($Doc, $Genesis, $Tool)) {
    if (-not (Test-Path -LiteralPath $f)) {
        Write-Error "genesis-validator-bls-pop-rehearsal-smoke: missing $f"
    }
}

foreach ($needle in @("require_validator_bls_pop", "bls_register_sig_hex", "genesis-validator-bls-pop")) {
    if (-not (Select-String -LiteralPath $Doc -Pattern $needle -Quiet)) {
        Write-Error "genesis-validator-bls-pop-rehearsal-smoke: TESTNET_GENESIS_CEREMONY.md missing: $needle"
    }
}

$out = & powershell -NoProfile -File $Tool -Genesis $Genesis 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $out -notmatch "validators\[0\]" -or $out -notmatch "bls_register_sig_hex=") {
    Write-Error "genesis-validator-bls-pop-rehearsal-smoke: compute failed`n$out"
}

& powershell -NoProfile -File $Tool -Genesis $Genesis -Verify | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output "genesis-validator-bls-pop-rehearsal-smoke: PASS plan-only"
