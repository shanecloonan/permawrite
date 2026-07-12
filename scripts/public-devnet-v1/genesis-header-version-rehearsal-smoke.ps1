# Lane 4 / TL-7 Path B: plan-only genesis header_version rehearsal gate (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\TESTNET_GENESIS_CEREMONY.md"
$Security = Join-Path $RepoRoot "docs\SECURITY_CONSIDERATIONS.md"
$Problems = Join-Path $RepoRoot "docs\PROBLEMS.md"
$Genesis = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.json"
$HeaderRs = Join-Path $RepoRoot "mfn-consensus\src\block\header.rs"
$GenesisRs = Join-Path $RepoRoot "mfn-consensus\src\block\genesis.rs"
$GenesisSpec = Join-Path $RepoRoot "mfn-runtime\src\genesis_spec.rs"

foreach ($path in @($Doc, $Security, $Problems, $Genesis, $HeaderRs, $GenesisRs, $GenesisSpec)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "genesis-header-version-rehearsal-smoke: missing $path"
    }
}

foreach ($needle in @("header_version: 2", "utxo_root")) {
    if (-not (Select-String -LiteralPath $Doc -Pattern ([regex]::Escape($needle)) -Quiet)) {
        throw "genesis-header-version-rehearsal-smoke: TESTNET_GENESIS_CEREMONY.md missing: $needle"
    }
}
if (-not (Select-String -LiteralPath $Security -Pattern "header_version: 2" -Quiet)) {
    throw "genesis-header-version-rehearsal-smoke: SECURITY_CONSIDERATIONS.md missing header_version: 2"
}
if (-not (Select-String -LiteralPath $Problems -Pattern "genesis-threaded" -Quiet)) {
    throw "genesis-header-version-rehearsal-smoke: PROBLEMS.md missing genesis-threaded status"
}
if (-not (Select-String -LiteralPath $HeaderRs -Pattern "HEADER_VERSION_UTXO_QUORUM" -Quiet)) {
    throw "genesis-header-version-rehearsal-smoke: header.rs missing HEADER_VERSION_UTXO_QUORUM"
}
if (-not (Select-String -LiteralPath $GenesisRs -Pattern "header_version" -Quiet)) {
    throw "genesis-header-version-rehearsal-smoke: genesis.rs missing header_version field"
}
if (-not (Select-String -LiteralPath $GenesisSpec -Pattern "accepts_header_version_two" -Quiet)) {
    throw "genesis-header-version-rehearsal-smoke: genesis_spec.rs missing accepts_header_version_two test"
}

$genesisText = Get-Content -Raw -LiteralPath $Genesis
if ($genesisText -match '"header_version"\s*:\s*2') {
    throw "genesis-header-version-rehearsal-smoke: public_devnet_v1.json must stay header v1 (Path A)"
}

Write-Host "genesis-header-version-rehearsal-smoke: plan"
Write-Host "  path_a=public_devnet_v1.json defaults header v1"
Write-Host "  path_b=optional header_version: 2 in fresh genesis JSON"
Write-Host "  consensus=HEADER_VERSION_UTXO_QUORUM signing bytes"
Write-Host "  docs=TESTNET_GENESIS_CEREMONY.md SECURITY_CONSIDERATIONS.md PROBLEMS.md"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "genesis-header-version-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "genesis-header-version-rehearsal-smoke: live mode not implemented"
