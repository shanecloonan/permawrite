# F12 phase 1–4: signed checkpoint log rehearsal (plan-only default; -Live uses local devnet).
param(
    [switch]$PlanOnly,
    [switch]$Live,
    [switch]$NoStart,
    [switch]$NoStop
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\CHECKPOINT_LOG.md"
$Publish = Join-Path $ScriptDir "publish-checkpoint-log.ps1"

$RehearsalSeedHex = if ($env:MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_SEED_HEX) {
    $env:MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_SEED_HEX
} else {
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
}
$RehearsalSignerId = if ($env:MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_ID) {
    $env:MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_ID
} else {
    "permawrite-rehearsal-maintainer"
}

if (-not (Test-Path $Doc)) {
    throw "checkpoint-log-rehearsal-smoke: missing $Doc"
}
if (-not (Test-Path $Publish)) {
    throw "checkpoint-log-rehearsal-smoke: missing $Publish"
}

$needles = @(
    "checkpoint-log sign",
    "checkpoint-log verify",
    "checkpoint-log cross-check",
    "publish-checkpoint-log",
    "MFN:checkpoint-log-signer:v1",
    "MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX",
    "MFN_CHECKPOINT_LOG_REHEARSAL_SIGNER_SEED_HEX",
    "--checkpoint-log",
    "checkpoint_log=matched",
    "checkpointLogVerify",
    "checkpointLogCrossCheck"
)
foreach ($n in $needles) {
    if (-not (Select-String -LiteralPath $Doc -Pattern $n -Quiet)) {
        throw "checkpoint-log-rehearsal-smoke: CHECKPOINT_LOG.md missing: $n"
    }
}

Write-Host "checkpoint-log-rehearsal-smoke: plan"
Write-Host "  flow=export-trusted-summary -> checkpoint-log sign -> verify -> cross-check"
Write-Host "  tl8=publish-checkpoint-log.ps1 -Apply (production maintainer seed)"
Write-Host "  light_scan=wallet light-scan --checkpoint-log FILE"
Write-Host "  docs=docs/CHECKPOINT_LOG.md"
Write-Host "  cli=mfn-cli checkpoint-log sign|verify|cross-check"
Write-Host "  wasm=checkpointLogVerify; checkpointLogCrossCheck (mfn-wasm wasm-full)"

if ($PlanOnly -or -not $Live) {
    Write-Host "checkpoint-log-rehearsal-smoke: PASS plan-only"
    exit 0
}

$Mfnd = Join-Path $RepoRoot "target\release\mfnd.exe"
$Mcli = Join-Path $RepoRoot "target\release\mfn-cli.exe"
if (-not (Test-Path $Mfnd) -or -not (Test-Path $Mcli)) {
    throw "checkpoint-log-rehearsal-smoke: build mfnd + mfn-cli release first"
}

try {
    if (-not $NoStart) {
        & bash (Join-Path $ScriptDir "start-all.sh") --no-build
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    $Ports = Join-Path $ScriptDir "devnet-ports.env"
    if (-not (Test-Path $Ports)) {
        throw "checkpoint-log-rehearsal-smoke: missing $Ports"
    }
    $Rpc = ""
    Get-Content $Ports | ForEach-Object {
        if ($_ -match '^\s*HUB_RPC=(.+)$') { $Rpc = $Matches[1].Trim() }
    }
    if (-not $Rpc) { throw "checkpoint-log-rehearsal-smoke: HUB_RPC missing from $Ports" }

    $Tmp = Join-Path $env:TEMP ("mfn-checkpoint-rehearsal-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $Tmp | Out-Null
    $Summary = Join-Path $Tmp "trusted-summary.json"
    $Log = Join-Path $Tmp "checkpoints.jsonl"
    $Wallet = Join-Path $Tmp "wallet.json"

    Push-Location $RepoRoot
    & $Mcli --rpc $Rpc --wallet $Wallet wallet new | Out-Null
    & $Mcli --rpc $Rpc --wallet $Wallet wallet export-trusted-summary --out $Summary
    & $Mcli checkpoint-log sign --summary $Summary --signer-id $RehearsalSignerId `
        --signer-seed-hex $RehearsalSeedHex --append $Log | Out-Null
    & $Mcli checkpoint-log verify $Log
    & $Mcli checkpoint-log cross-check --summary $Summary --log $Log
    Write-Host "checkpoint-log-rehearsal-smoke: PASS live rpc=$Rpc signer_id=$RehearsalSignerId"
} finally {
    Pop-Location -ErrorAction SilentlyContinue
    if ($Tmp -and (Test-Path $Tmp)) { Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue }
    if (-not $NoStop -and -not $NoStart) {
        & bash (Join-Path $ScriptDir "stop-all.sh") 2>$null | Out-Null
    }
}
