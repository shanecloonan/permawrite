# F12 phase 1–2: plan-only signed checkpoint log rehearsal (Windows parity).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\CHECKPOINT_LOG.md"

if (-not (Test-Path -LiteralPath $Doc)) {
    throw "checkpoint-log-rehearsal-smoke: missing $Doc"
}

$needles = @(
    "checkpoint-log sign",
    "checkpoint-log verify",
    "MFN:checkpoint-log-signer:v1",
    "MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX",
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
Write-Host "  flow=export-trusted-summary -> checkpoint-log sign -> checkpoint-log verify"
Write-Host "  light_scan=wallet light-scan --checkpoint-log FILE"
Write-Host "  docs=docs/CHECKPOINT_LOG.md"
Write-Host "  cli=mfn-cli checkpoint-log sign|verify; wallet light-scan --checkpoint-log"
Write-Host "  wasm=checkpointLogVerify; checkpointLogCrossCheck (mfn-wasm wasm-full)"
Write-Host "  live_rehearsal=deferred (publish log at TL-8 invite)"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "checkpoint-log-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "checkpoint-log-rehearsal-smoke: live mode not implemented; use maintainer publish at TL-8"
