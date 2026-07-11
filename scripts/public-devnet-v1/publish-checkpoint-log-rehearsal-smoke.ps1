# Lane 7 / TL-8 / F12: plan-only publish-checkpoint-log rehearsal gate (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\CHECKPOINT_LOG.md"
$Invite = Join-Path $RepoRoot "docs\TESTNET_INVITE.md"
$Ops = Join-Path $ScriptDir "OPERATORS.md"
$Publish = Join-Path $ScriptDir "publish-checkpoint-log.ps1"
$DefaultLog = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.checkpoints.jsonl"

foreach ($path in @($Doc, $Invite, $Ops, $Publish)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "publish-checkpoint-log-rehearsal-smoke: missing $path"
    }
}

$docNeedles = @("publish-checkpoint-log", "checkpoint-log sign", "MFN_CHECKPOINT_LOG_SIGNER")
foreach ($n in $docNeedles) {
    if (-not (Select-String -LiteralPath $Doc -Pattern ([regex]::Escape($n)) -Quiet)) {
        throw "publish-checkpoint-log-rehearsal-smoke: CHECKPOINT_LOG.md missing: $n"
    }
}
$inviteNeedles = @("public_devnet_v1.checkpoints.jsonl", "checkpointLogVerify")
foreach ($n in $inviteNeedles) {
    if (-not (Select-String -LiteralPath $Invite -Pattern ([regex]::Escape($n)) -Quiet)) {
        throw "publish-checkpoint-log-rehearsal-smoke: TESTNET_INVITE.md missing: $n"
    }
}
if (-not (Select-String -LiteralPath $Ops -Pattern "publish-checkpoint-log" -Quiet)) {
    throw "publish-checkpoint-log-rehearsal-smoke: OPERATORS.md missing publish-checkpoint-log"
}

& $Publish -PlanOnly | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "publish-checkpoint-log-rehearsal-smoke: publish-checkpoint-log.ps1 --plan-only failed"
}

Write-Host "publish-checkpoint-log-rehearsal-smoke: plan"
Write-Host "  flow=publish-checkpoint-log.ps1 -Rpc HOST:PORT [-Apply]"
Write-Host "  default_log=$DefaultLog"
Write-Host "  docs=docs/CHECKPOINT_LOG.md"
Write-Host "  live_rehearsal=human VPS after TL-7 sign-off + TL-8 seeds"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "publish-checkpoint-log-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "publish-checkpoint-log-rehearsal-smoke: live mode not implemented"
