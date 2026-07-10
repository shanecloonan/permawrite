# Lane 7 / TL-8: sign and append a maintainer checkpoint log entry (F12 phase 4).
param(
    [string]$Rpc = "",
    [string]$LogPath = "",
    [string]$SignerId = $(if ($env:MFN_CHECKPOINT_LOG_SIGNER_ID) { $env:MFN_CHECKPOINT_LOG_SIGNER_ID } else { "permawrite-maintainer-1" }),
    [switch]$Apply,
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
if (-not $LogPath) {
    $LogPath = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.checkpoints.jsonl"
}

if ($PlanOnly) {
    Write-Host "publish-checkpoint-log: plan"
    Write-Host "  flow=export-trusted-summary -> checkpoint-log sign -> verify -> cross-check"
    Write-Host "  default_log=$LogPath"
    Write-Host "  docs=docs/CHECKPOINT_LOG.md"
    Write-Host "publish-checkpoint-log: PASS plan-only"
    exit 0
}

function Resolve-Rpc {
    if ($Rpc) { return $Rpc }
    $bind = Join-Path $ScriptDir "vps-bind.env"
    if (Test-Path $bind) {
        Get-Content $bind | ForEach-Object {
            if ($_ -match '^\s*MFND_RPC_LISTEN_HUB=(.+)$') { return $Matches[1].Trim() }
        }
    }
    $ports = Join-Path $ScriptDir "devnet-ports.env"
    if (Test-Path $ports) {
        Get-Content $ports | ForEach-Object {
            if ($_ -match '^\s*HUB_RPC=(.+)$') { return $Matches[1].Trim() }
        }
    }
    return ""
}

$Rpc = Resolve-Rpc
if (-not $Rpc) {
    throw "publish-checkpoint-log: set -Rpc or run from a host with vps-bind.env / devnet-ports.env"
}

$Mcli = Join-Path $RepoRoot "target\release\mfn-cli.exe"
if (-not (Test-Path $Mcli)) {
    $cmd = Get-Command mfn-cli -ErrorAction SilentlyContinue
    if ($cmd) { $Mcli = $cmd.Source } else { throw "publish-checkpoint-log: build mfn-cli release first" }
}

if (-not $env:MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX) {
    throw "publish-checkpoint-log: set MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX (32-byte hex maintainer seed)"
}

Write-Host "publish-checkpoint-log: TL-8 preview rpc=$Rpc log=$LogPath signer_id=$SignerId"
Write-Host "publish-checkpoint-log: flow=export-trusted-summary -> checkpoint-log sign -> verify -> cross-check"

if (-not $Apply) {
    Write-Host ""
    Write-Host "publish-checkpoint-log: dry-run only; re-run with -Apply after TL-7 sign-off"
    exit 0
}

$Tmp = Join-Path $env:TEMP ("mfn-checkpoint-log-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
    $Summary = Join-Path $Tmp "trusted-summary.json"
    $Wallet = Join-Path $Tmp "publish-wallet.json"
    Push-Location $RepoRoot
    & $Mcli --rpc $Rpc --wallet $Wallet wallet new | Out-Null
    & $Mcli --rpc $Rpc --wallet $Wallet wallet export-trusted-summary --out $Summary
    & $Mcli checkpoint-log sign --summary $Summary --signer-id $SignerId `
        --signer-seed-hex $env:MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX --append $LogPath | Out-Null
    & $Mcli checkpoint-log verify $LogPath
    & $Mcli checkpoint-log cross-check --summary $Summary --log $LogPath
    Write-Host "publish-checkpoint-log: OK appended to $LogPath"
    Write-Host "publish-checkpoint-log: commit log + link from docs/TESTNET_INVITE.md (TL-8)"
} finally {
    Pop-Location -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
