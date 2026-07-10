# Lane 7 / TL-7: plan-only vps-launch-ceremony rehearsal gate (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Ops = Join-Path $ScriptDir "OPERATORS.md"
$Playbook = Join-Path $RepoRoot "docs\TESTNET_LAUNCH.md"
$Doc = Join-Path $RepoRoot "docs\VPS_SINGLE_BOX_LAUNCH.md"
$Ceremony = Join-Path $ScriptDir "vps-launch-ceremony.sh"

foreach ($path in @($Ops, $Playbook, $Doc, $Ceremony)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "vps-launch-ceremony-rehearsal-smoke: missing $path"
    }
}
if (-not (Select-String -LiteralPath $Ops -Pattern "vps-launch-ceremony" -Quiet)) {
    throw "vps-launch-ceremony-rehearsal-smoke: OPERATORS.md missing vps-launch-ceremony"
}

$bash = Get-Command bash -ErrorAction SilentlyContinue
if ($bash) {
    $planOut = & bash $Ceremony --plan-only 2>&1 | Out-String
} else {
    $planOut = Get-Content -Raw -LiteralPath $Ceremony
}
$needles = @(
    "TL-5", "TL-6", "TL-7", "TL-8", "TL-9",
    "publish-seed-nodes.sh", "launch-go-no-go.sh",
    "vps-internet-soak.sh", "vps-participant-rehearsal.sh"
)
foreach ($n in $needles) {
    if ($planOut -notmatch [regex]::Escape($n)) {
        throw "vps-launch-ceremony-rehearsal-smoke: --plan-only output missing: $n"
    }
}

Write-Host "vps-launch-ceremony-rehearsal-smoke: plan"
Write-Host "  helper=vps-launch-ceremony.sh [--plan-only|--check]"
Write-Host "  ordered=TL-5..TL-9"
Write-Host "  docs=docs/TESTNET_LAUNCH.md docs/VPS_SINGLE_BOX_LAUNCH.md"
Write-Host "  live_rehearsal=human VPS ceremony after local RC green"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "vps-launch-ceremony-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "vps-launch-ceremony-rehearsal-smoke: live mode not implemented"
