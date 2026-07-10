# Lane 7 / TL-6: plan-only vps-participant-rehearsal rehearsal gate (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\VPS_SINGLE_BOX_LAUNCH.md"
$Ops = Join-Path $RepoRoot "scripts\public-devnet-v1\OPERATORS.md"
$Rehearsal = Join-Path $ScriptDir "vps-participant-rehearsal.sh"
$Smoke = Join-Path $ScriptDir "participant-rehearsal-smoke.sh"

foreach ($path in @($Doc, $Ops, $Rehearsal, $Smoke)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "vps-participant-rehearsal-rehearsal-smoke: missing $path"
    }
}

$needles = @(
    "vps-participant-rehearsal.sh",
    "vps-participant-rehearsal-observer-linux-",
    "--no-start",
    "--no-stop"
)
foreach ($n in $needles) {
    if (-not (Select-String -LiteralPath $Doc -Pattern ([regex]::Escape($n)) -Quiet)) {
        throw "vps-participant-rehearsal-rehearsal-smoke: VPS_SINGLE_BOX_LAUNCH.md missing: $n"
    }
}
if (-not (Select-String -LiteralPath $Ops -Pattern "vps-participant-rehearsal" -Quiet)) {
    throw "vps-participant-rehearsal-rehearsal-smoke: OPERATORS.md missing vps-participant-rehearsal"
}

$rehearsalText = Get-Content -Raw -LiteralPath $Rehearsal
foreach ($required in @("participant-rehearsal-smoke.sh", "--vps", "--with-observer", "--archive-evidence")) {
    if ($rehearsalText -notmatch [regex]::Escape($required)) {
        throw "vps-participant-rehearsal-rehearsal-smoke: vps-participant-rehearsal.sh missing: $required"
    }
}

Write-Host "vps-participant-rehearsal-rehearsal-smoke: plan"
Write-Host "  flow=vps-participant-rehearsal.sh -> participant-rehearsal-smoke.sh --vps --with-observer"
Write-Host "  evidence=vps-participant-rehearsal-observer-linux-*.txt"
Write-Host "  docs=docs/VPS_SINGLE_BOX_LAUNCH.md"
Write-Host "  live_rehearsal=human VPS after TL-5 soak PASS"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "vps-participant-rehearsal-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "vps-participant-rehearsal-rehearsal-smoke: live mode not implemented; run on VPS after TL-5"
