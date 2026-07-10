# Lane 7 / TL-5: plan-only vps-internet-soak rehearsal gate (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\VPS_SINGLE_BOX_LAUNCH.md"
$Ops = Join-Path $RepoRoot "scripts\public-devnet-v1\OPERATORS.md"
$Soak = Join-Path $ScriptDir "vps-internet-soak.sh"
$Preflight = Join-Path $ScriptDir "vps-preflight.sh"

foreach ($path in @($Doc, $Ops, $Soak, $Preflight)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "vps-internet-soak-rehearsal-smoke: missing $path"
    }
}

$needles = @(
    "vps-internet-soak.sh",
    "vps-preflight.sh",
    "vps-internet-soak-linux-",
    "MFN_VPS_SOAK_MIN_HEIGHT"
)
foreach ($n in $needles) {
    if (-not (Select-String -LiteralPath $Doc -Pattern ([regex]::Escape($n)) -Quiet)) {
        throw "vps-internet-soak-rehearsal-smoke: VPS_SINGLE_BOX_LAUNCH.md missing: $n"
    }
}
if (-not (Select-String -LiteralPath $Ops -Pattern "vps-internet-soak" -Quiet)) {
    throw "vps-internet-soak-rehearsal-smoke: OPERATORS.md missing vps-internet-soak"
}

$soakText = Get-Content -Raw -LiteralPath $Soak
foreach ($required in @("vps-preflight.sh", "soak.sh", "--vps", "--archive-evidence")) {
    if ($soakText -notmatch [regex]::Escape($required)) {
        throw "vps-internet-soak-rehearsal-smoke: vps-internet-soak.sh missing: $required"
    }
}

Write-Host "vps-internet-soak-rehearsal-smoke: plan"
Write-Host "  flow=vps-preflight.sh -> soak.sh --vps --archive-evidence"
Write-Host "  evidence=vps-internet-soak-linux-*.txt"
Write-Host "  docs=docs/VPS_SINGLE_BOX_LAUNCH.md"
Write-Host "  live_rehearsal=human VPS (TL-5 execution)"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "vps-internet-soak-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "vps-internet-soak-rehearsal-smoke: live mode not implemented; run vps-internet-soak.sh on VPS"
