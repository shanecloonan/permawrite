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

$Assert = Join-Path $ScriptDir "assert-vps-internet-soak-evidence.ps1"
$Fixture = Join-Path $ScriptDir "fixtures\vps-internet-soak-evidence-v1\vps-internet-soak-linux-30s-slot-20260712T000000Z.txt"

foreach ($path in @($Doc, $Ops, $Soak, $Preflight, $Assert, $Fixture)) {
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

if (-not (Select-String -LiteralPath $Ops -Pattern "assert-vps-internet-soak-evidence" -Quiet)) {
    throw "vps-internet-soak-rehearsal-smoke: OPERATORS.md missing assert-vps-internet-soak-evidence"
}
& $Assert -EvidenceFile $Fixture | Out-Null

Write-Host "vps-internet-soak-rehearsal-smoke: plan"
Write-Host "  flow=vps-preflight.sh -> soak.sh --vps --archive-evidence"
Write-Host "  evidence=vps-internet-soak-linux-*.txt"
Write-Host "  assert=assert-vps-internet-soak-evidence.ps1"
Write-Host "  docs=docs/VPS_SINGLE_BOX_LAUNCH.md"
Write-Host "  live_rehearsal=human VPS (TL-5 execution)"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "vps-internet-soak-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "vps-internet-soak-rehearsal-smoke: live mode not implemented; run vps-internet-soak.sh on VPS"
