# Lane 6 / B-40: D0 preflight - treasury sample + B-28 floors + checklist needles.
# Does NOT enable subsidy_to_treasury_bps (B-33 human gate).
param(
    [switch]$PlanOnly,
    [string]$Rpc = ""
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($PlanOnly -or -not $Rpc) {
    Write-Host "b40-d0-preflight: plan"
    Write-Host "  steps=treasury-telemetry-watch,assert-b28-treasury-thresholds,d0-checklist"
    Write-Host "  pre_enable=true"
    Write-Host "  no_b13c_enable=true"
    Write-Host "  docs=docs/B40_PERMANENCE_WEEK.md"
    Write-Host "  command=b40-d0-preflight.ps1 -Rpc http://5.161.201.73:8787/rpc"
    Write-Host "b40-d0-preflight: PASS plan-only"
    exit 0
}

Write-Host ("b40-d0-preflight: live rpc=" + $Rpc)
& powershell -NoProfile -File (Join-Path $ScriptDir "treasury-telemetry-watch.ps1") -Rpc $Rpc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& powershell -NoProfile -File (Join-Path $ScriptDir "assert-b28-treasury-thresholds.ps1") -Rpc $Rpc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "b40-d0-preflight: checklist"
Write-Host "  [ ] Claim B-40 in AGENTS.md section 5 (lane 6 Doing); claim base = L4 tip SHA"
Write-Host "  [ ] Archive evidence/b40-d0-treasury-<UTC>.md from telemetry output"
Write-Host "  [ ] Confirm B-13a sims still in tip ancestry (256+512)"
Write-Host "  [ ] Ping lane 4+7: B-32 arm status (>=2 distinct hosts)"
Write-Host "  [ ] Confirm B-33 human cells open - do NOT enable B-13c on D0"
Write-Host "b40-d0-preflight: PASS"
