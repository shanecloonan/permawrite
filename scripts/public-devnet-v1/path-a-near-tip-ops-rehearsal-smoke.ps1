param([switch]$PlanOnly, [switch]$Help)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Help) { Write-Host "usage: path-a-near-tip-ops-rehearsal-smoke.ps1 [-PlanOnly]"; exit 0 }
& (Join-Path $ScriptDir "assert-path-a-near-tip-timer-rehearsal-smoke.ps1") -PlanOnly
& (Join-Path $ScriptDir "land-path-a-checkpoint-from-vps-rehearsal-smoke.ps1") -PlanOnly
Write-Host "path-a-near-tip-ops-rehearsal-smoke: PASS plan-only"
exit 0