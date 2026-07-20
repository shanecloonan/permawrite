# CI plan gate for B-34 watch-ci-stall (Windows twin).
param([switch]$PlanOnly)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($f in @("watch-ci-stall.py", "watch-ci-stall.ps1", "watch-ci-stall.sh")) {
    if (-not (Test-Path (Join-Path $ScriptDir $f))) { throw "missing $f" }
}
$src = Get-Content -Raw (Join-Path $ScriptDir "watch-ci-stall.py")
foreach ($n in @("B-34", "all_jobs_queued_empty_steps", "never=cancel_healthy_in_progress")) {
    if ($src -notmatch [regex]::Escape($n)) { throw "missing needle $n" }
}
$plan = (python (Join-Path $ScriptDir "watch-ci-stall.py") --plan-only) -join "`n"
if ($plan -notmatch "watch-ci-stall: PASS plan-only") { throw "plan-only failed`n$plan" }
Write-Host "watch-ci-stall-rehearsal-smoke: plan"
Write-Host "  unit=B-34"
Write-Host "  tool=watch-ci-stall.py"
Write-Host "watch-ci-stall-rehearsal-smoke: PASS plan-only"
