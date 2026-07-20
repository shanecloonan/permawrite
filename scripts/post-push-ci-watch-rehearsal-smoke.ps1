# CI plan gate for B-93 post-push-ci-watch (Windows twin).
param([switch]$PlanOnly)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($f in @("post-push-ci-watch.py", "post-push-ci-watch.ps1", "post-push-ci-watch.sh", "watch-ci-stall.py")) {
  if (-not (Test-Path (Join-Path $ScriptDir $f))) { throw "missing $f" }
}
$src = Get-Content -Raw (Join-Path $ScriptDir "post-push-ci-watch.py")
foreach ($n in @("B-93", "wraps=watch-ci-stall.py", "never=cancel_healthy_in_progress", "after_push")) {
  if ($src -notmatch [regex]::Escape($n)) { throw "missing needle $n" }
}
$plan = (python (Join-Path $ScriptDir "post-push-ci-watch.py") --plan-only) -join "`n"
if ($plan -notmatch "post-push-ci-watch: PASS plan-only") { throw "plan-only failed`n$plan" }
Write-Host "post-push-ci-watch-rehearsal-smoke: plan"
Write-Host "  unit=B-93"
Write-Host "  tool=post-push-ci-watch.py"
Write-Host "post-push-ci-watch-rehearsal-smoke: PASS plan-only"
