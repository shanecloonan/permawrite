param([switch]$PlanOnly, [switch]$Help)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Help) { Write-Host "usage: assert-path-a-near-tip-timer-rehearsal-smoke.ps1 [-PlanOnly]"; exit 0 }
$assert = Join-Path $ScriptDir "assert-path-a-near-tip-timer.sh"
if (-not (Test-Path -LiteralPath $assert)) { throw "missing $assert" }
$needles = @("assert-path-a-near-tip-timer", "B-89", "never=faucet-http", "path-a-near-tip-ckpt.timer")
$text = Get-Content -LiteralPath $assert -Raw
foreach ($n in $needles) { if ($text -notlike "*$n*") { throw "missing needle $n" } }
$bashPath = $null
foreach ($c in @("C:\msys64\usr\bin\bash.exe","C:\Program Files\Git\bin\bash.exe","C:\Program Files\Git\usr\bin\bash.exe")) {
  if (Test-Path -LiteralPath $c) { $bashPath = $c; break }
}
if (-not $bashPath) { $cmd = Get-Command bash -ErrorAction SilentlyContinue; if ($cmd) { $bashPath = $cmd.Source } }
if ($bashPath) {
  $bashDir = Split-Path -Parent $bashPath
  $pre = $env:Path
  try { $env:Path = "$bashDir;C:\msys64\usr\bin;$pre"; $plan = (& $bashPath $assert --plan-only 2>&1) -join "`n" }
  finally { $env:Path = $pre }
  if ($plan -notmatch "assert-path-a-near-tip-timer: PASS plan-only") { $plan | ForEach-Object { [Console]::Error.WriteLine($_) }; exit 1 }
} elseif ($text -notlike "*assert-path-a-near-tip-timer: PASS plan-only*") { throw "no bash and missing PASS marker" }
Write-Host "assert-path-a-near-tip-timer-rehearsal-smoke: PASS plan-only"
exit 0