param([switch]$PlanOnly, [switch]$Help)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Help) { Write-Host "usage: land-path-a-checkpoint-from-vps-rehearsal-smoke.ps1 [-PlanOnly]"; exit 0 }
$land = Join-Path $ScriptDir "land-path-a-checkpoint-from-vps.sh"
if (-not (Test-Path -LiteralPath $land)) { throw "missing $land" }
$needles = @("land-path-a-checkpoint-from-vps", "B-89", "never=faucet-http", "git-commit")
$text = Get-Content -LiteralPath $land -Raw
foreach ($n in $needles) { if ($text -notlike "*$n*") { throw "missing needle $n" } }
$bashPath = $null
foreach ($c in @("C:\msys64\usr\bin\bash.exe","C:\Program Files\Git\bin\bash.exe","C:\Program Files\Git\usr\bin\bash.exe")) {
  if (Test-Path -LiteralPath $c) { $bashPath = $c; break }
}
if (-not $bashPath) { $cmd = Get-Command bash -ErrorAction SilentlyContinue; if ($cmd) { $bashPath = $cmd.Source } }
if ($bashPath) {
  $bashDir = Split-Path -Parent $bashPath
  $pre = $env:Path
  try { $env:Path = "$bashDir;C:\msys64\usr\bin;$pre"; $plan = (& $bashPath $land --plan-only 2>&1) -join "`n" }
  finally { $env:Path = $pre }
  if ($plan -notmatch "land-path-a-checkpoint-from-vps: PASS plan-only") { $plan | ForEach-Object { [Console]::Error.WriteLine($_) }; exit 1 }
} elseif ($text -notlike "*land-path-a-checkpoint-from-vps: PASS plan-only*") { throw "no bash and missing PASS marker" }
Write-Host "land-path-a-checkpoint-from-vps-rehearsal-smoke: PASS plan-only"
exit 0