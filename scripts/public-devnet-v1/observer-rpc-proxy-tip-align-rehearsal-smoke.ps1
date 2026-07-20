param([switch]$PlanOnly, [switch]$Help)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($Help) { Write-Host "usage: observer-rpc-proxy-tip-align-rehearsal-smoke.ps1 [-PlanOnly]"; exit 0 }
$mjs = Join-Path $ScriptDir "observer-rpc-proxy.mjs"
$svc = Join-Path $ScriptDir "observer-rpc-proxy.service"
foreach ($p in @($mjs, $svc)) { if (-not (Test-Path -LiteralPath $p)) { throw "missing $p" } }
$needles = @("PROXY_HUB_TIP_RPC", "tipAlignBeforeUploads", "list_recent_uploads", "B-90", "F105", "tip_align_waits")
$text = Get-Content -LiteralPath $mjs -Raw
foreach ($n in $needles) { if ($text -notlike "*$n*") { throw "missing needle $n" } }
$svcText = Get-Content -LiteralPath $svc -Raw
if ($svcText -notlike "*PROXY_HUB_TIP_RPC=127.0.0.1:18731*") { throw "missing hub tip env" }
if ($svcText -notlike "*PROXY_TIP_ALIGN_MS=45000*") { throw "missing tip align ms" }
$deploy = Join-Path $ScriptDir "vps-update-observer-rpc-proxy.sh"
if (-not (Test-Path -LiteralPath $deploy)) { throw "missing $deploy" }
$depText = Get-Content -LiteralPath $deploy -Raw
if ($depText -notlike "*B-90*") { throw "missing B-90 in deploy" }
if ($depText -notlike "*never=faucet-http*") { throw "missing never=faucet-http in deploy" }
$bashPath = $null
foreach ($c in @("C:\msys64\usr\bin\bash.exe","C:\Program Files\Git\bin\bash.exe","C:\Program Files\Git\usr\bin\bash.exe")) {
  if (Test-Path -LiteralPath $c) { $bashPath = $c; break }
}
if (-not $bashPath) { $cmd = Get-Command bash -ErrorAction SilentlyContinue; if ($cmd) { $bashPath = $cmd.Source } }
if ($bashPath) {
  $bashDir = Split-Path -Parent $bashPath
  $pre = $env:Path
  try { $env:Path = "$bashDir;C:\msys64\usr\bin;$pre"; $plan = (& $bashPath $deploy --plan-only 2>&1) -join "`n" }
  finally { $env:Path = $pre }
  if ($plan -notmatch "vps-update-observer-rpc-proxy: PASS plan-only") { $plan | ForEach-Object { [Console]::Error.WriteLine($_) }; exit 1 }
}
Write-Host "observer-rpc-proxy-tip-align-rehearsal-smoke: PASS plan-only"
exit 0