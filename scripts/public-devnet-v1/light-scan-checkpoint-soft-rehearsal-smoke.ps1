# B-165: Windows twin of light-scan-checkpoint-soft-rehearsal-smoke.sh
param([switch]$PlanOnly)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "../..")).Path
$softSh = Join-Path $ScriptDir "light-scan-checkpoint-soft.sh"
$softPs1 = Join-Path $ScriptDir "light-scan-checkpoint-soft.ps1"
$rpcRs = Join-Path $RepoRoot "mfn-cli/src/rpc.rs"
$lwRs = Join-Path $RepoRoot "mfn-cli/src/light_wallet.rs"
if (-not (Test-Path $softSh)) { Write-Error "missing light-scan-checkpoint-soft.sh" }
if (-not (Test-Path $softPs1)) { Write-Error "missing light-scan-checkpoint-soft.ps1 (B-164)" }
foreach ($pair in @(
  @($softSh, "B-161"),
  @($softPs1, "B-161"),
  @($softSh, "f45-soft"),
  @($rpcRs, "MFN_HEAVY_RPC_TIMEOUT_MS"),
  @($lwRs, "checkpoint_log_f45_soft_pass"),
  @($lwRs, "maybe_auto_bootstrap_from_checkpoint_log")
)) {
  $txt = Get-Content -Raw $pair[0]
  if ($txt -notmatch [regex]::Escape($pair[1])) { Write-Error "missing needle $($pair[1]) in $($pair[0])" }
}
$plan = & powershell -NoProfile -File $softPs1 -PlanOnly
$joined = ($plan | Out-String)
if ($joined -notmatch "light-scan-checkpoint-soft: PASS plan-only") { Write-Output $joined; Write-Error "soft.ps1 plan failed" }
if ($joined -notmatch "B-161") { Write-Output $joined; Write-Error "soft.ps1 plan missing B-161" }
Write-Output "light-scan-checkpoint-soft-rehearsal-smoke: PASS plan-only"
if (-not $PlanOnly) { exit 0 }