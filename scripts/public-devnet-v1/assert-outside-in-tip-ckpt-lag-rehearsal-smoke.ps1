# CI plan gate for B-127 outside-in tip-ckpt lag assert (Windows twin).
param([switch]$PlanOnly)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($f in @(
    (Join-Path $ScriptDir "assert-outside-in-tip-ckpt-lag.ps1"),
    (Join-Path $ScriptDir "assert-outside-in-tip-ckpt-lag.sh")
)) {
    if (-not (Test-Path $f)) { throw "assert-outside-in-tip-ckpt-lag-rehearsal-smoke: missing $f" }
}
$src = Get-Content -Raw (Join-Path $ScriptDir "assert-outside-in-tip-ckpt-lag.ps1")
foreach ($n in @("B-127", "B-129", "outside-in-tip-ckpt-lag", "never=faucet-http", "path-a-publish", "MFN_CKPT_LAG_THRESHOLD", "EVIDENCE", "auto-archive")) {
    if ($src -notmatch [regex]::Escape($n)) {
        throw "assert-outside-in-tip-ckpt-lag-rehearsal-smoke: assert missing $n"
    }
}
$plan = (powershell -NoProfile -File (Join-Path $ScriptDir "assert-outside-in-tip-ckpt-lag.ps1") -PlanOnly) -join "`n"
if ($plan -notmatch "assert-outside-in-tip-ckpt-lag: PASS plan-only") {
    throw "assert-outside-in-tip-ckpt-lag-rehearsal-smoke: plan-only failed`n$plan"
}
Write-Host "assert-outside-in-tip-ckpt-lag-rehearsal-smoke: plan"
Write-Host "  unit=B-127+B-129"
Write-Host "  assert=assert-outside-in-tip-ckpt-lag.ps1"
Write-Host "assert-outside-in-tip-ckpt-lag-rehearsal-smoke: PASS plan-only"
