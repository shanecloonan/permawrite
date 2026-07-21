# CI plan gate for B-27 outside-in invite-head soak tooling (+ B-96 pin assert; Windows twin).
param([switch]$PlanOnly)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$need = @(
    (Join-Path $ScriptDir "outside-in-invite-soak.ps1"),
    (Join-Path $ScriptDir "assert-outside-in-invite-soak-evidence.ps1"),
    (Join-Path $ScriptDir "fixtures\outside-in-invite-soak-evidence-v1\outside-in-invite-soak-20260720T000000Z.txt")
)
foreach ($f in $need) {
    if (-not (Test-Path $f)) { throw "outside-in-invite-soak-rehearsal-smoke: missing $f" }
}
$soakSrc = Get-Content -Raw (Join-Path $ScriptDir "outside-in-invite-soak.ps1")
foreach ($n in @("B-27", "outside-in-invite-soak", "never=faucet-http", "assert-outside-in-invite-soak-evidence", "nightly_run=", "ci_run=", "Get-MfnGreenRunId")) {
    if ($soakSrc -notmatch [regex]::Escape($n)) {
        throw "outside-in-invite-soak-rehearsal-smoke: outside-in-invite-soak.ps1 missing $n"
    }
}
$assertSrc = Get-Content -Raw (Join-Path $ScriptDir "assert-outside-in-invite-soak-evidence.ps1")
foreach ($n in @("missing # nightly_run", "missing # ci_run", "B-96")) {
    if ($assertSrc -notmatch [regex]::Escape($n)) {
        throw "outside-in-invite-soak-rehearsal-smoke: assert missing $n"
    }
}
$planText = (powershell -NoProfile -File (Join-Path $ScriptDir "outside-in-invite-soak.ps1") -PlanOnly) -join "`n"
if ($planText -notmatch "outside-in-invite-soak: PASS plan-only") {
    throw "outside-in-invite-soak-rehearsal-smoke: plan-only failed`n$planText"
}
$fixture = Join-Path $ScriptDir "fixtures\outside-in-invite-soak-evidence-v1\outside-in-invite-soak-20260720T000000Z.txt"
$assertText = (powershell -NoProfile -File (Join-Path $ScriptDir "assert-outside-in-invite-soak-evidence.ps1") -EvidenceFile $fixture) -join "`n"
if ($assertText -notmatch "assert-outside-in-invite-soak-evidence: OK") {
    throw "outside-in-invite-soak-rehearsal-smoke: fixture assert failed`n$assertText"
}
Write-Host "outside-in-invite-soak-rehearsal-smoke: plan"
Write-Host "  unit=B-27+B-96"
Write-Host "  soak=outside-in-invite-soak.ps1"
Write-Host "  assert=assert-outside-in-invite-soak-evidence.ps1"
Write-Host "  fixture_assert=true"
Write-Host "outside-in-invite-soak-rehearsal-smoke: PASS plan-only"
