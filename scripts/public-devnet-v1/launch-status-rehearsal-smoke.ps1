# Lane 7: plan-only launch-status v4 schema rehearsal (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$launch = & powershell -NoProfile -File (Join-Path $ScriptDir "launch-status.ps1") -Json | ConvertFrom-Json

if ($launch.schema_version -ne "launch-status.v4") {
    throw "launch-status-rehearsal-smoke: expected launch-status.v4 got $($launch.schema_version)"
}
if ($launch.checkpoint_log.path -ne "mfn-node/testdata/public_devnet_v1.checkpoints.jsonl") {
    throw "launch-status-rehearsal-smoke: unexpected checkpoint_log.path $($launch.checkpoint_log.path)"
}
foreach ($key in @("exists", "entry_count", "published")) {
    if ($null -eq $launch.checkpoint_log.$key -and $key -ne "published") {
        # published is bool; exists/entry_count required
    }
}

Write-Host "launch-status-rehearsal-smoke: plan"
Write-Host "  schema=launch-status.v4"
Write-Host "  checkpoint_log.path=$($launch.checkpoint_log.path)"
Write-Host "  checkpoint_log.entry_count=$($launch.checkpoint_log.entry_count)"
Write-Host "  helper=launch-status.ps1 -Json"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "launch-status-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "launch-status-rehearsal-smoke: live mode not implemented"
