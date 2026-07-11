# Lane 7: plan-only launch-status v5 schema rehearsal (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$launch = & powershell -NoProfile -File (Join-Path $ScriptDir "launch-status.ps1") -Json | ConvertFrom-Json

if ($launch.schema_version -ne "launch-status.v5") {
    throw "launch-status-rehearsal-smoke: expected launch-status.v5 got $($launch.schema_version)"
}
if ($launch.checkpoint_log.path -ne "mfn-node/testdata/public_devnet_v1.checkpoints.jsonl") {
    throw "launch-status-rehearsal-smoke: unexpected checkpoint_log.path $($launch.checkpoint_log.path)"
}
if ($launch.execution_checklist.schema_version -ne "vps-execution-checklist.v2") {
    throw "launch-status-rehearsal-smoke: expected execution_checklist v2 got $($launch.execution_checklist.schema_version)"
}
if ($launch.execution_checklist.helper -notmatch "vps-execution-checklist.sh") {
    throw "launch-status-rehearsal-smoke: execution_checklist.helper missing vps-execution-checklist.sh"
}

Write-Host "launch-status-rehearsal-smoke: plan"
Write-Host "  schema=launch-status.v5"
Write-Host "  checkpoint_log.path=$($launch.checkpoint_log.path)"
Write-Host "  checkpoint_log.entry_count=$($launch.checkpoint_log.entry_count)"
Write-Host "  execution_checklist=$($launch.execution_checklist.schema_version)"
Write-Host "  helper=launch-status.ps1 -Json"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "launch-status-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "launch-status-rehearsal-smoke: live mode not implemented"
