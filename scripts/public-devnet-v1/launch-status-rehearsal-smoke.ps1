# Lane 7: plan-only launch-status v6 schema rehearsal (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$launch = & powershell -NoProfile -File (Join-Path $ScriptDir "launch-status.ps1") -Json | ConvertFrom-Json

if ($launch.schema_version -ne "launch-status.v6") {
    throw "launch-status-rehearsal-smoke: expected launch-status.v6 got $($launch.schema_version)"
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
if ($launch.treasury_telemetry.schema_version -ne "treasury-telemetry-watch.v1") {
    throw "launch-status-rehearsal-smoke: expected treasury_telemetry v1"
}
if ($launch.treasury_telemetry.helper -notmatch "treasury-telemetry-watch.sh") {
    throw "launch-status-rehearsal-smoke: treasury_telemetry.helper missing treasury-telemetry-watch.sh"
}
if ($launch.role_templates.schema_version -ne "vps-role-templates.v1") {
    throw "launch-status-rehearsal-smoke: expected role_templates v1"
}
if ($launch.role_templates.templates.Count -lt 4) {
    throw "launch-status-rehearsal-smoke: role_templates.templates expected >= 4"
}

Write-Host "launch-status-rehearsal-smoke: plan"
Write-Host "  schema=launch-status.v6"
Write-Host "  checkpoint_log.path=$($launch.checkpoint_log.path)"
Write-Host "  checkpoint_log.entry_count=$($launch.checkpoint_log.entry_count)"
Write-Host "  execution_checklist=$($launch.execution_checklist.schema_version)"
Write-Host "  treasury_telemetry=$($launch.treasury_telemetry.schema_version)"
Write-Host "  role_templates=$($launch.role_templates.schema_version)"
Write-Host "  helper=launch-status.ps1 -Json"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "launch-status-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "launch-status-rehearsal-smoke: live mode not implemented"
