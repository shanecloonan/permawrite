# Lane 7: plan-only launch-status v10 schema rehearsal (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$launch = & powershell -NoProfile -File (Join-Path $ScriptDir "launch-status.ps1") -Json | ConvertFrom-Json

if ($launch.schema_version -ne "launch-status.v10") {
    throw "launch-status-rehearsal-smoke: expected launch-status.v10 got $($launch.schema_version)"
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
if (-not $launch.software_ready) {
    throw "launch-status-rehearsal-smoke: software_ready block missing"
}
if ($launch.software_ready.schema_version -ne "software-ready-pin.v1") {
    throw "launch-status-rehearsal-smoke: software_ready.schema_version expected software-ready-pin.v1"
}
if (-not $launch.software_ready.release_commit) {
    throw "launch-status-rehearsal-smoke: software_ready.release_commit empty"
}
if (-not $launch.fraud_proof) {
    throw "launch-status-rehearsal-smoke: fraud_proof block missing"
}
if ($launch.fraud_proof.phase_shipped -ne "1c") {
    throw "launch-status-rehearsal-smoke: fraud_proof.phase_shipped expected 1c got $($launch.fraud_proof.phase_shipped)"
}
if ($launch.fraud_proof.on_chain_producer_slash -ne "shipped") {
    throw "launch-status-rehearsal-smoke: fraud_proof.on_chain_producer_slash expected shipped"
}
if ($launch.fraud_proof.validity_proof -ne "research") {
    throw "launch-status-rehearsal-smoke: fraud_proof.validity_proof expected research got $($launch.fraud_proof.validity_proof)"
}
if ($launch.fraud_proof.validity_proof_phase -ne "4b.1") {
    throw "launch-status-rehearsal-smoke: fraud_proof.validity_proof_phase expected 4b.1"
}
if ($launch.fraud_proof.stark_backend -ne "winterfell") {
    throw "launch-status-rehearsal-smoke: fraud_proof.stark_backend expected winterfell"
}
if ($launch.fraud_proof.p2p_tag_validity -ne "0x14") {
    throw "launch-status-rehearsal-smoke: fraud_proof.p2p_tag_validity expected 0x14"
}
if (-not $launch.fraud_proof.list_fraud_contests_rpc) {
    throw "launch-status-rehearsal-smoke: fraud_proof.list_fraud_contests_rpc expected true"
}

Write-Host "launch-status-rehearsal-smoke: plan"
Write-Host "  schema=launch-status.v10"
Write-Host "  checkpoint_log.path=$($launch.checkpoint_log.path)"
Write-Host "  checkpoint_log.entry_count=$($launch.checkpoint_log.entry_count)"
Write-Host "  execution_checklist=$($launch.execution_checklist.schema_version)"
Write-Host "  treasury_telemetry=$($launch.treasury_telemetry.schema_version)"
Write-Host "  role_templates=$($launch.role_templates.schema_version)"
Write-Host "  software_ready_pin=$($launch.software_ready.release_commit) head_matches_pin=$($launch.software_ready.head_matches_pin)"
Write-Host "  fraud_proof_phase=$($launch.fraud_proof.phase_shipped)"
Write-Host "  helper=launch-status.ps1 -Json"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "launch-status-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "launch-status-rehearsal-smoke: live mode not implemented"
