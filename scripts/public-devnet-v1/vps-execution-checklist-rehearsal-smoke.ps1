# Lane 7: plan-only vps-execution-checklist rehearsal (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Ops = Join-Path $RepoRoot "scripts\public-devnet-v1\OPERATORS.md"
$Doc = Join-Path $RepoRoot "docs\VPS_PROVISION.md"

foreach ($path in @($Ops, $Doc)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "vps-execution-checklist-rehearsal-smoke: missing $path"
    }
}
if (-not (Select-String -LiteralPath $Ops -Pattern "vps-execution-checklist" -Quiet)) {
    throw "vps-execution-checklist-rehearsal-smoke: OPERATORS.md missing vps-execution-checklist"
}

$report = & powershell -NoProfile -File (Join-Path $ScriptDir "vps-execution-checklist.ps1") -Json | ConvertFrom-Json
if ($report.schema_version -ne "vps-execution-checklist.v1") {
    throw "vps-execution-checklist-rehearsal-smoke: expected v1 got $($report.schema_version)"
}
foreach ($key in @("provision", "preflight", "tl5_soak", "tl6_rehearsal", "treasury_telemetry", "pm23_rehearsal", "tl9_launch_gate")) {
    if (-not $report.commands.$key) {
        throw "vps-execution-checklist-rehearsal-smoke: commands missing $key"
    }
}
if (-not $report.launch_status) {
    throw "vps-execution-checklist-rehearsal-smoke: launch_status missing"
}

Write-Host "vps-execution-checklist-rehearsal-smoke: plan"
Write-Host "  schema=$($report.schema_version)"
Write-Host "  ready_for_vps_execution=$($report.ready_for_vps_execution)"
Write-Host "  local_rc_complete=$($report.local_rc_complete)"
Write-Host "  helper=vps-execution-checklist.ps1 -Json [-Strict]"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "vps-execution-checklist-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "vps-execution-checklist-rehearsal-smoke: live mode not implemented"
