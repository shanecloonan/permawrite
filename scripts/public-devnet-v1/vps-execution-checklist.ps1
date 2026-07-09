# Lane 7 — read-only checklist before TL-5/TL-6 VPS execution (Windows).
param(
    [switch]$Json,
    [switch]$Strict
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path

$launchJson = & powershell -NoProfile -File (Join-Path $ScriptDir "launch-status.ps1") -Json | ConvertFrom-Json

$ci = @{}
if (Get-Command gh -ErrorAction SilentlyContinue) {
    Push-Location $RepoRoot
    try {
        $line = gh run list --workflow CI --limit 1 --json databaseId,status,conclusion,headSha 2>$null
        if ($line) { $ci = ($line | ConvertFrom-Json)[0] }
    } finally {
        Pop-Location
    }
}
$ciGreen = ($ci.status -eq "completed" -and $ci.conclusion -eq "success")

$blockers = @()
$warnings = @()
if (-not $launchJson.local_rc_complete) {
    $blockers += "local MFER rehearsals incomplete (need no-observer + observer PASS evidence)"
}
if (-not $launchJson.release_evidence_archived) {
    $warnings += "release-evidence-*.json not archived under evidence/ (refresh on green CI head)"
}
if (-not $launchJson.rc_audit_go) {
    $warnings += "rc-audit-dry-run go evidence missing under evidence/"
}
if ($launchJson.vps_soak_evidence) {
    $warnings += "TL-5 VPS soak evidence already present - skip re-soak unless reprovisioning"
}
if ($launchJson.vps_rehearsal_evidence) {
    $warnings += "TL-6 VPS rehearsal evidence already present"
}
if ($ci -and -not $ciGreen) {
    $msg = "GitHub CI not green (run=$($ci.databaseId) status=$($ci.status) conclusion=$($ci.conclusion))"
    if ($Strict) { $blockers += $msg } else { $warnings += $msg }
} elseif (-not $ci) {
    $warnings += "gh not available - skip live CI lookup"
}

$report = [ordered]@{
    schema_version          = "vps-execution-checklist.v1"
    ready_for_vps_execution = ($blockers.Count -eq 0)
    local_rc_complete       = [bool]$launchJson.local_rc_complete
    suggested_phase         = $launchJson.suggested_phase
    head_sha                = $launchJson.head_sha
    genesis_id              = $launchJson.genesis_id
    blockers                = $blockers
    warnings                = $warnings
    launch_status           = $launchJson
    ci                      = $ci
    commands                = [ordered]@{
        provision    = "docs/VPS_PROVISION.md"
        preflight    = "bash scripts/public-devnet-v1/vps-preflight.sh"
        tl5_soak     = "bash scripts/public-devnet-v1/vps-internet-soak.sh"
        tl6_rehearsal = "bash scripts/public-devnet-v1/vps-participant-rehearsal.sh --no-start --no-stop"
        archive      = "git add scripts/public-devnet-v1/evidence/vps-*.txt && git commit"
        ceremony     = "bash scripts/public-devnet-v1/vps-launch-ceremony.sh"
    }
}

if ($Json) {
    $report | ConvertTo-Json -Depth 8
} else {
    Write-Host "vps-execution-checklist: ready=$($report.ready_for_vps_execution) head=$($report.head_sha)"
    Write-Host "vps-execution-checklist: phase=$($report.suggested_phase)"
    Write-Host "vps-execution-checklist: local_rc_complete=$($report.local_rc_complete)"
    foreach ($b in $blockers) { Write-Host "vps-execution-checklist: BLOCKER $b" }
    foreach ($w in $warnings) { Write-Host "vps-execution-checklist: WARN $w" }
    Write-Host "vps-execution-checklist: ordered path:"
    Write-Host "  1. $($report.commands.provision)"
    Write-Host "  2. $($report.commands.preflight)"
    Write-Host "  3. $($report.commands.tl5_soak)  # archive vps-internet-soak-linux-*.txt"
    Write-Host "  4. $($report.commands.tl6_rehearsal)  # archive vps-participant-rehearsal-*.txt"
    Write-Host "  5. $($report.commands.archive)"
    Write-Host "  6. $($report.commands.ceremony)"
}

if (-not $report.ready_for_vps_execution) { exit 1 }
exit 0
