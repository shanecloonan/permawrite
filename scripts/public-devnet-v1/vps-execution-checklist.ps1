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
    $prevEap = $ErrorActionPreference
    try {
        if (-not $env:GH_TOKEN -and $env:GITHUB_TOKEN) {
            $env:GH_TOKEN = $env:GITHUB_TOKEN
        }
        if ($env:GH_TOKEN) {
            $ErrorActionPreference = "SilentlyContinue"
            $line = gh run list --workflow CI --limit 1 --json databaseId,status,conclusion,headSha 2>$null
            if ($line) { $ci = ($line | ConvertFrom-Json)[0] }
        }
    } finally {
        $ErrorActionPreference = $prevEap
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
if ($launchJson.vps_rehearsal_evidence -and -not $launchJson.checkpoint_log.published) {
    $warnings += "checkpoint log empty - run publish-checkpoint-log.ps1 -Apply after TL-7 before TL-8 invite"
}
if ($ci -and -not $ciGreen) {
    $msg = "GitHub CI not green (run=$($ci.databaseId) status=$($ci.status) conclusion=$($ci.conclusion))"
    if ($Strict) { $blockers += $msg } else { $warnings += $msg }
} elseif (-not $ci) {
    $warnings += "gh not available - skip live CI lookup"
}

$report = [ordered]@{
    schema_version          = "vps-execution-checklist.v2"
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
        ceremony      = "bash scripts/public-devnet-v1/vps-launch-ceremony.sh"
        treasury_telemetry = "bash scripts/public-devnet-v1/treasury-telemetry-watch.sh --rpc 127.0.0.1:18731"
        pm23_rehearsal = "bash scripts/public-devnet-v1/pm23-operator-manifest-rehearsal-smoke.sh --plan-only"
        role_templates = "bash scripts/public-devnet-v1/vps-role-templates-rehearsal-smoke.sh --plan-only"
        tl9_launch_gate = "bash scripts/public-devnet-v1/launch-go-no-go.sh"
        tl7_signoff = "docs/TESTNET_GENESIS_CEREMONY.md"
        tl8_publish_seeds = "bash scripts/public-devnet-v1/publish-seed-nodes.sh --public-ip YOUR_VPS_IP --apply"
        tl8_publish_checkpoint_log = "bash scripts/public-devnet-v1/publish-checkpoint-log.sh --apply"
        tl8_invite = "docs/TESTNET_INVITE.md"
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
    Write-Host "  7. $($report.commands.tl7_signoff)  # human sign-off"
    Write-Host "  8. $($report.commands.tl8_publish_seeds)  # commit manifest"
    Write-Host "  9. $($report.commands.tl8_publish_checkpoint_log)  # commit checkpoints.jsonl"
    Write-Host " 10. $($report.commands.tl8_invite)  # share invite packet"
    Write-Host " 11. $($report.commands.tl9_launch_gate)"
}

if (-not $report.ready_for_vps_execution) { exit 1 }
exit 0
