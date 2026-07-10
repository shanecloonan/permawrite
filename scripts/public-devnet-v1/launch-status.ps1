# Lane 7 — read-only internet-facing testnet launch posture (Windows).
param(
    [switch]$Json
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$ManifestPath = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.manifest.json"
$CheckpointLogPath = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.checkpoints.jsonl"
$CheckpointLogRel = "mfn-node/testdata/public_devnet_v1.checkpoints.jsonl"
$EvidenceDir = Join-Path $ScriptDir "evidence"
$Playbook = "docs/TESTNET_LAUNCH.md"

function Read-Manifest {
    if (-not (Test-Path $ManifestPath)) {
        return $null
    }
    Get-Content -Raw -Encoding UTF8 $ManifestPath | ConvertFrom-Json
}

function Get-HeadSha {
    Push-Location $RepoRoot
    try {
        return (git rev-parse --short HEAD 2>$null)
    } finally {
        Pop-Location
    }
}

function Get-CiSummary {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        return @{ message = "gh not on PATH" }
    }
    Push-Location $RepoRoot
    try {
        $line = gh run list --workflow CI --limit 1 --json databaseId,status,conclusion,headSha 2>$null
        if (-not $line) {
            return @{ message = "gh run list failed" }
        }
        $run = ($line | ConvertFrom-Json)[0]
        return @{
            message    = "run=$($run.databaseId) status=$($run.status) conclusion=$($run.conclusion)"
            run_id     = $run.databaseId
            status     = $run.status
            conclusion = $run.conclusion
            head_sha   = $run.headSha
        }
    } finally {
        Pop-Location
    }
}

function Get-EvidencePassFile {
    param(
        [Parameter(Mandatory = $true)][string]$Pattern
    )
    $files = Get-ChildItem -Path $EvidenceDir -Filter $Pattern -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    foreach ($f in $files) {
        if (Select-String -Path $f.FullName -Pattern "SUMMARY: PASS" -Quiet) {
            return $f.Name
        }
    }
    return $null
}

function Get-CheckpointLogStatus {
    $exists = Test-Path -LiteralPath $CheckpointLogPath
    $entryCount = 0
    $published = $false
    $verified = $null
    if ($exists) {
        $lines = Get-Content -LiteralPath $CheckpointLogPath -ErrorAction SilentlyContinue |
            Where-Object { $_.Trim() -ne "" }
        $entryCount = @($lines).Count
        if ($entryCount -gt 0) {
            $published = $true
            $mcli = Join-Path $RepoRoot "target\release\mfn-cli.exe"
            if (Test-Path -LiteralPath $mcli) {
                & $mcli checkpoint-log verify $CheckpointLogPath 2>$null | Out-Null
                $verified = ($LASTEXITCODE -eq 0)
            }
        }
    }
    return [ordered]@{
        path         = $CheckpointLogRel
        exists       = $exists
        entry_count  = $entryCount
        published    = $published
        verified     = $verified
    }
}

function Test-RcAuditGo {
    $files = Get-ChildItem -Path $EvidenceDir -Filter "rc-audit-dry-run-*.json" -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        try {
            $doc = Get-Content -Raw -Encoding UTF8 $f.FullName | ConvertFrom-Json
            if ($doc.decision -eq "go") {
                return $f.Name
            }
        } catch {
            continue
        }
    }
    return $null
}

$manifest = Read-Manifest
$seedCount = 0
$genesisId = $null
if ($manifest) {
    $seedCount = @($manifest.seed_nodes).Count
    $genesisId = $manifest.genesis_id
}

$binaries = @("mfnd.exe", "mfn-cli.exe", "mfn-storage-operator.exe")
$missingBins = @()
foreach ($b in $binaries) {
    $p = Join-Path $RepoRoot "target\release\$b"
    if (-not (Test-Path $p)) { $missingBins += $b }
}

$tl5File = Get-EvidencePassFile -Pattern "vps-internet-soak-linux-*.txt"
$tl6File = Get-EvidencePassFile -Pattern "vps-participant-rehearsal-*.txt"
$tl5Evidence = [bool]$tl5File
$tl6Evidence = [bool]$tl6File

$localMferNoObserverFile = Get-EvidencePassFile -Pattern "participant-rehearsal-no-observer-*.txt"
$localMferObserverFile = Get-EvidencePassFile -Pattern "participant-rehearsal-observer-*.txt"
$localMferNoObserver = [bool]$localMferNoObserverFile
$localMferObserver = [bool]$localMferObserverFile
$localRcComplete = $localMferNoObserver -and $localMferObserver

$releaseEvidenceFiles = Get-ChildItem -Path $EvidenceDir -Filter "release-evidence-*.json" -ErrorAction SilentlyContinue
$releaseEvidenceArchived = [bool]$releaseEvidenceFiles
$releaseEvidenceFile = if ($releaseEvidenceFiles) { $releaseEvidenceFiles[0].Name } else { "" }

$rcAuditFile = Test-RcAuditGo
$rcAuditGo = [bool]$rcAuditFile

$checkpointLog = Get-CheckpointLogStatus

$phase = 'TL-5 (provision VPS - see docs/VPS_PROVISION.md)'
$nextAction = 'docs/VPS_PROVISION.md then bash scripts/public-devnet-v1/vps-preflight.sh'
if ($seedCount -gt 0) {
    $phase = 'TL-9+ (seed_nodes published - run launch-go-no-go.sh before invite)'
    $nextAction = 'bash scripts/public-devnet-v1/launch-go-no-go.sh'
} elseif ($tl6Evidence) {
    $phase = 'TL-7 (human genesis ceremony - TESTNET_GENESIS_CEREMONY.md)'
    if (-not $checkpointLog.published) {
        $nextAction = 'complete TL-7 sign-off then publish-seed-nodes.sh + publish-checkpoint-log.sh --apply'
    } else {
        $nextAction = 'complete TL-7 sign-off then publish-seed-nodes.sh (checkpoint log already has entries)'
    }
} elseif ($tl5Evidence) {
    $phase = 'TL-6 (VPS soak done; run vps-participant-rehearsal.sh)'
    $nextAction = 'bash scripts/public-devnet-v1/vps-participant-rehearsal.sh --no-start --no-stop'
} elseif ($localRcComplete -and $missingBins.Count -eq 0) {
    $phase = 'TL-5 (local RC complete - provision VPS for internet soak)'
    $nextAction = 'docs/VPS_PROVISION.md -> vps-preflight.sh -> vps-internet-soak.sh'
} elseif ($missingBins.Count -eq 0) {
    $phase = 'TL-5 (build complete - run local MFER rehearsals then provision VPS)'
    $nextAction = 'participant-rehearsal-smoke before VPS; see docs/VPS_PROVISION.md'
}

$ci = Get-CiSummary
$head = Get-HeadSha
$internetFacing = ($seedCount -gt 0)

$report = [ordered]@{
    schema_version         = "launch-status.v4"
    lane                   = 7
    playbook               = $Playbook
    invite_packet          = "docs/TESTNET_INVITE.md"
    suggested_phase        = $phase
    next_action            = $nextAction
    head_sha               = $head
    genesis_id             = $genesisId
    seed_nodes_count       = $seedCount
    internet_facing        = $internetFacing
    local_rc_complete      = $localRcComplete
    local_mfer_rehearsal     = [ordered]@{
        no_observer      = $localMferNoObserver
        observer         = $localMferObserver
        no_observer_file = $(if ($localMferNoObserverFile) { $localMferNoObserverFile } else { "" })
        observer_file    = $(if ($localMferObserverFile) { $localMferObserverFile } else { "" })
    }
    vps_soak_evidence      = $tl5Evidence
    vps_rehearsal_evidence = $tl6Evidence
    vps_soak_file          = $(if ($tl5File) { $tl5File } else { "" })
    vps_rehearsal_file     = $(if ($tl6File) { $tl6File } else { "" })
    release_evidence_archived = $releaseEvidenceArchived
    release_evidence_file  = $releaseEvidenceFile
    rc_audit_go            = $rcAuditGo
    rc_audit_file          = $(if ($rcAuditFile) { $rcAuditFile } else { "" })
    checkpoint_log         = $checkpointLog
    release_binaries_missing = $missingBins
    ci                     = $ci
}

if ($Json) {
    $report | ConvertTo-Json -Depth 6
    exit 0
}

Write-Host "launch-status: lane=7 phase=$phase head=$head"
Write-Host "launch-status: genesis_id=$genesisId seed_nodes=$seedCount internet_facing=$internetFacing"
Write-Host "launch-status: local_rc_complete=$localRcComplete local_mfer_no_observer=$localMferNoObserver local_mfer_observer=$localMferObserver"
Write-Host "launch-status: vps_soak_evidence=$tl5Evidence vps_rehearsal_evidence=$tl6Evidence"
Write-Host "launch-status: release_evidence_archived=$releaseEvidenceArchived rc_audit_go=$rcAuditGo"
Write-Host "launch-status: checkpoint_log_entries=$($checkpointLog.entry_count) published=$($checkpointLog.published) verified=$($checkpointLog.verified)"
if ($missingBins.Count -gt 0) {
    Write-Host "launch-status: missing_release_binaries=$($missingBins -join ',')"
}
if ($ci.run_id) {
    Write-Host "launch-status: ci $($ci.message)"
} else {
    Write-Host "launch-status: ci $($ci.message)"
}
Write-Host "launch-status: next_action=$nextAction"
Write-Host "launch-status: playbook=$Playbook invite=docs/TESTNET_INVITE.md"
