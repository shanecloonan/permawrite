# Lane 7 / TL-9: automatable launch gate summary (human sign-off still required).
param([switch]$Json)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$ManifestPath = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.manifest.json"
$EvidenceDir = Join-Path $ScriptDir "evidence"
$fail = 0

function Pass([string]$Msg) { Write-Host "launch-go-no-go: PASS $Msg" }
function Fail([string]$Msg) { Write-Host "launch-go-no-go: FAIL $Msg" -ForegroundColor Red; $script:fail = 1 }
function Warn([string]$Msg) { Write-Host "launch-go-no-go: WARN $Msg" -ForegroundColor Yellow }

function Test-LocalMferRehearsalPass {
    param([Parameter(Mandatory = $true)][string]$Pattern)
    $files = Get-ChildItem -Path $EvidenceDir -Filter $Pattern -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        if (Select-String -Path $f.FullName -Pattern "SUMMARY: PASS" -Quiet) {
            return $true
        }
    }
    return $false
}

Push-Location $RepoRoot
try { $head = (git rev-parse --short HEAD 2>$null) } finally { Pop-Location }
if (-not $head) { $head = "unknown" }

$expectedGenesis = "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005"
$genesisId = $null
$seedCount = 0
if (Test-Path $ManifestPath) {
    $manifest = Get-Content -Raw -Encoding UTF8 $ManifestPath | ConvertFrom-Json
    $genesisId = $manifest.genesis_id
    $seedCount = @($manifest.seed_nodes).Count
}

if ($genesisId -eq $expectedGenesis) {
    Pass "genesis_id matches public_devnet_v1 ($genesisId)"
} else {
    Fail "genesis_id=$genesisId expected $expectedGenesis (Path B? document TL-7 sign-off)"
}

if ($seedCount -ge 3) {
    Pass "seed_nodes count=$seedCount"
} else {
    Fail "seed_nodes count=$seedCount (need >= 3 for TL-8)"
}

$soak = Get-ChildItem -Path $EvidenceDir -Filter "vps-internet-soak-linux-*.txt" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($soak -and (Select-String -Path $soak.FullName -Pattern "status=PASS" -Quiet)) {
    Pass "TL-5 evidence $($soak.Name)"
} elseif ($soak) {
    Fail "TL-5 evidence missing PASS summary in $($soak.Name)"
} else {
    $localNo = Test-LocalMferRehearsalPass -Pattern "participant-rehearsal-no-observer-*.txt"
    $localObs = Test-LocalMferRehearsalPass -Pattern "participant-rehearsal-observer-*.txt"
    if ($localNo -and $localObs) {
        Warn "TL-5 not run; local MFER rehearsals PASS - ready for VPS provision (docs/VPS_PROVISION.md)"
    } else {
        Warn "TL-5 not run; complete local participant-rehearsal-smoke on MFER devnet before VPS"
    }
    Fail "TL-5 evidence missing (vps-internet-soak-linux-*.txt)"
}

$rehearsal = Get-ChildItem -Path $EvidenceDir -Filter "vps-participant-rehearsal-*.txt" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($rehearsal -and (Select-String -Path $rehearsal.FullName -Pattern "SUMMARY: PASS" -Quiet)) {
    Pass "TL-6 evidence $($rehearsal.Name)"
} elseif ($rehearsal) {
    Fail "TL-6 evidence missing PASS in $($rehearsal.Name)"
} else {
    if ($soak) {
        Warn "TL-6 not run; VPS soak evidence present - run vps-participant-rehearsal.sh"
    }
    Fail "TL-6 evidence missing (vps-participant-rehearsal-*.txt)"
}

$release = Get-ChildItem -Path $EvidenceDir -Filter "release-evidence-*.json" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($release) {
    Pass "release evidence $($release.Name)"
} else {
    Warn "release-evidence-*.json not archived under evidence/ (refresh on green CI head)"
}

if (Test-Path (Join-Path $RepoRoot "docs\TESTNET_GENESIS_CEREMONY.md")) {
    Pass "TL-7 ceremony doc present (human sign-off still required)"
} else {
    Fail "missing docs/TESTNET_GENESIS_CEREMONY.md"
}

if (Test-Path (Join-Path $RepoRoot "docs\PUBLIC_DEVNET_THREAT_MODEL.md")) {
    Pass "threat model doc present"
} else {
    Fail "missing docs/PUBLIC_DEVNET_THREAT_MODEL.md"
}

$checkpointLogPath = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.checkpoints.jsonl"
if ($seedCount -ge 3) {
    if (Test-Path -LiteralPath $checkpointLogPath) {
        $checkpointLines = Get-Content -LiteralPath $checkpointLogPath -ErrorAction SilentlyContinue |
            Where-Object { $_.Trim() -ne "" }
        $checkpointEntries = @($checkpointLines).Count
        if ($checkpointEntries -gt 0) {
            Pass "checkpoint log has $checkpointEntries entries ($(Split-Path -Leaf $checkpointLogPath))"
        } else {
            Fail "checkpoint log empty ($checkpointLogPath); run publish-checkpoint-log.ps1 -Apply after TL-7"
        }
    } else {
        Fail "checkpoint log missing ($checkpointLogPath); run publish-checkpoint-log.ps1 -Apply after TL-7"
    }
}

if (Get-Command gh -ErrorAction SilentlyContinue) {
    Push-Location $RepoRoot
    $prevEap = $ErrorActionPreference
    try {
        if (-not $env:GH_TOKEN -and $env:GITHUB_TOKEN) {
            $env:GH_TOKEN = $env:GITHUB_TOKEN
        }
        if (-not $env:GH_TOKEN) {
            Warn "gh token not configured - skip CI lookup"
        } else {
            $ErrorActionPreference = "SilentlyContinue"
            $run = (gh run list --workflow CI --limit 1 --json status,conclusion 2>$null | ConvertFrom-Json)[0]
            if ($run.status -eq "completed" -and $run.conclusion -eq "success") {
                Pass "GitHub CI green (latest run)"
            } elseif ($run.status -eq "in_progress") {
                Warn "GitHub CI in progress on latest push"
            } else {
                Fail "GitHub CI status=$($run.status) conclusion=$($run.conclusion)"
            }
        }
    } catch {
        Warn "gh run list unavailable"
    } finally {
        $ErrorActionPreference = $prevEap
        Pop-Location
    }
} else {
    Warn "gh not on PATH - skip CI lookup"
}

Write-Host ""
Write-Host "launch-go-no-go: manual gates (see OPERATORS.md Launch go/no-go):"
Write-Host "  - TL-7 named human sign-off (toy keys Path A or fresh genesis Path B)"
Write-Host "  - TL-9 named launch-day watchers + halt authority"
Write-Host "  - RPC loopback-only verified on VPS"
Write-Host "  - Backups + rollback plan documented"
Write-Host ""
Write-Host "launch-go-no-go: head=$head playbook=docs/TESTNET_LAUNCH.md"

if ($Json) {
    [ordered]@{
        schema_version = "launch-go-no-go.v1"
        head_sha = $head
        genesis_id = $genesisId
        seed_nodes_count = $seedCount
        automatable_pass = ($fail -eq 0)
        tl5_evidence = if ($soak) { $soak.Name } else { "" }
        tl6_evidence = if ($rehearsal) { $rehearsal.Name } else { "" }
    } | ConvertTo-Json -Depth 4
}

if ($fail -ne 0) { exit 1 }
Write-Host "launch-go-no-go: automatable gates PASS (human TL-7/TL-9 sign-off still required before invite)"
