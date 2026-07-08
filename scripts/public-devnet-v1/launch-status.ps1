# Lane 7 — read-only internet-facing testnet launch posture (Windows).
param(
    [switch]$Json
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$ManifestPath = Join-Path $RepoRoot "mfn-node\testdata\public_devnet_v1.manifest.json"
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
        return @{ available = $false; message = "gh not on PATH" }
    }
    Push-Location $RepoRoot
    try {
        $line = gh run list --workflow CI --limit 1 --json databaseId,status,conclusion,headSha 2>$null
        if (-not $line) {
            return @{ available = $false; message = "gh run list failed" }
        }
        $run = ($line | ConvertFrom-Json)[0]
        return @{
            available = $true
            run_id    = $run.databaseId
            status    = $run.status
            conclusion = $run.conclusion
            head_sha  = $run.headSha
        }
    } finally {
        Pop-Location
    }
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

$phase = "TL-1"
if ($seedCount -gt 0) { $phase = "TL-8+" }
elseif ($missingBins.Count -eq 0) { $phase = "TL-2+ (build ready; follow TESTNET_LAUNCH.md)" }

$ci = Get-CiSummary
$head = Get-HeadSha

$report = [ordered]@{
    schema_version = "launch-status.v1"
    lane           = 7
    playbook       = $Playbook
    suggested_phase = $phase
    head_sha       = $head
    genesis_id     = $genesisId
    seed_nodes_count = $seedCount
    internet_facing = ($seedCount -gt 0)
    release_binaries_missing = $missingBins
    ci             = $ci
    next_actions   = @(
        "Complete TL phases in order: $Playbook",
        "Run release-ci-watch after TL-2 gate",
        "Do not publish seed_nodes until TL-5/TL-6 VPS evidence exists"
    )
}

if ($Json) {
    $report | ConvertTo-Json -Depth 6
    exit 0
}

Write-Host "launch-status: lane=7 phase=$phase head=$head"
Write-Host "launch-status: genesis_id=$genesisId seed_nodes=$seedCount internet_facing=$($report.internet_facing)"
if ($missingBins.Count -gt 0) {
    Write-Host "launch-status: missing_release_binaries=$($missingBins -join ',')"
}
if ($ci.available) {
    Write-Host "launch-status: ci run=$($ci.run_id) status=$($ci.status) conclusion=$($ci.conclusion) head=$($ci.head_sha)"
} else {
    Write-Host "launch-status: ci=$($ci.message)"
}
Write-Host "launch-status: playbook=$Playbook"
