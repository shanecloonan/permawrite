# Build a release-candidate audit dry-run using archived M2.4.70 evidence artifacts.
param(
    [string]$ReleaseEvidenceJson = "",
    [string]$OutputPath = "",
    [switch]$Json
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
Set-Location $RepoRoot

if (-not $ReleaseEvidenceJson) {
    $shortCommit = (& git rev-parse --short HEAD).Trim()
    $headEvidence = Join-Path $ScriptDir "evidence/release-evidence-$shortCommit.json"
    if (Test-Path -LiteralPath $headEvidence -PathType Leaf) {
        $ReleaseEvidenceJson = $headEvidence
    } else {
        $ReleaseEvidenceJson = Join-Path $ScriptDir "evidence/release-evidence-ebe1e48.json"
    }
}
if (-not (Test-Path -LiteralPath $ReleaseEvidenceJson -PathType Leaf)) {
    throw "release-rc-audit-dry-run: missing release evidence JSON $ReleaseEvidenceJson"
}

$commit = (& git rev-parse HEAD).Trim()
$shortCommit = (& git rev-parse --short HEAD).Trim()
$archiveRoot = Join-Path ([System.IO.Path]::GetTempPath()) "permawrite-rc-audit-dry-run-$shortCommit"
if (Test-Path -LiteralPath $archiveRoot -PathType Container) {
    Remove-Item -LiteralPath $archiveRoot -Recurse -Force
}
$archiveDir = Join-Path $archiveRoot "permawrite-public-devnet-dry-run-$shortCommit"

$releaseEvidenceMd = Join-Path $ScriptDir "evidence/release-evidence-ebe1e48.md"
if (-not (Test-Path -LiteralPath $releaseEvidenceMd -PathType Leaf)) {
    $releaseEvidenceMd = ""
}

$inventoryStaging = Join-Path ([System.IO.Path]::GetTempPath()) "permawrite-rc-inventory-$shortCommit.md"
$evidenceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ReleaseEvidenceJson).Hash.ToLowerInvariant()
@(
    "# RC dry-run inventory",
    "",
    "- Path or URL: evidence/release-evidence.json",
    "- SHA-256: $evidenceHash",
    "- Reviewer: rc-dry-run",
    "",
    "Decision: go"
) | Set-Content -LiteralPath $inventoryStaging -Encoding utf8

$archiveArgs = @(
    "-NoProfile", "-File", (Join-Path $ScriptDir "release-archive-dry-run.ps1"),
    "-OutputDir", $archiveRoot,
    "-ReleaseEvidenceJson", $ReleaseEvidenceJson,
    "-Inventory", $inventoryStaging
)
if ($releaseEvidenceMd) {
    $archiveArgs += @("-ReleaseEvidenceMarkdown", $releaseEvidenceMd)
}
& powershell @archiveArgs | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$wheelhouseDir = Join-Path $archiveDir "toolchain/wheelhouse-release-schema"
if (Test-Path -LiteralPath $wheelhouseDir -PathType Container) {
    $wheelCount = (Get-ChildItem -LiteralPath $wheelhouseDir -Filter *.whl -File -ErrorAction SilentlyContinue).Count
    if ($wheelCount -lt 3) {
        Remove-Item -LiteralPath $wheelhouseDir -Recurse -Force
    }
}

$signoffManifest = "docs/release-signoff-manifest-v1.sample.json"
$inventoryInArchive = Join-Path $archiveDir "evidence/release-artifact-inventory.md"
if (-not (Test-Path -LiteralPath $inventoryInArchive -PathType Leaf)) {
    throw "release-rc-audit-dry-run: archive missing $inventoryInArchive"
}

$ciMock = Join-Path $archiveDir "signoff-ci-success.json"
@(
    @{ headSha = $commit; status = "completed"; conclusion = "success"; url = "https://github.com/shanecloonan/permawrite/actions/runs/rc-dry-run" }
) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ciMock -Encoding utf8

$soakEvidence = Join-Path $ScriptDir "evidence/soak-restart-windows-30s-slot-20260703T132240Z.txt"
if (Test-Path -LiteralPath $soakEvidence -PathType Leaf) {
    Copy-Item -LiteralPath $soakEvidence -Destination (Join-Path $archiveDir "evidence/soak-restart-windows-30s-slot.txt") -Force
}

function Write-DirectoryChecksumsLocal {
    param([string]$Directory)
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }
    $files = Get-ChildItem -LiteralPath $Directory -File | Where-Object { $_.Name -ne "checksums.sha256" } | Sort-Object Name
    if ($files.Count -eq 0) { return }
    $rows = foreach ($file in $files) {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        "$hash  $($file.Name)"
    }
    Set-Content -LiteralPath (Join-Path $Directory "checksums.sha256") -Value ($rows -join "`n") -Encoding utf8
}

Write-DirectoryChecksumsLocal $archiveDir
Get-ChildItem -LiteralPath $archiveDir -Directory -Recurse | ForEach-Object {
    Write-DirectoryChecksumsLocal $_.FullName
}

$fixtureRoot = Join-Path $ScriptDir "fixtures/participant-rehearsal-evidence-v1"
$auditArgs = @(
    "-NoProfile", "-File", (Join-Path $ScriptDir "release-audit-packet.ps1"),
    "-ReleaseEvidenceJson", $ReleaseEvidenceJson,
    "-SignoffManifest", $signoffManifest,
    "-ArchiveDir", $archiveDir,
    "-Inventory", $inventoryInArchive,
    "-Commit", $commit,
    "-CiMockRuns", $ciMock,
    "-ParticipantRehearsalLog", (Join-Path $fixtureRoot "participant-rehearsal.log"),
    "-ParticipantSupportBundle", (Join-Path $fixtureRoot "support-bundle"),
    "-AllowDryRun",
    "-Json"
)
$auditJson = & powershell @auditArgs
if ($LASTEXITCODE -ne 0) {
    if ($auditJson -is [array]) { $auditJson = $auditJson -join "`n" }
    Write-Output $auditJson
    exit $LASTEXITCODE
}

if ($auditJson -is [array]) { $auditJson = $auditJson -join "`n" }

if (-not $OutputPath) {
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $OutputPath = Join-Path $ScriptDir "evidence/rc-audit-dry-run-$shortCommit-$stamp.json"
}

$auditObject = $auditJson | ConvertFrom-Json
if ($auditObject.decision -ne "go") {
    Write-Output ($auditObject | ConvertTo-Json -Depth 10)
    throw "release-rc-audit-dry-run: audit packet decision=$($auditObject.decision)"
}

$auditText = $auditObject | ConvertTo-Json -Depth 10
Set-Content -LiteralPath $OutputPath -Value $auditText -Encoding utf8
Write-Host "release-rc-audit-dry-run: OK decision=go path=$OutputPath"

if ($Json) {
    Write-Output $auditText
}
