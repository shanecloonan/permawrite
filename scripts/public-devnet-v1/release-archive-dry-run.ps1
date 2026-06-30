# Stage public release-candidate archive artifacts without secrets.
param(
    [string]$OutputDir,
    [switch]$PlanOnly,
    [switch]$IncludeBinaries,
    [string]$ReleaseEvidenceMarkdown,
    [string]$ReleaseEvidenceJson,
    [string]$SupportBundle,
    [string]$SignoffReview,
    [string]$SignoffManifest,
    [string]$Inventory
)
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RepoRoot

function Invoke-GitText {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $output = & git @Args 2>$null
    if ($LASTEXITCODE -ne 0) { return "unknown" }
    return (($output -join "`n").Trim())
}

function Test-PublicSource {
    param(
        [string]$Path,
        [switch]$AllowPublicGenesis
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "release-archive-dry-run: missing source $Path"
    }
    $name = Split-Path -Leaf $Path
    $safeGenesis = $AllowPublicGenesis -and $name -eq "public_devnet_v1.json"
    if (-not $safeGenesis -and $name -match "(?i)(wallet|seed|secret|api[-_]?key|private|credential|peers\.json)") {
        throw "release-archive-dry-run: refusing private-looking source $Path"
    }
}

function Copy-PublicFile {
    param(
        [string]$Source,
        [string]$Destination,
        [switch]$AllowPublicGenesis
    )
    Test-PublicSource -Path $Source -AllowPublicGenesis:$AllowPublicGenesis
    if ($PlanOnly) {
        Write-Output "PLAN copy $Source -> $Destination"
        return
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Write-DirectoryChecksums {
    param([string]$Directory)
    if ($PlanOnly -or -not (Test-Path -LiteralPath $Directory -PathType Container)) {
        return
    }
    $files = Get-ChildItem -LiteralPath $Directory -File | Where-Object { $_.Name -ne "checksums.sha256" } | Sort-Object Name
    if ($files.Count -eq 0) { return }
    $rows = foreach ($file in $files) {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        "$hash  $($file.Name)"
    }
    Set-Content -LiteralPath (Join-Path $Directory "checksums.sha256") -Value ($rows -join "`n") -Encoding utf8
}

function Write-TreeChecksums {
    param([string]$Directory)
    if ($PlanOnly -or -not (Test-Path -LiteralPath $Directory -PathType Container)) {
        return
    }
    Write-DirectoryChecksums -Directory $Directory
    Get-ChildItem -LiteralPath $Directory -Directory -Recurse | ForEach-Object {
        Write-DirectoryChecksums -Directory $_.FullName
    }
}

$shortCommit = Invoke-GitText "rev-parse" "--short" "HEAD"
if (-not $OutputDir) {
    $OutputDir = Join-Path ([System.IO.Path]::GetTempPath()) "permawrite-release-archive-dry-run-$shortCommit"
}
$ArchiveRoot = Join-Path $OutputDir "permawrite-public-devnet-dry-run-$shortCommit"

Write-Output "release-archive-dry-run: archive=$ArchiveRoot"
Write-Output "release-archive-dry-run: public-only staging; private wallet, seed, API-key, credential, and peers.json sources are refused"

$entries = @(
    @{ Source = "mfn-node/testdata/public_devnet_v1.json"; Destination = "network/genesis.json"; AllowPublicGenesis = $true },
    @{ Source = "mfn-node/testdata/public_devnet_v1.manifest.json"; Destination = "network/public_devnet_manifest.json" },
    @{ Source = "docs/TESTNET.md"; Destination = "docs/TESTNET.md" },
    @{ Source = "SECURITY.md"; Destination = "docs/SECURITY.md" },
    @{ Source = "docs/PUBLIC_DEVNET_THREAT_MODEL.md"; Destination = "docs/PUBLIC_DEVNET_THREAT_MODEL.md" },
    @{ Source = "scripts/public-devnet-v1/OPERATORS.md"; Destination = "docs/OPERATORS.md" },
    @{ Source = "docs/release-evidence-v1.schema.json"; Destination = "evidence/release-evidence-v1.schema.json" },
    @{ Source = "docs/release-evidence-v1.sample.json"; Destination = "evidence/release-evidence-v1.sample.json" }
)

if ($Inventory) {
    $entries += @{ Source = $Inventory; Destination = "evidence/release-artifact-inventory.md" }
} else {
    $entries += @{ Source = "docs/RELEASE_ARTIFACT_INVENTORY_TEMPLATE.md"; Destination = "evidence/release-artifact-inventory-template.md" }
}
if ($ReleaseEvidenceMarkdown) {
    $entries += @{ Source = $ReleaseEvidenceMarkdown; Destination = "evidence/release-evidence.md" }
}
if ($ReleaseEvidenceJson) {
    $entries += @{ Source = $ReleaseEvidenceJson; Destination = "evidence/release-evidence.json" }
}
if ($SignoffReview) {
    $entries += @{ Source = $SignoffReview; Destination = "evidence/release-signoff-review.md" }
}
if ($SignoffManifest) {
    $entries += @{ Source = $SignoffManifest; Destination = "evidence/release-signoff-manifest.json" }
}

if ($IncludeBinaries) {
    $binaryDir = if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) { "binaries/windows-x86_64" } else { "binaries/local" }
    foreach ($binary in @("mfnd", "mfn-cli", "mfn-storage-operator")) {
        $candidate = Join-Path "target/release" $binary
        if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
            $candidate = "$candidate.exe"
        }
        $entries += @{ Source = $candidate; Destination = "$binaryDir/$(Split-Path -Leaf $candidate)" }
    }
}

foreach ($entry in $entries) {
    Copy-PublicFile -Source $entry.Source -Destination (Join-Path $ArchiveRoot $entry.Destination) -AllowPublicGenesis:([bool]$entry.AllowPublicGenesis)
}

if ($SupportBundle) {
    Test-PublicSource -Path $SupportBundle
    if (Test-Path -LiteralPath $SupportBundle -PathType Container) {
        $manifest = Join-Path $SupportBundle "manifest.json"
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
            throw "release-archive-dry-run: support bundle directory is missing manifest.json"
        }
        Copy-PublicFile -Source $manifest -Destination (Join-Path $ArchiveRoot "support/manifest.json")
        if (-not $PlanOnly) {
            Set-Content -LiteralPath (Join-Path $ArchiveRoot "support/support-bundle-source.txt") -Value "Support bundle directory source was not copied wholesale. Review, redact, compress, and place the approved public archive at support/support-bundle.zip." -Encoding utf8
        } else {
            Write-Output "PLAN write support/support-bundle-source.txt"
        }
    } else {
        Copy-PublicFile -Source $SupportBundle -Destination (Join-Path $ArchiveRoot "support/support-bundle$(Split-Path -Leaf $SupportBundle | ForEach-Object { [System.IO.Path]::GetExtension($_) })")
    }
}

if (-not $PlanOnly) {
    New-Item -ItemType Directory -Force -Path $ArchiveRoot | Out-Null
    $readme = @"
# Permawrite Public-Devnet Release Archive Dry Run

Commit: $shortCommit

This archive was assembled by ``release-archive-dry-run.ps1`` from public release artifacts only. Treat it as a staging rehearsal until reviewers fill out the artifact inventory, attach release evidence, and explicitly approve any support-bundle archive.

Do not add wallet seeds, validator private seeds, RPC API keys, private ``peers.json``, host credentials, or private operator notes to this directory.
"@
    Set-Content -LiteralPath (Join-Path $ArchiveRoot "README.md") -Value $readme -Encoding utf8
    Write-TreeChecksums -Directory $ArchiveRoot
    Write-Output "release-archive-dry-run: OK path=$ArchiveRoot"
} else {
    Write-Output "release-archive-dry-run: PLAN OK"
}
