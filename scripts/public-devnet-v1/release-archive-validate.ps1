# Validate a staged public release-candidate archive.
param(
    [Parameter(Mandatory = $true)][string]$ArchiveDir,
    [switch]$AllowDryRun
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ArchiveDir -PathType Container)) {
    throw "release-archive-validate: missing archive directory $ArchiveDir"
}

$archiveRoot = (Resolve-Path -LiteralPath $ArchiveDir).Path
$issues = New-Object System.Collections.Generic.List[string]

function Get-ArchiveRelativePath {
    param([string]$Path)
    $resolvedRoot = (Resolve-Path -LiteralPath $archiveRoot).Path
    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $rootUri = [System.Uri]::new(($resolvedRoot.TrimEnd("\", "/") + [System.IO.Path]::DirectorySeparatorChar))
    $pathUri = [System.Uri]::new($resolvedPath)
    return ([System.Uri]::UnescapeDataString($rootUri.MakeRelativeUri($pathUri).ToString()) -replace "/", [System.IO.Path]::DirectorySeparatorChar)
}

function Add-Issue {
    param([string]$Message)
    $script:issues.Add($Message) | Out-Null
}

function Test-PrivateName {
    param([string]$Path)
    $name = Split-Path -Leaf $Path
    if ($name -match "(?i)(wallet|seed|secret|api[-_]?key|private|credential|peers\.json)") {
        Add-Issue "private-looking path is present: $Path"
    }
}

function Require-File {
    param([string]$RelativePath)
    $full = Join-Path $archiveRoot $RelativePath
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Add-Issue "missing required file: $RelativePath"
    }
}

function Test-DirectoryChecksums {
    param([string]$Directory)
    $files = Get-ChildItem -LiteralPath $Directory -File | Where-Object { $_.Name -ne "checksums.sha256" } | Sort-Object Name
    if ($files.Count -eq 0) { return }

    $checksumFile = Join-Path $Directory "checksums.sha256"
    $relativeDir = Get-ArchiveRelativePath $Directory
    if (-not (Test-Path -LiteralPath $checksumFile -PathType Leaf)) {
        Add-Issue "missing checksum manifest: $relativeDir/checksums.sha256"
        return
    }

    $expected = @{}
    foreach ($file in $files) {
        $expected[$file.Name] = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
    }

    $seen = @{}
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $checksumFile) {
        $lineNumber++
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed -notmatch "^(?<hash>[0-9a-fA-F]{64})\s+(?<name>[^\\/]+)$") {
            Add-Issue "invalid checksum line in $relativeDir/checksums.sha256:${lineNumber}"
            continue
        }
        $name = $Matches.name
        $hash = $Matches.hash.ToLowerInvariant()
        if (-not $expected.ContainsKey($name)) {
            Add-Issue "checksum references unknown file: $relativeDir/$name"
            continue
        }
        if ($expected[$name] -ne $hash) {
            Add-Issue "checksum mismatch: $relativeDir/$name"
        }
        $seen[$name] = $true
    }

    foreach ($name in $expected.Keys) {
        if (-not $seen.ContainsKey($name)) {
            Add-Issue "checksum missing file entry: $relativeDir/$name"
        }
    }
}

Get-ChildItem -LiteralPath $archiveRoot -Recurse -Force | ForEach-Object {
    Test-PrivateName -Path (Get-ArchiveRelativePath $_.FullName)
}

foreach ($required in @(
    "README.md",
    "network/genesis.json",
    "network/public_devnet_manifest.json",
    "docs/TESTNET.md",
    "docs/SECURITY.md",
    "docs/PUBLIC_DEVNET_THREAT_MODEL.md",
    "docs/OPERATORS.md",
    "evidence/release-evidence-v1.schema.json",
    "evidence/release-signoff-manifest-v1.schema.json",
    "evidence/release-audit-packet-v1.schema.json"
)) {
    Require-File $required
}

if ($AllowDryRun) {
    Require-File "evidence/release-evidence-v1.sample.json"
    Require-File "evidence/release-signoff-manifest-v1.sample.json"
    Require-File "evidence/release-audit-packet-v1.sample.json"
    if (-not ((Test-Path -LiteralPath (Join-Path $archiveRoot "evidence/release-artifact-inventory.md") -PathType Leaf) -or (Test-Path -LiteralPath (Join-Path $archiveRoot "evidence/release-artifact-inventory-template.md") -PathType Leaf))) {
        Add-Issue "missing dry-run inventory artifact: evidence/release-artifact-inventory.md or evidence/release-artifact-inventory-template.md"
    }
} else {
    foreach ($required in @(
        "evidence/release-evidence.md",
        "evidence/release-evidence.json",
        "evidence/release-artifact-inventory.md",
        "evidence/release-signoff-review.md",
        "evidence/release-signoff-manifest.json",
        "evidence/release-audit-packet.json",
        "support/manifest.json"
    )) {
        Require-File $required
    }
}

Test-DirectoryChecksums -Directory $archiveRoot
Get-ChildItem -LiteralPath $archiveRoot -Directory -Recurse | ForEach-Object {
    Test-DirectoryChecksums -Directory $_.FullName
}

if ($issues.Count -gt 0) {
    $issues | ForEach-Object { [Console]::Error.WriteLine("release-archive-validate: $_") }
    exit 1
}

Write-Output "release-archive-validate: OK"
