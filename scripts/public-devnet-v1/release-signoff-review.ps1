# Print a release sign-off checklist from a generated support bundle.
param(
    [Parameter(Mandatory = $true)][string]$BundleDir,
    [string]$LaunchNotes = "release-evidence.md"
)
$ErrorActionPreference = "Stop"

function Format-Check {
    param([bool]$Ok)
    if ($Ok) { return "x" }
    return " "
}

function Add-CheckLine {
    param([System.Collections.Generic.List[string]]$Lines, [bool]$Ok, [string]$Text)
    $Lines.Add("- [$(Format-Check $Ok)] $Text") | Out-Null
}

function Test-BundleFile {
    param([string]$Name)
    return (Test-Path (Join-Path $ResolvedBundle $Name))
}

$ResolvedBundle = (Resolve-Path $BundleDir).Path
$manifestPath = Join-Path $ResolvedBundle "manifest.json"
if (-not (Test-Path $manifestPath)) {
    throw "release-signoff-review: missing manifest.json in $ResolvedBundle"
}
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

$evidenceFile = if ($manifest.release_evidence.copied_file) { $manifest.release_evidence.copied_file } else { "release-evidence.json" }
$evidencePath = Join-Path $ResolvedBundle $evidenceFile
$evidenceExists = Test-Path $evidencePath
$evidence = $null
if ($evidenceExists) {
    $evidence = Get-Content $evidencePath -Raw | ConvertFrom-Json
}

$evidenceValid = $evidenceExists -and $evidence.schema_version -eq "release-evidence.v1"
$manifestEvidenceValid = [bool]$manifest.release_evidence.provided -and [bool]$manifest.release_evidence.valid
$commitMatches = $false
if ($evidence -and $manifest.release_evidence.commit_head) {
    $commitMatches = $manifest.release_evidence.commit_head -eq $evidence.commit.head
}
$failedCommands = @($manifest.commands | Where-Object { $_.exit_code -ne 0 })
$coreFiles = @("node-status.json", "uploads-list.json", "operator-pool.json")
$supportFiles = @("wallet-status.json", "wallet-backup-info.json", "uploads-status.json", "operator-artifacts.json", "operator-challenge.json", "operator-inbox-status.json")
$presentSupportFiles = @($supportFiles | Where-Object { Test-BundleFile $_ })

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# Permawrite Release Sign-Off Bundle Review") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("Bundle: ``$ResolvedBundle``") | Out-Null
$lines.Add("Generated UTC: ``$((Get-Date).ToUniversalTime().ToString("o"))``") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("## Required Files") | Out-Null
$lines.Add("") | Out-Null
Add-CheckLine $lines $false "Launch notes include ``$LaunchNotes`` for human review (outside support bundle)."
Add-CheckLine $lines $evidenceValid "``$evidencePath`` exists and uses ``schema_version=release-evidence.v1``."
Add-CheckLine $lines ($manifestEvidenceValid -and $commitMatches) "``$manifestPath`` records valid release evidence and matches the evidence commit."
foreach ($file in $coreFiles) {
    Add-CheckLine $lines (Test-BundleFile $file) "``$(Join-Path $ResolvedBundle $file)`` is present."
}
Add-CheckLine $lines ($failedCommands.Count -eq 0) "``manifest.json`` has no unexplained command failures."
Add-CheckLine $lines ($presentSupportFiles.Count -gt 0) "Wallet/storage support diagnostics are present when the launch claim depends on them."
$lines.Add("") | Out-Null
$lines.Add("## Required Approvals") | Out-Null
$lines.Add("") | Out-Null
Add-CheckLine $lines $false "Release operator confirms commit, stats timestamp, GitHub CI, ignored/nightly smoke, and local CI mirror."
Add-CheckLine $lines $false "Security reviewer confirms pre-audit risk language and named owners for residual risks."
Add-CheckLine $lines $false "RPC/network reviewer confirms RPC exposure controls, P2P reachability, and expected genesis."
Add-CheckLine $lines $false "Storage/permanence reviewer confirms upload, replication/backfill, retrieval, and SPoRA proof rehearsal."
Add-CheckLine $lines $false "Operations reviewer confirms backups, restore rehearsal, rollback/halt authority, incident notes, and watchers."
$lines.Add("") | Out-Null
$lines.Add("## Detected Status") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("- Evidence schema: ``$(if ($evidence) { $evidence.schema_version } else { "missing" })``") | Out-Null
$lines.Add("- Evidence commit: ``$(if ($evidence) { $evidence.commit.head } else { "missing" })``") | Out-Null
$lines.Add("- Manifest evidence commit: ``$(if ($manifest.release_evidence.commit_head) { $manifest.release_evidence.commit_head } else { "missing" })``") | Out-Null
$lines.Add("- RPC endpoint: ``$(if ($evidence) { $evidence.rpc.endpoint } else { "missing" })``") | Out-Null
$lines.Add("- Present wallet/storage files: ``$(if ($presentSupportFiles.Count -gt 0) { $presentSupportFiles -join ", " } else { "none" })``") | Out-Null
$lines.Add("- Command failures: ``$(if ($failedCommands.Count -gt 0) { ($failedCommands | ForEach-Object { "$($_.name)=$($_.exit_code)" }) -join ", " } else { "none" })``") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("Any unchecked required file, approval, unknown evidence field, dirty working tree, or unexplained command failure remains a no-go until a reviewer writes down the exception and names an owner.") | Out-Null

Write-Output ($lines -join "`n")
