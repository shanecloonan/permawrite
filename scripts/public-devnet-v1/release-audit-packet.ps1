# Build a final release-candidate audit packet from all machine-readable gates.
param(
    [Parameter(Mandatory = $true)][string]$ReleaseEvidenceJson,
    [Parameter(Mandatory = $true)][string]$SignoffManifest,
    [Parameter(Mandatory = $true)][string]$ArchiveDir,
    [Parameter(Mandatory = $true)][string]$Inventory,
    [string]$Commit = "",
    [string]$CiMockRuns = "",
    [string]$ParticipantRehearsalLog = "",
    [string]$ParticipantSupportBundle = "",
    [string]$OutputPath = "",
    [switch]$AllowDryRun,
    [switch]$StrictStatsFreshness,
    [switch]$Json
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
Set-Location $RepoRoot

$checks = New-Object System.Collections.Generic.List[object]

function Invoke-Tool {
    param([string]$FilePath, [string[]]$ArgumentList)
    $stdout = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-audit-" + [System.Guid]::NewGuid().ToString("N") + ".out")
    $stderr = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-audit-" + [System.Guid]::NewGuid().ToString("N") + ".err")
    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $rawOut = if (Test-Path -LiteralPath $stdout) { Get-Content -LiteralPath $stdout -Raw } else { "" }
        $rawErr = if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Raw } else { "" }
        $outText = if ($null -eq $rawOut) { "" } else { [string]$rawOut }
        $errText = if ($null -eq $rawErr) { "" } else { [string]$rawErr }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $outText.Trim(); Stderr = $errText.Trim() }
    } finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

function Add-Check {
    param([string]$Name, [string]$Status, [string]$Message)
    $script:checks.Add([pscustomobject]@{ name = $Name; status = $Status; message = $Message }) | Out-Null
}

function Add-ToolCheck {
    param([string]$Name, [string]$FilePath, [string[]]$ArgumentList)
    $result = Invoke-Tool -FilePath $FilePath -ArgumentList $ArgumentList
    $message = if ($result.ExitCode -eq 0) { $result.Stdout } else { ($result.Stderr + "`n" + $result.Stdout).Trim() }
    Add-Check -Name $Name -Status $(if ($result.ExitCode -eq 0) { "pass" } else { "fail" }) -Message $message
}

function Test-SameBundleReference {
    param([string]$ReportedBundle, [string]$ProvidedBundle)
    $reported = $ReportedBundle.Trim().Trim('"')
    $providedResolved = (Resolve-Path -LiteralPath $ProvidedBundle).Path
    if (Test-Path -LiteralPath $reported) {
        $reportedResolved = (Resolve-Path -LiteralPath $reported).Path
        return [StringComparer]::OrdinalIgnoreCase.Equals($reportedResolved, $providedResolved)
    }
    $reportedLeaf = Split-Path -Leaf $reported
    $providedLeaf = Split-Path -Leaf $providedResolved
    return $reportedLeaf -and [StringComparer]::OrdinalIgnoreCase.Equals($reportedLeaf, $providedLeaf)
}

function Add-ParticipantEvidenceCheck {
    param([string]$LogPath, [string]$BundleDir)
    if (-not $LogPath -and -not $BundleDir) { return }
    if (-not $LogPath -or -not $BundleDir) {
        Add-Check -Name "participant rehearsal evidence" -Status "fail" -Message "provide both participant rehearsal log and support bundle directory"
        return
    }
    if (-not (Test-Path -LiteralPath $LogPath -PathType Leaf)) {
        Add-Check -Name "participant rehearsal evidence" -Status "fail" -Message "missing participant rehearsal log $LogPath"
        return
    }
    if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
        Add-Check -Name "participant rehearsal evidence" -Status "fail" -Message "missing participant support bundle directory $BundleDir"
        return
    }
    $logText = Get-Content -LiteralPath $LogPath -Raw
    $passMatch = [regex]::Match($logText, "participant-rehearsal: PASS\s+commitment_hash=(?<commit>[0-9a-fA-F]+)\s+restored_sha256=(?<sha>[0-9a-fA-F]{64})\s+restored_path=(?<restored>\S+)\s+support_bundle=(?<bundle>\S+)")
    if (-not $passMatch.Success) {
        Add-Check -Name "participant rehearsal evidence" -Status "fail" -Message "participant rehearsal log missing final PASS line with commitment_hash, restored_sha256, restored_path, and support_bundle"
        return
    }
    if (-not (Test-SameBundleReference -ReportedBundle $passMatch.Groups["bundle"].Value -ProvidedBundle $BundleDir)) {
        Add-Check -Name "participant rehearsal evidence" -Status "fail" -Message "participant rehearsal PASS support_bundle does not match provided support bundle directory"
        return
    }
    $manifestPath = Join-Path $BundleDir "manifest.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Add-Check -Name "participant rehearsal evidence" -Status "fail" -Message "support bundle is missing manifest.json"
        return
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $commitHash = $passMatch.Groups["commit"].Value.ToLowerInvariant()
    if (-not $manifest.read_only) {
        Add-Check -Name "participant rehearsal evidence" -Status "fail" -Message "support bundle manifest is not marked read_only=true"
        return
    }
    if (([string]$manifest.commit_hash).ToLowerInvariant() -ne $commitHash) {
        Add-Check -Name "participant rehearsal evidence" -Status "fail" -Message "support bundle commit_hash does not match participant rehearsal PASS line"
        return
    }
    $commandNames = @($manifest.commands | ForEach-Object { [string]$_.name })
    foreach ($required in @("node-status", "uploads-list", "operator-pool", "operator-challenge")) {
        if ($commandNames -notcontains $required) {
            Add-Check -Name "participant rehearsal evidence" -Status "fail" -Message "support bundle missing required capture $required"
            return
        }
    }
    Add-Check -Name "participant rehearsal evidence" -Status "pass" -Message "commitment_hash=$commitHash restored_sha256=$($passMatch.Groups["sha"].Value.ToLowerInvariant()) support_bundle=$BundleDir"
}

function Normalize-Stats {
    param([string]$Text)
    return ($Text -replace "(?m)^\*\*Generated \(UTC\):\*\* .+$", "**Generated (UTC):** <normalized>").Trim()
}

if (-not (Test-Path -LiteralPath $ReleaseEvidenceJson -PathType Leaf)) { throw "release-audit-packet: missing release evidence JSON $ReleaseEvidenceJson" }
if (-not (Test-Path -LiteralPath $SignoffManifest -PathType Leaf)) { throw "release-audit-packet: missing sign-off manifest $SignoffManifest" }
if (-not (Test-Path -LiteralPath $ArchiveDir -PathType Container)) { throw "release-audit-packet: missing archive directory $ArchiveDir" }
if (-not (Test-Path -LiteralPath $Inventory -PathType Leaf)) { throw "release-audit-packet: missing inventory $Inventory" }

$evidence = Get-Content -LiteralPath $ReleaseEvidenceJson -Raw | ConvertFrom-Json
if (-not $Commit) { $Commit = [string]$evidence.commit.head }
if (-not $Commit) { $Commit = (& git rev-parse HEAD).Trim() }

Add-ToolCheck -Name "release evidence schema" -FilePath "powershell" -ArgumentList @("-NoProfile", "-File", (Join-Path $ScriptDir "release-json-schema-validate.ps1"), "-Schema", "docs/release-evidence-v1.schema.json", "-Json", $ReleaseEvidenceJson)
Add-ToolCheck -Name "signoff manifest schema" -FilePath "powershell" -ArgumentList @("-NoProfile", "-File", (Join-Path $ScriptDir "release-json-schema-validate.ps1"), "-Schema", "docs/release-signoff-manifest-v1.schema.json", "-Json", $SignoffManifest)
Add-ToolCheck -Name "signoff manifest gates" -FilePath "powershell" -ArgumentList @("-NoProfile", "-File", (Join-Path $ScriptDir "release-signoff-manifest-validate.ps1"), "-Manifest", $SignoffManifest)

$archiveArgs = @("-NoProfile", "-File", (Join-Path $ScriptDir "release-archive-validate.ps1"), "-ArchiveDir", $ArchiveDir)
if ($AllowDryRun) { $archiveArgs += "-AllowDryRun" }
Add-ToolCheck -Name "release archive" -FilePath "powershell" -ArgumentList $archiveArgs
Add-ToolCheck -Name "artifact inventory" -FilePath "powershell" -ArgumentList @("-NoProfile", "-File", (Join-Path $ScriptDir "artifact-inventory-validate.ps1"), $Inventory)

$ciArgs = @("-NoProfile", "-File", (Join-Path $ScriptDir "release-ci-watch.ps1"), "-Commit", $Commit, "-Json")
if ($CiMockRuns) { $ciArgs += @("-MockRuns", $CiMockRuns) }
Add-ToolCheck -Name "exact commit CI" -FilePath "powershell" -ArgumentList $ciArgs
Add-ParticipantEvidenceCheck -LogPath $ParticipantRehearsalLog -BundleDir $ParticipantSupportBundle

$statsPath = Join-Path $RepoRoot "CODEBASE_STATS.md"
if (-not (Test-Path -LiteralPath $statsPath -PathType Leaf)) {
    Add-Check -Name "codebase stats" -Status "fail" -Message "CODEBASE_STATS.md is missing"
} elseif ($StrictStatsFreshness) {
    $currentStats = Get-Content -LiteralPath $statsPath -Raw
    $generatedStats = (& node scripts/codebase-stats.mjs --dry-run) -join "`n"
    if ((Normalize-Stats $currentStats) -eq (Normalize-Stats $generatedStats)) {
        Add-Check -Name "codebase stats" -Status "pass" -Message "CODEBASE_STATS.md matches dry-run output after timestamp normalization"
    } else {
        Add-Check -Name "codebase stats" -Status "fail" -Message "CODEBASE_STATS.md is stale; run node scripts/codebase-stats.mjs in a clean release tree"
    }
} else {
    $statsText = Get-Content -LiteralPath $statsPath -Raw
    if ($statsText -match "\*\*Generated \(UTC\):\*\* (?<ts>.+)") {
        Add-Check -Name "codebase stats" -Status "pass" -Message "CODEBASE_STATS.md generated at $($Matches.ts.Trim())"
    } else {
        Add-Check -Name "codebase stats" -Status "fail" -Message "CODEBASE_STATS.md has no generated timestamp"
    }
}

$failed = @($checks | Where-Object { $_.status -ne "pass" })
$decision = if ($failed.Count -eq 0) { "go" } else { "no-go" }
$checkArray = @($checks.ToArray())
$packet = [pscustomobject]@{
    schema_version = "release-audit-packet.v1"
    generated_utc = (Get-Date).ToUniversalTime().ToString("o")
    commit = $Commit
    decision = $decision
    release_evidence_json = $ReleaseEvidenceJson
    signoff_manifest = $SignoffManifest
    archive_dir = $ArchiveDir
    inventory = $Inventory
    participant_rehearsal_log = if ($ParticipantRehearsalLog) { $ParticipantRehearsalLog } else { $null }
    participant_support_bundle = if ($ParticipantSupportBundle) { $ParticipantSupportBundle } else { $null }
    checks = $checkArray
}

if ($Json) {
    $output = $packet | ConvertTo-Json -Depth 10
} else {
    $rows = @("# Permawrite Release Audit Packet", "", "Commit: $Commit", "Decision: $($packet.decision)", "")
    foreach ($check in $checks) {
        $rows += "- [$($check.status)] $($check.name): $($check.message)"
    }
    $output = $rows -join "`n"
}

if ($OutputPath) {
    Set-Content -LiteralPath $OutputPath -Value $output -Encoding utf8
    Write-Output "release-audit-packet: wrote $OutputPath"
} else {
    Write-Output $output
}

if ($failed.Count -gt 0) { exit 1 }
