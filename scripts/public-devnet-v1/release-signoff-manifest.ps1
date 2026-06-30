# Build a machine-readable release-candidate sign-off decision manifest.
param(
    [Parameter(Mandatory = $true)][string]$ReleaseEvidenceJson,
    [string]$ArchiveDir = "",
    [string]$Inventory = "",
    [string]$CiMockRuns = "",
    [string]$Commit = "",
    [ValidateSet("go", "no-go")][string]$Decision = "no-go",
    [string]$Operator = "",
    [string]$Reviewer = "",
    [string]$Notes = "",
    [string]$OutputPath = "",
    [switch]$AllowDryRun,
    [switch]$ThreatModelReviewed,
    [switch]$ResidualRisksHaveOwners,
    [switch]$RpcExposureApproved,
    [switch]$BackupsRestoreRehearsed,
    [switch]$HaltRollbackAuthorityAgreed
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
Set-Location $RepoRoot

$issues = New-Object System.Collections.Generic.List[string]
function Add-Issue {
    param([string]$Message)
    $script:issues.Add($Message) | Out-Null
}

function Invoke-ToolJson {
    param([string[]]$ArgumentList)
    $stdout = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-tool-" + [System.Guid]::NewGuid().ToString("N") + ".out")
    $stderr = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-tool-" + [System.Guid]::NewGuid().ToString("N") + ".err")
    try {
        $process = Start-Process -FilePath "powershell" -ArgumentList $ArgumentList -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $outText = ""
        if (Test-Path -LiteralPath $stdout) {
            $rawOut = Get-Content -LiteralPath $stdout -Raw
            if ($null -ne $rawOut) { $outText = [string]$rawOut }
        }
        $errText = ""
        if (Test-Path -LiteralPath $stderr) {
            $rawErr = Get-Content -LiteralPath $stderr -Raw
            if ($null -ne $rawErr) { $errText = [string]$rawErr }
        }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $outText.Trim(); Stderr = $errText.Trim() }
    } finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-ToolText {
    param([string[]]$ArgumentList)
    $result = Invoke-ToolJson -ArgumentList $ArgumentList
    return $result
}

if (-not (Test-Path -LiteralPath $ReleaseEvidenceJson -PathType Leaf)) {
    throw "release-signoff-manifest: missing release evidence JSON $ReleaseEvidenceJson"
}

$evidence = Get-Content -LiteralPath $ReleaseEvidenceJson -Raw | ConvertFrom-Json
if ($evidence.schema_version -ne "release-evidence.v1") {
    Add-Issue "release evidence schema_version is not release-evidence.v1"
}
if (-not $Commit) {
    $Commit = [string]$evidence.commit.head
}
if (-not $Commit) {
    $Commit = (& git rev-parse HEAD).Trim()
}
if ([string]$evidence.commit.head -and [string]$evidence.commit.head -ne $Commit) {
    Add-Issue "release evidence commit does not match requested commit"
}

$ciArgs = @("-NoProfile", "-File", (Join-Path $ScriptDir "release-ci-watch.ps1"), "-Commit", $Commit, "-Json")
if ($CiMockRuns) { $ciArgs += @("-MockRuns", $CiMockRuns) }
$ciResult = Invoke-ToolJson -ArgumentList $ciArgs
$ciObject = $null
if ($ciResult.Stdout) {
    try { $ciObject = $ciResult.Stdout | ConvertFrom-Json } catch { Add-Issue "release-ci-watch JSON output could not be parsed" }
}
if ($ciResult.ExitCode -ne 0) {
    Add-Issue "GitHub CI is not green for the exact commit"
}

$archiveStatus = "not provided"
$archiveMessage = ""
if ($ArchiveDir) {
    $archiveArgs = @("-NoProfile", "-File", (Join-Path $ScriptDir "release-archive-validate.ps1"), "-ArchiveDir", $ArchiveDir)
    if ($AllowDryRun) { $archiveArgs += "-AllowDryRun" }
    $archiveResult = Invoke-ToolText -ArgumentList $archiveArgs
    $archiveStatus = if ($archiveResult.ExitCode -eq 0) { "pass" } else { "fail" }
    $archiveMessage = if ($archiveResult.ExitCode -eq 0) { $archiveResult.Stdout } else { $archiveResult.Stderr }
    if ($archiveResult.ExitCode -ne 0) { Add-Issue "release archive validation failed" }
}

$inventoryStatus = "not provided"
$inventoryMessage = ""
if ($Inventory) {
    $inventoryResult = Invoke-ToolText -ArgumentList @("-NoProfile", "-File", (Join-Path $ScriptDir "artifact-inventory-validate.ps1"), $Inventory)
    $inventoryStatus = if ($inventoryResult.ExitCode -eq 0) { "pass" } else { "fail" }
    $inventoryMessage = if ($inventoryResult.ExitCode -eq 0) { $inventoryResult.Stdout } else { $inventoryResult.Stderr }
    if ($inventoryResult.ExitCode -ne 0) { Add-Issue "artifact inventory validation failed" }
}

$approvalMap = [ordered]@{
    threat_model_reviewed = [bool]$ThreatModelReviewed
    residual_risks_have_named_owners = [bool]$ResidualRisksHaveOwners
    rpc_exposure_approved = [bool]$RpcExposureApproved
    backups_and_restore_rehearsed = [bool]$BackupsRestoreRehearsed
    halt_rollback_authority_agreed = [bool]$HaltRollbackAuthorityAgreed
}

if ($Decision -eq "go") {
    if (-not $Operator) { Add-Issue "operator is required for go decision" }
    if (-not $Reviewer) { Add-Issue "reviewer is required for go decision" }
    foreach ($key in $approvalMap.Keys) {
        if (-not $approvalMap[$key]) { Add-Issue "approval '$key' is required for go decision" }
    }
    if (-not $ArchiveDir) { Add-Issue "archive validation is required for go decision" }
    if (-not $Inventory) { Add-Issue "artifact inventory validation is required for go decision" }
}

$manifest = [pscustomobject]@{
    schema_version = "release-signoff-manifest.v1"
    generated_utc = (Get-Date).ToUniversalTime().ToString("o")
    decision = $Decision
    commit = $Commit
    release_evidence = [pscustomobject]@{
        path = $ReleaseEvidenceJson
        schema_version = $evidence.schema_version
        commit = $evidence.commit.head
    }
    gates = [pscustomobject]@{
        ci = $ciObject
        archive_validation = [pscustomobject]@{ status = $archiveStatus; path = $ArchiveDir; message = $archiveMessage }
        artifact_inventory = [pscustomobject]@{ status = $inventoryStatus; path = $Inventory; message = $inventoryMessage }
    }
    approvals = [pscustomobject]@{
        operator = $Operator
        reviewer = $Reviewer
        threat_model_reviewed = $approvalMap.threat_model_reviewed
        residual_risks_have_named_owners = $approvalMap.residual_risks_have_named_owners
        rpc_exposure_approved = $approvalMap.rpc_exposure_approved
        backups_and_restore_rehearsed = $approvalMap.backups_and_restore_rehearsed
        halt_rollback_authority_agreed = $approvalMap.halt_rollback_authority_agreed
        notes = $Notes
    }
    issues = @($issues)
}

$json = $manifest | ConvertTo-Json -Depth 12
if ($OutputPath) {
    Set-Content -LiteralPath $OutputPath -Value $json -Encoding utf8
    Write-Output "release-signoff-manifest: wrote $OutputPath"
} else {
    Write-Output $json
}

if ($Decision -eq "go" -and $issues.Count -gt 0) {
    exit 1
}
