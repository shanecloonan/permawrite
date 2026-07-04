# Write release-evidence JSON/Markdown for the current HEAD under evidence/.
param(
    [string]$Notes = "",
    [string]$Operator = "",
    [string]$OutputDir = "",
    [switch]$AllowPendingCi,
    [switch]$RunRcAuditDryRun
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
Set-Location $RepoRoot

$head = (& git rev-parse HEAD).Trim()
$shortCommit = (& git rev-parse --short HEAD).Trim()
if (-not $OutputDir) {
    $OutputDir = Join-Path $ScriptDir "evidence"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$jsonPath = Join-Path $OutputDir "release-evidence-$shortCommit.json"
$mdPath = Join-Path $OutputDir "release-evidence-$shortCommit.md"

$commonArgs = @(
    "-NoProfile",
    "-File",
    (Join-Path $ScriptDir "release-evidence.ps1")
)
if ($Operator) {
    $commonArgs += @("-Operator", $Operator)
}
if ($Notes) {
    $commonArgs += @("-Notes", $Notes)
}

& powershell @commonArgs -Json -OutputPath $jsonPath | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& powershell @commonArgs -OutputPath $mdPath | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$evidenceObject = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
$ciOk = ($evidenceObject.ci.status -eq "completed" -and $evidenceObject.ci.conclusion -eq "success")
if (-not $ciOk -and -not $AllowPendingCi) {
    throw "release-evidence-refresh-for-head: GitHub CI is not green for $head (status=$($evidenceObject.ci.status) conclusion=$($evidenceObject.ci.conclusion)). Re-run with -AllowPendingCi to record pending CI anyway."
}

Write-Host "release-evidence-refresh-for-head: OK json=$jsonPath md=$mdPath ci_status=$($evidenceObject.ci.status) ci_conclusion=$($evidenceObject.ci.conclusion)"

if ($RunRcAuditDryRun) {
    $rcOutput = Join-Path $env:TEMP ("permawrite-rc-audit-refresh-" + [Guid]::NewGuid().ToString("N") + ".json")
    & powershell -NoProfile -File (Join-Path $ScriptDir "release-rc-audit-dry-run.ps1") -ReleaseEvidenceJson $jsonPath -OutputPath $rcOutput -Json | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $rcObject = Get-Content -LiteralPath $rcOutput -Raw | ConvertFrom-Json
    Remove-Item -Force $rcOutput -ErrorAction SilentlyContinue
    if ($rcObject.decision -ne "go") {
        throw "release-evidence-refresh-for-head: RC audit dry-run decision=$($rcObject.decision)"
    }
    Write-Host "release-evidence-refresh-for-head: RC audit dry-run decision=go"
}