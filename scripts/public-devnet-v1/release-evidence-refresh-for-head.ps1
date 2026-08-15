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

& powershell -NoProfile -File (Join-Path $ScriptDir "release-json-schema-validate.ps1") `
    -Schema (Join-Path $RepoRoot "docs/release-evidence-v1.schema.json") `
    -Json $jsonPath | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$evidenceObject = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
$ciOk = ($evidenceObject.ci.status -eq "completed" -and $evidenceObject.ci.conclusion -eq "success")
$nightlyOk = ($evidenceObject.nightly.status -eq "completed" -and $evidenceObject.nightly.conclusion -eq "success")
$holes = ($evidenceObject.economy.subsidy_to_treasury_bps -eq 0) -or ($evidenceObject.economy.min_storage_operator_bond -eq 0)
if ($holes -ne [bool]$evidenceObject.economy.path_a_experimental) {
    throw "release-evidence-refresh-for-head: path_a_experimental=$($evidenceObject.economy.path_a_experimental) does not match subsidy_bps=$($evidenceObject.economy.subsidy_to_treasury_bps) min_storage_operator_bond=$($evidenceObject.economy.min_storage_operator_bond)"
}
if ((-not $ciOk -or -not $nightlyOk) -and -not $AllowPendingCi) {
    throw "release-evidence-refresh-for-head: GitHub CI or Nightly is not green for $head (ci=$($evidenceObject.ci.status)/$($evidenceObject.ci.conclusion) nightly=$($evidenceObject.nightly.status)/$($evidenceObject.nightly.conclusion)). Re-run with -AllowPendingCi to record pending runs anyway."
}

Write-Host "release-evidence-refresh-for-head: OK json=$jsonPath md=$mdPath ci_status=$($evidenceObject.ci.status) ci_conclusion=$($evidenceObject.ci.conclusion) nightly_status=$($evidenceObject.nightly.status) nightly_conclusion=$($evidenceObject.nightly.conclusion)"

if ($RunRcAuditDryRun) {
    $rcOutput = Join-Path $env:TEMP ("permawrite-rc-audit-refresh-" + [Guid]::NewGuid().ToString("N") + ".json")
    & powershell -NoProfile -File (Join-Path $ScriptDir "release-rc-audit-dry-run.ps1") -ReleaseEvidenceJson $jsonPath -OutputPath $rcOutput -Json | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $rcObject = Get-Content -LiteralPath $rcOutput -Raw | ConvertFrom-Json
    Remove-Item -Force $rcOutput -ErrorAction SilentlyContinue
    $holes = ($evidenceObject.economy.subsidy_to_treasury_bps -eq 0) -or ($evidenceObject.economy.min_storage_operator_bond -eq 0) -or [bool]$evidenceObject.economy.path_a_experimental
    $economyCheck = @($rcObject.checks | Where-Object { $_.name -eq "path_a_economy" }) | Select-Object -First 1
    if ($holes) {
        if ($rcObject.decision -ne "no-go" -or -not $economyCheck -or $economyCheck.status -ne "fail") {
            throw "release-evidence-refresh-for-head: Path A holes must force RC decision=no-go via path_a_economy (decision=$($rcObject.decision))"
        }
    } elseif ($rcObject.decision -ne "go") {
        throw "release-evidence-refresh-for-head: RC audit dry-run decision=$($rcObject.decision)"
    }
    Write-Host "release-evidence-refresh-for-head: RC audit dry-run decision=$($rcObject.decision)"
}