# Validate participant rehearsal smoke policy in CI automation files.
param(
    [string[]]$Path
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path

$PlanOnlyRequired = @(
    (Join-Path $RepoRoot ".github/workflows/ci.yml"),
    (Join-Path $RepoRoot "scripts/ci-check.sh"),
    (Join-Path $RepoRoot "scripts/ci-check.ps1")
)
$RealRunAllowed = @(
    (Join-Path $RepoRoot ".github/workflows/nightly.yml"),
    (Join-Path $RepoRoot "scripts/ci-ignored.sh"),
    (Join-Path $RepoRoot "scripts/ci-ignored.ps1")
)
$RealRunAllowedNames = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]($RealRunAllowed | ForEach-Object { Split-Path -Leaf $_ }),
    [StringComparer]::OrdinalIgnoreCase
)
$AllowMarkers = @(
    "--plan-only",
    "-PlanOnly",
    "participant-rehearsal.log",
    "participant-rehearsal-bad-bundle.log",
    "--participant-rehearsal-log",
    "-ParticipantRehearsalLog"
)
$SmokeScriptRe = [regex]"participant-rehearsal-smoke\.(?:sh|ps1)"
$RehearsalScriptRe = [regex]"participant-rehearsal\.(?:sh|ps1)"

function Test-AllowedInvocation {
    param([string]$Line)
    foreach ($marker in $AllowMarkers) {
        if ($Line.Contains($marker)) { return $true }
    }
    return $false
}

function Get-PolicyIssues {
    param([string]$FilePath)
    $issues = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        $issues.Add("missing policy scan file: $FilePath") | Out-Null
        return $issues
    }

    $leaf = Split-Path -Leaf $FilePath
    $lineno = 0
    foreach ($line in Get-Content -LiteralPath $FilePath) {
        $lineno++
        $stripped = $line.Trim()
        if (-not $stripped -or $stripped.StartsWith("#")) { continue }
        if (-not ($SmokeScriptRe.IsMatch($line) -or $RehearsalScriptRe.IsMatch($line))) { continue }
        if ($RealRunAllowedNames.Contains($leaf)) { continue }
        if (-not (Test-AllowedInvocation $line)) {
            $issues.Add(
                "${FilePath}:${lineno}: participant rehearsal automation must stay plan-only in default CI until mesh lifetime is stable: $stripped"
            ) | Out-Null
        }
    }
    return $issues
}

$scanPaths = if ($Path -and $Path.Count -gt 0) { $Path } else { $PlanOnlyRequired + $RealRunAllowed }
$allIssues = New-Object System.Collections.Generic.List[string]
foreach ($scanPath in $scanPaths) {
    foreach ($issue in (Get-PolicyIssues $scanPath)) {
        $allIssues.Add($issue) | Out-Null
    }
}

if ($allIssues.Count -gt 0) {
    foreach ($issue in $allIssues) {
        Write-Error "release-participant-smoke-policy-check: $issue"
    }
    exit 1
}

Write-Output "release-participant-smoke-policy-check: OK"
