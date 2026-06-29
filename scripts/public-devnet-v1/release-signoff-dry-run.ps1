# Exercise release evidence generation, support-bundle validation, and sign-off rendering without a live node.
param(
    [string]$OutputDir = ""
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path

$createdTemp = $false
if (-not $OutputDir) {
    $OutputDir = Join-Path ([System.IO.Path]::GetTempPath()) ("permawrite-release-signoff-" + [System.Guid]::NewGuid().ToString("N"))
    $createdTemp = $true
}
$OutputDir = (New-Item -ItemType Directory -Force -Path $OutputDir).FullName

try {
    $evidencePath = Join-Path $OutputDir "release-evidence.json"
    powershell -NoProfile -File (Join-Path $ScriptDir "release-evidence.ps1") `
        -Json `
        -SkipCiLookup `
        -Operator "dry-run" `
        -Notes "release sign-off dry-run fixture" `
        -OutputPath $evidencePath | Out-Null
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $supportPlan = powershell -NoProfile -File (Join-Path $ScriptDir "support-bundle.ps1") `
        -Rpc "127.0.0.1:18731" `
        -ReleaseEvidence $evidencePath `
        -PlanOnly
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if (-not (($supportPlan -join "`n").Contains("valid release-evidence.v1"))) {
        throw "release-signoff-dry-run: support-bundle did not validate generated release evidence"
    }

    $evidence = Get-Content $evidencePath -Raw | ConvertFrom-Json
    $bundleDir = Join-Path $OutputDir "support-bundle"
    New-Item -ItemType Directory -Force -Path $bundleDir | Out-Null
    Copy-Item $evidencePath (Join-Path $bundleDir "release-evidence.json") -Force
    foreach ($name in @("node-status.json", "uploads-list.json", "operator-pool.json", "wallet-status.json")) {
        Set-Content -Path (Join-Path $bundleDir $name) -Value "{}" -Encoding utf8
    }

    $manifest = [pscustomobject]@{
        release_evidence = [pscustomobject]@{
            provided = $true
            valid = $true
            copied_file = "release-evidence.json"
            commit_head = $evidence.commit.head
        }
        commands = @(
            [pscustomobject]@{ name = "node-status"; exit_code = 0; stdout = "node-status.json"; stderr = $null },
            [pscustomobject]@{ name = "uploads-list"; exit_code = 0; stdout = "uploads-list.json"; stderr = $null },
            [pscustomobject]@{ name = "operator-pool"; exit_code = 0; stdout = "operator-pool.json"; stderr = $null }
        )
    }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $bundleDir "manifest.json") -Encoding utf8

    $review = powershell -NoProfile -File (Join-Path $ScriptDir "release-signoff-review.ps1") -BundleDir $bundleDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $reviewText = $review -join "`n"
    foreach ($required in @("# Permawrite Release Sign-Off Bundle Review", "release-evidence.v1", "Required Approvals", "Command failures: ``none``")) {
        if (-not $reviewText.Contains($required)) {
            throw "release-signoff-dry-run: rendered review missing '$required'"
        }
    }
    $reviewText | Set-Content -Path (Join-Path $OutputDir "release-signoff-review.md") -Encoding utf8

    Write-Host "release-signoff-dry-run: output_dir=$OutputDir"
    Write-Host "release-signoff-dry-run: OK"
} finally {
    if ($createdTemp) {
        Remove-Item -Recurse -Force $OutputDir -ErrorAction SilentlyContinue
    }
}
