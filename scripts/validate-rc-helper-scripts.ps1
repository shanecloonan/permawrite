# Fail closed on UTF-16 or syntactically invalid RC helpers, ci-check entrypoints, and agent boards (M2.5.24-M2.5.28).
param()
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot
$devnetDir = Join-Path $repoRoot "scripts\public-devnet-v1"

function Test-Utf8TextFile {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { return "UTF-16 BOM $Path" }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { return "UTF-16 BOM $Path" }
    $sampleLen = [Math]::Min(63, [Math]::Max(0, $bytes.Length - 1))
    if ($sampleLen -ge 0) {
        $nullCount = 0
        for ($i = 0; $i -le $sampleLen; $i++) {
            if ($bytes[$i] -eq 0) { $nullCount++ }
        }
        if ($nullCount -ge 3) { return "null bytes $Path" }
    }
    return $null
}

$failed = @()
$psCount = 0
$shCount = 0

Get-ChildItem -Path $devnetDir -Filter "*.ps1" -File | ForEach-Object {
    $psCount++
    $issue = Test-Utf8TextFile $_.FullName
    if ($issue) {
        $failed += $issue
        return
    }
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        $failed += "PowerShell parse $($_.Name): $($errors[0].Message)"
    }
}

Get-ChildItem -Path $devnetDir -Filter "*.sh" -File | ForEach-Object {
    $shCount++
    $issue = Test-Utf8TextFile $_.FullName
    if ($issue) { $failed += $issue }
}

$bash = $null
foreach ($candidate in @(
        "C:\msys64\usr\bin\bash.exe",
        "C:\Program Files\Git\bin\bash.exe",
        "bash"
    )) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $bash = $candidate
        break
    }
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) {
        $bash = $cmd.Source
        break
    }
}

if ($bash) {
    Get-ChildItem -Path $devnetDir -Filter "*.sh" -File | ForEach-Object {
        & $bash -n $_.FullName
        if ($LASTEXITCODE -ne 0) {
            $failed += "bash -n $($_.Name)"
        }
    }
}

$requiredScripts = @(
    "import-linux-soak-artifact.ps1",
    "import-linux-soak-artifact.sh",
    "release-participant-smoke-policy-check.ps1",
    "release-participant-smoke-policy-check.sh",
    "release-rc-audit-dry-run.ps1",
    "dispatch-rc-workflows.ps1"
)
foreach ($name in $requiredScripts) {
    $path = Join-Path $devnetDir $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $failed += "missing RC helper $name"
    }
}

foreach ($rel in @("AGENTS.md", "docs\AGENTS.md", "3agent.md", "docs\STORAGE_ACCESSIBILITY.md")) {
    $path = Join-Path $repoRoot $rel
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $failed += "missing coordination/doc file $rel"
        continue
    }
    $issue = Test-Utf8TextFile $path
    if ($issue) { $failed += $issue }
}

$entrypointScripts = @(
    (Join-Path $repoRoot "scripts\validate-rc-helper-scripts.ps1"),
    (Join-Path $repoRoot "scripts\validate-rc-helper-scripts.sh"),
    (Join-Path $repoRoot "scripts\validate-workflow-encoding.ps1"),
    (Join-Path $repoRoot "scripts\validate-workflow-encoding.sh"),
    (Join-Path $repoRoot "scripts\ci-check.ps1"),
    (Join-Path $repoRoot "scripts\ci-check.sh")
)
foreach ($path in $entrypointScripts) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $failed += "missing ci entrypoint $path"
        continue
    }
    $issue = Test-Utf8TextFile $path
    if ($issue) { $failed += $issue }
}

$ciCheckPs1 = Join-Path $repoRoot "scripts\ci-check.ps1"
if (Test-Path -LiteralPath $ciCheckPs1 -PathType Leaf) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($ciCheckPs1, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        $failed += "PowerShell parse ci-check.ps1: $($errors[0].Message)"
    }
}
if ($failed.Count -gt 0) {
    Write-Host "validate-rc-helper-scripts: FAIL"
    $failed | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host "validate-rc-helper-scripts: OK ($psCount devnet ps1, $shCount devnet sh, $($entrypointScripts.Count) ci entrypoints, 4 boards/docs; bash=$([bool]$bash))"
