# Fail if GitHub Actions workflow YAML or shell scripts are UTF-16 (GitHub/bash cannot parse them).
param(
    [string]$WorkflowDir = ""
)
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..")).Path
if (-not $WorkflowDir) {
    $WorkflowDir = Join-Path $repoRoot ".github\workflows"
}
$WorkflowDir = (Resolve-Path $WorkflowDir).Path

function Test-Utf8TextFile {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $sample = $bytes[0..([Math]::Min(63, $bytes.Length - 1))]
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { return "UTF-16 BOM $Path" }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { return "UTF-16 BOM $Path" }
    $nullCount = @($sample | Where-Object { $_ -eq 0 }).Count
    if ($nullCount -ge 3) { return "null bytes $Path" }
    return $null
}

$failed = @()
Get-ChildItem -Path $WorkflowDir -Filter "*.yml" -File | ForEach-Object {
    $issue = Test-Utf8TextFile $_.FullName
    if ($issue) { $failed += $issue }
}
Get-ChildItem -Path (Join-Path $repoRoot "scripts") -Filter "*.sh" -Recurse -File | ForEach-Object {
    $issue = Test-Utf8TextFile $_.FullName
    if ($issue) { $failed += $issue }
}
foreach ($rel in @(
        ".gitattributes",
        "scripts/validate-rc-helper-scripts.ps1",
        "scripts/validate-rc-helper-scripts.sh",
        "AGENTS.md",
        "docs/AGENTS.md",
        "3agent.md",
        "docs/STORAGE_ACCESSIBILITY.md"
    )) {
    $path = Join-Path $repoRoot $rel
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $issue = Test-Utf8TextFile $path
        if ($issue) { $failed += $issue }
    }
}

if ($failed.Count -gt 0) {
    Write-Host "validate-workflow-encoding: FAIL"
    $failed | ForEach-Object { Write-Host "  $_" }
    exit 1
}

$workflowCount = (Get-ChildItem -Path $WorkflowDir -Filter "*.yml" -File).Count
$scriptCount = (Get-ChildItem -Path (Join-Path $repoRoot "scripts") -Filter "*.sh" -Recurse -File).Count
Write-Host "validate-workflow-encoding: OK ($workflowCount workflow files, $scriptCount shell scripts UTF-8)"
