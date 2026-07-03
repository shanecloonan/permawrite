# Fail if GitHub Actions workflow YAML is UTF-16 (GitHub cannot parse it).
param(
    [string]$WorkflowDir = ""
)
$ErrorActionPreference = "Stop"

if (-not $WorkflowDir) {
    $WorkflowDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..\.github\workflows"
}
$WorkflowDir = (Resolve-Path $WorkflowDir).Path

function Test-WorkflowUtf8 {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { return $false }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { return $false }
    $nullCount = 0
    $checkLen = [Math]::Min($bytes.Length, 64)
    for ($i = 0; $i -lt $checkLen; $i++) {
        if ($bytes[$i] -eq 0) { $nullCount++ }
    }
    if ($nullCount -ge 3) { return $false }
    return $true
}

$failed = @()
Get-ChildItem -Path $WorkflowDir -Filter "*.yml" -File | ForEach-Object {
    if (-not (Test-WorkflowUtf8 $_.FullName)) { $failed += $_.FullName }
}

if ($failed.Count -gt 0) {
    Write-Host "validate-workflow-encoding: FAIL UTF-16 or null-byte workflow YAML detected:"
    $failed | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host "validate-workflow-encoding: OK ($((Get-ChildItem $WorkflowDir -Filter '*.yml').Count) workflow files UTF-8)"
