# Fail if GitHub Actions workflow YAML is UTF-16 (GitHub cannot parse it).
param(
    [string]$WorkflowDir = ""
)
$ErrorActionPreference = "Stop"

if (-not $WorkflowDir) {
    $WorkflowDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "..\.github\workflows"
}
$WorkflowDir = (Resolve-Path $WorkflowDir).Path

$failed = @()
Get-ChildItem -Path $WorkflowDir -Filter "*.yml" -File | ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    $sample = $bytes[0..([Math]::Min(63, $bytes.Length - 1))]
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { $failed += "UTF-16 BOM $($_.FullName)"; return }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { $failed += "UTF-16 BOM $($_.FullName)"; return }
    $nullCount = @($sample | Where-Object { $_ -eq 0 }).Count
    if ($nullCount -ge 3) { $failed += "null bytes $($_.FullName)" }
}

if ($failed.Count -gt 0) {
    Write-Host "validate-workflow-encoding: FAIL"
    $failed | ForEach-Object { Write-Host "  $_" }
    exit 1
}

$count = (Get-ChildItem -Path $WorkflowDir -Filter "*.yml" -File).Count
Write-Host "validate-workflow-encoding: OK ($count workflow files UTF-8)"
