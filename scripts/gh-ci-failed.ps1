# Print failed logs from the latest (or given) GitHub Actions CI run.
# Usage: .\scripts\gh-ci-failed.ps1 [run-id]
param([string]$RunId)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Error "gh CLI not found. Install: https://cli.github.com/"
}

if (-not $RunId) {
    $RunId = (gh run list --workflow CI --limit 1 --json databaseId --jq ".[0].databaseId")
    Write-Host "Latest CI run: $RunId"
}

gh run view $RunId --log-failed
