# Dispatch release-candidate validation workflows on GitHub Actions (requires gh auth).
param(
    [switch]$Nightly,
    [switch]$LinuxSoakAudit,
    [switch]$All,
    [string]$Ref = "main",
    [string]$SlotMs = "30000",
    [string]$DurationMinutes = "35",
    [string]$MinFinalHeight = "10"
)
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $RepoRoot

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "dispatch-rc-workflows: install GitHub CLI (gh) and run 'gh auth login'"
}

$auth = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "dispatch-rc-workflows: gh not authenticated. Run: gh auth login"
}

$dispatchNightly = $Nightly -or $All
$dispatchSoak = $LinuxSoakAudit -or $All
if (-not $dispatchNightly -and -not $dispatchSoak) {
  $dispatchNightly = $true
  $dispatchSoak = $true
}

if ($dispatchNightly) {
    Write-Host "dispatch-rc-workflows: triggering Nightly on ref=$Ref"
    gh workflow run nightly.yml --ref $Ref
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

if ($dispatchSoak) {
    Write-Host "dispatch-rc-workflows: triggering Linux Soak Audit on ref=$Ref (SLOT_MS=$SlotMs duration=${DurationMinutes}m min_height=$MinFinalHeight)"
    gh workflow run linux-soak-audit.yml --ref $Ref `
        -f slot_ms=$SlotMs `
        -f duration_minutes=$DurationMinutes `
        -f min_final_height=$MinFinalHeight
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "dispatch-rc-workflows: OK — monitor https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/actions"
