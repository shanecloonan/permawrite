# M2.5.39: remove gitignored local debris only (never tracked paths).
param(
    [switch]$WhatIf
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

$cleanArgs = @("-f", "-d", "-X")
if ($WhatIf) {
    $cleanArgs = @("-n", "-d", "-X")
}

Write-Host "purge-repo-debris: git clean $($cleanArgs -join ' ')"
& git clean @cleanArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
