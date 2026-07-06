# Resolve a Python executable for release-schema validation (Windows Scripts/ vs Unix bin/).
param(
    [string]$VenvRoot = ""
)
$ErrorActionPreference = "Stop"

function Resolve-VenvPython {
    param([Parameter(Mandatory = $true)][string]$Root)
    $candidates = @(
        (Join-Path $Root "Scripts\python.exe"),
        (Join-Path $Root "bin\python.exe"),
        (Join-Path $Root "bin\python")
    )
    return $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}

if ($env:PERMAWRITE_RELEASE_SCHEMA_PYTHON) {
    $fromEnv = $env:PERMAWRITE_RELEASE_SCHEMA_PYTHON
    if (Test-Path -LiteralPath $fromEnv -PathType Leaf) {
        Write-Output $fromEnv
        exit 0
    }
}

if (-not $VenvRoot) {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $VenvRoot = Join-Path $repoRoot ".permawrite-ci-venv"
}

if (Test-Path -LiteralPath $VenvRoot -PathType Container) {
    $venvPython = Resolve-VenvPython -Root $VenvRoot
    if ($venvPython) {
        Write-Output $venvPython
        exit 0
    }
}

Write-Output "python"
