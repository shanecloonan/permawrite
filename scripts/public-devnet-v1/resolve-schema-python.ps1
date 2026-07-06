# Resolve a Python executable for release-schema validation (Windows Scripts/ vs Unix bin/).
param(
    [string]$VenvRoot = ""
)
$ErrorActionPreference = "Stop"

function Normalize-ExecutablePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-VenvPython {
    param([Parameter(Mandatory = $true)][string]$Root)
    $candidates = @(
        (Join-Path $Root "Scripts\python.exe"),
        (Join-Path $Root "bin\python.exe"),
        (Join-Path $Root "bin\python")
    )
    foreach ($candidate in $candidates) {
        $resolved = Normalize-ExecutablePath -Path $candidate
        if ($resolved) {
            return $resolved
        }
    }
    return $null
}

if ($env:PERMAWRITE_RELEASE_SCHEMA_PYTHON) {
    $fromEnv = $env:PERMAWRITE_RELEASE_SCHEMA_PYTHON.Trim()
    # Ignore stale relative paths left in the parent shell; only trust rooted executables.
    if ([System.IO.Path]::IsPathRooted($fromEnv)) {
        $resolvedEnv = Normalize-ExecutablePath -Path $fromEnv
        if ($resolvedEnv) {
            Write-Output $resolvedEnv
            exit 0
        }
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not $VenvRoot) {
    $VenvRoot = Join-Path $repoRoot ".permawrite-ci-venv"
} elseif (-not [System.IO.Path]::IsPathRooted($VenvRoot)) {
    $VenvRoot = Join-Path $repoRoot $VenvRoot
}

if (Test-Path -LiteralPath $VenvRoot -PathType Container) {
    $venvPython = Resolve-VenvPython -Root $VenvRoot
    if ($venvPython) {
        Write-Output $venvPython
        exit 0
    }
}

Write-Output "python"
