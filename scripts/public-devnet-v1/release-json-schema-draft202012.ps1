# Validate release JSON artifacts with pinned jsonschema Draft 2020-12.
param(
    [Parameter(Mandatory = $true)][string]$Schema,
    [Parameter(Mandatory = $true)][string]$Json,
    [string]$Python = ""
)
$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $PSScriptRoot "release-json-schema-draft202012.py"
$python = if ($Python) {
    $Python
} else {
    $resolver = Join-Path $PSScriptRoot "resolve-schema-python.ps1"
    if (Test-Path -LiteralPath $resolver -PathType Leaf) {
        (& powershell -NoProfile -File $resolver).Trim()
    } elseif ($env:PERMAWRITE_RELEASE_SCHEMA_PYTHON) {
        $env:PERMAWRITE_RELEASE_SCHEMA_PYTHON.Trim()
    } else {
        "python"
    }
}
& $python $scriptPath --schema $Schema --json $Json
exit $LASTEXITCODE
