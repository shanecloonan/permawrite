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
    (& (Join-Path $PSScriptRoot "resolve-schema-python.ps1")).Trim()
}
& $python $scriptPath --schema $Schema --json $Json
exit $LASTEXITCODE
