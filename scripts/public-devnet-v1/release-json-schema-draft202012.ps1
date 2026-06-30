# Validate release JSON artifacts with pinned jsonschema Draft 2020-12.
param(
    [Parameter(Mandatory = $true)][string]$Schema,
    [Parameter(Mandatory = $true)][string]$Json
)
$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $PSScriptRoot "release-json-schema-draft202012.py"
$python = if ($env:PERMAWRITE_RELEASE_SCHEMA_PYTHON) { $env:PERMAWRITE_RELEASE_SCHEMA_PYTHON } else { "python" }
& $python $scriptPath --schema $Schema --json $Json
exit $LASTEXITCODE
