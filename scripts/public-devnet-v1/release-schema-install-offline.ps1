# Install hash-pinned release-schema Python deps from a local wheelhouse (no PyPI).
param(
    [string]$Wheelhouse = (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "wheelhouse-release-schema")
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Req = Join-Path $ScriptDir "requirements-release-schema.txt"
$Python = if ($env:PERMAWRITE_RELEASE_SCHEMA_PYTHON) { $env:PERMAWRITE_RELEASE_SCHEMA_PYTHON } else { "python" }

if (-not (Test-Path -LiteralPath $Wheelhouse -PathType Container)) {
    throw "release-schema-install-offline: missing wheelhouse at $Wheelhouse"
}

& $Python -m pip install --disable-pip-version-check --no-index `
    --find-links $Wheelhouse --require-hashes -r $Req
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $Python -c "import importlib.metadata; assert importlib.metadata.version('jsonschema') == '4.17.3'"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "release-schema-install-offline: PASS wheelhouse=$Wheelhouse jsonschema=4.17.3"
