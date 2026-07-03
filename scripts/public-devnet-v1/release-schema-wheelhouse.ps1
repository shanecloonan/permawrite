# Download hash-pinned release-schema Python wheels for offline strict validation.
param(
    [string]$Output = (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "wheelhouse-release-schema")
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Req = Join-Path $ScriptDir "requirements-release-schema.txt"
$Python = if ($env:PERMAWRITE_RELEASE_SCHEMA_PYTHON) { $env:PERMAWRITE_RELEASE_SCHEMA_PYTHON } else { "python" }

if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    throw "release-schema-wheelhouse: python not found ($Python)"
}

New-Item -ItemType Directory -Force -Path $Output | Out-Null
& $Python -m pip download --disable-pip-version-check --require-hashes `
    -r $Req -d $Output
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$count = (Get-ChildItem -LiteralPath $Output -Filter *.whl -File).Count
Write-Host "release-schema-wheelhouse: PASS output=$Output packages=$count"
