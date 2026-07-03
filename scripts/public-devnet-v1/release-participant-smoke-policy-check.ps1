# Validate participant rehearsal smoke policy in CI automation files.
$ErrorActionPreference = "Stop"

$python = if ($env:PERMAWRITE_RELEASE_SCHEMA_PYTHON) { $env:PERMAWRITE_RELEASE_SCHEMA_PYTHON } else { "python" }
& $python (Join-Path $PSScriptRoot "release-participant-smoke-policy-check.py") @args
exit $LASTEXITCODE
