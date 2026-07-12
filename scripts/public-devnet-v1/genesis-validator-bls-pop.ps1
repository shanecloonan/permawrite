# Compute or verify genesis validator BLS register PoP signatures (Path B ceremony).
param(
    [Parameter(Mandatory = $true)]
    [string]$Genesis,
    [switch]$Verify
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")

Push-Location $RepoRoot
try {
    $args = @("--example", "genesis_validator_bls_pop", "--", "--genesis", $Genesis)
    if ($Verify) { $args += "--verify" }
    & cargo run --quiet --release -p mfn-runtime @args
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}
