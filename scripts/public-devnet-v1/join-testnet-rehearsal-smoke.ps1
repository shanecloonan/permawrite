# B-15 smoke wrapper (Windows): delegates to join-testnet-rehearsal-smoke.sh
param(
    [string]$Rpc = "",
    [string]$FaucetUrl = "",
    [string]$ObserverProxyUrl = "",
    [switch]$UseLiveUrls,
    [string]$SmokeDir = "",
    [string]$EvidenceDir = "",
    [switch]$NoStart,
    [switch]$NoBuild,
    [switch]$ArchiveEvidence,
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Smoke = Join-Path $ScriptDir "join-testnet-rehearsal-smoke.sh"
if (-not (Test-Path $Smoke)) { throw "join-testnet-rehearsal-smoke: missing $Smoke" }

$bashArgs = @()
if ($Rpc) { $bashArgs += @("--rpc", $Rpc) }
if ($FaucetUrl) { $bashArgs += @("--faucet-url", $FaucetUrl) }
if ($ObserverProxyUrl) { $bashArgs += @("--observer-proxy-url", $ObserverProxyUrl) }
if ($SmokeDir) { $bashArgs += @("--smoke-dir", $SmokeDir) }
if ($EvidenceDir) { $bashArgs += @("--evidence-dir", $EvidenceDir) }
if ($UseLiveUrls) { $bashArgs += "--use-live-urls" }
if ($NoStart) { $bashArgs += "--no-start" }
if ($NoBuild) { $bashArgs += "--no-build" }
if ($ArchiveEvidence) { $bashArgs += "--archive-evidence" }
if ($PlanOnly) { $bashArgs += "--plan-only" }

Push-Location $RepoRoot
try {
    & bash $Smoke @bashArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
