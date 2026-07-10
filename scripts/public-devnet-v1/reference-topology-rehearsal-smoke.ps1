# P32: plan-only reference topology rehearsal (Windows parity).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$Doc = Join-Path $RepoRoot "docs\REFERENCE_TOPOLOGY.md"

if (-not (Test-Path -LiteralPath $Doc)) {
    throw "reference-topology-rehearsal-smoke: missing $Doc"
}

$needles = @(
    "mfnd_role_topology_warning",
    "Loopback devnet",
    "Wallet keys never on validator",
    "community observers usually expose public RPC",
    "mfn-cli --tor",
    "vps-role-validator.env.example"
)
foreach ($n in $needles) {
    if (-not (Select-String -LiteralPath $Doc -Pattern $n -Quiet)) {
        throw "reference-topology-rehearsal-smoke: REFERENCE_TOPOLOGY.md missing: $n"
    }
}

$templates = @(
    "vps-role-validator.env.example",
    "vps-role-observer.env.example",
    "vps-role-operator.env.example",
    "vps-role-wallet.env.example"
)
foreach ($t in $templates) {
    $path = Join-Path $ScriptDir $t
    if (-not (Test-Path -LiteralPath $path)) {
        throw "reference-topology-rehearsal-smoke: missing $path"
    }
}

Write-Host "reference-topology-rehearsal-smoke: plan"
Write-Host "  flow=read REFERENCE_TOPOLOGY.md -> verify P32 harness + separation rules"
Write-Host "  templates=vps-role-*.env.example (validator|observer|operator|wallet)"
Write-Host "  docs=docs/REFERENCE_TOPOLOGY.md"
Write-Host "  lint=mfnd_role_topology_warning (phase 0 shipped f76991a)"
Write-Host "  live_rehearsal=deferred (VPS TL-5/TL-6 uses separated observer + validators)"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "reference-topology-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "reference-topology-rehearsal-smoke: live mode not implemented; use VPS TL-6"
