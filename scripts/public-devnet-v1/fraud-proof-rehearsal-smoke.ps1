# Lane 4 / F5 phase 0: plan-only fraud-proof doc + module wiring gate (Windows).
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "../..")).Path
$Doc = Join-Path $RepoRoot "docs/FRAUD_PROOFS.md"
$Problems = Join-Path $RepoRoot "docs/PROBLEMS.md"
$Security = Join-Path $RepoRoot "docs/SECURITY_CONSIDERATIONS.md"
$Consensus = Join-Path $RepoRoot "mfn-consensus/src/fraud_proof.rs"
$Net = Join-Path $RepoRoot "mfn-net/src/fraud_proof_v1.rs"
$Frame = Join-Path $RepoRoot "mfn-net/src/frame.rs"

foreach ($path in @($Doc, $Problems, $Security, $Consensus, $Net, $Frame)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "fraud-proof-rehearsal-smoke: missing $path"
    }
}

foreach ($needle in @("verify_body_root_fraud_proof", "FRAUD_PROOF_SOFT_FINALITY_SLOTS", "0x13")) {
    if (-not (Select-String -LiteralPath $Doc -Pattern ([regex]::Escape($needle)) -Quiet)) {
        throw "fraud-proof-rehearsal-smoke: FRAUD_PROOFS.md missing: $needle"
    }
}
if (-not (Select-String -LiteralPath $Problems -Pattern "fraud-proof" -Quiet)) {
    throw "fraud-proof-rehearsal-smoke: PROBLEMS.md missing fraud-proof roadmap"
}
if (-not (Select-String -LiteralPath $Frame -Pattern "FRAUD_PROOF_V1_TAG" -Quiet)) {
    throw "fraud-proof-rehearsal-smoke: frame.rs must document FRAUD_PROOF_V1_TAG"
}
if (-not (Select-String -LiteralPath $Net -Pattern "FRAUD_PROOF_V1_TAG" -Quiet)) {
    throw "fraud-proof-rehearsal-smoke: fraud_proof_v1.rs missing tag constant"
}

Write-Host "fraud-proof-rehearsal-smoke: plan"
Write-Host "  docs=docs/FRAUD_PROOFS.md"
Write-Host "  consensus=mfn_consensus::fraud_proof"
Write-Host "  p2p_tag=0x13 FRAUD_PROOF_V1_TAG"
Write-Host "  phase=0 body-root verify only; no gossip yet"

if ($PlanOnly) {
    Write-Host "fraud-proof-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "fraud-proof-rehearsal-smoke: live mode not implemented"