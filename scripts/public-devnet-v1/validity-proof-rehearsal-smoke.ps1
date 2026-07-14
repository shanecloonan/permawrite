# Lane 4 / F5 phase 4a: plan-only validity-proof wire + P2P tag gate.
param(
    [switch]$PlanOnly
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "../..")).Path
$Doc = Join-Path $RepoRoot "docs/FRAUD_PROOFS.md"
$Consensus = Join-Path $RepoRoot "mfn-consensus/src/validity_proof.rs"
$Net = Join-Path $RepoRoot "mfn-net/src/validity_proof_v1.rs"
$Frame = Join-Path $RepoRoot "mfn-net/src/frame.rs"
$Gossip = Join-Path $RepoRoot "mfn-net/src/gossip.rs"
$NodeGossip = Join-Path $RepoRoot "mfn-node/src/p2p_gossip.rs"
$Serve = Join-Path $RepoRoot "mfn-net/src/serve.rs"

foreach ($path in @($Doc, $Consensus, $Net, $Frame, $Gossip, $NodeGossip, $Serve)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "validity-proof-rehearsal-smoke: missing $path"
    }
}

foreach ($needle in @("verify_validity_proof_v1", "VALIDITY_PROOF_V1_TAG", "0x14", "phase 4a")) {
    if (-not (Select-String -LiteralPath $Doc -Pattern ([regex]::Escape($needle)) -Quiet)) {
        throw "validity-proof-rehearsal-smoke: FRAUD_PROOFS.md missing: $needle"
    }
}
if (-not (Select-String -LiteralPath $Consensus -Pattern "build_apply_block_replay_validity_proof" -Quiet)) {
    throw "validity-proof-rehearsal-smoke: validity_proof.rs missing replay builder"
}
if (-not (Select-String -LiteralPath $Net -Pattern "VALIDITY_PROOF_V1_TAG" -Quiet)) {
    throw "validity-proof-rehearsal-smoke: validity_proof_v1.rs missing tag constant"
}
if (-not (Select-String -LiteralPath $Frame -Pattern "VALIDITY_PROOF_V1_TAG" -Quiet)) {
    throw "validity-proof-rehearsal-smoke: frame.rs must document VALIDITY_PROOF_V1_TAG"
}

$phase4a = @{
    "on_validity_proof_v1"              = $Gossip
    "send_validity_proof_v1"            = $Gossip
    "push_validity_proof_gossip_to_peer" = $Gossip
    "verify_validity_proof_v1"          = $NodeGossip
    "mfnd_validity_proof_valid"         = $Serve
}
foreach ($entry in $phase4a.GetEnumerator()) {
    if (-not (Select-String -LiteralPath $entry.Value -Pattern ([regex]::Escape($entry.Key)) -Quiet)) {
        throw "validity-proof-rehearsal-smoke: $($entry.Value) missing: $($entry.Key)"
    }
}

Write-Host "validity-proof-rehearsal-smoke: plan"
Write-Host "  docs=docs/FRAUD_PROOFS.md"
Write-Host "  consensus=mfn_consensus::validity_proof"
Write-Host "  p2p_tag=0x14 VALIDITY_PROOF_V1_TAG"
Write-Host "  witness=apply_block_replay (STARK deferred)"

if ($PlanOnly -or -not $PSBoundParameters.ContainsKey("PlanOnly")) {
    Write-Host "validity-proof-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "validity-proof-rehearsal-smoke: live mode not implemented"
