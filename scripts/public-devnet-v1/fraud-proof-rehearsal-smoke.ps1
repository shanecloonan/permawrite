# Lane 4 / F5: plan-only fraud-proof doc + module wiring gate (phase 0 + phase 1 gossip).
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
$Gossip = Join-Path $RepoRoot "mfn-net/src/gossip.rs"
$NodeGossip = Join-Path $RepoRoot "mfn-node/src/p2p_gossip.rs"
$NodeFanout = Join-Path $RepoRoot "mfn-node/src/p2p_fanout.rs"
$Serve = Join-Path $RepoRoot "mfn-net/src/serve.rs"

foreach ($path in @($Doc, $Problems, $Security, $Consensus, $Net, $Frame, $Gossip, $NodeGossip, $NodeFanout, $Serve)) {
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

$phase1 = @{
    "on_fraud_proof_v1"            = $Gossip
    "send_fraud_proof_v1"          = $Gossip
    "push_fraud_proof_gossip_to_peer" = $Gossip
    "fanout_fraud_proof"           = $NodeFanout
    "mfnd_fraud_proof_valid"       = $Serve
    "verify_interactive_fraud_proof" = $NodeGossip
}
foreach ($entry in $phase1.GetEnumerator()) {
    if (-not (Select-String -LiteralPath $entry.Value -Pattern ([regex]::Escape($entry.Key)) -Quiet)) {
        throw "fraud-proof-rehearsal-smoke: $($entry.Value) missing phase 1: $($entry.Key)"
    }
}
foreach ($needle in @("verify_coinbase_amount_fraud_proof", "verify_interactive_fraud_proof", "COINBASE_FRAUD_PROOF_VERSION", "verify_tx_fraud_proof", "TX_FRAUD_PROOF_VERSION", "InvalidClsag", "InvalidSpora", "RingMemberUtxo", "RING_FRAUD_DEDUP_KIND", "fraud_proof_producer_slash_hint")) {
    if (-not (Select-String -LiteralPath $Consensus -Pattern ([regex]::Escape($needle)) -Quiet)) {
        throw "fraud-proof-rehearsal-smoke: fraud_proof.rs missing phase 2/3/3b: $needle"
    }
}
if (-not (Select-String -LiteralPath $Serve -Pattern ([regex]::Escape("mfnd_fraud_proof_producer_slash_hint")) -Quiet)) {
    throw "fraud-proof-rehearsal-smoke: serve.rs missing mfnd_fraud_proof_producer_slash_hint"
}
if (-not (Select-String -LiteralPath $NodeGossip -Pattern ([regex]::Escape("RingMember")) -Quiet)) {
    throw "fraud-proof-rehearsal-smoke: p2p_gossip.rs missing RingMember verdict handling"
}

Write-Host "fraud-proof-rehearsal-smoke: plan"
Write-Host "  docs=docs/FRAUD_PROOFS.md"
Write-Host "  consensus=mfn_consensus::fraud_proof"
Write-Host "  p2p_tag=0x13 FRAUD_PROOF_V1_TAG"
Write-Host "  phase=3b ring UTXO witness + producer slash ops hint"

if ($PlanOnly) {
    Write-Host "fraud-proof-rehearsal-smoke: PASS plan-only"
    exit 0
}

throw "fraud-proof-rehearsal-smoke: live mode not implemented"
