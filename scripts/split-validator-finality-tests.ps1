# Split validator_finality_evolution.rs into a directory integration test crate.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path "$root\mfn-consensus\tests\validator_finality_evolution.rs")) {
    $root = "c:\Users\shane\Downloads\permawrite-worktree"
}
$srcPath = Join-Path $root "mfn-consensus\tests\validator_finality_evolution.rs"
$dstDir = Join-Path $root "mfn-consensus\tests\validator_finality_evolution"
New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
$lines = Get-Content $srcPath

function Make-PubSupport {
    param([int]$Start, [int]$End)
    $chunk = $lines[$Start..$End] -join "`n"
    $chunk = $chunk -replace '(?m)^struct Fixture', 'pub struct Fixture'
    $chunk = $chunk -replace '(?m)^    state:', '    pub state:'
    $chunk = $chunk -replace '(?m)^    secrets:', '    pub secrets:'
    $chunk = $chunk -replace '(?m)^    params:', '    pub params:'
    $chunk = $chunk -replace '(?m)^const ENTRY_CHURN_REGISTER_STAKE', 'pub const ENTRY_CHURN_REGISTER_STAKE'
    $chunk = $chunk -replace '(?m)^fn ', 'pub fn '
    return $chunk
}

$supportImports = @'
use mfn_bls::{bls_keygen_from_seed, bls_sign};
use mfn_consensus::bond_wire::{sign_register, sign_unbond};
use mfn_consensus::bonding::{BondingParams, DEFAULT_BONDING_PARAMS};
use mfn_consensus::consensus::{
    cast_vote, eligibility_threshold, encode_finality_proof, finalize, is_eligible, pick_winner,
    slot_seed, try_produce_slot, FinalityProof, ProducerProof, SlotContext, Validator,
    ValidatorSecrets,
};
use mfn_consensus::{
    apply_genesis, build_genesis, build_unsealed_header, header_signing_hash, seal_block, Block,
    BondOp, ChainState, ConsensusParams, GenesisConfig, SlashEvidence, ValidatorStats,
    DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::vrf::{vrf_keygen_from_seed, vrf_prove};
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

'@

$ineligibleStart = ($lines | Select-String -Pattern '^fn ineligible_producer_at_ctx' | Select-Object -First 1).LineNumber - 1
$ineligibleEnd = ($lines | Select-String -Pattern '^/// VRF output at or above' | Select-Object -First 1).LineNumber - 2
$supportBody = Make-PubSupport -Start 40 -End 343
$ineligible = Make-PubSupport -Start $ineligibleStart -End $ineligibleEnd
$support = $supportImports + $supportBody + "`n`n" + $ineligible
Set-Content -Path (Join-Path $dstDir "support.rs") -Value $support -NoNewline

$testHeader = @'
use crate::support::*;

'@

$assignments = @{
    pre_block = @(
        'finality_quorum_uses_pre_block_validator_set'
        'validator_root_is_pre_block_in_validator_mode'
    )
    finality_rejection = @(
        'rejected_block_leaves_state_unchanged'
        'prev_hash_mismatch_rejects_without_state_change'
        'bad_height_rejects_without_state_change'
        'finality_msg_mismatch_rejects_without_state_change'
        'tampered_producer_proof_rejects_without_state_change'
        'signing_stake_mismatch_rejects_without_state_change'
        'producer_not_in_set_rejects_without_state_change'
        'producer_sig_invalid_rejects_without_state_change'
        'vrf_invalid_rejects_without_state_change'
        'vrf_output_mismatch_rejects_without_state_change'
        'aggregate_invalid_rejects_without_state_change'
        'producer_not_eligible_rejects_without_state_change'
        'missing_producer_proof_rejects_without_state_change'
        'finality_decode_error_rejects_without_state_change'
        'sub_quorum_finality_rejects_with_quorum_not_met'
    )
    header_roots = @(
        'bond_root_mismatch_rejects_without_state_change'
        'slashing_root_mismatch_rejects_without_state_change'
        'tx_root_mismatch_rejects_without_state_change'
        'storage_proof_root_mismatch_rejects_without_state_change'
        'claims_root_mismatch_rejects_without_state_change'
        'utxo_root_mismatch_rejects_without_state_change'
        'storage_root_mismatch_rejects_without_state_change'
    )
    liveness = @(
        'liveness_bitmap_and_stats_evolve_atomically_on_accept'
        'liveness_stats_unchanged_when_block_rejected'
        'validator_root_moves_on_liveness_slash'
        'liveness_skips_zero_stake_validator_after_equivocation'
        'liveness_slash_credits_treasury_in_validator_mode'
        'liveness_signed_clears_consecutive_missed_in_validator_mode'
    )
    slashing = @(
        'equivocation_slash_moves_successor_validator_root'
        'equivocation_during_unbond_delay_still_zeros_stake'
        'invalid_slash_evidence_rejects_without_state_change'
        'duplicate_slash_evidence_rejects_without_state_change'
        'equivocation_slash_credits_treasury_in_validator_mode'
    )
    bond_ops = @(
        'unbond_request_preserves_validator_root_in_delay_window'
        'validator_root_moves_on_unbond_settlement'
        'exit_churn_cap_defers_third_unbond_settlement'
        'exit_churn_cap_resets_at_epoch_boundary'
        'entry_churn_cap_rejects_third_register_without_state_change'
        'entry_churn_cap_allows_two_registers_and_moves_validator_root'
        'entry_churn_cap_resets_at_epoch_boundary'
        'duplicate_vrf_register_rejects_without_state_change'
        'duplicate_unbond_enqueue_rejects_without_state_change'
        'register_stake_below_minimum_rejects_without_state_change'
        'same_block_register_then_unbond_rejects_without_state_change'
        'same_block_duplicate_vrf_register_rejects_without_state_change'
        'unbond_zombie_validator_rejects_without_state_change'
        'forged_unbond_signature_rejects_without_state_change'
        'unbond_unknown_validator_rejects_without_state_change'
        'bond_rejection_leaves_treasury_unchanged'
        'duplicate_unbond_after_pending_request_rejects_without_state_change'
        'register_assigns_monotonic_validator_index'
        'register_extends_validator_stats'
        'register_success_credits_treasury'
        'unbond_settlement_clears_pending_unbond_in_validator_mode'
    )
    epoch_checkpoint = @(
        'bond_epoch_entry_count_persists_across_empty_blocks'
        'bond_epoch_exit_count_persists_across_empty_blocks'
        'bond_epoch_counters_persist_in_chain_checkpoint_roundtrip'
        'bond_epoch_id_increments_at_epoch_boundary'
    )
}

# Map test fn name -> start line (0-based index of #[test])
$testStarts = @{}
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -eq '#[test]') {
        $fnLine = $lines[$i + 1]
        if ($fnLine -match '^fn (\w+)') {
            $testStarts[$Matches[1]] = $i
        }
    }
}

function Get-TestChunk {
    param([string]$Name)
    $start = $testStarts[$Name]
    if ($null -eq $start) { throw "missing test $Name" }
    # include doc comments above
    $docStart = $start
    while ($docStart -gt 344 -and ($lines[$docStart - 1] -match '^///' -or $lines[$docStart - 1].Trim() -eq '')) {
        $docStart--
    }
    # find end: next #[test] or EOF
    $end = $lines.Count
    for ($j = $start + 1; $j -lt $lines.Count; $j++) {
        if ($lines[$j] -eq '#[test]' -or $lines[$j] -match '^fn ineligible_producer_at_ctx') {
            $end = $j
            while ($end -gt ($start + 1) -and ($lines[$end - 1].Trim() -eq '' -or $lines[$end - 1] -match '^///')) {
                $end--
            }
            break
        }
    }
    return ($lines[$docStart..($end - 1)] -join "`n")
}

$commonUse = @'
use crate::support::*;
use mfn_bls::{bls_keygen_from_seed, bls_sign};
use mfn_consensus::bond_wire::{sign_register, sign_unbond};
use mfn_consensus::bonding::DEFAULT_BONDING_PARAMS;
use mfn_consensus::consensus::{
    decode_finality_proof, encode_finality_proof, validator_set_root, verify_finality_proof,
    ConsensusCheck, FinalityProof, ProducerProof, SlotContext,
};
use mfn_consensus::{
    apply_block, build_unsealed_header, decode_chain_checkpoint, encode_chain_checkpoint,
    header_signing_hash, ApplyOutcome, Block, BlockError, BondOp, ChainCheckpoint, SlashEvidence,
    ValidatorStats,
};
use mfn_crypto::point::generator_g;
use mfn_crypto::vrf::vrf_keygen_from_seed;

'@

foreach ($mod in $assignments.Keys) {
    $body = $commonUse
    foreach ($t in $assignments[$mod]) {
        $body += "`n" + (Get-TestChunk -Name $t) + "`n"
    }
    Set-Content -Path (Join-Path $dstDir "$mod.rs") -Value $body
}

$doc = ($lines[0..19] -join "`n")
$main = $doc + @'

#![allow(unused_imports)]

mod bond_ops;
mod epoch_checkpoint;
mod finality_rejection;
mod header_roots;
mod liveness;
mod pre_block;
mod slashing;
mod support;
'@
Set-Content -Path (Join-Path $dstDir "main.rs") -Value $main

Write-Host "Split complete -> $dstDir"
