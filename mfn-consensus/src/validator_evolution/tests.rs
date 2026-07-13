#![allow(unused_imports)]

use super::internal::*;
use super::*;
use super::*;
use crate::block::HEADER_VERSION;
use crate::bonding::DEFAULT_BONDING_PARAMS;
use crate::consensus::{ValidatorPayout, ValidatorSecrets};
use crate::DEFAULT_EMISSION_PARAMS;
use crate::TEST_CONSENSUS_PARAMS;
use mfn_bls::bls_keygen_from_seed;
use mfn_crypto::stealth::stealth_gen;
use mfn_crypto::vrf::vrf_keygen_from_seed;

fn mk_validator(i: u32, stake: u64) -> (Validator, ValidatorSecrets) {
    let vrf = vrf_keygen_from_seed(&[i as u8 + 1; 32]).unwrap();
    let bls = bls_keygen_from_seed(&[i as u8 + 101; 32]);
    let payout_wallet = stealth_gen();
    let payout = ValidatorPayout {
        view_pub: payout_wallet.view_pub,
        spend_pub: payout_wallet.spend_pub,
    };
    let val = Validator {
        index: i,
        vrf_pk: vrf.pk,
        bls_pk: bls.pk,
        stake,
        payout: Some(payout),
    };
    let secrets = ValidatorSecrets {
        index: i,
        vrf,
        bls: bls.clone(),
    };
    (val, secrets)
}

fn default_params() -> ConsensusParams {
    ConsensusParams {
        expected_proposers_per_slot: 10.0,
        quorum_stake_bps: 6666,
        liveness_max_consecutive_missed: 3,
        liveness_slash_bps: 100,
        ..TEST_CONSENSUS_PARAMS
    }
}

/// Equivocation slashing with an empty input list is a no-op.
#[test]
fn equivocation_empty_input_is_noop() {
    let (v0, _) = mk_validator(0, 1_000);
    let mut validators = vec![v0];
    let out = apply_equivocation_slashings(
        &mut validators,
        &[],
        &DEFAULT_EMISSION_PARAMS,
        1,
        HEADER_VERSION,
    );
    assert_eq!(out.forfeited_total, 0);
    assert!(out.errors.is_empty());
    assert_eq!(validators[0].stake, 1_000);
}

/// Liveness slashing: a validator that misses ≥ threshold blocks
/// gets its stake reduced; total_signed / total_missed track.
#[test]
fn liveness_clears_consecutive_missed_on_signed_bit() {
    let (mut v0, _) = mk_validator(0, 10_000);
    v0.stake = 10_000;
    let mut validators = vec![v0];
    let mut stats = vec![ValidatorStats::default()];
    let mut params = default_params();
    params.liveness_max_consecutive_missed = 2;
    params.liveness_slash_bps = 100;

    // Miss twice → slash applied at miss #2 (>=threshold).
    let bitmap_miss = vec![0u8];
    let out1 = apply_liveness_evolution(&mut validators, &mut stats, &bitmap_miss, &params);
    assert_eq!(out1.liveness_burn_total, 0);
    let out2 = apply_liveness_evolution(&mut validators, &mut stats, &bitmap_miss, &params);
    assert!(out2.liveness_burn_total > 0);
    assert_eq!(stats[0].liveness_slashes, 1);
    assert_eq!(stats[0].consecutive_missed, 0, "resets after slash");

    // Now a signed block clears the counter without further slash.
    let bitmap_signed = vec![1u8];
    let out3 = apply_liveness_evolution(&mut validators, &mut stats, &bitmap_signed, &params);
    assert_eq!(out3.liveness_burn_total, 0);
    assert_eq!(stats[0].consecutive_missed, 0);
    assert_eq!(stats[0].total_signed, 1);
}

/// Zero-stake validators are skipped (liveness doesn't touch zombies).
#[test]
fn liveness_skips_zero_stake_validators() {
    let (mut v0, _) = mk_validator(0, 0);
    v0.stake = 0;
    let mut validators = vec![v0];
    let mut stats = vec![ValidatorStats::default()];
    let params = default_params();
    let bitmap = vec![0u8];
    let out = apply_liveness_evolution(&mut validators, &mut stats, &bitmap, &params);
    assert_eq!(out.liveness_burn_total, 0);
    assert_eq!(stats[0].consecutive_missed, 0, "untouched");
    assert_eq!(stats[0].total_missed, 0);
}

/// Liveness automatically resizes the stats array to match
/// validators if they're misaligned.
#[test]
fn liveness_resizes_stats_when_misaligned() {
    let (v0, _) = mk_validator(0, 10_000);
    let (v1, _) = mk_validator(1, 10_000);
    let mut validators = vec![v0, v1];
    // Stats has only 1 entry but we have 2 validators.
    let mut stats = vec![ValidatorStats::default()];
    let params = default_params();
    let bitmap = vec![0b11u8];
    apply_liveness_evolution(&mut validators, &mut stats, &bitmap, &params);
    assert_eq!(stats.len(), 2, "stats grew to match validators");
    assert_eq!(stats[0].total_signed, 1);
    assert_eq!(stats[1].total_signed, 1);
}

/// Empty bond-ops list is a no-op (no mutation, no error).
#[test]
fn bond_ops_empty_is_noop() {
    let (v0, _) = mk_validator(0, 1_000_000);
    let mut validators = vec![v0];
    let mut stats = vec![ValidatorStats::default()];
    let mut pending = BTreeMap::new();
    let mut counters = BondEpochCounters {
        bond_epoch_id: 0,
        bond_epoch_entry_count: 0,
        bond_epoch_exit_count: 0,
        next_validator_index: 1,
    };
    let pre_counters = counters;
    let burn = apply_bond_ops_evolution(
        10,
        &mut counters,
        &mut validators,
        &mut stats,
        &mut pending,
        &DEFAULT_BONDING_PARAMS,
        &[],
    )
    .expect("empty ok");
    assert_eq!(burn, 0);
    assert_eq!(validators.len(), 1);
    assert_eq!(stats.len(), 1);
    assert!(pending.is_empty());
    // Epoch id is recomputed from height — at height 10 with default
    // slots_per_epoch (which is large), epoch is still 0.
    assert_eq!(counters.bond_epoch_id, pre_counters.bond_epoch_id);
    assert_eq!(
        counters.next_validator_index,
        pre_counters.next_validator_index
    );
}

/// Unbond settlements: empty pending list is a no-op.
#[test]
fn unbond_settlements_empty_pending_is_noop() {
    let (v0, _) = mk_validator(0, 1_000_000);
    let mut validators = vec![v0];
    let mut pending = BTreeMap::new();
    let mut counters = BondEpochCounters {
        bond_epoch_id: 0,
        bond_epoch_entry_count: 0,
        bond_epoch_exit_count: 0,
        next_validator_index: 1,
    };
    apply_unbond_settlements(
        100,
        &mut counters,
        &DEFAULT_BONDING_PARAMS,
        &mut validators,
        &mut pending,
    );
    assert_eq!(validators[0].stake, 1_000_000);
    assert_eq!(counters.bond_epoch_exit_count, 0);
}

/// Unbond settlements: a pending unbond whose unlock_height has
/// arrived zeros the validator's stake.
#[test]
fn unbond_settlements_zeros_validator_at_unlock_height() {
    let (mut v0, _) = mk_validator(0, 1_000_000);
    v0.stake = 1_000_000;
    let mut validators = vec![v0];
    let mut pending = BTreeMap::new();
    pending.insert(
        0,
        PendingUnbond {
            validator_index: 0,
            unlock_height: 50,
            stake_at_request: 1_000_000,
            request_height: 10,
        },
    );
    let mut counters = BondEpochCounters {
        bond_epoch_id: 0,
        bond_epoch_entry_count: 0,
        bond_epoch_exit_count: 0,
        next_validator_index: 1,
    };
    // Before unlock: nothing happens.
    apply_unbond_settlements(
        49,
        &mut counters,
        &DEFAULT_BONDING_PARAMS,
        &mut validators,
        &mut pending,
    );
    assert_eq!(validators[0].stake, 1_000_000);
    assert_eq!(pending.len(), 1);

    // At unlock: settles.
    apply_unbond_settlements(
        50,
        &mut counters,
        &DEFAULT_BONDING_PARAMS,
        &mut validators,
        &mut pending,
    );
    assert_eq!(validators[0].stake, 0);
    assert!(pending.is_empty());
    assert_eq!(counters.bond_epoch_exit_count, 1);
}

/// Bitmap extraction: empty producer_proof → None.
#[test]
fn bitmap_extract_empty_proof_returns_none() {
    let header = BlockHeader {
        version: 1,
        prev_hash: [0u8; 32],
        height: 0,
        slot: 0,
        timestamp: 0,
        tx_root: [0u8; 32],
        storage_root: [0u8; 32],
        bond_root: [0u8; 32],
        slashing_root: [0u8; 32],
        storage_proof_root: [0u8; 32],
        validator_root: [0u8; 32],
        claims_root: [0u8; 32],
        producer_proof: Vec::new(),
        utxo_root: [0u8; 32],
    };
    assert!(finality_bitmap_from_header(&header).is_none());
}
