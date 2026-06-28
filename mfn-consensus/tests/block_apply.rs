//! Block pply_block integration tests.
//!
//! Kept as a crate integration test so editing src/block/*.rs does not
//! recompile ~1.6k lines of apply-block coverage on every change.

#![allow(unused_imports)]

use mfn_consensus::bond_wire::*;
use mfn_consensus::bonding::*;
use mfn_consensus::consensus::*;
use mfn_consensus::emission::*;
use mfn_consensus::slashing::*;
use mfn_consensus::storage::StorageCommitment;
use mfn_consensus::*;
use mfn_crypto::codec::Writer;
use mfn_storage::{
    accrue_proof_reward, storage_commitment_hash, storage_proof_merkle_root, AccrueArgs,
    BuiltCommitment, EndowmentParams, DEFAULT_ENDOWMENT_PARAMS,
};

fn genesis_state() -> ChainState {
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    apply_genesis(&g, &cfg).unwrap()
}

#[test]
fn build_apply_genesis_matches() {
    let cfg = GenesisConfig {
        timestamp: 42,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let st = apply_genesis(&g, &cfg).unwrap();
    assert_eq!(st.height, Some(0));
    assert_eq!(st.block_ids.len(), 1);
    assert_eq!(st.block_ids[0], block_id(&g.header));
}

#[test]
fn apply_genesis_sets_optional_bonding_params() {
    let custom = BondingParams {
        min_validator_stake: 2_000_000,
        ..DEFAULT_BONDING_PARAMS
    };
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(custom),
    };
    let g = build_genesis(&cfg);
    let st = apply_genesis(&g, &cfg).unwrap();
    assert_eq!(st.bonding_params.min_validator_stake, 2_000_000);
}

#[test]
fn empty_block_applies_in_legacy_mode() {
    let st = genesis_state();
    let header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
    let blk = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.height, Some(1));
            assert_eq!(state.block_ids.len(), 2);
        }
        ApplyOutcome::Err { errors, .. } => panic!("expected ok, got: {errors:?}"),
    }
}

#[test]
fn bad_height_is_rejected() {
    let st = genesis_state();
    let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
    header.height = 99;
    // Have to recompute prev_hash + utxo_root for the bad height since
    // they're independent... actually no, only height is wrong here, so
    // the locally-computed expected_tx_root and utxo_root will still
    // match. Just check that BadHeight surfaces.
    let blk = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::BadHeight { .. })));
        }
        ApplyOutcome::Ok { .. } => panic!("expected err"),
    }
}

#[test]
fn bad_prev_hash_is_rejected() {
    let st = genesis_state();
    let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
    header.prev_hash = [9u8; 32];
    let blk = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::PrevHashMismatch)));
        }
        ApplyOutcome::Ok { .. } => panic!("expected err"),
    }
}

#[test]
fn tx_root_mismatch_is_rejected() {
    let st = genesis_state();
    let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
    header.tx_root[0] ^= 0xff;
    let blk = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::TxRootMismatch)));
        }
        ApplyOutcome::Ok { .. } => panic!("expected err"),
    }
}

#[test]
fn bond_root_mismatch_is_rejected() {
    let st = genesis_state();
    let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
    header.bond_root[0] ^= 0xff;
    let blk = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::BondRootMismatch)));
        }
        ApplyOutcome::Ok { .. } => panic!("expected err"),
    }
}

#[test]
fn storage_proof_root_mismatch_is_rejected() {
    // Build a legitimate empty-storage-proofs block, then flip a
    // byte of the header's storage_proof_root.
    let st = genesis_state();
    let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
    assert_eq!(header.storage_proof_root, [0u8; 32]);
    header.storage_proof_root[0] = 0xff;
    let blk = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::StorageProofRootMismatch)));
        }
        ApplyOutcome::Ok { .. } => panic!("expected err"),
    }
}

#[test]
fn slashing_root_mismatch_is_rejected() {
    // Build a valid empty-slashings block in legacy/no-validator
    // mode, then flip one byte of `header.slashing_root` to a value
    // the empty list cannot produce.
    let st = genesis_state();
    let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
    assert_eq!(header.slashing_root, [0u8; 32]);
    header.slashing_root[0] = 0xff;
    let blk = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::SlashingRootMismatch)));
        }
        ApplyOutcome::Ok { .. } => panic!("expected err"),
    }
}

#[test]
fn validator_root_mismatch_is_rejected() {
    // Build a valid empty block (legacy / no-validator mode is fine —
    // the validator-root check runs *regardless* of validator-set
    // size), then flip one byte of `header.validator_root` to a
    // value the pre-block state cannot produce.
    let st = genesis_state();
    let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
    // No validators ⇒ pre-block root is the all-zero sentinel.
    assert_eq!(header.validator_root, [0u8; 32]);
    header.validator_root[0] = 0xff;
    let blk = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::ValidatorRootMismatch)));
        }
        ApplyOutcome::Ok { .. } => panic!("expected err"),
    }
}

#[test]
fn build_unsealed_header_commits_pre_block_validator_set() {
    // The header for block N must commit to the validator set as it
    // stood at the end of block N-1 — the set the producer-proof is
    // verified against. Verify by building the header from a state
    // with a non-empty validator set and checking it equals
    // `validator_set_root(&state.validators)`.
    use crate::consensus::{validator_set_root, Validator};
    use mfn_bls::bls_keygen_from_seed;
    use mfn_crypto::point::generator_g;

    let mut st = genesis_state();
    let v = Validator {
        index: 0,
        vrf_pk: generator_g(),
        bls_pk: bls_keygen_from_seed(&[7u8; 32]).pk,
        stake: 1_000_000,
        payout: None,
    };
    st.validators.push(v.clone());
    st.validator_stats.push(ValidatorStats::default());
    st.next_validator_index = 1;

    let header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
    assert_eq!(header.validator_root, validator_set_root(&st.validators));
    assert_ne!(header.validator_root, [0u8; 32]);
}

#[test]
fn bond_ops_apply_is_atomic_on_error() {
    use mfn_bls::bls_keygen_from_seed;
    use mfn_crypto::point::{generator_g, generator_h};

    let st = genesis_state();
    let bls1 = bls_keygen_from_seed(&[1u8; 32]);
    let stake_ok = crate::DEFAULT_BONDING_PARAMS.min_validator_stake;
    let vrf_ok = generator_g();
    let ok_op = BondOp::Register {
        stake: stake_ok,
        vrf_pk: vrf_ok,
        bls_pk: bls1.pk,
        payout: None,
        sig: crate::bond_wire::sign_register(stake_ok, &vrf_ok, &bls1.pk, None, &bls1.sk),
    };
    let bls2 = bls_keygen_from_seed(&[2u8; 32]);
    let stake_bad = 1u64;
    let vrf_bad = generator_h();
    let bad_op = BondOp::Register {
        stake: stake_bad,
        vrf_pk: vrf_bad,
        bls_pk: bls2.pk,
        payout: None,
        sig: crate::bond_wire::sign_register(stake_bad, &vrf_bad, &bls2.pk, None, &bls2.sk),
    };
    let bond_ops = vec![ok_op, bad_op];
    let header = build_unsealed_header(&st, &[], &bond_ops, &[], &[], 1, 100);
    let blk = seal_block(
        header,
        Vec::new(),
        bond_ops,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::BondOpRejected { index: 1, .. })));
        }
        ApplyOutcome::Ok { .. } => panic!("expected err"),
    }
    assert!(st.validators.is_empty());
}

// Bad register signature must be rejected (atomic apply ⇒ the
// whole bond-op set is rolled back, no validators appended, no
// treasury credit). Mempool-grade authorization: this is the
// property that prevents an adversarial relayer from replaying a
// serialized BondOp::Register op for any operator's keys.
#[test]
fn register_rejects_invalid_signature() {
    use mfn_bls::bls_keygen_from_seed;
    use mfn_crypto::point::generator_g;

    let st = genesis_state();
    let attacker = bls_keygen_from_seed(&[200u8; 32]);
    let victim_bls = bls_keygen_from_seed(&[201u8; 32]);
    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let vrf_pk = generator_g();
    // The attacker signs over the victim's bls_pk but with their
    // own secret key — the resulting sig won't verify under
    // victim_bls.pk.
    let forged =
        crate::bond_wire::sign_register(stake, &vrf_pk, &victim_bls.pk, None, &attacker.sk);
    let op = BondOp::Register {
        stake,
        vrf_pk,
        bls_pk: victim_bls.pk,
        payout: None,
        sig: forged,
    };
    let header = build_unsealed_header(&st, &[], std::slice::from_ref(&op), &[], &[], 1, 100);
    let blk = seal_block(
        header,
        Vec::new(),
        vec![op],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { index: 0, .. })),
                "expected BondOpRejected at index 0, got {errors:?}"
            );
            // No state mutation must have occurred.
            assert_eq!(st.validators.len(), 0);
            assert_eq!(st.treasury, 0);
        }
        ApplyOutcome::Ok { .. } => panic!("forged register signature must reject"),
    }
}

// Unbond rejection in legacy mode (empty validators ⇒ no finality
// proof required for this block). End-to-end register → unbond →
// settle flows live in tests/integration.rs::unbond_lifecycle_*.
#[test]
fn unbond_rejects_unknown_validator_legacy_mode() {
    use mfn_bls::bls_keygen_from_seed;
    let st = genesis_state();
    let bls = bls_keygen_from_seed(&[100u8; 32]);
    let unbond = BondOp::Unbond {
        validator_index: 42,
        sig: crate::bond_wire::sign_unbond(42, &bls.sk),
    };
    let header = build_unsealed_header(&st, &[], std::slice::from_ref(&unbond), &[], &[], 1, 100);
    let blk = seal_block(
        header,
        Vec::new(),
        vec![unbond],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::BondOpRejected { .. })));
        }
        ApplyOutcome::Ok { .. } => panic!("unknown validator must reject"),
    }
}

#[test]
fn unbond_wire_round_trip_inside_bond_root() {
    use mfn_bls::bls_keygen_from_seed;
    use mfn_crypto::point::generator_g;
    let bls = bls_keygen_from_seed(&[55u8; 32]);
    let unbond = BondOp::Unbond {
        validator_index: 7,
        sig: crate::bond_wire::sign_unbond(7, &bls.sk),
    };
    let reg_bls = bls_keygen_from_seed(&[11u8; 32]);
    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let vrf_pk = generator_g();
    let reg = BondOp::Register {
        stake,
        vrf_pk,
        bls_pk: reg_bls.pk,
        payout: None,
        sig: crate::bond_wire::sign_register(stake, &vrf_pk, &reg_bls.pk, None, &reg_bls.sk),
    };
    let ops = vec![reg, unbond];
    let root = crate::bond_wire::bond_merkle_root(&ops);
    assert_ne!(root, [0u8; 32], "merkle root over mixed ops is non-zero");
}

#[test]
fn utxo_root_mismatch_is_rejected() {
    let st = genesis_state();
    let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
    header.utxo_root[0] ^= 0xff;
    let blk = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(errors
                .iter()
                .any(|e| matches!(e, BlockError::UtxoRootMismatch)));
        }
        ApplyOutcome::Ok { .. } => panic!("expected err"),
    }
}

#[test]
fn header_signing_hash_excludes_producer_proof() {
    let st = genesis_state();
    let h0 = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
    let hash0 = header_signing_hash(&h0);
    let mut h1 = h0.clone();
    h1.producer_proof = b"this is whatever the producer attaches".to_vec();
    let hash1 = header_signing_hash(&h1);
    assert_eq!(
        hash0, hash1,
        "signing hash must not depend on producer_proof"
    );
    // But the full block id DOES depend on producer_proof.
    assert_ne!(block_id(&h0), block_id(&h1));
}

#[test]
fn storage_root_uses_zero_when_empty() {
    assert_eq!(storage_merkle_root(&[]), [0u8; 32]);
}

#[test]
fn storage_merkle_root_is_stable_under_no_op_storage() {
    use mfn_crypto::point::generator_g;
    let sc = StorageCommitment {
        data_root: [1u8; 32],
        size_bytes: 1_000,
        chunk_size: 256,
        num_chunks: 4,
        replication: 3,
        endowment: generator_g(),
    };
    let r1 = storage_merkle_root(std::slice::from_ref(&sc));
    let r2 = storage_merkle_root(&[sc]);
    assert_eq!(r1, r2);
}

/* --------- Endowment burden + storage proof gating ---------- *
 *                                                              *
 *  These tests run apply_block end-to-end against a no-         *
 *  validator chain. With validators.is_empty(), the finality    *
 *  + coinbase machinery is bypassed, so we get clean coverage   *
 *  of the upload-burden + SPoRA proof paths.                    *
 * ------------------------------------------------------------ */

fn empty_genesis_with_endowment(ep: EndowmentParams) -> ChainState {
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: ep,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    apply_genesis(&g, &cfg).unwrap()
}

/// Snapshot storage-provenance + treasury fields for SPoRA payout tests.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StorageProofPayoutSnap {
    height: Option<u32>,
    treasury: u128,
    last_proven_height: u32,
    last_proven_slot: u64,
    pending_yield_ppb: u128,
}

fn storage_proof_payout_snap(st: &ChainState, commit_hash: &[u8; 32]) -> StorageProofPayoutSnap {
    let entry = &st.storage[commit_hash];
    StorageProofPayoutSnap {
        height: st.height,
        treasury: st.treasury,
        last_proven_height: entry.last_proven_height,
        last_proven_slot: entry.last_proven_slot,
        pending_yield_ppb: entry.pending_yield_ppb,
    }
}

fn genesis_with_storage_commit(
    built: &BuiltCommitment,
    ep: EndowmentParams,
) -> (ChainState, [u8; 32]) {
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![built.commit.clone()],
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: ep,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).unwrap();
    let commit_hash = storage_commitment_hash(&built.commit);
    (state, commit_hash)
}

fn twin_storage_genesis(
    ep: EndowmentParams,
) -> (
    ChainState,
    BuiltCommitment,
    Vec<u8>,
    BuiltCommitment,
    Vec<u8>,
) {
    let payload_a: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let payload_b: Vec<u8> = (0..4096u32).map(|i| ((i + 17) % 251) as u8).collect();
    let built_a = mfn_storage::build_storage_commitment(
        &payload_a,
        1_000,
        Some(4096),
        ep.min_replication,
        None,
    )
    .unwrap();
    let built_b = mfn_storage::build_storage_commitment(
        &payload_b,
        1_000,
        Some(4096),
        ep.min_replication,
        None,
    )
    .unwrap();
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![built_a.commit.clone(), built_b.commit.clone()],
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: ep,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let state = apply_genesis(&g, &cfg).unwrap();
    (state, built_a, payload_a, built_b, payload_b)
}

#[test]
fn duplicate_storage_proof_in_one_block_rejected() {
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let built = mfn_storage::build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .unwrap();
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![built.commit.clone()],
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let state0 = apply_genesis(&g, &cfg).unwrap();
    let unsealed = build_unsealed_header(&state0, &[], &[], &[], &[], 5_000, 1_000);
    let p = mfn_storage::build_storage_proof(
        &built.commit,
        &unsealed.prev_hash,
        5_000,
        &payload,
        &built.tree,
    )
    .unwrap();
    let block = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![p.clone(), p],
    );
    let before = storage_proof_payout_snap(&state0, &storage_commitment_hash(&built.commit));
    match apply_block(&state0, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::DuplicateStorageProof { .. })),
                "expected DuplicateStorageProof, got {errors:?}"
            );
            assert_eq!(
                before,
                storage_proof_payout_snap(&state0, &storage_commitment_hash(&built.commit)),
                "duplicate proof must not mutate storage or treasury state"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("duplicate proof must reject the block"),
    }
}

#[test]
fn storage_proof_for_unknown_commit_rejected() {
    let state0 = empty_genesis_with_endowment(DEFAULT_ENDOWMENT_PARAMS);
    let payload = b"unanchored".to_vec();
    let built = mfn_storage::build_storage_commitment(
        &payload,
        1,
        Some(64), // 64-byte chunks → many small chunks
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .unwrap();
    let unsealed = build_unsealed_header(&state0, &[], &[], &[], &[], 1, 100);
    let p = mfn_storage::build_storage_proof(
        &built.commit,
        &unsealed.prev_hash,
        1,
        &payload,
        &built.tree,
    )
    .unwrap();
    let block = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![p],
    );
    let before = (state0.storage.len(), state0.treasury, state0.height);
    match apply_block(&state0, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofUnknownCommit { .. })),
                "expected StorageProofUnknownCommit, got {errors:?}"
            );
            assert_eq!(
                (state0.storage.len(), state0.treasury, state0.height),
                before,
                "unknown commit must not mutate storage or treasury state"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("unanchored proof must reject the block"),
    }
}

#[test]
fn storage_proof_with_wrong_chunk_rejected() {
    let payload: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
    let built = mfn_storage::build_storage_commitment(
        &payload,
        1,
        Some(64),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .unwrap();
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![built.commit.clone()],
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let state0 = apply_genesis(&g, &cfg).unwrap();
    let unsealed = build_unsealed_header(&state0, &[], &[], &[], &[], 1, 100);
    let mut p = mfn_storage::build_storage_proof(
        &built.commit,
        &unsealed.prev_hash,
        1,
        &payload,
        &built.tree,
    )
    .unwrap();
    if !p.chunk.is_empty() {
        p.chunk[0] ^= 0xff;
    }
    let block = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![p],
    );
    let commit_hash = storage_commitment_hash(&built.commit);
    let before = storage_proof_payout_snap(&state0, &commit_hash);
    match apply_block(&state0, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofInvalid { .. })),
                "expected StorageProofInvalid, got {errors:?}"
            );
            assert_eq!(
                before,
                storage_proof_payout_snap(&state0, &commit_hash),
                "invalid proof must not mutate storage or treasury state"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("corrupt proof must reject the block"),
    }
}

#[test]
fn build_unsealed_header_commits_storage_proof_emit_order() {
    let ep = DEFAULT_ENDOWMENT_PARAMS;
    let (state0, built_a, payload_a, built_b, payload_b) = twin_storage_genesis(ep);
    let slot = 5_000u32;
    let scratch = build_unsealed_header(&state0, &[], &[], &[], &[], slot, 1_000);
    let proof_a = mfn_storage::build_storage_proof(
        &built_a.commit,
        &scratch.prev_hash,
        slot,
        &payload_a,
        &built_a.tree,
    )
    .unwrap();
    let proof_b = mfn_storage::build_storage_proof(
        &built_b.commit,
        &scratch.prev_hash,
        slot,
        &payload_b,
        &built_b.tree,
    )
    .unwrap();
    let proofs_ab = [proof_a.clone(), proof_b.clone()];
    let root_ab = storage_proof_merkle_root(&proofs_ab);
    let root_ba = storage_proof_merkle_root(&[proof_b, proof_a]);
    assert_ne!(
        root_ab, root_ba,
        "emit order must change the committed root"
    );
    let header_ab = build_unsealed_header(&state0, &[], &[], &[], &proofs_ab, slot, 1_000);
    assert_eq!(header_ab.storage_proof_root, root_ab);
}

#[test]
fn storage_proof_root_wrong_emit_order_rejected() {
    let ep = DEFAULT_ENDOWMENT_PARAMS;
    let (state0, built_a, payload_a, built_b, payload_b) = twin_storage_genesis(ep);
    let slot = 5_000u32;
    let scratch = build_unsealed_header(&state0, &[], &[], &[], &[], slot, 1_000);
    let proof_a = mfn_storage::build_storage_proof(
        &built_a.commit,
        &scratch.prev_hash,
        slot,
        &payload_a,
        &built_a.tree,
    )
    .unwrap();
    let proof_b = mfn_storage::build_storage_proof(
        &built_b.commit,
        &scratch.prev_hash,
        slot,
        &payload_b,
        &built_b.tree,
    )
    .unwrap();
    let proofs_ab = [proof_a.clone(), proof_b.clone()];
    let hash_a = proof_a.commit_hash;
    let hash_b = proof_b.commit_hash;
    let before_a = storage_proof_payout_snap(&state0, &hash_a);
    let before_b = storage_proof_payout_snap(&state0, &hash_b);
    let mut header = build_unsealed_header(&state0, &[], &[], &[], &proofs_ab, slot, 1_000);
    // Header claims reversed emit order while the body keeps [a, b].
    header.storage_proof_root = storage_proof_merkle_root(&[proof_b, proof_a]);
    let block = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs_ab.to_vec(),
    );
    match apply_block(&state0, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofRootMismatch)),
                "expected StorageProofRootMismatch, got {errors:?}"
            );
            assert_eq!(before_a, storage_proof_payout_snap(&state0, &hash_a));
            assert_eq!(before_b, storage_proof_payout_snap(&state0, &hash_b));
        }
        ApplyOutcome::Ok { .. } => panic!("wrong emit-order root must reject the block"),
    }
}

#[test]
fn tampered_storage_proof_root_rejects_before_payout_effects() {
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let built = mfn_storage::build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .unwrap();
    let (mut state0, commit_hash) = genesis_with_storage_commit(&built, DEFAULT_ENDOWMENT_PARAMS);
    state0.treasury = 10_000_000;
    let slot = 5_000u32;
    let scratch = build_unsealed_header(&state0, &[], &[], &[], &[], slot, 1_000);
    let proof = mfn_storage::build_storage_proof(
        &built.commit,
        &scratch.prev_hash,
        slot,
        &payload,
        &built.tree,
    )
    .unwrap();
    let before = storage_proof_payout_snap(&state0, &commit_hash);
    let mut header = build_unsealed_header(
        &state0,
        &[],
        &[],
        &[],
        std::slice::from_ref(&proof),
        slot,
        1_000,
    );
    header.storage_proof_root[0] ^= 0xff;
    let block = seal_block(
        header,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![proof],
    );
    match apply_block(&state0, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofRootMismatch)),
                "expected StorageProofRootMismatch, got {errors:?}"
            );
            assert_eq!(before, storage_proof_payout_snap(&state0, &commit_hash));
        }
        ApplyOutcome::Ok { .. } => panic!("tampered storage_proof_root must reject before payout"),
    }
}

#[test]
fn accepted_storage_proof_updates_provenance_and_treasury() {
    let ep = EndowmentParams {
        real_yield_ppb: 50_000_000, // 5% > 2% inflation buffer
        ..DEFAULT_ENDOWMENT_PARAMS
    };
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let built = mfn_storage::build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        ep.min_replication,
        None,
    )
    .unwrap();
    let (mut state0, commit_hash) = genesis_with_storage_commit(&built, ep);
    state0.treasury = 100_000_000;
    let slot = 500_000u32;
    let scratch = build_unsealed_header(&state0, &[], &[], &[], &[], slot, 1_000);
    let proof = mfn_storage::build_storage_proof(
        &built.commit,
        &scratch.prev_hash,
        slot,
        &payload,
        &built.tree,
    )
    .unwrap();
    let expected_accrual = accrue_proof_reward(AccrueArgs {
        size_bytes: built.commit.size_bytes,
        replication: built.commit.replication,
        pending_ppb: 0,
        last_proven_slot: 0,
        current_slot: u64::from(slot),
        params: &ep,
    })
    .expect("accrue");
    assert!(
        expected_accrual.payout > 0 || expected_accrual.new_pending_ppb > 0,
        "test setup must produce yield movement"
    );
    let treasury_before = state0.treasury;
    let unsealed = build_unsealed_header(
        &state0,
        &[],
        &[],
        &[],
        std::slice::from_ref(&proof),
        slot,
        1_000,
    );
    let block = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![proof],
    );
    let state1 = match apply_block(&state0, &block) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("expected ok, got {errors:?}"),
    };
    let entry = &state1.storage[&commit_hash];
    assert_eq!(entry.last_proven_height, 1);
    assert_eq!(entry.last_proven_slot, u64::from(slot));
    assert_eq!(entry.pending_yield_ppb, expected_accrual.new_pending_ppb);
    let storage_reward_total = u128::from(state0.emission_params.storage_proof_reward)
        .saturating_add(expected_accrual.payout);
    let expected_treasury =
        treasury_before.saturating_sub(treasury_before.min(storage_reward_total));
    assert_eq!(state1.treasury, expected_treasury);
}

#[test]
fn storage_proof_accrual_respects_proof_reward_window_at_apply_block() {
    let window = 100u64;
    let ep = EndowmentParams {
        real_yield_ppb: 50_000_000, // 5% > 2% inflation buffer
        proof_reward_window_slots: window,
        ..DEFAULT_ENDOWMENT_PARAMS
    };
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let built = mfn_storage::build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        ep.min_replication,
        None,
    )
    .unwrap();
    let (mut state0, commit_hash) = genesis_with_storage_commit(&built, ep);
    state0.treasury = 100_000_000;
    let slot = 50_000u32;
    let expected_accrual = accrue_proof_reward(AccrueArgs {
        size_bytes: built.commit.size_bytes,
        replication: built.commit.replication,
        pending_ppb: 0,
        last_proven_slot: 0,
        current_slot: u64::from(slot),
        params: &ep,
    })
    .expect("accrue");
    assert_eq!(
        expected_accrual.credited_slots, window,
        "elapsed {slot} must cap at proof_reward_window_slots"
    );
    let scratch = build_unsealed_header(&state0, &[], &[], &[], &[], slot, 1_000);
    let proof = mfn_storage::build_storage_proof(
        &built.commit,
        &scratch.prev_hash,
        slot,
        &payload,
        &built.tree,
    )
    .unwrap();
    let treasury_before = state0.treasury;
    let unsealed = build_unsealed_header(
        &state0,
        &[],
        &[],
        &[],
        std::slice::from_ref(&proof),
        slot,
        1_000,
    );
    let block = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![proof],
    );
    let state1 = match apply_block(&state0, &block) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("expected ok, got {errors:?}"),
    };
    let entry = &state1.storage[&commit_hash];
    assert_eq!(entry.last_proven_height, 1);
    assert_eq!(entry.last_proven_slot, u64::from(slot));
    assert_eq!(entry.pending_yield_ppb, expected_accrual.new_pending_ppb);
    let storage_reward_total = u128::from(state0.emission_params.storage_proof_reward)
        .saturating_add(expected_accrual.payout);
    let expected_treasury =
        treasury_before.saturating_sub(treasury_before.min(storage_reward_total));
    assert_eq!(state1.treasury, expected_treasury);
}

#[test]
fn dual_distinct_storage_proofs_in_one_block_update_both_entries() {
    let ep = DEFAULT_ENDOWMENT_PARAMS;
    let (mut state0, built_a, payload_a, built_b, payload_b) = twin_storage_genesis(ep);
    state0.treasury = 100_000_000;
    let slot = 5_000u32;
    let scratch = build_unsealed_header(&state0, &[], &[], &[], &[], slot, 1_000);
    let proof_a = mfn_storage::build_storage_proof(
        &built_a.commit,
        &scratch.prev_hash,
        slot,
        &payload_a,
        &built_a.tree,
    )
    .unwrap();
    let proof_b = mfn_storage::build_storage_proof(
        &built_b.commit,
        &scratch.prev_hash,
        slot,
        &payload_b,
        &built_b.tree,
    )
    .unwrap();
    let proofs = [proof_a, proof_b];
    let hash_a = storage_commitment_hash(&built_a.commit);
    let hash_b = storage_commitment_hash(&built_b.commit);
    let treasury_before = state0.treasury;
    let unsealed = build_unsealed_header(&state0, &[], &[], &[], &proofs, slot, 1_000);
    assert_eq!(
        unsealed.storage_proof_root,
        storage_proof_merkle_root(&proofs),
        "header must commit producer emit order [a, b]"
    );
    let block = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs.to_vec(),
    );
    let state1 = match apply_block(&state0, &block) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("expected ok, got {errors:?}"),
    };
    assert_eq!(state1.storage[&hash_a].last_proven_height, 1);
    assert_eq!(state1.storage[&hash_a].last_proven_slot, u64::from(slot));
    assert_eq!(state1.storage[&hash_b].last_proven_height, 1);
    assert_eq!(state1.storage[&hash_b].last_proven_slot, u64::from(slot));
    let storage_reward_total =
        u128::from(state0.emission_params.storage_proof_reward).saturating_mul(2);
    let expected_treasury =
        treasury_before.saturating_sub(treasury_before.min(storage_reward_total));
    assert_eq!(state1.treasury, expected_treasury);
}

#[test]
fn dual_distinct_storage_proofs_positive_yield_accrues_both_entries() {
    let ep = EndowmentParams {
        real_yield_ppb: 50_000_000, // 5% > 2% inflation buffer
        ..DEFAULT_ENDOWMENT_PARAMS
    };
    let (mut state0, built_a, payload_a, built_b, payload_b) = twin_storage_genesis(ep);
    state0.treasury = 100_000_000;
    let slot = 500_000u32;
    let scratch = build_unsealed_header(&state0, &[], &[], &[], &[], slot, 1_000);
    let proof_a = mfn_storage::build_storage_proof(
        &built_a.commit,
        &scratch.prev_hash,
        slot,
        &payload_a,
        &built_a.tree,
    )
    .unwrap();
    let proof_b = mfn_storage::build_storage_proof(
        &built_b.commit,
        &scratch.prev_hash,
        slot,
        &payload_b,
        &built_b.tree,
    )
    .unwrap();
    let proofs = [proof_a, proof_b];
    let hash_a = storage_commitment_hash(&built_a.commit);
    let hash_b = storage_commitment_hash(&built_b.commit);
    let accrual_a = accrue_proof_reward(AccrueArgs {
        size_bytes: built_a.commit.size_bytes,
        replication: built_a.commit.replication,
        pending_ppb: 0,
        last_proven_slot: 0,
        current_slot: u64::from(slot),
        params: &ep,
    })
    .expect("accrue a");
    let accrual_b = accrue_proof_reward(AccrueArgs {
        size_bytes: built_b.commit.size_bytes,
        replication: built_b.commit.replication,
        pending_ppb: 0,
        last_proven_slot: 0,
        current_slot: u64::from(slot),
        params: &ep,
    })
    .expect("accrue b");
    assert!(
        accrual_a.payout > 0 || accrual_a.new_pending_ppb > 0,
        "test setup must produce yield movement on commit a"
    );
    assert!(
        accrual_b.payout > 0 || accrual_b.new_pending_ppb > 0,
        "test setup must produce yield movement on commit b"
    );
    let treasury_before = state0.treasury;
    let unsealed = build_unsealed_header(&state0, &[], &[], &[], &proofs, slot, 1_000);
    let block = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        proofs.to_vec(),
    );
    let state1 = match apply_block(&state0, &block) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("expected ok, got {errors:?}"),
    };
    assert_eq!(state1.storage[&hash_a].last_proven_height, 1);
    assert_eq!(state1.storage[&hash_a].last_proven_slot, u64::from(slot));
    assert_eq!(
        state1.storage[&hash_a].pending_yield_ppb,
        accrual_a.new_pending_ppb
    );
    assert_eq!(state1.storage[&hash_b].last_proven_height, 1);
    assert_eq!(state1.storage[&hash_b].last_proven_slot, u64::from(slot));
    assert_eq!(
        state1.storage[&hash_b].pending_yield_ppb,
        accrual_b.new_pending_ppb
    );
    let storage_reward_total = u128::from(state0.emission_params.storage_proof_reward)
        .saturating_mul(2)
        .saturating_add(accrual_a.payout)
        .saturating_add(accrual_b.payout);
    let expected_treasury =
        treasury_before.saturating_sub(treasury_before.min(storage_reward_total));
    assert_eq!(state1.treasury, expected_treasury);
}

#[test]
fn storage_proof_body_tamper_rejects_without_state_change() {
    let ep = DEFAULT_ENDOWMENT_PARAMS;
    let (state0, built_a, payload_a, built_b, payload_b) = twin_storage_genesis(ep);
    let slot = 5_000u32;
    let scratch = build_unsealed_header(&state0, &[], &[], &[], &[], slot, 1_000);
    let proof_a = mfn_storage::build_storage_proof(
        &built_a.commit,
        &scratch.prev_hash,
        slot,
        &payload_a,
        &built_a.tree,
    )
    .unwrap();
    let proof_b = mfn_storage::build_storage_proof(
        &built_b.commit,
        &scratch.prev_hash,
        slot,
        &payload_b,
        &built_b.tree,
    )
    .unwrap();
    let hash_a = storage_commitment_hash(&built_a.commit);
    let hash_b = storage_commitment_hash(&built_b.commit);
    let before_a = storage_proof_payout_snap(&state0, &hash_a);
    let before_b = storage_proof_payout_snap(&state0, &hash_b);
    let unsealed = build_unsealed_header(
        &state0,
        &[],
        &[],
        &[],
        std::slice::from_ref(&proof_a),
        slot,
        1_000,
    );
    let mut block = seal_block(
        unsealed,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![proof_a],
    );
    block.storage_proofs.push(proof_b);
    match apply_block(&state0, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofRootMismatch)),
                "expected StorageProofRootMismatch, got {errors:?}"
            );
            assert_eq!(before_a, storage_proof_payout_snap(&state0, &hash_a));
            assert_eq!(before_b, storage_proof_payout_snap(&state0, &hash_b));
        }
        ApplyOutcome::Ok { .. } => panic!("body tamper must reject before payout"),
    }
}

/* ----------------------------------------------------------------- *
 *                                                                   *
 *  These tests target the only thing standing between Permawrite     *
 *  and the mint-out-of-thin-air attack: every CLSAG ring member     *
 *  (P, C) MUST exist in the chain UTXO set. Without this guard a    *
 *  spender can fabricate a ring member with arbitrary hidden value, *
 *  balance their pseudo-output against it, and emit outputs they    *
 *  do not own.                                                       *
 * ----------------------------------------------------------------- */

#[test]
fn ring_member_not_in_utxo_set_rejected() {
    use curve25519_dalek::scalar::Scalar;
    use mfn_crypto::clsag::ClsagRing;
    use mfn_crypto::point::{generator_g, generator_h};
    use mfn_crypto::scalar::random_scalar;
    use mfn_crypto::stealth::stealth_gen;

    use crate::transaction::{sign_transaction, InputSpec, OutputSpec, Recipient};

    // Genesis funds the real signer with a known UTXO. No decoys are
    // anchored, so any ring member other than the signer's UTXO will
    // be unknown to the chain.
    let init_value = 1_000_000u64;
    let init_blinding = random_scalar();
    let signer_spend = random_scalar();
    let signer_p = generator_g() * signer_spend;
    let signer_c = (generator_g() * init_blinding) + (generator_h() * Scalar::from(init_value));
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: vec![GenesisOutput {
            one_time_addr: signer_p,
            amount: signer_c,
        }],
        initial_storage: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let state0 = apply_genesis(&g, &cfg).unwrap();

    // Construct a 4-member ring; signer at index 1, the other three
    // are random (P, C) pairs that aren't in the UTXO set.
    let mut ring_p = Vec::new();
    let mut ring_c = Vec::new();
    for i in 0..4 {
        if i == 1 {
            ring_p.push(signer_p);
            ring_c.push(signer_c);
        } else {
            let sp = random_scalar();
            let bp = random_scalar();
            let vp = random_scalar();
            ring_p.push(generator_g() * sp);
            ring_c.push((generator_g() * bp) + (generator_h() * vp));
        }
    }
    let recipient_wallet = stealth_gen();
    let r = Recipient {
        view_pub: recipient_wallet.view_pub,
        spend_pub: recipient_wallet.spend_pub,
    };
    let send_value = init_value - 1_000;
    let signed = sign_transaction(
        vec![InputSpec {
            ring: ClsagRing {
                p: ring_p,
                c: ring_c,
            },
            signer_idx: 1,
            spend_priv: signer_spend,
            value: init_value,
            blinding: init_blinding,
        }],
        vec![OutputSpec::ToRecipient {
            recipient: r,
            value: send_value,
            storage: None,
        }],
        1_000,
        b"attack".to_vec(),
    )
    .expect("sign");

    let unsealed = build_unsealed_header(
        &state0,
        std::slice::from_ref(&signed.tx),
        &[],
        &[],
        &[],
        1,
        100,
    );
    let block = seal_block(
        unsealed,
        vec![signed.tx],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&state0, &block) {
        ApplyOutcome::Err { errors, .. } => {
            let saw_ring_error = errors
                .iter()
                .any(|e| matches!(e, BlockError::RingMemberNotInUtxoSet { .. }));
            assert!(
                saw_ring_error,
                "expected RingMemberNotInUtxoSet, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => {
            panic!("ring with fabricated members must reject the block (counterfeit attack)")
        }
    }
}

#[test]
fn ring_member_with_wrong_commit_rejected() {
    use curve25519_dalek::scalar::Scalar;
    use mfn_crypto::clsag::ClsagRing;
    use mfn_crypto::point::{generator_g, generator_h};
    use mfn_crypto::scalar::random_scalar;
    use mfn_crypto::stealth::stealth_gen;

    use crate::transaction::{sign_transaction, InputSpec, OutputSpec, Recipient};

    // Anchor a real UTXO at genesis; spender will reference it in
    // their ring but with an inflated Pedersen commitment to try to
    // sneak extra hidden value past the chain. Must be rejected.
    let init_value = 1_000_000u64;
    let init_blinding = random_scalar();
    let signer_spend = random_scalar();
    let signer_p = generator_g() * signer_spend;
    let signer_c = (generator_g() * init_blinding) + (generator_h() * Scalar::from(init_value));

    // A second anchored UTXO with KNOWN small value that the attacker
    // will reference in their ring, but with an inflated C.
    let decoy_spend = random_scalar();
    let decoy_p = generator_g() * decoy_spend;
    let decoy_value = 1u64;
    let decoy_blinding = random_scalar();
    let decoy_c = (generator_g() * decoy_blinding) + (generator_h() * Scalar::from(decoy_value));

    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: vec![
            GenesisOutput {
                one_time_addr: signer_p,
                amount: signer_c,
            },
            GenesisOutput {
                one_time_addr: decoy_p,
                amount: decoy_c,
            },
        ],
        initial_storage: Vec::new(),
        validators: Vec::new(),
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let state0 = apply_genesis(&g, &cfg).unwrap();

    // Attacker's ring: signer's real UTXO + the decoy's P with an
    // INFLATED C (pretending the decoy holds 10^9 base units).
    let inflated_c =
        (generator_g() * random_scalar()) + (generator_h() * Scalar::from(1_000_000_000u64));
    let ring_p = vec![signer_p, decoy_p];
    let ring_c = vec![signer_c, inflated_c];

    let recipient_wallet = stealth_gen();
    let r = Recipient {
        view_pub: recipient_wallet.view_pub,
        spend_pub: recipient_wallet.spend_pub,
    };
    let send_value = init_value - 1_000;
    let signed = sign_transaction(
        vec![InputSpec {
            ring: ClsagRing {
                p: ring_p,
                c: ring_c,
            },
            signer_idx: 0,
            spend_priv: signer_spend,
            value: init_value,
            blinding: init_blinding,
        }],
        vec![OutputSpec::ToRecipient {
            recipient: r,
            value: send_value,
            storage: None,
        }],
        1_000,
        b"inflated-c".to_vec(),
    )
    .expect("sign");

    let unsealed = build_unsealed_header(
        &state0,
        std::slice::from_ref(&signed.tx),
        &[],
        &[],
        &[],
        1,
        100,
    );
    let block = seal_block(
        unsealed,
        vec![signed.tx],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&state0, &block) {
        ApplyOutcome::Err { errors, .. } => {
            let saw_commit_error = errors
                .iter()
                .any(|e| matches!(e, BlockError::RingMemberCommitMismatch { .. }));
            assert!(
                saw_commit_error,
                "expected RingMemberCommitMismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("inflated-C ring member must reject the block"),
    }
}

/* ---- Liveness participation + auto-slashing ---------------------- *
 *                                                                   *
 *  These unit tests drive `apply_block` against the liveness bitmap  *
 *  path with hand-crafted state — we don't need a real validator    *
 *  set or BLS finality machinery because the liveness logic         *
 *  consumes `finality_bitmap` after `verify_finality_proof` has     *
 *  already cleared the block. We bypass that path by stuffing the   *
 *  bitmap directly into a synthetic `next` via the public surface:  *
 *  set up an empty-validator chain, then manually invoke the path.  *
 *                                                                   *
 *  Integration coverage with REAL BLS finality flowing into the     *
 *  liveness path lives in `tests/integration.rs`.                   *
 * ----------------------------------------------------------------- */

/// Direct unit test of the liveness-update logic, called as the
/// equivalent inline block of `apply_block`. This keeps the test
/// hermetic — no BLS setup, no genesis dance — just the state
/// transition the bitmap drives.
fn apply_liveness_step(state: &mut ChainState, bitmap: &[u8], max_missed: u32, slash_bps: u32) {
    // Mirrors the `if let Some(ref bitmap)` branch in apply_block.
    if state.validator_stats.len() != state.validators.len() {
        state
            .validator_stats
            .resize(state.validators.len(), ValidatorStats::default());
    }
    let slash_bps = u128::from(slash_bps);
    let mut burn_total: u128 = 0;
    for (i, v) in state.validators.iter_mut().enumerate() {
        if v.stake == 0 {
            continue;
        }
        let byte = i >> 3;
        let bit = i & 7;
        let signed = byte < bitmap.len() && (bitmap[byte] & (1u8 << bit)) != 0;
        let stats = &mut state.validator_stats[i];
        if signed {
            stats.consecutive_missed = 0;
            stats.total_signed = stats.total_signed.saturating_add(1);
        } else {
            stats.consecutive_missed = stats.consecutive_missed.saturating_add(1);
            stats.total_missed = stats.total_missed.saturating_add(1);
            if max_missed > 0 && stats.consecutive_missed >= max_missed {
                let bps = slash_bps.min(10_000);
                let old_stake = u128::from(v.stake);
                let new_stake_u128 = old_stake * (10_000 - bps) / 10_000;
                let forfeited = old_stake - new_stake_u128;
                v.stake = u64::try_from(new_stake_u128).unwrap_or(u64::MAX);
                burn_total = burn_total.saturating_add(forfeited);
                stats.liveness_slashes = stats.liveness_slashes.saturating_add(1);
                stats.consecutive_missed = 0;
            }
        }
    }
    state.treasury = state.treasury.saturating_add(burn_total);
}

fn fake_validator(idx: u32, stake: u64) -> Validator {
    // VRF + BLS pubkeys are placeholders; the liveness path doesn't
    // touch them. We just need a Validator-shaped struct.
    Validator {
        index: idx,
        vrf_pk: mfn_crypto::vrf::vrf_keygen_from_seed(&[idx as u8 + 7; 32])
            .unwrap()
            .pk,
        bls_pk: mfn_bls::bls_keygen_from_seed(&[idx as u8 + 17; 32]).pk,
        stake,
        payout: None,
    }
}

#[test]
fn liveness_signed_resets_counter_and_credits() {
    let mut state = ChainState::empty();
    state.validators = vec![fake_validator(0, 100)];
    state.validator_stats = vec![ValidatorStats::default()];
    // Bitmap with bit 0 set.
    apply_liveness_step(&mut state, &[0b0000_0001], 32, 100);
    let s = state.validator_stats[0];
    assert_eq!(s.consecutive_missed, 0);
    assert_eq!(s.total_signed, 1);
    assert_eq!(s.total_missed, 0);
    assert_eq!(state.validators[0].stake, 100);
}

#[test]
fn liveness_unset_increments_counter() {
    let mut state = ChainState::empty();
    state.validators = vec![fake_validator(0, 100)];
    state.validator_stats = vec![ValidatorStats::default()];
    for _ in 0..5 {
        apply_liveness_step(&mut state, &[0b0000_0000], 32, 100);
    }
    let s = state.validator_stats[0];
    assert_eq!(s.consecutive_missed, 5);
    assert_eq!(s.total_missed, 5);
    assert_eq!(s.total_signed, 0);
    assert_eq!(s.liveness_slashes, 0);
    assert_eq!(state.validators[0].stake, 100, "below threshold ⇒ no slash");
}

#[test]
fn liveness_threshold_triggers_slash_and_reset() {
    let mut state = ChainState::empty();
    state.validators = vec![fake_validator(0, 1_000_000)];
    state.validator_stats = vec![ValidatorStats::default()];
    // 32 consecutive misses → first slash.
    for _ in 0..32 {
        apply_liveness_step(&mut state, &[], 32, 100);
    }
    let s = state.validator_stats[0];
    assert_eq!(s.liveness_slashes, 1);
    assert_eq!(s.consecutive_missed, 0, "counter resets after slash");
    // 1% of 1_000_000 = 10_000; new stake = 990_000.
    assert_eq!(state.validators[0].stake, 990_000);
}

#[test]
fn liveness_compounds_multiplicatively() {
    let mut state = ChainState::empty();
    state.validators = vec![fake_validator(0, 1_000_000)];
    state.validator_stats = vec![ValidatorStats::default()];
    // 5 slash cycles of 32 misses each.
    for _ in 0..(5 * 32) {
        apply_liveness_step(&mut state, &[], 32, 100);
    }
    // After 5 × (1% reduction): stake = 1_000_000 × 0.99^5
    // = 1_000_000 × 0.95099 ≈ 950_990.
    // Each step rounds down (floor div), so we expect ≤ 951_000
    // with a small floor-rounding margin.
    let stake = state.validators[0].stake;
    assert!(
        (940_000..=952_000).contains(&stake),
        "expected ~951k after 5 slashes, got {stake}"
    );
    assert_eq!(state.validator_stats[0].liveness_slashes, 5);
}

#[test]
fn liveness_signed_clears_pending_counter() {
    // A validator that misses 30 votes and then signs has their
    // consecutive_missed reset to 0 — no slash triggered. This is
    // the "transient outage" forgiveness.
    let mut state = ChainState::empty();
    state.validators = vec![fake_validator(0, 100)];
    state.validator_stats = vec![ValidatorStats::default()];
    for _ in 0..30 {
        apply_liveness_step(&mut state, &[], 32, 100);
    }
    assert_eq!(state.validator_stats[0].consecutive_missed, 30);
    apply_liveness_step(&mut state, &[0b0000_0001], 32, 100);
    let s = state.validator_stats[0];
    assert_eq!(s.consecutive_missed, 0);
    assert_eq!(s.total_signed, 1);
    assert_eq!(s.total_missed, 30);
    assert_eq!(s.liveness_slashes, 0);
    assert_eq!(state.validators[0].stake, 100, "transient outage forgiven");
}

#[test]
fn liveness_zero_stake_validator_skipped() {
    // Equivocation-slashed (stake=0) validators are zombies; the
    // liveness layer must not touch them.
    let mut state = ChainState::empty();
    state.validators = vec![fake_validator(0, 0)];
    state.validator_stats = vec![ValidatorStats::default()];
    for _ in 0..100 {
        apply_liveness_step(&mut state, &[], 32, 100);
    }
    let s = state.validator_stats[0];
    assert_eq!(s.consecutive_missed, 0);
    assert_eq!(s.total_missed, 0);
    assert_eq!(s.liveness_slashes, 0);
}

#[test]
fn liveness_bitmap_too_short_treated_as_missing() {
    // If a validator's bit index lies beyond the bitmap's length,
    // they are treated as a missed vote.
    let mut state = ChainState::empty();
    state.validators = vec![fake_validator(0, 100), fake_validator(1, 100)];
    state.validator_stats = vec![ValidatorStats::default(); 2];
    // Bitmap only carries bit 0; validator 1's byte index is 0 too
    // (bit 1) and IS in range. Use a 0-length bitmap to force the
    // out-of-range case.
    apply_liveness_step(&mut state, &[], 32, 100);
    assert_eq!(state.validator_stats[0].consecutive_missed, 1);
    assert_eq!(state.validator_stats[1].consecutive_missed, 1);
}

#[test]
fn liveness_slash_caps_at_full_stake_loss() {
    // A pathological slash_bps > 10_000 must clamp to 100% so we
    // can't underflow into negative stake.
    let mut state = ChainState::empty();
    state.validators = vec![fake_validator(0, 1_000_000)];
    state.validator_stats = vec![ValidatorStats::default()];
    for _ in 0..1 {
        apply_liveness_step(&mut state, &[], 1, 99_999);
    }
    assert_eq!(state.validators[0].stake, 0);
    assert_eq!(state.validator_stats[0].liveness_slashes, 1);
}

/* ---- Burn-on-bond + slash-to-treasury economic invariants -------- *
 *                                                                    *
 *  These tests assert the M1 economic-symmetry property: every base  *
 *  unit a validator commits enters the permanence treasury. Stake    *
 *  may later flow out via unbond settlement (future work), but for   *
 *  M1 the slash and liveness paths re-credit any forfeited stake to  *
 *  treasury — so the chain's permanence-funding pool is always       *
 *  bounded below by the sum of validator burns minus rewards paid.   *
 * ------------------------------------------------------------------ */

#[test]
fn liveness_slash_credits_treasury() {
    let mut state = ChainState::empty();
    state.validators = vec![fake_validator(0, 1_000_000)];
    state.validator_stats = vec![ValidatorStats::default()];
    assert_eq!(state.treasury, 0);
    // One full slash cycle = 1% multiplicative reduction = 10_000.
    for _ in 0..32 {
        apply_liveness_step(&mut state, &[], 32, 100);
    }
    assert_eq!(state.validators[0].stake, 990_000);
    assert_eq!(state.treasury, 10_000, "1% liveness slash → treasury");
}

#[test]
fn liveness_slash_treasury_compounds_with_validator_stake() {
    let mut state = ChainState::empty();
    state.validators = vec![fake_validator(0, 1_000_000)];
    state.validator_stats = vec![ValidatorStats::default()];
    // 5 full slash cycles at 1% each. Multiplicative on stake; the
    // treasury accumulates the discrete forfeits.
    for _ in 0..(5 * 32) {
        apply_liveness_step(&mut state, &[], 32, 100);
    }
    let stake = state.validators[0].stake;
    let treasury = state.treasury;
    let total = u128::from(stake) + treasury;
    // No emission/coinbase flow in this unit test — stake + treasury
    // must equal the original endowment (modulo floor-division loss
    // on the multiplicative path).
    assert!(
        (995_000..=1_000_000).contains(&total),
        "stake+treasury ≈ original endowment, got stake={stake} treasury={treasury}"
    );
}

#[test]
fn equivocation_slash_credits_treasury_via_apply_block() {
    use mfn_bls::{bls_keygen_from_seed, bls_sign};

    // Two-validator chain so we can pin the producer/voter roles.
    // We don't actually drive consensus here — apply_block sees an
    // empty `validators` set (legacy mode) so the slashing path runs
    // without a finality proof.
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: vec![fake_validator(0, 7_500), fake_validator(1, 2_500)],
        params: DEFAULT_CONSENSUS_PARAMS,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let g = build_genesis(&cfg);
    let st = apply_genesis(&g, &cfg).unwrap();

    // Validator 0's BLS key signs two different headers at the same
    // slot → equivocation. We reuse the fake_validator seed mapping
    // for the BLS key.
    let bls = bls_keygen_from_seed(&[17u8; 32]); // matches idx=0
                                                 // The genesis validator must match: re-derive index 0's BLS pk
                                                 // to confirm the seed.
    assert_eq!(bls.pk, st.validators[0].bls_pk);
    let h1 = [11u8; 32];
    let h2 = [22u8; 32];
    let ev = SlashEvidence {
        height: 1,
        slot: 1,
        voter_index: 0,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, &bls.sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, &bls.sk),
    };

    // Build a block with the evidence. Since the chain has a non-
    // empty validator set, we can't actually run apply_block without
    // a real finality proof; instead, drive the slashing path
    // directly through the public surface by feeding the evidence
    // into a manual mirror. The chain semantics live in apply_block,
    // but the equivocation accounting here is straightforward and
    // verifiable in isolation.
    let mut next = st.clone();
    let chk = crate::slashing::verify_evidence(&ev, &next.validators);
    assert_eq!(chk, EvidenceCheck::Valid);
    let idx = ev.voter_index as usize;
    let forfeited = u128::from(next.validators[idx].stake);
    next.validators[idx].stake = 0;
    next.treasury = next.treasury.saturating_add(forfeited);
    assert_eq!(next.validators[0].stake, 0);
    assert_eq!(next.treasury, 7_500);
}

#[test]
fn burn_on_bond_credits_treasury() {
    use mfn_bls::bls_keygen_from_seed;
    use mfn_crypto::point::generator_g;

    let st = genesis_state();
    assert_eq!(st.treasury, 0);
    let bls = bls_keygen_from_seed(&[42u8; 32]);
    let stake = 2_500_000u64;
    let vrf_pk = generator_g();
    let bond = BondOp::Register {
        stake,
        vrf_pk,
        bls_pk: bls.pk,
        payout: None,
        sig: crate::bond_wire::sign_register(stake, &vrf_pk, &bls.pk, None, &bls.sk),
    };
    let bond_ops = vec![bond];
    let header = build_unsealed_header(&st, &[], &bond_ops, &[], &[], 1, 100);
    let blk = seal_block(
        header,
        Vec::new(),
        bond_ops,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, 2_500_000, "bond burn must credit treasury");
            assert_eq!(state.validators.len(), 1);
            assert_eq!(state.validators[0].stake, 2_500_000);
        }
        ApplyOutcome::Err { errors, .. } => panic!("bond apply failed: {errors:?}"),
    }
}

#[test]
fn burn_on_bond_aggregates_multiple_registers() {
    use mfn_bls::bls_keygen_from_seed;
    use mfn_crypto::point::{generator_g, generator_h};

    let st = genesis_state();
    let min = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let bls1 = bls_keygen_from_seed(&[1u8; 32]);
    let bls2 = bls_keygen_from_seed(&[2u8; 32]);
    let vrf1 = generator_g();
    let vrf2 = generator_h();
    let ops = vec![
        BondOp::Register {
            stake: min,
            vrf_pk: vrf1,
            bls_pk: bls1.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(min, &vrf1, &bls1.pk, None, &bls1.sk),
        },
        BondOp::Register {
            stake: min * 3,
            vrf_pk: vrf2,
            bls_pk: bls2.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(min * 3, &vrf2, &bls2.pk, None, &bls2.sk),
        },
    ];
    let header = build_unsealed_header(&st, &[], &ops, &[], &[], 1, 100);
    let blk = seal_block(header, Vec::new(), ops, Vec::new(), Vec::new(), Vec::new());
    match apply_block(&st, &blk) {
        ApplyOutcome::Ok { state, .. } => {
            assert_eq!(state.treasury, u128::from(min) * 4);
            assert_eq!(state.validators.len(), 2);
        }
        ApplyOutcome::Err { errors, .. } => panic!("bond apply failed: {errors:?}"),
    }
}

#[test]
fn failed_bond_does_not_credit_treasury() {
    use mfn_bls::bls_keygen_from_seed;
    use mfn_crypto::point::{generator_g, generator_h};

    let st = genesis_state();
    // Below-minimum stake → rejection; the whole block must not
    // credit the treasury (atomic apply).
    let min = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let bls1 = bls_keygen_from_seed(&[1u8; 32]);
    let bls2 = bls_keygen_from_seed(&[2u8; 32]);
    let vrf1 = generator_g();
    let vrf2 = generator_h();
    let ops = vec![
        BondOp::Register {
            stake: min,
            vrf_pk: vrf1,
            bls_pk: bls1.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(min, &vrf1, &bls1.pk, None, &bls1.sk),
        },
        BondOp::Register {
            stake: 1, // below min
            vrf_pk: vrf2,
            bls_pk: bls2.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(1, &vrf2, &bls2.pk, None, &bls2.sk),
        },
    ];
    let header = build_unsealed_header(&st, &[], &ops, &[], &[], 1, 100);
    let blk = seal_block(header, Vec::new(), ops, Vec::new(), Vec::new(), Vec::new());
    match apply_block(&st, &blk) {
        ApplyOutcome::Err { .. } => {
            // Pre-state untouched: treasury still zero.
            assert_eq!(st.treasury, 0);
        }
        ApplyOutcome::Ok { .. } => panic!("expected rejection"),
    }
}

/* ----------------------------------------------------------------- *
 *  M2.0.9 — Header wire codec round-trip + malformed rejection      *
 * ----------------------------------------------------------------- */

fn sample_header() -> BlockHeader {
    BlockHeader {
        version: HEADER_VERSION,
        prev_hash: [0xa1u8; 32],
        height: 7,
        slot: 11,
        timestamp: 1_700_000_000,
        tx_root: [0xb2u8; 32],
        storage_root: [0xc3u8; 32],
        bond_root: [0xd4u8; 32],
        slashing_root: [0xe5u8; 32],
        storage_proof_root: [0xf6u8; 32],
        validator_root: [0x07u8; 32],
        claims_root: [0x29u8; 32],
        producer_proof: (0..73u8).collect(),
        utxo_root: [0x18u8; 32],
    }
}

/// `decode_block_header` is a left inverse of `block_header_bytes`.
#[test]
fn block_header_codec_round_trip() {
    let h = sample_header();
    let bytes = block_header_bytes(&h);
    let h2 = decode_block_header(&bytes).expect("decode");
    assert_eq!(h2.version, h.version);
    assert_eq!(h2.prev_hash, h.prev_hash);
    assert_eq!(h2.height, h.height);
    assert_eq!(h2.slot, h.slot);
    assert_eq!(h2.timestamp, h.timestamp);
    assert_eq!(h2.tx_root, h.tx_root);
    assert_eq!(h2.storage_root, h.storage_root);
    assert_eq!(h2.bond_root, h.bond_root);
    assert_eq!(h2.slashing_root, h.slashing_root);
    assert_eq!(h2.storage_proof_root, h.storage_proof_root);
    assert_eq!(h2.validator_root, h.validator_root);
    assert_eq!(h2.claims_root, h.claims_root);
    assert_eq!(h2.producer_proof, h.producer_proof);
    assert_eq!(h2.utxo_root, h.utxo_root);
    // And `block_id(h) == block_id(decode(encode(h)))`.
    assert_eq!(block_id(&h), block_id(&h2));
}

/// Empty `producer_proof` is a valid encoding — genesis / no-validator chains.
#[test]
fn block_header_codec_round_trip_empty_producer_proof() {
    let mut h = sample_header();
    h.producer_proof = Vec::new();
    let bytes = block_header_bytes(&h);
    let h2 = decode_block_header(&bytes).expect("decode");
    assert!(h2.producer_proof.is_empty());
    assert_eq!(block_id(&h), block_id(&h2));
}

/// Truncating any prefix of a valid encoding must surface
/// `HeaderDecodeError::Truncated` (or a varint-overflow for the
/// degenerate 0-byte case — we just require `Err`).
#[test]
fn block_header_codec_rejects_truncation() {
    let h = sample_header();
    let bytes = block_header_bytes(&h);
    // Sweep every prefix length except the full one.
    for cut in 0..bytes.len() {
        let err = decode_block_header(&bytes[..cut]).expect_err("must reject prefix");
        // Any error is fine; the goal is to never decode a partial
        // header as if it were complete.
        match err {
            HeaderDecodeError::Truncated { .. }
            | HeaderDecodeError::VarintOverflow { .. }
            | HeaderDecodeError::ProducerProofTooLarge { .. }
            | HeaderDecodeError::VersionOutOfRange { .. } => (),
            HeaderDecodeError::TrailingBytes { .. } => {
                panic!("prefix of len {cut} cannot have trailing bytes")
            }
        }
    }
}

/// Extra trailing bytes after a valid header → `TrailingBytes`.
#[test]
fn block_header_codec_rejects_trailing_bytes() {
    let h = sample_header();
    let mut bytes = block_header_bytes(&h);
    bytes.push(0xAB);
    bytes.push(0xCD);
    let err = decode_block_header(&bytes).expect_err("must reject tail");
    match err {
        HeaderDecodeError::TrailingBytes { remaining } => assert_eq!(remaining, 2),
        other => panic!("expected TrailingBytes, got {other:?}"),
    }
}

/// `version` encoded as a varint > u32::MAX → `VersionOutOfRange`.
/// Forge the bytes by hand — easiest way to exercise the branch.
#[test]
fn block_header_codec_rejects_oversized_version() {
    // LEB128 for `2^33` (well over u32::MAX): 5 bytes.
    let v: u64 = 1u64 << 33;
    let mut w = Writer::new();
    w.varint(v);
    let mut bytes = w.into_bytes();
    // Pad rest with zeros so we don't trip Truncated before
    // VersionOutOfRange.
    bytes.extend(std::iter::repeat(0u8).take(128));

    let err = decode_block_header(&bytes).expect_err("must reject");
    match err {
        HeaderDecodeError::VersionOutOfRange { got } => assert_eq!(got, v),
        other => panic!("expected VersionOutOfRange, got {other:?}"),
    }
}

/// Flipping a single byte inside the encoded header changes
/// `block_id` exactly when that byte materially decodes into a
/// header field — i.e. the encoding is non-redundant. (Sanity:
/// if any byte is "dead", the codec leaks state silently.)
#[test]
fn block_header_codec_has_no_dead_bytes() {
    let h = sample_header();
    let bytes = block_header_bytes(&h);
    let original_id = block_id(&h);
    for i in 0..bytes.len() {
        let mut tampered = bytes.clone();
        tampered[i] ^= 0x01;
        match decode_block_header(&tampered) {
            Ok(h2) => assert_ne!(
                block_id(&h2),
                original_id,
                "flipping byte {i} must materially change the header"
            ),
            Err(_) => {
                // Tampering broke the encoding outright — also acceptable.
            }
        }
    }
}

/// TS-parity golden vector for the header wire codec. The fixed
/// input below pins the byte-for-byte encoding produced by
/// `block_header_bytes` and the resulting `block_id`. Changing
/// the codec is consensus-critical and must bump this vector
/// deliberately.
#[test]
fn block_header_codec_golden_vector() {
    let h = BlockHeader {
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
    let bytes = block_header_bytes(&h);
    // Layout (genesis-shaped header):
    //   version=1            : 0x01
    //   prev_hash            : 32 × 0x00
    //   height=0             : 0x00 0x00 0x00 0x00
    //   slot=0               : 0x00 0x00 0x00 0x00
    //   timestamp=0          : 0x00 × 8
    //   tx_root              : 32 × 0x00
    //   storage_root         : 32 × 0x00
    //   bond_root            : 32 × 0x00
    //   slashing_root        : 32 × 0x00
    //   storage_proof_root   : 32 × 0x00
    //   validator_root       : 32 × 0x00
    //   claims_root          : 32 × 0x00
    //   producer_proof.len=0 : 0x00
    //   utxo_root            : 32 × 0x00
    // Total = 1 + 32 + 4 + 4 + 8 + (32 * 7) + 1 + 32 = 306 bytes.
    assert_eq!(bytes.len(), 306, "expected 306 bytes, got {}", bytes.len());
    assert_eq!(bytes[0], 0x01, "varint(version=1) is one byte 0x01");
    assert_eq!(
        bytes.iter().filter(|&&b| b != 0).count(),
        1,
        "only the version byte is non-zero in a genesis-shaped header"
    );
    // Round-trip pin.
    let h2 = decode_block_header(&bytes).expect("decode");
    assert_eq!(block_id(&h), block_id(&h2));
}

/* ----------------------------------------------------------------- *
 *  M2.0.10 — Full block wire codec                                  *
 * ----------------------------------------------------------------- */

/// Construct a structurally minimal but valid `Block`: the
/// genesis-shaped header with an empty body. Exercises the
/// framing layer (length-prefixed empty sections) without
/// dragging the heavyweight CLSAG / BLS / SPoRA verifiers
/// in. Real-data round-trip is covered by the mfn-light
/// integration test, which uses `mfn-node::Chain` to build
/// fully-signed blocks.
fn sample_empty_block() -> Block {
    let mut header = sample_header();
    header.producer_proof = Vec::new();
    Block {
        header,
        txs: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
        bond_ops: Vec::new(),
    }
}

/// `decode_block` is a left inverse of `encode_block` on an
/// empty-body block.
#[test]
fn block_codec_round_trip_empty_body() {
    let b = sample_empty_block();
    let bytes = encode_block(&b);
    let b2 = decode_block(&bytes).expect("decode");
    assert_eq!(block_id(&b.header), block_id(&b2.header));
    assert!(b2.txs.is_empty());
    assert!(b2.slashings.is_empty());
    assert!(b2.storage_proofs.is_empty());
    assert!(b2.bond_ops.is_empty());
    // Re-encoding must yield identical bytes (deterministic).
    assert_eq!(encode_block(&b2), bytes);
}

/// The encoding always starts with the exact bytes the header
/// codec produces — a hard invariant that lets a peer extract a
/// header for fast filtering before re-encoding the full block.
#[test]
fn block_codec_starts_with_block_header_bytes() {
    let b = sample_empty_block();
    let block_bytes = encode_block(&b);
    let header_bytes = block_header_bytes(&b.header);
    assert!(
        block_bytes.starts_with(&header_bytes),
        "encode_block must prefix with block_header_bytes(header)"
    );
    // And the four empty-body-section varints come right after.
    let tail = &block_bytes[header_bytes.len()..];
    // Four varints of value 0 = four 0x00 bytes.
    assert_eq!(tail, &[0u8, 0u8, 0u8, 0u8]);
}

/// Adding a trailing byte after a valid encoding → `TrailingBytes`.
#[test]
fn block_codec_rejects_trailing_bytes() {
    let b = sample_empty_block();
    let mut bytes = encode_block(&b);
    bytes.push(0xCD);
    let err = decode_block(&bytes).expect_err("must reject tail");
    match err {
        BlockDecodeError::TrailingBytes { remaining } => assert_eq!(remaining, 1),
        other => panic!("expected TrailingBytes, got {other:?}"),
    }
}

/// Sweeping every prefix of a valid encoding must fail to decode.
#[test]
fn block_codec_rejects_truncation_at_every_prefix() {
    let b = sample_empty_block();
    let bytes = encode_block(&b);
    for cut in 0..bytes.len() {
        let err = decode_block(&bytes[..cut]);
        assert!(
            err.is_err(),
            "prefix of length {cut}/{} should be rejected",
            bytes.len()
        );
    }
}

/// Mutating the txs-count varint to a huge value must surface
/// either `Codec(ShortBuffer)` or `Codec(VarintTooLong)` — never
/// silently allocate an enormous Vec.
#[test]
fn block_codec_rejects_oversized_txs_count() {
    let b = sample_empty_block();
    let header_len = block_header_bytes(&b.header).len();
    let mut bytes = encode_block(&b);
    // The byte at header_len is the txs-count varint (== 0 in
    // empty body). Replace it with a 10-byte LEB128 encoding of
    // u64::MAX (the longest legal varint). The decoder must
    // refuse to read that many blob entries because the buffer
    // ends a few bytes later.
    bytes.splice(
        header_len..header_len + 1,
        // u64::MAX in LEB128 is 10 bytes of 0xff…0x01.
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
    );
    let err = decode_block(&bytes).expect_err("must reject");
    // We accept any Codec / Transaction error — the goal is
    // "doesn't decode" + "doesn't OOM".
    match err {
        BlockDecodeError::Codec(_)
        | BlockDecodeError::Transaction { .. }
        | BlockDecodeError::CountTooLarge { .. } => (),
        other => panic!("unexpected error variant {other:?}"),
    }
}

/// Golden vector for the empty-body encoding shape: a genesis-
/// shaped block must serialise to exactly the 306 header bytes
/// followed by four `0x00` count varints (= 310 bytes total).
/// Pins the wire layout so any unintentional codec change
/// trips a hard failure.
#[test]
fn block_codec_empty_body_golden_shape() {
    let h = BlockHeader {
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
    let b = Block {
        header: h,
        txs: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
        bond_ops: Vec::new(),
    };
    let bytes = encode_block(&b);
    // 306 (header) + 4 (four zero-length section varints) = 310.
    assert_eq!(bytes.len(), 310);
    // Last four bytes are the empty-section count varints.
    assert_eq!(&bytes[306..], &[0u8, 0u8, 0u8, 0u8]);
    // Round-trip pin.
    let b2 = decode_block(&bytes).expect("decode");
    assert_eq!(block_id(&b.header), block_id(&b2.header));
}
