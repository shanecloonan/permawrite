//! Validator-mode finality + validator-set evolution invariants.
//!
//! Covers pre-block finality quorum, pre-block `validator_root`, atomic
//! liveness stats/stake updates, header body-root binding (bond, slashing,
//! tx, storage_proof, claims, utxo, storage), unbond-settlement root evolution, equivocation during
//! unbond delay, entry/exit churn caps and epoch reset, duplicate/invalid slash
//! rejection, bond-op admission rejects (duplicate vrf, duplicate unbond,
//! stake below minimum, same-block register-then-unbond, same-block duplicate
//! vrf batch, zombie unbond, forged/unknown unbond, duplicate unbond after
//! pending request, bond rejection treasury preservation), chain linkage
//! (prev_hash), finality proof integrity (msg mismatch, tampered blob,
//! signing_stake claim, producer index), producer VRF/BLS verification
//! failures, aggregate signature integrity, bond epoch counter persistence,
//! checkpoint roundtrip of bond counters, missing/malformed producer proof,
//! explicit sub-quorum `QuorumNotMet`, zero-stake liveness skip after equivocation,
//! monotonic register index assignment, register stats/treasury credits,
//! slash-forfeiture treasury credits in validator mode, liveness sign resets
//! consecutive misses, unbond settlement clears pending queue, bond epoch rollover,
//! plus rejection preserving caller state.
//! Empty blocks only — no privacy txs, storage proofs, or coinbase.

use mfn_bls::{bls_keygen_from_seed, bls_sign};
use mfn_consensus::bond_wire::{sign_register, sign_unbond};
use mfn_consensus::bonding::{BondingParams, DEFAULT_BONDING_PARAMS};
use mfn_consensus::consensus::{
    cast_vote, decode_finality_proof, eligibility_threshold, encode_finality_proof, finalize,
    is_eligible, pick_winner, slot_seed, try_produce_slot, validator_set_root,
    verify_finality_proof, ConsensusCheck, FinalityProof, ProducerProof, SlotContext, Validator,
    ValidatorSecrets,
};
use mfn_consensus::{
    apply_block, apply_genesis, build_genesis, build_unsealed_header, decode_chain_checkpoint,
    encode_chain_checkpoint, header_signing_hash, seal_block, ApplyOutcome, Block, BlockError,
    BondOp, ChainCheckpoint, ChainState, ConsensusParams, GenesisConfig, SlashEvidence,
    ValidatorStats, DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::point::generator_g;
use mfn_crypto::vrf::{vrf_keygen_from_seed, vrf_prove};
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

struct Fixture {
    state: ChainState,
    secrets: Vec<ValidatorSecrets>,
    params: ConsensusParams,
}

fn mk_validator(i: u32, stake: u64) -> (Validator, ValidatorSecrets) {
    let vrf = vrf_keygen_from_seed(&[(i.wrapping_add(1)) as u8; 32]).expect("vrf");
    let bls = bls_keygen_from_seed(&[(i.wrapping_add(101)) as u8; 32]);
    let val = Validator {
        index: i,
        vrf_pk: vrf.pk,
        bls_pk: bls.pk,
        stake,
        payout: None,
    };
    let secrets = ValidatorSecrets { index: i, vrf, bls };
    (val, secrets)
}

fn boot_three_validators(liveness_max_missed: u32) -> Fixture {
    boot_three_validators_cfg(
        liveness_max_missed,
        DEFAULT_BONDING_PARAMS.unbond_delay_heights,
    )
}

/// Algorand-style `F = 1` with a dust-stake validator whose eligibility
/// threshold is negligible — used to deterministically exercise `NotEligible`.
fn boot_three_validators_strict_eligibility(liveness_max_missed: u32) -> Fixture {
    let (v0, s0) = mk_validator(0, 1);
    let (v1, s1) = mk_validator(1, 1_000_000);
    let (v2, s2) = mk_validator(2, 1_000_000);
    let validators = vec![v0, v1, v2];
    let secrets = vec![s0, s1, s2];
    let params = ConsensusParams {
        expected_proposers_per_slot: 1.0,
        quorum_stake_bps: 6667,
        liveness_max_consecutive_missed: liveness_max_missed,
        liveness_slash_bps: 100,
    };
    let bonding = BondingParams {
        min_validator_stake: 100_000,
        unbond_delay_heights: DEFAULT_BONDING_PARAMS.unbond_delay_heights,
        ..DEFAULT_BONDING_PARAMS
    };
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: validators.clone(),
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(bonding),
    };
    let genesis = build_genesis(&cfg);
    let state = apply_genesis(&genesis, &cfg).expect("genesis");
    Fixture {
        state,
        secrets,
        params,
    }
}

fn boot_three_validators_cfg(liveness_max_missed: u32, unbond_delay_heights: u32) -> Fixture {
    let (v0, s0) = mk_validator(0, 1_000_000);
    let (v1, s1) = mk_validator(1, 1_000_000);
    let (v2, s2) = mk_validator(2, 1_000_000);
    let validators = vec![v0, v1, v2];
    let secrets = vec![s0, s1, s2];
    let params = ConsensusParams {
        expected_proposers_per_slot: 10.0,
        quorum_stake_bps: 6667,
        liveness_max_consecutive_missed: liveness_max_missed,
        liveness_slash_bps: 100,
    };
    let bonding = BondingParams {
        min_validator_stake: 100_000,
        unbond_delay_heights,
        ..DEFAULT_BONDING_PARAMS
    };
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: validators.clone(),
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(bonding),
    };
    let genesis = build_genesis(&cfg);
    let state = apply_genesis(&genesis, &cfg).expect("genesis");
    Fixture {
        state,
        secrets,
        params,
    }
}

fn boot_three_validators_entry_churn_cfg(
    max_entry_churn_per_epoch: u32,
    slots_per_epoch: u32,
) -> Fixture {
    let (v0, s0) = mk_validator(0, 1_000_000);
    let (v1, s1) = mk_validator(1, 1_000_000);
    let (v2, s2) = mk_validator(2, 1_000_000);
    let validators = vec![v0, v1, v2];
    let secrets = vec![s0, s1, s2];
    let params = ConsensusParams {
        expected_proposers_per_slot: 10.0,
        quorum_stake_bps: 6667,
        liveness_max_consecutive_missed: 64,
        liveness_slash_bps: 0,
    };
    let bonding = BondingParams {
        min_validator_stake: 100_000,
        max_entry_churn_per_epoch,
        slots_per_epoch,
        ..DEFAULT_BONDING_PARAMS
    };
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: validators.clone(),
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(bonding),
    };
    let genesis = build_genesis(&cfg);
    let state = apply_genesis(&genesis, &cfg).expect("genesis");
    Fixture {
        state,
        secrets,
        params,
    }
}

/// Matches `boot_three_validators_entry_churn_cfg`'s lowered `min_validator_stake`.
const ENTRY_CHURN_REGISTER_STAKE: u64 = 100_000;

/// Four-validator chain with short unbond delay and a tight exit-churn cap.
fn boot_four_validators_exit_churn() -> Fixture {
    boot_four_validators_exit_churn_cfg(DEFAULT_BONDING_PARAMS.slots_per_epoch)
}

fn boot_four_validators_exit_churn_cfg(slots_per_epoch: u32) -> Fixture {
    let (v0, s0) = mk_validator(0, 1_000_000);
    let (v1, s1) = mk_validator(1, 1_000_000);
    let (v2, s2) = mk_validator(2, 1_000_000);
    let (v3, s3) = mk_validator(3, 1_000_000);
    let validators = vec![v0, v1, v2, v3];
    let secrets = vec![s0, s1, s2, s3];
    let params = ConsensusParams {
        expected_proposers_per_slot: 10.0,
        quorum_stake_bps: 5000,
        liveness_max_consecutive_missed: 64,
        liveness_slash_bps: 0,
    };
    let bonding = BondingParams {
        min_validator_stake: 100_000,
        unbond_delay_heights: 1,
        max_exit_churn_per_epoch: 2,
        slots_per_epoch,
        ..DEFAULT_BONDING_PARAMS
    };
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: validators.clone(),
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: Some(bonding),
    };
    let genesis = build_genesis(&cfg);
    let state = apply_genesis(&genesis, &cfg).expect("genesis");
    Fixture {
        state,
        secrets,
        params,
    }
}

fn register_op(stake: u64, seed: u8) -> BondOp {
    let vrf = vrf_keygen_from_seed(&[seed.wrapping_add(50); 32]).expect("vrf");
    let bls = bls_keygen_from_seed(&[seed.wrapping_add(150); 32]);
    BondOp::Register {
        stake,
        vrf_pk: vrf.pk,
        bls_pk: bls.pk,
        payout: None,
        sig: sign_register(stake, &vrf.pk, &bls.pk, None, &bls.sk),
    }
}

/// Attach BLS finality; `voter_positions` lists indices into `st.validators`.
fn attach_finality(
    st: &ChainState,
    fx: &Fixture,
    mut unsealed: mfn_consensus::BlockHeader,
    voter_positions: &[usize],
) -> (mfn_consensus::BlockHeader, Vec<u8>) {
    let total_stake: u64 = st.validators.iter().map(|v| v.stake).sum();
    let f = st.params.expected_proposers_per_slot;
    let base_slot = unsealed.slot;

    for bump in 0u32..=512 {
        unsealed.slot = base_slot.saturating_add(bump);
        let header_hash = header_signing_hash(&unsealed);
        let ctx = SlotContext {
            height: unsealed.height,
            slot: unsealed.slot,
            prev_hash: unsealed.prev_hash,
        };

        let mut candidates: Vec<ProducerProof> = Vec::new();
        for (i, v) in st.validators.iter().enumerate().take(fx.secrets.len()) {
            if let Ok(Some(p)) =
                try_produce_slot(&ctx, &fx.secrets[i], v, total_stake, f, &header_hash)
            {
                candidates.push(p);
            }
        }
        let Some(producer_proof) = pick_winner(&candidates).cloned() else {
            continue;
        };
        let producer_validator = st
            .validators
            .iter()
            .find(|v| v.index == producer_proof.validator_index)
            .expect("producer in set");

        let mut votes = Vec::new();
        let mut signing_stake = 0u64;
        for &pos in voter_positions {
            let v = &st.validators[pos];
            let vote = cast_vote(
                &header_hash,
                &fx.secrets[pos],
                &ctx,
                &producer_proof,
                producer_validator,
                total_stake,
                f,
            )
            .expect("vote");
            signing_stake = signing_stake.saturating_add(v.stake);
            votes.push(vote);
        }
        let agg = finalize(&header_hash, &votes, st.validators.len()).expect("finalize");
        let fin = FinalityProof {
            producer: producer_proof,
            finality: agg,
            signing_stake,
        };
        return (unsealed, encode_finality_proof(&fin));
    }
    panic!("no VRF-eligible producer in 512 slot attempts");
}

fn seal_empty(
    fx: &Fixture,
    st: &ChainState,
    height: u32,
    bond_ops: Vec<BondOp>,
    slashings: Vec<SlashEvidence>,
    voter_positions: &[usize],
) -> Block {
    let unsealed = build_unsealed_header(
        st,
        &[],
        &bond_ops,
        &slashings,
        &[],
        height,
        u64::from(height) * 100,
    );
    let (unsealed, fin) = attach_finality(st, fx, unsealed, voter_positions);
    seal_block(unsealed, Vec::new(), bond_ops, fin, slashings, Vec::new())
}

fn all_voter_positions(st: &ChainState) -> Vec<usize> {
    (0..st.validators.len()).collect()
}

/// Genesis committee positions — only these validators have BLS secrets in
/// the fixture, so post-`Register` blocks must not iterate new indices.
fn incumbent_voter_positions(fx: &Fixture) -> Vec<usize> {
    (0..fx.secrets.len()).collect()
}

fn snapshot(st: &ChainState) -> (Option<u32>, usize, Vec<u64>, Vec<ValidatorStats>) {
    (
        st.height,
        st.block_ids.len(),
        st.validators.iter().map(|v| v.stake).collect(),
        st.validator_stats.clone(),
    )
}

/// Finality quorum is checked against the pre-block validator set. A
/// same-block `Register` with huge stake must not raise the quorum bar
/// for the signatures already collected from the incumbent committee.
#[test]
fn finality_quorum_uses_pre_block_validator_set() {
    let fx = boot_three_validators(64);
    let pre = fx.state.clone();
    let pre_total: u64 = pre.validators.iter().map(|v| v.stake).sum();
    assert_eq!(pre_total, 3_000_000);

    let huge_stake = 9_000_000u64;
    let register = register_op(huge_stake, 7);
    let voters = all_voter_positions(&pre);
    let block = seal_empty(&fx, &pre, 1, vec![register], Vec::new(), &voters);

    let post = apply_block(&pre, &block)
        .into_state()
        .expect("register block must apply with pre-block quorum");
    assert_eq!(post.validators.len(), 4);
    assert_eq!(post.validators[3].stake, huge_stake);
    assert!(
        post.treasury >= u128::from(huge_stake),
        "register burns bonded stake into treasury"
    );

    let header_hash = header_signing_hash(&block.header);
    let ctx = SlotContext {
        height: block.header.height,
        slot: block.header.slot,
        prev_hash: block.header.prev_hash,
    };
    let fin = mfn_consensus::consensus::decode_finality_proof(&block.header.producer_proof)
        .expect("decode finality");

    let pre_check = verify_finality_proof(
        &ctx,
        &fin,
        &pre.validators,
        fx.params.expected_proposers_per_slot,
        fx.params.quorum_stake_bps,
        &header_hash,
    );
    assert_eq!(pre_check, ConsensusCheck::Ok);

    // Hypothetical post-register set would require ~8.67M signing stake;
    // the proof only covers the pre-block 3M committee.
    let post_check = verify_finality_proof(
        &ctx,
        &fin,
        &post.validators,
        fx.params.expected_proposers_per_slot,
        fx.params.quorum_stake_bps,
        &header_hash,
    );
    assert_eq!(
        post_check,
        ConsensusCheck::QuorumNotMet,
        "quorum must not be recomputed against post-block stake"
    );
}

/// `header.validator_root` commits to validators as they stood before
/// this block — including when the body carries a `Register` bond op.
#[test]
fn validator_root_is_pre_block_in_validator_mode() {
    let fx = boot_three_validators(64);
    let pre = fx.state.clone();
    let pre_root = validator_set_root(&pre.validators);

    let register = register_op(500_000, 9);
    let block = seal_empty(
        &fx,
        &pre,
        1,
        vec![register],
        Vec::new(),
        &all_voter_positions(&pre),
    );
    assert_eq!(
        block.header.validator_root, pre_root,
        "signed header must commit pre-block set"
    );

    let post = apply_block(&pre, &block)
        .into_state()
        .expect("apply register block");
    let post_root = validator_set_root(&post.validators);
    assert_ne!(pre_root, post_root, "register moves the live set root");

    let next_unsealed = build_unsealed_header(&post, &[], &[], &[], &[], 2, 200);
    assert_eq!(
        next_unsealed.validator_root, post_root,
        "successor header commits post-block-1 set"
    );
}

/// On acceptance, liveness counters and stake reduction from the finality
/// bitmap land in the same `apply_block` transition.
#[test]
fn liveness_bitmap_and_stats_evolve_atomically_on_accept() {
    let fx = boot_three_validators(2);
    let mut st = fx.state.clone();
    let mut params = fx.params;
    params.quorum_stake_bps = 6666;
    st.params = params;

    // v0 + v2 sign (2M); v1 missing — clears quorum at 6666 bps.
    let voters_miss_v1 = [0usize, 2];
    let block1 = seal_empty(&fx, &st, 1, Vec::new(), Vec::new(), &voters_miss_v1);
    st = apply_block(&st, &block1)
        .into_state()
        .expect("first miss block");
    assert_eq!(st.validator_stats[1].consecutive_missed, 1);
    assert_eq!(st.validator_stats[1].total_missed, 1);
    assert_eq!(st.validators[1].stake, 1_000_000);

    let block2 = seal_empty(&fx, &st, 2, Vec::new(), Vec::new(), &voters_miss_v1);
    st = apply_block(&st, &block2).into_state().expect("slash block");
    assert_eq!(st.validator_stats[1].liveness_slashes, 1);
    assert_eq!(st.validator_stats[1].consecutive_missed, 0);
    assert_eq!(
        st.validators[1].stake, 990_000,
        "slash applied with stats reset"
    );
    assert_eq!(st.validator_stats[0].total_signed, 2);
    assert_eq!(st.validator_stats[2].total_signed, 2);
}

/// A rejected block must not advance liveness stats even when the
/// finality bitmap would have recorded misses and a bond op fails last.
#[test]
fn liveness_stats_unchanged_when_block_rejected() {
    let fx = boot_three_validators(2);
    let mut st = fx.state.clone();
    let mut params = fx.params;
    params.quorum_stake_bps = 6666;
    st.params = params;

    let good = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    st = apply_block(&st, &good)
        .into_state()
        .expect("baseline block");
    let before = st.validator_stats.clone();

    let attacker = bls_keygen_from_seed(&[250u8; 32]);
    let victim = bls_keygen_from_seed(&[251u8; 32]);
    let vrf = vrf_keygen_from_seed(&[252u8; 32]).expect("vrf");
    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let bad_register = BondOp::Register {
        stake,
        vrf_pk: vrf.pk,
        bls_pk: victim.pk,
        payout: None,
        sig: sign_register(stake, &vrf.pk, &victim.pk, None, &attacker.sk),
    };

    let block = seal_empty(&fx, &st, 2, vec![bad_register], Vec::new(), &[0, 2]);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { .. })),
                "expected bond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("forged register must reject"),
    }
    assert_eq!(st.validator_stats, before, "stats untouched on rejection");
    assert_eq!(st.validators[1].stake, 1_000_000);
}

/// `apply_block` never mutates the caller's `ChainState` on failure.
#[test]
fn rejected_block_leaves_state_unchanged() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    // Sub-quorum finality at default 6667 bps (producer + one peer = 2/3 flat).
    let block = seal_empty(&fx, &st, 1, Vec::new(), Vec::new(), &[0, 1]);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::FinalityInvalid(_))),
                "expected finality rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("sub-quorum block must reject"),
    }
    assert_eq!(snapshot(&st), before);

    // Root tamper on an otherwise valid block.
    let mut valid = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    valid.header.validator_root[0] ^= 0xff;
    match apply_block(&st, &valid) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::ValidatorRootMismatch)),
                "expected root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Header `bond_root` must match the body's bond-op list; tampering
/// rejects before any validator-set mutation.
#[test]
fn bond_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.bond_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondRootMismatch)),
                "expected bond_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered bond_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Multiplicative liveness slash reduces stake; the successor header
/// must commit the post-slash validator set root.
#[test]
fn validator_root_moves_on_liveness_slash() {
    let fx = boot_three_validators(2);
    let mut st = fx.state.clone();
    let mut params = fx.params;
    params.quorum_stake_bps = 6666;
    st.params = params;
    let root_before = validator_set_root(&st.validators);

    let voters_miss_v1 = [0usize, 2];
    let block1 = seal_empty(&fx, &st, 1, Vec::new(), Vec::new(), &voters_miss_v1);
    st = apply_block(&st, &block1).into_state().expect("first miss");
    let block2 = seal_empty(&fx, &st, 2, Vec::new(), Vec::new(), &voters_miss_v1);
    st = apply_block(&st, &block2)
        .into_state()
        .expect("liveness slash");
    assert_eq!(st.validators[1].stake, 990_000);

    let root_after = validator_set_root(&st.validators);
    assert_ne!(
        root_before, root_after,
        "liveness slash must move validator_root"
    );

    let next = build_unsealed_header(&st, &[], &[], &[], &[], 3, 300);
    assert_eq!(
        next.validator_root, root_after,
        "successor header commits post-slash set"
    );
}

/// Equivocation evidence zeroes stake; the next header's
/// `validator_root` must reflect the slashed set.
#[test]
fn equivocation_slash_moves_successor_validator_root() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let root_before = validator_set_root(&st.validators);
    let v1_idx = st.validators[1].index;
    let v1_bls_sk = fx.secrets[1].bls.sk.clone();

    let h1 = [33u8; 32];
    let h2 = [44u8; 32];
    let evidence = SlashEvidence {
        height: 1,
        slot: 1,
        voter_index: v1_idx,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, &v1_bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, &v1_bls_sk),
    };
    let block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        vec![evidence],
        &all_voter_positions(&st),
    );
    assert_eq!(
        block.header.validator_root, root_before,
        "slash block still commits pre-block set"
    );

    let post = apply_block(&st, &block)
        .into_state()
        .expect("equivocation slash block");
    assert_eq!(post.validators[1].stake, 0);
    let root_after = validator_set_root(&post.validators);
    assert_ne!(root_before, root_after);

    let next = build_unsealed_header(&post, &[], &[], &[], &[], 2, 200);
    assert_eq!(next.validator_root, root_after);
}

/// Header `slashing_root` must match the body's slashings list even when
/// the list carries valid equivocation evidence.
#[test]
fn slashing_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let v1_idx = st.validators[1].index;
    let v1_bls_sk = fx.secrets[1].bls.sk.clone();

    let h1 = [55u8; 32];
    let h2 = [66u8; 32];
    let evidence = SlashEvidence {
        height: 1,
        slot: 1,
        voter_index: v1_idx,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, &v1_bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, &v1_bls_sk),
    };
    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        vec![evidence],
        &all_voter_positions(&st),
    );
    assert_ne!(block.header.slashing_root, [0u8; 32]);
    block.header.slashing_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::SlashingRootMismatch)),
                "expected slashing_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered slashing_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Requesting unbond enqueues exit but keeps stake and `validator_root`
/// stable until the delay elapses.
#[test]
fn unbond_request_preserves_validator_root_in_delay_window() {
    let fx = boot_three_validators_cfg(64, 2);
    let mut st = fx.state.clone();
    let root_genesis = validator_set_root(&st.validators);
    let v1_idx = st.validators[1].index;
    let unbond = BondOp::Unbond {
        validator_index: v1_idx,
        sig: sign_unbond(v1_idx, &fx.secrets[1].bls.sk),
    };

    let block1 = seal_empty(
        &fx,
        &st,
        1,
        vec![unbond],
        Vec::new(),
        &all_voter_positions(&st),
    );
    st = apply_block(&st, &block1)
        .into_state()
        .expect("unbond request block");
    assert_eq!(st.validators[1].stake, 1_000_000);
    assert_eq!(
        validator_set_root(&st.validators),
        root_genesis,
        "request alone must not move validator_root"
    );

    let block2 = seal_empty(
        &fx,
        &st,
        2,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    st = apply_block(&st, &block2)
        .into_state()
        .expect("delay window block");
    assert_eq!(
        validator_set_root(&st.validators),
        root_genesis,
        "delay window keeps validator_root stable"
    );
}

/// Unbond settlement zeroes stake; the successor header commits the
/// post-settlement validator set root.
#[test]
fn validator_root_moves_on_unbond_settlement() {
    let fx = boot_three_validators_cfg(64, 2);
    let mut st = fx.state.clone();
    let root_genesis = validator_set_root(&st.validators);
    let v1_idx = st.validators[1].index;
    let unbond = BondOp::Unbond {
        validator_index: v1_idx,
        sig: sign_unbond(v1_idx, &fx.secrets[1].bls.sk),
    };

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![unbond],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("unbond request");
    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            2,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("delay window");

    let block3 = seal_empty(
        &fx,
        &st,
        3,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    st = apply_block(&st, &block3)
        .into_state()
        .expect("unbond settlement");
    assert_eq!(st.validators[1].stake, 0);
    let root_after = validator_set_root(&st.validators);
    assert_ne!(
        root_genesis, root_after,
        "settlement must move validator_root"
    );

    let next = build_unsealed_header(&st, &[], &[], &[], &[], 4, 400);
    assert_eq!(
        next.validator_root, root_after,
        "successor header commits post-settlement set"
    );
}

/// Header `tx_root` must match the (empty) tx list on validator-mode blocks.
#[test]
fn tx_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.tx_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::TxRootMismatch)),
                "expected tx_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered tx_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Header `storage_proof_root` must match the (empty) proofs list.
#[test]
fn storage_proof_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    assert_eq!(block.header.storage_proof_root, [0u8; 32]);
    block.header.storage_proof_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofRootMismatch)),
                "expected storage_proof_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered storage_proof_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Header `claims_root` must match the (empty) authorship-claims list.
#[test]
fn claims_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.claims_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::ClaimsRootMismatch)),
                "expected claims_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered claims_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Header `utxo_root` must match the projected post-block accumulator.
#[test]
fn utxo_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.utxo_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::UtxoRootMismatch)),
                "expected utxo_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered utxo_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Header `storage_root` must match newly-anchored commitments (empty ⇒ zero).
#[test]
fn storage_root_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    assert_eq!(block.header.storage_root, [0u8; 32]);
    block.header.storage_root[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageRootMismatch)),
                "expected storage_root mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered storage_root must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// A validator who requested unbond remains slashable during the delay;
/// equivocation evidence still zeroes stake and moves `validator_root`.
#[test]
fn equivocation_during_unbond_delay_still_zeros_stake() {
    let fx = boot_three_validators_cfg(64, 100);
    let mut st = fx.state.clone();
    let root_before = validator_set_root(&st.validators);
    let v1_idx = st.validators[1].index;
    let v1_bls_sk = fx.secrets[1].bls.sk.clone();
    let unbond = BondOp::Unbond {
        validator_index: v1_idx,
        sig: sign_unbond(v1_idx, &v1_bls_sk),
    };

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![unbond],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("unbond request");
    assert_eq!(st.validators[1].stake, 1_000_000);
    assert!(st.pending_unbonds.contains_key(&v1_idx));

    let h1 = [11u8; 32];
    let h2 = [22u8; 32];
    let evidence = SlashEvidence {
        height: 2,
        slot: 2,
        voter_index: v1_idx,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, &v1_bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, &v1_bls_sk),
    };
    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            2,
            Vec::new(),
            vec![evidence],
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("equivocation during delay");
    assert_eq!(
        st.validators[1].stake, 0,
        "equivocation during unbond delay still zeros stake"
    );
    assert!(
        st.pending_unbonds.contains_key(&v1_idx),
        "pending unbond entry survives slash until settlement"
    );
    let root_after = validator_set_root(&st.validators);
    assert_ne!(root_before, root_after);
}

/// A block mixing invalid and valid slash evidence is rejected whole;
/// even the valid slash must not commit when any evidence fails.
#[test]
fn invalid_slash_evidence_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let v0_idx = st.validators[0].index;
    let v2_idx = st.validators[2].index;
    let v2_sk = fx.secrets[2].bls.sk.clone();

    let h_bad_a = [77u8; 32];
    let h_bad_b = [88u8; 32];
    let invalid = SlashEvidence {
        height: 1,
        slot: 1,
        voter_index: v0_idx,
        header_hash_a: h_bad_a,
        sig_a: bls_sign(&h_bad_a, &v2_sk),
        header_hash_b: h_bad_b,
        sig_b: bls_sign(&h_bad_b, &v2_sk),
    };
    let h_good_a = [99u8; 32];
    let h_good_b = [100u8; 32];
    let valid = SlashEvidence {
        height: 1,
        slot: 1,
        voter_index: v2_idx,
        header_hash_a: h_good_a,
        sig_a: bls_sign(&h_good_a, &v2_sk),
        header_hash_b: h_good_b,
        sig_b: bls_sign(&h_good_b, &v2_sk),
    };

    let block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        vec![invalid, valid],
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::SlashInvalid { .. })),
                "expected slash invalid, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("mixed slash evidence must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert_eq!(st.validators[2].stake, 1_000_000);
}

/// Per-epoch exit churn caps defer settlement beyond the first N due unbonds.
#[test]
fn exit_churn_cap_defers_third_unbond_settlement() {
    let fx = boot_four_validators_exit_churn();
    let mut st = fx.state.clone();
    let i1 = st.validators[1].index;
    let i2 = st.validators[2].index;
    let i3 = st.validators[3].index;
    let unbonds = vec![
        BondOp::Unbond {
            validator_index: i1,
            sig: sign_unbond(i1, &fx.secrets[1].bls.sk),
        },
        BondOp::Unbond {
            validator_index: i2,
            sig: sign_unbond(i2, &fx.secrets[2].bls.sk),
        },
        BondOp::Unbond {
            validator_index: i3,
            sig: sign_unbond(i3, &fx.secrets[3].bls.sk),
        },
    ];

    st = apply_block(
        &st,
        &seal_empty(&fx, &st, 1, unbonds, Vec::new(), &all_voter_positions(&st)),
    )
    .into_state()
    .expect("three unbond requests");
    assert_eq!(st.pending_unbonds.len(), 3);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            2,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("first settlement block");
    assert_eq!(st.pending_unbonds.len(), 1);
    assert!(st.pending_unbonds.contains_key(&i3));
    assert_eq!(st.validators[1].stake, 0);
    assert_eq!(st.validators[2].stake, 0);
    assert_eq!(st.validators[3].stake, 1_000_000);
    assert_eq!(st.bond_epoch_exit_count, 2);
}

/// Duplicate slash evidence for the same validator rejects the block whole.
#[test]
fn duplicate_slash_evidence_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let v2_idx = st.validators[2].index;
    let v2_sk = fx.secrets[2].bls.sk.clone();

    let first = SlashEvidence {
        height: 1,
        slot: 1,
        voter_index: v2_idx,
        header_hash_a: [41u8; 32],
        sig_a: bls_sign(&[41u8; 32], &v2_sk),
        header_hash_b: [42u8; 32],
        sig_b: bls_sign(&[42u8; 32], &v2_sk),
    };
    let duplicate = SlashEvidence {
        height: 1,
        slot: 1,
        voter_index: v2_idx,
        header_hash_a: [43u8; 32],
        sig_a: bls_sign(&[43u8; 32], &v2_sk),
        header_hash_b: [44u8; 32],
        sig_b: bls_sign(&[44u8; 32], &v2_sk),
    };

    let block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        vec![first, duplicate],
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::DuplicateSlash { .. })),
                "expected duplicate slash, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("duplicate slash evidence must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert_eq!(st.validators[2].stake, 1_000_000);
}

/// Exit-churn budget resets at the bond epoch boundary so deferred unbonds
/// can settle on the first block of the next epoch.
#[test]
fn exit_churn_cap_resets_at_epoch_boundary() {
    let fx = boot_four_validators_exit_churn_cfg(4);
    let mut st = fx.state.clone();
    let i1 = st.validators[1].index;
    let i2 = st.validators[2].index;
    let i3 = st.validators[3].index;
    let unbonds = vec![
        BondOp::Unbond {
            validator_index: i1,
            sig: sign_unbond(i1, &fx.secrets[1].bls.sk),
        },
        BondOp::Unbond {
            validator_index: i2,
            sig: sign_unbond(i2, &fx.secrets[2].bls.sk),
        },
        BondOp::Unbond {
            validator_index: i3,
            sig: sign_unbond(i3, &fx.secrets[3].bls.sk),
        },
    ];

    st = apply_block(
        &st,
        &seal_empty(&fx, &st, 1, unbonds, Vec::new(), &all_voter_positions(&st)),
    )
    .into_state()
    .expect("unbond requests");
    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            2,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("cap settles first two");
    assert_eq!(st.pending_unbonds.len(), 1);
    assert!(st.pending_unbonds.contains_key(&i3));

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            3,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("same epoch still capped");
    assert_eq!(st.pending_unbonds.len(), 1);
    assert_eq!(st.validators[3].stake, 1_000_000);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            4,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("new epoch settles deferred exit");
    assert!(!st.pending_unbonds.contains_key(&i3));
    assert_eq!(st.validators[3].stake, 0);
    assert_eq!(st.bond_epoch_exit_count, 1);
}

/// Per-epoch entry churn rejects a third `Register` in the same block.
#[test]
fn entry_churn_cap_rejects_third_register_without_state_change() {
    let fx = boot_three_validators_entry_churn_cfg(2, DEFAULT_BONDING_PARAMS.slots_per_epoch);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let stake = ENTRY_CHURN_REGISTER_STAKE;
    let ops = vec![
        register_op(stake, 10),
        register_op(stake, 11),
        register_op(stake, 12),
    ];
    let block = seal_empty(&fx, &st, 1, ops, Vec::new(), &all_voter_positions(&st));
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { index: 2, .. })),
                "expected third register rejected, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("third register must exceed entry churn cap"),
    }
    assert_eq!(snapshot(&st), before);
    assert_eq!(st.validators.len(), 3);
}

/// Two `Register` ops within the entry cap apply atomically and move
/// `validator_root` for the successor header.
#[test]
fn entry_churn_cap_allows_two_registers_and_moves_validator_root() {
    let fx = boot_three_validators_entry_churn_cfg(2, DEFAULT_BONDING_PARAMS.slots_per_epoch);
    let st = fx.state.clone();
    let pre_root = validator_set_root(&st.validators);
    let stake = ENTRY_CHURN_REGISTER_STAKE;
    let ops = vec![register_op(stake, 20), register_op(stake, 21)];
    let block = seal_empty(&fx, &st, 1, ops, Vec::new(), &all_voter_positions(&st));
    assert_eq!(block.header.validator_root, pre_root);

    let post = apply_block(&st, &block)
        .into_state()
        .expect("two registers within cap");
    assert_eq!(post.validators.len(), 5);
    assert_eq!(post.bond_epoch_entry_count, 2);
    let post_root = validator_set_root(&post.validators);
    assert_ne!(pre_root, post_root);

    let next = build_unsealed_header(&post, &[], &[], &[], &[], 2, 200);
    assert_eq!(next.validator_root, post_root);
}

/// Entry-churn budget resets at the bond epoch boundary.
#[test]
fn entry_churn_cap_resets_at_epoch_boundary() {
    let fx = boot_three_validators_entry_churn_cfg(2, 4);
    let mut st = fx.state.clone();
    let stake = ENTRY_CHURN_REGISTER_STAKE;

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(stake, 30), register_op(stake, 31)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("first two registers");
    assert_eq!(st.validators.len(), 5);
    assert_eq!(st.bond_epoch_entry_count, 2);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            2,
            Vec::new(),
            Vec::new(),
            &incumbent_voter_positions(&fx),
        ),
    )
    .into_state()
    .expect("advance to height 2");
    assert_eq!(st.height, Some(2));

    let after_two = st.clone();
    let block3 = seal_empty(
        &fx,
        &st,
        3,
        vec![register_op(stake, 32)],
        Vec::new(),
        &incumbent_voter_positions(&fx),
    );
    match apply_block(&st, &block3) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { index: 0, .. })),
                "expected entry cap rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("third register same epoch must reject"),
    }
    assert_eq!(st.validators.len(), after_two.validators.len());

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            3,
            Vec::new(),
            Vec::new(),
            &incumbent_voter_positions(&fx),
        ),
    )
    .into_state()
    .expect("advance to height 3 before epoch boundary");
    assert_eq!(st.height, Some(3));

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            4,
            vec![register_op(stake, 33), register_op(stake, 34)],
            Vec::new(),
            &incumbent_voter_positions(&fx),
        ),
    )
    .into_state()
    .expect("new epoch allows two more registers");
    assert_eq!(st.validators.len(), 7);
    assert_eq!(st.bond_epoch_entry_count, 2);
}

/// `Register` with a vrf_pk already in the active set rejects atomically.
#[test]
fn duplicate_vrf_register_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let dup_vrf = st.validators[0].vrf_pk;
    let bls = bls_keygen_from_seed(&[190u8; 32]);
    let dup_register = BondOp::Register {
        stake,
        vrf_pk: dup_vrf,
        bls_pk: bls.pk,
        payout: None,
        sig: sign_register(stake, &dup_vrf, &bls.pk, None, &bls.sk),
    };
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![dup_register],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("duplicate vrf_pk")
                    )
                }),
                "expected duplicate vrf rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("duplicate vrf register must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Two `Unbond` ops for the same validator in one block reject atomically.
#[test]
fn duplicate_unbond_enqueue_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let idx = st.validators[1].index;
    let sig = sign_unbond(idx, &fx.secrets[1].bls.sk);
    let ops = vec![
        BondOp::Unbond {
            validator_index: idx,
            sig,
        },
        BondOp::Unbond {
            validator_index: idx,
            sig: sign_unbond(idx, &fx.secrets[1].bls.sk),
        },
    ];
    let block = seal_empty(&fx, &st, 1, ops, Vec::new(), &all_voter_positions(&st));
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 1,
                            message,
                            ..
                        } if message.contains("pending unbond")
                    )
                }),
                "expected duplicate unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("duplicate unbond enqueue must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert!(st.pending_unbonds.is_empty());
}

/// Stake below `min_validator_stake` rejects without mutating chain state.
#[test]
fn register_stake_below_minimum_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let below_min = st.bonding_params.min_validator_stake - 1;
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![register_op(below_min, 41)],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("min_validator_stake")
                    )
                }),
                "expected stake minimum rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("sub-minimum register must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Same-block `Register` then `Unbond` of the new validator rejects atomically
/// because unbond resolves only against the pre-block validator set.
#[test]
fn same_block_register_then_unbond_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let reg = register_op(stake, 42);
    let new_index = st.next_validator_index;
    let bls = bls_keygen_from_seed(&[192u8; 32]);
    let unbond_new = BondOp::Unbond {
        validator_index: new_index,
        sig: sign_unbond(new_index, &bls.sk),
    };
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![reg, unbond_new],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 1,
                            message,
                            ..
                        } if message.contains("unknown validator")
                    )
                }),
                "expected same-block register-then-unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("same-block register-then-unbond must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert_eq!(st.validators.len(), 3);
}

/// Two `Register` ops sharing a vrf_pk in one block reject at the second op.
#[test]
fn same_block_duplicate_vrf_register_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let stake = st.bonding_params.min_validator_stake;
    let vrf = vrf_keygen_from_seed(&[60u8; 32]).expect("vrf");
    let bls0 = bls_keygen_from_seed(&[161u8; 32]);
    let bls1 = bls_keygen_from_seed(&[162u8; 32]);
    let ops = vec![
        BondOp::Register {
            stake,
            vrf_pk: vrf.pk,
            bls_pk: bls0.pk,
            payout: None,
            sig: sign_register(stake, &vrf.pk, &bls0.pk, None, &bls0.sk),
        },
        BondOp::Register {
            stake,
            vrf_pk: vrf.pk,
            bls_pk: bls1.pk,
            payout: None,
            sig: sign_register(stake, &vrf.pk, &bls1.pk, None, &bls1.sk),
        },
    ];
    let block = seal_empty(&fx, &st, 1, ops, Vec::new(), &all_voter_positions(&st));
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 1,
                            message,
                            ..
                        } if message.contains("duplicate vrf_pk")
                    )
                }),
                "expected same-block duplicate vrf rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("same-block duplicate vrf must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// `Unbond` of a settled zombie (`stake == 0`) rejects atomically.
#[test]
fn unbond_zombie_validator_rejects_without_state_change() {
    let fx = boot_three_validators_cfg(64, 2);
    let mut st = fx.state.clone();
    let v1_idx = st.validators[1].index;
    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![BondOp::Unbond {
                validator_index: v1_idx,
                sig: sign_unbond(v1_idx, &fx.secrets[1].bls.sk),
            }],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("unbond request");
    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            2,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("delay window");
    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            3,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("settlement");
    assert_eq!(st.validators[1].stake, 0);

    let before = snapshot(&st);
    let block = seal_empty(
        &fx,
        &st,
        4,
        vec![BondOp::Unbond {
            validator_index: v1_idx,
            sig: sign_unbond(v1_idx, &fx.secrets[1].bls.sk),
        }],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("zombie")
                    )
                }),
                "expected zombie unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("unbond of zombie must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Forged `Unbond` signature rejects without mutating chain state.
#[test]
fn forged_unbond_signature_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let idx = st.validators[1].index;
    let attacker = bls_keygen_from_seed(&[253u8; 32]);
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![BondOp::Unbond {
            validator_index: idx,
            sig: sign_unbond(idx, &attacker.sk),
        }],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("unbond signature invalid")
                    )
                }),
                "expected forged unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("forged unbond must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert!(st.pending_unbonds.is_empty());
}

/// `Unbond` referencing an unknown validator index rejects atomically.
#[test]
fn unbond_unknown_validator_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let bls = bls_keygen_from_seed(&[254u8; 32]);
    let unknown = st.next_validator_index;
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![BondOp::Unbond {
            validator_index: unknown,
            sig: sign_unbond(unknown, &bls.sk),
        }],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("unknown validator")
                    )
                }),
                "expected unknown validator unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("unbond of unknown validator must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Failed bond ops must not credit treasury — register burn is all-or-nothing.
#[test]
fn bond_rejection_leaves_treasury_unchanged() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let treasury_before = st.treasury;
    let attacker = bls_keygen_from_seed(&[240u8; 32]);
    let victim = bls_keygen_from_seed(&[241u8; 32]);
    let vrf = vrf_keygen_from_seed(&[242u8; 32]).expect("vrf");
    let stake = st.bonding_params.min_validator_stake;
    let bad_register = BondOp::Register {
        stake,
        vrf_pk: vrf.pk,
        bls_pk: victim.pk,
        payout: None,
        sig: sign_register(stake, &vrf.pk, &victim.pk, None, &attacker.sk),
    };
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![bad_register],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { .. })),
                "expected bond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("forged register must reject"),
    }
    assert_eq!(st.treasury, treasury_before);
    assert_eq!(st.validators.len(), 3);
}

/// Second `Unbond` for a validator who already has a pending exit rejects.
#[test]
fn duplicate_unbond_after_pending_request_rejects_without_state_change() {
    let fx = boot_three_validators_cfg(64, 4);
    let mut st = fx.state.clone();
    let idx = st.validators[1].index;
    let unbond = BondOp::Unbond {
        validator_index: idx,
        sig: sign_unbond(idx, &fx.secrets[1].bls.sk),
    };
    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![unbond],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("first unbond request");
    assert_eq!(st.pending_unbonds.len(), 1);

    let before = snapshot(&st);
    let treasury_before = st.treasury;
    let block2 = seal_empty(
        &fx,
        &st,
        2,
        vec![BondOp::Unbond {
            validator_index: idx,
            sig: sign_unbond(idx, &fx.secrets[1].bls.sk),
        }],
        Vec::new(),
        &all_voter_positions(&st),
    );
    match apply_block(&st, &block2) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BondOpRejected {
                            index: 0,
                            message,
                            ..
                        } if message.contains("pending unbond")
                    )
                }),
                "expected duplicate pending unbond rejection, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("second unbond while pending must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert_eq!(st.treasury, treasury_before);
    assert_eq!(st.pending_unbonds.len(), 1);
}

/// Wrong `prev_hash` breaks chain linkage before any state mutation.
#[test]
fn prev_hash_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.prev_hash[0] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::PrevHashMismatch)),
                "expected prev_hash mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("wrong prev_hash must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Finality aggregate message must match `header_signing_hash`.
#[test]
fn finality_msg_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    let mut fin =
        decode_finality_proof(&block.header.producer_proof).expect("decode producer proof");
    fin.finality.msg[0] ^= 0xff;
    block.header.producer_proof = encode_finality_proof(&fin);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::FinalityInvalid(ConsensusCheck::FinalityMsgMismatch)
                    )
                }),
                "expected finality msg mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("finality msg mismatch must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Post-seal tampering of `producer_proof` invalidates finality verification.
#[test]
fn tampered_producer_proof_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    assert!(
        !block.header.producer_proof.is_empty(),
        "validator-mode block must carry producer proof"
    );
    block.header.producer_proof[10] ^= 0xff;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::FinalityInvalid(_))),
                "expected finality invalidation, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("tampered producer_proof must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Bond epoch entry counters survive empty blocks until the epoch rolls.
#[test]
fn bond_epoch_entry_count_persists_across_empty_blocks() {
    let fx = boot_three_validators(64);
    let mut st = fx.state.clone();
    let epoch0 = st.bond_epoch_id;

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(ENTRY_CHURN_REGISTER_STAKE, 70)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("one register");
    assert_eq!(st.bond_epoch_entry_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            2,
            Vec::new(),
            Vec::new(),
            &incumbent_voter_positions(&fx),
        ),
    )
    .into_state()
    .expect("empty block 2");
    assert_eq!(st.bond_epoch_entry_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            3,
            Vec::new(),
            Vec::new(),
            &incumbent_voter_positions(&fx),
        ),
    )
    .into_state()
    .expect("empty block 3");
    assert_eq!(st.bond_epoch_entry_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);
    assert_eq!(st.validators.len(), 4);
}

/// Block height must equal `state.height + 1`.
#[test]
fn bad_height_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.height = 99;
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::BadHeight {
                            expected: 1,
                            got: 99
                        }
                    )
                }),
                "expected bad height, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("wrong height must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Cached `signing_stake` must match the BLS finality bitmap stake sum.
#[test]
fn signing_stake_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    let mut fin =
        decode_finality_proof(&block.header.producer_proof).expect("decode producer proof");
    fin.signing_stake = fin.signing_stake.saturating_add(1);
    block.header.producer_proof = encode_finality_proof(&fin);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::FinalityInvalid(ConsensusCheck::SigningStakeMismatch)
                    )
                }),
                "expected signing_stake mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("signing_stake mismatch must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Producer `validator_index` must exist in the pre-block validator set.
#[test]
fn producer_not_in_set_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    let mut fin =
        decode_finality_proof(&block.header.producer_proof).expect("decode producer proof");
    fin.producer.validator_index = st.next_validator_index;
    block.header.producer_proof = encode_finality_proof(&fin);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::FinalityInvalid(ConsensusCheck::ProducerNotInSet)
                    )
                }),
                "expected producer not in set, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("unknown producer index must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Bond epoch exit counters survive empty blocks until the epoch rolls.
#[test]
fn bond_epoch_exit_count_persists_across_empty_blocks() {
    let fx = boot_four_validators_exit_churn_cfg(DEFAULT_BONDING_PARAMS.slots_per_epoch);
    let mut st = fx.state.clone();
    let epoch0 = st.bond_epoch_id;
    let idx = st.validators[1].index;

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![BondOp::Unbond {
                validator_index: idx,
                sig: sign_unbond(idx, &fx.secrets[1].bls.sk),
            }],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("unbond request");
    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            2,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("unbond settlement");
    assert_eq!(st.bond_epoch_exit_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);
    assert_eq!(st.validators[1].stake, 0);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            3,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("empty block 3");
    assert_eq!(st.bond_epoch_exit_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            4,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("empty block 4");
    assert_eq!(st.bond_epoch_exit_count, 1);
    assert_eq!(st.bond_epoch_id, epoch0);
}

/// Invalid producer BLS signature fails finality verification.
#[test]
fn producer_sig_invalid_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    let mut fin =
        decode_finality_proof(&block.header.producer_proof).expect("decode producer proof");
    let attacker = bls_keygen_from_seed(&[240u8; 32]);
    fin.producer.producer_sig = bls_sign(&header_signing_hash(&block.header), &attacker.sk);
    block.header.producer_proof = encode_finality_proof(&fin);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::FinalityInvalid(ConsensusCheck::ProducerSigInvalid)
                    )
                }),
                "expected producer sig invalid, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("invalid producer sig must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Corrupt VRF proof bytes fail producer verification.
#[test]
fn vrf_invalid_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    let mut fin =
        decode_finality_proof(&block.header.producer_proof).expect("decode producer proof");
    fin.producer.vrf_proof.gamma = generator_g();
    block.header.producer_proof = encode_finality_proof(&fin);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(e, BlockError::FinalityInvalid(ConsensusCheck::VrfInvalid))
                }),
                "expected vrf invalid, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("invalid vrf must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Stated `beta` must match the verified VRF output.
#[test]
fn vrf_output_mismatch_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    let mut fin =
        decode_finality_proof(&block.header.producer_proof).expect("decode producer proof");
    fin.producer.beta[0] ^= 0xff;
    block.header.producer_proof = encode_finality_proof(&fin);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::FinalityInvalid(ConsensusCheck::VrfOutputMismatch)
                    )
                }),
                "expected vrf output mismatch, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("vrf output mismatch must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// BLS aggregate over the committee vote set must verify under validator keys.
#[test]
fn aggregate_invalid_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    let mut fin =
        decode_finality_proof(&block.header.producer_proof).expect("decode producer proof");
    let attacker = bls_keygen_from_seed(&[241u8; 32]);
    fin.finality.agg_sig = bls_sign(&header_signing_hash(&block.header), &attacker.sk);
    block.header.producer_proof = encode_finality_proof(&fin);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(
                        e,
                        BlockError::FinalityInvalid(ConsensusCheck::AggregateInvalid)
                    )
                }),
                "expected aggregate invalid, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("invalid aggregate must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Bond epoch counters and validator set survive chain-checkpoint encode/decode.
#[test]
fn bond_epoch_counters_persist_in_chain_checkpoint_roundtrip() {
    let fx = boot_three_validators(64);
    let mut st = fx.state.clone();
    let genesis_id = st.block_ids[0];

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(ENTRY_CHURN_REGISTER_STAKE, 80)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("register block");
    assert_eq!(st.bond_epoch_entry_count, 1);
    assert_eq!(st.validators.len(), 4);

    let cp = ChainCheckpoint {
        genesis_id,
        state: st.clone(),
    };
    let restored = decode_chain_checkpoint(&encode_chain_checkpoint(&cp)).expect("roundtrip");
    assert_eq!(restored.genesis_id, genesis_id);
    assert_eq!(restored.state.bond_epoch_id, st.bond_epoch_id);
    assert_eq!(
        restored.state.bond_epoch_entry_count,
        st.bond_epoch_entry_count
    );
    assert_eq!(
        restored.state.bond_epoch_exit_count,
        st.bond_epoch_exit_count
    );
    assert_eq!(restored.state.next_validator_index, st.next_validator_index);
    assert_eq!(restored.state.validators.len(), st.validators.len());
    assert_eq!(
        validator_set_root(&restored.state.validators),
        validator_set_root(&st.validators)
    );
}

fn ineligible_producer_at_ctx(
    fx: &Fixture,
    st: &ChainState,
    ctx: &SlotContext,
    header_hash: &[u8; 32],
) -> Option<ProducerProof> {
    let total_stake: u64 = st.validators.iter().map(|v| v.stake).sum();
    let f = st.params.expected_proposers_per_slot;
    let seed = slot_seed(ctx);
    for (i, v) in st.validators.iter().enumerate().take(fx.secrets.len()) {
        let res = vrf_prove(&fx.secrets[i].vrf, &seed).ok()?;
        let threshold = eligibility_threshold(v.stake, total_stake, f);
        if !is_eligible(&res.output, threshold) {
            return Some(ProducerProof {
                validator_index: v.index,
                beta: res.output,
                vrf_proof: res.proof,
                producer_sig: bls_sign(header_hash, &fx.secrets[i].bls.sk),
            });
        }
    }
    None
}

/// VRF output at or above the eligibility threshold is rejected as producer.
#[test]
fn producer_not_eligible_rejects_without_state_change() {
    let fx = boot_three_validators_strict_eligibility(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    let ctx = SlotContext {
        height: block.header.height,
        slot: block.header.slot,
        prev_hash: block.header.prev_hash,
    };
    let header_hash = header_signing_hash(&block.header);
    let ineligible = ineligible_producer_at_ctx(&fx, &st, &ctx, &header_hash)
        .expect("at least one validator ineligible at sealed slot");
    let mut fin =
        decode_finality_proof(&block.header.producer_proof).expect("decode producer proof");
    fin.producer = ineligible;
    block.header.producer_proof = encode_finality_proof(&fin);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(e, BlockError::FinalityInvalid(ConsensusCheck::NotEligible))
                }),
                "expected not eligible, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("ineligible producer must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Validator-mode blocks must carry a non-empty `producer_proof`.
#[test]
fn missing_producer_proof_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.producer_proof.clear();
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::MissingProducerProof)),
                "expected missing producer proof, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("empty producer_proof must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Truncated `producer_proof` bytes fail decode before state mutation.
#[test]
fn finality_decode_error_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let mut block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        Vec::new(),
        &all_voter_positions(&st),
    );
    block.header.producer_proof.truncate(8);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::FinalityDecode(_))),
                "expected finality decode error, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("truncated producer_proof must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Sub-quorum BLS finality must surface `QuorumNotMet` through `apply_block`.
#[test]
fn sub_quorum_finality_rejects_with_quorum_not_met() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);

    let block = seal_empty(&fx, &st, 1, Vec::new(), Vec::new(), &[0, 1]);
    match apply_block(&st, &block) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| {
                    matches!(e, BlockError::FinalityInvalid(ConsensusCheck::QuorumNotMet))
                }),
                "expected quorum not met, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("sub-quorum block must reject"),
    }
    assert_eq!(snapshot(&st), before);
}

/// Equivocation-zeroed validators are zombies; liveness must not touch them.
#[test]
fn liveness_skips_zero_stake_validator_after_equivocation() {
    let fx = boot_three_validators(64);
    let mut st = fx.state.clone();
    let v1_idx = st.validators[1].index;
    let v1_bls_sk = fx.secrets[1].bls.sk.clone();

    let h1 = [33u8; 32];
    let h2 = [44u8; 32];
    let evidence = SlashEvidence {
        height: 1,
        slot: 1,
        voter_index: v1_idx,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, &v1_bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, &v1_bls_sk),
    };
    let slash_block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        vec![evidence],
        &all_voter_positions(&st),
    );
    st = apply_block(&st, &slash_block)
        .into_state()
        .expect("equivocation slash");
    assert_eq!(st.validators[1].stake, 0);
    let stats_after_slash = st.validator_stats[1];

    let mut params = fx.params;
    params.quorum_stake_bps = 6666;
    st.params = params;
    let miss_v1 = seal_empty(&fx, &st, 2, Vec::new(), Vec::new(), &[0, 2]);
    st = apply_block(&st, &miss_v1)
        .into_state()
        .expect("miss block without v1 in bitmap");
    assert_eq!(
        st.validator_stats[1], stats_after_slash,
        "zero-stake validator stats must not evolve"
    );
    assert_eq!(st.validators[1].stake, 0);
}

/// Successful `Register` assigns `next_validator_index` monotonically.
#[test]
fn register_assigns_monotonic_validator_index() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    assert_eq!(st.next_validator_index, 3);

    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let block = seal_empty(
        &fx,
        &st,
        1,
        vec![register_op(stake, 40)],
        Vec::new(),
        &all_voter_positions(&st),
    );
    let post = apply_block(&st, &block)
        .into_state()
        .expect("register block");
    assert_eq!(post.validators.len(), 4);
    assert_eq!(post.validators[3].index, 3);
    assert_eq!(post.next_validator_index, 4);
    assert_eq!(post.bond_epoch_entry_count, 1);
}

/// Successful `Register` extends `validator_stats` in lockstep with the set.
#[test]
fn register_extends_validator_stats() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    assert_eq!(st.validator_stats.len(), 3);

    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let post = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(stake, 41)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("register block");
    assert_eq!(post.validators.len(), 4);
    assert_eq!(post.validator_stats.len(), 4);
    assert_eq!(post.validator_stats[3], ValidatorStats::default());
}

/// Successful `Register` burns bonded stake into the permanence treasury.
#[test]
fn register_success_credits_treasury() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    assert_eq!(st.treasury, 0);

    let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
    let post = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(stake, 42)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("register block");
    assert_eq!(post.treasury, u128::from(stake));
}

/// Equivocation forfeiture credits treasury through validator-mode `apply_block`.
#[test]
fn equivocation_slash_credits_treasury_in_validator_mode() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    assert_eq!(st.treasury, 0);
    let v1_idx = st.validators[1].index;
    let v1_bls_sk = fx.secrets[1].bls.sk.clone();

    let h1 = [33u8; 32];
    let h2 = [44u8; 32];
    let evidence = SlashEvidence {
        height: 1,
        slot: 1,
        voter_index: v1_idx,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, &v1_bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, &v1_bls_sk),
    };
    let post = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            Vec::new(),
            vec![evidence],
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("equivocation slash block");
    assert_eq!(post.validators[1].stake, 0);
    assert_eq!(post.treasury, 1_000_000);
}

/// Liveness slash forfeiture credits treasury through validator-mode `apply_block`.
#[test]
fn liveness_slash_credits_treasury_in_validator_mode() {
    let fx = boot_three_validators(2);
    let mut st = fx.state.clone();
    let mut params = fx.params;
    params.quorum_stake_bps = 6666;
    st.params = params;
    assert_eq!(st.treasury, 0);

    let voters_miss_v1 = [0usize, 2];
    st = apply_block(
        &st,
        &seal_empty(&fx, &st, 1, Vec::new(), Vec::new(), &voters_miss_v1),
    )
    .into_state()
    .expect("first miss");
    st = apply_block(
        &st,
        &seal_empty(&fx, &st, 2, Vec::new(), Vec::new(), &voters_miss_v1),
    )
    .into_state()
    .expect("liveness slash");
    assert_eq!(st.validators[1].stake, 990_000);
    assert_eq!(st.treasury, 10_000);
}

/// Signing after consecutive misses resets the counter without slashing.
#[test]
fn liveness_signed_clears_consecutive_missed_in_validator_mode() {
    let fx = boot_three_validators(64);
    let mut st = fx.state.clone();
    let mut params = fx.params;
    params.quorum_stake_bps = 6666;
    st.params = params;
    let miss_v1 = [0usize, 2];

    for height in 1..=30 {
        st = apply_block(
            &st,
            &seal_empty(&fx, &st, height, Vec::new(), Vec::new(), &miss_v1),
        )
        .into_state()
        .expect("miss block");
    }
    assert_eq!(st.validator_stats[1].consecutive_missed, 30);
    assert_eq!(st.validators[1].stake, 1_000_000);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            31,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("full quorum block");
    assert_eq!(st.validator_stats[1].consecutive_missed, 0);
    assert_eq!(st.validator_stats[1].total_signed, 1);
    assert_eq!(st.validator_stats[1].liveness_slashes, 0);
    assert_eq!(st.validators[1].stake, 1_000_000);
}

/// Unbond settlement removes the pending exit entry from chain state.
#[test]
fn unbond_settlement_clears_pending_unbond_in_validator_mode() {
    let fx = boot_three_validators_cfg(64, 2);
    let mut st = fx.state.clone();
    let v1_idx = st.validators[1].index;
    let unbond = BondOp::Unbond {
        validator_index: v1_idx,
        sig: sign_unbond(v1_idx, &fx.secrets[1].bls.sk),
    };

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![unbond],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("unbond request");
    assert!(st.pending_unbonds.contains_key(&v1_idx));

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            2,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("delay window");
    assert!(st.pending_unbonds.contains_key(&v1_idx));

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            3,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("settlement");
    assert!(!st.pending_unbonds.contains_key(&v1_idx));
    assert_eq!(st.validators[1].stake, 0);
}

/// Empty blocks at the epoch boundary roll `bond_epoch_id` and reset churn counters.
#[test]
fn bond_epoch_id_increments_at_epoch_boundary() {
    let fx = boot_three_validators_entry_churn_cfg(2, 4);
    let mut st = fx.state.clone();
    let stake = ENTRY_CHURN_REGISTER_STAKE;
    assert_eq!(st.bond_epoch_id, 0);

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            vec![register_op(stake, 50), register_op(stake, 51)],
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("two registers in epoch 0");
    assert_eq!(st.bond_epoch_entry_count, 2);
    assert_eq!(st.bond_epoch_id, 0);

    for height in 2..=3 {
        st = apply_block(
            &st,
            &seal_empty(
                &fx,
                &st,
                height,
                Vec::new(),
                Vec::new(),
                &incumbent_voter_positions(&fx),
            ),
        )
        .into_state()
        .expect("advance within epoch 0");
    }

    st = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            4,
            Vec::new(),
            Vec::new(),
            &incumbent_voter_positions(&fx),
        ),
    )
    .into_state()
    .expect("first block of epoch 1");
    assert_eq!(st.bond_epoch_id, 1);
    assert_eq!(st.bond_epoch_entry_count, 0);
    assert_eq!(st.bond_epoch_exit_count, 0);
}
