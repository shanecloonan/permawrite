//! Validator-mode finality + validator-set evolution invariants.
//!
//! Covers pre-block finality quorum, pre-block `validator_root`, atomic
//! liveness stats/stake updates, and rejection preserving caller state.
//! Empty blocks only — no privacy txs, storage proofs, or coinbase.

use mfn_bls::{bls_keygen_from_seed, bls_sign};
use mfn_consensus::bond_wire::sign_register;
use mfn_consensus::bonding::{BondingParams, DEFAULT_BONDING_PARAMS};
use mfn_consensus::consensus::{
    cast_vote, encode_finality_proof, finalize, pick_winner, try_produce_slot, validator_set_root,
    verify_finality_proof, ConsensusCheck, FinalityProof, ProducerProof, SlotContext, Validator,
    ValidatorSecrets,
};
use mfn_consensus::{
    apply_block, apply_genesis, build_genesis, build_unsealed_header, header_signing_hash,
    seal_block, ApplyOutcome, Block, BlockError, BondOp, ChainState, ConsensusParams,
    GenesisConfig, SlashEvidence, ValidatorStats, DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::vrf::vrf_keygen_from_seed;
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
        for (i, v) in st.validators.iter().enumerate() {
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
