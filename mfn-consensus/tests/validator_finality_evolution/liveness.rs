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
    header_signing_hash, ApplyOutcome, Block, BlockError, BondOp, ChainCheckpoint,
    EquivocationEvidence, SlashEvidence, ValidatorStats,
};
use mfn_crypto::point::generator_g;
use mfn_crypto::vrf::vrf_keygen_from_seed;

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

/// Sub-quorum finality must not advance liveness stats even when the
/// finality bitmap would record misses for absent validators.
#[test]
fn liveness_stats_unchanged_on_subquorum_finality_reject() {
    let fx = boot_three_validators(2);
    let mut st = fx.state.clone();

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

    // v0 + v1 sign (2M); v2 missing — below 6667 bps quorum on 3M total.
    let block = seal_empty(&fx, &st, 2, Vec::new(), Vec::new(), &[0, 1]);
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
    assert_eq!(st.validator_stats, before);
    assert_eq!(st.validators[2].stake, 1_000_000);
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

/// Equivocation-zeroed validators are zombies; liveness must not touch them.
#[test]
fn liveness_skips_zero_stake_validator_after_equivocation() {
    let fx = boot_three_validators(64);
    let mut st = fx.state.clone();
    let v1_idx = st.validators[1].index;
    let v1_bls_sk = fx.secrets[1].bls.sk.clone();

    let h1 = [33u8; 32];
    let h2 = [44u8; 32];
    let evidence = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: v1_idx,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, &v1_bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, &v1_bls_sk),
    });
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
