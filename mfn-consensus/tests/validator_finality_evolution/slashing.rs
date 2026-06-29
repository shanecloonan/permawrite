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
