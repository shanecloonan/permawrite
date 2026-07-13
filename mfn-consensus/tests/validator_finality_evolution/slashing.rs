use crate::support::*;
use mfn_bls::{bls_keygen_from_seed, bls_sign};
use mfn_consensus::bond_wire::{sign_register, sign_unbond};
use mfn_consensus::bonding::DEFAULT_BONDING_PARAMS;
use mfn_consensus::coinbase::{build_coinbase, PayoutAddress};
use mfn_consensus::consensus::{
    decode_finality_proof, encode_finality_proof, encode_producer_proof, slot_seed,
    validator_set_root, verify_finality_proof, ConsensusCheck, FinalityProof, ProducerProof,
    SlotContext,
};
use mfn_consensus::emission::producer_portion_amount;
use mfn_consensus::fraud_proof::{
    encode_coinbase_amount_fraud_proof, CoinbaseAmountFraudProof, COINBASE_FRAUD_PROOF_VERSION,
};
use mfn_consensus::slashing::{
    verify_invalid_block_evidence, InvalidBlockEvidence, InvalidBlockEvidenceCheck, SlashEvidence,
};
use mfn_consensus::{
    apply_block, block_id, build_unsealed_header, decode_chain_checkpoint, encode_chain_checkpoint,
    header_signing_hash, seal_block, ApplyOutcome, Block, BlockError, BondOp, ChainCheckpoint,
    ChainState, EquivocationEvidence, ValidatorStats, DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::point::generator_g;
use mfn_crypto::stealth::stealth_gen;
use mfn_crypto::vrf::{vrf_keygen_from_seed, vrf_prove};

/// Build invalid-block slash evidence for a coinbase-amount fraud at `height`.
fn coinbase_fraud_invalid_block_evidence(
    fx: &Fixture,
    st: &ChainState,
    height: u32,
    producer_pos: usize,
) -> SlashEvidence {
    let w = stealth_gen();
    let payout = PayoutAddress {
        view_pub: w.view_pub,
        spend_pub: w.spend_pub,
    };
    let fee_sum = 0u128;
    let expected = producer_portion_amount(u64::from(height), &DEFAULT_EMISSION_PARAMS, fee_sum);
    let wrong_cb = build_coinbase(u64::from(height), expected.saturating_add(1), &payout)
        .expect("wrong coinbase");
    let mut unsealed = build_unsealed_header(
        st,
        std::slice::from_ref(&wrong_cb),
        &[],
        &[],
        &[],
        height,
        u64::from(height) * 100,
    );
    let header_hash = header_signing_hash(&unsealed);
    let v = &st.validators[producer_pos];
    let ctx = SlotContext {
        height,
        slot: unsealed.slot,
        prev_hash: unsealed.prev_hash,
    };
    let vrf_out = vrf_prove(&fx.secrets[producer_pos].vrf, &slot_seed(&ctx)).expect("vrf");
    let producer = ProducerProof {
        validator_index: v.index,
        beta: vrf_out.output,
        vrf_proof: vrf_out.proof,
        producer_sig: bls_sign(&header_hash, &fx.secrets[producer_pos].bls.sk),
    };
    unsealed.producer_proof = encode_producer_proof(&producer);
    let producer_wire = unsealed.producer_proof.clone();
    let block = seal_block(
        unsealed,
        vec![wrong_cb],
        vec![],
        producer_wire,
        vec![],
        vec![],
    );
    let proof = CoinbaseAmountFraudProof {
        version: COINBASE_FRAUD_PROOF_VERSION,
        block: block.clone(),
        fee_sum,
        producer_payout: payout,
        accepted_settlements: Vec::new(),
    };
    let wire = encode_coinbase_amount_fraud_proof(&proof);
    SlashEvidence::InvalidBlock(InvalidBlockEvidence {
        height,
        block_id: block_id(&block.header),
        producer_index: v.index,
        fraud_proof_wire: wire,
    })
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
    let evidence = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: v1_idx,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, &v1_bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, &v1_bls_sk),
    });
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
    let evidence = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 2,
        slot: 2,
        voter_index: v1_idx,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, &v1_bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, &v1_bls_sk),
    });
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
    let invalid = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: v0_idx,
        header_hash_a: h_bad_a,
        sig_a: bls_sign(&h_bad_a, &v2_sk),
        header_hash_b: h_bad_b,
        sig_b: bls_sign(&h_bad_b, &v2_sk),
    });
    let h_good_a = [99u8; 32];
    let h_good_b = [100u8; 32];
    let valid = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: v2_idx,
        header_hash_a: h_good_a,
        sig_a: bls_sign(&h_good_a, &v2_sk),
        header_hash_b: h_good_b,
        sig_b: bls_sign(&h_good_b, &v2_sk),
    });

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

/// Valid slash evidence before invalid still rejects atomically ? staging
/// must not commit the valid slash when any evidence fails.
#[test]
fn valid_then_invalid_slash_evidence_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let v0_idx = st.validators[0].index;
    let v2_idx = st.validators[2].index;
    let v2_sk = fx.secrets[2].bls.sk.clone();

    let h_good_a = [99u8; 32];
    let h_good_b = [100u8; 32];
    let valid = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: v2_idx,
        header_hash_a: h_good_a,
        sig_a: bls_sign(&h_good_a, &v2_sk),
        header_hash_b: h_good_b,
        sig_b: bls_sign(&h_good_b, &v2_sk),
    });
    let h_bad_a = [77u8; 32];
    let h_bad_b = [88u8; 32];
    let invalid = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: v0_idx,
        header_hash_a: h_bad_a,
        sig_a: bls_sign(&h_bad_a, &v2_sk),
        header_hash_b: h_bad_b,
        sig_b: bls_sign(&h_bad_b, &v2_sk),
    });

    let block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        vec![valid, invalid],
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
        ApplyOutcome::Ok { .. } => panic!("valid-then-invalid slash batch must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert_eq!(st.validators[2].stake, 1_000_000);
    assert_eq!(st.treasury, 0);
}

/// Duplicate slash evidence for the same validator rejects the block whole.
#[test]
fn duplicate_slash_evidence_rejects_without_state_change() {
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    let before = snapshot(&st);
    let v2_idx = st.validators[2].index;
    let v2_sk = fx.secrets[2].bls.sk.clone();

    let first = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: v2_idx,
        header_hash_a: [41u8; 32],
        sig_a: bls_sign(&[41u8; 32], &v2_sk),
        header_hash_b: [42u8; 32],
        sig_b: bls_sign(&[42u8; 32], &v2_sk),
    });
    let duplicate = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: v2_idx,
        header_hash_a: [43u8; 32],
        sig_a: bls_sign(&[43u8; 32], &v2_sk),
        header_hash_b: [44u8; 32],
        sig_b: bls_sign(&[44u8; 32], &v2_sk),
    });

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
    let evidence = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: v1_idx,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, &v1_bls_sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, &v1_bls_sk),
    });
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

/// Coinbase fraud slash evidence zeroes producer stake through validator-mode `apply_block`.
#[test]
fn invalid_block_slash_zeros_producer_on_coinbase_fraud() {
    let fx = boot_three_validators_fraud_slash(64);
    let st = fx.state.clone();
    assert_eq!(st.treasury, 0);
    let st1 = apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            Vec::new(),
            Vec::new(),
            &all_voter_positions(&st),
        ),
    )
    .into_state()
    .expect("height-1 block");
    let evidence = coinbase_fraud_invalid_block_evidence(&fx, &st, 1, 1);
    let InvalidBlockEvidence {
        height,
        producer_index,
        ..
    } = match &evidence {
        SlashEvidence::InvalidBlock(inner) => inner.clone(),
        SlashEvidence::Equivocation(_) => panic!("expected invalid-block"),
    };
    assert_eq!(
        verify_invalid_block_evidence(
            match &evidence {
                SlashEvidence::InvalidBlock(inner) => inner,
                _ => panic!("expected invalid-block"),
            },
            &st1.validators,
            &DEFAULT_EMISSION_PARAMS,
            2,
            st1.header_version,
        ),
        InvalidBlockEvidenceCheck::Valid,
    );
    let post = apply_block(
        &st1,
        &seal_empty(
            &fx,
            &st1,
            2,
            Vec::new(),
            vec![evidence],
            &all_voter_positions(&st1),
        ),
    )
    .into_state()
    .expect("invalid-block slash block");
    assert_eq!(post.validators[producer_index as usize].stake, 0);
    assert_eq!(post.treasury, 1_000_000);
    assert_eq!(post.height, Some(2));
    assert_eq!(height, 1);
}

/// Invalid-block slash evidence cannot target the same height as the applying block.
#[test]
fn invalid_block_slash_rejects_same_height() {
    let fx = boot_three_validators_fraud_slash(64);
    let st = fx.state.clone();
    let evidence = coinbase_fraud_invalid_block_evidence(&fx, &st, 1, 1);
    let before = snapshot(&st);
    match apply_block(
        &st,
        &seal_empty(
            &fx,
            &st,
            1,
            Vec::new(),
            vec![evidence],
            &all_voter_positions(&st),
        ),
    ) {
        ApplyOutcome::Err { errors, .. } => {
            assert!(
                errors.iter().any(|e| matches!(
                    e,
                    BlockError::SlashInvalid {
                        reason: mfn_consensus::slashing::SlashRejectReason::InvalidBlock(
                            InvalidBlockEvidenceCheck::SameHeightSlash
                        ),
                        ..
                    }
                )),
                "expected same-height slash reject, got {errors:?}"
            );
        }
        ApplyOutcome::Ok { .. } => panic!("same-height invalid-block slash must reject"),
    }
    assert_eq!(snapshot(&st), before);
    assert_eq!(st.validators[1].stake, 1_000_000);
}
