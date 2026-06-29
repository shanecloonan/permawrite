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
