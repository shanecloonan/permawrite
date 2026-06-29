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
