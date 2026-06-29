use crate::support::mk_validator;
use mfn_consensus::consensus::{
    cast_vote, try_produce_slot, verify_producer_proof, ConsensusCheck, ConsensusError, SlotContext,
};

/// `verify_producer_proof` rejects when the proof's index does not match the validator record.
#[test]
fn producer_proof_index_mismatch_rejects_verification() {
    let (val_producer, sec_producer) = mk_validator(0, 1_000_000);
    let (val_wrong, _) = mk_validator(1, 1_000_000);
    let ctx = SlotContext {
        height: 1,
        slot: 0,
        prev_hash: [42u8; 32],
    };
    let header_hash = [11u8; 32];
    let proof = try_produce_slot(
        &ctx,
        &sec_producer,
        &val_producer,
        1_000_000,
        10.0,
        &header_hash,
    )
    .expect("propose")
    .expect("eligible at F=10");
    let chk = verify_producer_proof(&ctx, &proof, &val_wrong, 1_000_000, 10.0, &header_hash);
    assert_eq!(chk, ConsensusCheck::IndexMismatch);
}

/// Committee members refuse to vote when producer proof index mismatches the validator record.
#[test]
fn cast_vote_refuses_when_producer_index_mismatch() {
    let (val_producer, sec_producer) = mk_validator(0, 1_000_000);
    let (val_wrong, _) = mk_validator(1, 1_000_000);
    let (_, sec_voter) = mk_validator(2, 1_000_000);
    let ctx = SlotContext {
        height: 1,
        slot: 0,
        prev_hash: [42u8; 32],
    };
    let header_hash = [11u8; 32];
    let proof = try_produce_slot(
        &ctx,
        &sec_producer,
        &val_producer,
        1_000_000,
        10.0,
        &header_hash,
    )
    .expect("propose")
    .expect("eligible at F=10");
    let err = cast_vote(
        &header_hash,
        &sec_voter,
        &ctx,
        &proof,
        &val_wrong,
        1_000_000,
        10.0,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConsensusError::RefusingToVote(ConsensusCheck::IndexMismatch)
    ));
}
