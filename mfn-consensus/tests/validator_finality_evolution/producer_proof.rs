use crate::support::{
    boot_three_validators_strict_eligibility, ineligible_producer_at_ctx, mk_validator,
};
use mfn_consensus::consensus::{
    cast_vote, try_produce_slot, verify_producer_proof, ConsensusCheck, ConsensusError, SlotContext,
};
use mfn_consensus::{build_unsealed_header, header_signing_hash};

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

/// `try_produce_slot` rejects when validator secrets index ≠ validator record index.
#[test]
fn try_produce_slot_secrets_index_mismatch_rejects() {
    let (val, _sec) = mk_validator(0, 1_000_000);
    let (_, wrong_sec) = mk_validator(1, 1_000_000);
    let ctx = SlotContext {
        height: 1,
        slot: 0,
        prev_hash: [42u8; 32],
    };
    let err = try_produce_slot(&ctx, &wrong_sec, &val, 1_000_000, 10.0, &[11u8; 32]).unwrap_err();
    assert!(matches!(err, ConsensusError::SecretsIndexMismatch));
}

/// Committee members refuse to vote for an ineligible producer proof.
#[test]
fn cast_vote_refuses_when_producer_not_eligible() {
    let fx = boot_three_validators_strict_eligibility(64);
    let st = &fx.state;
    let ctx = SlotContext {
        height: 1,
        slot: 1,
        prev_hash: st.block_ids[0],
    };
    let unsealed = build_unsealed_header(st, &[], &[], &[], &[], 1, 100);
    let header_hash = header_signing_hash(&unsealed);
    let ineligible = ineligible_producer_at_ctx(&fx, st, &ctx, &header_hash)
        .expect("dust-stake validator ineligible at F=1");
    let producer_validator = st
        .validators
        .iter()
        .find(|v| v.index == ineligible.validator_index)
        .expect("producer in set");
    let total_stake: u64 = st.validators.iter().map(|v| v.stake).sum();
    let err = cast_vote(
        &header_hash,
        &fx.secrets[1],
        &ctx,
        &ineligible,
        producer_validator,
        total_stake,
        st.params.expected_proposers_per_slot,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ConsensusError::RefusingToVote(ConsensusCheck::NotEligible)
    ));
}
