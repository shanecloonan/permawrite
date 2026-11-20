//! B-330: equivocation evidence binds height and slot behind header v8.
//!
//! The gap ([`DESIGN_REVIEW_2026-11.md` §1]): legacy evidence carries two
//! signed hashes and the verifier never learns which height or slot each
//! hash was for, so two ordinary votes from one honest validator look like a
//! double-sign. At header v8 evidence carries both header signing preimages
//! and `apply_block` refuses a pair that does not name one height and slot.

use crate::support::*;
use mfn_bls::bls_sign;
use mfn_consensus::slashing::{BoundEquivocationEvidence, EvidenceCheck, SlashRejectReason};
use mfn_consensus::{
    apply_block, build_unsealed_header, header_signing_bytes, header_signing_hash_from_bytes,
    ApplyOutcome, BlockError, ChainState, EquivocationEvidence, SlashEvidence,
    HEADER_VERSION_EQUIVOCATION_BIND,
};

/// The header signing preimage an honest validator would vote on at
/// `height` / `slot` on top of `st`. `salt` perturbs the timestamp so two
/// candidate headers at one height hash differently.
fn vote_preimage(st: &ChainState, height: u32, slot: u32, salt: u64) -> Vec<u8> {
    let mut unsealed = build_unsealed_header(st, &[], &[], &[], &[], height, 0);
    unsealed.slot = slot;
    unsealed.timestamp = u64::from(height) * 100 + salt;
    header_signing_bytes(&unsealed)
}

fn bound_evidence(
    fx: &Fixture,
    voter_pos: usize,
    height: u32,
    slot: u32,
    signing_a: Vec<u8>,
    signing_b: Vec<u8>,
) -> SlashEvidence {
    let sk = &fx.secrets[voter_pos].bls.sk;
    let sig_a = bls_sign(&header_signing_hash_from_bytes(&signing_a), sk);
    let sig_b = bls_sign(&header_signing_hash_from_bytes(&signing_b), sk);
    SlashEvidence::BoundEquivocation(BoundEquivocationEvidence {
        height,
        slot,
        voter_index: fx.state.validators[voter_pos].index,
        signing_a,
        sig_a,
        signing_b,
        sig_b,
    })
}

/// The equivocation rejection in a failed outcome, with the full error
/// list for the assertion message.
fn equivocation_reject(outcome: ApplyOutcome) -> (Option<EvidenceCheck>, Vec<BlockError>) {
    let errors = match outcome {
        ApplyOutcome::Err { errors, .. } => errors,
        ApplyOutcome::Ok { .. } => Vec::new(),
    };
    let check = errors.iter().find_map(|e| match e {
        BlockError::SlashInvalid {
            reason: SlashRejectReason::Equivocation(check),
            ..
        } => Some(check.clone()),
        _ => None,
    });
    (check, errors)
}

#[test]
fn b330_v8_same_height_slot_double_sign_slashes() {
    let fx = boot_three_validators_equivocation_bind(64);
    let st = fx.state.clone();
    assert_eq!(st.header_version, HEADER_VERSION_EQUIVOCATION_BIND);
    let treasury_before = st.treasury;
    let stake = st.validators[1].stake;

    let a = vote_preimage(&st, 1, 1, 0);
    let b = vote_preimage(&st, 1, 1, 1);
    assert_ne!(a, b);
    let ev = bound_evidence(&fx, 1, 1, 1, a, b);

    let block = seal_empty(&fx, &st, 1, Vec::new(), vec![ev], &all_voter_positions(&st));
    let post = apply_block(&st, &block)
        .into_state()
        .expect("bound equivocation at one height and slot slashes");
    assert_eq!(post.validators[1].stake, 0);
    assert_eq!(post.treasury, treasury_before + u128::from(stake));
}

#[test]
fn b330_v8_honest_votes_at_two_heights_do_not_slash() {
    let fx = boot_three_validators_equivocation_bind(64);
    let st = fx.state.clone();
    let stake = st.validators[1].stake;

    // Validator 1 voted honestly for a header at height 1 and then for a
    // header at height 2. A prover labels the pair "height 1, slot 1".
    let a = vote_preimage(&st, 1, 1, 0);
    let b = vote_preimage(&st, 2, 2, 0);
    let ev = bound_evidence(&fx, 1, 1, 1, a, b);

    let block = seal_empty(&fx, &st, 1, Vec::new(), vec![ev], &all_voter_positions(&st));
    let (check, errors) = equivocation_reject(apply_block(&st, &block));
    assert_eq!(check, Some(EvidenceCheck::HeightSlotMismatch), "{errors:?}");
    // Rejection leaves the caller's state untouched.
    assert_eq!(st.validators[1].stake, stake);
}

#[test]
fn b330_v8_same_height_different_slot_does_not_slash() {
    let fx = boot_three_validators_equivocation_bind(64);
    let st = fx.state.clone();

    let a = vote_preimage(&st, 1, 1, 0);
    let b = vote_preimage(&st, 1, 2, 0);
    let ev = bound_evidence(&fx, 1, 1, 1, a, b);

    let block = seal_empty(&fx, &st, 1, Vec::new(), vec![ev], &all_voter_positions(&st));
    let (check, errors) = equivocation_reject(apply_block(&st, &block));
    assert_eq!(check, Some(EvidenceCheck::HeightSlotMismatch), "{errors:?}");
}

#[test]
fn b330_v8_refuses_legacy_unbound_evidence() {
    let fx = boot_three_validators_equivocation_bind(64);
    let st = fx.state.clone();
    let sk = &fx.secrets[1].bls.sk;

    // The legacy form would have been accepted at v1 — two real votes,
    // heights unproven.
    let a = header_signing_hash_from_bytes(&vote_preimage(&st, 1, 1, 0));
    let b = header_signing_hash_from_bytes(&vote_preimage(&st, 2, 2, 0));
    let ev = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: st.validators[1].index,
        header_hash_a: a,
        sig_a: bls_sign(&a, sk),
        header_hash_b: b,
        sig_b: bls_sign(&b, sk),
    });

    let block = seal_empty(&fx, &st, 1, Vec::new(), vec![ev], &all_voter_positions(&st));
    let (check, errors) = equivocation_reject(apply_block(&st, &block));
    assert_eq!(
        check,
        Some(EvidenceCheck::UnboundOnBindingVersion),
        "{errors:?}"
    );
}

#[test]
fn b330_v1_chain_still_accepts_legacy_form_and_refuses_bound() {
    // Path A stays at header v1: the legacy blob is still the only slash
    // wire there. A bound blob cannot even be encoded for a v1 block body,
    // and the verifier refuses it if one is handed in directly.
    let fx = boot_three_validators(64);
    let st = fx.state.clone();
    assert_eq!(st.header_version, 1);

    let a = vote_preimage(&st, 1, 1, 0);
    let b = vote_preimage(&st, 1, 1, 1);
    let bound = bound_evidence(&fx, 1, 1, 1, a, b);
    assert_eq!(
        mfn_consensus::slashing::verify_equivocation_for_version(
            &bound,
            &st.validators,
            st.header_version
        ),
        Some(EvidenceCheck::BoundOnLegacyVersion)
    );
    assert!(
        mfn_consensus::encode_slash_evidence(&bound, st.header_version).is_empty(),
        "a v1 body has no wire for bound evidence"
    );

    let sk = &fx.secrets[1].bls.sk;
    let h1 = [33u8; 32];
    let h2 = [44u8; 32];
    let legacy = SlashEvidence::Equivocation(EquivocationEvidence {
        height: 1,
        slot: 1,
        voter_index: st.validators[1].index,
        header_hash_a: h1,
        sig_a: bls_sign(&h1, sk),
        header_hash_b: h2,
        sig_b: bls_sign(&h2, sk),
    });
    let block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        vec![legacy],
        &all_voter_positions(&st),
    );
    let post = apply_block(&st, &block)
        .into_state()
        .expect("v1 legacy equivocation still applies");
    assert_eq!(post.validators[1].stake, 0);
}

#[test]
fn b330_v8_bound_evidence_survives_block_wire_round_trip() {
    use mfn_consensus::{decode_block, encode_block};

    let fx = boot_three_validators_equivocation_bind(64);
    let st = fx.state.clone();
    let a = vote_preimage(&st, 1, 1, 0);
    let b = vote_preimage(&st, 1, 1, 1);
    let ev = bound_evidence(&fx, 1, 1, 1, a, b);
    let block = seal_empty(&fx, &st, 1, Vec::new(), vec![ev], &all_voter_positions(&st));

    let bytes = encode_block(&block);
    let back = decode_block(&bytes).expect("v8 block with bound evidence decodes");
    assert_eq!(back.slashings.len(), 1);
    assert!(matches!(
        back.slashings[0],
        SlashEvidence::BoundEquivocation(_)
    ));
    let post = apply_block(&st, &back)
        .into_state()
        .expect("decoded bound evidence slashes");
    assert_eq!(post.validators[1].stake, 0);
}

/* ---- B-332: detector output is what apply_block slashes ---------------- */

/// Validator 1 casts a real committee vote (`cast_vote`) on two competing
/// proposals for height 1 / slot 1. The detector, fed those votes the way a
/// node's vote intake would, emits bound evidence, and that evidence slashes
/// through `apply_block` on the v8 chain. An honest vote on the next height
/// first does not change the outcome.
#[test]
fn b332_detector_evidence_from_real_votes_slashes_through_apply_block() {
    use mfn_consensus::consensus::{cast_vote, pick_winner, try_produce_slot, SlotContext};
    use mfn_consensus::equivocation_detector::{EquivocationDetector, Observation};
    use mfn_consensus::header_signing_hash;

    let fx = boot_three_validators_equivocation_bind(64);
    let st = fx.state.clone();
    let total_stake: u64 = st.validators.iter().map(|v| v.stake).sum();
    let f = st.params.expected_proposers_per_slot;

    // Two competing proposals at height 1 that differ only in timestamp,
    // both carrying a producer proof some validator is eligible for.
    let mut proposals = Vec::new();
    for salt in [0u64, 1] {
        let mut unsealed = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100 + salt);
        unsealed.slot = 1;
        let hash = header_signing_hash(&unsealed);
        let ctx = SlotContext {
            height: 1,
            slot: 1,
            prev_hash: unsealed.prev_hash,
        };
        let mut candidates = Vec::new();
        for (i, v) in st.validators.iter().enumerate() {
            if let Ok(Some(p)) = try_produce_slot(&ctx, &fx.secrets[i], v, total_stake, f, &hash) {
                candidates.push(p);
            }
        }
        let producer = pick_winner(&candidates)
            .cloned()
            .expect("some validator is eligible at slot 1 with F=10");
        let producer_validator = st
            .validators
            .iter()
            .find(|v| v.index == producer.validator_index)
            .expect("producer in set");
        let vote = cast_vote(
            &hash,
            &fx.secrets[1],
            &ctx,
            &producer,
            producer_validator,
            total_stake,
            f,
        )
        .expect("validator 1 votes");
        proposals.push((header_signing_bytes(&unsealed), vote.sig));
    }

    let mut detector = EquivocationDetector::default();
    // An honest vote at the next height first: never pairs with anything.
    let mut next = build_unsealed_header(&st, &[], &[], &[], &[], 2, 200);
    next.slot = 2;
    let next_bytes = header_signing_bytes(&next);
    let next_sig = mfn_bls::bls_sign(&header_signing_hash(&next), &fx.secrets[1].bls.sk);
    assert_eq!(
        detector.observe(&st.validators, 1, &next_bytes, &next_sig),
        Observation::Recorded
    );

    let (bytes_a, sig_a) = &proposals[0];
    let (bytes_b, sig_b) = &proposals[1];
    assert_eq!(
        detector.observe(&st.validators, 1, bytes_a, sig_a),
        Observation::Recorded
    );
    let Observation::Equivocation(evidence) = detector.observe(&st.validators, 1, bytes_b, sig_b)
    else {
        panic!("two votes for height 1 / slot 1 on different headers is a double-sign");
    };
    assert_eq!(evidence.voter_index, st.validators[1].index);

    let stake = st.validators[1].stake;
    let block = seal_empty(
        &fx,
        &st,
        1,
        Vec::new(),
        vec![SlashEvidence::BoundEquivocation(*evidence)],
        &all_voter_positions(&st),
    );
    let post = apply_block(&st, &block)
        .into_state()
        .expect("detector evidence slashes on the v8 chain");
    assert_eq!(post.validators[1].stake, 0);
    assert_eq!(post.treasury, st.treasury + u128::from(stake));
}
