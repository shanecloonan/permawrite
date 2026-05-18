#![allow(unused_imports)]

use super::internal::*;
use super::*;
use super::*;
use crate::block::{apply_genesis, build_genesis, build_unsealed_header, seal_block};
use crate::coinbase::{build_coinbase, PayoutAddress};
use crate::consensus::{
    cast_vote, encode_finality_proof, finalize, try_produce_slot, FinalityProof, Validator,
    ValidatorPayout, ValidatorSecrets,
};
use crate::emission::{emission_at_height, DEFAULT_EMISSION_PARAMS};
use crate::{ConsensusParams, GenesisConfig};
use mfn_bls::bls_keygen_from_seed;
use mfn_crypto::stealth::stealth_gen;
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

fn mk_validator(i: u32, stake: u64) -> (Validator, ValidatorSecrets) {
    let vrf = vrf_keygen_from_seed(&[i as u8 + 1; 32]).unwrap();
    let bls = bls_keygen_from_seed(&[i as u8 + 101; 32]);
    let payout_wallet = stealth_gen();
    let payout = ValidatorPayout {
        view_pub: payout_wallet.view_pub,
        spend_pub: payout_wallet.spend_pub,
    };
    let val = Validator {
        index: i,
        vrf_pk: vrf.pk,
        bls_pk: bls.pk,
        stake,
        payout: Some(payout),
    };
    let secrets = ValidatorSecrets {
        index: i,
        vrf,
        bls: bls.clone(),
    };
    (val, secrets)
}

/// Build a real, fully signed block at height 1 against a
/// single-validator chain. Returns the header + the validator
/// set the header was signed against (i.e. the pre-block set).
fn build_signed_block_1() -> (
    crate::block::Block,
    Vec<Validator>,
    ConsensusParams,
    ValidatorSecrets,
) {
    let (v0, s0) = mk_validator(0, 1_000_000);
    let params = ConsensusParams {
        expected_proposers_per_slot: 10.0,
        quorum_stake_bps: 6666,
        liveness_max_consecutive_missed: 64,
        liveness_slash_bps: 0,
    };
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: vec![v0.clone()],
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let genesis = build_genesis(&cfg);
    let state = apply_genesis(&genesis, &cfg).expect("apply genesis");

    // Build block 1.
    let payout = v0.payout.unwrap();
    let cb_payout = PayoutAddress {
        view_pub: payout.view_pub,
        spend_pub: payout.spend_pub,
    };
    let emission = emission_at_height(1, &DEFAULT_EMISSION_PARAMS);
    let cb = build_coinbase(1, emission, &cb_payout).expect("cb");
    let txs = vec![cb];

    let unsealed = build_unsealed_header(&state, &txs, &[], &[], &[], 1, 100);
    let header_hash = header_signing_hash(&unsealed);
    let ctx = SlotContext {
        height: 1,
        slot: 1,
        prev_hash: unsealed.prev_hash,
    };
    let total_stake = v0.stake;
    let producer_proof = try_produce_slot(
        &ctx,
        &s0,
        &v0,
        total_stake,
        params.expected_proposers_per_slot,
        &header_hash,
    )
    .expect("produce")
    .expect("eligible");
    let vote = cast_vote(
        &header_hash,
        &s0,
        &ctx,
        &producer_proof,
        &v0,
        total_stake,
        params.expected_proposers_per_slot,
    )
    .expect("vote");
    let agg = finalize(&header_hash, &[vote], 1).expect("agg");
    let fin = FinalityProof {
        producer: producer_proof,
        finality: agg,
        signing_stake: v0.stake,
    };
    let block = seal_block(
        unsealed,
        txs,
        Vec::new(),
        encode_finality_proof(&fin),
        Vec::new(),
        Vec::new(),
    );
    (block, vec![v0], params, s0)
}

/// Headline case: a real signed block 1 verifies under its
/// pre-block validator set.
#[test]
fn verify_header_accepts_real_signed_block() {
    let (block, validators, params, _s0) = build_signed_block_1();
    let check = verify_header(&block.header, &validators, &params).expect("must verify");
    assert_eq!(check.producer_index, 0);
    assert_eq!(check.signing_stake, 1_000_000);
    assert_eq!(check.total_stake, 1_000_000);
    assert!(check.quorum_reached);
    assert_eq!(check.validator_count, 1);
    // 1_000_000 * 6666 / 10_000 = 666_600 (ceil-div, exact)
    assert_eq!(check.quorum_required, 666_600);
}

/// Tampered `validator_root`: caller's trusted set no longer
/// matches what the header committed to.
#[test]
fn verify_header_rejects_tampered_validator_root() {
    let (mut block, validators, params, _s0) = build_signed_block_1();
    block.header.validator_root[0] ^= 0xff;
    let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
    assert_eq!(err, HeaderVerifyError::ValidatorRootMismatch);
}

/// Caller's trusted set is the WRONG set — different stake, same
/// vrf/bls keys. The computed `validator_root` won't match.
#[test]
fn verify_header_rejects_wrong_trusted_set() {
    let (block, mut validators, params, _s0) = build_signed_block_1();
    // Bump stake — root must change.
    validators[0].stake += 1;
    let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
    assert_eq!(err, HeaderVerifyError::ValidatorRootMismatch);
}

/// Tampered finality bitmap → BLS aggregate disagrees.
#[test]
fn verify_header_rejects_tampered_producer_proof() {
    let (mut block, validators, params, _s0) = build_signed_block_1();
    // Flip a byte of the producer_proof. Since this contains
    // the BLS aggregate, signature verification must fail.
    let mid = block.header.producer_proof.len() / 2;
    block.header.producer_proof[mid] ^= 0xff;
    let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
    // Could be a decode failure or a finality failure — both
    // are acceptable rejections.
    match err {
        HeaderVerifyError::FinalityRejected(_) | HeaderVerifyError::ProducerProofDecode(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

/// Empty trusted set → typed error, not panic.
#[test]
fn verify_header_rejects_empty_trusted_set() {
    let (block, _validators, params, _s0) = build_signed_block_1();
    let err = verify_header(&block.header, &[], &params).expect_err("must reject");
    assert_eq!(err, HeaderVerifyError::EmptyTrustedSet);
}

/// A header with an empty `producer_proof` (the genesis-style
/// case) is rejected with a specific error so a light client can
/// surface a helpful message rather than a cryptic decode
/// failure.
#[test]
fn verify_header_rejects_empty_producer_proof() {
    let (mut block, validators, params, _s0) = build_signed_block_1();
    block.header.producer_proof = Vec::new();
    let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
    assert_eq!(err, HeaderVerifyError::GenesisHeader);
}

/// Truncated `producer_proof` bytes → decode error path.
#[test]
fn verify_header_rejects_truncated_producer_proof() {
    let (mut block, validators, params, _s0) = build_signed_block_1();
    // Keep just a few bytes — not enough to decode.
    block.header.producer_proof.truncate(8);
    let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
    assert!(
        matches!(err, HeaderVerifyError::ProducerProofDecode(_)),
        "expected ProducerProofDecode, got {err:?}"
    );
}

/// Tampered `header.height` → `header_signing_hash` differs from
/// what the producer / committee signed → finality verification
/// fails.
#[test]
fn verify_header_rejects_tampered_height() {
    let (mut block, validators, params, _s0) = build_signed_block_1();
    block.header.height = 42;
    let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
    match err {
        HeaderVerifyError::FinalityRejected(_) => {}
        other => panic!("expected FinalityRejected, got {other:?}"),
    }
}

/// Tampered `header.slot` → producer-proof's slot context
/// differs → VRF / producer signature fails.
#[test]
fn verify_header_rejects_tampered_slot() {
    let (mut block, validators, params, _s0) = build_signed_block_1();
    block.header.slot = block.header.slot.wrapping_add(1);
    let err = verify_header(&block.header, &validators, &params).expect_err("must reject");
    match err {
        HeaderVerifyError::FinalityRejected(_) => {}
        other => panic!("expected FinalityRejected, got {other:?}"),
    }
}

/// Determinism: repeat verification of the same valid header
/// must produce byte-for-byte the same `HeaderCheck`.
#[test]
fn verify_header_is_deterministic() {
    let (block, validators, params, _s0) = build_signed_block_1();
    let a = verify_header(&block.header, &validators, &params).expect("a");
    let b = verify_header(&block.header, &validators, &params).expect("b");
    assert_eq!(a, b);
}

/* ----------------------------------------------------------------- *
 *  M2.0.7 — verify_block_body                                        *
 * ----------------------------------------------------------------- */

/// Headline: a real signed block 1 — built by `build_unsealed_header`
/// which sets every root consistently — must body-verify cleanly.
#[test]
fn verify_block_body_accepts_consistent_block() {
    let (block, _validators, _params, _s0) = build_signed_block_1();
    verify_block_body(&block).expect("must verify");
}

/// Tampered `tx_root` → typed `TxRootMismatch` with the actual
/// re-derived root in `got`.
#[test]
fn verify_block_body_rejects_tampered_tx_root() {
    let (mut block, _validators, _params, _s0) = build_signed_block_1();
    let original = block.header.tx_root;
    block.header.tx_root[0] ^= 0xff;
    let err = verify_block_body(&block).expect_err("must reject");
    match err {
        BodyVerifyError::TxRootMismatch { expected, got } => {
            assert_ne!(expected, original, "header field was tampered");
            assert_eq!(
                got, original,
                "re-derived root equals the un-tampered original"
            );
        }
        other => panic!("expected TxRootMismatch, got {other:?}"),
    }
}

/// Tampered `bond_root` → typed `BondRootMismatch`.
#[test]
fn verify_block_body_rejects_tampered_bond_root() {
    let (mut block, _validators, _params, _s0) = build_signed_block_1();
    block.header.bond_root[0] ^= 0xff;
    let err = verify_block_body(&block).expect_err("must reject");
    assert!(matches!(err, BodyVerifyError::BondRootMismatch { .. }));
}

/// Tampered `slashing_root` → typed `SlashingRootMismatch`.
#[test]
fn verify_block_body_rejects_tampered_slashing_root() {
    let (mut block, _validators, _params, _s0) = build_signed_block_1();
    block.header.slashing_root[0] ^= 0xff;
    let err = verify_block_body(&block).expect_err("must reject");
    assert!(matches!(err, BodyVerifyError::SlashingRootMismatch { .. }));
}

/// Tampered `storage_proof_root` → typed `StorageProofRootMismatch`.
#[test]
fn verify_block_body_rejects_tampered_storage_proof_root() {
    let (mut block, _validators, _params, _s0) = build_signed_block_1();
    block.header.storage_proof_root[0] ^= 0xff;
    let err = verify_block_body(&block).expect_err("must reject");
    assert!(matches!(
        err,
        BodyVerifyError::StorageProofRootMismatch { .. }
    ));
}

/// Tampered `claims_root` → typed `ClaimsRootMismatch`.
#[test]
fn verify_block_body_rejects_tampered_claims_root() {
    let (mut block, _validators, _params, _s0) = build_signed_block_1();
    block.header.claims_root[0] ^= 0xff;
    let err = verify_block_body(&block).expect_err("must reject");
    assert!(matches!(err, BodyVerifyError::ClaimsRootMismatch { .. }));
}

/// Re-ordering txs (swap two equivalent-but-distinct txs)
/// must move `tx_root` → body verification rejects.
///
/// We use the coinbase tx as the sole tx in our test setup, so
/// here we instead simulate body-side tampering by pushing a
/// duplicate of the coinbase tx into `block.txs` — the producer
/// committed to one tx; an added tx changes the recomputed root.
#[test]
fn verify_block_body_rejects_tampered_tx_body() {
    let (mut block, _validators, _params, _s0) = build_signed_block_1();
    // Duplicate the existing coinbase. Note: this is purely a
    // body-side tamper test — apply_block would reject the
    // duplicate-coinbase block for other reasons; here we're
    // verifying that the *body root check itself* catches the
    // mismatch.
    let cb = block.txs[0].clone();
    block.txs.push(cb);
    let err = verify_block_body(&block).expect_err("must reject");
    assert!(matches!(err, BodyVerifyError::TxRootMismatch { .. }));
}

/// Determinism: repeat verification of the same valid block
/// must produce byte-for-byte the same `Ok(())`.
#[test]
fn verify_block_body_is_deterministic() {
    let (block, _validators, _params, _s0) = build_signed_block_1();
    let a = verify_block_body(&block);
    let b = verify_block_body(&block);
    assert_eq!(a, b);
}

/// Genesis block is body-consistent (all empty bodies → all-zero
/// sentinel roots in the genesis header, which `build_genesis`
/// computes the same way).
#[test]
fn verify_block_body_accepts_genesis() {
    let (v0, _s0) = mk_validator(0, 1_000_000);
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: vec![v0],
        params: ConsensusParams {
            expected_proposers_per_slot: 10.0,
            quorum_stake_bps: 6666,
            liveness_max_consecutive_missed: 64,
            liveness_slash_bps: 0,
        },
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let genesis = build_genesis(&cfg);
    verify_block_body(&genesis).expect("genesis body must verify");
}
