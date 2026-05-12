//! Integration test for [`mfn_consensus::verify_header`] — the
//! light-header verification primitive (M2.0.5).
//!
//! Builds a real 3-block chain through `Chain` + `produce_solo_block`,
//! then *separately* runs `verify_header` against the pre-block
//! trusted validator set for each header. Both must agree on every
//! block: if `apply_block` accepts, the light verifier must also
//! accept; if the verifier accepts, the producer was a quorum
//! member of the trusted set.
//!
//! This is the live demonstration that the M2.0.x header-binds-body
//! work cashes out as a real light-client primitive: a verifier
//! holding only the header chain + a trusted starting validator set
//! can independently re-derive trust on every subsequent header.

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    build_coinbase, emission_at_height, validator_set_root, verify_header, ConsensusParams,
    GenesisConfig, HeaderVerifyError, PayoutAddress, Validator, ValidatorPayout, ValidatorSecrets,
    DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::stealth::stealth_gen;
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_node::{produce_solo_block, BlockInputs, Chain, ChainConfig};
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

fn single_validator_genesis() -> (GenesisConfig, ValidatorSecrets, ConsensusParams) {
    let (v0, s0) = mk_validator(0, 1_000_000);
    let params = ConsensusParams {
        expected_proposers_per_slot: 10.0,
        quorum_stake_bps: 6666,
        liveness_max_consecutive_missed: 64,
        liveness_slash_bps: 0,
    };
    (
        GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: vec![v0],
            params,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        },
        s0,
        params,
    )
}

/// Produce a real BLS-signed block at `height` against `chain` and
/// return it (unapplied). Caller decides whether to apply.
fn produce_block(
    chain: &Chain,
    secrets: &ValidatorSecrets,
    params: ConsensusParams,
    height: u32,
) -> mfn_consensus::Block {
    let producer = chain.validators()[0].clone();
    let payout = producer.payout.unwrap();
    let cb_payout = PayoutAddress {
        view_pub: payout.view_pub,
        spend_pub: payout.spend_pub,
    };
    let emission = emission_at_height(u64::from(height), &DEFAULT_EMISSION_PARAMS);
    let cb = build_coinbase(u64::from(height), emission, &cb_payout).expect("cb");
    let inputs = BlockInputs {
        height,
        slot: height,
        timestamp: u64::from(height) * 100,
        txs: vec![cb],
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    produce_solo_block(chain, &producer, secrets, params, inputs).expect("produce_solo_block")
}

/// Headline test: for every block of a 3-block chain, `verify_header`
/// (with the pre-block trusted validator set) must accept iff
/// `apply_block` does.
#[test]
fn verify_header_agrees_with_apply_block_across_three_blocks() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");

    for height in 1u32..=3 {
        // Snapshot the *pre-block* validator set — this is the trust
        // anchor for the light-header verification of `block.header`.
        let trusted = chain.validators().to_vec();

        let block = produce_block(&chain, &secrets, params, height);

        // The light verifier (with no chain state, just the trusted
        // set + params) must accept the same header that apply_block
        // accepts.
        let check = verify_header(&block.header, &trusted, &params).unwrap_or_else(|e| {
            panic!("verify_header rejected block {height}: {e:?}");
        });
        assert_eq!(check.producer_index, 0);
        assert_eq!(check.signing_stake, 1_000_000);
        assert_eq!(check.total_stake, 1_000_000);
        assert!(check.quorum_reached);

        chain
            .apply(&block)
            .expect("apply must accept the same block");
    }
}

/// Trying to verify block 2's header against the post-block-2
/// trusted set (instead of the pre-block-2 set) — for a chain
/// without rotation, the validator set hasn't moved, so verification
/// should *still* pass. This pins the invariant that for
/// rotation-free intervals, validator-set-state is constant and
/// either pre- or post-state can be used as the trust anchor.
#[test]
fn verify_header_works_with_post_block_trusted_set_when_no_rotation() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");

    // Produce + apply block 1 to advance state.
    let b1 = produce_block(&chain, &secrets, params, 1);
    chain.apply(&b1).expect("apply b1");

    // Produce block 2.
    let b2 = produce_block(&chain, &secrets, params, 2);

    // The chain's current (post-block-1, pre-block-2) validator set
    // equals what block 2's header committed to. Verify with it.
    let trusted_pre_block_2 = chain.validators().to_vec();
    verify_header(&b2.header, &trusted_pre_block_2, &params).expect("must verify");

    // Apply, then verify again with the post-block-2 set. Without
    // rotation the set is identical, so the same trusted slice still
    // verifies — confirming a stable validator set is the only thing
    // needed for header-chain following in this regime.
    chain.apply(&b2).expect("apply b2");
    let trusted_post_block_2 = chain.validators().to_vec();
    // `Validator` doesn't implement `PartialEq`, so compare under
    // the canonical validator-set Merkle root — which is exactly
    // the equality the chain itself uses.
    assert_eq!(
        validator_set_root(&trusted_pre_block_2),
        validator_set_root(&trusted_post_block_2)
    );
    verify_header(&b2.header, &trusted_post_block_2, &params).expect("must verify (still)");
}

/// A header that fails light-header verification must *also* be
/// rejected by `apply_block`. We tamper with each header field and
/// confirm both code paths reject — this is the symmetric half of
/// the agreement invariant.
#[test]
fn tampered_header_is_rejected_by_both_verify_header_and_apply_block() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");
    let trusted = chain.validators().to_vec();
    let block = produce_block(&chain, &secrets, params, 1);

    // (a) Tamper validator_root.
    {
        let mut bad = block.clone();
        bad.header.validator_root[0] ^= 0xff;
        let err = verify_header(&bad.header, &trusted, &params).expect_err("light reject");
        assert_eq!(err, HeaderVerifyError::ValidatorRootMismatch);
        chain
            .apply(&bad)
            .expect_err("apply_block must also reject (validator_root)");
    }

    // (b) Tamper producer_proof.
    {
        let mut bad = block.clone();
        let mid = bad.header.producer_proof.len() / 2;
        bad.header.producer_proof[mid] ^= 0xff;
        verify_header(&bad.header, &trusted, &params).expect_err("light reject (proof)");
        chain
            .apply(&bad)
            .expect_err("apply_block must also reject (producer_proof)");
    }

    // (c) Tamper height.
    {
        let mut bad = block.clone();
        bad.header.height = 42;
        verify_header(&bad.header, &trusted, &params).expect_err("light reject (height)");
        chain
            .apply(&bad)
            .expect_err("apply_block must also reject (height)");
    }

    // After all tampered-block rejections, the chain must still be
    // at genesis.
    assert_eq!(chain.tip_height(), Some(0));

    // The *original* unmodified block must still apply cleanly —
    // confirming we haven't corrupted state with our tampering above.
    chain.apply(&block).expect("clean block must still apply");
    assert_eq!(chain.tip_height(), Some(1));
}
