//! Integration test: a [`LightChain`] follows a real 3-block chain.
//!
//! This is the load-bearing demonstration that the light-client
//! skeleton actually composes with the full-node primitives: we use
//! [`mfn_node::produce_solo_block`] to make real BLS-signed blocks,
//! apply them to both a full [`mfn_node::Chain`] *and* the
//! [`mfn_light::LightChain`], and assert they reach identical tips at
//! every step. If the M2.0.5 light verifier + the M2.0.6 chain
//! follower agree with `apply_block` on three blocks in a row,
//! they'll agree on three thousand.

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    build_coinbase, emission_at_height, BlockHeader, ConsensusParams, GenesisConfig,
    HeaderVerifyError, PayoutAddress, Validator, ValidatorPayout, ValidatorSecrets,
    DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::stealth::stealth_gen;
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_light::{LightChain, LightChainConfig, LightChainError};
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

/// Produce a real BLS-signed block via `produce_solo_block` against
/// the given full-node `Chain`. Caller decides whether to apply.
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

/// Headline: a `LightChain` follows a `Chain` step-for-step over 3
/// real BLS-signed blocks. After each block, tips must match; after
/// the last block, both chains report the same final state.
#[test]
fn light_chain_follows_full_chain_across_three_blocks() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut full = Chain::from_genesis(ChainConfig::new(cfg.clone())).expect("genesis (full)");
    let mut light = LightChain::from_genesis(LightChainConfig::new(cfg));

    // Genesis: both must agree on tip id + height.
    assert_eq!(full.tip_height(), Some(0));
    assert_eq!(light.tip_height(), 0);
    assert_eq!(full.tip_id(), Some(light.tip_id()));
    assert_eq!(full.genesis_id(), light.genesis_id());

    for height in 1u32..=3 {
        let block = produce_block(&full, &secrets, params, height);

        // Apply to both chains.
        let full_tip = full.apply(&block).expect("full apply");
        let applied = light
            .apply_header(&block.header)
            .expect("light apply_header");

        // Tips must agree on every block.
        assert_eq!(full_tip, applied.block_id);
        assert_eq!(full.tip_height(), Some(height));
        assert_eq!(light.tip_height(), height);
        assert_eq!(full.tip_id(), Some(light.tip_id()));

        // Light client should also know who produced this block.
        assert_eq!(applied.check.producer_index, 0);
        assert_eq!(applied.check.signing_stake, 1_000_000);
    }
}

/// Skipping a header (applying `block 2` after `block 0`) must yield
/// a typed `HeightMismatch` and leave the light chain untouched.
#[test]
fn light_chain_rejects_skipped_header_with_state_preserved() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut full = Chain::from_genesis(ChainConfig::new(cfg.clone())).expect("genesis (full)");
    let mut light = LightChain::from_genesis(LightChainConfig::new(cfg));

    // Build block 1, apply to the full chain only (skip in light chain).
    let b1 = produce_block(&full, &secrets, params, 1);
    full.apply(&b1).expect("full apply 1");

    // Build block 2 on top of block 1.
    let b2 = produce_block(&full, &secrets, params, 2);

    // Try to apply b2 directly to the light chain — it expects b1's
    // height (1), not b2's (2). Typed error; state untouched.
    let pre = light.stats();
    let err = light.apply_header(&b2.header).expect_err("must reject");
    match err {
        LightChainError::HeightMismatch { expected, got } => {
            assert_eq!(expected, 1);
            assert_eq!(got, 2);
        }
        other => panic!("expected HeightMismatch, got {other:?}"),
    }
    assert_eq!(light.stats(), pre);
    assert_eq!(light.tip_height(), 0);
}

/// Cross-chain header-injection guard: a light client bootstrapped
/// from chain A must reject a block-1 header produced under chain
/// B's validator set.
///
/// Note: with minimal `initial_outputs == []` and
/// `initial_storage == []`, two genesis blocks are byte-for-byte
/// identical regardless of which validators are configured. The
/// genesis header commits to the *pre-genesis* validator set
/// (deliberately `[0u8; 32]`, since the genesis block itself
/// *installs* the initial set). So `genesis_id_A == genesis_id_B`
/// here, and the `prev_hash` linkage check passes by construction.
/// **The defence-in-depth that catches this is `validator_root`**
/// (M2.0): chain B's block 1 commits to chain B's validator set,
/// the light chain trusts chain A's. The light client surfaces this
/// as `LightChainError::HeaderVerify { ValidatorRootMismatch }`.
///
/// This is exactly why the M2.0 validator-set commitment matters:
/// without it, header linkage alone would not distinguish parallel
/// chains that share a minimal genesis.
#[test]
fn light_chain_rejects_header_from_different_chain() {
    // Chain A.
    let (cfg_a, _secrets_a, params_a) = single_validator_genesis();

    // Light chain bootstrapped from chain A.
    let mut light = LightChain::from_genesis(LightChainConfig::new(cfg_a.clone()));

    // Chain B: same minimal config + same params, but a *different*
    // validator key set. Index is still 0 (chain B has one validator).
    let vrf_b = vrf_keygen_from_seed(&[200u8; 32]).unwrap();
    let bls_b = bls_keygen_from_seed(&[201u8; 32]);
    let payout_wallet = stealth_gen();
    let payout = ValidatorPayout {
        view_pub: payout_wallet.view_pub,
        spend_pub: payout_wallet.spend_pub,
    };
    let v_b = Validator {
        index: 0,
        vrf_pk: vrf_b.pk,
        bls_pk: bls_b.pk,
        stake: 1_000_000,
        payout: Some(payout),
    };
    let s_b = ValidatorSecrets {
        index: 0,
        vrf: vrf_b,
        bls: bls_b,
    };
    let cfg_b = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: vec![v_b],
        params: params_a,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let mut full_b = Chain::from_genesis(ChainConfig::new(cfg_b)).expect("genesis B");
    let b1_b = produce_block(&full_b, &s_b, params_a, 1);
    full_b.apply(&b1_b).expect("apply B");

    // Feed chain B's block-1 header to light chain A. The genesis
    // ids coincide (both minimal-config genesis headers are
    // byte-identical), so the linkage passes; the
    // *validator_root* check is what trips, exactly as the M2.0
    // design intended.
    let err = light.apply_header(&b1_b.header).expect_err("must reject");
    match err {
        LightChainError::HeaderVerify {
            source: HeaderVerifyError::ValidatorRootMismatch,
            height,
        } => assert_eq!(height, 1),
        other => panic!("expected HeaderVerify/ValidatorRootMismatch, got {other:?}"),
    }
}

/// Tamper a single header bit *after* the chain has caught up. The
/// light chain's prior tip and trusted set must be left intact, and
/// the *next* (clean) header must still apply cleanly on top.
#[test]
fn light_chain_recovers_after_rejected_header() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut full = Chain::from_genesis(ChainConfig::new(cfg.clone())).expect("genesis");
    let mut light = LightChain::from_genesis(LightChainConfig::new(cfg));

    // Block 1: apply cleanly.
    let b1 = produce_block(&full, &secrets, params, 1);
    full.apply(&b1).expect("apply b1");
    light.apply_header(&b1.header).expect("light b1");

    // Block 2: build, then tamper a cryptographic field.
    let b2 = produce_block(&full, &secrets, params, 2);
    let mut tampered = BlockHeader::clone(&b2.header);
    // Flip a byte in producer_proof (BLS aggregate breaks).
    let mid = tampered.producer_proof.len() / 2;
    tampered.producer_proof[mid] ^= 0xff;
    let pre_tip = *light.tip_id();
    let pre_height = light.tip_height();
    let err = light.apply_header(&tampered).expect_err("tamper rejected");
    assert!(matches!(err, LightChainError::HeaderVerify { .. }));
    // State preserved.
    assert_eq!(light.tip_id(), &pre_tip);
    assert_eq!(light.tip_height(), pre_height);

    // The clean b2 still applies on top — light client recovered.
    let applied = light.apply_header(&b2.header).expect("clean b2");
    assert_eq!(light.tip_height(), 2);
    full.apply(&b2).expect("full b2");
    assert_eq!(full.tip_id(), Some(&applied.block_id));
}

/// Tampering the validator_root must yield the canonical typed error
/// up through the wrapped `LightChainError::HeaderVerify`.
#[test]
fn light_chain_surfaces_validator_root_mismatch_through_typed_error() {
    let (cfg, secrets, params) = single_validator_genesis();
    let full = Chain::from_genesis(ChainConfig::new(cfg.clone())).expect("genesis");
    let mut light = LightChain::from_genesis(LightChainConfig::new(cfg));

    let b1 = produce_block(&full, &secrets, params, 1);
    let mut bad = BlockHeader::clone(&b1.header);
    bad.validator_root[0] ^= 0xff;

    let err = light.apply_header(&bad).expect_err("must reject");
    match err {
        LightChainError::HeaderVerify {
            source: HeaderVerifyError::ValidatorRootMismatch,
            height,
        } => assert_eq!(height, 1),
        other => panic!("expected HeaderVerify/ValidatorRootMismatch, got {other:?}"),
    }
}
