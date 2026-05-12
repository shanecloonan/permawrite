//! Integration test: a 1-validator chain driven through 3 real
//! BLS-signed blocks via the [`mfn_node::Chain`] driver and the
//! [`mfn_node::produce_solo_block`] producer helper.
//!
//! This is the smallest end-to-end demonstration that the driver
//! actually advances a chain — not just rejects bad blocks. It builds
//! one validator with its own ed25519 + VRF + BLS keys, bootstraps
//! genesis through `Chain::from_genesis`, then for three blocks runs
//! the full producer → finality-vote → seal → apply path. The
//! producer-side boilerplate is wrapped by `produce_solo_block`; the
//! application boilerplate is wrapped by `chain.apply()`. The result
//! is a tight ~10-line per-block loop that exercises every consensus
//! primitive end-to-end.
//!
//! Both helpers are reused by the future producer-loop module (M2.1),
//! the RPC handler that takes a tx batch and produces a block, and
//! every multi-block test across the workspace.

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    build_coinbase, emission_at_height, ConsensusParams, GenesisConfig, PayoutAddress, Validator,
    ValidatorPayout, ValidatorSecrets, DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::stealth::stealth_gen;
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_node::{produce_solo_block, BlockInputs, Chain, ChainConfig};
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

/// Build a deterministic single validator with full secrets.
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

/// Build a single-validator genesis config.
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

/// Produce + apply one block at the given `height` through the
/// `Chain` driver and the `produce_solo_block` helper. Returns the
/// new tip's `block_id`.
fn produce_and_apply(
    chain: &mut Chain,
    secrets: &ValidatorSecrets,
    params: ConsensusParams,
    height: u32,
) -> [u8; 32] {
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
    let block =
        produce_solo_block(chain, &producer, secrets, params, inputs).expect("produce_solo_block");
    chain.apply(&block).expect("apply block")
}

/// End-to-end smoke: one validator, three real BLS-signed blocks,
/// driven through the chain driver. Every block must move height,
/// move tip_id, and (because the coinbase carries the producer's
/// emission share + treasury-share-of-zero-fees) leave the treasury
/// at zero (no tx fees in this minimal flow).
#[test]
fn one_validator_three_blocks_advance_through_chain_driver() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");

    assert_eq!(chain.tip_height(), Some(0));
    assert_eq!(chain.validators().len(), 1);
    assert_eq!(chain.total_stake(), 1_000_000);
    let g_id = *chain.genesis_id();

    let id_b1 = produce_and_apply(&mut chain, &secrets, params, 1);
    assert_eq!(chain.tip_height(), Some(1));
    assert_eq!(chain.tip_id(), Some(&id_b1));
    assert_ne!(id_b1, g_id, "block 1 id must differ from genesis");

    let id_b2 = produce_and_apply(&mut chain, &secrets, params, 2);
    assert_eq!(chain.tip_height(), Some(2));
    assert_eq!(chain.tip_id(), Some(&id_b2));
    assert_ne!(id_b2, id_b1, "block 2 id must differ from block 1");

    let id_b3 = produce_and_apply(&mut chain, &secrets, params, 3);
    assert_eq!(chain.tip_height(), Some(3));
    assert_eq!(chain.tip_id(), Some(&id_b3));
    assert_ne!(id_b3, id_b2, "block 3 id must differ from block 2");

    // Validator set unchanged (no bond ops). Total stake unchanged.
    assert_eq!(chain.validators().len(), 1);
    assert_eq!(chain.total_stake(), 1_000_000);

    // Treasury is zero across this flow (no tx fees → no
    // treasury-share inflow; no slashings → no treasury credits).
    assert_eq!(chain.treasury(), 0);
}

/// After three blocks, the chain reports consistent stats — the
/// snapshot view (`ChainStats`) must agree with the accessor methods.
#[test]
fn chain_stats_agree_with_individual_accessors_after_run() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");
    for h in 1..=3 {
        produce_and_apply(&mut chain, &secrets, params, h);
    }
    let stats = chain.stats();
    assert_eq!(stats.height, chain.tip_height());
    assert_eq!(stats.tip_id.as_ref(), chain.tip_id());
    assert_eq!(stats.validator_count, chain.validators().len());
    assert_eq!(stats.total_stake, chain.total_stake());
    assert_eq!(stats.treasury, chain.treasury());
}

/// A block-height duplication attempt (re-applying the same block)
/// is rejected and the chain's state is preserved. This is the
/// driver's contract: it must not partially commit even pathological
/// input.
#[test]
fn replaying_a_block_is_rejected_state_preserved() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");

    let producer = chain.validators()[0].clone();
    let payout = producer.payout.unwrap();
    let cb_payout = PayoutAddress {
        view_pub: payout.view_pub,
        spend_pub: payout.spend_pub,
    };
    let height = 1u32;
    let emission = emission_at_height(u64::from(height), &DEFAULT_EMISSION_PARAMS);
    let cb = build_coinbase(u64::from(height), emission, &cb_payout).expect("cb");
    let inputs = BlockInputs {
        height,
        slot: height,
        timestamp: 100,
        txs: vec![cb],
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    let block = produce_solo_block(&chain, &producer, &secrets, params, inputs)
        .expect("produce_solo_block");

    let _id_b1 = chain.apply(&block).expect("first apply ok");
    assert_eq!(chain.tip_height(), Some(1));
    let snapshot_after_b1 = chain.stats();

    // Re-apply the *same* block — height is now wrong (chain wants
    // height 2 next), so apply_block must reject.
    let err = chain.apply(&block).expect_err("replay must reject");
    match err {
        mfn_node::ChainError::Reject { errors, .. } => {
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, mfn_consensus::BlockError::BadHeight { .. })),
                "expected BadHeight in {errors:?}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
    // State must be byte-for-byte unchanged.
    assert_eq!(chain.stats(), snapshot_after_b1);
}
