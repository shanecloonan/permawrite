//! Integration test: full chain → checkpoint → restore → continue
//! lockstep round-trip (M2.0.15).
//!
//! Exercises every layer end-to-end:
//!
//! 1. Build a real 1-validator chain via [`Chain::from_genesis`].
//! 2. Produce + apply three BLS-signed blocks through the producer
//!    helper (`produce_solo_block`) — so the chain has non-trivial
//!    state: validator coinbase outputs in `utxo` + `utxo_tree`, a
//!    non-zero validator stake, a non-empty `block_ids` chain, and
//!    a live emission schedule.
//! 3. Serialise the chain state with [`Chain::encode_checkpoint`].
//! 4. Decode into a *fresh* chain instance with
//!    [`Chain::from_checkpoint_bytes`].
//! 5. Verify the restored chain agrees with the original on every
//!    diagnostic (tip_id, tip_height, stats, encoded bytes).
//! 6. Produce a fourth block and apply it to **both** the original
//!    and the restored chain. The resulting `block_id` and full
//!    encoded checkpoint must be byte-identical — the restored chain
//!    must be operationally indistinguishable from the original.
//!
//! This is the ground-truth contract for the M2.1 daemon: a node
//! restart must yield a chain that produces the same blocks and
//! responds the same way to network input.

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    build_coinbase, emission_at_height, ConsensusParams, GenesisConfig, PayoutAddress, Validator,
    ValidatorPayout, ValidatorSecrets, DEFAULT_EMISSION_PARAMS,
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

/// Produce three real BLS-signed blocks, take a checkpoint, decode
/// into a fresh `Chain`, then verify the restored chain agrees with
/// the original at every observable surface — and continues to agree
/// after both are advanced by an identical fourth block.
#[test]
fn checkpoint_round_trip_after_three_real_blocks_advances_in_lockstep() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut chain = Chain::from_genesis(ChainConfig::new(cfg.clone())).expect("genesis");

    // Build up a non-trivial chain: 3 BLS-signed blocks each with a
    // single coinbase output (so utxo/utxo_tree advance, validator
    // stats accumulate, block_ids grows, emission lands).
    for h in 1..=3 {
        produce_and_apply(&mut chain, &secrets, params, h);
    }
    assert_eq!(chain.tip_height(), Some(3));

    // Sanity-check the chain has actually accumulated state.
    assert!(!chain.state().utxo.is_empty(), "should have coinbase utxos");
    assert!(
        chain.state().utxo_tree.leaf_count() > 0,
        "utxo_tree should have leaves"
    );
    assert_eq!(
        chain.state().block_ids.len(),
        4,
        "genesis + 3 blocks = 4 block_ids"
    );
    assert!(
        !chain.state().validator_stats.is_empty(),
        "validator_stats populated"
    );
    let original_stats_v0 = chain.state().validator_stats[0];
    assert!(
        original_stats_v0.total_signed >= 3,
        "validator must have signed the 3 blocks we applied"
    );

    // Snapshot the diagnostic surface.
    let stats_before = chain.stats();
    let tip_id_before = *chain.tip_id().unwrap();
    let g_id = *chain.genesis_id();

    // Encode the chain to bytes and decode into a fresh instance.
    let bytes = chain.encode_checkpoint();
    let restored =
        Chain::from_checkpoint_bytes(ChainConfig::new(cfg.clone()), &bytes).expect("restore");

    // Diagnostic agreement.
    assert_eq!(restored.genesis_id(), &g_id);
    assert_eq!(restored.tip_id(), Some(&tip_id_before));
    assert_eq!(restored.tip_height(), Some(3));
    assert_eq!(restored.stats(), stats_before);

    // State-byte agreement: re-encoding the restored chain produces
    // identical bytes — the codec is fully canonical, and every
    // ChainState field round-tripped.
    let bytes_after = restored.encode_checkpoint();
    assert_eq!(
        bytes, bytes_after,
        "restored chain must re-encode to byte-identical state"
    );

    // Advance BOTH chains with the SAME fourth block — the coinbase
    // uses fresh ephemeral randomness, so we must produce the block
    // exactly once and apply the same bytes to both. The restored
    // chain must accept the block and end at byte-identical state.
    let mut restored = restored;
    let producer = chain.validators()[0].clone();
    let payout = producer.payout.as_ref().unwrap();
    let cb_payout = PayoutAddress {
        view_pub: payout.view_pub,
        spend_pub: payout.spend_pub,
    };
    let emission = emission_at_height(4, &DEFAULT_EMISSION_PARAMS);
    let cb = build_coinbase(4, emission, &cb_payout).expect("cb");
    let inputs = BlockInputs {
        height: 4,
        slot: 4,
        timestamp: 400,
        txs: vec![cb],
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    let block_4 = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("produce");
    let id_orig = chain.apply(&block_4).expect("orig advance");
    let id_rest = restored.apply(&block_4).expect("restored advance");
    assert_eq!(
        id_orig, id_rest,
        "restored chain must accept the same block 4 with the same block_id"
    );
    assert_eq!(chain.tip_id(), restored.tip_id());
    assert_eq!(chain.stats(), restored.stats());
    assert_eq!(
        chain.encode_checkpoint(),
        restored.encode_checkpoint(),
        "post-advance state must remain byte-identical"
    );
}

/// `Chain::encode_checkpoint` is deterministic on a non-trivial
/// chain — calling it twice without applying anything between yields
/// byte-identical results.
#[test]
fn encode_checkpoint_is_deterministic_on_non_trivial_chain() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");
    for h in 1..=3 {
        produce_and_apply(&mut chain, &secrets, params, h);
    }
    let a = chain.encode_checkpoint();
    let b = chain.encode_checkpoint();
    assert_eq!(a, b, "same state must encode to identical bytes");
}

/// Restoring a checkpoint into a foreign `ChainConfig` (different
/// timestamp → different genesis_id) is rejected before any state is
/// touched. The daemon must never silently swap chains on restart.
#[test]
fn from_checkpoint_rejects_foreign_genesis_through_real_chain() {
    let (cfg, secrets, params) = single_validator_genesis();
    let mut chain = Chain::from_genesis(ChainConfig::new(cfg.clone())).expect("genesis");
    for h in 1..=3 {
        produce_and_apply(&mut chain, &secrets, params, h);
    }
    let bytes = chain.encode_checkpoint();

    let mut foreign = cfg.clone();
    foreign.timestamp = 1_000_000;
    let err =
        Chain::from_checkpoint_bytes(ChainConfig::new(foreign), &bytes).expect_err("must reject");
    match err {
        mfn_node::ChainError::GenesisMismatch { expected, got } => {
            assert_eq!(&expected, chain.genesis_id());
            assert_ne!(&got, chain.genesis_id());
        }
        other => panic!("expected GenesisMismatch, got {other:?}"),
    }
}
