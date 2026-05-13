//! End-to-end wallet test.
//!
//! Exercises the **full** stack:
//!
//! 1. `mfn_node::Chain` produces three blocks via `produce_solo_block`.
//!    Each block's coinbase pays an `mfn_wallet::Wallet` (Alice).
//! 2. Alice's wallet ingests every block; balance grows by the
//!    deterministic emission schedule.
//! 3. Bob's wallet (a peer) ingests the same blocks and finds nothing.
//! 4. Alice builds a CLSAG-signed transfer paying Bob. The transfer
//!    is included in block 4 alongside that block's coinbase.
//! 5. The full chain accepts the block. Bob ingests it and finds the
//!    transfer; Alice ingests it, replaces her consumed UTXO with a
//!    change output back to herself, and the totals balance.
//! 6. An `mfn_light::LightChain` follows every block in lockstep and
//!    ends up at the same tip id as the full node.
//!
//! This is the proof that the wallet crate is wired correctly: it
//! consumes the canonical block format, produces canonical
//! transactions, and round-trips through full-node + light-node
//! verification.

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    build_coinbase, emission_at_height, ConsensusParams, GenesisConfig, GenesisOutput,
    PayoutAddress, Validator, ValidatorPayout, ValidatorSecrets, DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::scalar::random_scalar;
use mfn_crypto::seeded_rng;
use mfn_crypto::stealth::stealth_gen;
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_light::{LightChain, LightChainConfig};
use mfn_node::{produce_solo_block, BlockInputs, Chain, ChainConfig};
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

use mfn_wallet::{wallet_from_seed, TransferRecipient, Wallet};

fn consensus_params() -> ConsensusParams {
    ConsensusParams {
        expected_proposers_per_slot: 10.0,
        quorum_stake_bps: 6666,
        liveness_max_consecutive_missed: 64,
        liveness_slash_bps: 0,
    }
}

/// Make a validator whose **payout** is the `payout`'s stealth pubkeys
/// (so a wallet holding those keys can scan and recover the coinbase).
fn validator_with_payout(
    i: u32,
    stake: u64,
    payout: ValidatorPayout,
) -> (Validator, ValidatorSecrets) {
    let vrf = vrf_keygen_from_seed(&[i as u8 + 1; 32]).unwrap();
    let bls = bls_keygen_from_seed(&[i as u8 + 101; 32]);
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

/// Build the coinbase paying `producer`'s registered payout for the
/// given height, with `extra_fees` of producer-claimed fees on top of
/// the deterministic emission. Mirrors the helper that lives in
/// `mfn_node`'s own test suite, generalised to non-empty blocks.
fn coinbase_for(
    producer: &Validator,
    height: u32,
    extra_fees: u64,
) -> mfn_consensus::TransactionWire {
    let p = producer.payout.unwrap();
    let payout = PayoutAddress {
        view_pub: p.view_pub,
        spend_pub: p.spend_pub,
    };
    let emission = emission_at_height(u64::from(height), &DEFAULT_EMISSION_PARAMS);
    build_coinbase(u64::from(height), emission + extra_fees, &payout).expect("cb")
}

/// Build a small genesis with N random "decoy seed" outputs already
/// in the chain's UTXO set. These give `select_gamma_decoys` something
/// to draw from when Alice eventually builds her transfer.
fn decoy_seed_genesis_outputs(n: usize) -> Vec<GenesisOutput> {
    use curve25519_dalek::scalar::Scalar;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let sp = random_scalar();
        let bp = random_scalar();
        let p = generator_g() * sp;
        let c = (generator_g() * bp) + (generator_h() * Scalar::from((i as u64).wrapping_add(7)));
        out.push(GenesisOutput {
            one_time_addr: p,
            amount: c,
        });
    }
    out
}

#[test]
fn wallet_round_trip_through_full_chain_and_light_chain() {
    let alice_keys = wallet_from_seed(&[0xaa; 32]);
    let mut alice = Wallet::from_keys(alice_keys.clone());
    let mut bob = Wallet::from_seed(&[0xbb; 32]);

    let alice_payout = ValidatorPayout {
        view_pub: alice_keys.view_pub(),
        spend_pub: alice_keys.spend_pub(),
    };
    let (producer, secrets) = validator_with_payout(0, 1_000_000, alice_payout);

    let params = consensus_params();
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: decoy_seed_genesis_outputs(20),
        initial_storage: Vec::new(),
        validators: vec![producer.clone()],
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };

    let mut chain = Chain::from_genesis(ChainConfig::new(cfg.clone())).expect("genesis");
    let mut light = LightChain::from_genesis(LightChainConfig::new(cfg.clone()));

    // ---- Blocks 1..=3 — pure coinbase blocks paying Alice. ----
    let mut expected_alice = 0u64;
    for h in 1u32..=3 {
        let inputs = BlockInputs {
            height: h,
            slot: h,
            timestamp: u64::from(h) * 100,
            txs: vec![coinbase_for(&producer, h, 0)],
            bond_ops: Vec::new(),
            slashings: Vec::new(),
            storage_proofs: Vec::new(),
        };
        let block =
            produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("produce");
        chain.apply(&block).expect("full chain accepts block");
        light
            .apply_block(&block)
            .expect("light chain accepts block");
        alice.ingest_block(&block);
        bob.ingest_block(&block);

        expected_alice = expected_alice
            .saturating_add(emission_at_height(u64::from(h), &DEFAULT_EMISSION_PARAMS));
    }
    assert_eq!(alice.balance(), expected_alice);
    assert_eq!(alice.owned_count(), 3);
    assert_eq!(bob.balance(), 0);
    assert_eq!(chain.tip_height(), Some(3));
    assert_eq!(light.tip_height(), 3);
    assert_eq!(chain.tip_id(), Some(light.tip_id()));

    // ---- Block 4 — Alice transfers a portion to Bob. ----

    // Fee is split 90% treasury / 10% producer at default params, so
    // pick a value that's a clean multiple of 10_000 to keep the
    // arithmetic exact.
    let transfer_value = 100_000u64;
    let fee = 10_000u64;
    let recipients = vec![TransferRecipient {
        recipient: mfn_consensus::Recipient {
            view_pub: bob.keys().view_pub(),
            spend_pub: bob.keys().spend_pub(),
        },
        value: transfer_value,
    }];

    // Capture Alice's balance BEFORE `build_transfer` (it locally
    // evicts the consumed UTXO so that a follow-up build_transfer
    // doesn't double-spend; `ingest_block` later credits the change
    // output back).
    let pre_h4_alice_balance = alice.balance();

    let mut rng = seeded_rng(0x1234_5678);
    let signed = alice
        .build_transfer(&recipients, fee, 4, chain.state(), b"hello bob", &mut rng)
        .expect("build transfer");

    // Default emission params route 90% of fees to treasury; the
    // producer's coinbase claims only the remaining 10%.
    let treasury_fee_bps = 9000u64;
    let producer_fee = fee - (fee * treasury_fee_bps / 10_000);
    let inputs = BlockInputs {
        height: 4,
        slot: 4,
        timestamp: 400,
        txs: vec![coinbase_for(&producer, 4, producer_fee), signed.tx.clone()],
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    let block4 =
        produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("produce block 4");
    chain.apply(&block4).expect("chain accepts transfer block");
    light
        .apply_block(&block4)
        .expect("light chain accepts transfer block");

    alice.ingest_block(&block4);
    bob.ingest_block(&block4);

    // The transfer Alice built had:
    //   inputs: Σ = (one selected coinbase output's value)
    //   outputs: Bob gets transfer_value; Alice gets change = inputs - transfer_value - fee
    //   fee: claimed by producer
    //
    // Producer = Alice (same payout), so Alice's block-4 coinbase
    // hands her back `block4_emission + producer_fee`. The transfer
    // burned one coinbase UTXO worth `consumed_value` and minted a
    // change UTXO worth `consumed_value − transfer_value − fee`.
    // Net delta from the transfer alone: −transfer_value − fee.
    // Add back the block-4 emission + producer fee from the coinbase.
    let block4_emission = emission_at_height(4, &DEFAULT_EMISSION_PARAMS);
    let expected_delta =
        (block4_emission + producer_fee) as i128 - transfer_value as i128 - fee as i128;
    assert_eq!(
        bob.balance(),
        transfer_value,
        "Bob receives exactly transfer_value"
    );
    assert_eq!(
        alice.balance() as i128,
        pre_h4_alice_balance as i128 + expected_delta,
        "Alice's balance must reflect (block-4 emission + producer fee) − transfer_value − fee"
    );
    assert_eq!(chain.tip_height(), Some(4));
    assert_eq!(light.tip_height(), 4);
    assert_eq!(chain.tip_id(), Some(light.tip_id()));
}

#[test]
fn wallet_rejects_transfer_when_below_balance() {
    let alice_keys = wallet_from_seed(&[0xcc; 32]);
    let mut alice = Wallet::from_keys(alice_keys.clone());
    let alice_payout = ValidatorPayout {
        view_pub: alice_keys.view_pub(),
        spend_pub: alice_keys.spend_pub(),
    };
    let (producer, secrets) = validator_with_payout(0, 1_000_000, alice_payout);

    let params = consensus_params();
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: decoy_seed_genesis_outputs(8),
        initial_storage: Vec::new(),
        validators: vec![producer.clone()],
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let mut chain = Chain::from_genesis(ChainConfig::new(cfg.clone())).expect("genesis");

    let inputs = BlockInputs {
        height: 1,
        slot: 1,
        timestamp: 100,
        txs: vec![coinbase_for(&producer, 1, 0)],
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    let block = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("produce");
    chain.apply(&block).expect("apply");
    alice.ingest_block(&block);

    let bob = stealth_gen();
    let recipients = vec![TransferRecipient {
        recipient: mfn_consensus::Recipient {
            view_pub: bob.view_pub,
            spend_pub: bob.spend_pub,
        },
        value: alice.balance().saturating_add(1),
    }];
    let mut rng = seeded_rng(7);
    let err = alice
        .build_transfer(&recipients, 0, 4, chain.state(), &[], &mut rng)
        .unwrap_err();
    assert!(matches!(
        err,
        mfn_wallet::WalletError::InsufficientFunds { .. }
    ));
}
