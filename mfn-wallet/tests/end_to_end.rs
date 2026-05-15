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
use mfn_node::{
    produce_solo_block, AdmitOutcome, BlockInputs, Chain, ChainConfig, Mempool, MempoolConfig,
};
use mfn_storage::{storage_commitment_hash, DEFAULT_ENDOWMENT_PARAMS};

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

#[test]
fn wallet_storage_upload_through_mempool_producer_and_chain() {
    // The M2.0.14 end-to-end proof:
    //
    //   coinbases → Alice ── build_storage_upload ─→ Mempool ── drain ─→
    //     producer → block(N) → Chain::apply → state.storage[h] populated
    //     → Alice.ingest_block credits change UTXO + sees anchor UTXO
    //     → LightChain follows in lockstep
    //
    // Asserts every cross-crate invariant in one shot:
    //   - `Wallet::upload_min_fee` agrees with the mempool's burden gate.
    //   - The wallet-built tx is admitted Fresh.
    //   - The producer drains + includes it (highest-fee-first).
    //   - The chain accepts the block; `state.storage` is keyed by
    //     `storage_commitment_hash(&art.built.commit)`.
    //   - Both wallets ingest the block correctly.
    //   - The light chain ends up at the same tip as the full chain.
    let alice_keys = wallet_from_seed(&[0xab; 32]);
    let mut alice = Wallet::from_keys(alice_keys.clone());

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
    let mut pool = Mempool::new(MempoolConfig::default());

    // Coinbase blocks 1..=3 fund Alice generously enough to cover the
    // upload + fee + a change output.
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
        chain.apply(&block).expect("apply");
        light.apply_block(&block).expect("light apply");
        alice.ingest_block(&block);
    }
    assert!(alice.balance() > 0);

    // Pick a payload that gives a non-trivial but tiny burden so we
    // don't need an absurd test balance. ~1 KiB at replication 3 gives
    // a small handful of base units of burden at default params.
    let data: Vec<u8> = (0u8..255u8).cycle().take(1024).collect();
    let replication: u8 = 3;

    let min_fee = alice
        .upload_min_fee(data.len() as u64, replication, chain.state())
        .expect("upload_min_fee");
    // Pay a bit above the minimum to leave some producer tip — the
    // chain will accept any fee ≥ min_fee.
    let fee = min_fee.saturating_add(1_000);
    let anchor_value: u64 = 5_000;

    let pre_upload_balance = alice.balance();
    let mut rng = seeded_rng(0xabad_cafe);
    let art = alice
        .build_storage_upload(
            &data,
            replication,
            fee,
            alice.recipient(),
            anchor_value,
            None,
            4, // ring size
            chain.state(),
            b"upload-end-to-end",
            &mut rng,
        )
        .expect("build_storage_upload");

    let upload_hash = storage_commitment_hash(&art.built.commit);
    assert!(
        !chain.state().storage.contains_key(&upload_hash),
        "before the block is applied, the commitment is not yet on chain"
    );

    // (1) Mempool admits.
    let outcome = pool
        .admit(art.signed.tx.clone(), chain.state())
        .expect("mempool admits storage upload");
    assert!(matches!(outcome, AdmitOutcome::Fresh { .. }));

    // (2) Drain — producer picks up the storage tx.
    let drained = pool.drain(16);
    assert_eq!(drained.len(), 1);
    assert_eq!(
        mfn_consensus::tx_id(&drained[0]),
        mfn_consensus::tx_id(&art.signed.tx),
    );
    assert!(pool.is_empty());

    // (3) Producer prepends a coinbase + applies.
    let treasury_fee_bps = 9000u64;
    let producer_fee = fee - (fee * treasury_fee_bps / 10_000);
    let mut txs = vec![coinbase_for(&producer, 4, producer_fee)];
    txs.extend(drained);
    let inputs = BlockInputs {
        height: 4,
        slot: 4,
        timestamp: 400,
        txs,
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    let block4 =
        produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("produce block 4");
    chain.apply(&block4).expect("chain applies block 4");
    light.apply_block(&block4).expect("light applies block 4");

    // (4) state.storage now carries the upload, keyed by its commitment hash.
    let entry = chain
        .state()
        .storage
        .get(&upload_hash)
        .expect("upload now anchored");
    assert_eq!(entry.commit.size_bytes as usize, data.len());
    assert_eq!(entry.commit.replication, replication);
    assert_eq!(
        entry.last_proven_height, 4,
        "anchor block is the initial proven height"
    );

    // (5) Light chain follows in lockstep.
    assert_eq!(chain.tip_height(), Some(4));
    assert_eq!(light.tip_height(), 4);
    assert_eq!(chain.tip_id(), Some(light.tip_id()));

    // (6) Alice ingests + her balance reflects: + block-4 emission + producer tip,
    //     − anchor_value (becomes a recovered UTXO again, since the anchor was to self)
    //     − fee.
    //     Self-anchoring + change → owned set should still be intact (the
    //     anchor + change come back to the wallet) and balance reflects
    //     only the fee (minus the producer-tip kickback).
    alice.ingest_block(&block4);
    let block4_emission = emission_at_height(4, &DEFAULT_EMISSION_PARAMS);
    // Net delta from the upload:
    //   spent inputs were `>= anchor_value + fee`; the wallet got back the
    //   anchor_value + any leftover as change, so the only real outflow
    //   is `fee` (the public fee).
    // Plus the coinbase pays Alice `block4_emission + producer_fee`.
    let expected_delta = (block4_emission + producer_fee) as i128 - fee as i128;
    assert_eq!(
        alice.balance() as i128,
        pre_upload_balance as i128 + expected_delta,
        "Alice's balance must reflect (block-4 emission + producer fee) − fee \
         (anchor_value + change both come back to self)"
    );
}

#[test]
fn wallet_storage_upload_rejects_insufficient_funds_before_signing() {
    // The wallet should hit InsufficientFunds in `select_inputs` before
    // ever calling the upload primitives, so signing/CLSAG work is
    // saved on a doomed upload.
    let alice_keys = wallet_from_seed(&[0xad; 32]);
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

    // One coinbase block barely funds Alice; pick an `anchor_value`
    // that strictly exceeds her balance.
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

    let mut rng = seeded_rng(11);
    let err = alice
        .build_storage_upload(
            b"some-data",
            3,
            0, // fee=0 (burden is small enough that 0 may or may not satisfy underfunding — irrelevant; we hit InsufficientFunds first)
            alice.recipient(),
            alice.balance().saturating_add(1_000_000_000), // way more than wallet holds
            None,
            4,
            chain.state(),
            &[],
            &mut rng,
        )
        .unwrap_err();
    assert!(
        matches!(err, mfn_wallet::WalletError::InsufficientFunds { .. }),
        "expected InsufficientFunds, got {err:?}"
    );
}

#[test]
fn wallet_storage_upload_rejects_fee_too_low_before_signing() {
    // If the caller specifies a fee that does not satisfy the
    // mempool's UploadUnderfunded gate, the wallet must surface it as
    // a typed `UploadUnderfunded` error rather than producing a tx the
    // mempool would reject (which would waste a CLSAG ring and leak
    // the spent inputs).
    let alice_keys = wallet_from_seed(&[0xae; 32]);
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

    // Fund Alice once.
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

    // Build a non-trivial payload so the burden is actually positive.
    let data: Vec<u8> = (0u8..255u8).cycle().take(8 * 1024).collect();
    let replication: u8 = 3;
    let min_fee = alice
        .upload_min_fee(data.len() as u64, replication, chain.state())
        .expect("min_fee");
    assert!(
        min_fee > 0,
        "8 KiB at replication 3 must have positive min_fee"
    );

    let mut rng = seeded_rng(13);
    let err = alice
        .build_storage_upload(
            &data,
            replication,
            min_fee.saturating_sub(1), // exactly one below the floor
            alice.recipient(),
            /* anchor_value */ 1_000,
            None,
            4,
            chain.state(),
            &[],
            &mut rng,
        )
        .unwrap_err();
    match err {
        mfn_wallet::WalletError::UploadUnderfunded {
            fee,
            min_fee: reported,
            ..
        } => {
            assert_eq!(fee, min_fee.saturating_sub(1));
            assert_eq!(reported, min_fee);
        }
        other => panic!("expected UploadUnderfunded, got {other:?}"),
    }
}

/// Authorship claim tx: `Mempool::admit` → solo block → `apply_block`
/// populates `ChainState::claims` for the claimed `data_root`.
#[test]
fn publish_claim_tx_round_trip_through_chain() {
    use mfn_wallet::ClaimingIdentity;

    let alice_keys = wallet_from_seed(&[0x31; 32]);
    let mut alice = Wallet::from_keys(alice_keys.clone());
    let claiming = ClaimingIdentity::from_seed(&[0x31; 32]);

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
        chain.apply(&block).expect("apply");
        alice.ingest_block(&block);
    }

    let fee = 10_000u64;
    let treasury_fee_bps = 9000u64;
    let producer_fee = fee - (fee * treasury_fee_bps / 10_000);
    let data_root = [0x77u8; 32];
    let mut rng = seeded_rng(0xfeed_beef);

    let signed = alice
        .publish_claim_tx(
            &claiming,
            data_root,
            b"signed by claiming key",
            fee,
            4,
            chain.state(),
            &mut rng,
        )
        .expect("publish claim");

    let mut pool = Mempool::new(MempoolConfig::default());
    let admit = pool
        .admit(signed.tx.clone(), chain.state())
        .expect("mempool admits claim tx");
    assert!(matches!(admit, AdmitOutcome::Fresh { .. }));

    let inputs = BlockInputs {
        height: 4,
        slot: 4,
        timestamp: 400,
        txs: vec![coinbase_for(&producer, 4, producer_fee), signed.tx.clone()],
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    let block4 = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("block 4");
    chain.apply(&block4).expect("chain applies claim block");

    let recs = chain
        .state()
        .claims
        .get(&data_root)
        .expect("claim index must list this data_root");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].claim.claim_pubkey, claiming.claim_pubkey());
    assert_eq!(recs[0].claim.message, b"signed by claiming key".as_slice());
}
