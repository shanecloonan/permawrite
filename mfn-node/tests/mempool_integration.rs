//! End-to-end mempool integration test.
//!
//! Exercises the wallet → mempool → producer → chain → mempool loop:
//!
//! 1. Genesis + three pure-coinbase blocks fund Alice's wallet.
//! 2. Alice signs a transfer to Bob via her wallet.
//! 3. The signed tx is submitted to a [`Mempool`].
//! 4. The producer drains the mempool (highest-fee first), prepends a
//!    coinbase, builds block 4, and applies it to the chain.
//! 5. After applying, the mempool is asked to `remove_mined(&block)` —
//!    the tx that was just included is evicted; nothing else is.
//! 6. Bob's wallet ingests the block and finds the transfer; Alice's
//!    wallet ingests it and accounts for the change output.
//! 7. The [`LightChain`] follows in lockstep and ends up at the same
//!    tip id.
//!
//! This is the proof that the mempool is byte-compatible with the
//! wallet's output and the producer's input — the three crates speak
//! exactly the same `TransactionWire`.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    build_coinbase, emission_at_height, sign_transaction, ConsensusParams, GenesisConfig,
    GenesisOutput, InputSpec, OutputSpec, PayoutAddress, Recipient, Validator, ValidatorPayout,
    ValidatorSecrets, DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::clsag::ClsagRing;
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::scalar::random_scalar;
use mfn_crypto::seeded_rng;
use mfn_crypto::stealth::stealth_gen;
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_light::{LightChain, LightChainConfig};
use mfn_node::{
    produce_solo_block, AdmitError, AdmitOutcome, BlockInputs, Chain, ChainConfig, Mempool,
    MempoolConfig,
};
use mfn_storage::{storage_commitment_hash, StorageCommitment, DEFAULT_ENDOWMENT_PARAMS};
use mfn_wallet::{wallet_from_seed, TransferRecipient, Wallet};

fn consensus_params() -> ConsensusParams {
    ConsensusParams {
        expected_proposers_per_slot: 10.0,
        quorum_stake_bps: 6666,
        liveness_max_consecutive_missed: 64,
        liveness_slash_bps: 0,
    }
}

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
fn wallet_to_mempool_to_producer_to_chain_round_trip() {
    let alice_keys = wallet_from_seed(&[0xa1; 32]);
    let mut alice = Wallet::from_keys(alice_keys.clone());
    let mut bob = Wallet::from_seed(&[0xb1; 32]);

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

    // Blocks 1..=3: pure coinbase, no mempool involvement (the mempool
    // never sees coinbases — they're synthesized by the producer).
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
        bob.ingest_block(&block);

        // Sanity: remove_mined on a coinbase-only block does nothing
        // (no inputs to match against).
        assert_eq!(pool.remove_mined(&block), 0);
    }
    assert!(alice.balance() > 0);
    assert_eq!(bob.balance(), 0);

    // ---- Block 4: Alice → Bob via the mempool ----
    let transfer_value = 100_000u64;
    let fee = 10_000u64;
    let recipients = vec![TransferRecipient {
        recipient: mfn_consensus::Recipient {
            view_pub: bob.keys().view_pub(),
            spend_pub: bob.keys().spend_pub(),
        },
        value: transfer_value,
    }];

    let pre_balance = alice.balance();
    let mut rng = seeded_rng(0xdead_beef);
    let signed = alice
        .build_transfer(&recipients, fee, 4, chain.state(), b"hi bob", &mut rng)
        .expect("build transfer");

    // (1) Submit to mempool — should be Fresh.
    let outcome = pool.admit(signed.tx.clone(), chain.state()).expect("admit");
    assert!(matches!(outcome, AdmitOutcome::Fresh { .. }));
    assert_eq!(pool.len(), 1);

    // (2) Idempotent re-submit: DuplicateTx.
    let dup_err = pool.admit(signed.tx.clone(), chain.state()).unwrap_err();
    assert!(matches!(dup_err, AdmitError::DuplicateTx { .. }));

    // (3) Producer drains the mempool, top-fee-first.
    let drained = pool.drain(16);
    assert_eq!(drained.len(), 1);
    assert_eq!(
        mfn_consensus::tx_id(&drained[0]),
        mfn_consensus::tx_id(&signed.tx)
    );
    assert!(pool.is_empty());

    // (4) Prepend coinbase + apply.
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
    chain.apply(&block4).expect("chain accepts block 4");
    light.apply_block(&block4).expect("light accepts block 4");

    // (5) remove_mined on the (now-empty) pool is a no-op.
    assert_eq!(pool.remove_mined(&block4), 0);

    // (6) Wallets ingest, balances reflect the transfer.
    alice.ingest_block(&block4);
    bob.ingest_block(&block4);

    assert_eq!(
        bob.balance(),
        transfer_value,
        "Bob receives exactly transfer_value"
    );
    let block4_emission = emission_at_height(4, &DEFAULT_EMISSION_PARAMS);
    let expected_delta =
        (block4_emission + producer_fee) as i128 - transfer_value as i128 - fee as i128;
    assert_eq!(
        alice.balance() as i128,
        pre_balance as i128 + expected_delta,
        "Alice's balance must reflect (block-4 emission + producer fee) − transfer_value − fee"
    );
    assert_eq!(chain.tip_height(), Some(4));
    assert_eq!(light.tip_height(), 4);
    assert_eq!(chain.tip_id(), Some(light.tip_id()));
}

#[test]
fn mempool_evicts_tx_after_block_includes_it_via_remove_mined() {
    // Build a single coinbase block, fund Alice, sign a transfer,
    // admit it to the mempool. Then build block 2 by hand-picking
    // the tx from the mempool, apply block 2 to the chain WITHOUT
    // draining the mempool. Then call `remove_mined(&block2)` and
    // observe the eviction.
    let alice_keys = wallet_from_seed(&[0xa2; 32]);
    let mut alice = Wallet::from_keys(alice_keys.clone());
    let bob = mfn_crypto::stealth::stealth_gen();
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

    // Block 1: coinbase to Alice.
    let inputs = BlockInputs {
        height: 1,
        slot: 1,
        timestamp: 100,
        txs: vec![coinbase_for(&producer, 1, 0)],
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    let block1 = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("produce");
    chain.apply(&block1).expect("apply");
    alice.ingest_block(&block1);

    let mut pool = Mempool::new(MempoolConfig::default());
    let recipients = vec![TransferRecipient {
        recipient: mfn_consensus::Recipient {
            view_pub: bob.view_pub,
            spend_pub: bob.spend_pub,
        },
        value: 50_000,
    }];
    let fee = 10_000u64;
    let mut rng = seeded_rng(11);
    let signed = alice
        .build_transfer(&recipients, fee, 2, chain.state(), &[], &mut rng)
        .expect("build");
    pool.admit(signed.tx.clone(), chain.state()).expect("admit");
    assert_eq!(pool.len(), 1);

    // Block 2: producer builds with the tx, but the mempool stays
    // populated (simulating a node that produced without draining).
    let treasury_fee_bps = 9000u64;
    let producer_fee = fee - (fee * treasury_fee_bps / 10_000);
    let inputs = BlockInputs {
        height: 2,
        slot: 2,
        timestamp: 200,
        txs: vec![coinbase_for(&producer, 2, producer_fee), signed.tx.clone()],
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    let block2 = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("produce");
    chain.apply(&block2).expect("apply block 2");
    assert_eq!(pool.len(), 1, "pool still holds the now-mined tx");

    // remove_mined must evict it.
    let evicted = pool.remove_mined(&block2);
    assert_eq!(evicted, 1);
    assert!(pool.is_empty());
}

#[test]
fn mempool_admit_after_chain_advanced_still_works() {
    // Sanity check that the mempool gates against the CURRENT chain
    // state, not a snapshot: build a tx against state at height 1,
    // advance the chain to height 2 (without including the tx), then
    // admit the tx. The ring members were anchored at height 0 (decoy
    // seeds), so they're still in `state.utxo`; the key images are not
    // yet on chain. Admission should succeed.
    let alice_keys = wallet_from_seed(&[0xa3; 32]);
    let mut alice = Wallet::from_keys(alice_keys.clone());
    let bob = mfn_crypto::stealth::stealth_gen();
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

    // Block 1 funds Alice.
    let inputs = BlockInputs {
        height: 1,
        slot: 1,
        timestamp: 100,
        txs: vec![coinbase_for(&producer, 1, 0)],
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    let block1 = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("produce");
    chain.apply(&block1).expect("apply");
    alice.ingest_block(&block1);

    // Alice signs a tx now (height 1 state).
    let recipients = vec![TransferRecipient {
        recipient: mfn_consensus::Recipient {
            view_pub: bob.view_pub,
            spend_pub: bob.spend_pub,
        },
        value: 50_000,
    }];
    let fee = 10_000u64;
    let mut rng = seeded_rng(42);
    let signed = alice
        .build_transfer(&recipients, fee, 2, chain.state(), &[], &mut rng)
        .expect("build");

    // Now advance the chain by one empty block (coinbase only) without
    // including Alice's tx.
    let inputs = BlockInputs {
        height: 2,
        slot: 2,
        timestamp: 200,
        txs: vec![coinbase_for(&producer, 2, 0)],
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    let block2 = produce_solo_block(&chain, &producer, &secrets, params, inputs).expect("produce");
    chain.apply(&block2).expect("apply");

    // Mempool should still admit the (older) tx — its ring members
    // are still in the UTXO set, its key images are not yet spent.
    let mut pool = Mempool::new(MempoolConfig::default());
    pool.admit(signed.tx, chain.state())
        .expect("admit against advanced chain");
    assert_eq!(pool.len(), 1);
}

/* --------------------------------------------------------------------- *
 *  M2.0.13: storage-anchoring tx round-trip                                *
 * --------------------------------------------------------------------- */

/// One spendable input + decoys, anchored at genesis. The wallet
/// (M2.0.11) doesn't yet build storage-anchoring txs — that's M2.0.14 —
/// so this helper hand-rolls the InputSpec the same way the mempool's
/// own unit tests do, then signs a storage-bearing tx through
/// `mfn_consensus::sign_transaction`.
fn genesis_with_spendable_decoy(ring_size: usize, signer_value: u64) -> (Chain, InputSpec) {
    assert!(ring_size >= 2);
    let signer_spend = random_scalar();
    let signer_blinding = random_scalar();
    let signer_p = generator_g() * signer_spend;
    let signer_c = (generator_g() * signer_blinding) + (generator_h() * Scalar::from(signer_value));

    let mut decoy_p: Vec<EdwardsPoint> = Vec::with_capacity(ring_size - 1);
    let mut decoy_c: Vec<EdwardsPoint> = Vec::with_capacity(ring_size - 1);
    let mut decoy_outputs: Vec<GenesisOutput> = Vec::with_capacity(ring_size - 1);
    for i in 0..(ring_size - 1) {
        let sp = random_scalar();
        let bp = random_scalar();
        let p = generator_g() * sp;
        let c = (generator_g() * bp) + (generator_h() * Scalar::from((i as u64) + 1));
        decoy_p.push(p);
        decoy_c.push(c);
        decoy_outputs.push(GenesisOutput {
            one_time_addr: p,
            amount: c,
        });
    }
    let mut initial_outputs = vec![GenesisOutput {
        one_time_addr: signer_p,
        amount: signer_c,
    }];
    initial_outputs.extend(decoy_outputs.iter().cloned());

    let bls = bls_keygen_from_seed(&[42u8; 32]);
    let vrf = vrf_keygen_from_seed(&[1u8; 32]).unwrap();
    let payout_keys = stealth_gen();
    let payout = ValidatorPayout {
        view_pub: payout_keys.view_pub,
        spend_pub: payout_keys.spend_pub,
    };
    let validator = Validator {
        index: 0,
        vrf_pk: vrf.pk,
        bls_pk: bls.pk,
        stake: 1_000_000,
        payout: Some(payout),
    };

    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs,
        initial_storage: Vec::new(),
        validators: vec![validator],
        params: consensus_params(),
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");

    let signer_idx = ring_size / 2;
    let mut p = Vec::with_capacity(ring_size);
    let mut c = Vec::with_capacity(ring_size);
    let mut di = 0usize;
    for i in 0..ring_size {
        if i == signer_idx {
            p.push(signer_p);
            c.push(signer_c);
        } else {
            p.push(decoy_p[di]);
            c.push(decoy_c[di]);
            di += 1;
        }
    }
    let inp = InputSpec {
        ring: ClsagRing { p, c },
        signer_idx,
        spend_priv: signer_spend,
        value: signer_value,
        blinding: signer_blinding,
    };
    (chain, inp)
}

#[test]
fn storage_tx_through_full_mempool_producer_chain_pipeline() {
    // Build a chain whose producer is the same validator key the
    // helper hard-codes. Mining a block requires a producer with
    // stake > 0; the helper sets up exactly that.
    let (mut chain, inp) = genesis_with_spendable_decoy(4, 1_000);
    let validator = chain.validators()[0].clone();
    let bls = bls_keygen_from_seed(&[42u8; 32]);
    let vrf = vrf_keygen_from_seed(&[1u8; 32]).unwrap();
    let secrets = ValidatorSecrets { index: 0, vrf, bls };

    // A 1 KB upload at min replication.
    let storage = StorageCommitment {
        data_root: [0xab; 32],
        size_bytes: 1024,
        chunk_size: 256,
        num_chunks: 4,
        replication: 3,
        endowment: generator_g(),
    };
    let storage_hash = storage_commitment_hash(&storage);

    // Sign a storage-anchoring tx. fee=100 → treasury share 90,
    // burden ≈ 32 → admits.
    let recipient = {
        let w = stealth_gen();
        Recipient {
            view_pub: w.view_pub,
            spend_pub: w.spend_pub,
        }
    };
    let signed_tx = sign_transaction(
        vec![inp],
        vec![OutputSpec::ToRecipient {
            recipient,
            value: 900,
            storage: Some(storage.clone()),
        }],
        100,
        Vec::new(),
    )
    .expect("sign")
    .tx;

    // Mempool: admit + verify Fresh.
    let mut pool = Mempool::new(MempoolConfig::default());
    let outcome = pool.admit(signed_tx.clone(), chain.state()).expect("admit");
    assert!(matches!(outcome, AdmitOutcome::Fresh { .. }));

    // Producer drains + builds block 1 (coinbase + storage tx).
    let drained = pool.drain(16);
    assert_eq!(drained.len(), 1);
    let treasury_fee_bps = 9000u64;
    let producer_fee = 100 - (100 * treasury_fee_bps / 10_000);
    let mut txs = vec![coinbase_for(&validator, 1, producer_fee)];
    txs.extend(drained);
    let inputs = BlockInputs {
        height: 1,
        slot: 1,
        timestamp: 100,
        txs,
        bond_ops: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
    };
    let block = produce_solo_block(&chain, &validator, &secrets, consensus_params(), inputs)
        .expect("produce");
    chain
        .apply(&block)
        .expect("chain accepts storage-anchor block");

    // ChainState now contains the new storage commitment.
    assert!(
        chain.state().storage.contains_key(&storage_hash),
        "storage commitment must be anchored on chain"
    );

    // remove_mined cleans up.
    assert_eq!(pool.remove_mined(&block), 0); // already drained
    assert!(pool.is_empty());

    // A second admission of the same tx hits the cross-chain
    // double-spend gate (key images now in spent_key_images).
    let err = pool.admit(signed_tx, chain.state()).unwrap_err();
    assert!(matches!(err, AdmitError::KeyImageAlreadyOnChain { .. }));
}

#[test]
fn storage_tx_underfunded_is_rejected_by_mempool_before_producer() {
    // Same setup as the happy-path test, but with a fee that doesn't
    // cover the burden. The mempool MUST reject — otherwise the chain
    // would later reject the producer's block via UploadUnderfunded.
    let (chain, inp) = genesis_with_spendable_decoy(4, 1_000);
    let storage = StorageCommitment {
        data_root: [0xcd; 32],
        size_bytes: 64 * 1024, // 64 KB
        chunk_size: 256,
        num_chunks: 256,
        replication: 3,
        endowment: generator_g(),
    };

    let recipient = {
        let w = stealth_gen();
        Recipient {
            view_pub: w.view_pub,
            spend_pub: w.spend_pub,
        }
    };
    let signed_tx = sign_transaction(
        vec![inp],
        vec![OutputSpec::ToRecipient {
            recipient,
            value: 900,
            storage: Some(storage),
        }],
        100, // way too small for 64 KB
        Vec::new(),
    )
    .expect("sign")
    .tx;

    let mut pool = Mempool::new(MempoolConfig::default());
    let err = pool.admit(signed_tx, chain.state()).unwrap_err();
    assert!(matches!(err, AdmitError::UploadUnderfunded { .. }));
}

#[test]
fn already_anchored_storage_tx_silently_skips_burden_in_mempool() {
    // Pre-seed the chain's storage map with a commitment, then attempt
    // to admit a NEW tx that references the same data_root. The chain
    // treats this as a silent skip (no burden, no error). The mempool
    // must agree — even with a tiny fee.
    let storage = StorageCommitment {
        data_root: [0xef; 32],
        size_bytes: 1024,
        chunk_size: 256,
        num_chunks: 4,
        replication: 3,
        endowment: generator_g(),
    };

    let signer_spend = random_scalar();
    let signer_blinding = random_scalar();
    let signer_p = generator_g() * signer_spend;
    let signer_c = (generator_g() * signer_blinding) + (generator_h() * Scalar::from(1_000u64));

    let mut decoy_p: Vec<EdwardsPoint> = Vec::new();
    let mut decoy_c: Vec<EdwardsPoint> = Vec::new();
    let mut decoy_outputs: Vec<GenesisOutput> = Vec::new();
    for i in 0..3 {
        let sp = random_scalar();
        let bp = random_scalar();
        let p = generator_g() * sp;
        let c = (generator_g() * bp) + (generator_h() * Scalar::from((i as u64) + 1));
        decoy_p.push(p);
        decoy_c.push(c);
        decoy_outputs.push(GenesisOutput {
            one_time_addr: p,
            amount: c,
        });
    }
    let mut initial_outputs = vec![GenesisOutput {
        one_time_addr: signer_p,
        amount: signer_c,
    }];
    initial_outputs.extend(decoy_outputs.iter().cloned());

    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs,
        initial_storage: vec![storage.clone()],
        validators: Vec::<Validator>::new(),
        params: ConsensusParams::default(),
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let chain = Chain::from_genesis(ChainConfig::new(cfg)).expect("genesis");

    let signer_idx = 1usize;
    let mut p = Vec::new();
    let mut c = Vec::new();
    let mut di = 0usize;
    for i in 0..4 {
        if i == signer_idx {
            p.push(signer_p);
            c.push(signer_c);
        } else {
            p.push(decoy_p[di]);
            c.push(decoy_c[di]);
            di += 1;
        }
    }
    let inp = InputSpec {
        ring: ClsagRing { p, c },
        signer_idx,
        spend_priv: signer_spend,
        value: 1_000,
        blinding: signer_blinding,
    };

    let recipient = {
        let w = stealth_gen();
        Recipient {
            view_pub: w.view_pub,
            spend_pub: w.spend_pub,
        }
    };
    // fee=1 → treasury share = 0. Without the silent-skip, burden ≈ 32
    // would force UploadUnderfunded. With it, the upload is inert and
    // the tx admits.
    let signed_tx = sign_transaction(
        vec![inp],
        vec![OutputSpec::ToRecipient {
            recipient,
            value: 999,
            storage: Some(storage),
        }],
        1,
        Vec::new(),
    )
    .expect("sign")
    .tx;

    let mut pool = Mempool::new(MempoolConfig::default());
    pool.admit(signed_tx, chain.state())
        .expect("admit (already-anchored silent skip)");
}
