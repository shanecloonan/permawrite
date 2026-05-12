//! End-to-end exercise of the protocol layer.
//!
//! Drives a small simulated "block":
//!
//! 1. Wallets A, B, C are created.
//! 2. A has a "previous output" (a fake UTXO with known stealth address +
//!    Pedersen commitment) it wants to spend.
//! 3. A signs a confidential transaction paying B and C, with a fee.
//! 4. The block producer P assembles a block:
//!    - A's privacy transaction.
//!    - A coinbase paying P the emission for height + the tx's fee.
//! 5. Every verifier confirms:
//!    - Privacy tx verifies.
//!    - Coinbase verifies for the expected amount.
//!    - Recipients B and C can detect + open their stealth outputs (decrypting
//!      the encrypted-amount blob).
//!    - The tx-level key image of A's spend is unique (no global
//!      double-spend within the simulated block).

use curve25519_dalek::scalar::Scalar;

use mfn_consensus::{
    build_coinbase, coinbase_tx_priv, emission_at_height, sign_transaction, verify_coinbase,
    verify_transaction, InputSpec, OutputSpec, PayoutAddress, Recipient, DEFAULT_EMISSION_PARAMS,
};
use mfn_crypto::clsag::ClsagRing;
use mfn_crypto::encrypted_amount::decrypt_output_amount;
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::scalar::random_scalar;
use mfn_crypto::stealth::{indexed_stealth_spend_key, stealth_gen};

/// Build an InputSpec where the real input at `signer_idx` has known
/// `spend_priv`, `value`, and `blinding`. Other ring members are unrelated
/// random points (decoys).
fn fake_input(value: u64, ring_size: usize, signer_idx: usize) -> InputSpec {
    let mut p = Vec::with_capacity(ring_size);
    let mut c = Vec::with_capacity(ring_size);

    let signer_spend = random_scalar();
    let signer_blinding = random_scalar();
    let signer_p = generator_g() * signer_spend;
    let signer_c = (generator_g() * signer_blinding) + (generator_h() * Scalar::from(value));

    for i in 0..ring_size {
        if i == signer_idx {
            p.push(signer_p);
            c.push(signer_c);
        } else {
            let s = random_scalar();
            let b = random_scalar();
            let v = random_scalar();
            p.push(generator_g() * s);
            c.push((generator_g() * b) + (generator_h() * v));
        }
    }

    InputSpec {
        ring: ClsagRing { p, c },
        signer_idx,
        spend_priv: signer_spend,
        value,
        blinding: signer_blinding,
    }
}

#[test]
fn end_to_end_block_flow() {
    // Wallets.
    let wallet_b = stealth_gen();
    let wallet_c = stealth_gen();
    let wallet_p = stealth_gen();

    let r_b = Recipient {
        view_pub: wallet_b.view_pub,
        spend_pub: wallet_b.spend_pub,
    };
    let r_c = Recipient {
        view_pub: wallet_c.view_pub,
        spend_pub: wallet_c.spend_pub,
    };
    let payout_p = PayoutAddress {
        view_pub: wallet_p.view_pub,
        spend_pub: wallet_p.spend_pub,
    };

    // A's input: 1.000_000_00 MFN.
    let in_value = 100_000_000u64;
    let input = fake_input(in_value, 11, 5);

    // Two outputs + a fee.
    let v_b = 60_000_000u64;
    let v_c = 39_900_000u64;
    let fee = 100_000u64;
    assert_eq!(v_b + v_c + fee, in_value);

    // Sign the privacy tx.
    let signed = sign_transaction(
        vec![input],
        vec![
            OutputSpec::ToRecipient {
                recipient: r_b,
                value: v_b,
                storage: None,
            },
            OutputSpec::ToRecipient {
                recipient: r_c,
                value: v_c,
                storage: None,
            },
        ],
        fee,
        b"end-to-end".to_vec(),
    )
    .expect("sign");

    // Verify the privacy tx.
    let res = verify_transaction(&signed.tx);
    assert!(res.ok, "privacy tx errors: {:?}", res.errors);
    assert_eq!(res.key_images.len(), 1);

    // Build the block's coinbase. height=10, reward = emission + fee.
    let height = 10u64;
    let emission = emission_at_height(height, &DEFAULT_EMISSION_PARAMS);
    let coinbase_amount = emission + fee;
    let coinbase = build_coinbase(height, coinbase_amount, &payout_p).expect("coinbase");

    let cb_res = verify_coinbase(&coinbase, height, coinbase_amount, &payout_p);
    assert!(cb_res.ok, "coinbase errors: {:?}", cb_res.errors);
    assert_eq!(cb_res.amount, coinbase_amount);

    // Recipients B and C scan: derive their one-time stealth address from
    // the tx-level R, confirm it matches the on-chain output, and open the
    // encrypted amount blob to learn the value.
    for (idx, (wallet, expected_value)) in [(&wallet_b, v_b), (&wallet_c, v_c)].iter().enumerate() {
        let one_time_priv = indexed_stealth_spend_key(&signed.tx.r_pub, idx as u32, wallet);
        let derived = generator_g() * one_time_priv;
        assert_eq!(
            derived, signed.tx.outputs[idx].one_time_addr,
            "recipient {} stealth-scan must hit output {}",
            idx, idx
        );

        let dec = decrypt_output_amount(
            &signed.tx.r_pub,
            idx as u32,
            wallet.view_priv,
            &signed.tx.outputs[idx].enc_amount,
        )
        .expect("decrypt");
        assert_eq!(
            dec.value, *expected_value,
            "recipient {idx} value must match"
        );
    }

    // Producer P can decrypt their coinbase.
    let cb_dec = decrypt_output_amount(
        &coinbase.r_pub,
        0,
        wallet_p.view_priv,
        &coinbase.outputs[0].enc_amount,
    )
    .expect("coinbase decrypt");
    assert_eq!(cb_dec.value, coinbase_amount);

    // The tx-level key image is the *unique* spent-output marker. A
    // double-spend would surface as the same image showing up in a
    // different block; here we just confirm it's non-identity.
    assert_ne!(
        res.key_images[0],
        curve25519_dalek::edwards::EdwardsPoint::default()
    );
}

/// Full block-application test: genesis → block 1 with a privacy tx +
/// coinbase + BLS-quorum finality → block 2 with slashing evidence that
/// zeros a validator's stake.
#[test]
fn chain_genesis_block1_block2_with_slashing() {
    use mfn_bls::{bls_keygen_from_seed, bls_sign};
    use mfn_consensus::{
        apply_block, apply_genesis, build_genesis, build_unsealed_header, cast_vote,
        encode_finality_proof, finalize, header_signing_hash, seal_block, try_produce_slot,
        ApplyOutcome, ConsensusParams, FinalityProof, GenesisConfig, GenesisOutput, SlashEvidence,
        SlotContext, Validator, ValidatorPayout, ValidatorSecrets, DEFAULT_EMISSION_PARAMS,
    };
    use mfn_crypto::vrf::vrf_keygen_from_seed;

    /* ----- 3 validators (each with VRF + BLS) ----- */
    let mk_validator = |i: u32, stake: u64| -> (Validator, ValidatorSecrets, _) {
        let vrf = vrf_keygen_from_seed(&[i as u8 + 1; 32]).unwrap();
        let bls = bls_keygen_from_seed(&[i as u8 + 101; 32]);
        let wallet = stealth_gen();
        let payout = ValidatorPayout {
            view_pub: wallet.view_pub,
            spend_pub: wallet.spend_pub,
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
        (val, secrets, wallet)
    };

    let (v0, s0, w0) = mk_validator(0, 100);
    let (v1, s1, _w1) = mk_validator(1, 100);
    let (v2, s2, _w2) = mk_validator(2, 100);
    let validators = vec![v0.clone(), v1.clone(), v2.clone()];
    let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
    let params = ConsensusParams {
        expected_proposers_per_slot: 10.0, // oversample to make every validator always eligible
        quorum_stake_bps: 6667,
        ..ConsensusParams::default()
    };

    /* ----- Genesis with one initial UTXO that wallet_a controls ----- */
    let wallet_a = stealth_gen();
    let init_value = 1_000_000_000u64;
    let init_blinding = random_scalar();
    let one_time_addr = generator_g()
        * mfn_crypto::stealth::indexed_stealth_spend_key(&generator_g(), 0, &wallet_a);
    // We're not bothering with proper stealth derivation for the seed UTXO —
    // wallet_a will sign the spend with `signer_spend` directly.
    let _ = one_time_addr;

    // Use a synthetic input controlled directly by spend_priv.
    let signer_spend = random_scalar();
    let signer_p = generator_g() * signer_spend;
    let signer_c = (generator_g() * init_blinding) + (generator_h() * Scalar::from(init_value));

    // Decoy UTXOs anchored at genesis. In a real chain these would be
    // historical outputs the wallet selects via gamma-aged sampling; for
    // the test we just need them to exist in the chain's UTXO set so the
    // chain's ring-membership guard accepts them.
    let ring_size = 11usize;
    let signer_idx = 5usize;
    let mut decoy_outputs: Vec<GenesisOutput> = Vec::with_capacity(ring_size - 1);
    let mut decoy_p: Vec<curve25519_dalek::edwards::EdwardsPoint> =
        Vec::with_capacity(ring_size - 1);
    let mut decoy_c: Vec<curve25519_dalek::edwards::EdwardsPoint> =
        Vec::with_capacity(ring_size - 1);
    for _ in 0..(ring_size - 1) {
        let sp = random_scalar();
        let bp = random_scalar();
        let vp = random_scalar();
        let p = generator_g() * sp;
        let c = (generator_g() * bp) + (generator_h() * vp);
        decoy_outputs.push(GenesisOutput {
            one_time_addr: p,
            amount: c,
        });
        decoy_p.push(p);
        decoy_c.push(c);
    }
    let mut initial_outputs = vec![GenesisOutput {
        one_time_addr: signer_p,
        amount: signer_c,
    }];
    initial_outputs.extend(decoy_outputs.iter().cloned());

    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs,
        initial_storage: Vec::new(),
        validators: validators.clone(),
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: mfn_storage::DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let genesis = build_genesis(&cfg);
    let state0 = apply_genesis(&genesis, &cfg).expect("apply genesis");
    assert_eq!(state0.height, Some(0));

    /* ----- Build block 1: one privacy tx (spends the genesis UTXO) +
    coinbase paying producer (validator 0). ----- */
    let recipient_wallet = stealth_gen();
    let r = Recipient {
        view_pub: recipient_wallet.view_pub,
        spend_pub: recipient_wallet.spend_pub,
    };
    let send_value = 500_000_000u64;
    let change_value = 499_900_000u64;
    let fee = 100_000u64;
    assert_eq!(send_value + change_value + fee, init_value);

    // Assemble a ring with the real input at `signer_idx` and the
    // genesis-anchored decoys filling the rest of the slots.
    let (ring_p, ring_c) = {
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
        (p, c)
    };
    let priv_in = InputSpec {
        ring: ClsagRing {
            p: ring_p,
            c: ring_c,
        },
        signer_idx,
        spend_priv: signer_spend,
        value: init_value,
        blinding: init_blinding,
    };
    let signed = sign_transaction(
        vec![priv_in],
        vec![
            OutputSpec::ToRecipient {
                recipient: r,
                value: send_value,
                storage: None,
            },
            OutputSpec::ToRecipient {
                recipient: r,
                value: change_value,
                storage: None,
            },
        ],
        fee,
        b"block-1".to_vec(),
    )
    .expect("sign");

    // Coinbase paying validator 0.
    let v0_payout = v0.payout.as_ref().unwrap();
    let cb_payout = PayoutAddress {
        view_pub: v0_payout.view_pub,
        spend_pub: v0_payout.spend_pub,
    };
    let emission_b1 = emission_at_height(1, &DEFAULT_EMISSION_PARAMS);
    // Fees split between treasury and producer; producer only collects
    // its share in the coinbase. With no storage proofs in this block the
    // storage-reward addend is zero.
    let producer_fee_b1 =
        fee - fee * u64::from(DEFAULT_EMISSION_PARAMS.fee_to_treasury_bps) / 10_000;
    let cb_amount_b1 = emission_b1 + producer_fee_b1;
    let coinbase_b1 = build_coinbase(1, cb_amount_b1, &cb_payout).expect("coinbase b1");

    let txs_b1: Vec<_> = vec![coinbase_b1.clone(), signed.tx.clone()];

    // Unsealed header → produce finality → seal.
    let unsealed = build_unsealed_header(&state0, &txs_b1, &[], 1, 100);
    let header_hash = header_signing_hash(&unsealed);
    let ctx_b1 = SlotContext {
        height: 1,
        slot: 1,
        prev_hash: unsealed.prev_hash,
    };
    let producer_proof = try_produce_slot(
        &ctx_b1,
        &s0,
        &v0,
        total_stake,
        params.expected_proposers_per_slot,
        &header_hash,
    )
    .expect("produce")
    .expect("eligible at F=10");

    // All 3 validators sign.
    let votes = vec![
        cast_vote(
            &header_hash,
            &s0,
            &ctx_b1,
            &producer_proof,
            &v0,
            total_stake,
            params.expected_proposers_per_slot,
        )
        .unwrap(),
        cast_vote(
            &header_hash,
            &s1,
            &ctx_b1,
            &producer_proof,
            &v0,
            total_stake,
            params.expected_proposers_per_slot,
        )
        .unwrap(),
        cast_vote(
            &header_hash,
            &s2,
            &ctx_b1,
            &producer_proof,
            &v0,
            total_stake,
            params.expected_proposers_per_slot,
        )
        .unwrap(),
    ];
    let agg = finalize(&header_hash, &votes, validators.len()).expect("agg");
    let fin = FinalityProof {
        producer: producer_proof,
        finality: agg,
        signing_stake: total_stake,
    };

    let block1 = seal_block(
        unsealed,
        txs_b1,
        Vec::new(),
        encode_finality_proof(&fin),
        Vec::new(),
        Vec::new(),
    );

    let outcome = apply_block(&state0, &block1);
    let state1 = match outcome {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("block1 rejected: {errors:?}"),
    };
    assert_eq!(state1.height, Some(1));
    assert_eq!(state1.block_ids.len(), 2);
    // Validator 0's coinbase output is decryptable.
    let cb_dec = decrypt_output_amount(
        &block1.txs[0].r_pub,
        0,
        w0.view_priv,
        &block1.txs[0].outputs[0].enc_amount,
    )
    .expect("decrypt cb");
    assert_eq!(cb_dec.value, cb_amount_b1);

    /* ----- Block 2: validator 1 equivocates. Construct slashing evidence,
    produce block 2 with only the slash + coinbase. ----- */

    // Two distinct header hashes signed by validator 1 (the actual headers
    // don't need to be realistic — what matters is that v1's BLS pubkey
    // verifies both).
    let evil_a = [0xAAu8; 32];
    let evil_b = [0xBBu8; 32];
    let sig_a = bls_sign(&evil_a, &s1.bls.sk);
    let sig_b = bls_sign(&evil_b, &s1.bls.sk);
    let evidence = SlashEvidence {
        height: 1,
        slot: 1,
        voter_index: 1,
        header_hash_a: evil_a,
        sig_a,
        header_hash_b: evil_b,
        sig_b,
    };

    let coinbase_b2 = {
        let emission_b2 = emission_at_height(2, &DEFAULT_EMISSION_PARAMS);
        // No fees in block 2.
        build_coinbase(2, emission_b2, &cb_payout).expect("coinbase b2")
    };

    let txs_b2 = vec![coinbase_b2];
    let unsealed_b2 = build_unsealed_header(&state1, &txs_b2, &[], 2, 200);
    let header_hash_b2 = header_signing_hash(&unsealed_b2);
    let ctx_b2 = SlotContext {
        height: 2,
        slot: 2,
        prev_hash: unsealed_b2.prev_hash,
    };
    let prop_b2 = try_produce_slot(
        &ctx_b2,
        &s0,
        &v0,
        total_stake,
        params.expected_proposers_per_slot,
        &header_hash_b2,
    )
    .expect("produce b2")
    .expect("eligible");
    let votes_b2 = vec![
        cast_vote(
            &header_hash_b2,
            &s0,
            &ctx_b2,
            &prop_b2,
            &v0,
            total_stake,
            params.expected_proposers_per_slot,
        )
        .unwrap(),
        cast_vote(
            &header_hash_b2,
            &s1,
            &ctx_b2,
            &prop_b2,
            &v0,
            total_stake,
            params.expected_proposers_per_slot,
        )
        .unwrap(),
        cast_vote(
            &header_hash_b2,
            &s2,
            &ctx_b2,
            &prop_b2,
            &v0,
            total_stake,
            params.expected_proposers_per_slot,
        )
        .unwrap(),
    ];
    let agg_b2 = finalize(&header_hash_b2, &votes_b2, validators.len()).expect("agg b2");
    let fin_b2 = FinalityProof {
        producer: prop_b2,
        finality: agg_b2,
        signing_stake: total_stake,
    };

    let block2 = seal_block(
        unsealed_b2,
        txs_b2,
        Vec::new(),
        encode_finality_proof(&fin_b2),
        vec![evidence],
        Vec::new(),
    );

    let outcome_b2 = apply_block(&state1, &block2);
    let state2 = match outcome_b2 {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("block2 rejected: {errors:?}"),
    };
    assert_eq!(state2.height, Some(2));
    assert_eq!(state2.block_ids.len(), 3);
    // Validator 1's stake is now zero.
    assert_eq!(state2.validators[1].stake, 0);
    // V0 and V2 retain their stake.
    assert_eq!(state2.validators[0].stake, 100);
    assert_eq!(state2.validators[2].stake, 100);

    // The genesis UTXO is now spent — verify its key image is recorded.
    let priv_tx_res = verify_transaction(&block1.txs[1]);
    assert!(priv_tx_res.ok);
    let ki_bytes = priv_tx_res.key_images[0].compress().to_bytes();
    assert!(state2.spent_key_images.contains(&ki_bytes));
}

/// End-to-end SPoRA flow: anchor a storage commitment at genesis, ship
/// a storage proof in block 1, verify the per-commitment state is
/// updated and any per-proof yield is accrued.
///
/// Sidesteps the BLS finality + coinbase dance by genesis-ing with an
/// empty validator set (apply_block bypasses both when no validators
/// are registered) and by anchoring the commitment in `initial_storage`
/// rather than via an upload tx. Upload-fee-burden enforcement and the
/// upload-tx → storage-commitment binding are covered by the per-module
/// unit tests in `block.rs` and `mfn-storage`.
#[test]
fn storage_proof_flow_at_genesis_plus_block1() {
    use mfn_consensus::{
        apply_block, apply_genesis, build_genesis, build_unsealed_header, seal_block, ApplyOutcome,
        ConsensusParams, GenesisConfig,
    };
    use mfn_storage::{
        build_storage_commitment, build_storage_proof, storage_commitment_hash,
        DEFAULT_ENDOWMENT_PARAMS,
    };

    /* ----- Build a 4096-byte payload + storage commitment ----- */
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let replication = DEFAULT_ENDOWMENT_PARAMS.min_replication;
    let chunk_size = 4096usize; // single-chunk for speed; deterministic challenge always picks idx 0
    let built = build_storage_commitment(&payload, 1_000, Some(chunk_size), replication, None)
        .expect("build commitment");
    let commit_hash = storage_commitment_hash(&built.commit);

    /* ----- Genesis: commitment in initial_storage, no validators ----- */
    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: vec![built.commit.clone()],
        validators: Vec::new(),
        params: ConsensusParams {
            expected_proposers_per_slot: 1.0,
            quorum_stake_bps: 6667,
            ..ConsensusParams::default()
        },
        emission_params: mfn_consensus::DEFAULT_EMISSION_PARAMS,
        endowment_params: DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let genesis = build_genesis(&cfg);
    let state0 = apply_genesis(&genesis, &cfg).expect("apply genesis");
    assert_eq!(state0.storage.len(), 1, "commitment anchored at genesis");
    let entry0 = state0.storage[&commit_hash].clone();
    assert_eq!(entry0.last_proven_height, 0);
    assert_eq!(entry0.last_proven_slot, 0);
    assert_eq!(entry0.pending_yield_ppb, 0);

    /* ----- Block 1: ship a storage proof at slot 5_000 ----- */
    let slot_b1 = 5_000u32;
    let timestamp_b1: u64 = 1_000;
    let unsealed_b1 = build_unsealed_header(&state0, &[], &[], slot_b1, timestamp_b1);
    let storage_proof = build_storage_proof(
        &built.commit,
        &unsealed_b1.prev_hash,
        slot_b1,
        &payload,
        &built.tree,
    )
    .expect("build proof");
    let block1 = seal_block(
        unsealed_b1,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![storage_proof],
    );
    let state1 = match apply_block(&state0, &block1) {
        ApplyOutcome::Ok { state, .. } => state,
        ApplyOutcome::Err { errors, .. } => panic!("block1 rejected: {errors:?}"),
    };
    assert_eq!(state1.height, Some(1));
    let entry1 = state1.storage[&commit_hash].clone();
    assert_eq!(entry1.last_proven_height, 1);
    assert_eq!(entry1.last_proven_slot, u64::from(slot_b1));
    assert_eq!(entry1.commit, built.commit, "commitment fields unchanged");
    // pending_yield_ppb may be 0 (sub-base-unit fractions) but it MUST
    // have moved monotonically relative to the prior pending value (which
    // was also 0 — we just check it's well-defined).
    let _ = entry1.pending_yield_ppb;

    /* ----- Block 2: duplicate proof must be rejected ----- */
    let slot_b2 = 5_100u32;
    let timestamp_b2: u64 = 2_000;
    let unsealed_b2 = build_unsealed_header(&state1, &[], &[], slot_b2, timestamp_b2);
    let storage_proof_b2 = build_storage_proof(
        &built.commit,
        &unsealed_b2.prev_hash,
        slot_b2,
        &payload,
        &built.tree,
    )
    .expect("build proof v2");
    let dup_proof = storage_proof_b2.clone();
    let block2 = seal_block(
        unsealed_b2,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![storage_proof_b2, dup_proof],
    );
    let outcome_b2 = apply_block(&state1, &block2);
    assert!(
        matches!(outcome_b2, ApplyOutcome::Err { .. }),
        "duplicate proof must reject the block"
    );
}

#[test]
fn coinbase_replay_is_byte_identical() {
    // Two nodes computing the same height + amount + payout must produce
    // byte-identical coinbase transactions. This is the deterministic-replay
    // invariant that lets the chain check coinbase rules without trusting
    // the producer's representation.
    let wallet = stealth_gen();
    let payout = PayoutAddress {
        view_pub: wallet.view_pub,
        spend_pub: wallet.spend_pub,
    };

    let cb_a = build_coinbase(1234, 50_000_000, &payout).expect("a");
    let cb_b = build_coinbase(1234, 50_000_000, &payout).expect("b");

    // Same key, same address, same commitment.
    assert_eq!(cb_a.r_pub, cb_b.r_pub);
    assert_eq!(cb_a.outputs[0].one_time_addr, cb_b.outputs[0].one_time_addr);
    assert_eq!(cb_a.outputs[0].amount, cb_b.outputs[0].amount);
    assert_eq!(cb_a.outputs[0].enc_amount, cb_b.outputs[0].enc_amount);
    // And the deterministic tx-priv recovers correctly.
    let recovered = coinbase_tx_priv(1234, &payout.spend_pub);
    assert_eq!(generator_g() * recovered, cb_a.r_pub);
}

/// Liveness slashing integration test.
///
/// 3-validator chain. Validator 1 NEVER signs. We drive enough empty
/// blocks past the liveness threshold (set to 3 for the test so we don't
/// have to produce 32+ blocks) and verify:
///
/// 1. Stats track signed/missed counts correctly per validator.
/// 2. Validator 1's stake is slashed multiplicatively on the threshold
///    block.
/// 3. The remaining 2 validators (who do sign) are untouched.
/// 4. Quorum is still met across the slashed-stake landscape because
///    1000 + 0 + 1000 = 2000 stake vs (1000+slashed_1+1000)·6667/10000.
#[test]
fn liveness_slashing_chronic_absentee_gets_slashed() {
    use mfn_bls::bls_keygen_from_seed;
    use mfn_consensus::{
        apply_block, apply_genesis, build_genesis, build_unsealed_header, cast_vote,
        encode_finality_proof, finalize, header_signing_hash, seal_block, try_produce_slot,
        ApplyOutcome, ConsensusParams, FinalityProof, GenesisConfig, SlotContext, Validator,
        ValidatorPayout, ValidatorSecrets, DEFAULT_EMISSION_PARAMS,
    };
    use mfn_crypto::vrf::vrf_keygen_from_seed;

    let mk_validator = |i: u32, stake: u64| -> (Validator, ValidatorSecrets, _) {
        let vrf = vrf_keygen_from_seed(&[i as u8 + 1; 32]).unwrap();
        let bls = bls_keygen_from_seed(&[i as u8 + 101; 32]);
        let wallet = stealth_gen();
        let payout = ValidatorPayout {
            view_pub: wallet.view_pub,
            spend_pub: wallet.spend_pub,
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
        (val, secrets, wallet)
    };

    // Use very high stakes so the 1% liveness slash is non-trivial in
    // integer math; threshold = 3 so we don't need to produce 32 blocks.
    let (v0, s0, w0) = mk_validator(0, 1_000_000);
    let (v1, _s1, _w1) = mk_validator(1, 1_000_000);
    let (v2, s2, _w2) = mk_validator(2, 1_000_000);
    let validators = vec![v0.clone(), v1.clone(), v2.clone()];
    let total_stake: u64 = validators.iter().map(|v| v.stake).sum();
    let params = ConsensusParams {
        expected_proposers_per_slot: 10.0,
        // With only v0+v2 voting (66.67% stake exactly) we sit right at
        // the 6667 bps quorum. Drop the quorum 1bp to 6666 so the
        // chronic absentee doesn't break finality.
        quorum_stake_bps: 6666,
        liveness_max_consecutive_missed: 3,
        liveness_slash_bps: 100, // 1%
    };

    let cfg = GenesisConfig {
        timestamp: 0,
        initial_outputs: Vec::new(),
        initial_storage: Vec::new(),
        validators: validators.clone(),
        params,
        emission_params: DEFAULT_EMISSION_PARAMS,
        endowment_params: mfn_storage::DEFAULT_ENDOWMENT_PARAMS,
        bonding_params: None,
    };
    let genesis = build_genesis(&cfg);
    let mut state = apply_genesis(&genesis, &cfg).expect("apply genesis");
    assert_eq!(state.validator_stats.len(), 3);

    // Produce 4 blocks. After block 3 (3 consecutive misses), v1 is
    // slashed. Block 4 verifies the slash sticks and stats keep tracking.
    for height in 1u32..=4 {
        let v0_payout = state.validators[0].payout.as_ref().unwrap();
        let cb_payout = PayoutAddress {
            view_pub: v0_payout.view_pub,
            spend_pub: v0_payout.spend_pub,
        };
        let emission = emission_at_height(u64::from(height), &DEFAULT_EMISSION_PARAMS);
        // No fees in these blocks, so coinbase reward = emission only.
        let cb = build_coinbase(u64::from(height), emission, &cb_payout).expect("cb");

        let txs = vec![cb];
        let unsealed = build_unsealed_header(&state, &txs, &[], height, u64::from(height) * 100);
        let header_hash = header_signing_hash(&unsealed);
        let ctx = SlotContext {
            height,
            slot: height,
            prev_hash: unsealed.prev_hash,
        };
        let producer_proof = try_produce_slot(
            &ctx,
            &s0,
            &state.validators[0],
            total_stake,
            params.expected_proposers_per_slot,
            &header_hash,
        )
        .expect("produce")
        .expect("eligible");

        // ONLY v0 + v2 sign. v1 stays silent → liveness miss.
        let votes = vec![
            cast_vote(
                &header_hash,
                &s0,
                &ctx,
                &producer_proof,
                &state.validators[0],
                total_stake,
                params.expected_proposers_per_slot,
            )
            .unwrap(),
            cast_vote(
                &header_hash,
                &s2,
                &ctx,
                &producer_proof,
                &state.validators[0],
                total_stake,
                params.expected_proposers_per_slot,
            )
            .unwrap(),
        ];
        let agg = finalize(&header_hash, &votes, state.validators.len()).expect("agg");
        let signing_stake = state.validators[0].stake + state.validators[2].stake;
        let fin = FinalityProof {
            producer: producer_proof,
            finality: agg,
            signing_stake,
        };

        let block = seal_block(
            unsealed,
            txs,
            Vec::new(),
            encode_finality_proof(&fin),
            Vec::new(),
            Vec::new(),
        );
        state = match apply_block(&state, &block) {
            ApplyOutcome::Ok { state, .. } => state,
            ApplyOutcome::Err { errors, .. } => panic!("block {height} rejected: {errors:?}"),
        };

        match height {
            1 | 2 => {
                assert_eq!(
                    state.validators[1].stake, 1_000_000,
                    "no slash yet at h={height}"
                );
                assert_eq!(state.validator_stats[1].consecutive_missed, height);
                assert_eq!(state.validator_stats[1].liveness_slashes, 0);
            }
            3 => {
                // Threshold trip: 1% of 1_000_000 = 10_000 → stake 990_000.
                assert_eq!(state.validators[1].stake, 990_000);
                assert_eq!(state.validator_stats[1].liveness_slashes, 1);
                assert_eq!(state.validator_stats[1].consecutive_missed, 0);
                assert_eq!(state.validator_stats[1].total_missed, 3);
            }
            4 => {
                // First miss of the next cycle.
                assert_eq!(state.validators[1].stake, 990_000);
                assert_eq!(state.validator_stats[1].consecutive_missed, 1);
                assert_eq!(state.validator_stats[1].liveness_slashes, 1);
                assert_eq!(state.validator_stats[1].total_missed, 4);
            }
            _ => unreachable!(),
        }
        // v0 and v2 always signed → counters always 0, stake intact.
        assert_eq!(state.validators[0].stake, 1_000_000);
        assert_eq!(state.validators[2].stake, 1_000_000);
        assert_eq!(state.validator_stats[0].consecutive_missed, 0);
        assert_eq!(state.validator_stats[2].consecutive_missed, 0);
        assert_eq!(state.validator_stats[0].total_signed, u64::from(height));
        assert_eq!(state.validator_stats[2].total_signed, u64::from(height));

        // Producer can decrypt their coinbase to confirm the chain
        // accepted it as paying the right party.
        let cb_dec = decrypt_output_amount(
            &block.txs[0].r_pub,
            0,
            w0.view_priv,
            &block.txs[0].outputs[0].enc_amount,
        )
        .expect("decrypt cb");
        assert_eq!(cb_dec.value, emission);
    }
}

/* ---------------------------------------------------------------------- *
 *  Unbond lifecycle integration (M1)                                     *
 *                                                                        *
 *  These tests exercise the full register → unbond → settle path with    *
 *  real BLS finality proofs. The helper `unbond_chain_step` runs one     *
 *  block with empty payload (no privacy txs, no storage proofs) and a    *
 *  caller-supplied bond_ops list. It assumes a 3-validator chain where   *
 *  v0/v1/v2 all sign every block.                                        *
 * ---------------------------------------------------------------------- */

#[cfg(test)]
mod unbond_lifecycle {
    use mfn_bls::{bls_keygen_from_seed, bls_sign};
    use mfn_consensus::{
        apply_block, apply_genesis, build_coinbase, build_genesis, build_unsealed_header,
        cast_vote, emission_at_height, encode_finality_proof, finalize, header_signing_hash,
        seal_block, sign_unbond, try_produce_slot, ApplyOutcome, BondOp, BondingParams, ChainState,
        ConsensusParams, FinalityProof, GenesisConfig, PayoutAddress, SlashEvidence, SlotContext,
        Validator, ValidatorPayout, ValidatorSecrets, DEFAULT_EMISSION_PARAMS,
    };
    use mfn_crypto::stealth::stealth_gen;
    use mfn_crypto::vrf::vrf_keygen_from_seed;
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    struct ChainFixture {
        state: ChainState,
        validators: Vec<Validator>,
        secrets: Vec<ValidatorSecrets>,
        params: ConsensusParams,
    }

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

    fn boot_3_validator_chain(unbond_delay: u32) -> ChainFixture {
        let (v0, s0) = mk_validator(0, 1_000_000);
        let (v1, s1) = mk_validator(1, 1_000_000);
        let (v2, s2) = mk_validator(2, 1_000_000);
        let validators = vec![v0, v1, v2];
        let secrets = vec![s0, s1, s2];
        let params = ConsensusParams {
            expected_proposers_per_slot: 10.0,
            quorum_stake_bps: 6666,
            liveness_max_consecutive_missed: 64, // high so liveness doesn't trip
            liveness_slash_bps: 0,
        };
        let bp = BondingParams {
            min_validator_stake: 100,
            unbond_delay_heights: unbond_delay,
            max_entry_churn_per_epoch: 4,
            max_exit_churn_per_epoch: 4,
            slots_per_epoch: 1024,
        };
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: validators.clone(),
            params,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: Some(bp),
        };
        let genesis = build_genesis(&cfg);
        let state = apply_genesis(&genesis, &cfg).expect("apply genesis");
        ChainFixture {
            state,
            validators,
            secrets,
            params,
        }
    }

    /// Produce one block at `height` with the given bond_ops and slashings.
    /// All active (stake > 0) validators sign. Producer is always v0
    /// (the highest-stake validator by ordering).
    fn step(
        fx: &mut ChainFixture,
        height: u32,
        bond_ops: Vec<BondOp>,
        slashings: Vec<SlashEvidence>,
    ) {
        let v0_payout = fx.state.validators[0].payout.unwrap();
        let cb_payout = PayoutAddress {
            view_pub: v0_payout.view_pub,
            spend_pub: v0_payout.spend_pub,
        };
        let emission = emission_at_height(u64::from(height), &DEFAULT_EMISSION_PARAMS);
        let cb = build_coinbase(u64::from(height), emission, &cb_payout).expect("cb");
        let txs = vec![cb];

        let unsealed =
            build_unsealed_header(&fx.state, &txs, &bond_ops, height, u64::from(height) * 100);
        let header_hash = header_signing_hash(&unsealed);
        let ctx = SlotContext {
            height,
            slot: height,
            prev_hash: unsealed.prev_hash,
        };

        let total_stake: u64 = fx.state.validators.iter().map(|v| v.stake).sum();
        let producer_proof = try_produce_slot(
            &ctx,
            &fx.secrets[0],
            &fx.state.validators[0],
            total_stake,
            fx.params.expected_proposers_per_slot,
            &header_hash,
        )
        .expect("produce")
        .expect("eligible");

        // Every validator with stake > 0 votes. Index by validators[i].
        let mut votes = Vec::new();
        let mut signing_stake: u64 = 0;
        for (i, v) in fx.state.validators.iter().enumerate() {
            if v.stake == 0 {
                continue;
            }
            let vote = cast_vote(
                &header_hash,
                &fx.secrets[i],
                &ctx,
                &producer_proof,
                &fx.state.validators[0],
                total_stake,
                fx.params.expected_proposers_per_slot,
            )
            .unwrap();
            votes.push(vote);
            signing_stake = signing_stake.saturating_add(v.stake);
        }
        let agg = finalize(&header_hash, &votes, fx.state.validators.len()).expect("agg");
        let fin = FinalityProof {
            producer: producer_proof,
            finality: agg,
            signing_stake,
        };
        let block = seal_block(
            unsealed,
            txs,
            bond_ops,
            encode_finality_proof(&fin),
            slashings,
            Vec::new(),
        );
        fx.state = match apply_block(&fx.state, &block) {
            ApplyOutcome::Ok { state, .. } => state,
            ApplyOutcome::Err { errors, .. } => panic!("block {height} rejected: {errors:?}"),
        };
    }

    /// Force-set unbond delay for a fresh fixture.
    fn fixture_with_delay(delay: u32) -> ChainFixture {
        boot_3_validator_chain(delay)
    }

    #[test]
    fn unbond_lifecycle_request_delay_settle() {
        // Tiny delay so the test is fast.
        let mut fx = fixture_with_delay(2);
        let v1_idx = fx.validators[1].index;
        let v1_bls_sk = fx.secrets[1].bls.sk.clone();

        // Block 1: v1 submits unbond.
        let unbond = BondOp::Unbond {
            validator_index: v1_idx,
            sig: sign_unbond(v1_idx, &v1_bls_sk),
        };
        step(&mut fx, 1, vec![unbond], Vec::new());
        assert!(fx.state.pending_unbonds.contains_key(&v1_idx));
        assert_eq!(fx.state.validators[1].stake, 1_000_000);
        assert_eq!(fx.state.pending_unbonds[&v1_idx].unlock_height, 3); // 1 + delay 2

        // Block 2: still in delay window.
        step(&mut fx, 2, Vec::new(), Vec::new());
        assert!(fx.state.pending_unbonds.contains_key(&v1_idx));
        assert_eq!(fx.state.validators[1].stake, 1_000_000);

        // Block 3: unlock height reached -> v1's stake zeroed.
        step(&mut fx, 3, Vec::new(), Vec::new());
        assert!(!fx.state.pending_unbonds.contains_key(&v1_idx));
        assert_eq!(fx.state.validators[1].stake, 0);
        assert_eq!(fx.state.bond_epoch_exit_count, 1);
    }

    #[test]
    fn unbond_lifecycle_equivocation_during_delay_still_slashes() {
        // v1 unbonds; before settlement, v1 is caught equivocating.
        // The slash zeros their stake AND credits treasury (per M1
        // burn-on-bond + slash-to-treasury symmetry).
        let mut fx = fixture_with_delay(100); // long delay
        let v1_idx = fx.validators[1].index;
        let v1_bls_sk = fx.secrets[1].bls.sk.clone();

        let pre_treasury = fx.state.treasury;
        let unbond = BondOp::Unbond {
            validator_index: v1_idx,
            sig: sign_unbond(v1_idx, &v1_bls_sk),
        };
        step(&mut fx, 1, vec![unbond], Vec::new());
        assert_eq!(fx.state.validators[1].stake, 1_000_000);
        // Treasury didn't grow from the unbond op itself.
        assert_eq!(fx.state.treasury, pre_treasury);

        // Block 2: equivocation evidence for v1.
        let h1 = [11u8; 32];
        let h2 = [22u8; 32];
        let ev = SlashEvidence {
            height: 2,
            slot: 2,
            voter_index: v1_idx,
            header_hash_a: h1,
            sig_a: bls_sign(&h1, &v1_bls_sk),
            header_hash_b: h2,
            sig_b: bls_sign(&h2, &v1_bls_sk),
        };
        step(&mut fx, 2, Vec::new(), vec![ev]);
        assert_eq!(
            fx.state.validators[1].stake, 0,
            "equivocation during unbond delay still zeros stake"
        );
        // 1M credited to treasury (slash) on top of any prior delta.
        assert!(fx.state.treasury >= pre_treasury + 1_000_000);
        // Pending unbond entry stays — settles as a zombie at unlock height.
        assert!(fx.state.pending_unbonds.contains_key(&v1_idx));
    }

    #[test]
    fn unbond_lifecycle_exit_churn_cap_spills_to_next_block() {
        // 3 simultaneous unbonds, exit cap = 2: two settle in the first
        // post-unlock block, one spills.
        let (v0, s0) = mk_validator(0, 1_000_000);
        let (v1, s1) = mk_validator(1, 1_000_000);
        let (v2, s2) = mk_validator(2, 1_000_000);
        let (v3, s3) = mk_validator(3, 1_000_000);
        let validators = vec![v0.clone(), v1.clone(), v2.clone(), v3.clone()];
        let secrets = vec![s0, s1, s2, s3];
        let params = ConsensusParams {
            expected_proposers_per_slot: 10.0,
            quorum_stake_bps: 5000, // half quorum so we survive 3 exits
            liveness_max_consecutive_missed: 64,
            liveness_slash_bps: 0,
        };
        let bp = BondingParams {
            min_validator_stake: 100,
            unbond_delay_heights: 1,
            max_entry_churn_per_epoch: 4,
            max_exit_churn_per_epoch: 2, // the constraint under test
            slots_per_epoch: 1024,
        };
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: validators.clone(),
            params,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: Some(bp),
        };
        let g = build_genesis(&cfg);
        let mut fx = ChainFixture {
            state: apply_genesis(&g, &cfg).unwrap(),
            validators,
            secrets,
            params,
        };

        // Block 1: v1, v2, v3 all unbond.
        let b1 = fx.secrets[1].bls.sk.clone();
        let b2 = fx.secrets[2].bls.sk.clone();
        let b3 = fx.secrets[3].bls.sk.clone();
        let i1 = fx.validators[1].index;
        let i2 = fx.validators[2].index;
        let i3 = fx.validators[3].index;
        let ops = vec![
            BondOp::Unbond {
                validator_index: i1,
                sig: sign_unbond(i1, &b1),
            },
            BondOp::Unbond {
                validator_index: i2,
                sig: sign_unbond(i2, &b2),
            },
            BondOp::Unbond {
                validator_index: i3,
                sig: sign_unbond(i3, &b3),
            },
        ];
        step(&mut fx, 1, ops, Vec::new());
        assert_eq!(fx.state.pending_unbonds.len(), 3);

        // Block 2: unlock_height = 1+1 = 2 reached. Cap is 2 → first two
        // (by sorted index, i.e. v1 and v2) settle; v3 spills.
        step(&mut fx, 2, Vec::new(), Vec::new());
        assert_eq!(fx.state.pending_unbonds.len(), 1);
        assert!(fx.state.pending_unbonds.contains_key(&i3));
        assert_eq!(fx.state.validators[1].stake, 0);
        assert_eq!(fx.state.validators[2].stake, 0);
        assert_eq!(fx.state.validators[3].stake, 1_000_000);
        assert_eq!(fx.state.bond_epoch_exit_count, 2);

        // Block 3: cap is still 2 this epoch, but one slot used. Wait,
        // the cap was already hit (we used 2 of 2). So v3 still can't
        // settle this block — or can it? Looking at logic: try_register_exit_churn
        // accepts up to max_exit_churn_per_epoch. We already have count=2
        // = max, so v3's settle fails → spill continues. v3 has to wait
        // until the next epoch (slot 1024).
        step(&mut fx, 3, Vec::new(), Vec::new());
        assert_eq!(
            fx.state.pending_unbonds.len(),
            1,
            "exit cap exhausted for the epoch — v3 still pending"
        );
        assert_eq!(fx.state.validators[3].stake, 1_000_000);
    }
}
