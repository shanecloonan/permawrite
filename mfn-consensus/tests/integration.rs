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
