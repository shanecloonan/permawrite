#![allow(unused_imports)]

use super::internal::*;
use super::{
    decode_transaction, encode_transaction, sign_transaction, tx_id, tx_preimage,
    verify_transaction, InputSpec, OutputSpec, Recipient, SignedTransaction, TransactionWire,
    TxBuildError, TxDecodeError, TxInputWire, TxOutputWire, VerifyResult, TX_RANGE_BITS,
    TX_VERSION,
};
use crate::block::RingPolicy;
use mfn_crypto::pedersen::pedersen_commit;
use mfn_crypto::stealth::{indexed_stealth_spend_key, stealth_gen, StealthWallet};

/// Build a fake ring of size `n` and return (ring, signer_idx,
/// spend_priv, value, blinding) for the real input at `signer_idx`.
fn make_input(value: u64, ring_size: usize) -> InputSpec {
    let signer_idx = ring_size / 2;
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
            p.push(generator_g() * s);
            let v_dec = random_scalar();
            c.push((generator_g() * random_scalar()) + (generator_h() * v_dec));
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

fn recipient() -> (StealthWallet, Recipient) {
    let w = stealth_gen();
    let r = Recipient {
        view_pub: w.view_pub,
        spend_pub: w.spend_pub,
    };
    (w, r)
}

#[test]
fn sign_and_verify_round_trip_single_input_two_outputs() {
    let inputs = vec![make_input(1_000_000, 8)];
    let (_w_a, ra) = recipient();
    let (_w_b, rb) = recipient();
    let outputs = vec![
        OutputSpec::ToRecipient {
            recipient: ra,
            value: 600_000,
            storage: None,
        },
        OutputSpec::ToRecipient {
            recipient: rb,
            value: 399_000,
            storage: None,
        },
    ];
    let signed = sign_transaction(inputs, outputs, 1_000, Vec::new()).expect("sign");

    let res = verify_transaction(&signed.tx, &RingPolicy::TEST);
    assert!(res.ok, "errors: {:?}", res.errors);
    assert_eq!(res.key_images.len(), 1);
}

/// F5-P5 / B1: under a policy with the output floor active, a
/// single-output transaction is a consensus reject — the wallet-layer
/// two-output pad is now network-wide law, not courtesy.
#[test]
fn single_output_tx_rejected_when_output_floor_active() {
    let floor_only = RingPolicy {
        min_output_count: crate::block::MIN_TX_OUTPUTS_UNIFORM_TIER,
        ..RingPolicy::TEST
    };
    let inputs = vec![make_input(1_000_000, 4)];
    let (_w, r) = recipient();
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 999_000,
        storage: None,
    }];
    let signed = sign_transaction(inputs, outputs, 1_000, Vec::new()).expect("sign");

    // Same tx, floor off: valid.
    assert!(verify_transaction(&signed.tx, &RingPolicy::TEST).ok);

    // Floor on: rejected with the specific diagnostic.
    let res = verify_transaction(&signed.tx, &floor_only);
    assert!(!res.ok, "single-output tx must fail the output floor");
    assert!(
        res.errors
            .iter()
            .any(|e| e.contains("anti-fingerprinting floor")),
        "expected the floor diagnostic, got: {:?}",
        res.errors
    );
}

/// The output floor engages exactly when the uniform-ring tier is on:
/// production params derive `min_output_count == 2`, test params derive 0.
#[test]
fn ring_policy_derivation_ties_output_floor_to_uniform_tier() {
    use crate::block::{DEFAULT_CONSENSUS_PARAMS, TEST_CONSENSUS_PARAMS};
    assert_eq!(
        DEFAULT_CONSENSUS_PARAMS.ring_policy().min_output_count,
        crate::block::MIN_TX_OUTPUTS_UNIFORM_TIER
    );
    assert_eq!(TEST_CONSENSUS_PARAMS.ring_policy().min_output_count, 0);
    assert_eq!(
        RingPolicy::PRODUCTION.min_output_count,
        crate::block::MIN_TX_OUTPUTS_UNIFORM_TIER
    );
    assert_eq!(
        DEFAULT_CONSENSUS_PARAMS.ring_policy(),
        RingPolicy::PRODUCTION,
        "derived production policy must equal the PRODUCTION constant"
    );
}

/// A two-output tx passes the floor (and everything else) under a
/// floor-active policy.
#[test]
fn two_output_tx_passes_output_floor() {
    let floor_only = RingPolicy {
        min_output_count: crate::block::MIN_TX_OUTPUTS_UNIFORM_TIER,
        ..RingPolicy::TEST
    };
    let inputs = vec![make_input(1_000_000, 4)];
    let (_w_a, ra) = recipient();
    let (_w_b, rb) = recipient();
    let outputs = vec![
        OutputSpec::ToRecipient {
            recipient: ra,
            value: 600_000,
            storage: None,
        },
        OutputSpec::ToRecipient {
            recipient: rb,
            value: 399_000,
            storage: None,
        },
    ];
    let signed = sign_transaction(inputs, outputs, 1_000, Vec::new()).expect("sign");
    let res = verify_transaction(&signed.tx, &floor_only);
    assert!(res.ok, "errors: {:?}", res.errors);
}

#[test]
fn multi_input_multi_output_balances() {
    let inputs = vec![
        make_input(500_000, 6),
        make_input(500_000, 6),
        make_input(100_000, 6),
    ];
    let (_w_a, ra) = recipient();
    let (_w_b, rb) = recipient();
    let outputs = vec![
        OutputSpec::ToRecipient {
            recipient: ra,
            value: 700_000,
            storage: None,
        },
        OutputSpec::ToRecipient {
            recipient: rb,
            value: 395_000,
            storage: None,
        },
    ];
    let signed = sign_transaction(inputs, outputs, 5_000, Vec::new()).expect("sign");
    let res = verify_transaction(&signed.tx, &RingPolicy::TEST);
    assert!(res.ok, "errors: {:?}", res.errors);
    assert_eq!(res.key_images.len(), 3);
}

#[test]
fn recipient_can_open_stealth_output() {
    let inputs = vec![make_input(200_000, 4)];
    let (wallet, r) = recipient();
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 199_500,
        storage: None,
    }];
    let signed = sign_transaction(inputs, outputs, 500, Vec::new()).expect("sign");
    let res = verify_transaction(&signed.tx, &RingPolicy::TEST);
    assert!(res.ok);

    // Recipient derives the one-time spend key for output 0.
    let one_time_priv = indexed_stealth_spend_key(&signed.tx.r_pub, 0, &wallet);
    let derived = generator_g() * one_time_priv;
    assert_eq!(derived, signed.tx.outputs[0].one_time_addr);
}

#[test]
fn tampered_amount_breaks_balance() {
    let inputs = vec![make_input(100_000, 4)];
    let (_w, r) = recipient();
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 99_500,
        storage: None,
    }];
    let signed = sign_transaction(inputs, outputs, 500, Vec::new()).expect("sign");
    let mut tx = signed.tx;

    // Replace output amount with a different commitment.
    let bad = pedersen_commit(Scalar::from(123u64), None);
    tx.outputs[0].amount = bad.c;

    let res = verify_transaction(&tx, &RingPolicy::TEST);
    assert!(!res.ok);
    // Could fail balance or range-proof binding (or both).
    assert!(res.errors.iter().any(|e| e.contains("balance")
        || e.contains("range-proof V")
        || e.contains("range proof")));
}

#[test]
fn tampered_fee_breaks_balance() {
    let inputs = vec![make_input(100_000, 4)];
    let (_w, r) = recipient();
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 99_500,
        storage: None,
    }];
    let signed = sign_transaction(inputs, outputs, 500, Vec::new()).expect("sign");
    let mut tx = signed.tx;
    tx.fee = 600;

    let res = verify_transaction(&tx, &RingPolicy::TEST);
    assert!(!res.ok);
    assert!(res
        .errors
        .iter()
        .any(|e| e.contains("balance") || e.contains("CLSAG")));
}

#[test]
fn key_image_repeated_within_tx_rejected() {
    let inputs = vec![make_input(100_000, 4)];
    let (_w, r) = recipient();
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 99_500,
        storage: None,
    }];
    let signed = sign_transaction(inputs, outputs, 500, Vec::new()).expect("sign");
    let mut tx = signed.tx;
    // Duplicate the signed input, which duplicates the key image.
    let dup = tx.inputs[0].clone();
    tx.inputs.push(dup);

    let res = verify_transaction(&tx, &RingPolicy::TEST);
    assert!(!res.ok);
    assert!(res
        .errors
        .iter()
        .any(|e| e.contains("key image repeated") || e.contains("balance")));
}

#[test]
fn key_image_not_in_prime_subgroup_rejected() {
    // A valid signed tx whose key image is perturbed by a non-identity
    // order-8 torsion point is no longer a prime-order-subgroup member and
    // must be rejected by the consensus key-image validity check. This is
    // the key-image-malleability guard (Monero parity).
    let inputs = vec![make_input(100_000, 4)];
    let (_w, r) = recipient();
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 99_500,
        storage: None,
    }];
    let signed = sign_transaction(inputs, outputs, 500, Vec::new()).expect("sign");
    let mut tx = signed.tx;

    // EIGHT_TORSION[0] is the identity; [1] is a non-identity order-8 point.
    let torsion = curve25519_dalek::constants::EIGHT_TORSION[1];
    assert!(!torsion.is_torsion_free(), "sanity: [1] is a torsion point");
    tx.inputs[0].sig.key_image += torsion;

    let res = verify_transaction(&tx, &RingPolicy::TEST);
    assert!(!res.ok);
    assert!(
        res.errors
            .iter()
            .any(|e| e.contains("not in prime-order subgroup")),
        "expected prime-order-subgroup rejection, got: {:?}",
        res.errors
    );
}

#[test]
fn key_image_identity_rejected() {
    // A degenerate all-zero (identity) key image is rejected outright.
    let inputs = vec![make_input(100_000, 4)];
    let (_w, r) = recipient();
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 99_500,
        storage: None,
    }];
    let signed = sign_transaction(inputs, outputs, 500, Vec::new()).expect("sign");
    let mut tx = signed.tx;
    tx.inputs[0].sig.key_image = EdwardsPoint::identity();

    let res = verify_transaction(&tx, &RingPolicy::TEST);
    assert!(!res.ok);
    assert!(
        res.errors.iter().any(|e| e.contains("identity")),
        "expected identity rejection, got: {:?}",
        res.errors
    );
}

#[test]
fn honest_key_image_still_accepted() {
    // Guard against over-rejection: an honestly-signed tx (key image
    // `x·H_p(P)`, torsion-free by cofactor clearing) must still verify.
    let inputs = vec![make_input(250_000, 8)];
    let (_w, r) = recipient();
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 249_500,
        storage: None,
    }];
    let signed = sign_transaction(inputs, outputs, 500, Vec::new()).expect("sign");
    assert!(
        signed.tx.inputs[0].sig.key_image.is_torsion_free(),
        "honest key image must be a prime-order-subgroup member"
    );
    let res = verify_transaction(&signed.tx, &RingPolicy::TEST);
    assert!(res.ok, "honest tx must verify: {:?}", res.errors);
    assert_eq!(res.key_images.len(), 1);
}

#[test]
fn unbalanced_inputs_rejected_at_sign() {
    let inputs = vec![make_input(1_000, 4)];
    let (_w, r) = recipient();
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 2_000, // > input total
        storage: None,
    }];
    let err = sign_transaction(inputs, outputs, 0, Vec::new()).unwrap_err();
    assert!(matches!(err, TxBuildError::UnbalancedAmounts { .. }));
}

#[test]
fn tx_id_changes_when_signature_changes() {
    let inputs = vec![make_input(100_000, 4)];
    let (_w, r) = recipient();
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 99_500,
        storage: None,
    }];
    let signed_a =
        sign_transaction(inputs.clone(), outputs.clone(), 500, Vec::new()).expect("sign A");
    let signed_b = sign_transaction(inputs, outputs, 500, Vec::new()).expect("sign B");

    // Different `r` scalar each time → different tx-level R, different sigs.
    assert_ne!(
        tx_id(&signed_a.tx),
        tx_id(&signed_b.tx),
        "two signings differ in tx-level R"
    );
}

#[test]
fn extra_payload_is_committed() {
    let inputs = vec![make_input(100_000, 4)];
    let (_w, r) = recipient();
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 99_500,
        storage: None,
    }];
    let signed = sign_transaction(inputs, outputs, 500, b"hello".to_vec()).expect("sign");
    let mut tx = signed.tx;
    let id_before = tx_id(&tx);
    tx.extra = b"hellp".to_vec();
    let id_after = tx_id(&tx);
    assert_ne!(id_before, id_after);
}

#[test]
fn storage_commitment_binds_into_preimage() {
    let inputs = vec![make_input(100_000, 4)];
    let (_w, r) = recipient();
    let commit = StorageCommitment {
        data_root: [9u8; 32],
        size_bytes: 4096,
        chunk_size: 4096,
        num_chunks: 1,
        replication: 3,
        endowment: generator_g() * Scalar::from(42u64),
    };
    let outputs = vec![OutputSpec::ToRecipient {
        recipient: r,
        value: 99_500,
        storage: Some(commit.clone()),
    }];
    let signed = sign_transaction(inputs, outputs, 500, Vec::new()).expect("sign");
    assert!(verify_transaction(&signed.tx, &RingPolicy::TEST).ok);

    // Tamper with storage commit → tx_id changes.
    let mut tx = signed.tx;
    let mut bad = commit;
    bad.replication = 4;
    tx.outputs[0].storage = Some(bad);
    // The tx is now inconsistent with its CLSAG signatures.
    assert!(!verify_transaction(&tx, &RingPolicy::TEST).ok);
}

/* ---------------------------------------------------------------- *
 *  Wire codec (M2.0.10)                                              *
 * ---------------------------------------------------------------- */

fn signed_simple_tx() -> SignedTransaction {
    let inputs = vec![make_input(1_000_000, 8)];
    let (_w_a, ra) = recipient();
    let (_w_b, rb) = recipient();
    let outputs = vec![
        OutputSpec::ToRecipient {
            recipient: ra,
            value: 600_000,
            storage: None,
        },
        OutputSpec::ToRecipient {
            recipient: rb,
            value: 399_000,
            storage: None,
        },
    ];
    sign_transaction(inputs, outputs, 1_000, b"memo".to_vec()).expect("sign")
}

fn signed_multi_input_storage_tx() -> SignedTransaction {
    let inputs = vec![
        make_input(500_000, 6),
        make_input(500_000, 6),
        make_input(100_000, 6),
    ];
    let (_w_a, ra) = recipient();
    let (_w_b, rb) = recipient();
    let commit = StorageCommitment {
        data_root: [9u8; 32],
        size_bytes: 4096,
        chunk_size: 4096,
        num_chunks: 1,
        replication: 3,
        endowment: generator_g() * Scalar::from(123u64),
    };
    let outputs = vec![
        OutputSpec::ToRecipient {
            recipient: ra,
            value: 700_000,
            storage: Some(commit),
        },
        OutputSpec::ToRecipient {
            recipient: rb,
            value: 395_000,
            storage: None,
        },
    ];
    sign_transaction(inputs, outputs, 5_000, Vec::new()).expect("sign")
}

#[test]
fn encode_decode_round_trip_simple_tx() {
    let signed = signed_simple_tx();
    let bytes = encode_transaction(&signed.tx);
    let recovered = decode_transaction(&bytes).expect("decode");

    // Byte-for-byte round-trip via re-encode.
    let re = encode_transaction(&recovered);
    assert_eq!(re, bytes, "transaction codec is not byte-deterministic");

    // tx_id agrees (the consensus-critical invariant).
    assert_eq!(tx_id(&recovered), tx_id(&signed.tx));

    // Re-verifying the decoded tx proves CLSAG / range / balance
    // all survived the round-trip intact.
    let v = verify_transaction(&recovered, &RingPolicy::TEST);
    assert!(v.ok, "decoded tx must verify: {:?}", v.errors);
}

#[test]
fn encode_decode_round_trip_multi_input_with_storage() {
    let signed = signed_multi_input_storage_tx();
    let bytes = encode_transaction(&signed.tx);
    let recovered = decode_transaction(&bytes).expect("decode");

    assert_eq!(encode_transaction(&recovered), bytes);
    assert_eq!(tx_id(&recovered), tx_id(&signed.tx));

    // Storage commitment survived intact (full struct, not just hash).
    assert_eq!(recovered.outputs[0].storage, signed.tx.outputs[0].storage);
    assert!(recovered.outputs[0].storage.is_some());
    assert!(recovered.outputs[1].storage.is_none());

    assert!(verify_transaction(&recovered, &RingPolicy::TEST).ok);
}

#[test]
fn encode_decode_raw_output_round_trip() {
    let inputs = vec![make_input(50_000, 4)];
    let one_time = generator_g() * random_scalar();
    let outputs = vec![OutputSpec::Raw {
        one_time_addr: one_time,
        value: 49_900,
        storage: None,
    }];
    let signed = sign_transaction(inputs, outputs, 100, Vec::new()).expect("sign");

    let bytes = encode_transaction(&signed.tx);
    let recovered = decode_transaction(&bytes).expect("decode");
    assert_eq!(tx_id(&recovered), tx_id(&signed.tx));
    assert!(verify_transaction(&recovered, &RingPolicy::TEST).ok);
}

#[test]
fn decode_rejects_truncation_at_every_prefix() {
    let signed = signed_simple_tx();
    let bytes = encode_transaction(&signed.tx);
    for prefix in 0..bytes.len() {
        let err = decode_transaction(&bytes[..prefix]);
        assert!(
            err.is_err(),
            "prefix of length {prefix}/{} should be rejected",
            bytes.len()
        );
    }
}

#[test]
fn decode_rejects_trailing_bytes() {
    let signed = signed_simple_tx();
    let mut bytes = encode_transaction(&signed.tx);
    bytes.push(0xff);
    let err = decode_transaction(&bytes).unwrap_err();
    assert!(matches!(err, TxDecodeError::TrailingBytes { remaining: 1 }));
}

#[test]
fn decode_rejects_invalid_storage_flag() {
    // Build a tx with no storage; the storage flag byte is `0`.
    // Find that byte in the encoded buffer and set it to `2`,
    // which is neither 0 nor 1. The decoder must reject it as a
    // structural error (not just an underlying codec failure)
    // because flags are part of this codec's contract.
    let signed = signed_simple_tx();
    let mut bytes = encode_transaction(&signed.tx);

    // The first output's storage flag lives near the end of the
    // tx — walk the encoded body deterministically by re-decoding
    // up to that point and noting the reader's position.
    //
    // Simpler: flip the LAST storage flag in the buffer. We know
    // the last output's storage flag is the byte right before the
    // tx tail (since storage was None → no trailing storage blob).
    // The encoder places the storage flag right before the next
    // output or end-of-tx, so the very LAST `0` byte in the
    // encoded buffer is a candidate — but to be exact, we
    // re-encode and locate it deterministically by reading the
    // length-prefix structure.
    //
    // To keep the test robust against future codec changes, we
    // simply search for the well-known `0u8` storage flag at the
    // exact offset we get by re-encoding the leading section and
    // counting bytes through one output. That's overkill — the
    // simpler approach below is to corrupt the last byte of the
    // encoded tx, which is precisely the second output's storage
    // flag (== 0). Re-encoding the tx (storage=None on the last
    // output) places the storage flag as the final byte.
    let last_idx = bytes.len() - 1;
    assert_eq!(bytes[last_idx], 0u8, "last byte should be storage flag 0");
    bytes[last_idx] = 2;
    let err = decode_transaction(&bytes).unwrap_err();
    assert!(matches!(err, TxDecodeError::InvalidStorageFlag { .. }));
}

#[test]
fn decode_preserves_storage_commitment_exactly() {
    let signed = signed_multi_input_storage_tx();
    let original = signed.tx.outputs[0].storage.as_ref().unwrap().clone();
    let bytes = encode_transaction(&signed.tx);
    let recovered = decode_transaction(&bytes).expect("decode");

    let got = recovered.outputs[0].storage.as_ref().unwrap();
    assert_eq!(got.data_root, original.data_root);
    assert_eq!(got.size_bytes, original.size_bytes);
    assert_eq!(got.chunk_size, original.chunk_size);
    assert_eq!(got.num_chunks, original.num_chunks);
    assert_eq!(got.replication, original.replication);
    assert_eq!(got.endowment, original.endowment);
}

#[test]
fn raw_one_time_addr_outputs_supported() {
    let inputs = vec![make_input(50_000, 4)];
    let one_time = generator_g() * random_scalar();
    let outputs = vec![OutputSpec::Raw {
        one_time_addr: one_time,
        value: 49_900,
        storage: None,
    }];
    let signed = sign_transaction(inputs, outputs, 100, Vec::new()).expect("sign");
    let res = verify_transaction(&signed.tx, &RingPolicy::TEST);
    assert!(res.ok, "errors: {:?}", res.errors);
    // Raw outputs get zero enc_amount blob (no recipient view-key).
    assert_eq!(signed.tx.outputs[0].enc_amount, [0u8; ENC_AMOUNT_BYTES]);
    assert!(signed.tx.outputs[0].view_tag.is_some());
}

#[test]
fn v2_outputs_carry_view_tags() {
    let inputs = vec![make_input(1_000_000, 4)];
    let (w, r) = recipient();
    let signed = sign_transaction(
        inputs,
        vec![OutputSpec::ToRecipient {
            recipient: r,
            value: 999_000,
            storage: None,
        }],
        1_000,
        Vec::new(),
    )
    .expect("sign");
    assert_eq!(signed.tx.version, TX_VERSION);
    let expected = mfn_crypto::stealth::indexed_view_tag(&signed.tx.r_pub, 0, &w.view_priv);
    assert_eq!(signed.tx.outputs[0].view_tag, Some(expected));
}

#[test]
fn legacy_v1_wire_decodes_without_view_tag_byte() {
    use super::TX_VERSION_LEGACY;

    let signed = sign_transaction(
        vec![make_input(500_000, 4)],
        vec![OutputSpec::ToRecipient {
            recipient: recipient().1,
            value: 499_000,
            storage: None,
        }],
        1_000,
        Vec::new(),
    )
    .expect("sign");
    let v2_bytes = encode_transaction(&signed.tx);
    // Strip the per-output view_tag byte(s) and downgrade version to v1.
    let mut v1_tx = signed.tx.clone();
    v1_tx.version = TX_VERSION_LEGACY;
    for out in &mut v1_tx.outputs {
        out.view_tag = None;
    }
    let v1_bytes = encode_transaction(&v1_tx);
    assert_ne!(v1_bytes, v2_bytes);
    let decoded = decode_transaction(&v1_bytes).expect("legacy v1 decode");
    assert_eq!(decoded.version, TX_VERSION_LEGACY);
    assert!(decoded.outputs.iter().all(|o| o.view_tag.is_none()));
}
