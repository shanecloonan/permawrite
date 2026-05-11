//! Coinbase — the synthetic block-reward transaction.
//!
//! A coinbase has **no inputs** (value is minted from thin air by protocol
//! rule) and **one output** paying the block producer. Its amount equals
//! `emission_at_height(height) + Σ fees` of the block; any deviation rejects
//! the block.
//!
//! Port of `cloonan-group/lib/network/coinbase.ts`.
//!
//! ## Deterministic ephemeral key
//!
//! For regular transactions the tx-level private scalar `r` is randomly
//! chosen and stays secret. For a coinbase, the sender is the *protocol* —
//! we have no one to keep `r` secret from — so we derive it deterministically
//! from public inputs, letting any node replay history byte-for-byte:
//!
//! ```text
//! r        = H_s( DOMAIN.COINBASE_TX_KEY || height_be8 || spend_pub )
//! R        = G · r
//! blinding = H_s( DOMAIN.COINBASE_BLIND || R || view_pub || spend_pub )
//! ```
//!
//! Leaking `r` here reveals nothing: the coinbase amount is already public
//! (every node can compute emission + Σ fees). When the validator later
//! spends the coinbase output, the spend itself goes through normal
//! CLSAG-with-decoys and inherits full RingCT privacy.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use mfn_crypto::bulletproofs::{bp_prove, bp_verify};
use mfn_crypto::codec::Writer;
use mfn_crypto::domain::{COINBASE_BLIND, COINBASE_TX_KEY};
use mfn_crypto::encrypted_amount::ENC_AMOUNT_BYTES;
use mfn_crypto::hash::hash_to_scalar;
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::stealth::{indexed_stealth_address, StealthPubKeys};

use crate::transaction::{TransactionWire, TxOutputWire, TX_RANGE_BITS, TX_VERSION};

/// Stealth payout address (view + spend pubkeys) of a block producer.
#[derive(Clone, Copy, Debug)]
pub struct PayoutAddress {
    /// Producer's public view key.
    pub view_pub: EdwardsPoint,
    /// Producer's public spend key.
    pub spend_pub: EdwardsPoint,
}

impl From<PayoutAddress> for StealthPubKeys {
    fn from(p: PayoutAddress) -> Self {
        StealthPubKeys {
            view_pub: p.view_pub,
            spend_pub: p.spend_pub,
        }
    }
}

/* ----------------------------------------------------------------------- *
 *  Deterministic key derivation                                            *
 * ----------------------------------------------------------------------- */

/// Compute the deterministic tx-priv scalar for a coinbase at `height`
/// paying `producer_spend_pub`. Public on purpose — `r` is not a secret for
/// coinbase, only a structural seed.
pub fn coinbase_tx_priv(height: u64, producer_spend_pub: &EdwardsPoint) -> Scalar {
    let mut w = Writer::new();
    w.push(COINBASE_TX_KEY);
    w.push(&height.to_be_bytes());
    w.point(producer_spend_pub);
    let s = hash_to_scalar(&[w.bytes()]);
    // Pathologically unlucky-zero recovery, deterministic per height.
    if s == Scalar::ZERO {
        Scalar::ONE
    } else {
        s
    }
}

/// Deterministic blinding factor for a coinbase output.
///
/// Not secret (the coinbase amount is public), so we derive it from public
/// inputs. Any node validating the block re-derives the same value.
fn coinbase_blinding(r_pub: &EdwardsPoint, payout: &PayoutAddress) -> Scalar {
    let mut w = Writer::new();
    w.push(COINBASE_BLIND);
    w.point(r_pub);
    w.point(&payout.view_pub);
    w.point(&payout.spend_pub);
    let s = hash_to_scalar(&[w.bytes()]);
    if s == Scalar::ZERO {
        Scalar::ONE
    } else {
        s
    }
}

/* ----------------------------------------------------------------------- *
 *  Build                                                                   *
 * ----------------------------------------------------------------------- */

/// Errors raised while constructing or verifying a coinbase.
#[derive(Debug, thiserror::Error)]
pub enum CoinbaseError {
    /// `height < 1`.
    #[error("coinbase: height must be >= 1 (got 0)")]
    HeightZero,
    /// Underlying crypto failure (range-proof construction can fail if the
    /// supplied value is somehow out-of-range, which we reject anyway).
    #[error(transparent)]
    Crypto(#[from] mfn_crypto::CryptoError),
}

/// Construct the coinbase [`TransactionWire`] paying `amount` to the
/// producer's stealth payout address. Anyone can build this — the function
/// is deterministic. In practice, the block producer calls it during
/// proposal.
pub fn build_coinbase(
    height: u64,
    amount: u64,
    payout: &PayoutAddress,
) -> Result<TransactionWire, CoinbaseError> {
    if height < 1 {
        return Err(CoinbaseError::HeightZero);
    }
    let tx_priv = coinbase_tx_priv(height, &payout.spend_pub);
    let r_pub = generator_g() * tx_priv;

    let payout_pk: StealthPubKeys = (*payout).into();
    // outputIndex = 0 by convention; only one output.
    let one_time_addr = indexed_stealth_address(tx_priv, &payout_pk, 0);
    let blinding = coinbase_blinding(&r_pub, payout);
    let amount_commit = (generator_g() * blinding) + (generator_h() * Scalar::from(amount));
    let bp = bp_prove(amount, &blinding, TX_RANGE_BITS)?;
    debug_assert_eq!(bp.v, amount_commit);

    let enc_amount = mfn_crypto::encrypted_amount::encrypt_output_amount(
        tx_priv,
        &payout.view_pub,
        0,
        amount,
        &blinding,
    );

    let output = TxOutputWire {
        one_time_addr,
        amount: amount_commit,
        range_proof: bp.proof,
        enc_amount,
        storage: None,
    };

    Ok(TransactionWire {
        version: TX_VERSION,
        r_pub,
        inputs: Vec::new(),
        outputs: vec![output],
        fee: 0,
        extra: Vec::new(),
    })
}

/* ----------------------------------------------------------------------- *
 *  Verify                                                                  *
 * ----------------------------------------------------------------------- */

/// Result of [`verify_coinbase`].
#[derive(Clone, Debug)]
pub struct CoinbaseVerifyResult {
    /// `true` iff every check passed.
    pub ok: bool,
    /// Diagnostic strings for failures.
    pub errors: Vec<String>,
    /// Public amount this coinbase claims to mint (echoed back for callers).
    pub amount: u64,
}

/// Validate that a [`TransactionWire`] conforms to coinbase rules for a
/// given height, expected amount, and producer payout address.
///
/// Does NOT check the amount against the protocol's expected
/// `emission + Σ fees` for the block — that's `apply_block`'s job. This
/// function checks STRUCTURAL correctness only.
pub fn verify_coinbase(
    tx: &TransactionWire,
    height: u64,
    expected_amount: u64,
    payout: &PayoutAddress,
) -> CoinbaseVerifyResult {
    let mut errors = Vec::new();

    if tx.version != TX_VERSION {
        errors.push(format!(
            "bad version {} (expected {})",
            tx.version, TX_VERSION
        ));
    }
    if !tx.inputs.is_empty() {
        errors.push(format!(
            "coinbase has {} inputs (must be 0)",
            tx.inputs.len()
        ));
    }
    if tx.outputs.len() != 1 {
        errors.push(format!(
            "coinbase has {} outputs (must be 1)",
            tx.outputs.len()
        ));
    }
    if tx.fee != 0 {
        errors.push(format!("coinbase fee must be 0, got {}", tx.fee));
    }
    if !errors.is_empty() {
        return CoinbaseVerifyResult {
            ok: false,
            errors,
            amount: 0,
        };
    }

    let out = &tx.outputs[0];

    let tx_priv = coinbase_tx_priv(height, &payout.spend_pub);
    let expected_r = generator_g() * tx_priv;
    if expected_r != tx.r_pub {
        errors.push("R does not match deterministic coinbase derivation".to_string());
    }

    let payout_pk: StealthPubKeys = (*payout).into();
    let expected_one_time = indexed_stealth_address(tx_priv, &payout_pk, 0);
    if expected_one_time != out.one_time_addr {
        errors.push("one_time_addr does not match payout-derived stealth address".to_string());
    }

    let blinding = coinbase_blinding(&tx.r_pub, payout);
    let expected_commit =
        (generator_g() * blinding) + (generator_h() * Scalar::from(expected_amount));
    if expected_commit != out.amount {
        errors.push("amount commitment does not match (expected_amount, blinding)".to_string());
    }

    if out.amount != out.range_proof.v {
        errors.push("range-proof V does not match coinbase amount commitment".to_string());
    } else if out.range_proof.n != TX_RANGE_BITS {
        errors.push(format!(
            "range-proof bit-width {} ≠ {TX_RANGE_BITS}",
            out.range_proof.n
        ));
    } else if !bp_verify(&out.range_proof) {
        errors.push("range proof invalid".to_string());
    }

    if out.storage.is_some() {
        errors.push("coinbase output cannot anchor storage".to_string());
    }

    if out.enc_amount.len() != ENC_AMOUNT_BYTES {
        errors.push(format!(
            "enc_amount must be {ENC_AMOUNT_BYTES} bytes (got {})",
            out.enc_amount.len()
        ));
    }

    CoinbaseVerifyResult {
        ok: errors.is_empty(),
        errors,
        amount: expected_amount,
    }
}

/* ----------------------------------------------------------------------- *
 *  Identification + debug                                                  *
 * ----------------------------------------------------------------------- */

/// Heuristic: "this tx is shaped like a coinbase". The block applier uses
/// this to route the first tx through [`verify_coinbase`] instead of the
/// regular tx verifier. The unique structural signature is
/// `inputs.is_empty()`, which `verify_transaction` explicitly rejects.
#[inline]
pub fn is_coinbase_shaped(tx: &TransactionWire) -> bool {
    tx.inputs.is_empty()
}

/// Pretty-print a coinbase for test output / node logs (public info only).
pub fn describe_coinbase(tx: &TransactionWire, height: u64) -> String {
    if !is_coinbase_shaped(tx) || tx.outputs.len() != 1 {
        return "(not a coinbase)".to_string();
    }
    let one_time_hex = hex::encode(tx.outputs[0].one_time_addr.compress().to_bytes());
    format!(
        "coinbase{{height={height}, one_time_addr={}…}}",
        &one_time_hex[..16]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_crypto::encrypted_amount::decrypt_output_amount;
    use mfn_crypto::stealth::stealth_gen;

    fn fresh_payout() -> (PayoutAddress, mfn_crypto::stealth::StealthWallet) {
        let w = stealth_gen();
        (
            PayoutAddress {
                view_pub: w.view_pub,
                spend_pub: w.spend_pub,
            },
            w,
        )
    }

    #[test]
    fn build_and_verify_round_trip() {
        let (payout, _w) = fresh_payout();
        let cb = build_coinbase(42, 50_000_000, &payout).expect("build");
        let res = verify_coinbase(&cb, 42, 50_000_000, &payout);
        assert!(res.ok, "errors: {:?}", res.errors);
        assert_eq!(res.amount, 50_000_000);
    }

    #[test]
    fn deterministic_replay_matches_byte_for_byte() {
        let (payout, _w) = fresh_payout();
        let a = build_coinbase(100, 1_234_567, &payout).expect("build A");
        let b = build_coinbase(100, 1_234_567, &payout).expect("build B");

        assert_eq!(a.r_pub, b.r_pub);
        assert_eq!(a.outputs[0].one_time_addr, b.outputs[0].one_time_addr);
        assert_eq!(a.outputs[0].amount, b.outputs[0].amount);
        assert_eq!(a.outputs[0].enc_amount, b.outputs[0].enc_amount);
    }

    #[test]
    fn different_heights_yield_different_coinbases() {
        let (payout, _w) = fresh_payout();
        let a = build_coinbase(10, 1_000_000, &payout).expect("h=10");
        let b = build_coinbase(11, 1_000_000, &payout).expect("h=11");
        assert_ne!(a.r_pub, b.r_pub);
    }

    #[test]
    fn rejects_zero_height() {
        let (payout, _w) = fresh_payout();
        assert!(matches!(
            build_coinbase(0, 1, &payout),
            Err(CoinbaseError::HeightZero)
        ));
    }

    #[test]
    fn rejects_wrong_expected_amount() {
        let (payout, _w) = fresh_payout();
        let cb = build_coinbase(1, 50_000_000, &payout).expect("build");
        let res = verify_coinbase(&cb, 1, 50_000_001, &payout);
        assert!(!res.ok);
        assert!(res.errors.iter().any(|e| e.contains("amount commitment")));
    }

    #[test]
    fn rejects_wrong_payout() {
        let (payout_a, _w) = fresh_payout();
        let (payout_b, _w2) = fresh_payout();
        let cb = build_coinbase(1, 100, &payout_a).expect("build");
        let res = verify_coinbase(&cb, 1, 100, &payout_b);
        assert!(!res.ok);
    }

    #[test]
    fn rejects_extra_input() {
        let (payout, _w) = fresh_payout();
        let mut cb = build_coinbase(1, 100, &payout).expect("build");
        // Forge an input.
        cb.inputs.push(crate::transaction::TxInputWire {
            ring: mfn_crypto::clsag::ClsagRing {
                p: vec![generator_g()],
                c: vec![generator_g()],
            },
            c_pseudo: generator_g(),
            sig: mfn_crypto::clsag::ClsagSignature {
                c0: Scalar::ZERO,
                s: vec![Scalar::ZERO],
                key_image: generator_g(),
                d: generator_g(),
            },
        });
        let res = verify_coinbase(&cb, 1, 100, &payout);
        assert!(!res.ok);
        assert!(res.errors.iter().any(|e| e.contains("inputs")));
    }

    #[test]
    fn rejects_storage_on_coinbase() {
        let (payout, _w) = fresh_payout();
        let mut cb = build_coinbase(1, 100, &payout).expect("build");
        cb.outputs[0].storage = Some(crate::storage::StorageCommitment {
            data_root: [0u8; 32],
            size_bytes: 0,
            chunk_size: 1,
            num_chunks: 1,
            replication: 1,
            endowment: generator_g(),
        });
        let res = verify_coinbase(&cb, 1, 100, &payout);
        assert!(!res.ok);
        assert!(res.errors.iter().any(|e| e.contains("storage")));
    }

    #[test]
    fn is_coinbase_shaped_detects_no_input_txs() {
        let (payout, _w) = fresh_payout();
        let cb = build_coinbase(1, 100, &payout).expect("build");
        assert!(is_coinbase_shaped(&cb));
    }

    #[test]
    fn producer_can_decrypt_amount() {
        let (payout, wallet) = fresh_payout();
        let cb = build_coinbase(7, 25_000_000, &payout).expect("build");
        let dec = decrypt_output_amount(&cb.r_pub, 0, wallet.view_priv, &cb.outputs[0].enc_amount)
            .expect("decrypt");
        assert_eq!(dec.value, 25_000_000);
    }

    #[test]
    fn describe_pretty_prints() {
        let (payout, _w) = fresh_payout();
        let cb = build_coinbase(99, 1, &payout).expect("build");
        let s = describe_coinbase(&cb, 99);
        assert!(s.contains("height=99"));
        assert!(s.contains("one_time_addr="));
    }
}
