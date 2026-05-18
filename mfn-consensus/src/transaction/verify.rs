//! Transaction verification.

#![allow(unused_imports)]

use super::build::placeholder_clsag;
use super::internal::*;
use super::wire::{TransactionWire, TxInputWire};
use super::{tx_id, tx_preimage, TX_RANGE_BITS, TX_VERSION};

/* ----------------------------------------------------------------------- *
 *  Verification                                                            *
 * ----------------------------------------------------------------------- */

/// Result of [`verify_transaction`].
#[derive(Clone, Debug)]
pub struct VerifyResult {
    /// `true` iff every check passed.
    pub ok: bool,
    /// Diagnostic strings for failures (empty when `ok`).
    pub errors: Vec<String>,
    /// Key images this tx spends — the mempool / block validator uses these
    /// to detect global double-spends.
    pub key_images: Vec<EdwardsPoint>,
    /// The transaction id (hash over preimage + signatures).
    pub tx_id: [u8; 32],
}

/// Validate a transaction. Pure function: no chain state required.
///
/// Performs every check the consensus rules demand at tx ingress:
/// version + structural shape, range proofs, balance equation,
/// CLSAG signatures, within-tx key-image uniqueness.
pub fn verify_transaction(tx: &TransactionWire) -> VerifyResult {
    let mut errors = Vec::new();

    if tx.version != TX_VERSION {
        errors.push(format!(
            "bad version {} (expected {})",
            tx.version, TX_VERSION
        ));
    }
    if tx.inputs.is_empty() {
        errors.push("no inputs".to_string());
    }
    if tx.outputs.is_empty() {
        errors.push("no outputs".to_string());
    }

    // Range proofs: bound to the on-chain amount commitment.
    for (i, out) in tx.outputs.iter().enumerate() {
        if out.amount != out.range_proof.v {
            errors.push(format!(
                "output {i}: range-proof V does not match output amount"
            ));
            continue;
        }
        if out.range_proof.n != TX_RANGE_BITS {
            errors.push(format!(
                "output {i}: range-proof bit-width {} ≠ canonical {TX_RANGE_BITS}",
                out.range_proof.n
            ));
            continue;
        }
        if !bp_verify(&out.range_proof) {
            errors.push(format!("output {i}: range proof invalid"));
        }
    }

    // Balance equation: Σ c_pseudo − Σ amount − fee·H == 0
    let mut balance = EdwardsPoint::identity();
    for inp in &tx.inputs {
        balance += inp.c_pseudo;
    }
    for out in &tx.outputs {
        balance -= out.amount;
    }
    balance -= generator_h() * Scalar::from(tx.fee);
    if balance != EdwardsPoint::identity() {
        errors.push("balance proof failed (Σ pseudo ≠ Σ out + fee·H)".to_string());
    }

    // Reconstruct the signing preimage (no signatures in the preimage).
    let stub_inputs: Vec<TxInputWire> = tx
        .inputs
        .iter()
        .map(|inp| TxInputWire {
            ring: inp.ring.clone(),
            c_pseudo: inp.c_pseudo,
            sig: placeholder_clsag(),
        })
        .collect();
    let stub = TransactionWire {
        version: tx.version,
        r_pub: tx.r_pub,
        inputs: stub_inputs,
        outputs: tx.outputs.clone(),
        fee: tx.fee,
        extra: tx.extra.clone(),
    };
    let msg = tx_preimage(&stub);

    // CLSAG verifications + within-tx key-image uniqueness.
    let mut seen_ki: Vec<[u8; 32]> = Vec::with_capacity(tx.inputs.len());
    let mut key_images: Vec<EdwardsPoint> = Vec::with_capacity(tx.inputs.len());
    for (i, inp) in tx.inputs.iter().enumerate() {
        if !clsag_verify(&msg, &inp.ring, &inp.c_pseudo, &inp.sig) {
            errors.push(format!("input {i}: CLSAG signature invalid"));
        }
        let ki_bytes = inp.sig.key_image.compress().to_bytes();
        if seen_ki.iter().any(|prev| prev == &ki_bytes) {
            errors.push(format!("input {i}: key image repeated within tx"));
        } else {
            seen_ki.push(ki_bytes);
            key_images.push(inp.sig.key_image);
        }
    }

    let tx_id = tx_id(tx);
    VerifyResult {
        ok: errors.is_empty(),
        errors,
        key_images,
        tx_id,
    }
}
