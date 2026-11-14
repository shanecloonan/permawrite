//! Transaction verification.

#![allow(unused_imports)]

use super::build::placeholder_clsag;
use super::internal::*;
use super::wire::{TransactionWire, TxInputWire};
use super::{
    tx_id, tx_preimage, tx_version_supported, TX_RANGE_BITS, TX_VERSION, TX_VERSION_HIDDEN_FEE,
    TX_VERSION_LEGACY,
};
use crate::block::RingPolicy;

/* ----------------------------------------------------------------------- *
 *  Verification                                                            *
 * ----------------------------------------------------------------------- */

fn hidden_fee_term(
    tx: &TransactionWire,
    hidden_fees: bool,
    errors: &mut Vec<String>,
) -> EdwardsPoint {
    if tx.version == TX_VERSION_HIDDEN_FEE {
        if !hidden_fees {
            errors.push("hidden-fee transaction requires header version 6".to_string());
            return EdwardsPoint::identity();
        }
        if tx.fee != 0 {
            errors.push("hidden-fee transaction must encode plaintext fee as 0".to_string());
        }
        match (&tx.fee_commitment, &tx.fee_range_proof) {
            (Some(c), Some(proof)) => {
                if proof.v != *c || proof.n != TX_RANGE_BITS || !bp_verify(proof) {
                    errors.push("hidden fee range proof invalid".to_string());
                }
                *c
            }
            _ => {
                errors.push("hidden-fee transaction missing fee commitment".to_string());
                EdwardsPoint::identity()
            }
        }
    } else {
        if hidden_fees {
            errors.push("header version 6 requires a hidden-fee transaction".to_string());
        }
        if tx.fee_commitment.is_some() || tx.fee_range_proof.is_some() {
            errors.push("plaintext-fee transaction carries a fee commitment".to_string());
        }
        generator_h() * Scalar::from(tx.fee)
    }
}

/// `Σ fee_commitment = total·H + blinding·G`.
#[must_use]
pub fn fee_commitments_open(commits: &[EdwardsPoint], total: u64, blinding: &Scalar) -> bool {
    let mut sum = EdwardsPoint::identity();
    for c in commits {
        sum += *c;
    }
    sum == (generator_g() * blinding) + (generator_h() * Scalar::from(total))
}

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
pub fn verify_transaction(tx: &TransactionWire, ring: &RingPolicy) -> VerifyResult {
    let mut errors = Vec::new();

    if !tx_version_supported(tx.version) {
        errors.push(format!(
            "bad version {} (expected {} or {})",
            tx.version, TX_VERSION_LEGACY, TX_VERSION
        ));
    }
    if tx.version >= TX_VERSION {
        for (i, out) in tx.outputs.iter().enumerate() {
            if out.view_tag.is_none() {
                errors.push(format!("v2 output {i} missing view_tag"));
            }
        }
    }
    if tx.version == TX_VERSION_LEGACY {
        for (i, out) in tx.outputs.iter().enumerate() {
            if out.view_tag.is_some() {
                errors.push(format!("v1 output {i} must not carry view_tag"));
            }
        }
    }
    if tx.inputs.is_empty() {
        errors.push("no inputs".to_string());
    }
    if tx.outputs.is_empty() {
        errors.push("no outputs".to_string());
    }
    // Anti-fingerprinting output floor (F5-P5 / B1): under the uniform-ring
    // tier every regular tx must carry at least `min_output_count` outputs,
    // so a no-change sweep is indistinguishable from payment + change
    // network-wide (wallets already pad; this makes it consensus).
    if ring.min_output_count != 0 && (tx.outputs.len() as u32) < ring.min_output_count {
        errors.push(format!(
            "output count {} < consensus minimum {} (uniform-tier anti-fingerprinting floor)",
            tx.outputs.len(),
            ring.min_output_count
        ));
    }
    // Anti-fingerprinting input floor (F7 / B15 consensus tail): under the
    // uniform-ring tier every regular tx must carry at least
    // `min_input_count` inputs, matching the common two-input Monero
    // default shape network-wide (wallets pad when possible; this makes
    // it consensus law).
    if ring.min_input_count != 0 && (tx.inputs.len() as u32) < ring.min_input_count {
        errors.push(format!(
            "input count {} < consensus minimum {} (uniform-tier anti-fingerprinting floor)",
            tx.inputs.len(),
            ring.min_input_count
        ));
    }
    // B-35: header versions at or above HEADER_VERSION_INPUT_PAD set
    // `input_count_buckets`. Path A / F-A leave the flag false, so a
    // three-input spend stays valid there.
    if ring.input_count_buckets
        && !crate::block::input_count_is_padded_bucket(tx.inputs.len() as u32)
    {
        let n = tx.inputs.len();
        let padded = crate::block::padded_input_count(n as u32);
        errors.push(format!(
            "input count {n} is not a canonical power-of-two bucket (pad to {padded})"
        ));
    }
    // B-318: header version 8 requires the same power-of-two shape for
    // outputs. Header v1 still accepts a 3-output spend.
    if ring.output_count_buckets
        && !crate::block::output_count_is_padded_bucket(tx.outputs.len() as u32)
    {
        let n = tx.outputs.len();
        let padded = crate::block::padded_output_count(n as u32);
        errors.push(format!(
            "output count {n} is not a canonical power-of-two bucket (pad to {padded})"
        ));
    }
    // F5 P20 / B-301: non-empty extra must be a well-formed MFEX
    // envelope. Opaque memos are a public fingerprint.
    if let Err(e) = crate::extra_codec::parse_mfex_extra(&tx.extra) {
        errors.push(format!("tx.extra: {e}"));
    }
    // F5 P20 / B-304: MFEX is upload-only. A well-formed envelope on a
    // no-storage transfer partitions vs honest empty extra.
    let has_storage = tx.outputs.iter().any(|o| o.storage.is_some());
    if !tx.extra.is_empty() && !has_storage {
        errors.push("tx.extra: MFEX is only allowed on storage-anchor txs".to_string());
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

    // Balance equation. Header v1: Σ c_pseudo − Σ amount − fee·H == 0.
    // Header v6 (B-37): the fee term is a commitment, and plaintext fee is 0.
    let mut balance = EdwardsPoint::identity();
    for inp in &tx.inputs {
        balance += inp.c_pseudo;
    }
    for out in &tx.outputs {
        balance -= out.amount;
    }
    let fee_term = hidden_fee_term(tx, ring.hidden_fees, &mut errors);
    balance -= fee_term;
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
        fee_commitment: tx.fee_commitment,
        fee_range_proof: tx.fee_range_proof.clone(),
    };
    let msg = tx_preimage(&stub);

    // CLSAG verifications + key-image validity + within-tx key-image uniqueness.
    //
    // ---- Key-image subgroup validity (consensus-critical) ----
    //
    // The double-spend gate keys on the compressed bytes of each key
    // image. ed25519 has cofactor 8, so a decompressed point may carry a
    // low-order (torsion) component. A key image that is not a member of
    // the prime-order subgroup is malformed: an honest image is
    // `I = x·H_p(P)` where `H_p` clears the cofactor (`mul_by_cofactor`),
    // so every honest image is torsion-free by construction. Admitting a
    // non-subgroup image would let an adversary present multiple distinct
    // encodings of "the same" spend (`I` and `I + T` for a torsion point
    // `T`) and is the classic key-image-malleability footgun Monero closes
    // by rejecting non-prime-order key images. We reject:
    //
    //   * the identity point (a degenerate all-zero image), and
    //   * any image outside the prime-order subgroup (`!is_torsion_free()`).
    //
    // No honest transaction is affected; only malformed/malicious images
    // are rejected. `verify_transaction` is the single ingress point shared
    // by the mempool and `apply_block`, so this guards both.
    let mut seen_ki: Vec<[u8; 32]> = Vec::with_capacity(tx.inputs.len());
    let mut key_images: Vec<EdwardsPoint> = Vec::with_capacity(tx.inputs.len());
    for (i, inp) in tx.inputs.iter().enumerate() {
        let ring_len = inp.ring.p.len();
        if ring_len != inp.ring.c.len() {
            errors.push(format!("input {i}: ring P/C length mismatch"));
        }
        if (ring_len as u32) < ring.min_ring_size {
            errors.push(format!(
                "input {i}: ring size {ring_len} < min {}",
                ring.min_ring_size
            ));
        }
        if ring.tier2_rings {
            if !crate::block::TIER2_RING_SIZES.contains(&(ring_len as u32)) {
                errors.push(format!(
                    "input {i}: ring size {ring_len} is not a Tier 2 size (32 or 64)"
                ));
            }
        } else if ring.uniform_ring_size != 0 && ring_len as u32 != ring.uniform_ring_size {
            errors.push(format!(
                "input {i}: ring size {ring_len} != uniform {}",
                ring.uniform_ring_size
            ));
        }
        if !clsag_verify(&msg, &inp.ring, &inp.c_pseudo, &inp.sig) {
            errors.push(format!("input {i}: CLSAG signature invalid"));
        }
        if inp.sig.key_image == EdwardsPoint::identity() {
            errors.push(format!("input {i}: key image is identity (degenerate)"));
            continue;
        }
        if !inp.sig.key_image.is_torsion_free() {
            errors.push(format!("input {i}: key image not in prime-order subgroup"));
            continue;
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
