//! Confidential transaction — RingCT-style with stealth addressing and
//! permanence binding.
//!
//! Port of `cloonan-group/lib/network/transaction.ts`. The shape and
//! encoding are byte-for-byte identical so the TS reference and this Rust
//! implementation produce equal `tx_id` values for the same input.
//!
//! ## Anatomy
//!
//! ```text
//! Transaction
//! ├── version              codec version (currently 1)
//! ├── R                    tx-level public key (R = r·G; recipients scan with it)
//! ├── fee                  public u64 (the producer claims this)
//! ├── extra                opaque payload (memo, hint), bound by the preimage
//! ├── inputs[i]
//! │   ├── ring             { P[..], C[..] } — anonymity set
//! │   ├── c_pseudo         pseudo-output commitment (matches real value)
//! │   └── sig              CLSAG signature + key image
//! └── outputs[i]
//!     ├── one_time_addr    stealth address P_i
//!     ├── amount           Pedersen commitment C_i = γ_i·G + v_i·H
//!     ├── range_proof      Bulletproof for v_i ∈ [0, 2^TX_RANGE_BITS)
//!     ├── enc_amount       40-byte RingCT-style encrypted (value, blinding)
//!     └── storage          optional StorageCommitment (permanence binding)
//! ```
//!
//! ## Soundness chain
//!
//! 1. Each `range_proof` proves the output amount is non-negative and bounded
//!    — no overflow into the modular wrap-around.
//! 2. The balance equation `Σ c_pseudo − Σ amount − fee·H == 0·G` proves
//!    inputs and outputs sum to the same hidden value plus the public fee.
//! 3. Each CLSAG proves the spender owns one of the ring members AND knows
//!    the blinding-factor difference `r_in − r_pseudo`, linking the pseudo
//!    commitment to a real prior output.
//! 4. The key image `I` is unique per real input: the same `I` appearing in
//!    two transactions is a global double-spend.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use mfn_crypto::bulletproofs::{bp_prove, bp_verify, encode_bulletproof, BulletproofRange};
use mfn_crypto::clsag::{clsag_sign, clsag_verify, encode_clsag, ClsagRing, ClsagSignature};
use mfn_crypto::codec::Writer;
use mfn_crypto::domain::{TX_ID, TX_PREIMAGE};
use mfn_crypto::encrypted_amount::{encrypt_output_amount, ENC_AMOUNT_BYTES};
use mfn_crypto::hash::dhash;
use mfn_crypto::point::{generator_g, generator_h};
use mfn_crypto::scalar::random_scalar;
use mfn_crypto::stealth::{indexed_stealth_address, StealthPubKeys};

use crate::storage::{storage_commitment_hash, StorageCommitment};

/// Current consensus version of the transaction wire format.
pub const TX_VERSION: u32 = 1;

/// Canonical bit width of output range proofs. Amounts are 64-bit unsigned.
pub const TX_RANGE_BITS: u32 = 64;

/* ----------------------------------------------------------------------- *
 *  Wire types                                                              *
 * ----------------------------------------------------------------------- */

/// One signed input on the wire.
///
/// Hides the actual prior output among `ring`, commits to the spent value
/// via `c_pseudo`, and proves ownership + balance binding via `sig`.
#[derive(Clone, Debug)]
pub struct TxInputWire {
    /// Ring of `(P_i, C_i)` pairs forming the anonymity set.
    pub ring: ClsagRing,
    /// Pseudo-output commitment with the same hidden value as the real input.
    pub c_pseudo: EdwardsPoint,
    /// CLSAG signature authorizing the spend.
    pub sig: ClsagSignature,
}

/// One output on the wire.
///
/// `enc_amount` carries the encrypted (value, blinding) so the recipient
/// can open the commitment. For outputs whose target was a pre-built
/// `one_time_addr` (decoys, tests), the sender has no recipient view-key to
/// encrypt under and `enc_amount` is the all-zero 40-byte blob.
#[derive(Clone, Debug)]
pub struct TxOutputWire {
    /// Stealth one-time address.
    pub one_time_addr: EdwardsPoint,
    /// Pedersen commitment to the hidden output amount.
    pub amount: EdwardsPoint,
    /// Bulletproof range proof for the amount. `proof.v == amount`.
    pub range_proof: BulletproofRange,
    /// RingCT-style encrypted (value, blinding) blob, always
    /// [`ENC_AMOUNT_BYTES`] long.
    pub enc_amount: [u8; ENC_AMOUNT_BYTES],
    /// Optional permanence binding — `Some` if this output anchors data.
    pub storage: Option<StorageCommitment>,
}

/// A full signed transaction on the wire.
#[derive(Clone, Debug)]
pub struct TransactionWire {
    /// Codec version.
    pub version: u32,
    /// Tx-level public key `R = r·G`.
    pub r_pub: EdwardsPoint,
    /// Inputs being spent.
    pub inputs: Vec<TxInputWire>,
    /// Outputs being created.
    pub outputs: Vec<TxOutputWire>,
    /// Public fee — claimed by the block producer.
    pub fee: u64,
    /// Opaque payload, committed-to by the preimage (immutable post-signing).
    pub extra: Vec<u8>,
}

/* ----------------------------------------------------------------------- *
 *  Encoding                                                                *
 * ----------------------------------------------------------------------- */

/// Consensus-critical preimage. This is the message CLSAG signs over and
/// the input to [`tx_id`].
///
/// **Byte-for-byte compatible with `txPreimage` in `transaction.ts`.**
pub fn tx_preimage(tx: &TransactionWire) -> [u8; 32] {
    let mut w = Writer::new();
    w.varint(u64::from(tx.version));
    w.point(&tx.r_pub);
    w.u64(tx.fee);
    w.blob(&tx.extra);

    w.varint(tx.inputs.len() as u64);
    for inp in &tx.inputs {
        w.points(&inp.ring.p);
        w.points(&inp.ring.c);
        w.point(&inp.c_pseudo);
    }

    w.varint(tx.outputs.len() as u64);
    for out in &tx.outputs {
        w.point(&out.one_time_addr);
        w.point(&out.amount);
        w.blob(&encode_bulletproof(&out.range_proof));
        w.push(&out.enc_amount);
        match &out.storage {
            Some(c) => {
                w.u8(1);
                w.push(&storage_commitment_hash(c));
            }
            None => {
                w.u8(0);
            }
        }
    }

    dhash(TX_PREIMAGE, &[w.bytes()])
}

/// Full transaction id — hash of preimage concatenated with the wire-format
/// signatures. Two txs with the same preimage but different sigs hash to
/// different ids (malleability defense).
///
/// **Byte-for-byte compatible with `txId` in `transaction.ts`.**
pub fn tx_id(tx: &TransactionWire) -> [u8; 32] {
    let preimage = tx_preimage(tx);
    let mut w = Writer::new();
    w.push(&preimage);
    w.varint(tx.inputs.len() as u64);
    for inp in &tx.inputs {
        w.blob(&encode_clsag(&inp.sig));
    }
    dhash(TX_ID, &[w.bytes()])
}

/* ----------------------------------------------------------------------- *
 *  Builder                                                                 *
 * ----------------------------------------------------------------------- */

/// Spec for one input to be signed. The caller must know the spend private
/// key for `ring[signer_idx]` and the blinding factor of its commitment.
#[derive(Clone, Debug)]
pub struct InputSpec {
    /// Ring of `(P_i, C_i)`. MUST include the real input at `signer_idx`.
    pub ring: ClsagRing,
    /// Index of the real input within `ring`.
    pub signer_idx: usize,
    /// Private spend key `x` with `P_signer = x·G`.
    pub spend_priv: Scalar,
    /// Hidden value `v` of the real input.
    pub value: u64,
    /// Blinding factor of the real input's commitment `C_signer`.
    pub blinding: Scalar,
}

/// A stealth-address recipient (view + spend public keys).
#[derive(Clone, Copy, Debug)]
pub struct Recipient {
    /// Recipient's public view key.
    pub view_pub: EdwardsPoint,
    /// Recipient's public spend key.
    pub spend_pub: EdwardsPoint,
}

impl From<Recipient> for StealthPubKeys {
    fn from(r: Recipient) -> Self {
        StealthPubKeys {
            view_pub: r.view_pub,
            spend_pub: r.spend_pub,
        }
    }
}

/// Spec for one output to be created.
///
/// Use `OutputSpec::ToRecipient` for real payments — the builder derives the
/// on-chain stealth address from the tx-level pubkey `R` so the recipient
/// can scan for it later. Use `OutputSpec::Raw` only for decoys / tests
/// where you supply a pre-built one-time address.
#[derive(Clone, Debug)]
pub enum OutputSpec {
    /// Real payment to a recipient by stealth pubkeys. The builder derives
    /// `one_time_addr` from `R` + `recipient` + output index.
    ToRecipient {
        /// Recipient's view + spend public keys.
        recipient: Recipient,
        /// Amount to pay.
        value: u64,
        /// Optional storage commitment to anchor data permanently.
        storage: Option<StorageCommitment>,
    },
    /// Output to a pre-computed stealth address. The recipient (if any)
    /// CANNOT scan for this since the tx-level `R` is unrelated to how the
    /// address was derived.
    Raw {
        /// Pre-built stealth one-time address.
        one_time_addr: EdwardsPoint,
        /// Amount.
        value: u64,
        /// Optional storage commitment.
        storage: Option<StorageCommitment>,
    },
}

impl OutputSpec {
    fn value(&self) -> u64 {
        match self {
            Self::ToRecipient { value, .. } | Self::Raw { value, .. } => *value,
        }
    }
    fn storage(&self) -> Option<&StorageCommitment> {
        match self {
            Self::ToRecipient { storage, .. } | Self::Raw { storage, .. } => storage.as_ref(),
        }
    }
}

/// Result of [`sign_transaction`].
///
/// `output_blindings` is the secret material the sender hands to each
/// recipient out-of-band so they can later open their amount commitments;
/// it MUST NOT be published on-chain.
#[derive(Clone, Debug)]
pub struct SignedTransaction {
    /// The transaction wire object.
    pub tx: TransactionWire,
    /// Per-output blinding factors (private to the recipient).
    pub output_blindings: Vec<Scalar>,
}

/// Errors raised while building / signing a transaction.
#[derive(Debug, thiserror::Error)]
pub enum TxBuildError {
    /// No inputs supplied.
    #[error("at least one input is required")]
    NoInputs,
    /// No outputs supplied.
    #[error("at least one output is required")]
    NoOutputs,
    /// `Σ inputs.value ≠ Σ outputs.value + fee`.
    #[error("amounts do not balance: Σin={in_sum}, Σout={out_sum}, fee={fee}")]
    UnbalancedAmounts {
        /// Sum of input values.
        in_sum: u128,
        /// Sum of output values.
        out_sum: u128,
        /// Public fee.
        fee: u64,
    },
    /// `Σ inputs.value` overflowed `u128`.
    #[error("input sum overflowed u128")]
    InputSumOverflow,
    /// `signer_idx` is out of range for the input ring.
    #[error("input {idx}: signer_idx {signer_idx} is out of range for ring of size {ring_size}")]
    SignerOutOfRange {
        /// Input index in the tx.
        idx: usize,
        /// Out-of-range signer index.
        signer_idx: usize,
        /// Actual ring size.
        ring_size: usize,
    },
    /// Underlying cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] mfn_crypto::CryptoError),
}

/// Build, sign, and seal a confidential transaction.
///
/// Performs the full RingCT-style ceremony: pseudo-blindings → output
/// blindings → range proofs → CLSAGs. Returns the wire-ready transaction
/// plus the per-output blinding factors (private to the recipient).
pub fn sign_transaction(
    inputs: Vec<InputSpec>,
    outputs: Vec<OutputSpec>,
    fee: u64,
    extra: Vec<u8>,
) -> Result<SignedTransaction, TxBuildError> {
    if inputs.is_empty() {
        return Err(TxBuildError::NoInputs);
    }
    if outputs.is_empty() {
        return Err(TxBuildError::NoOutputs);
    }

    // Balance check (clear-text on the sender side).
    let mut in_sum: u128 = 0;
    for i in &inputs {
        in_sum = in_sum
            .checked_add(u128::from(i.value))
            .ok_or(TxBuildError::InputSumOverflow)?;
    }
    let mut out_sum: u128 = 0;
    for o in &outputs {
        out_sum = out_sum
            .checked_add(u128::from(o.value()))
            .ok_or(TxBuildError::InputSumOverflow)?;
    }
    if in_sum != out_sum + u128::from(fee) {
        return Err(TxBuildError::UnbalancedAmounts {
            in_sum,
            out_sum,
            fee,
        });
    }

    // signer_idx bounds.
    for (idx, i) in inputs.iter().enumerate() {
        if i.signer_idx >= i.ring.p.len() {
            return Err(TxBuildError::SignerOutOfRange {
                idx,
                signer_idx: i.signer_idx,
                ring_size: i.ring.p.len(),
            });
        }
    }

    // Tx-level keypair (R = r·G).
    let tx_priv = random_scalar();
    let r_pub = generator_g() * tx_priv;

    // Resolve each output's stealth address.
    let mut one_time_addrs: Vec<EdwardsPoint> = Vec::with_capacity(outputs.len());
    for (i, o) in outputs.iter().enumerate() {
        let addr = match o {
            OutputSpec::ToRecipient { recipient, .. } => {
                let pk: StealthPubKeys = (*recipient).into();
                indexed_stealth_address(tx_priv, &pk, i as u32)
            }
            OutputSpec::Raw { one_time_addr, .. } => *one_time_addr,
        };
        one_time_addrs.push(addr);
    }

    // Output blindings + commitments + range proofs.
    let mut output_blindings: Vec<Scalar> = Vec::with_capacity(outputs.len());
    let mut output_commits: Vec<EdwardsPoint> = Vec::with_capacity(outputs.len());
    let mut range_proofs: Vec<BulletproofRange> = Vec::with_capacity(outputs.len());
    let mut out_blinding_sum = Scalar::ZERO;
    for o in &outputs {
        let r_out = random_scalar();
        output_blindings.push(r_out);
        out_blinding_sum += r_out;

        let bp = bp_prove(o.value(), &r_out, TX_RANGE_BITS)?;
        output_commits.push(bp.v);
        range_proofs.push(bp.proof);
    }

    // Pseudo-output blindings: free for inputs[0..n-2], constrained for the
    // last one so Σ pseudo_in = Σ out_blinding (the balance equation closes).
    let n = inputs.len();
    let mut pseudo_blindings: Vec<Scalar> = Vec::with_capacity(n);
    let mut acc = Scalar::ZERO;
    for _ in 0..n - 1 {
        let b = random_scalar();
        pseudo_blindings.push(b);
        acc += b;
    }
    pseudo_blindings.push(out_blinding_sum - acc);

    // Pseudo-output commitments commit to the input values v_i (so the
    // verifier can derive z = r_in − r_pseudo for the CLSAG).
    let mut pseudo_commits: Vec<EdwardsPoint> = Vec::with_capacity(n);
    for (i, inp) in inputs.iter().enumerate() {
        let c = (generator_g() * pseudo_blindings[i]) + (generator_h() * Scalar::from(inp.value));
        pseudo_commits.push(c);
    }

    // Encrypt (value, blinding) for each ToRecipient output.
    let mut enc_amounts: Vec<[u8; ENC_AMOUNT_BYTES]> = Vec::with_capacity(outputs.len());
    for (i, o) in outputs.iter().enumerate() {
        match o {
            OutputSpec::ToRecipient {
                recipient, value, ..
            } => {
                let enc = encrypt_output_amount(
                    tx_priv,
                    &recipient.view_pub,
                    i as u32,
                    *value,
                    &output_blindings[i],
                );
                enc_amounts.push(enc);
            }
            OutputSpec::Raw { .. } => {
                enc_amounts.push([0u8; ENC_AMOUNT_BYTES]);
            }
        }
    }

    // Assemble outputs wire.
    let outputs_wire: Vec<TxOutputWire> = outputs
        .iter()
        .enumerate()
        .map(|(i, o)| TxOutputWire {
            one_time_addr: one_time_addrs[i],
            amount: output_commits[i],
            range_proof: range_proofs[i].clone(),
            enc_amount: enc_amounts[i],
            storage: o.storage().cloned(),
        })
        .collect();

    // Build a stub tx so we can derive the signing preimage. Signatures are
    // NOT part of the preimage, so the placeholder values are fine.
    let stub_inputs: Vec<TxInputWire> = inputs
        .iter()
        .enumerate()
        .map(|(i, inp)| TxInputWire {
            ring: inp.ring.clone(),
            c_pseudo: pseudo_commits[i],
            sig: placeholder_clsag(),
        })
        .collect();
    let stub = TransactionWire {
        version: TX_VERSION,
        r_pub,
        inputs: stub_inputs,
        outputs: outputs_wire.clone(),
        fee,
        extra: extra.clone(),
    };
    let msg = tx_preimage(&stub);

    // Sign each input with CLSAG.
    let mut signed_inputs: Vec<TxInputWire> = Vec::with_capacity(n);
    for (i, inp) in inputs.iter().enumerate() {
        let z = inp.blinding - pseudo_blindings[i];
        let sig = clsag_sign(
            &msg,
            &inp.ring,
            &pseudo_commits[i],
            inp.signer_idx,
            &inp.spend_priv,
            &z,
        )?;
        signed_inputs.push(TxInputWire {
            ring: inp.ring.clone(),
            c_pseudo: pseudo_commits[i],
            sig,
        });
    }

    Ok(SignedTransaction {
        tx: TransactionWire {
            version: TX_VERSION,
            r_pub,
            inputs: signed_inputs,
            outputs: outputs_wire,
            fee,
            extra,
        },
        output_blindings,
    })
}

fn placeholder_clsag() -> ClsagSignature {
    ClsagSignature {
        c0: Scalar::ZERO,
        s: Vec::new(),
        key_image: EdwardsPoint::identity(),
        d: EdwardsPoint::identity(),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
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

        let res = verify_transaction(&signed.tx);
        assert!(res.ok, "errors: {:?}", res.errors);
        assert_eq!(res.key_images.len(), 1);
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
        let res = verify_transaction(&signed.tx);
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
        let res = verify_transaction(&signed.tx);
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

        let res = verify_transaction(&tx);
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

        let res = verify_transaction(&tx);
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

        let res = verify_transaction(&tx);
        assert!(!res.ok);
        assert!(res
            .errors
            .iter()
            .any(|e| e.contains("key image repeated") || e.contains("balance")));
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
        assert!(verify_transaction(&signed.tx).ok);

        // Tamper with storage commit → tx_id changes.
        let mut tx = signed.tx;
        let mut bad = commit;
        bad.replication = 4;
        tx.outputs[0].storage = Some(bad);
        // The tx is now inconsistent with its CLSAG signatures.
        assert!(!verify_transaction(&tx).ok);
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
        let res = verify_transaction(&signed.tx);
        assert!(res.ok, "errors: {:?}", res.errors);
        // Raw outputs get zero enc_amount blob (no recipient view-key).
        assert_eq!(signed.tx.outputs[0].enc_amount, [0u8; ENC_AMOUNT_BYTES]);
    }
}
