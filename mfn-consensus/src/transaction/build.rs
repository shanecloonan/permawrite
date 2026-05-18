//! Transaction builder and signing.

#![allow(unused_imports)]

use super::id::tx_preimage;
use super::internal::*;
use super::wire::{TransactionWire, TxInputWire, TxOutputWire};
use super::{TX_RANGE_BITS, TX_VERSION};

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

pub(crate) fn placeholder_clsag() -> ClsagSignature {
    ClsagSignature {
        c0: Scalar::ZERO,
        s: Vec::new(),
        key_image: EdwardsPoint::identity(),
        d: EdwardsPoint::identity(),
    }
}
