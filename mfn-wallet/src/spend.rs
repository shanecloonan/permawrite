//! Transfer construction.
//!
//! Build a signed [`mfn_consensus::TransactionWire`] that spends one or
//! more owned outputs and pays an arbitrary set of stealth recipients.
//!
//! The hard parts (CLSAG signing, range proofs, encrypted-amount blobs,
//! tx-level r-pub generation, pseudo-blinding balance) are all in
//! [`mfn_consensus::sign_transaction`]. This module is the *adapter*:
//! it knows how to translate the wallet's view of the world
//! (`OwnedOutput`s, `TransferRecipient`s, a decoy pool) into the
//! `InputSpec` / `OutputSpec` vocabulary the consensus layer expects.
//!
//! ## Ring construction
//!
//! For each real input we:
//!
//! 1. Take `ring_size - 1` decoys from the caller-supplied pool via
//!    [`mfn_crypto::select_gamma_decoys`].
//! 2. Choose a uniformly random slot `signer_idx ∈ [0, ring_size)` for
//!    the real input.
//! 3. Assemble the `(P_i, C_i)` columns by walking the decoys and
//!    inserting the real input at `signer_idx`.
//!
//! The same decoy pool is reused across all inputs in a single
//! transfer — `select_gamma_decoys` already deduplicates within one
//! call, but reusing it across inputs is fine because each input gets
//! its own *independent* sample.

use mfn_consensus::{sign_transaction, InputSpec, OutputSpec, Recipient, SignedTransaction};
use mfn_crypto::clsag::ClsagRing;
use mfn_crypto::{select_gamma_decoys, DecoyCandidate, DEFAULT_GAMMA_PARAMS};

use crate::decoy::RingMember;
use crate::error::WalletError;
use crate::owned::OwnedOutput;

/// A single transfer leg.
///
/// Mirrors [`mfn_consensus::Recipient`] but adds the `value` to send so
/// the wallet can synthesise the full `OutputSpec` itself.
#[derive(Clone, Copy, Debug)]
pub struct TransferRecipient {
    /// Recipient's view + spend public keys.
    pub recipient: Recipient,
    /// Amount to pay (atomic units).
    pub value: u64,
}

/// Inputs for [`build_transfer`].
///
/// Each field is documented with the role it plays in the RingCT
/// ceremony. The wallet's higher-level `Wallet::build_transfer` wires
/// these together for the common path.
///
/// The RNG type is `FnMut() -> f64`, matching the
/// [`mfn_crypto::Random`] trait used by `select_gamma_decoys`. For
/// production use [`mfn_crypto::crypto_random`]; for deterministic
/// tests use [`mfn_crypto::seeded_rng`].
pub struct TransferPlan<'a, R: FnMut() -> f64> {
    /// Outputs being spent. The wallet picks them via coin-selection
    /// upstream; this layer simply consumes the choice.
    pub inputs: &'a [&'a OwnedOutput],
    /// Recipients of the transfer (`Σ value` + `fee` must equal `Σ
    /// inputs.value`).
    pub recipients: &'a [TransferRecipient],
    /// Public fee claimed by the producer.
    pub fee: u64,
    /// Opaque memo committed-to by the tx preimage. Pass `&[]` for
    /// none.
    pub extra: &'a [u8],
    /// Anonymity-set size **including** the real input. The wallet
    /// asserts this is `>= 2`.
    pub ring_size: usize,
    /// Decoy candidate pool. Must be sorted by height ascending — use
    /// [`crate::DecoyPoolBuilder`] to construct.
    pub decoy_pool: &'a [DecoyCandidate<RingMember>],
    /// Chain height the wallet is spending from (drives the gamma age
    /// distribution).
    pub current_height: u64,
    /// `FnMut() -> f64` returning uniform `[0, 1)`. Used for both
    /// decoy sampling and `signer_idx` selection.
    pub rng: &'a mut R,
}

/// Build, sign, and seal a transfer transaction.
///
/// The returned [`SignedTransaction`] carries the wire-ready
/// [`TransactionWire`] plus the per-output blinding factors that the
/// sender hands to recipients out-of-band (in our model the recipients
/// recover them from the on-chain `enc_amount` blob, so the
/// `output_blindings` Vec is informational here).
///
/// # Errors
///
/// - [`WalletError::NoRecipients`] — `recipients` is empty.
/// - [`WalletError::InsufficientFunds`] — `Σ recipients.value + fee >
///   Σ inputs.value`.
/// - [`WalletError::DecoyPoolTooSmall`] — `ring_size > decoy_pool.len()
///   + 1`.
/// - [`WalletError::Crypto`] / [`WalletError::TxBuild`] — propagated
///   from `mfn-crypto` / `mfn-consensus`.
pub fn build_transfer<R>(plan: TransferPlan<'_, R>) -> Result<SignedTransaction, WalletError>
where
    R: FnMut() -> f64,
{
    if plan.recipients.is_empty() {
        return Err(WalletError::NoRecipients);
    }
    if plan.ring_size < 2 {
        return Err(WalletError::DecoyPoolTooSmall {
            ring_size: plan.ring_size,
            pool_size: plan.decoy_pool.len(),
        });
    }
    if plan.decoy_pool.len() + 1 < plan.ring_size {
        return Err(WalletError::DecoyPoolTooSmall {
            ring_size: plan.ring_size,
            pool_size: plan.decoy_pool.len(),
        });
    }

    let input_total: u64 = plan
        .inputs
        .iter()
        .map(|o| o.value)
        .fold(0u64, u64::saturating_add);
    let output_total: u64 = plan
        .recipients
        .iter()
        .map(|r| r.value)
        .fold(0u64, u64::saturating_add);
    let needed = output_total.saturating_add(plan.fee);
    if input_total < needed {
        return Err(WalletError::InsufficientFunds {
            requested: needed,
            available: input_total,
        });
    }
    if input_total != needed {
        return Err(WalletError::InsufficientFunds {
            requested: needed,
            available: input_total,
        });
    }

    let mut input_specs: Vec<InputSpec> = Vec::with_capacity(plan.inputs.len());
    let decoys_per_input = plan.ring_size - 1;

    for real in plan.inputs.iter().copied() {
        let decoys = select_gamma_decoys(
            plan.decoy_pool,
            decoys_per_input,
            plan.current_height,
            plan.rng,
            &DEFAULT_GAMMA_PARAMS,
        )?;

        // `select_gamma_decoys` returns up to `count` unique members,
        // falling back to uniform on starvation. If it returned fewer
        // than we asked for, the pool is genuinely too small — surface
        // a typed error instead of silently degrading anonymity.
        if decoys.len() < decoys_per_input {
            return Err(WalletError::DecoyPoolTooSmall {
                ring_size: plan.ring_size,
                pool_size: plan.decoy_pool.len(),
            });
        }

        // Choose the real input's slot uniformly at random within
        // [0, ring_size). Map `[0, 1)` → `[0, ring_size)` by floor.
        let r = (plan.rng)();
        let signer_idx = {
            let raw = (r * plan.ring_size as f64) as usize;
            raw.min(plan.ring_size - 1)
        };

        let mut p_col: Vec<curve25519_dalek::edwards::EdwardsPoint> =
            Vec::with_capacity(plan.ring_size);
        let mut c_col: Vec<curve25519_dalek::edwards::EdwardsPoint> =
            Vec::with_capacity(plan.ring_size);
        let mut decoy_iter = decoys.into_iter();
        for slot in 0..plan.ring_size {
            if slot == signer_idx {
                p_col.push(real.one_time_addr);
                c_col.push(real.commit);
            } else {
                let next = decoy_iter
                    .next()
                    .expect("decoy_iter must have ring_size-1 items");
                p_col.push(next.data.0);
                c_col.push(next.data.1);
            }
        }
        input_specs.push(InputSpec {
            ring: ClsagRing { p: p_col, c: c_col },
            signer_idx,
            spend_priv: real.one_time_spend,
            value: real.value,
            blinding: real.blinding,
        });
    }

    let output_specs: Vec<OutputSpec> = plan
        .recipients
        .iter()
        .map(|r| OutputSpec::ToRecipient {
            recipient: r.recipient,
            value: r.value,
            storage: None,
        })
        .collect();

    Ok(sign_transaction(
        input_specs,
        output_specs,
        plan.fee,
        plan.extra.to_vec(),
    )?)
}
