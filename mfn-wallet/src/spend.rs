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
/// production use [`crate::production_tx_rng`]; for deterministic
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
    if plan.ring_size < crate::WALLET_MIN_RING_SIZE {
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

    let mut output_specs: Vec<OutputSpec> = plan
        .recipients
        .iter()
        .map(|r| OutputSpec::ToRecipient {
            recipient: r.recipient,
            value: r.value,
            storage: None,
        })
        .collect();

    // Privacy floor (universal backstop for every reference caller —
    // wallet, WASM, CLI): never sign a single-output transfer. A lone
    // output reveals a no-change sweep or exact-amount payment and
    // fingerprints the spend against ordinary "payment + change"
    // transfers. Pad to `WALLET_MIN_TX_OUTPUTS` with zero-value outputs
    // addressed to a recipient already on this tx (no new counterparty is
    // exposed). Output amounts are Pedersen-committed, so the padding is
    // indistinguishable on-chain, and value 0 leaves the balance equation
    // (`Σ inputs == Σ outputs + fee`) untouched. `recipients` is
    // non-empty (checked above), so indexing `[0]` is safe.
    while output_specs.len() < crate::WALLET_MIN_TX_OUTPUTS {
        output_specs.push(OutputSpec::ToRecipient {
            recipient: plan.recipients[0].recipient,
            value: 0,
            storage: None,
        });
    }

    // Canonical output ordering (F5:P9 / PRIVACY_HARDENING B3): the
    // construction order — recipients first, change/pad appended last —
    // is itself a fingerprint ("the last output is the change") that
    // partitions every reference-wallet tx. Fisher–Yates shuffle with the
    // plan RNG so output position carries no information. One-time
    // addresses are derived from the *final* index inside
    // `sign_transaction`, so shuffling specs here is invisible to
    // recipients and to the balance equation.
    for i in (1..output_specs.len()).rev() {
        let r = (plan.rng)();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let j = ((r * (i + 1) as f64) as usize).min(i);
        output_specs.swap(i, j);
    }

    Ok(sign_transaction(
        input_specs,
        output_specs,
        plan.fee,
        plan.extra.to_vec(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{wallet_from_seed, OwnedOutput};
    use curve25519_dalek::scalar::Scalar;
    use mfn_consensus::{verify_transaction, RingPolicy};
    use mfn_crypto::point::{generator_g, generator_h};
    use mfn_crypto::scalar::random_scalar;

    fn owned(value: u64) -> OwnedOutput {
        let one_time_spend = random_scalar();
        let blinding = random_scalar();
        let one_time_addr = generator_g() * one_time_spend;
        let commit = (generator_g() * blinding) + (generator_h() * Scalar::from(value));
        let key_image =
            crate::owned::key_image_for_owned(&one_time_addr, one_time_spend).expect("key image");
        OwnedOutput {
            one_time_addr,
            commit,
            value,
            blinding,
            one_time_spend,
            key_image,
            tx_id: [0u8; 32],
            output_idx: 0,
            height: 1,
        }
    }

    fn pool(n: usize) -> Vec<DecoyCandidate<RingMember>> {
        (0..n)
            .map(|i| {
                let p = generator_g() * random_scalar();
                let c = (generator_g() * random_scalar())
                    + (generator_h() * Scalar::from((i as u64) + 1));
                DecoyCandidate {
                    data: (p, c),
                    height: 1,
                }
            })
            .collect()
    }

    /// A single-recipient, exact-amount (no-change) transfer must be
    /// padded up to the two-output privacy floor and still verify under
    /// the production ring policy. This is the anti-fingerprinting
    /// guarantee: no reference caller ever broadcasts a one-output tx.
    #[test]
    fn single_recipient_transfer_is_padded_to_two_outputs() {
        let input_a = owned(600_000);
        let input_b = owned(500_000);
        let refs = [&input_a, &input_b];
        let decoys = pool(20);
        let keys = wallet_from_seed(&[7u8; 32]);
        let recipient = Recipient {
            view_pub: keys.view_pub(),
            spend_pub: keys.spend_pub(),
        };
        let fee = 1_000u64;
        let recipients = [TransferRecipient {
            recipient,
            value: 1_100_000 - fee,
        }];
        let mut r = mfn_crypto::seeded_rng(0x0abc_def0);
        let plan = TransferPlan {
            inputs: &refs,
            recipients: &recipients,
            fee,
            extra: &[],
            ring_size: crate::WALLET_MIN_RING_SIZE,
            decoy_pool: &decoys,
            current_height: 1,
            rng: &mut r,
        };
        let signed = build_transfer(plan).expect("build transfer");
        assert_eq!(
            signed.tx.outputs.len(),
            crate::WALLET_MIN_TX_OUTPUTS,
            "no-change transfer must be padded to the two-output floor"
        );
        let v = verify_transaction(&signed.tx, &RingPolicy::PRODUCTION);
        assert!(v.ok, "padded transfer must verify: {:?}", v.errors);
    }

    /// A transfer that already has two outputs (payment + change) is left
    /// untouched — the pad only fills up to the floor, never beyond.
    #[test]
    fn transfer_with_change_is_not_over_padded() {
        let input_a = owned(600_000);
        let input_b = owned(500_000);
        let refs = [&input_a, &input_b];
        let decoys = pool(20);
        let keys = wallet_from_seed(&[9u8; 32]);
        let recipient = Recipient {
            view_pub: keys.view_pub(),
            spend_pub: keys.spend_pub(),
        };
        let fee = 1_000u64;
        let recipients = [
            TransferRecipient {
                recipient,
                value: 600_000,
            },
            TransferRecipient {
                recipient,
                value: 1_100_000 - 600_000 - fee,
            },
        ];
        let mut r = mfn_crypto::seeded_rng(0x1234_5678);
        let plan = TransferPlan {
            inputs: &refs,
            recipients: &recipients,
            fee,
            extra: &[],
            ring_size: crate::WALLET_MIN_RING_SIZE,
            decoy_pool: &decoys,
            current_height: 1,
            rng: &mut r,
        };
        let signed = build_transfer(plan).expect("build transfer");
        assert_eq!(signed.tx.outputs.len(), 2, "two outputs must be preserved");
        let v = verify_transaction(&signed.tx, &RingPolicy::PRODUCTION);
        assert!(v.ok, "transfer must verify: {:?}", v.errors);
    }

    /// Canonical output ordering (F5:P9 / B3): the change output must not
    /// sit at a fixed position. Across seeds, the second recipient (the
    /// change-like output) must land at index 0 sometimes and index 1
    /// sometimes — and every shuffled tx must still verify and scan.
    #[test]
    fn output_position_carries_no_change_signal() {
        use std::collections::HashSet;

        let payee_keys = wallet_from_seed(&[21u8; 32]);
        let change_keys = wallet_from_seed(&[22u8; 32]);
        let fee = 1_000u64;
        let mut seen_positions = HashSet::new();

        for seed in 0..16u32 {
            let input_a = owned(600_000);
            let input_b = owned(500_000);
            let refs = [&input_a, &input_b];
            let decoys = pool(20);
            let recipients = [
                TransferRecipient {
                    recipient: Recipient {
                        view_pub: payee_keys.view_pub(),
                        spend_pub: payee_keys.spend_pub(),
                    },
                    value: 600_000,
                },
                TransferRecipient {
                    recipient: Recipient {
                        view_pub: change_keys.view_pub(),
                        spend_pub: change_keys.spend_pub(),
                    },
                    value: 1_100_000 - 600_000 - fee,
                },
            ];
            let mut r = mfn_crypto::seeded_rng(0x5EED_0000 + seed);
            let plan = TransferPlan {
                inputs: &refs,
                recipients: &recipients,
                fee,
                extra: &[],
                ring_size: crate::WALLET_MIN_RING_SIZE,
                decoy_pool: &decoys,
                current_height: 1,
                rng: &mut r,
            };
            let signed = build_transfer(plan).expect("build transfer");
            let v = verify_transaction(&signed.tx, &RingPolicy::PRODUCTION);
            assert!(v.ok, "shuffled transfer must verify: {:?}", v.errors);

            let scan = crate::scan::scan_transaction(
                &signed.tx,
                1,
                &change_keys,
                &std::collections::HashSet::new(),
            );
            assert_eq!(scan.recovered.len(), 1, "change wallet must own one output");
            assert_eq!(scan.recovered[0].value, 1_100_000 - 600_000 - fee);
            seen_positions.insert(scan.recovered[0].output_idx);
        }

        assert!(
            seen_positions.len() > 1,
            "change output position must vary across transactions; \
             only saw {seen_positions:?}"
        );
    }
}
