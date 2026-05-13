//! Owned-output bookkeeping.
//!
//! Every output that the scanner attributes to this wallet is reduced to
//! an [`OwnedOutput`] — a compact record carrying just the data needed
//! to (a) verify the Pedersen commitment opens to the claimed value, (b)
//! later spend the output (one-time spend scalar + value + blinding),
//! and (c) deduplicate spends across blocks via the key image.
//!
//! ## Pedersen-open verification
//!
//! `decrypt_output_amount` in `mfn-crypto` is XOR-pad-shaped — there is
//! no authenticator on the encrypted blob. Decoding succeeds on every
//! 40-byte input and silently yields garbage when the receiver's view
//! key is wrong. The only reliable way to confirm "this output is mine"
//! is to verify that the on-chain Pedersen commitment opens to the
//! decrypted `(value, blinding)`:
//!
//! ```text
//! amount_commit ?= value · H + blinding · G
//! ```
//!
//! [`verify_pedersen_open`] is the canonical primitive; the wallet's
//! scan path calls it after every successful stealth-detection so an
//! adversary cannot trick us into "owning" outputs that aren't ours by
//! grinding `r_pub` / `enc_amount` blobs.
//!
//! ## Key-image precomputation
//!
//! The Monero key image `I = x · H_p(P)` (where `x` is the one-time
//! spend scalar and `P = x · G` is the one-time address) is a
//! deterministic per-UTXO fingerprint. We compute it eagerly when the
//! scanner records the output so that:
//!
//! 1. Each *spend* by this wallet stamps the key image into a local
//!    set, preventing accidental double-spends inside an unmined batch.
//! 2. Each *scanned tx* whose inputs contain one of our key images
//!    marks the corresponding output spent — handles the cross-device
//!    case where another instance of the same wallet spent first.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use mfn_crypto::hash::hash_to_point;
use mfn_crypto::point::{generator_g, generator_h};

use crate::error::WalletError;

/// A single unspent output that belongs to this wallet.
///
/// Every field is needed downstream:
///
/// - `one_time_addr` + `commit` are the *public* on-chain identifiers;
///   `one_time_addr.compress()` keys the [`mfn_consensus::ChainState`]
///   UTXO map.
/// - `value` + `blinding` are the *secret* opening of the Pedersen
///   commitment, required to construct a CLSAG input pseudo-commitment.
/// - `one_time_spend` is the per-output spend scalar; `P = one_time_spend
///   · G`. Required to sign the CLSAG for this input.
/// - `key_image` is the deterministic spend fingerprint — eagerly
///   computed so cross-block / cross-device dedup is O(1).
/// - `tx_id`, `output_idx`, `height` are bookkeeping for callers that
///   want to display history or build decoy pools that exclude the
///   wallet's own outputs.
#[derive(Clone, Debug)]
pub struct OwnedOutput {
    /// One-time stealth address `P` (the on-chain `out.one_time_addr`).
    pub one_time_addr: EdwardsPoint,
    /// Pedersen commitment `C = value · H + blinding · G`.
    pub commit: EdwardsPoint,
    /// Decrypted hidden value `v`.
    pub value: u64,
    /// Decrypted blinding factor `γ` (so `C` opens).
    pub blinding: Scalar,
    /// One-time spend private scalar `x` with `P = x · G`. Required for
    /// CLSAG signing.
    pub one_time_spend: Scalar,
    /// Cached key image `I = x · H_p(P)`. Deduplicates spends.
    pub key_image: EdwardsPoint,
    /// Transaction id of the tx that created this output.
    pub tx_id: [u8; 32],
    /// Index of this output within `tx.outputs`.
    pub output_idx: u32,
    /// Block height at which the tx was applied.
    pub height: u32,
}

impl OwnedOutput {
    /// 32-byte key used by [`mfn_consensus::ChainState::utxo`] for
    /// lookups. Identical to `one_time_addr.compress().to_bytes()`.
    #[inline]
    pub fn utxo_key(&self) -> [u8; 32] {
        self.one_time_addr.compress().to_bytes()
    }
}

/// Lightweight reference to an [`OwnedOutput`] — used by spend-side
/// helpers that need to name an output without owning its scalar
/// material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OwnedRef {
    /// `one_time_addr.compress().to_bytes()`.
    pub utxo_key: [u8; 32],
}

/// Check that `amount_commit` opens to `(value, blinding)`.
///
/// This is the binding step that turns the *unauthenticated* XOR-pad
/// `decrypt_output_amount` into a sound "this output is mine"
/// predicate. Returns `true` iff the on-chain commitment equals the
/// recomputed `value · H + blinding · G`.
#[inline]
pub fn verify_pedersen_open(amount_commit: &EdwardsPoint, value: u64, blinding: &Scalar) -> bool {
    let recomputed = (generator_g() * blinding) + (generator_h() * Scalar::from(value));
    &recomputed == amount_commit
}

/// Compute the Monero-style key image `I = x · H_p(P)` for an owned
/// output's one-time spend scalar `x` and one-time address `P`.
///
/// Returns [`WalletError::Crypto`] if `hash_to_point` cannot land on a
/// valid Edwards point for `P.compress()` within the bounded retry
/// window (cryptographically improbable for a real stealth address).
pub fn key_image_for_owned(
    one_time_addr: &EdwardsPoint,
    one_time_spend: Scalar,
) -> Result<EdwardsPoint, WalletError> {
    let hp = hash_to_point(&one_time_addr.compress().to_bytes())?;
    Ok(hp * one_time_spend)
}

/// Sum the `value`s of an iterator of owned outputs.
///
/// Saturating to `u64::MAX` is a defensive choice — overflowing here
/// would require the wallet to hold approximately the entire money
/// supply, which never happens, but a saturating sum makes the helper
/// total even under malformed test inputs.
pub fn owned_balance<'a, I>(outputs: I) -> u64
where
    I: IntoIterator<Item = &'a OwnedOutput>,
{
    outputs
        .into_iter()
        .map(|o| o.value)
        .fold(0u64, u64::saturating_add)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pedersen_open_round_trips() {
        let blinding = Scalar::from(123_456_789u64);
        let value = 42_000u64;
        let commit = (generator_g() * blinding) + (generator_h() * Scalar::from(value));
        assert!(verify_pedersen_open(&commit, value, &blinding));
    }

    #[test]
    fn pedersen_open_rejects_wrong_value() {
        let blinding = Scalar::from(1u64);
        let commit = (generator_g() * blinding) + (generator_h() * Scalar::from(10u64));
        assert!(!verify_pedersen_open(&commit, 11, &blinding));
    }

    #[test]
    fn pedersen_open_rejects_wrong_blinding() {
        let commit = (generator_g() * Scalar::from(5u64)) + (generator_h() * Scalar::from(10u64));
        assert!(!verify_pedersen_open(&commit, 10, &Scalar::from(6u64)));
    }

    #[test]
    fn key_image_is_deterministic() {
        let x = Scalar::from(99u64);
        let p = generator_g() * x;
        let a = key_image_for_owned(&p, x).unwrap();
        let b = key_image_for_owned(&p, x).unwrap();
        assert_eq!(a.compress(), b.compress());
    }

    #[test]
    fn key_image_changes_with_spend_key() {
        let x1 = Scalar::from(1u64);
        let x2 = Scalar::from(2u64);
        let p = generator_g() * x1;
        let a = key_image_for_owned(&p, x1).unwrap();
        let b = key_image_for_owned(&p, x2).unwrap();
        assert_ne!(a.compress(), b.compress());
    }

    #[test]
    fn owned_balance_sums() {
        fn dummy(value: u64) -> OwnedOutput {
            OwnedOutput {
                one_time_addr: generator_g(),
                commit: generator_g(),
                value,
                blinding: Scalar::ONE,
                one_time_spend: Scalar::ONE,
                key_image: generator_g(),
                tx_id: [0u8; 32],
                output_idx: 0,
                height: 0,
            }
        }
        let v = [dummy(10), dummy(20), dummy(30)];
        assert_eq!(owned_balance(v.iter()), 60);
    }
}
