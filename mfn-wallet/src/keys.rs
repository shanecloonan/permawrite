//! Wallet key material — a thin layer on top of
//! [`mfn_crypto::stealth::StealthWallet`].
//!
//! The Permawrite wallet uses Monero-style **dual** keys:
//!
//! - The **view key** is used only to *scan* the chain. Sharing it with a
//!   third party (e.g. an auditor, an accountant, a watch-only mobile
//!   companion) lets them see your incoming payments but never lets them
//!   spend.
//! - The **spend key** is used only to *sign CLSAGs* that authorise
//!   spending. It never has to leave a hardware wallet.
//!
//! [`WalletKeys`] separates the two so that the future
//! `mfn_wallet::view::ViewWallet` (read-only) and
//! `mfn_wallet::Wallet` (read-write) can share one set of primitives.
//!
//! ## Deterministic key derivation
//!
//! `stealth_gen` in `mfn-crypto` is CSPRNG-only; this module adds a
//! deterministic [`wallet_from_seed`] entry point so that backups can be
//! a single 32-byte secret. We derive `(view_priv, spend_priv)` by
//! domain-separated hashing of the seed — the standard pattern used by
//! every wallet that wants 12-/24-word mnemonics to round-trip to chain
//! keys without ambiguity.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use mfn_crypto::hash::hash_to_scalar;
use mfn_crypto::point::generator_g;
use mfn_crypto::stealth::{StealthPubKeys, StealthWallet};

/// Domain tag for deriving the view-private scalar from a wallet seed.
const SEED_TAG_VIEW: &[u8] = b"MFW_SEED_VIEW_V1";
/// Domain tag for deriving the spend-private scalar from a wallet seed.
const SEED_TAG_SPEND: &[u8] = b"MFW_SEED_SPEND_V1";

/// Wallet key material.
///
/// Wraps a [`StealthWallet`] so callers can construct a wallet from a
/// fixed seed (for HD-style backups), or from an existing `StealthWallet`
/// produced by [`mfn_crypto::stealth::stealth_gen`] when freshness is
/// already desired.
#[derive(Debug, Clone)]
pub struct WalletKeys {
    inner: StealthWallet,
}

impl WalletKeys {
    /// Wrap an existing [`StealthWallet`].
    #[inline]
    pub fn from_stealth(inner: StealthWallet) -> Self {
        Self { inner }
    }

    /// Borrow the wrapped [`StealthWallet`].
    ///
    /// Returned by reference so callers can use the `mfn-crypto` scan
    /// primitives directly without surrendering ownership.
    #[inline]
    pub fn inner(&self) -> &StealthWallet {
        &self.inner
    }

    /// Recipient-facing pubkey pair (view_pub, spend_pub) — what the
    /// sender needs to address this wallet.
    #[inline]
    pub fn pubkeys(&self) -> StealthPubKeys {
        StealthPubKeys::from(&self.inner)
    }

    /// Public view key `A = a·G`.
    #[inline]
    pub fn view_pub(&self) -> EdwardsPoint {
        self.inner.view_pub
    }

    /// Public spend key `B = b·G`.
    #[inline]
    pub fn spend_pub(&self) -> EdwardsPoint {
        self.inner.spend_pub
    }

    /// Private view key `a`. Exposed so callers can implement custom
    /// scan loops on top of [`mfn_crypto::decrypt_output_amount`].
    #[inline]
    pub fn view_priv(&self) -> Scalar {
        self.inner.view_priv
    }
}

/// Derive a [`WalletKeys`] deterministically from a 32-byte seed.
///
/// The seed is domain-separated twice to produce the two private
/// scalars; if either scalar reduces to zero we replace it with `1` (the
/// same pathological-recovery rule the consensus layer uses for
/// deterministic VRF / coinbase keys). The probability of a real-world
/// seed hitting that branch is astronomically small but the branch keeps
/// the function total.
pub fn wallet_from_seed(seed: &[u8; 32]) -> WalletKeys {
    let view_priv = derive_scalar(seed, SEED_TAG_VIEW);
    let spend_priv = derive_scalar(seed, SEED_TAG_SPEND);
    let g = generator_g();
    WalletKeys::from_stealth(StealthWallet {
        view_priv,
        view_pub: g * view_priv,
        spend_priv,
        spend_pub: g * spend_priv,
    })
}

fn derive_scalar(seed: &[u8; 32], tag: &[u8]) -> Scalar {
    let s = hash_to_scalar(&[tag, seed]);
    if s == Scalar::ZERO {
        Scalar::ONE
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [7u8; 32];
        let a = wallet_from_seed(&seed);
        let b = wallet_from_seed(&seed);
        assert_eq!(a.view_pub().compress(), b.view_pub().compress());
        assert_eq!(a.spend_pub().compress(), b.spend_pub().compress());
    }

    #[test]
    fn different_seeds_yield_different_wallets() {
        let a = wallet_from_seed(&[1u8; 32]);
        let b = wallet_from_seed(&[2u8; 32]);
        assert_ne!(a.view_pub().compress(), b.view_pub().compress());
        assert_ne!(a.spend_pub().compress(), b.spend_pub().compress());
    }

    #[test]
    fn view_and_spend_keys_are_independent() {
        let w = wallet_from_seed(&[42u8; 32]);
        assert_ne!(w.view_priv(), w.inner().spend_priv);
        assert_ne!(w.view_pub().compress(), w.spend_pub().compress());
    }

    #[test]
    fn pubkeys_round_trip_through_stealth_pubkeys() {
        let w = wallet_from_seed(&[9u8; 32]);
        let pk = w.pubkeys();
        assert_eq!(pk.view_pub.compress(), w.view_pub().compress());
        assert_eq!(pk.spend_pub.compress(), w.spend_pub().compress());
    }
}
