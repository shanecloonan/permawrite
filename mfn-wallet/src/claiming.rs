//! Optional **authorship claiming** keys (M2.2.x).
//!
//! A [`ClaimingIdentity`] is a Schnorr keypair used only to sign
//! [`mfn_crypto::authorship::AuthorshipClaim`] payloads bound to a storage
//! `data_root`. It is **not** the wallet's RingCT spend key — that
//! separation keeps anonymous uploads the default while still letting
//! publishers prove intent with a public `claim_pubkey`.
//!
//! ## Structural key firewall (F5:P10)
//!
//! The claiming scalar is derived by the canonical
//! [`mfn_crypto::authorship::derive_claiming_keypair`] under a derivation
//! domain disjoint from every financial-key domain, and this type's only
//! constructor is [`ClaimingIdentity::from_seed`] — a wallet *cannot* wrap
//! view/spend material in a `ClaimingIdentity`. The `Wallet` claim paths
//! additionally refuse to sign if a claiming pubkey ever collides with the
//! wallet's own view/spend pubkeys (defense in depth).

use curve25519_dalek::edwards::EdwardsPoint;

use mfn_crypto::authorship::derive_claiming_keypair;
use mfn_crypto::schnorr::SchnorrKeypair;

/// Schnorr identity used exclusively for authorship claims.
#[derive(Clone)]
pub struct ClaimingIdentity(SchnorrKeypair);

impl std::fmt::Debug for ClaimingIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimingIdentity")
            .field("claim_pub", &self.0.pub_key.compress())
            .finish_non_exhaustive()
    }
}

impl ClaimingIdentity {
    /// Derive a deterministic claiming keypair from the same 32-byte seed
    /// used for [`crate::wallet_from_seed`], via the canonical
    /// domain-separated derivation in
    /// [`mfn_crypto::authorship::derive_claiming_keypair`] — the claiming
    /// scalar is computationally independent of view/spend keys.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(derive_claiming_keypair(seed))
    }

    /// Public key advertised in every [`mfn_crypto::authorship::AuthorshipClaim`].
    #[inline]
    pub fn claim_pubkey(&self) -> EdwardsPoint {
        self.0.pub_key
    }

    /// Borrow the internal Schnorr keypair for signing.
    #[cfg(any(feature = "full", feature = "wasm-full"))]
    #[inline]
    pub(crate) fn keypair(&self) -> &SchnorrKeypair {
        &self.0
    }

    /// Construct from an arbitrary keypair — **tests only**, used to
    /// exercise the cross-domain reuse rejection in the claim paths.
    #[cfg(test)]
    pub(crate) fn from_keypair_for_tests(kp: SchnorrKeypair) -> Self {
        Self(kp)
    }

    /// Sign an MFCL authorship claim for a storage upload.
    #[cfg(any(feature = "full", feature = "wasm-full"))]
    pub fn sign_storage_claim(
        &self,
        data_root: [u8; 32],
        commit_hash: [u8; 32],
        message: &[u8],
    ) -> Result<mfn_crypto::authorship::AuthorshipClaim, crate::error::WalletError> {
        mfn_crypto::authorship::build_signed_claim(data_root, commit_hash, message, &self.0)
            .map_err(crate::error::WalletError::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_crypto::hash::hash_to_scalar;
    use mfn_crypto::point::generator_g;

    #[test]
    fn from_seed_matches_legacy_derivation() {
        // The pre-F5:P10 derivation lived in this module as
        // `hash_to_scalar([b"MFW_SEED_CLAIM_V1", seed])` with a zero->one
        // fallback. Moving it to mfn-crypto must not change any existing
        // claiming identity, or published claims would orphan on restore.
        for byte in [0u8, 3, 99, 0xff] {
            let seed = [byte; 32];
            let tag: &[u8] = b"MFW_SEED_CLAIM_V1";
            let legacy = hash_to_scalar(&[tag, &seed]);
            let id = ClaimingIdentity::from_seed(&seed);
            assert_eq!(
                (generator_g() * legacy).compress(),
                id.claim_pubkey().compress(),
                "derivation drifted for seed byte {byte}"
            );
        }
    }

    #[test]
    fn claiming_key_is_independent_of_wallet_keys_for_same_seed() {
        // F5:P10 — sharing one backup seed between the financial wallet
        // and the claiming identity must never link the two key domains.
        for byte in [0u8, 1, 42, 0xff] {
            let seed = [byte; 32];
            let id = ClaimingIdentity::from_seed(&seed);
            let wallet = crate::keys::wallet_from_seed(&seed);
            assert_ne!(
                id.claim_pubkey().compress(),
                wallet.view_pub().compress(),
                "claim key equals view key for seed byte {byte}"
            );
            assert_ne!(
                id.claim_pubkey().compress(),
                wallet.spend_pub().compress(),
                "claim key equals spend key for seed byte {byte}"
            );
        }
    }
}
