//! Optional **authorship claiming** keys (M2.2.x).
//!
//! A [`ClaimingIdentity`] is a Schnorr keypair used only to sign
//! [`mfn_crypto::authorship::AuthorshipClaim`] payloads bound to a storage
//! `data_root`. It is **not** the wallet's RingCT spend key — that
//! separation keeps anonymous uploads the default while still letting
//! publishers prove intent with a public `claim_pubkey`.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use mfn_crypto::hash::hash_to_scalar;
use mfn_crypto::point::generator_g;
use mfn_crypto::schnorr::SchnorrKeypair;

/// Domain tag for deriving the claiming private scalar from a wallet seed.
const SEED_TAG_CLAIM: &[u8] = b"MFW_SEED_CLAIM_V1";

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
    /// used for [`crate::wallet_from_seed`], using a separate domain tag
    /// so the claiming scalar is independent of view/spend keys.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let priv_key = derive_claim_scalar(seed);
        let pub_key = generator_g() * priv_key;
        Self(SchnorrKeypair { priv_key, pub_key })
    }

    /// Public key advertised in every [`mfn_crypto::authorship::AuthorshipClaim`].
    #[inline]
    pub fn claim_pubkey(&self) -> EdwardsPoint {
        self.0.pub_key
    }

    /// Borrow the internal Schnorr keypair for signing.
    #[inline]
    pub(crate) fn keypair(&self) -> &SchnorrKeypair {
        &self.0
    }
}

fn derive_claim_scalar(seed: &[u8; 32]) -> Scalar {
    let s = hash_to_scalar(&[SEED_TAG_CLAIM, seed]);
    if s == Scalar::ZERO {
        Scalar::ONE
    } else {
        s
    }
}
