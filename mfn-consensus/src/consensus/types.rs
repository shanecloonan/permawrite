//! Validator set types and Merkle roots (always available; no BLS12-381 runtime).

use curve25519_dalek::edwards::EdwardsPoint;

use crate::bls::encode_public_key;
use mfn_crypto::codec::Writer;
use mfn_crypto::domain::VALIDATOR_LEAF;
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;

/// Public payout destination of a validator (used by the chain's coinbase routing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorPayout {
    /// Public view key.
    pub view_pub: EdwardsPoint,
    /// Public spend key.
    pub spend_pub: EdwardsPoint,
}

/// A validator's on-chain record.
#[derive(Clone, Debug)]
pub struct Validator {
    /// Index into the canonical validator list (frozen at genesis in v0.1).
    pub index: u32,
    /// ed25519 VRF public key (for the leader lottery).
    pub vrf_pk: EdwardsPoint,
    /// BLS12-381 voting public key (for finality aggregation).
    pub bls_pk: crate::bls::BlsPublicKey,
    /// Effective stake weight.
    pub stake: u64,
    /// Optional stealth payout destination.
    pub payout: Option<ValidatorPayout>,
}

/// Canonical bytes for a single [`Validator`] when committed under the
/// block header's `validator_root`.
#[must_use]
pub fn validator_leaf_bytes(v: &Validator) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(v.index);
    w.u64(v.stake);
    w.push(&v.vrf_pk.compress().to_bytes());
    w.push(&encode_public_key(&v.bls_pk));
    match &v.payout {
        None => {
            w.u8(0);
        }
        Some(p) => {
            w.u8(1);
            w.push(&p.view_pub.compress().to_bytes());
            w.push(&p.spend_pub.compress().to_bytes());
        }
    }
    w.into_bytes()
}

/// 32-byte Merkle leaf hash for one validator.
#[must_use]
pub fn validator_leaf_hash(v: &Validator) -> [u8; 32] {
    dhash(VALIDATOR_LEAF, &[&validator_leaf_bytes(v)])
}

/// Merkle root over the active validator set in canonical index order.
#[must_use]
pub fn validator_set_root(validators: &[Validator]) -> [u8; 32] {
    if validators.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = validators.iter().map(validator_leaf_hash).collect();
    merkle_root_or_zero(&leaves)
}
