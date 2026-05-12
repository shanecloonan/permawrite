//! On-chain **bond operation** wire format (Milestone M1).
//!
//! Merkle leaves use [`mfn_crypto::domain::BOND_OP_LEAF`] so bond commitments
//! never collide with transaction ids or storage hashes.
//!
//! Two variants ride this enum today:
//!
//! - [`BondOp::Register`] — admit a new validator and burn its declared
//!   stake into the permanence treasury.
//! - [`BondOp::Unbond`] — schedule a validator's exit; settles at
//!   `request_height + bonding_params.unbond_delay_heights`. The op
//!   carries a BLS signature by the validator's own BLS secret key over
//!   a domain-separated payload, proving only the operator could have
//!   authorized the exit.

use curve25519_dalek::edwards::EdwardsPoint;

use mfn_bls::{bls_verify, BlsPublicKey, BlsSecretKey, BlsSignature};
use mfn_bls::{decode_public_key, decode_signature, encode_public_key, encode_signature};
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::{BOND_OP_LEAF, UNBOND_OP_SIG};
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;
use thiserror::Error;

use crate::consensus::ValidatorPayout;

/// Wire tag for [`BondOp::Register`].
pub const BOND_OP_REGISTER: u8 = 0;
/// Wire tag for [`BondOp::Unbond`].
pub const BOND_OP_UNBOND: u8 = 1;

/// A consensus operation that mutates the validator set (M1).
//
// `Register` is fundamentally larger than `Unbond` because it must carry
// the full validator public keys and optional stealth payout. Boxing the
// large variant would force every `Register` op through an extra heap
// allocation and indirection on the consensus hot path; we accept the
// enum-size asymmetry as a deliberate trade-off.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BondOp {
    /// Register a new validator with locked stake and public keys.
    Register {
        /// Effective stake weight (must satisfy `bonding::validate_stake`).
        stake: u64,
        /// VRF public key (compressed ed25519 point).
        vrf_pk: EdwardsPoint,
        /// BLS12-381 voting public key.
        bls_pk: BlsPublicKey,
        /// Optional stealth payout for producer rewards.
        payout: Option<ValidatorPayout>,
    },
    /// Schedule an honorable exit for an existing validator. The op is
    /// authenticated by a BLS signature under the validator's own `bls_pk`
    /// over [`unbond_signing_hash`]; replay across the same validator is
    /// prevented by [`crate::block::ChainState::pending_unbonds`]
    /// rejecting duplicate enqueues.
    Unbond {
        /// Validator index assigned at registration (matches `Validator::index`).
        validator_index: u32,
        /// BLS signature over the canonical authorization payload.
        sig: BlsSignature,
    },
}

/// Canonical bytes that an [`BondOp::Unbond`] BLS signature commits to.
///
/// Domain-separated under [`UNBOND_OP_SIG`] so a leaked Unbond signature
/// cannot be replayed for any other purpose (including a second unbond
/// at a different validator index on a forked chain).
#[must_use]
pub fn unbond_signing_bytes(validator_index: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(validator_index);
    w.into_bytes()
}

/// 32-byte digest of [`unbond_signing_bytes`] — what gets BLS-signed.
#[must_use]
pub fn unbond_signing_hash(validator_index: u32) -> [u8; 32] {
    dhash(UNBOND_OP_SIG, &[&unbond_signing_bytes(validator_index)])
}

/// Construct the signature an [`BondOp::Unbond`] requires. The validator's
/// wallet calls this with its BLS secret key when initiating exit.
#[must_use]
pub fn sign_unbond(validator_index: u32, sk: &BlsSecretKey) -> BlsSignature {
    let msg = unbond_signing_hash(validator_index);
    mfn_bls::bls_sign(&msg, sk)
}

/// Verify the authorization signature on a [`BondOp::Unbond`].
#[must_use]
pub fn verify_unbond_sig(validator_index: u32, sig: &BlsSignature, pk: &BlsPublicKey) -> bool {
    let msg = unbond_signing_hash(validator_index);
    bls_verify(sig, &msg, pk)
}

/// Encode `op` to canonical bytes (included in the bond Merkle leaf).
pub fn encode_bond_op(op: &BondOp) -> Vec<u8> {
    let mut w = Writer::new();
    match op {
        BondOp::Register {
            stake,
            vrf_pk,
            bls_pk,
            payout,
        } => {
            w.u8(BOND_OP_REGISTER);
            w.u64(*stake);
            w.push(&vrf_pk.compress().to_bytes());
            w.push(&encode_public_key(bls_pk));
            match payout {
                None => {
                    w.u8(0);
                }
                Some(p) => {
                    w.u8(1);
                    w.push(&p.view_pub.compress().to_bytes());
                    w.push(&p.spend_pub.compress().to_bytes());
                }
            }
        }
        BondOp::Unbond {
            validator_index,
            sig,
        } => {
            w.u8(BOND_OP_UNBOND);
            w.u32(*validator_index);
            w.push(&encode_signature(sig));
        }
    }
    w.into_bytes()
}

/// Errors decoding [`BondOp`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BondWireError {
    /// Truncated or malformed buffer.
    #[error("bond wire decode: {0}")]
    Decode(String),
    /// Unknown operation tag.
    #[error("unknown bond op tag {0}")]
    UnknownTag(u8),
}

/// Decode a [`BondOp`] from canonical bytes.
pub fn decode_bond_op(bytes: &[u8]) -> Result<BondOp, BondWireError> {
    let mut r = Reader::new(bytes);
    let tag = r.u8().map_err(|e| BondWireError::Decode(e.to_string()))?;
    match tag {
        BOND_OP_REGISTER => {
            let stake = r.u64().map_err(|e| BondWireError::Decode(e.to_string()))?;
            let vrf_slice = r
                .bytes(32)
                .map_err(|e| BondWireError::Decode(e.to_string()))?;
            let vrf_b: [u8; 32] = vrf_slice
                .try_into()
                .map_err(|_| BondWireError::Decode("vrf_pk length".into()))?;
            let vrf_pk = curve25519_dalek::edwards::CompressedEdwardsY(vrf_b)
                .decompress()
                .ok_or_else(|| BondWireError::Decode("invalid vrf_pk".into()))?;
            let bls_b = r
                .bytes(48)
                .map_err(|e| BondWireError::Decode(e.to_string()))?;
            let bls_pk =
                decode_public_key(bls_b).map_err(|e| BondWireError::Decode(e.to_string()))?;
            let has_payout = r.u8().map_err(|e| BondWireError::Decode(e.to_string()))?;
            let payout = match has_payout {
                0 => None,
                1 => {
                    let vb_slice = r
                        .bytes(32)
                        .map_err(|e| BondWireError::Decode(e.to_string()))?;
                    let sb_slice = r
                        .bytes(32)
                        .map_err(|e| BondWireError::Decode(e.to_string()))?;
                    let vb: [u8; 32] = vb_slice
                        .try_into()
                        .map_err(|_| BondWireError::Decode("view_pub length".into()))?;
                    let sb: [u8; 32] = sb_slice
                        .try_into()
                        .map_err(|_| BondWireError::Decode("spend_pub length".into()))?;
                    let view_pub = curve25519_dalek::edwards::CompressedEdwardsY(vb)
                        .decompress()
                        .ok_or_else(|| BondWireError::Decode("invalid view_pub".into()))?;
                    let spend_pub = curve25519_dalek::edwards::CompressedEdwardsY(sb)
                        .decompress()
                        .ok_or_else(|| BondWireError::Decode("invalid spend_pub".into()))?;
                    Some(ValidatorPayout {
                        view_pub,
                        spend_pub,
                    })
                }
                x => return Err(BondWireError::Decode(format!("bad payout flag {x}"))),
            };
            if r.remaining() != 0 {
                return Err(BondWireError::Decode("trailing bytes".into()));
            }
            Ok(BondOp::Register {
                stake,
                vrf_pk,
                bls_pk,
                payout,
            })
        }
        BOND_OP_UNBOND => {
            let validator_index = r.u32().map_err(|e| BondWireError::Decode(e.to_string()))?;
            let sig_bytes = r
                .bytes(96)
                .map_err(|e| BondWireError::Decode(e.to_string()))?;
            let sig =
                decode_signature(sig_bytes).map_err(|e| BondWireError::Decode(e.to_string()))?;
            if r.remaining() != 0 {
                return Err(BondWireError::Decode("trailing bytes".into()));
            }
            Ok(BondOp::Unbond {
                validator_index,
                sig,
            })
        }
        t => Err(BondWireError::UnknownTag(t)),
    }
}

/// 32-byte Merkle leaf for one bond op (domain-separated).
#[must_use]
pub fn bond_op_leaf_hash(op: &BondOp) -> [u8; 32] {
    let enc = encode_bond_op(op);
    dhash(BOND_OP_LEAF, &[&enc])
}

/// Merkle root over all bond ops in block order (empty → zero sentinel).
#[must_use]
pub fn bond_merkle_root(ops: &[BondOp]) -> [u8; 32] {
    if ops.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = ops.iter().map(bond_op_leaf_hash).collect();
    merkle_root_or_zero(&leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_bls::bls_keygen_from_seed;
    use mfn_crypto::point::generator_g;

    #[test]
    fn bond_op_round_trip() {
        let op = BondOp::Register {
            stake: 2_000_000,
            vrf_pk: generator_g(),
            bls_pk: bls_keygen_from_seed(&[9u8; 32]).pk,
            payout: None,
        };
        let b = encode_bond_op(&op);
        let dec = decode_bond_op(&b).unwrap();
        assert_eq!(dec, op);
    }

    #[test]
    fn merkle_empty_is_zero() {
        assert_eq!(bond_merkle_root(&[]), [0u8; 32]);
    }

    /// Wire + leaf from `cloonan-group/scripts/smoke-bond.ts` (`GOLDEN_BOND_OP_*`).
    /// Keeps MFBN bond bytes aligned with the TypeScript reference client.
    #[test]
    fn bond_register_wire_matches_cloonan_ts_smoke_reference() {
        const WIRE_HEX: &str = "0000000000000f4240b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1aab6e7afc31b3d67eef05ff38bfb40d5e608f352b3c0341ec019653505d7c1f13dd1e60640bb00d0735daa5cbd3b902600";
        const LEAF_HEX: &str = "51164109143ca1e9db57a1738443c078389c6492e5ea14ed8ecf0aea83d1962b";
        let wire = hex::decode(WIRE_HEX).expect("wire hex");
        let op = decode_bond_op(&wire).expect("decode ts wire");
        assert_eq!(encode_bond_op(&op), wire);
        assert_eq!(hex::encode(bond_op_leaf_hash(&op)), LEAF_HEX);
    }

    #[test]
    fn unbond_op_round_trip_and_sig_verify() {
        let bls = bls_keygen_from_seed(&[33u8; 32]);
        let idx = 7u32;
        let sig = sign_unbond(idx, &bls.sk);
        assert!(verify_unbond_sig(idx, &sig, &bls.pk));

        let op = BondOp::Unbond {
            validator_index: idx,
            sig,
        };
        let bytes = encode_bond_op(&op);
        // Tag(1) + u32(4) + sig(96) = 101 bytes.
        assert_eq!(bytes.len(), 1 + 4 + 96);
        let decoded = decode_bond_op(&bytes).unwrap();
        assert_eq!(decoded, op);
    }

    #[test]
    fn unbond_signing_hash_is_domain_separated() {
        // Same validator_index, different domain ⇒ different hash. Sanity
        // check: ensure UNBOND_OP_SIG isn't accidentally aliased to
        // BOND_OP_LEAF or any other consensus tag.
        let h1 = unbond_signing_hash(0);
        let h2 = mfn_crypto::hash::dhash(BOND_OP_LEAF, &[&unbond_signing_bytes(0)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn unbond_sig_does_not_verify_under_different_index() {
        let bls = bls_keygen_from_seed(&[44u8; 32]);
        let sig = sign_unbond(1, &bls.sk);
        assert!(verify_unbond_sig(1, &sig, &bls.pk));
        assert!(!verify_unbond_sig(2, &sig, &bls.pk));
    }

    #[test]
    fn unbond_decode_rejects_trailing_bytes() {
        let bls = bls_keygen_from_seed(&[55u8; 32]);
        let sig = sign_unbond(0, &bls.sk);
        let op = BondOp::Unbond {
            validator_index: 0,
            sig,
        };
        let mut bytes = encode_bond_op(&op);
        bytes.push(0xAA);
        assert!(decode_bond_op(&bytes).is_err());
    }
}
