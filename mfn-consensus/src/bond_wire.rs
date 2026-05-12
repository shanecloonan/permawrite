//! On-chain **bond operation** wire format (Milestone M1).
//!
//! Merkle leaves use [`mfn_crypto::domain::BOND_OP_LEAF`] so bond commitments
//! never collide with transaction ids or storage hashes.

use curve25519_dalek::edwards::EdwardsPoint;

use mfn_bls::{decode_public_key, encode_public_key, BlsPublicKey};
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::BOND_OP_LEAF;
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;
use thiserror::Error;

use crate::consensus::ValidatorPayout;

/// Wire tag for [`BondOp`].
pub const BOND_OP_REGISTER: u8 = 0;

/// A consensus operation that mutates the validator set (M1).
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
}
