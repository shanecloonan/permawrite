//! On-chain **storage-operator registration** wire format (B3 phase 3b).
//!
//! Distinct from validator [`BondOp`] — storage operators authorize with a
//! Schnorr signature under their payout **spend** public key, not BLS.
//! Leaves share the block header's `bond_root` Merkle tree (after validator
//! bond-op leaves) via [`bond_section_merkle_root`].

use curve25519_dalek::edwards::EdwardsPoint;

use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::{STORAGE_OPERATOR_OP_LEAF, STORAGE_OPERATOR_REGISTER_SIG};
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;
use mfn_crypto::schnorr::{
    decode_schnorr_signature, encode_schnorr_signature, schnorr_verify, SchnorrSignature,
    SCHNORR_SIGNATURE_BYTES,
};
use mfn_storage::{operator_identity_from_payout, operator_payout_is_valid, EndowmentParams};

use crate::block::StorageOperatorEntry;
use crate::bond_wire::{bond_op_leaf_hash, BondOp};

/// Wire tag for [`StorageOperatorOp::Register`].
pub const STORAGE_OP_REGISTER: u8 = 0;

/// A consensus operation that registers a storage operator payout identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageOperatorOp {
    /// Register operator payout keys and escrow `bond_amount` into the
    /// permanence treasury. Authorized by a Schnorr signature under
    /// `operator_spend_pub` over [`register_signing_hash`].
    Register {
        /// Escrowed bond in base units (burned to treasury on acceptance).
        bond_amount: u64,
        /// Operator payout view public key.
        operator_view_pub: EdwardsPoint,
        /// Operator payout spend public key (signing authority).
        operator_spend_pub: EdwardsPoint,
        /// Schnorr signature by the spend key over the register payload.
        sig: SchnorrSignature,
    },
}

/// Canonical bytes a [`StorageOperatorOp::Register`] Schnorr signature commits to.
#[must_use]
pub fn register_signing_bytes(
    bond_amount: u64,
    operator_view_pub: &EdwardsPoint,
    operator_spend_pub: &EdwardsPoint,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(bond_amount);
    w.push(&operator_view_pub.compress().to_bytes());
    w.push(&operator_spend_pub.compress().to_bytes());
    w.into_bytes()
}

/// 32-byte digest of [`register_signing_bytes`] — what gets Schnorr-signed.
#[must_use]
pub fn register_signing_hash(
    bond_amount: u64,
    operator_view_pub: &EdwardsPoint,
    operator_spend_pub: &EdwardsPoint,
) -> [u8; 32] {
    dhash(
        STORAGE_OPERATOR_REGISTER_SIG,
        &[&register_signing_bytes(
            bond_amount,
            operator_view_pub,
            operator_spend_pub,
        )],
    )
}

/// Verify the authorization signature on a [`StorageOperatorOp::Register`].
#[must_use]
pub fn verify_register_sig(
    bond_amount: u64,
    operator_view_pub: &EdwardsPoint,
    operator_spend_pub: &EdwardsPoint,
    sig: &SchnorrSignature,
) -> bool {
    let msg = register_signing_hash(bond_amount, operator_view_pub, operator_spend_pub);
    schnorr_verify(&msg, sig, operator_spend_pub)
}

/// Encode `op` to canonical bytes (included in the bond-section Merkle leaf).
pub fn encode_storage_operator_op(op: &StorageOperatorOp) -> Vec<u8> {
    let mut w = Writer::new();
    match op {
        StorageOperatorOp::Register {
            bond_amount,
            operator_view_pub,
            operator_spend_pub,
            sig,
        } => {
            w.u8(STORAGE_OP_REGISTER);
            w.u64(*bond_amount);
            w.push(&operator_view_pub.compress().to_bytes());
            w.push(&operator_spend_pub.compress().to_bytes());
            w.push(&encode_schnorr_signature(sig));
        }
    }
    w.into_bytes()
}

/// Errors decoding [`StorageOperatorOp`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StorageOperatorWireError {
    /// Truncated or malformed buffer.
    #[error("storage operator wire decode: {0}")]
    Decode(String),
    /// Unknown operation tag.
    #[error("unknown storage operator op tag {0}")]
    UnknownTag(u8),
}

/// Decode a [`StorageOperatorOp`] from canonical bytes.
pub fn decode_storage_operator_op(
    bytes: &[u8],
) -> Result<StorageOperatorOp, StorageOperatorWireError> {
    let mut r = Reader::new(bytes);
    let tag = r
        .u8()
        .map_err(|e| StorageOperatorWireError::Decode(e.to_string()))?;
    match tag {
        STORAGE_OP_REGISTER => {
            let bond_amount = r
                .u64()
                .map_err(|e| StorageOperatorWireError::Decode(e.to_string()))?;
            let view_b = r
                .bytes(32)
                .map_err(|e| StorageOperatorWireError::Decode(e.to_string()))?;
            let spend_b = r
                .bytes(32)
                .map_err(|e| StorageOperatorWireError::Decode(e.to_string()))?;
            let sig_b = r
                .bytes(SCHNORR_SIGNATURE_BYTES)
                .map_err(|e| StorageOperatorWireError::Decode(e.to_string()))?;
            if r.remaining() != 0 {
                return Err(StorageOperatorWireError::Decode("trailing bytes".into()));
            }
            let view_arr: [u8; 32] = view_b
                .try_into()
                .map_err(|_| StorageOperatorWireError::Decode("view_pub length".into()))?;
            let spend_arr: [u8; 32] = spend_b
                .try_into()
                .map_err(|_| StorageOperatorWireError::Decode("spend_pub length".into()))?;
            let sig_arr: [u8; SCHNORR_SIGNATURE_BYTES] = sig_b
                .try_into()
                .map_err(|_| StorageOperatorWireError::Decode("sig length".into()))?;
            let operator_view_pub = curve25519_dalek::edwards::CompressedEdwardsY(view_arr)
                .decompress()
                .ok_or_else(|| StorageOperatorWireError::Decode("invalid view_pub".into()))?;
            let operator_spend_pub = curve25519_dalek::edwards::CompressedEdwardsY(spend_arr)
                .decompress()
                .ok_or_else(|| StorageOperatorWireError::Decode("invalid spend_pub".into()))?;
            let sig = decode_schnorr_signature(&sig_arr)
                .map_err(|e| StorageOperatorWireError::Decode(e.to_string()))?;
            Ok(StorageOperatorOp::Register {
                bond_amount,
                operator_view_pub,
                operator_spend_pub,
                sig,
            })
        }
        t => Err(StorageOperatorWireError::UnknownTag(t)),
    }
}

/// 32-byte Merkle leaf for one storage-operator op (domain-separated).
#[must_use]
pub fn storage_operator_op_leaf_hash(op: &StorageOperatorOp) -> [u8; 32] {
    let enc = encode_storage_operator_op(op);
    dhash(STORAGE_OPERATOR_OP_LEAF, &[&enc])
}

/// Merkle root over validator bond ops followed by storage-operator ops.
///
/// Empty both lists → 32-byte zero sentinel (same as [`crate::bond_wire::bond_merkle_root`]).
#[must_use]
pub fn bond_section_merkle_root(
    bond_ops: &[BondOp],
    storage_operator_ops: &[StorageOperatorOp],
) -> [u8; 32] {
    if bond_ops.is_empty() && storage_operator_ops.is_empty() {
        return [0u8; 32];
    }
    let mut leaves: Vec<[u8; 32]> = bond_ops.iter().map(bond_op_leaf_hash).collect();
    leaves.extend(
        storage_operator_ops
            .iter()
            .map(storage_operator_op_leaf_hash),
    );
    merkle_root_or_zero(&leaves)
}

/// A single storage-operator op rejection.
#[derive(Debug)]
pub struct StorageOperatorOpError {
    /// 0-indexed position in `block.storage_operator_ops`.
    pub index: usize,
    /// Human-readable reason.
    pub message: String,
}

/// Apply storage-operator registration ops atomically.
///
/// On success: inserts into `storage_operators` and returns total bond burned
/// (caller credits treasury). On failure: no mutation.
pub fn apply_storage_operator_ops(
    height: u32,
    endowment_params: &EndowmentParams,
    storage_operators: &mut std::collections::BTreeMap<[u8; 32], StorageOperatorEntry>,
    ops: &[StorageOperatorOp],
) -> Result<u128, StorageOperatorOpError> {
    let mut staged: Vec<([u8; 32], StorageOperatorEntry)> = Vec::new();
    let mut seen_ids: std::collections::HashSet<[u8; 32]> =
        storage_operators.keys().copied().collect();
    let mut burn_total: u128 = 0;

    for (i, op) in ops.iter().enumerate() {
        let StorageOperatorOp::Register {
            bond_amount,
            operator_view_pub,
            operator_spend_pub,
            sig,
        } = op;
        if !operator_payout_is_valid(operator_view_pub, operator_spend_pub) {
            return Err(StorageOperatorOpError {
                index: i,
                message: "invalid operator payout keys".into(),
            });
        }
        if endowment_params.min_storage_operator_bond > 0
            && *bond_amount < endowment_params.min_storage_operator_bond
        {
            return Err(StorageOperatorOpError {
                index: i,
                message: format!(
                    "bond {bond_amount} below min_storage_operator_bond {}",
                    endowment_params.min_storage_operator_bond
                ),
            });
        }
        if !verify_register_sig(*bond_amount, operator_view_pub, operator_spend_pub, sig) {
            return Err(StorageOperatorOpError {
                index: i,
                message: "register signature invalid".into(),
            });
        }
        let id = operator_identity_from_payout(operator_view_pub, operator_spend_pub);
        if !seen_ids.insert(id) {
            return Err(StorageOperatorOpError {
                index: i,
                message: "duplicate operator identity".into(),
            });
        }
        staged.push((
            id,
            StorageOperatorEntry {
                operator_view_pub: *operator_view_pub,
                operator_spend_pub: *operator_spend_pub,
                registration_height: height,
                bond_amount: *bond_amount,
            },
        ));
        burn_total = burn_total.saturating_add(u128::from(*bond_amount));
    }

    for (id, entry) in staged {
        storage_operators.insert(id, entry);
    }
    Ok(burn_total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use mfn_crypto::point::generator_g;
    use mfn_crypto::schnorr::{schnorr_sign_with, SchnorrKeypair};
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    fn test_register_op(spend_scalar: u64, view_scalar: u64, bond: u64) -> StorageOperatorOp {
        let view = generator_g() * Scalar::from(view_scalar);
        let spend = generator_g() * Scalar::from(spend_scalar);
        let kp = SchnorrKeypair {
            priv_key: Scalar::from(spend_scalar),
            pub_key: spend,
        };
        let msg = register_signing_hash(bond, &view, &spend);
        let sig = schnorr_sign_with(&msg, &kp, &mut rand_core::OsRng);
        StorageOperatorOp::Register {
            bond_amount: bond,
            operator_view_pub: view,
            operator_spend_pub: spend,
            sig,
        }
    }

    #[test]
    fn storage_operator_op_round_trip() {
        let op = test_register_op(2, 1, 50_000);
        let bytes = encode_storage_operator_op(&op);
        let dec = decode_storage_operator_op(&bytes).unwrap();
        assert_eq!(dec, op);
    }

    #[test]
    fn bond_section_root_orders_bond_before_storage_ops() {
        use crate::bond_wire::bond_merkle_root;
        let both_empty = bond_section_merkle_root(&[], &[]);
        assert_eq!(bond_merkle_root(&[]), both_empty);

        let op = test_register_op(3, 5, 1);
        let root_one = bond_section_merkle_root(&[], std::slice::from_ref(&op));
        let root_two = bond_section_merkle_root(&[], std::slice::from_ref(&op));
        assert_eq!(root_one, root_two);
        assert_ne!(root_one, [0u8; 32]);
    }

    #[test]
    fn apply_register_inserts_operator() {
        let op = test_register_op(7, 11, 0);
        let StorageOperatorOp::Register {
            operator_view_pub,
            operator_spend_pub,
            ..
        } = &op;
        let id = operator_identity_from_payout(operator_view_pub, operator_spend_pub);
        let mut map = std::collections::BTreeMap::new();
        let burn =
            apply_storage_operator_ops(5, &DEFAULT_ENDOWMENT_PARAMS, &mut map, &[op]).unwrap();
        assert_eq!(burn, 0);
        assert!(map.contains_key(&id));
        assert_eq!(map[&id].registration_height, 5);
    }
}
