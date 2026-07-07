//! Transaction wire types.

#![allow(unused_imports)]

use super::internal::*;

/* ----------------------------------------------------------------------- *
 *  Wire types                                                              *
 * ----------------------------------------------------------------------- */

/// One signed input on the wire.
///
/// Hides the actual prior output among `ring`, commits to the spent value
/// via `c_pseudo`, and proves ownership + balance binding via `sig`.
#[derive(Clone, Debug)]
pub struct TxInputWire {
    /// Ring of `(P_i, C_i)` pairs forming the anonymity set.
    pub ring: ClsagRing,
    /// Pseudo-output commitment with the same hidden value as the real input.
    pub c_pseudo: EdwardsPoint,
    /// CLSAG signature authorizing the spend.
    pub sig: ClsagSignature,
}

/// One output on the wire.
///
/// `enc_amount` carries the encrypted (value, blinding) so the recipient
/// can open the commitment. For outputs whose target was a pre-built
/// `one_time_addr` (decoys, tests), the sender has no recipient view-key to
/// encrypt under and `enc_amount` is the all-zero 40-byte blob.
#[derive(Clone, Debug)]
pub struct TxOutputWire {
    /// Stealth one-time address.
    pub one_time_addr: EdwardsPoint,
    /// Pedersen commitment to the hidden output amount.
    pub amount: EdwardsPoint,
    /// Bulletproof range proof for the amount. `proof.v == amount`.
    pub range_proof: BulletproofRange,
    /// RingCT-style encrypted (value, blinding) blob, always
    /// [`ENC_AMOUNT_BYTES`] long.
    pub enc_amount: [u8; ENC_AMOUNT_BYTES],
    /// Monero-style 1-byte scan hint for the recipient view key.
    ///
    /// Present on v2 transactions (`Some`); absent on legacy v1 wire (`None`).
    pub view_tag: Option<u8>,
    /// Optional permanence binding — `Some` if this output anchors data.
    pub storage: Option<StorageCommitment>,
}

/// A full signed transaction on the wire.
#[derive(Clone, Debug)]
pub struct TransactionWire {
    /// Codec version.
    pub version: u32,
    /// Tx-level public key `R = r·G`.
    pub r_pub: EdwardsPoint,
    /// Inputs being spent.
    pub inputs: Vec<TxInputWire>,
    /// Outputs being created.
    pub outputs: Vec<TxOutputWire>,
    /// Public fee — claimed by the block producer.
    pub fee: u64,
    /// Opaque payload, committed-to by the preimage (immutable post-signing).
    pub extra: Vec<u8>,
}
