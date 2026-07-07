//! Transaction preimage and id hashing.

#![allow(unused_imports)]

use super::internal::*;
use super::wire::TransactionWire;
use super::{TX_VERSION, TX_VERSION_LEGACY};

/* ----------------------------------------------------------------------- *
 *  Encoding                                                                *
 * ----------------------------------------------------------------------- */

/// Consensus-critical preimage. This is the message CLSAG signs over and
/// the input to [`tx_id`].
///
/// **Canonical Rust transaction preimage hash.**
pub fn tx_preimage(tx: &TransactionWire) -> [u8; 32] {
    let mut w = Writer::new();
    w.varint(u64::from(tx.version));
    w.point(&tx.r_pub);
    w.u64(tx.fee);
    w.blob(&tx.extra);

    w.varint(tx.inputs.len() as u64);
    for inp in &tx.inputs {
        w.points(&inp.ring.p);
        w.points(&inp.ring.c);
        w.point(&inp.c_pseudo);
    }

    w.varint(tx.outputs.len() as u64);
    for out in &tx.outputs {
        w.point(&out.one_time_addr);
        w.point(&out.amount);
        w.blob(&encode_bulletproof(&out.range_proof));
        w.push(&out.enc_amount);
        if tx.version >= TX_VERSION {
            w.u8(out.view_tag.expect("v2 output missing view_tag"));
        } else if out.view_tag.is_some() {
            debug_assert_eq!(tx.version, TX_VERSION_LEGACY);
        }
        match &out.storage {
            Some(c) => {
                w.u8(1);
                w.push(&storage_commitment_hash(c));
            }
            None => {
                w.u8(0);
            }
        }
    }

    dhash(TX_PREIMAGE, &[w.bytes()])
}

/// Full transaction id — hash of preimage concatenated with the wire-format
/// signatures. Two txs with the same preimage but different sigs hash to
/// different ids (malleability defense).
///
/// **Canonical Rust transaction id hash.**
pub fn tx_id(tx: &TransactionWire) -> [u8; 32] {
    let preimage = tx_preimage(tx);
    let mut w = Writer::new();
    w.push(&preimage);
    w.varint(tx.inputs.len() as u64);
    for inp in &tx.inputs {
        w.blob(&encode_clsag(&inp.sig));
    }
    dhash(TX_ID, &[w.bytes()])
}
