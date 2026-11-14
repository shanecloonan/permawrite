//! G-2: collection counts on checkpoint, retrieval, UTXO-tree, and Merkle
//! proof bytes must fail before `with_capacity` when they do not fit.

use mfn_consensus::retrieval::{decode_retrieval_ops, RetrievalError};
use mfn_consensus::CheckpointReadError;
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::utxo_tree::{decode_utxo_tree_state, UtxoTreeDecodeError};
use mfn_storage::{decode_merkle_proof_wire, SporaError};

fn leb128(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out
}

#[test]
fn retrieval_ops_reject_a_huge_count() {
    let err = decode_retrieval_ops(&leb128(1 << 33)).expect_err("bomb");
    assert!(matches!(err, RetrievalError::Codec));
}

#[test]
fn utxo_tree_rejects_a_huge_node_count() {
    let mut w = Writer::new();
    w.u64(0);
    w.varint(1 << 40);
    let err = decode_utxo_tree_state(&w.into_bytes()).expect_err("bomb");
    assert!(matches!(
        err,
        UtxoTreeDecodeError::LengthOverflow {
            field: "nodes.len",
            ..
        }
    ));
}

#[test]
fn merkle_proof_rejects_a_huge_sibling_count() {
    let mut w = Writer::new();
    w.varint(0);
    w.varint(1 << 28);
    let err = decode_merkle_proof_wire(&w.into_bytes()).expect_err("bomb");
    assert!(matches!(err, SporaError::TooManyChunks));
}

#[test]
fn checkpoint_read_len_rejects_a_huge_count() {
    let mut w = Writer::new();
    w.varint(u64::MAX);
    let mut r = Reader::new(w.bytes());
    let err = mfn_consensus::checkpoint_codec::read_len(&mut r, "utxo.len").expect_err("bomb");
    assert!(matches!(
        err,
        CheckpointReadError::LengthExceedsBuffer { remaining: 0, .. }
            | CheckpointReadError::LengthOverflow { .. }
    ));
}
