//! Full block wire encode/decode and Merkle roots.

use super::internal::*;

use super::header::{block_header_bytes, decode_block_header, Block, HeaderDecodeError};

/* ----------------------------------------------------------------------- *
 *  Full block wire codec — M2.0.10                                          *
 * ----------------------------------------------------------------------- */

/// Lossless canonical byte encoding of a [`Block`].
///
/// Composes the existing header encoding ([`block_header_bytes`]) with
/// the four body sections in the same order the header roots them
/// (`tx_root`, `bond_root`, `slashing_root`, `storage_proof_root`) and
/// the same order [`crate::header_verify::verify_block_body`] re-derives
/// them in:
///
/// ```text
/// block_header_bytes(header)
/// varint(txs.len)          || blob(encode_transaction(t))*
/// varint(bond_ops.len)     || blob(encode_bond_op(o))*
/// varint(slashings.len)    || blob(encode_evidence(e))*
/// varint(storage_proofs.len) || blob(encode_storage_proof(p))*
/// ```
///
/// Every section is length-prefixed so the decoder can stream through
/// without needing to know the encoded shape of the body's individual
/// items in advance. Each item itself is length-prefixed via `blob`
/// (its inner encoder's `Vec<u8>` output) — this gives the decoder
/// a hard boundary per item even if a future codec version extends a
/// body element's payload.
///
/// `decode_block(&encode_block(b)) == Ok(b)` for every well-formed
/// block (byte-for-byte round-trip). The decoded block re-derives the
/// same header roots and the same [`block_id`].
fn encode_block_body_parts(
    w: &mut Writer,
    txs: &[TransactionWire],
    bond_ops: &[BondOp],
    slashings: &[SlashEvidence],
    storage_proofs: &[StorageProof],
) {
    w.varint(txs.len() as u64);
    for tx in txs {
        w.blob(&encode_transaction(tx));
    }
    w.varint(bond_ops.len() as u64);
    for op in bond_ops {
        w.blob(&encode_bond_op(op));
    }
    w.varint(slashings.len() as u64);
    for ev in slashings {
        w.blob(&encode_evidence(ev));
    }
    w.varint(storage_proofs.len() as u64);
    for p in storage_proofs {
        w.blob(&encode_storage_proof(p));
    }
}

/// Canonical body bytes (txs, bond ops, slashings, storage proofs) without a header.
#[must_use]
pub fn encode_block_body(
    txs: &[TransactionWire],
    bond_ops: &[BondOp],
    slashings: &[SlashEvidence],
    storage_proofs: &[StorageProof],
) -> Vec<u8> {
    let mut w = Writer::new();
    encode_block_body_parts(&mut w, txs, bond_ops, slashings, storage_proofs);
    w.into_bytes()
}

/// Decoded block body sections from [`encode_block_body`].
#[derive(Clone, Debug, Default)]
pub struct BlockBody {
    /// Transactions in block order.
    pub txs: Vec<TransactionWire>,
    /// Bond operations.
    pub bond_ops: Vec<BondOp>,
    /// Slashing evidence.
    pub slashings: Vec<SlashEvidence>,
    /// SPoRA storage proofs.
    pub storage_proofs: Vec<StorageProof>,
}

/// Encode a full block (header bytes + canonical body section).
#[must_use]
pub fn encode_block(b: &Block) -> Vec<u8> {
    let mut out = block_header_bytes(&b.header);
    let body = encode_block_body(&b.txs, &b.bond_ops, &b.slashings, &b.storage_proofs);
    out.extend_from_slice(&body);
    out
}

/// Typed errors produced by [`decode_block`].
#[derive(Debug, thiserror::Error)]
pub enum BlockDecodeError {
    /// Header section failed to decode.
    #[error("block header: {0}")]
    Header(#[from] HeaderDecodeError),
    /// Underlying codec layer hit a short read, invalid point, varint
    /// overflow, etc. while parsing the body section framing.
    #[error("block body codec: {0}")]
    Codec(#[from] mfn_crypto::CryptoError),
    /// A declared body-section count overflowed `usize`. Defensive
    /// guard for 32-bit targets.
    #[error("{field} count {got} exceeds usize")]
    CountTooLarge {
        /// Which body section's count tripped the guard.
        field: &'static str,
        /// The raw varint value that overflowed.
        got: u64,
    },
    /// A specific transaction in the body failed to decode.
    #[error("tx[{index}]: {source}")]
    Transaction {
        /// Index of the offending transaction in `block.txs`.
        index: usize,
        /// Underlying transaction-decoder error.
        #[source]
        source: TxDecodeError,
    },
    /// A specific bond op in the body failed to decode.
    #[error("bond_ops[{index}]: {source}")]
    BondOp {
        /// Index of the offending op in `block.bond_ops`.
        index: usize,
        /// Underlying bond-op-decoder error.
        #[source]
        source: BondWireError,
    },
    /// A specific slashing-evidence item in the body failed to decode.
    #[error("slashings[{index}]: {source}")]
    Slashing {
        /// Index of the offending evidence item in `block.slashings`.
        index: usize,
        /// Underlying slashing-decoder error.
        #[source]
        source: SlashDecodeError,
    },
    /// A specific storage proof in the body failed to decode.
    #[error("storage_proofs[{index}]: {source}")]
    StorageProof {
        /// Index of the offending proof in `block.storage_proofs`.
        index: usize,
        /// Underlying storage-proof-decoder error.
        #[source]
        source: mfn_storage::SporaError,
    },
    /// Bytes remained in the buffer after a full block had been parsed.
    /// Blocks are self-delimiting, so a non-empty tail always indicates
    /// caller-side framing confusion or corruption.
    #[error("{remaining} trailing byte(s) after block")]
    TrailingBytes {
        /// Number of trailing bytes left in the buffer.
        remaining: usize,
    },
}

/// Decode a [`Block`] from its canonical wire encoding produced by
/// [`encode_block`].
///
/// `decode_block(&encode_block(b)) == Ok(b)` byte-for-byte for every
/// well-formed block. Strict: any trailing byte after the last storage
/// proof is a hard reject ([`BlockDecodeError::TrailingBytes`]).
///
/// The decoded `Block`'s `header` is validated only structurally
/// (well-formed wire encoding); higher-level consensus checks
/// (`header.tx_root == tx_merkle_root(block.txs)`, finality proof,
/// linkage to the prior block, etc.) live in
/// [`crate::header_verify::verify_header`] and
/// [`crate::header_verify::verify_block_body`] respectively.
///
/// # Errors
///
/// Returns [`BlockDecodeError`] on header decode failure, truncated
/// body framing, a malformed body item (transaction / bond op /
/// slashing / storage proof), oversize counts, or trailing bytes.
pub fn decode_block(bytes: &[u8]) -> Result<Block, BlockDecodeError> {
    // The header has a self-delimiting wire format. We can't simply
    // call decode_block_header(bytes) — that would reject our body
    // bytes as trailing. Instead, walk the header inline using a
    // local Reader so the same Reader can carry on to the body.
    let mut r = Reader::new(bytes);

    let header_len = peek_block_header_len(&r)?;
    // Re-decode the header from its own framed slice so we get the
    // typed HeaderDecodeError surface (truncation field names, etc.).
    let header_bytes = r
        .bytes(header_len)
        .map_err(|_| HeaderDecodeError::Truncated {
            field: "header",
            needed: header_len,
        })?;
    let header = decode_block_header(header_bytes)?;

    let body = decode_block_body(r.bytes(r.remaining()).map_err(BlockDecodeError::Codec)?)?;

    Ok(Block {
        header,
        txs: body.txs,
        slashings: body.slashings,
        storage_proofs: body.storage_proofs,
        bond_ops: body.bond_ops,
    })
}

/// Decode body bytes from [`encode_block_body`].
pub fn decode_block_body(bytes: &[u8]) -> Result<BlockBody, BlockDecodeError> {
    let mut r = Reader::new(bytes);

    let n_txs_raw = r.varint()?;
    let n_txs: usize = usize::try_from(n_txs_raw).map_err(|_| BlockDecodeError::CountTooLarge {
        field: "txs",
        got: n_txs_raw,
    })?;
    let mut txs: Vec<TransactionWire> = Vec::new();
    for index in 0..n_txs {
        let tx_bytes = r.blob()?;
        let mut sub = Reader::new(tx_bytes);
        let tx = read_transaction(&mut sub)
            .map_err(|source| BlockDecodeError::Transaction { index, source })?;
        if !sub.end() {
            return Err(BlockDecodeError::Transaction {
                index,
                source: TxDecodeError::TrailingBytes {
                    remaining: sub.remaining(),
                },
            });
        }
        txs.push(tx);
    }

    let n_bond_raw = r.varint()?;
    let n_bond: usize =
        usize::try_from(n_bond_raw).map_err(|_| BlockDecodeError::CountTooLarge {
            field: "bond_ops",
            got: n_bond_raw,
        })?;
    let mut bond_ops: Vec<BondOp> = Vec::new();
    for index in 0..n_bond {
        let op_bytes = r.blob()?;
        let op = decode_bond_op(op_bytes)
            .map_err(|source| BlockDecodeError::BondOp { index, source })?;
        bond_ops.push(op);
    }

    let n_slash_raw = r.varint()?;
    let n_slash: usize =
        usize::try_from(n_slash_raw).map_err(|_| BlockDecodeError::CountTooLarge {
            field: "slashings",
            got: n_slash_raw,
        })?;
    let mut slashings: Vec<SlashEvidence> = Vec::new();
    for index in 0..n_slash {
        let ev_bytes = r.blob()?;
        let ev = decode_evidence(ev_bytes)
            .map_err(|source| BlockDecodeError::Slashing { index, source })?;
        slashings.push(ev);
    }

    let n_proof_raw = r.varint()?;
    let n_proof: usize =
        usize::try_from(n_proof_raw).map_err(|_| BlockDecodeError::CountTooLarge {
            field: "storage_proofs",
            got: n_proof_raw,
        })?;
    let mut storage_proofs: Vec<StorageProof> = Vec::new();
    for index in 0..n_proof {
        let pf_bytes = r.blob()?;
        let pf = decode_storage_proof(pf_bytes)
            .map_err(|source| BlockDecodeError::StorageProof { index, source })?;
        storage_proofs.push(pf);
    }

    if !r.end() {
        return Err(BlockDecodeError::TrailingBytes {
            remaining: r.remaining(),
        });
    }

    Ok(BlockBody {
        txs,
        bond_ops,
        slashings,
        storage_proofs,
    })
}

/// Compute the on-wire length of the next header in `r`'s buffer
/// without advancing it. Lets [`decode_block`] split the input into a
/// (header || body) pair and re-use [`decode_block_header`] on the
/// header section unchanged.
///
/// Mirrors the field-by-field layout of [`block_header_bytes`].
fn peek_block_header_len(r: &Reader<'_>) -> Result<usize, BlockDecodeError> {
    let mut probe = r.clone();
    // version (varint)
    let _ = probe
        .varint()
        .map_err(|_| HeaderDecodeError::VarintOverflow { field: "version" })?;
    // prev_hash + height + slot + timestamp +
    // tx_root + storage_root + bond_root + slashing_root +
    // storage_proof_root + validator_root + claims_root.
    //                32  + 4 +  4 +  8 + 32*7 = 272 bytes total.
    let _ = probe
        .bytes(32 + 4 + 4 + 8 + 32 * 7)
        .map_err(|_| HeaderDecodeError::Truncated {
            field: "header.fixed-section",
            needed: 32 + 4 + 4 + 8 + 32 * 7,
        })?;
    // producer_proof (length-prefixed blob)
    let _ = probe.blob().map_err(|_| HeaderDecodeError::Truncated {
        field: "producer_proof",
        needed: 1,
    })?;
    // utxo_root [u8; 32]
    let _ = probe.bytes(32).map_err(|_| HeaderDecodeError::Truncated {
        field: "utxo_root",
        needed: 32,
    })?;
    Ok(r.remaining() - probe.remaining())
}

/// Merkle root over the tx ids of the block. Empty list → 32-byte zero
/// (matches the TS reference's sentinel).
pub fn tx_merkle_root(txs: &[TransactionWire]) -> [u8; 32] {
    if txs.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = txs.iter().map(tx_id).collect();
    merkle_root_or_zero(&leaves)
}

/// Merkle root over the storage commitments newly anchored in the block.
/// Returns 32 zeros if `commits` is empty.
pub fn storage_merkle_root(commits: &[StorageCommitment]) -> [u8; 32] {
    if commits.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = commits.iter().map(storage_commitment_hash).collect();
    merkle_root_or_zero(&leaves)
}
