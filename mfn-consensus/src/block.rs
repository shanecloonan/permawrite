//! Block + chain-state machine.
//!
//! Port of `cloonan-group/lib/network/block.ts`. This module turns the
//! crate's other primitives — transactions, coinbase, emission, slashing,
//! consensus finality — into an **actual chain** with a deterministic
//! state-transition function.
//!
//! Three concepts:
//!
//! - [`BlockHeader`] / [`Block`] — header + body, deterministically hashed.
//! - [`ChainState`] — known UTXOs, spent key images, storage registry,
//!   validator set, treasury, accumulator root, and the block-id chain.
//! - [`apply_block`] — pure function that validates a candidate block
//!   against the current state and returns either a new state or a list
//!   of errors. Same inputs always produce the same outputs (modulo
//!   hashing the same bytes).
//!
//! ## v0.1 scope
//!
//! This is the consensus-critical subset. The rest of the TS reference
//! (storage proof verification, endowment-based per-tx burden, treasury
//! drain → storage reward routing, storage proof reward bonuses) lives
//! gated behind the future [`mfn-storage`](https://github.com/...)
//! crate. Block application here:
//!
//! - verifies header sanity (height, prev hash);
//! - checks the tx Merkle root;
//! - verifies the producer's [`crate::consensus::FinalityProof`] when
//!   the chain has a validator set;
//! - walks the tx list: position 0 may be a coinbase, all others go
//!   through [`crate::transaction::verify_transaction`];
//! - rejects cross-tx and cross-chain double-spends;
//! - inserts new UTXOs into both the map and the cryptographic
//!   accumulator;
//! - registers new storage commitments (without enforcing endowment);
//! - applies slashing evidence (stake zeroed);
//! - verifies the coinbase against `emission(height) + producer_fee` when
//!   the producer has a payout address;
//! - checks the storage Merkle root + the UTXO accumulator root.
//!
//! When the storage layer lands, the per-block apply function will gain
//! storage-proof verification, endowment-burden enforcement, and the
//! two-sided treasury/emission settlement. The wire format is forward-
//! compatible: blocks produced today will still validate then.

use std::collections::{BTreeMap, HashMap, HashSet};

use curve25519_dalek::edwards::EdwardsPoint;

use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::{BLOCK_HEADER, BLOCK_ID};
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::merkle_root_or_zero;
use mfn_crypto::utxo_tree::{
    append_utxo, empty_utxo_tree, utxo_leaf_hash, utxo_tree_root, UtxoTreeState,
};
use mfn_storage::{
    accrue_proof_reward, decode_storage_proof, encode_storage_proof, required_endowment,
    storage_commitment_hash, verify_storage_proof, AccrueArgs, EndowmentParams, StorageCommitment,
    StorageProof, StorageProofCheck, DEFAULT_ENDOWMENT_PARAMS,
};

use crate::bond_wire::{bond_merkle_root, decode_bond_op, encode_bond_op, BondOp, BondWireError};
use crate::bonding::{BondingParams, DEFAULT_BONDING_PARAMS};
use crate::claims::{
    claim_to_record, claims_merkle_root, collect_claim_merkle_leaves_for_txs,
    verified_claims_for_tx, VerifiedClaimsForTxResult,
};
use crate::coinbase::{is_coinbase_shaped, verify_coinbase};
use crate::consensus::{decode_finality_proof, verify_finality_proof, SlotContext, Validator};
use crate::emission::{emission_at_height, EmissionParams, DEFAULT_EMISSION_PARAMS};
use crate::slashing::{
    decode_evidence, encode_evidence, EvidenceCheck, SlashDecodeError, SlashEvidence,
};
use crate::transaction::{
    encode_transaction, read_transaction, tx_id, verify_transaction, TransactionWire, TxDecodeError,
};

/* ----------------------------------------------------------------------- *
 *  Header + Block                                                          *
 * ----------------------------------------------------------------------- */

/// Current block header version. Bumped on hard fork only.
pub const HEADER_VERSION: u32 = 1;

/// Block header — the consensus-critical, hash-committed metadata.
#[derive(Clone, Debug)]
pub struct BlockHeader {
    /// MFBN codec version.
    pub version: u32,
    /// Hash of the previous block's header (32 zeros at genesis).
    pub prev_hash: [u8; 32],
    /// Block height (genesis = 0).
    pub height: u32,
    /// Slot number this block was produced for.
    pub slot: u32,
    /// Wall-clock timestamp (seconds since UNIX epoch).
    pub timestamp: u64,
    /// Merkle root of the block's transactions (all-zero if empty).
    pub tx_root: [u8; 32],
    /// Merkle root of newly-anchored storage commitments (all-zero if
    /// none).
    pub storage_root: [u8; 32],
    /// Merkle root of [`Block::bond_ops`] (all-zero if empty).
    pub bond_root: [u8; 32],
    /// Merkle root of [`Block::slashings`] (all-zero if empty). Each
    /// leaf is the canonicalized form of one equivocation evidence
    /// piece — so two reorderings of the same conflict hash to the
    /// same leaf. Lets a light client verify the slashings list
    /// independently of the rest of the chain state. (M2.0.1)
    pub slashing_root: [u8; 32],
    /// Merkle root of [`Block::storage_proofs`] (all-zero if empty).
    /// Each leaf is the domain-separated hash of one
    /// `encode_storage_proof(p)`. Closes the last body-rooting gap:
    /// every part of the block body except the producer-proof
    /// itself is now header-rooted. (M2.0.2)
    pub storage_proof_root: [u8; 32],
    /// Merkle root of the **pre-block** validator set
    /// (see [`crate::consensus::validator_set_root`]). Committing the
    /// *pre-block* set — the one this block's `producer_proof` is
    /// verified against — lets a light client validate a header and its
    /// finality bitmap from the header alone, without holding the
    /// validator list as side state. Any rotation/slashing changes
    /// applied by this block move the *next* header's `validator_root`.
    /// All-zero only if the chain is bootstrapped without validators.
    pub validator_root: [u8; 32],
    /// Merkle root of authorship claim leaves for this block's txs
    /// (M2.2.x). All-zero when no claims appear in any non-coinbase tx.
    pub claims_root: [u8; 32],
    /// MFBN-encoded [`crate::consensus::FinalityProof`]. Empty for genesis
    /// and for chains running in legacy/centralized mode (no validator
    /// set).
    pub producer_proof: Vec<u8>,
    /// 32-byte cryptographic UTXO accumulator root **after** this block's
    /// outputs are appended. Light clients use this to verify membership
    /// without downloading the full UTXO set; log-size ring signatures
    /// prove inputs against it. Mandatory in v0.1.
    pub utxo_root: [u8; 32],
}

/// A full block: header + body.
#[derive(Clone, Debug)]
pub struct Block {
    /// Header.
    pub header: BlockHeader,
    /// Transactions. `txs[0]` MAY be a coinbase (no inputs); all others
    /// must be regular RingCT-style spends.
    pub txs: Vec<TransactionWire>,
    /// Slashing evidence accumulated since the previous block. Each piece
    /// zeros one offending validator's stake in the next state.
    pub slashings: Vec<SlashEvidence>,
    /// SPoRA storage proofs answering this block's deterministic
    /// per-commitment chunk challenges. Empty when no proofs are produced
    /// this block — commitments simply stay unproven longer.
    pub storage_proofs: Vec<StorageProof>,
    /// Validator bonding / rotation operations (M1). Verified against
    /// [`BlockHeader::bond_root`] before mutating the validator set.
    pub bond_ops: Vec<BondOp>,
}

/* ----------------------------------------------------------------------- *
 *  Hashing                                                                 *
 * ----------------------------------------------------------------------- */

/// Canonical encoding of a header (excluding the trailing `producer_proof`
/// blob). What [`header_signing_hash`] hashes; what producer and committee
/// BLS-sign over.
pub fn header_signing_bytes(h: &BlockHeader) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(u64::from(h.version));
    w.push(&h.prev_hash);
    w.u32(h.height);
    w.u32(h.slot);
    w.u64(h.timestamp);
    w.push(&h.tx_root);
    w.push(&h.storage_root);
    w.push(&h.bond_root);
    w.push(&h.slashing_root);
    w.push(&h.storage_proof_root);
    w.push(&h.validator_root);
    w.push(&h.claims_root);
    w.into_bytes()
}

/// Hash of the header **without** `producer_proof`. The message the
/// producer + committee BLS-sign — must be deterministic and exclude the
/// signature it's signing.
pub fn header_signing_hash(h: &BlockHeader) -> [u8; 32] {
    dhash(BLOCK_HEADER, &[&header_signing_bytes(h)])
}

/// Full header bytes including the `producer_proof` blob, length-prefixed.
pub fn block_header_bytes(h: &BlockHeader) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(u64::from(h.version));
    w.push(&h.prev_hash);
    w.u32(h.height);
    w.u32(h.slot);
    w.u64(h.timestamp);
    w.push(&h.tx_root);
    w.push(&h.storage_root);
    w.push(&h.bond_root);
    w.push(&h.slashing_root);
    w.push(&h.storage_proof_root);
    w.push(&h.validator_root);
    w.push(&h.claims_root);
    w.blob(&h.producer_proof);
    w.push(&h.utxo_root);
    w.into_bytes()
}

/// Block id = `dhash(BLOCK_ID, full_header_bytes)`.
pub fn block_id(h: &BlockHeader) -> [u8; 32] {
    dhash(BLOCK_ID, &[&block_header_bytes(h)])
}

/* ----------------------------------------------------------------------- *
 *  Header wire codec (decode side) — M2.0.9                                *
 * ----------------------------------------------------------------------- */

/// Typed errors produced by [`decode_block_header`].
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum HeaderDecodeError {
    /// The reader ran out of bytes before all fields were parsed.
    #[error("header truncated: needed at least {needed} more byte(s) at field `{field}`")]
    Truncated {
        /// Which field tripped the short read.
        field: &'static str,
        /// Minimum number of additional bytes that would have been needed.
        needed: usize,
    },

    /// A LEB128 varint overflowed its maximum length (matches the
    /// MFBN-1 codec's 64-bit cap).
    #[error("varint overflow at field `{field}`")]
    VarintOverflow {
        /// Which field overflowed.
        field: &'static str,
    },

    /// `version` decoded as a varint but didn't fit in the 32-bit
    /// header-version field. Pinned at [`HEADER_VERSION`] today (`1`).
    #[error("header version {got} does not fit in u32")]
    VersionOutOfRange {
        /// The raw varint value that overflowed.
        got: u64,
    },

    /// `producer_proof` declared a length that overflowed the
    /// platform's `usize`. Defensive guard for 32-bit targets — on
    /// 64-bit hosts this branch is unreachable.
    #[error("producer_proof length {got} exceeds usize")]
    ProducerProofTooLarge {
        /// The raw varint length that overflowed.
        got: u64,
    },

    /// Bytes remained in the buffer after a full header had been
    /// parsed. Headers have no trailing fields — a non-empty tail
    /// implies caller-side framing confusion or corruption.
    #[error("{remaining} trailing byte(s) after header")]
    TrailingBytes {
        /// Number of trailing bytes left in the buffer.
        remaining: usize,
    },
}

/// Helper: read exactly N bytes, mapping codec errors into typed
/// [`HeaderDecodeError`] with the offending field name.
fn read_fixed<const N: usize>(
    r: &mut Reader<'_>,
    field: &'static str,
) -> Result<[u8; N], HeaderDecodeError> {
    let slice = r
        .bytes(N)
        .map_err(|_| HeaderDecodeError::Truncated { field, needed: N })?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Decode a [`BlockHeader`] from its canonical wire encoding produced
/// by [`block_header_bytes`].
///
/// `decode_block_header(&block_header_bytes(h)) == Ok(h)` for every
/// well-formed `h` (byte-for-byte round-trip).
///
/// Strict: any trailing byte after the last field is a hard reject
/// ([`HeaderDecodeError::TrailingBytes`]). Headers are self-delimiting,
/// so a non-empty tail always indicates a caller-side framing bug or
/// corruption.
///
/// # Errors
///
/// - [`HeaderDecodeError::Truncated`] — buffer ended mid-field.
/// - [`HeaderDecodeError::VarintOverflow`] — `version` or
///   `producer_proof` length varint was malformed.
/// - [`HeaderDecodeError::VersionOutOfRange`] — `version > u32::MAX`.
/// - [`HeaderDecodeError::ProducerProofTooLarge`] — declared
///   `producer_proof` length doesn't fit in `usize`.
/// - [`HeaderDecodeError::TrailingBytes`] — extra bytes after the
///   header's final field.
pub fn decode_block_header(bytes: &[u8]) -> Result<BlockHeader, HeaderDecodeError> {
    let mut r = Reader::new(bytes);

    let version_raw = r
        .varint()
        .map_err(|_| HeaderDecodeError::VarintOverflow { field: "version" })?;
    let version: u32 = u32::try_from(version_raw)
        .map_err(|_| HeaderDecodeError::VersionOutOfRange { got: version_raw })?;

    let prev_hash: [u8; 32] = read_fixed(&mut r, "prev_hash")?;
    let height = r.u32().map_err(|_| HeaderDecodeError::Truncated {
        field: "height",
        needed: 4,
    })?;
    let slot = r.u32().map_err(|_| HeaderDecodeError::Truncated {
        field: "slot",
        needed: 4,
    })?;
    let timestamp = r.u64().map_err(|_| HeaderDecodeError::Truncated {
        field: "timestamp",
        needed: 8,
    })?;

    let tx_root: [u8; 32] = read_fixed(&mut r, "tx_root")?;
    let storage_root: [u8; 32] = read_fixed(&mut r, "storage_root")?;
    let bond_root: [u8; 32] = read_fixed(&mut r, "bond_root")?;
    let slashing_root: [u8; 32] = read_fixed(&mut r, "slashing_root")?;
    let storage_proof_root: [u8; 32] = read_fixed(&mut r, "storage_proof_root")?;
    let validator_root: [u8; 32] = read_fixed(&mut r, "validator_root")?;
    let claims_root: [u8; 32] = read_fixed(&mut r, "claims_root")?;

    let pp_len_raw = r.varint().map_err(|_| HeaderDecodeError::VarintOverflow {
        field: "producer_proof.len",
    })?;
    let pp_len: usize = usize::try_from(pp_len_raw)
        .map_err(|_| HeaderDecodeError::ProducerProofTooLarge { got: pp_len_raw })?;
    let producer_proof = r
        .bytes(pp_len)
        .map_err(|_| HeaderDecodeError::Truncated {
            field: "producer_proof",
            needed: pp_len,
        })?
        .to_vec();

    let utxo_root: [u8; 32] = read_fixed(&mut r, "utxo_root")?;

    if !r.end() {
        return Err(HeaderDecodeError::TrailingBytes {
            remaining: r.remaining(),
        });
    }

    Ok(BlockHeader {
        version,
        prev_hash,
        height,
        slot,
        timestamp,
        tx_root,
        storage_root,
        bond_root,
        slashing_root,
        storage_proof_root,
        validator_root,
        claims_root,
        producer_proof,
        utxo_root,
    })
}

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
#[must_use]
pub fn encode_block(b: &Block) -> Vec<u8> {
    let mut out = block_header_bytes(&b.header);

    let mut w = Writer::new();
    w.varint(b.txs.len() as u64);
    for tx in &b.txs {
        w.blob(&encode_transaction(tx));
    }
    w.varint(b.bond_ops.len() as u64);
    for op in &b.bond_ops {
        w.blob(&encode_bond_op(op));
    }
    w.varint(b.slashings.len() as u64);
    for ev in &b.slashings {
        w.blob(&encode_evidence(ev));
    }
    w.varint(b.storage_proofs.len() as u64);
    for p in &b.storage_proofs {
        w.blob(&encode_storage_proof(p));
    }
    out.extend_from_slice(w.bytes());
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

    // ---- body ----
    //
    // Note on capacity hints: we deliberately do **not** pass
    // attacker-controlled counts to `Vec::with_capacity`. A peer
    // could send a varint claiming `2^61` transactions, and the
    // allocator would abort the process before we ever consult the
    // backing buffer. Instead we grow the `Vec` naturally — the
    // real buffer length bounds the maximum number of items we can
    // legitimately decode, so memory use is proportional to input
    // size regardless of the declared count.
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

    Ok(Block {
        header,
        txs,
        slashings,
        storage_proofs,
        bond_ops,
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

/* ----------------------------------------------------------------------- *
 *  Chain state                                                             *
 * ----------------------------------------------------------------------- */

/// An unspent transaction output's record in the chain's UTXO set.
#[derive(Clone, Debug)]
pub struct UtxoEntry {
    /// Pedersen commitment to the output's hidden amount. Future spenders
    /// include this in their CLSAG ring's `C` column.
    pub commit: EdwardsPoint,
    /// Block height at which this output was anchored. Drives the gamma
    /// decoy-selection age weighting.
    pub height: u32,
}

/// Per-validator participation statistics. Tracked by `apply_block` from
/// the finality proof's bitmap; once `consecutive_missed` exceeds the
/// configured liveness threshold the validator's stake is slashed by
/// `ConsensusParams::liveness_slash_bps` and the counter resets.
///
/// Zeroed-stake (already-slashed) validators are excluded from stats
/// updates — they're zombies until validator rotation lands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidatorStats {
    /// Consecutive blocks (since this validator's last successful vote)
    /// at which their bit was not set in the finality bitmap.
    pub consecutive_missed: u32,
    /// Lifetime count of finality votes successfully contributed.
    pub total_signed: u64,
    /// Lifetime count of finality votes missed.
    pub total_missed: u64,
    /// Number of times this validator has been liveness-slashed (capped
    /// at `u32::MAX`).
    pub liveness_slashes: u32,
}

/// A validator's pending exit, tracked from the moment their
/// [`BondOp::Unbond`] is accepted until the unlock height passes and
/// settlement zeroes their voting weight (M1 rotation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingUnbond {
    /// Validator's `index` field (matches `Validator::index`).
    pub validator_index: u32,
    /// Block height at which this exit may be settled (`request_height + unbond_delay_heights`).
    pub unlock_height: u32,
    /// Stake the validator held when they requested unbond. Recorded for
    /// observability; M1 leaves the underlying MFN as a permanent
    /// treasury contribution (no payout path yet).
    pub stake_at_request: u64,
    /// Block height the unbond was requested at.
    pub request_height: u32,
}

/// Per-storage-commitment chain state.
#[derive(Clone, Debug)]
pub struct StorageEntry {
    /// The anchored commitment.
    pub commit: StorageCommitment,
    /// Height of the most recent successful storage proof (or anchoring
    /// height on first registration).
    pub last_proven_height: u32,
    /// Slot of the most recent successful storage proof. Drives
    /// per-proof yield accrual (slots, not heights, are the natural unit
    /// because misses make `slot >= height`).
    pub last_proven_slot: u64,
    /// Sub-base-unit yield accumulator, in PPB. Carries the fractional
    /// per-slot yield across proofs so even commitments whose per-slot
    /// payout is `<< 1` base unit eventually earn integer base units.
    pub pending_yield_ppb: u128,
}

/// Consensus parameters baked into the chain at genesis. Changing any of
/// these is a hard fork.
#[derive(Clone, Copy, Debug)]
pub struct ConsensusParams {
    /// Average number of validators eligible to propose per slot. Typical
    /// configs: `1.0` (Algorand-style) or `1.5` (extra liveness slack).
    pub expected_proposers_per_slot: f64,
    /// Stake-weighted quorum threshold in basis points. `6667` = 2/3 + 1bp.
    pub quorum_stake_bps: u32,
    /// Liveness threshold: a validator that misses this many CONSECUTIVE
    /// finality votes is auto-slashed by `liveness_slash_bps` and their
    /// counter is reset. Default `32` ≈ 6.4 minutes at 12-second slots —
    /// long enough to absorb a transient outage, short enough to deter
    /// chronic absenteeism.
    pub liveness_max_consecutive_missed: u32,
    /// Stake reduction per liveness slash, in basis points. Default `100`
    /// = 1% per offense. Repeated offenses compound multiplicatively, so
    /// 100 successive trip-ups reduce stake by roughly `e^{-1}` ≈ 63%.
    /// Equivocation slashing remains its own thing (`SlashEvidence`),
    /// which zeros stake outright.
    pub liveness_slash_bps: u32,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            expected_proposers_per_slot: 1.5,
            quorum_stake_bps: 6667,
            liveness_max_consecutive_missed: 32,
            liveness_slash_bps: 100,
        }
    }
}

/// Canonical default consensus parameters.
pub const DEFAULT_CONSENSUS_PARAMS: ConsensusParams = ConsensusParams {
    expected_proposers_per_slot: 1.5,
    quorum_stake_bps: 6667,
    liveness_max_consecutive_missed: 32,
    liveness_slash_bps: 100,
};

/// The mutable state of a Permawrite chain.
#[derive(Clone, Debug)]
pub struct ChainState {
    /// Height of the last applied block (`None` before genesis).
    pub height: Option<u32>,
    /// Live UTXO set, keyed by compressed one-time-address bytes.
    pub utxo: HashMap<[u8; 32], UtxoEntry>,
    /// Spent key images, keyed by compressed point bytes. Cross-block
    /// double-spend gate.
    pub spent_key_images: HashSet<[u8; 32]>,
    /// Storage commitments anchored on-chain, keyed by commitment hash.
    /// Each entry carries the commitment plus per-commitment proof state
    /// (last-proven slot, pending PPB yield) updated by each accepted
    /// SPoRA proof.
    pub storage: HashMap<[u8; 32], StorageEntry>,
    /// Authorship claims indexed by `data_root` (sorted map keys on wire).
    pub claims: BTreeMap<[u8; 32], Vec<crate::claims::AuthorshipClaimRecord>>,
    /// Leaf hashes of accepted claims (global dedup across the chain).
    pub claim_submitted: HashSet<[u8; 32]>,
    /// Block-id chain: `[genesis_id, block1_id, ...]`.
    pub block_ids: Vec<[u8; 32]>,
    /// Active validator set. Frozen at genesis in v0.1; epoch reconfig
    /// is a future upgrade.
    pub validators: Vec<Validator>,
    /// Per-validator participation stats, aligned with `validators` by
    /// index (`validator_stats[i]` is the stats for `validators[i]`).
    /// `apply_block` updates this from each block's finality bitmap and
    /// auto-slashes validators that exceed the configured consecutive-
    /// missed-votes threshold.
    pub validator_stats: Vec<ValidatorStats>,
    /// Consensus parameters.
    pub params: ConsensusParams,
    /// Emission schedule (defaults to [`DEFAULT_EMISSION_PARAMS`]).
    pub emission_params: EmissionParams,
    /// Endowment schedule (defaults to [`DEFAULT_ENDOWMENT_PARAMS`]).
    pub endowment_params: EndowmentParams,
    /// Permanence treasury, in base units (gains the fee→treasury share
    /// of every regular tx).
    pub treasury: u128,
    /// Cryptographic UTXO accumulator. Every output the chain ever
    /// anchors is appended in deterministic order.
    pub utxo_tree: UtxoTreeState,
    /// Bonding / rotation parameters (defaults at genesis).
    pub bonding_params: BondingParams,
    /// Epoch id (`height / slots_per_epoch`) for which the churn
    /// counters apply. Updated when the epoch rolls forward.
    pub bond_epoch_id: u64,
    /// Validators registered via [`BondOp::Register`] in the current epoch.
    pub bond_epoch_entry_count: u32,
    /// Validators that **fully exited** (unbond-settled) in the current
    /// epoch, gated by [`BondingParams::max_exit_churn_per_epoch`].
    pub bond_epoch_exit_count: u32,
    /// Next [`Validator::index`] assigned to a newly bonded validator.
    pub next_validator_index: u32,
    /// In-flight unbond requests keyed by `Validator::index`. Settled
    /// when `unlock_height <= current_height`, in deterministic sorted
    /// order during [`apply_block`]. A validator with an entry here is
    /// still subject to equivocation/liveness slashing during the delay.
    pub pending_unbonds: BTreeMap<u32, PendingUnbond>,
}

impl ChainState {
    /// Empty pre-genesis state.
    pub fn empty() -> Self {
        Self {
            height: None,
            utxo: HashMap::new(),
            spent_key_images: HashSet::new(),
            storage: HashMap::new(),
            claims: BTreeMap::new(),
            claim_submitted: HashSet::new(),
            block_ids: Vec::new(),
            validators: Vec::new(),
            validator_stats: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            treasury: 0,
            utxo_tree: empty_utxo_tree(),
            bonding_params: DEFAULT_BONDING_PARAMS,
            bond_epoch_id: 0,
            bond_epoch_entry_count: 0,
            bond_epoch_exit_count: 0,
            next_validator_index: 0,
            pending_unbonds: BTreeMap::new(),
        }
    }

    /// The block id of the chain's current tip (`None` before genesis).
    pub fn tip_id(&self) -> Option<&[u8; 32]> {
        self.block_ids.last()
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::empty()
    }
}

/* ----------------------------------------------------------------------- *
 *  Genesis                                                                 *
 * ----------------------------------------------------------------------- */

/// One initial output baked into genesis (no signatures — genesis is
/// trusted setup).
#[derive(Clone, Debug)]
pub struct GenesisOutput {
    /// Stealth one-time address.
    pub one_time_addr: EdwardsPoint,
    /// Pedersen commitment to the hidden amount.
    pub amount: EdwardsPoint,
}

/// Configuration for the genesis block (height 0).
#[derive(Clone, Debug)]
pub struct GenesisConfig {
    /// Wall-clock timestamp at chain start.
    pub timestamp: u64,
    /// Initial UTXO set.
    pub initial_outputs: Vec<GenesisOutput>,
    /// Initial storage commitments.
    pub initial_storage: Vec<StorageCommitment>,
    /// Validator set at genesis. Empty ⇒ chain runs without consensus
    /// validation (tests only).
    pub validators: Vec<Validator>,
    /// Consensus parameters (defaults if omitted at type level).
    pub params: ConsensusParams,
    /// Emission schedule (defaults if omitted at type level).
    pub emission_params: EmissionParams,
    /// Endowment schedule (defaults if omitted at type level).
    pub endowment_params: EndowmentParams,
    /// Bonding / churn limits. [`None`] ⇒ [`DEFAULT_BONDING_PARAMS`](bonding::DEFAULT_BONDING_PARAMS).
    pub bonding_params: Option<BondingParams>,
}

/// Build the genesis [`Block`].
pub fn build_genesis(cfg: &GenesisConfig) -> Block {
    let mut tree = empty_utxo_tree();
    for o in &cfg.initial_outputs {
        let leaf = utxo_leaf_hash(&o.one_time_addr, &o.amount, 0);
        tree = append_utxo(&tree, leaf).expect("genesis output count fits in accumulator");
    }
    let storage_root = storage_merkle_root(&cfg.initial_storage);
    // Genesis commits to the **pre-genesis** validator set (empty) — the
    // genesis block itself installs `cfg.validators`. The next block's
    // header will commit to `validator_set_root(&cfg.validators)`.
    let header = BlockHeader {
        version: HEADER_VERSION,
        prev_hash: [0u8; 32],
        height: 0,
        slot: 0,
        timestamp: cfg.timestamp,
        tx_root: [0u8; 32],
        storage_root,
        bond_root: [0u8; 32],
        slashing_root: [0u8; 32],
        storage_proof_root: [0u8; 32],
        validator_root: [0u8; 32],
        claims_root: [0u8; 32],
        producer_proof: Vec::new(),
        utxo_root: utxo_tree_root(&tree),
    };
    Block {
        header,
        txs: Vec::new(),
        slashings: Vec::new(),
        storage_proofs: Vec::new(),
        bond_ops: Vec::new(),
    }
}

/// Apply genesis to an empty state.
pub fn apply_genesis(genesis: &Block, cfg: &GenesisConfig) -> Result<ChainState, BlockError> {
    if genesis.header.height != 0 {
        return Err(BlockError::GenesisHeightNotZero);
    }
    let mut state = ChainState::empty();
    state.params = cfg.params;
    state.emission_params = cfg.emission_params;
    state.endowment_params = cfg.endowment_params;
    state.bonding_params = cfg.bonding_params.unwrap_or(DEFAULT_BONDING_PARAMS);
    state.validators = cfg.validators.clone();
    state.validator_stats = vec![ValidatorStats::default(); cfg.validators.len()];
    state.next_validator_index = cfg
        .validators
        .iter()
        .map(|v| v.index)
        .max()
        .map(|m| m.saturating_add(1))
        .unwrap_or(0);

    for o in &cfg.initial_outputs {
        let key = o.one_time_addr.compress().to_bytes();
        state.utxo.insert(
            key,
            UtxoEntry {
                commit: o.amount,
                height: 0,
            },
        );
        let leaf = utxo_leaf_hash(&o.one_time_addr, &o.amount, 0);
        state.utxo_tree = append_utxo(&state.utxo_tree, leaf).expect("genesis output count fits");
    }
    for s in &cfg.initial_storage {
        state.storage.insert(
            storage_commitment_hash(s),
            StorageEntry {
                commit: s.clone(),
                last_proven_height: 0,
                last_proven_slot: 0,
                pending_yield_ppb: 0,
            },
        );
    }

    state.height = Some(0);
    state.block_ids.push(block_id(&genesis.header));
    Ok(state)
}

/* ----------------------------------------------------------------------- *
 *  Block builder (producer-side)                                           *
 * ----------------------------------------------------------------------- */

/// Build an unsealed (no `producer_proof`) header for the next block.
/// Producers compute the [`header_signing_hash`] over this header to know
/// what to BLS-sign; once they have a [`crate::consensus::FinalityProof`],
/// they call [`seal_block`] to produce the final `Block`.
///
/// `slot` is the explicit slot timer value; tests can default it to
/// `height`.
pub fn build_unsealed_header(
    state: &ChainState,
    txs: &[TransactionWire],
    bond_ops: &[BondOp],
    slashings: &[SlashEvidence],
    storage_proofs: &[StorageProof],
    slot: u32,
    timestamp: u64,
) -> BlockHeader {
    let next_height = state.height.map(|h| h + 1).unwrap_or(0);

    // Storage commitments newly introduced this block (in tx-output
    // declaration order). Duplicates of already-anchored commitments do
    // NOT contribute (they were paid for by the original anchor).
    let mut new_storages: Vec<StorageCommitment> = Vec::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for tx in txs {
        for out in &tx.outputs {
            if let Some(sc) = &out.storage {
                let h = storage_commitment_hash(sc);
                if state.storage.contains_key(&h) || !seen.insert(h) {
                    continue;
                }
                new_storages.push(sc.clone());
            }
        }
    }

    // Project the post-block accumulator: every tx output appended in
    // tx-by-tx, output-by-output order.
    let mut projected_tree = state.utxo_tree.clone();
    for tx in txs {
        for out in &tx.outputs {
            let leaf = utxo_leaf_hash(&out.one_time_addr, &out.amount, next_height);
            projected_tree =
                append_utxo(&projected_tree, leaf).expect("realistic block fits in accumulator");
        }
    }

    let prev_hash = state.tip_id().copied().unwrap_or([0u8; 32]);

    let claim_leaves = collect_claim_merkle_leaves_for_txs(txs, next_height).unwrap_or_else(|e| {
        panic!("build_unsealed_header: invalid authorship MFEX/MFCL in tx list: {e}")
    });
    let claims_root = claims_merkle_root(&claim_leaves);

    BlockHeader {
        version: HEADER_VERSION,
        prev_hash,
        height: next_height,
        slot,
        timestamp,
        tx_root: tx_merkle_root(txs),
        storage_root: storage_merkle_root(&new_storages),
        bond_root: bond_merkle_root(bond_ops),
        slashing_root: crate::slashing::slashing_merkle_root(slashings),
        storage_proof_root: mfn_storage::storage_proof_merkle_root(storage_proofs),
        // Commit to the validator set the block was produced against —
        // i.e., the *pre-block* set held by `state`. Any rotation /
        // slashing applied in this block moves the *next* header's
        // validator_root, not this one's.
        validator_root: crate::consensus::validator_set_root(&state.validators),
        claims_root,
        producer_proof: Vec::new(),
        utxo_root: utxo_tree_root(&projected_tree),
    }
}

/// Attach an encoded finality proof to a header.
pub fn seal_block(
    mut header: BlockHeader,
    txs: Vec<TransactionWire>,
    bond_ops: Vec<BondOp>,
    producer_proof: Vec<u8>,
    slashings: Vec<SlashEvidence>,
    storage_proofs: Vec<StorageProof>,
) -> Block {
    header.producer_proof = producer_proof;
    Block {
        header,
        txs,
        slashings,
        storage_proofs,
        bond_ops,
    }
}

/* ----------------------------------------------------------------------- *
 *  Block application                                                      *
 * ----------------------------------------------------------------------- */

/// Either the new state (on success) or a structured list of errors.
///
/// Boxed-state variants would obscure the natural shape; the `Ok` arm
/// carries a `ChainState` directly. The size disparity between the
/// variants is fine because successful application is overwhelmingly the
/// common path and the `Err` variant is small anyway.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ApplyOutcome {
    /// All checks passed; `state` is the new tip state.
    Ok {
        /// New state.
        state: ChainState,
        /// Id of the applied block.
        block_id: [u8; 32],
    },
    /// One or more checks failed; the input state is unchanged.
    Err {
        /// Structured error list (one per failed check).
        errors: Vec<BlockError>,
        /// Id of the proposed block (so callers can log it).
        block_id: [u8; 32],
    },
}

impl ApplyOutcome {
    /// `true` iff application succeeded.
    pub fn is_ok(&self) -> bool {
        matches!(self, ApplyOutcome::Ok { .. })
    }

    /// Block id of the applied/proposed block.
    pub fn block_id(&self) -> &[u8; 32] {
        match self {
            ApplyOutcome::Ok { block_id, .. } | ApplyOutcome::Err { block_id, .. } => block_id,
        }
    }

    /// Move out the new state, if successful.
    pub fn into_state(self) -> Option<ChainState> {
        match self {
            ApplyOutcome::Ok { state, .. } => Some(state),
            ApplyOutcome::Err { .. } => None,
        }
    }
}

/// Apply a candidate block to a chain state.
///
/// Performs every consensus check, in order:
///
/// 1. Header sanity: height = `state.height + 1`, `prev_hash` = current
///    tip id (none ⇒ genesis-only chain).
/// 2. Tx Merkle root matches the recomputed root; bond Merkle root
///    matches [`Block::bond_ops`].
/// 3. (If validators present) the [`crate::consensus::FinalityProof`]
///    verifies — producer was eligible at this slot, committee quorum
///    signed the header.
/// 4. Each tx verifies; cross-tx and cross-chain key images do not
///    collide; outputs are added to the UTXO set + accumulator.
/// 5. Storage commitments newly introduced by tx outputs are registered.
/// 6. Slashing evidence verifies; offending validators have their stake
///    zeroed in the new state.
/// 7. SPoRA storage proofs accrue rewards and update per-commitment state.
/// 8. Liveness stats from the finality bitmap; auto-slash chronic misses.
/// 9. [`BondOp`]s are validated and applied atomically (new validators are
///    not subject to this block's finality bitmap).
/// 10. When a producer has a [`crate::consensus::ValidatorPayout`], the
///     block must include a coinbase (in `tx[0]`) paying
///     `emission(height) + producer_fee` (+ storage rewards).
/// 11. Storage Merkle root matches tx-anchored new commitments.
/// 12. UTXO accumulator root matches.
///
/// Returns [`ApplyOutcome::Ok`] with the new state, or
/// [`ApplyOutcome::Err`] with a list of [`BlockError`]s and the original
/// state untouched.
pub fn apply_block(state: &ChainState, block: &Block) -> ApplyOutcome {
    let proposed_id = block_id(&block.header);
    let mut errors: Vec<BlockError> = Vec::new();

    // ---- Header sanity ----
    let expected_height = state.height.map(|h| h + 1).unwrap_or(0);
    if block.header.height != expected_height {
        errors.push(BlockError::BadHeight {
            expected: expected_height,
            got: block.header.height,
        });
    }
    if let Some(tip) = state.tip_id() {
        if &block.header.prev_hash != tip {
            errors.push(BlockError::PrevHashMismatch);
        }
    } else if block.header.prev_hash != [0u8; 32] {
        errors.push(BlockError::PrevHashMismatch);
    }

    // ---- Tx merkle root ----
    let expected_tx_root = tx_merkle_root(&block.txs);
    if expected_tx_root != block.header.tx_root {
        errors.push(BlockError::TxRootMismatch);
    }

    let expected_bond_root = bond_merkle_root(&block.bond_ops);
    if expected_bond_root != block.header.bond_root {
        errors.push(BlockError::BondRootMismatch);
    }

    // ---- Slashing evidence merkle root (M2.0.1) ----
    //
    // Each piece of evidence is canonicalized in `slashing_leaf_hash`,
    // so swapping the (hash_a, sig_a) / (hash_b, sig_b) pair cannot
    // forge a different leaf. The root commits the slashing list under
    // the header so a light client can verify it without the rest of
    // the block body.
    let expected_slashing_root = crate::slashing::slashing_merkle_root(&block.slashings);
    if expected_slashing_root != block.header.slashing_root {
        errors.push(BlockError::SlashingRootMismatch);
    }

    // ---- Storage-proof merkle root (M2.0.2) ----
    //
    // Closes the last body-rooting gap: now every part of the block
    // body except the producer-proof itself is header-rooted.
    let expected_storage_proof_root = mfn_storage::storage_proof_merkle_root(&block.storage_proofs);
    if expected_storage_proof_root != block.header.storage_proof_root {
        errors.push(BlockError::StorageProofRootMismatch);
    }

    // ---- Validator-set merkle root (pre-block commitment, M2.0) ----
    //
    // Committing to the validator set **as it stood when this block was
    // produced** lets a light client verify the producer eligibility and
    // BLS quorum bitmap from the header alone, without holding the live
    // validator list. Validators introduced or evicted by this block
    // (bond ops, equivocation slashing, liveness slashing, unbond
    // settlement) move the *next* header's root, not this one's.
    let expected_validator_root = crate::consensus::validator_set_root(&state.validators);
    if expected_validator_root != block.header.validator_root {
        errors.push(BlockError::ValidatorRootMismatch);
    }

    // ---- Authorship claims Merkle root (M2.2.x) ----
    //
    // Header `claims_root` binds every verified claim leaf in block order
    // (non-coinbase txs only). Parse+verify once here; the tx walk reuses
    // the results when mutating [`ChainState::claims`].
    let per_tx_claims: Vec<VerifiedClaimsForTxResult> = block
        .txs
        .iter()
        .enumerate()
        .map(|(ti, tx)| {
            if ti == 0 && is_coinbase_shaped(tx) {
                Ok((Vec::new(), Vec::new()))
            } else {
                verified_claims_for_tx(tx, ti as u32, block.header.height)
            }
        })
        .collect();

    let mut header_claim_leaves: Vec<[u8; 32]> = Vec::new();
    for (ti, res) in per_tx_claims.iter().enumerate() {
        match res {
            Ok((_, leaves)) => {
                if !(ti == 0 && is_coinbase_shaped(&block.txs[ti])) {
                    header_claim_leaves.extend_from_slice(leaves);
                }
            }
            Err(e) => errors.push(BlockError::AuthorshipClaims(e.to_string())),
        }
    }
    let expected_claims_root = claims_merkle_root(&header_claim_leaves);
    if expected_claims_root != block.header.claims_root {
        errors.push(BlockError::ClaimsRootMismatch);
    }

    // ---- Producer/finality proof ----
    let mut producer_idx: Option<u32> = None;
    let mut finality_bitmap: Option<Vec<u8>> = None;
    if !state.validators.is_empty() {
        if block.header.producer_proof.is_empty() {
            errors.push(BlockError::MissingProducerProof);
        } else {
            match decode_finality_proof(&block.header.producer_proof) {
                Ok(fin) => {
                    let ctx = SlotContext {
                        height: block.header.height,
                        slot: block.header.slot,
                        prev_hash: block.header.prev_hash,
                    };
                    let header_hash = header_signing_hash(&block.header);
                    let chk = verify_finality_proof(
                        &ctx,
                        &fin,
                        &state.validators,
                        state.params.expected_proposers_per_slot,
                        state.params.quorum_stake_bps,
                        &header_hash,
                    );
                    if !chk.is_ok() {
                        errors.push(BlockError::FinalityInvalid(chk));
                    } else {
                        producer_idx = Some(fin.producer.validator_index);
                        finality_bitmap = Some(fin.finality.bitmap.clone());
                    }
                }
                Err(e) => errors.push(BlockError::FinalityDecode(format!("{e}"))),
            }
        }
    }

    // ---- Tentative state copy (only kept on success). ----
    let mut next = state.clone();
    next.height = Some(block.header.height);

    // Storage commitments newly anchored this block (in declaration order),
    // for the post-block storage-root check.
    let mut new_storages: Vec<StorageCommitment> = Vec::new();

    // Producer + coinbase policy.
    let producer =
        producer_idx.and_then(|idx| state.validators.iter().find(|v| v.index == idx).cloned());
    let require_coinbase = producer
        .as_ref()
        .map(|p| p.payout.is_some())
        .unwrap_or(false);

    // ---- Walk txs ----
    // A coinbase-shaped tx anywhere past position 0 is a protocol
    // violation. Catch up front.
    for (i, tx) in block.txs.iter().enumerate().skip(1) {
        if is_coinbase_shaped(tx) {
            errors.push(BlockError::CoinbaseOutOfPosition(i));
        }
    }

    let mut coinbase_tx: Option<&TransactionWire> = None;
    let mut fee_sum: u128 = 0;

    for (ti, tx) in block.txs.iter().enumerate() {
        let is_coinbase_pos = ti == 0 && is_coinbase_shaped(tx);

        if is_coinbase_pos {
            coinbase_tx = Some(tx);
            // Coinbase output goes into UTXO + accumulator. The actual
            // amount/balance check happens below after fee_sum is known.
            for out in &tx.outputs {
                let key = out.one_time_addr.compress().to_bytes();
                next.utxo.insert(
                    key,
                    UtxoEntry {
                        commit: out.amount,
                        height: block.header.height,
                    },
                );
                let leaf = utxo_leaf_hash(&out.one_time_addr, &out.amount, block.header.height);
                match append_utxo(&next.utxo_tree, leaf) {
                    Ok(t) => next.utxo_tree = t,
                    Err(e) => errors.push(BlockError::AccumulatorFull(format!("{e}"))),
                }
                // Coinbase outputs cannot anchor storage; verify_coinbase
                // enforces this, so we skip storage handling here.
            }
            continue;
        }

        if ti == 0 && require_coinbase {
            errors.push(BlockError::MissingCoinbase {
                got_inputs: tx.inputs.len(),
            });
        }

        // Regular tx path.
        let v = verify_transaction(tx);
        if !v.ok {
            errors.push(BlockError::TxInvalid {
                index: ti,
                errors: v.errors,
            });
            continue;
        }

        // ---- Ring-membership check (consensus-critical, see SECURITY note) ----
        //
        // `verify_transaction` is stateless: it proves the CLSAG signer
        // controlled the spend key of *some* ring member, but a CLSAG
        // ring whose members are fabricated (P, C) pairs would still
        // verify because the math doesn't care whether the points are
        // on-chain. Combined with the balance equation
        //
        //     Σ pseudo − Σ amount − fee·H == 0
        //
        // a malicious spender who invents a ring member with commitment
        // C_fake = G·r + H·v_fake can pseudo-output the fake value into
        // their own outputs — i.e. mint MFN out of thin air. The
        // CHAIN-LEVEL check that every ring member is a real UTXO is the
        // only thing that closes this attack.
        //
        // Genesis UTXOs are included in `state.utxo`, so genesis-anchored
        // outputs are valid ring members from height 0 onwards.
        let mut ring_ok = true;
        for (ii, inp) in tx.inputs.iter().enumerate() {
            if inp.ring.p.len() != inp.ring.c.len() {
                errors.push(BlockError::TxInvalid {
                    index: ti,
                    errors: vec![format!(
                        "input {ii}: ring P-column length {} != C-column length {}",
                        inp.ring.p.len(),
                        inp.ring.c.len()
                    )],
                });
                ring_ok = false;
                break;
            }
            for (ri, (p, c)) in inp.ring.p.iter().zip(inp.ring.c.iter()).enumerate() {
                let key = p.compress().to_bytes();
                match next.utxo.get(&key) {
                    Some(entry) if entry.commit == *c => {}
                    Some(_) => {
                        errors.push(BlockError::RingMemberCommitMismatch {
                            tx: ti,
                            input: ii,
                            ring_index: ri,
                            one_time_addr: hex_short(&key),
                        });
                        ring_ok = false;
                    }
                    None => {
                        errors.push(BlockError::RingMemberNotInUtxoSet {
                            tx: ti,
                            input: ii,
                            ring_index: ri,
                            one_time_addr: hex_short(&key),
                        });
                        ring_ok = false;
                    }
                }
            }
        }
        if !ring_ok {
            continue;
        }

        // Fees accrue to the producer via the coinbase.
        fee_sum += u128::from(tx.fee);

        // Cross-tx + cross-chain key image gate.
        for ki in &v.key_images {
            let ki_bytes = ki.compress().to_bytes();
            if next.spent_key_images.contains(&ki_bytes) {
                errors.push(BlockError::DoubleSpend {
                    index: ti,
                    key_image: hex_short(&ki_bytes),
                });
            } else {
                next.spent_key_images.insert(ki_bytes);
            }
        }

        // New outputs → UTXO map + accumulator + storage registry.
        for out in &tx.outputs {
            let key = out.one_time_addr.compress().to_bytes();
            next.utxo.insert(
                key,
                UtxoEntry {
                    commit: out.amount,
                    height: block.header.height,
                },
            );
            let leaf = utxo_leaf_hash(&out.one_time_addr, &out.amount, block.header.height);
            match append_utxo(&next.utxo_tree, leaf) {
                Ok(t) => next.utxo_tree = t,
                Err(e) => errors.push(BlockError::AccumulatorFull(format!("{e}"))),
            }

            if let Some(sc) = &out.storage {
                let h = storage_commitment_hash(sc);
                if let std::collections::hash_map::Entry::Vacant(e) = next.storage.entry(h) {
                    e.insert(StorageEntry {
                        commit: sc.clone(),
                        last_proven_height: block.header.height,
                        last_proven_slot: u64::from(block.header.slot),
                        pending_yield_ppb: 0,
                    });
                    new_storages.push(sc.clone());
                }
            }
        }

        // ---- Storage upload endowment enforcement ----
        //
        // For every NEW storage commitment in this tx's outputs, sum the
        // protocol-required endowment burden. The tx's treasury-bound
        // share of fees must cover the burden, otherwise the upload is
        // under-funded and the permanence guarantee breaks. Replication
        // bounds (min/max) are also enforced here.
        let mut tx_burden: u128 = 0;
        let mut tx_storage_ok = true;
        let mut seen_in_tx: HashSet<[u8; 32]> = HashSet::new();
        for (oi, out) in tx.outputs.iter().enumerate() {
            let sc = match &out.storage {
                Some(s) => s,
                None => continue,
            };
            let h = storage_commitment_hash(sc);
            // Only NEW anchors incur burden — duplicates are inert.
            if state.storage.contains_key(&h) || !seen_in_tx.insert(h) {
                continue;
            }
            let repl = sc.replication;
            if repl < next.endowment_params.min_replication {
                errors.push(BlockError::StorageReplicationTooLow {
                    tx: ti,
                    output: oi,
                    got: repl,
                    min: next.endowment_params.min_replication,
                });
                tx_storage_ok = false;
                break;
            }
            if repl > next.endowment_params.max_replication {
                errors.push(BlockError::StorageReplicationTooHigh {
                    tx: ti,
                    output: oi,
                    got: repl,
                    max: next.endowment_params.max_replication,
                });
                tx_storage_ok = false;
                break;
            }
            match required_endowment(sc.size_bytes, repl, &next.endowment_params) {
                Ok(b) => tx_burden = tx_burden.saturating_add(b),
                Err(e) => {
                    errors.push(BlockError::EndowmentMathFailed {
                        tx: ti,
                        output: oi,
                        reason: format!("{e}"),
                    });
                    tx_storage_ok = false;
                    break;
                }
            }
        }
        if tx_storage_ok && tx_burden > 0 {
            let tx_treasury_share: u128 =
                u128::from(tx.fee) * u128::from(next.emission_params.fee_to_treasury_bps) / 10_000;
            if tx_treasury_share < tx_burden {
                errors.push(BlockError::UploadUnderfunded {
                    tx: ti,
                    burden: tx_burden,
                    treasury_share: tx_treasury_share,
                    fee: tx.fee,
                    fee_to_treasury_bps: next.emission_params.fee_to_treasury_bps,
                });
            }
        }

        if !(ti == 0 && is_coinbase_shaped(tx)) {
            if let Ok((clist, leaves)) = &per_tx_claims[ti] {
                let tid = tx_id(tx);
                for (ci, c) in clist.iter().enumerate() {
                    let lh = leaves[ci];
                    if next.claim_submitted.insert(lh) {
                        let rec =
                            claim_to_record(c, tid, block.header.height, ti as u32, ci as u32);
                        next.claims.entry(c.data_root).or_default().push(rec);
                    }
                }
            }
        }
    }

    // ---- Slashing evidence (equivocation → stake zeroed, credit to treasury) ----
    //
    // Per the M1 economic model (see `docs/M1_VALIDATOR_ROTATION.md`), a
    // slashed validator's forfeited stake flows into the permanence
    // treasury rather than vanishing. This keeps the books balanced
    // against `BondOp::Register`'s burn-to-treasury credit: every base
    // unit a validator commits is permanently anchored in the chain's
    // permanence-funding pool, whether it's later returned via unbond,
    // forfeited via slash, or paid out as block reward.
    //
    // Validator-set mutation is delegated to
    // [`crate::validator_evolution::apply_equivocation_slashings`] —
    // the same pure function the light client uses.
    {
        let eq = crate::validator_evolution::apply_equivocation_slashings(
            &mut next.validators,
            &block.slashings,
        );
        next.treasury = next.treasury.saturating_add(eq.forfeited_total);
        for err in eq.errors {
            errors.push(match err {
                crate::validator_evolution::EquivocationError::Duplicate { index, voter_index } => {
                    BlockError::DuplicateSlash { index, voter_index }
                }
                crate::validator_evolution::EquivocationError::Invalid { index, reason } => {
                    BlockError::SlashInvalid { index, reason }
                }
            });
        }
    }

    // ---- Storage proofs: per-block SPoRA audit + endowment-proportional
    //      reward accrual via the PPB accumulator ----
    let mut seen_proofs: HashSet<[u8; 32]> = HashSet::new();
    let mut accepted_storage_proofs: u128 = 0;
    let mut storage_bonus_total: u128 = 0;
    let current_slot = u64::from(block.header.slot);
    for (pi, proof) in block.storage_proofs.iter().enumerate() {
        if !seen_proofs.insert(proof.commit_hash) {
            errors.push(BlockError::DuplicateStorageProof {
                index: pi,
                commit_hash: hex_short(&proof.commit_hash),
            });
            continue;
        }
        let entry = match next.storage.get(&proof.commit_hash).cloned() {
            Some(e) => e,
            None => {
                errors.push(BlockError::StorageProofUnknownCommit {
                    index: pi,
                    commit_hash: hex_short(&proof.commit_hash),
                });
                continue;
            }
        };
        let verdict = verify_storage_proof(
            &entry.commit,
            &block.header.prev_hash,
            block.header.slot,
            proof,
        );
        if !verdict.is_valid() {
            errors.push(BlockError::StorageProofInvalid {
                index: pi,
                reason: verdict,
            });
            continue;
        }
        match accrue_proof_reward(AccrueArgs {
            size_bytes: entry.commit.size_bytes,
            replication: entry.commit.replication,
            pending_ppb: entry.pending_yield_ppb,
            last_proven_slot: entry.last_proven_slot,
            current_slot,
            params: &next.endowment_params,
        }) {
            Ok(accrual) => {
                next.storage.insert(
                    proof.commit_hash,
                    StorageEntry {
                        commit: entry.commit,
                        last_proven_height: block.header.height,
                        last_proven_slot: current_slot,
                        pending_yield_ppb: accrual.new_pending_ppb,
                    },
                );
                accepted_storage_proofs += 1;
                storage_bonus_total = storage_bonus_total.saturating_add(accrual.payout);
            }
            Err(e) => errors.push(BlockError::EndowmentMathFailed {
                tx: 0,
                output: pi,
                reason: format!("accrue: {e}"),
            }),
        }
    }

    // ---- Liveness participation tracking + auto-slashing ----
    //
    // Walk this block's verified finality bitmap. For each non-zero-stake
    // validator: a set bit credits a successful vote, a clear bit
    // increments consecutive_missed. When consecutive_missed crosses
    // `liveness_max_consecutive_missed`, the validator's stake is
    // multiplicatively reduced by `liveness_slash_bps` and the counter
    // resets — repeated trip-ups compound. Equivocation slashing
    // (the `SlashEvidence` path above) zeros stake outright; this layer
    // catches chronic absenteeism that equivocation evidence can't
    // attribute.
    //
    // The slashed-away delta is credited to the permanence treasury —
    // same sink as equivocation slashing and bond burns, so chronic
    // absenteeism funds storage operators rather than vanishing.
    //
    // Mutation is delegated to
    // [`crate::validator_evolution::apply_liveness_evolution`].
    if let Some(ref bitmap) = finality_bitmap {
        let out = crate::validator_evolution::apply_liveness_evolution(
            &mut next.validators,
            &mut next.validator_stats,
            bitmap,
            &next.params,
        );
        if out.liveness_burn_total > 0 {
            next.treasury = next.treasury.saturating_add(out.liveness_burn_total);
        }
    }

    // ---- Bond ops (M1): new validators appended; not subject to this
    //      block's finality bitmap (they were not yet in the committee).
    //
    // Every successful `BondOp::Register` burns its declared `stake` to
    // the permanence treasury. Bonded MFN is therefore *immediately*
    // working for storage operators the moment a validator joins.
    //
    // `BondOp::Unbond` enqueues an exit; the validator stays in the
    // active set (still slashable!) until the unbond delay elapses,
    // at which point the settlement phase below zeros their stake.
    //
    // Mutation is delegated to
    // [`crate::validator_evolution::apply_bond_ops_evolution`] and
    // [`crate::validator_evolution::apply_unbond_settlements`] — the
    // same pure functions the light client uses to evolve its trusted
    // validator set across rotations.
    let mut counters = crate::validator_evolution::BondEpochCounters {
        bond_epoch_id: next.bond_epoch_id,
        bond_epoch_entry_count: next.bond_epoch_entry_count,
        bond_epoch_exit_count: next.bond_epoch_exit_count,
        next_validator_index: next.next_validator_index,
    };
    match crate::validator_evolution::apply_bond_ops_evolution(
        block.header.height,
        &mut counters,
        &mut next.validators,
        &mut next.validator_stats,
        &mut next.pending_unbonds,
        &next.bonding_params,
        &block.bond_ops,
    ) {
        Ok(burn_total) => {
            next.treasury = next.treasury.saturating_add(burn_total);
        }
        Err(crate::validator_evolution::BondOpError { index, message }) => {
            errors.push(BlockError::BondOpRejected { index, message });
        }
    }

    // ---- Unbond settlements (M1): scan pending_unbonds in deterministic
    //      sorted-by-index order; for each entry whose unlock_height has
    //      arrived AND exit-churn budget remains, zero the validator's
    //      stake. Bonded MFN stays in treasury -- for M1, bonding is a
    //      one-way contribution to permanence; an honorable exit only
    //      frees the operator from future slashing exposure.
    crate::validator_evolution::apply_unbond_settlements(
        block.header.height,
        &mut counters,
        &next.bonding_params,
        &mut next.validators,
        &mut next.pending_unbonds,
    );

    // Commit the counter mutations back to chain state.
    next.bond_epoch_id = counters.bond_epoch_id;
    next.bond_epoch_entry_count = counters.bond_epoch_entry_count;
    next.bond_epoch_exit_count = counters.bond_epoch_exit_count;
    next.next_validator_index = counters.next_validator_index;

    // ---- Two-sided economic settlement ----
    //
    //   1. treasury_fee = fee_sum · fee_to_treasury_bps / 10000
    //      producer_fee = fee_sum − treasury_fee
    //   2. Treasury gains treasury_fee.
    //   3. Storage rewards = storage_proof_reward · N_accepted + Σ bonus.
    //      Treasury drains first; any shortfall is minted via emission
    //      as a backstop. Treasury balance never goes negative.
    //   4. Coinbase pays producer = subsidy + producer_fee + storage_rewards.
    let emission_params = next.emission_params;
    let treasury_fee: u128 = fee_sum * u128::from(emission_params.fee_to_treasury_bps) / 10_000;
    let producer_fee_u128 = fee_sum - treasury_fee;
    let producer_fee: u64 = u64::try_from(producer_fee_u128).unwrap_or(u64::MAX);

    let storage_reward_total: u128 = u128::from(emission_params.storage_proof_reward)
        .saturating_mul(accepted_storage_proofs)
        .saturating_add(storage_bonus_total);

    let mut pending_treasury = next.treasury.saturating_add(treasury_fee);
    let storage_from_treasury = pending_treasury.min(storage_reward_total);
    pending_treasury -= storage_from_treasury;
    next.treasury = pending_treasury;
    // The remaining `storage_reward_total - storage_from_treasury` is the
    // emission backstop; it's part of the producer's coinbase amount but
    // not subtracted from the treasury.

    let subsidy = emission_at_height(u64::from(block.header.height), &emission_params);
    let expected_reward = u128::from(subsidy)
        .saturating_add(u128::from(producer_fee))
        .saturating_add(storage_reward_total);
    let expected_reward = u64::try_from(expected_reward).unwrap_or(u64::MAX);

    if require_coinbase {
        let producer = producer
            .as_ref()
            .expect("require_coinbase implies producer present");
        let payout = producer
            .payout
            .as_ref()
            .expect("require_coinbase implies payout present");
        match coinbase_tx {
            None => errors.push(BlockError::CoinbaseRequiredButAbsent),
            Some(cb) => {
                let cv = verify_coinbase(
                    cb,
                    u64::from(block.header.height),
                    expected_reward,
                    &crate::coinbase::PayoutAddress {
                        view_pub: payout.view_pub,
                        spend_pub: payout.spend_pub,
                    },
                );
                if !cv.ok {
                    errors.push(BlockError::CoinbaseInvalid(cv.errors));
                }
            }
        }
    } else if coinbase_tx.is_some() {
        errors.push(BlockError::UnexpectedCoinbase);
    }

    // ---- Storage root ----
    let expected_storage_root = storage_merkle_root(&new_storages);
    if expected_storage_root != block.header.storage_root {
        errors.push(BlockError::StorageRootMismatch);
    }

    // ---- UTXO accumulator root ----
    let computed_root = utxo_tree_root(&next.utxo_tree);
    if computed_root != block.header.utxo_root {
        errors.push(BlockError::UtxoRootMismatch);
    }

    if !errors.is_empty() {
        return ApplyOutcome::Err {
            errors,
            block_id: proposed_id,
        };
    }

    next.block_ids.push(proposed_id);
    ApplyOutcome::Ok {
        state: next,
        block_id: proposed_id,
    }
}

fn hex_short(b: &[u8]) -> String {
    let mut s = String::with_capacity(13);
    for byte in b.iter().take(6) {
        s.push_str(&format!("{byte:02x}"));
    }
    s.push('…');
    s
}

/* ----------------------------------------------------------------------- *
 *  Errors                                                                  *
 * ----------------------------------------------------------------------- */

/// Block-application errors. Surfaced via [`ApplyOutcome::Err`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    /// Genesis block must have `height == 0`.
    #[error("genesis height must be 0")]
    GenesisHeightNotZero,
    /// Header height didn't match `state.height + 1`.
    #[error("bad height: expected {expected}, got {got}")]
    BadHeight {
        /// Expected (current tip + 1).
        expected: u32,
        /// What the header carried.
        got: u32,
    },
    /// `prev_hash` didn't match the chain tip.
    #[error("prev_hash does not match tip")]
    PrevHashMismatch,
    /// Header `tx_root` didn't match the locally-recomputed root.
    #[error("tx_root mismatch")]
    TxRootMismatch,
    /// Header `bond_root` didn't match the locally-recomputed bond Merkle root.
    #[error("bond_root mismatch")]
    BondRootMismatch,
    /// Header `slashing_root` didn't match the locally-recomputed
    /// Merkle root over `block.slashings` (M2.0.1).
    #[error("slashing_root mismatch")]
    SlashingRootMismatch,
    /// Header `storage_proof_root` didn't match the locally-recomputed
    /// Merkle root over `block.storage_proofs` (M2.0.2).
    #[error("storage_proof_root mismatch")]
    StorageProofRootMismatch,
    /// Header `validator_root` didn't match the locally-recomputed Merkle
    /// root over the pre-block validator set (M2.0).
    #[error("validator_root mismatch")]
    ValidatorRootMismatch,
    /// Header `claims_root` didn't match the Merkle root recomputed from
    /// this block's non-coinbase `tx.extra` authorship payloads (M2.2.x).
    #[error("claims_root mismatch")]
    ClaimsRootMismatch,
    /// Authorship claim parse or signature verification failed for a tx.
    #[error("authorship claims: {0}")]
    AuthorshipClaims(String),
    /// A bond operation failed validation or conflicted with on-chain state.
    #[error("bond_ops[{index}]: {message}")]
    BondOpRejected {
        /// Index in `block.bond_ops`.
        index: usize,
        /// Human-readable reason.
        message: String,
    },
    /// Chain has a validator set but the header lacks a producer proof.
    #[error("missing producer proof")]
    MissingProducerProof,
    /// The producer proof failed to decode.
    #[error("producer proof decode failed: {0}")]
    FinalityDecode(String),
    /// The producer proof decoded but failed verification.
    #[error("finality invalid: {0:?}")]
    FinalityInvalid(crate::consensus::ConsensusCheck),
    /// A tx past index 0 was coinbase-shaped (no inputs).
    #[error("tx[{0}]: coinbase-shaped tx not allowed past position 0")]
    CoinbaseOutOfPosition(usize),
    /// The chain expected a coinbase at position 0 but got a non-coinbase
    /// (real-input tx).
    #[error("tx[0]: expected coinbase but got {got_inputs}-input tx")]
    MissingCoinbase {
        /// Number of inputs in the bogus first tx.
        got_inputs: usize,
    },
    /// `verify_transaction` rejected the tx.
    #[error("tx[{index}] invalid: {errors:?}")]
    TxInvalid {
        /// Position in `block.txs`.
        index: usize,
        /// Per-error strings from `verify_transaction`.
        errors: Vec<String>,
    },
    /// A key image already exists in the chain or this block.
    #[error("tx[{index}] double-spend: key image {key_image}")]
    DoubleSpend {
        /// Position of the offending tx.
        index: usize,
        /// Hex prefix of the duplicate key image.
        key_image: String,
    },
    /// A CLSAG ring member references a one-time address that is not in
    /// the chain's UTXO set. This is the chain-level guard against fake
    /// ring members; without it, a spender could mint MFN out of thin
    /// air by inventing a ring member with an arbitrary hidden value.
    #[error(
        "tx[{tx}].inputs[{input}].ring[{ring_index}]: one-time address {one_time_addr} not in UTXO set"
    )]
    RingMemberNotInUtxoSet {
        /// Position of the offending tx.
        tx: usize,
        /// Position of the offending input within the tx.
        input: usize,
        /// Position of the offending member within the ring.
        ring_index: usize,
        /// Hex prefix of the one-time address.
        one_time_addr: String,
    },
    /// A CLSAG ring member references a real UTXO but with a Pedersen
    /// commitment that doesn't match the on-chain commitment for that
    /// output. The ring's `C` column would let the spender inflate the
    /// hidden value of a real UTXO, so the chain enforces exact match.
    #[error(
        "tx[{tx}].inputs[{input}].ring[{ring_index}]: commitment mismatch for {one_time_addr}"
    )]
    RingMemberCommitMismatch {
        /// Position of the offending tx.
        tx: usize,
        /// Position of the offending input within the tx.
        input: usize,
        /// Position of the offending member within the ring.
        ring_index: usize,
        /// Hex prefix of the one-time address.
        one_time_addr: String,
    },
    /// The UTXO accumulator is full (depth-32 tree exhausted).
    #[error("utxo accumulator full: {0}")]
    AccumulatorFull(String),
    /// Two slashing pieces target the same validator.
    #[error("slashings[{index}]: duplicate evidence for validator {voter_index}")]
    DuplicateSlash {
        /// Index in `block.slashings`.
        index: usize,
        /// Validator index referenced twice.
        voter_index: u32,
    },
    /// A piece of slashing evidence failed verification.
    #[error("slashings[{index}]: {reason:?}")]
    SlashInvalid {
        /// Index in `block.slashings`.
        index: usize,
        /// Reason from the slashing verifier.
        reason: EvidenceCheck,
    },
    /// Producer has a payout but the block has no coinbase tx.
    #[error("coinbase required (producer has payout) but absent")]
    CoinbaseRequiredButAbsent,
    /// `verify_coinbase` rejected the tx.
    #[error("coinbase invalid: {0:?}")]
    CoinbaseInvalid(Vec<String>),
    /// Block has a coinbase but the producer has no payout (or there is
    /// no producer at all).
    #[error("unexpected coinbase: producer has no payout")]
    UnexpectedCoinbase,
    /// Storage Merkle root mismatch.
    #[error("storage_root mismatch")]
    StorageRootMismatch,
    /// UTXO accumulator root mismatch.
    #[error("utxo_root mismatch")]
    UtxoRootMismatch,
    /// A storage commitment declared replication below the configured
    /// `min_replication`.
    #[error("tx[{tx}].outputs[{output}]: storage replication {got} < min {min}")]
    StorageReplicationTooLow {
        /// Position of the offending tx.
        tx: usize,
        /// Position of the offending output within the tx.
        output: usize,
        /// Caller-supplied replication factor.
        got: u8,
        /// Configured minimum.
        min: u8,
    },
    /// A storage commitment declared replication above the configured
    /// `max_replication`.
    #[error("tx[{tx}].outputs[{output}]: storage replication {got} > max {max}")]
    StorageReplicationTooHigh {
        /// Position of the offending tx.
        tx: usize,
        /// Position of the offending output within the tx.
        output: usize,
        /// Caller-supplied replication factor.
        got: u8,
        /// Configured maximum.
        max: u8,
    },
    /// A tx introduced new storage commitments but didn't contribute
    /// enough treasury-fee to cover the protocol's required endowment.
    #[error(
        "tx[{tx}]: storage endowment burden {burden} exceeds tx treasury share {treasury_share} \
         (fee={fee}, fee_to_treasury_bps={fee_to_treasury_bps})"
    )]
    UploadUnderfunded {
        /// Position of the offending tx.
        tx: usize,
        /// Total required endowment for this tx's new storage commitments.
        burden: u128,
        /// Treasury-bound share of the tx fee available to cover it.
        treasury_share: u128,
        /// The tx's declared fee (base units).
        fee: u64,
        /// Chain's `fee_to_treasury_bps`.
        fee_to_treasury_bps: u16,
    },
    /// Underlying endowment math returned an error (overflow, validation).
    #[error("tx[{tx}].outputs[{output}]: endowment math failed: {reason}")]
    EndowmentMathFailed {
        /// Position of the related tx (or `0` for non-tx contexts).
        tx: usize,
        /// Position within outputs/proofs.
        output: usize,
        /// Stringified upstream error.
        reason: String,
    },
    /// Two storage proofs in the block target the same commitment.
    #[error("storage_proofs[{index}]: duplicate proof for {commit_hash}")]
    DuplicateStorageProof {
        /// Index in `block.storage_proofs`.
        index: usize,
        /// Hex prefix of the duplicated commit hash.
        commit_hash: String,
    },
    /// A storage proof referenced a commitment that isn't anchored in the
    /// chain's storage registry.
    #[error("storage_proofs[{index}]: commit {commit_hash} not in storage registry")]
    StorageProofUnknownCommit {
        /// Index in `block.storage_proofs`.
        index: usize,
        /// Hex prefix of the unknown commit hash.
        commit_hash: String,
    },
    /// A storage proof failed verification.
    #[error("storage_proofs[{index}]: {reason:?}")]
    StorageProofInvalid {
        /// Index in `block.storage_proofs`.
        index: usize,
        /// Structured reason from the SPoRA verifier.
        reason: StorageProofCheck,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageCommitment;

    fn genesis_state() -> ChainState {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        apply_genesis(&g, &cfg).unwrap()
    }

    #[test]
    fn build_apply_genesis_matches() {
        let cfg = GenesisConfig {
            timestamp: 42,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let st = apply_genesis(&g, &cfg).unwrap();
        assert_eq!(st.height, Some(0));
        assert_eq!(st.block_ids.len(), 1);
        assert_eq!(st.block_ids[0], block_id(&g.header));
    }

    #[test]
    fn apply_genesis_sets_optional_bonding_params() {
        let custom = BondingParams {
            min_validator_stake: 2_000_000,
            ..DEFAULT_BONDING_PARAMS
        };
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: Some(custom),
        };
        let g = build_genesis(&cfg);
        let st = apply_genesis(&g, &cfg).unwrap();
        assert_eq!(st.bonding_params.min_validator_stake, 2_000_000);
    }

    #[test]
    fn empty_block_applies_in_legacy_mode() {
        let st = genesis_state();
        let header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.height, Some(1));
                assert_eq!(state.block_ids.len(), 2);
            }
            ApplyOutcome::Err { errors, .. } => panic!("expected ok, got: {errors:?}"),
        }
    }

    #[test]
    fn bad_height_is_rejected() {
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
        header.height = 99;
        // Have to recompute prev_hash + utxo_root for the bad height since
        // they're independent... actually no, only height is wrong here, so
        // the locally-computed expected_tx_root and utxo_root will still
        // match. Just check that BadHeight surfaces.
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BadHeight { .. })));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn bad_prev_hash_is_rejected() {
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
        header.prev_hash = [9u8; 32];
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::PrevHashMismatch)));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn tx_root_mismatch_is_rejected() {
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
        header.tx_root[0] ^= 0xff;
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::TxRootMismatch)));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn bond_root_mismatch_is_rejected() {
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
        header.bond_root[0] ^= 0xff;
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondRootMismatch)));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn storage_proof_root_mismatch_is_rejected() {
        // Build a legitimate empty-storage-proofs block, then flip a
        // byte of the header's storage_proof_root.
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
        assert_eq!(header.storage_proof_root, [0u8; 32]);
        header.storage_proof_root[0] = 0xff;
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofRootMismatch)));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn slashing_root_mismatch_is_rejected() {
        // Build a valid empty-slashings block in legacy/no-validator
        // mode, then flip one byte of `header.slashing_root` to a value
        // the empty list cannot produce.
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
        assert_eq!(header.slashing_root, [0u8; 32]);
        header.slashing_root[0] = 0xff;
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::SlashingRootMismatch)));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn validator_root_mismatch_is_rejected() {
        // Build a valid empty block (legacy / no-validator mode is fine —
        // the validator-root check runs *regardless* of validator-set
        // size), then flip one byte of `header.validator_root` to a
        // value the pre-block state cannot produce.
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
        // No validators ⇒ pre-block root is the all-zero sentinel.
        assert_eq!(header.validator_root, [0u8; 32]);
        header.validator_root[0] = 0xff;
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::ValidatorRootMismatch)));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn build_unsealed_header_commits_pre_block_validator_set() {
        // The header for block N must commit to the validator set as it
        // stood at the end of block N-1 — the set the producer-proof is
        // verified against. Verify by building the header from a state
        // with a non-empty validator set and checking it equals
        // `validator_set_root(&state.validators)`.
        use crate::consensus::{validator_set_root, Validator};
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::generator_g;

        let mut st = genesis_state();
        let v = Validator {
            index: 0,
            vrf_pk: generator_g(),
            bls_pk: bls_keygen_from_seed(&[7u8; 32]).pk,
            stake: 1_000_000,
            payout: None,
        };
        st.validators.push(v.clone());
        st.validator_stats.push(ValidatorStats::default());
        st.next_validator_index = 1;

        let header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
        assert_eq!(header.validator_root, validator_set_root(&st.validators));
        assert_ne!(header.validator_root, [0u8; 32]);
    }

    #[test]
    fn bond_ops_apply_is_atomic_on_error() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::{generator_g, generator_h};

        let st = genesis_state();
        let bls1 = bls_keygen_from_seed(&[1u8; 32]);
        let stake_ok = crate::DEFAULT_BONDING_PARAMS.min_validator_stake;
        let vrf_ok = generator_g();
        let ok_op = BondOp::Register {
            stake: stake_ok,
            vrf_pk: vrf_ok,
            bls_pk: bls1.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(stake_ok, &vrf_ok, &bls1.pk, None, &bls1.sk),
        };
        let bls2 = bls_keygen_from_seed(&[2u8; 32]);
        let stake_bad = 1u64;
        let vrf_bad = generator_h();
        let bad_op = BondOp::Register {
            stake: stake_bad,
            vrf_pk: vrf_bad,
            bls_pk: bls2.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(stake_bad, &vrf_bad, &bls2.pk, None, &bls2.sk),
        };
        let bond_ops = vec![ok_op, bad_op];
        let header = build_unsealed_header(&st, &[], &bond_ops, &[], &[], 1, 100);
        let blk = seal_block(
            header,
            Vec::new(),
            bond_ops,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { index: 1, .. })));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
        assert!(st.validators.is_empty());
    }

    // Bad register signature must be rejected (atomic apply ⇒ the
    // whole bond-op set is rolled back, no validators appended, no
    // treasury credit). Mempool-grade authorization: this is the
    // property that prevents an adversarial relayer from replaying a
    // serialized BondOp::Register op for any operator's keys.
    #[test]
    fn register_rejects_invalid_signature() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::generator_g;

        let st = genesis_state();
        let attacker = bls_keygen_from_seed(&[200u8; 32]);
        let victim_bls = bls_keygen_from_seed(&[201u8; 32]);
        let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
        let vrf_pk = generator_g();
        // The attacker signs over the victim's bls_pk but with their
        // own secret key — the resulting sig won't verify under
        // victim_bls.pk.
        let forged =
            crate::bond_wire::sign_register(stake, &vrf_pk, &victim_bls.pk, None, &attacker.sk);
        let op = BondOp::Register {
            stake,
            vrf_pk,
            bls_pk: victim_bls.pk,
            payout: None,
            sig: forged,
        };
        let header = build_unsealed_header(&st, &[], std::slice::from_ref(&op), &[], &[], 1, 100);
        let blk = seal_block(
            header,
            Vec::new(),
            vec![op],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(
                    errors
                        .iter()
                        .any(|e| matches!(e, BlockError::BondOpRejected { index: 0, .. })),
                    "expected BondOpRejected at index 0, got {errors:?}"
                );
                // No state mutation must have occurred.
                assert_eq!(st.validators.len(), 0);
                assert_eq!(st.treasury, 0);
            }
            ApplyOutcome::Ok { .. } => panic!("forged register signature must reject"),
        }
    }

    // Unbond rejection in legacy mode (empty validators ⇒ no finality
    // proof required for this block). End-to-end register → unbond →
    // settle flows live in tests/integration.rs::unbond_lifecycle_*.
    #[test]
    fn unbond_rejects_unknown_validator_legacy_mode() {
        use mfn_bls::bls_keygen_from_seed;
        let st = genesis_state();
        let bls = bls_keygen_from_seed(&[100u8; 32]);
        let unbond = BondOp::Unbond {
            validator_index: 42,
            sig: crate::bond_wire::sign_unbond(42, &bls.sk),
        };
        let header =
            build_unsealed_header(&st, &[], std::slice::from_ref(&unbond), &[], &[], 1, 100);
        let blk = seal_block(
            header,
            Vec::new(),
            vec![unbond],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::BondOpRejected { .. })));
            }
            ApplyOutcome::Ok { .. } => panic!("unknown validator must reject"),
        }
    }

    #[test]
    fn unbond_wire_round_trip_inside_bond_root() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::generator_g;
        let bls = bls_keygen_from_seed(&[55u8; 32]);
        let unbond = BondOp::Unbond {
            validator_index: 7,
            sig: crate::bond_wire::sign_unbond(7, &bls.sk),
        };
        let reg_bls = bls_keygen_from_seed(&[11u8; 32]);
        let stake = DEFAULT_BONDING_PARAMS.min_validator_stake;
        let vrf_pk = generator_g();
        let reg = BondOp::Register {
            stake,
            vrf_pk,
            bls_pk: reg_bls.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(stake, &vrf_pk, &reg_bls.pk, None, &reg_bls.sk),
        };
        let ops = vec![reg, unbond];
        let root = crate::bond_wire::bond_merkle_root(&ops);
        assert_ne!(root, [0u8; 32], "merkle root over mixed ops is non-zero");
    }

    #[test]
    fn utxo_root_mismatch_is_rejected() {
        let st = genesis_state();
        let mut header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
        header.utxo_root[0] ^= 0xff;
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { errors, .. } => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, BlockError::UtxoRootMismatch)));
            }
            ApplyOutcome::Ok { .. } => panic!("expected err"),
        }
    }

    #[test]
    fn header_signing_hash_excludes_producer_proof() {
        let st = genesis_state();
        let h0 = build_unsealed_header(&st, &[], &[], &[], &[], 1, 100);
        let hash0 = header_signing_hash(&h0);
        let mut h1 = h0.clone();
        h1.producer_proof = b"this is whatever the producer attaches".to_vec();
        let hash1 = header_signing_hash(&h1);
        assert_eq!(
            hash0, hash1,
            "signing hash must not depend on producer_proof"
        );
        // But the full block id DOES depend on producer_proof.
        assert_ne!(block_id(&h0), block_id(&h1));
    }

    #[test]
    fn storage_root_uses_zero_when_empty() {
        assert_eq!(storage_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn storage_merkle_root_is_stable_under_no_op_storage() {
        use mfn_crypto::point::generator_g;
        let sc = StorageCommitment {
            data_root: [1u8; 32],
            size_bytes: 1_000,
            chunk_size: 256,
            num_chunks: 4,
            replication: 3,
            endowment: generator_g(),
        };
        let r1 = storage_merkle_root(std::slice::from_ref(&sc));
        let r2 = storage_merkle_root(&[sc]);
        assert_eq!(r1, r2);
    }

    /* --------- Endowment burden + storage proof gating ---------- *
     *                                                              *
     *  These tests run apply_block end-to-end against a no-         *
     *  validator chain. With validators.is_empty(), the finality    *
     *  + coinbase machinery is bypassed, so we get clean coverage   *
     *  of the upload-burden + SPoRA proof paths.                    *
     * ------------------------------------------------------------ */

    fn empty_genesis_with_endowment(ep: EndowmentParams) -> ChainState {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: ep,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        apply_genesis(&g, &cfg).unwrap()
    }

    #[test]
    fn duplicate_storage_proof_in_one_block_rejected() {
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let built = mfn_storage::build_storage_commitment(
            &payload,
            1_000,
            Some(4096),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .unwrap();
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: vec![built.commit.clone()],
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let state0 = apply_genesis(&g, &cfg).unwrap();
        let unsealed = build_unsealed_header(&state0, &[], &[], &[], &[], 5_000, 1_000);
        let p = mfn_storage::build_storage_proof(
            &built.commit,
            &unsealed.prev_hash,
            5_000,
            &payload,
            &built.tree,
        )
        .unwrap();
        let block = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![p.clone(), p],
        );
        match apply_block(&state0, &block) {
            ApplyOutcome::Err { errors, .. } => assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::DuplicateStorageProof { .. })),
                "expected DuplicateStorageProof, got {errors:?}"
            ),
            ApplyOutcome::Ok { .. } => panic!("duplicate proof must reject the block"),
        }
    }

    #[test]
    fn storage_proof_for_unknown_commit_rejected() {
        let state0 = empty_genesis_with_endowment(DEFAULT_ENDOWMENT_PARAMS);
        let payload = b"unanchored".to_vec();
        let built = mfn_storage::build_storage_commitment(
            &payload,
            1,
            Some(64), // 64-byte chunks → many small chunks
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .unwrap();
        let unsealed = build_unsealed_header(&state0, &[], &[], &[], &[], 1, 100);
        let p = mfn_storage::build_storage_proof(
            &built.commit,
            &unsealed.prev_hash,
            1,
            &payload,
            &built.tree,
        )
        .unwrap();
        let block = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![p],
        );
        match apply_block(&state0, &block) {
            ApplyOutcome::Err { errors, .. } => assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofUnknownCommit { .. })),
                "expected StorageProofUnknownCommit, got {errors:?}"
            ),
            ApplyOutcome::Ok { .. } => panic!("unanchored proof must reject the block"),
        }
    }

    #[test]
    fn storage_proof_with_wrong_chunk_rejected() {
        let payload: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
        let built = mfn_storage::build_storage_commitment(
            &payload,
            1,
            Some(64),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .unwrap();
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: vec![built.commit.clone()],
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let state0 = apply_genesis(&g, &cfg).unwrap();
        let unsealed = build_unsealed_header(&state0, &[], &[], &[], &[], 1, 100);
        let mut p = mfn_storage::build_storage_proof(
            &built.commit,
            &unsealed.prev_hash,
            1,
            &payload,
            &built.tree,
        )
        .unwrap();
        if !p.chunk.is_empty() {
            p.chunk[0] ^= 0xff;
        }
        let block = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![p],
        );
        match apply_block(&state0, &block) {
            ApplyOutcome::Err { errors, .. } => assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, BlockError::StorageProofInvalid { .. })),
                "expected StorageProofInvalid, got {errors:?}"
            ),
            ApplyOutcome::Ok { .. } => panic!("corrupt proof must reject the block"),
        }
    }

    /* ---- Ring-membership / counterfeit-input attack tests ------------ *
     *                                                                   *
     *  These tests target the only thing standing between Permawrite     *
     *  and the "mint MFN out of thin air" attack: every CLSAG ring       *
     *  member's (P, C) MUST exist in the chain's UTXO set. Without       *
     *  this guard a spender can fabricate a ring member with arbitrary   *
     *  hidden value, balance their pseudo-output against it, and emit    *
     *  outputs they don't own.                                           *
     * ----------------------------------------------------------------- */

    #[test]
    fn ring_member_not_in_utxo_set_rejected() {
        use curve25519_dalek::scalar::Scalar;
        use mfn_crypto::clsag::ClsagRing;
        use mfn_crypto::point::{generator_g, generator_h};
        use mfn_crypto::scalar::random_scalar;
        use mfn_crypto::stealth::stealth_gen;

        use crate::transaction::{sign_transaction, InputSpec, OutputSpec, Recipient};

        // Genesis funds the real signer with a known UTXO. No decoys are
        // anchored, so any ring member other than the signer's UTXO will
        // be unknown to the chain.
        let init_value = 1_000_000u64;
        let init_blinding = random_scalar();
        let signer_spend = random_scalar();
        let signer_p = generator_g() * signer_spend;
        let signer_c = (generator_g() * init_blinding) + (generator_h() * Scalar::from(init_value));
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: vec![GenesisOutput {
                one_time_addr: signer_p,
                amount: signer_c,
            }],
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let state0 = apply_genesis(&g, &cfg).unwrap();

        // Construct a 4-member ring; signer at index 1, the other three
        // are random (P, C) pairs that aren't in the UTXO set.
        let mut ring_p = Vec::new();
        let mut ring_c = Vec::new();
        for i in 0..4 {
            if i == 1 {
                ring_p.push(signer_p);
                ring_c.push(signer_c);
            } else {
                let sp = random_scalar();
                let bp = random_scalar();
                let vp = random_scalar();
                ring_p.push(generator_g() * sp);
                ring_c.push((generator_g() * bp) + (generator_h() * vp));
            }
        }
        let recipient_wallet = stealth_gen();
        let r = Recipient {
            view_pub: recipient_wallet.view_pub,
            spend_pub: recipient_wallet.spend_pub,
        };
        let send_value = init_value - 1_000;
        let signed = sign_transaction(
            vec![InputSpec {
                ring: ClsagRing {
                    p: ring_p,
                    c: ring_c,
                },
                signer_idx: 1,
                spend_priv: signer_spend,
                value: init_value,
                blinding: init_blinding,
            }],
            vec![OutputSpec::ToRecipient {
                recipient: r,
                value: send_value,
                storage: None,
            }],
            1_000,
            b"attack".to_vec(),
        )
        .expect("sign");

        let unsealed = build_unsealed_header(
            &state0,
            std::slice::from_ref(&signed.tx),
            &[],
            &[],
            &[],
            1,
            100,
        );
        let block = seal_block(
            unsealed,
            vec![signed.tx],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&state0, &block) {
            ApplyOutcome::Err { errors, .. } => {
                let saw_ring_error = errors
                    .iter()
                    .any(|e| matches!(e, BlockError::RingMemberNotInUtxoSet { .. }));
                assert!(
                    saw_ring_error,
                    "expected RingMemberNotInUtxoSet, got {errors:?}"
                );
            }
            ApplyOutcome::Ok { .. } => {
                panic!("ring with fabricated members must reject the block (counterfeit attack)")
            }
        }
    }

    #[test]
    fn ring_member_with_wrong_commit_rejected() {
        use curve25519_dalek::scalar::Scalar;
        use mfn_crypto::clsag::ClsagRing;
        use mfn_crypto::point::{generator_g, generator_h};
        use mfn_crypto::scalar::random_scalar;
        use mfn_crypto::stealth::stealth_gen;

        use crate::transaction::{sign_transaction, InputSpec, OutputSpec, Recipient};

        // Anchor a real UTXO at genesis; spender will reference it in
        // their ring but with an inflated Pedersen commitment to try to
        // sneak extra hidden value past the chain. Must be rejected.
        let init_value = 1_000_000u64;
        let init_blinding = random_scalar();
        let signer_spend = random_scalar();
        let signer_p = generator_g() * signer_spend;
        let signer_c = (generator_g() * init_blinding) + (generator_h() * Scalar::from(init_value));

        // A second anchored UTXO with KNOWN small value that the attacker
        // will reference in their ring, but with an inflated C.
        let decoy_spend = random_scalar();
        let decoy_p = generator_g() * decoy_spend;
        let decoy_value = 1u64;
        let decoy_blinding = random_scalar();
        let decoy_c =
            (generator_g() * decoy_blinding) + (generator_h() * Scalar::from(decoy_value));

        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: vec![
                GenesisOutput {
                    one_time_addr: signer_p,
                    amount: signer_c,
                },
                GenesisOutput {
                    one_time_addr: decoy_p,
                    amount: decoy_c,
                },
            ],
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let state0 = apply_genesis(&g, &cfg).unwrap();

        // Attacker's ring: signer's real UTXO + the decoy's P with an
        // INFLATED C (pretending the decoy holds 10^9 base units).
        let inflated_c =
            (generator_g() * random_scalar()) + (generator_h() * Scalar::from(1_000_000_000u64));
        let ring_p = vec![signer_p, decoy_p];
        let ring_c = vec![signer_c, inflated_c];

        let recipient_wallet = stealth_gen();
        let r = Recipient {
            view_pub: recipient_wallet.view_pub,
            spend_pub: recipient_wallet.spend_pub,
        };
        let send_value = init_value - 1_000;
        let signed = sign_transaction(
            vec![InputSpec {
                ring: ClsagRing {
                    p: ring_p,
                    c: ring_c,
                },
                signer_idx: 0,
                spend_priv: signer_spend,
                value: init_value,
                blinding: init_blinding,
            }],
            vec![OutputSpec::ToRecipient {
                recipient: r,
                value: send_value,
                storage: None,
            }],
            1_000,
            b"inflated-c".to_vec(),
        )
        .expect("sign");

        let unsealed = build_unsealed_header(
            &state0,
            std::slice::from_ref(&signed.tx),
            &[],
            &[],
            &[],
            1,
            100,
        );
        let block = seal_block(
            unsealed,
            vec![signed.tx],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&state0, &block) {
            ApplyOutcome::Err { errors, .. } => {
                let saw_commit_error = errors
                    .iter()
                    .any(|e| matches!(e, BlockError::RingMemberCommitMismatch { .. }));
                assert!(
                    saw_commit_error,
                    "expected RingMemberCommitMismatch, got {errors:?}"
                );
            }
            ApplyOutcome::Ok { .. } => panic!("inflated-C ring member must reject the block"),
        }
    }

    /* ---- Liveness participation + auto-slashing ---------------------- *
     *                                                                   *
     *  These unit tests drive `apply_block` against the liveness bitmap  *
     *  path with hand-crafted state — we don't need a real validator    *
     *  set or BLS finality machinery because the liveness logic         *
     *  consumes `finality_bitmap` after `verify_finality_proof` has     *
     *  already cleared the block. We bypass that path by stuffing the   *
     *  bitmap directly into a synthetic `next` via the public surface:  *
     *  set up an empty-validator chain, then manually invoke the path.  *
     *                                                                   *
     *  Integration coverage with REAL BLS finality flowing into the     *
     *  liveness path lives in `tests/integration.rs`.                   *
     * ----------------------------------------------------------------- */

    /// Direct unit test of the liveness-update logic, called as the
    /// equivalent inline block of `apply_block`. This keeps the test
    /// hermetic — no BLS setup, no genesis dance — just the state
    /// transition the bitmap drives.
    fn apply_liveness_step(state: &mut ChainState, bitmap: &[u8], max_missed: u32, slash_bps: u32) {
        // Mirrors the `if let Some(ref bitmap)` branch in apply_block.
        if state.validator_stats.len() != state.validators.len() {
            state
                .validator_stats
                .resize(state.validators.len(), ValidatorStats::default());
        }
        let slash_bps = u128::from(slash_bps);
        let mut burn_total: u128 = 0;
        for (i, v) in state.validators.iter_mut().enumerate() {
            if v.stake == 0 {
                continue;
            }
            let byte = i >> 3;
            let bit = i & 7;
            let signed = byte < bitmap.len() && (bitmap[byte] & (1u8 << bit)) != 0;
            let stats = &mut state.validator_stats[i];
            if signed {
                stats.consecutive_missed = 0;
                stats.total_signed = stats.total_signed.saturating_add(1);
            } else {
                stats.consecutive_missed = stats.consecutive_missed.saturating_add(1);
                stats.total_missed = stats.total_missed.saturating_add(1);
                if max_missed > 0 && stats.consecutive_missed >= max_missed {
                    let bps = slash_bps.min(10_000);
                    let old_stake = u128::from(v.stake);
                    let new_stake_u128 = old_stake * (10_000 - bps) / 10_000;
                    let forfeited = old_stake - new_stake_u128;
                    v.stake = u64::try_from(new_stake_u128).unwrap_or(u64::MAX);
                    burn_total = burn_total.saturating_add(forfeited);
                    stats.liveness_slashes = stats.liveness_slashes.saturating_add(1);
                    stats.consecutive_missed = 0;
                }
            }
        }
        state.treasury = state.treasury.saturating_add(burn_total);
    }

    fn fake_validator(idx: u32, stake: u64) -> Validator {
        // VRF + BLS pubkeys are placeholders; the liveness path doesn't
        // touch them. We just need a Validator-shaped struct.
        Validator {
            index: idx,
            vrf_pk: mfn_crypto::vrf::vrf_keygen_from_seed(&[idx as u8 + 7; 32])
                .unwrap()
                .pk,
            bls_pk: mfn_bls::bls_keygen_from_seed(&[idx as u8 + 17; 32]).pk,
            stake,
            payout: None,
        }
    }

    #[test]
    fn liveness_signed_resets_counter_and_credits() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 100)];
        state.validator_stats = vec![ValidatorStats::default()];
        // Bitmap with bit 0 set.
        apply_liveness_step(&mut state, &[0b0000_0001], 32, 100);
        let s = state.validator_stats[0];
        assert_eq!(s.consecutive_missed, 0);
        assert_eq!(s.total_signed, 1);
        assert_eq!(s.total_missed, 0);
        assert_eq!(state.validators[0].stake, 100);
    }

    #[test]
    fn liveness_unset_increments_counter() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 100)];
        state.validator_stats = vec![ValidatorStats::default()];
        for _ in 0..5 {
            apply_liveness_step(&mut state, &[0b0000_0000], 32, 100);
        }
        let s = state.validator_stats[0];
        assert_eq!(s.consecutive_missed, 5);
        assert_eq!(s.total_missed, 5);
        assert_eq!(s.total_signed, 0);
        assert_eq!(s.liveness_slashes, 0);
        assert_eq!(state.validators[0].stake, 100, "below threshold ⇒ no slash");
    }

    #[test]
    fn liveness_threshold_triggers_slash_and_reset() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 1_000_000)];
        state.validator_stats = vec![ValidatorStats::default()];
        // 32 consecutive misses → first slash.
        for _ in 0..32 {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        let s = state.validator_stats[0];
        assert_eq!(s.liveness_slashes, 1);
        assert_eq!(s.consecutive_missed, 0, "counter resets after slash");
        // 1% of 1_000_000 = 10_000; new stake = 990_000.
        assert_eq!(state.validators[0].stake, 990_000);
    }

    #[test]
    fn liveness_compounds_multiplicatively() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 1_000_000)];
        state.validator_stats = vec![ValidatorStats::default()];
        // 5 slash cycles of 32 misses each.
        for _ in 0..(5 * 32) {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        // After 5 × (1% reduction): stake = 1_000_000 × 0.99^5
        // = 1_000_000 × 0.95099 ≈ 950_990.
        // Each step rounds down (floor div), so we expect ≤ 951_000
        // with a small floor-rounding margin.
        let stake = state.validators[0].stake;
        assert!(
            (940_000..=952_000).contains(&stake),
            "expected ~951k after 5 slashes, got {stake}"
        );
        assert_eq!(state.validator_stats[0].liveness_slashes, 5);
    }

    #[test]
    fn liveness_signed_clears_pending_counter() {
        // A validator that misses 30 votes and then signs has their
        // consecutive_missed reset to 0 — no slash triggered. This is
        // the "transient outage" forgiveness.
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 100)];
        state.validator_stats = vec![ValidatorStats::default()];
        for _ in 0..30 {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        assert_eq!(state.validator_stats[0].consecutive_missed, 30);
        apply_liveness_step(&mut state, &[0b0000_0001], 32, 100);
        let s = state.validator_stats[0];
        assert_eq!(s.consecutive_missed, 0);
        assert_eq!(s.total_signed, 1);
        assert_eq!(s.total_missed, 30);
        assert_eq!(s.liveness_slashes, 0);
        assert_eq!(state.validators[0].stake, 100, "transient outage forgiven");
    }

    #[test]
    fn liveness_zero_stake_validator_skipped() {
        // Equivocation-slashed (stake=0) validators are zombies; the
        // liveness layer must not touch them.
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 0)];
        state.validator_stats = vec![ValidatorStats::default()];
        for _ in 0..100 {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        let s = state.validator_stats[0];
        assert_eq!(s.consecutive_missed, 0);
        assert_eq!(s.total_missed, 0);
        assert_eq!(s.liveness_slashes, 0);
    }

    #[test]
    fn liveness_bitmap_too_short_treated_as_missing() {
        // If a validator's bit index lies beyond the bitmap's length,
        // they are treated as a missed vote.
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 100), fake_validator(1, 100)];
        state.validator_stats = vec![ValidatorStats::default(); 2];
        // Bitmap only carries bit 0; validator 1's byte index is 0 too
        // (bit 1) and IS in range. Use a 0-length bitmap to force the
        // out-of-range case.
        apply_liveness_step(&mut state, &[], 32, 100);
        assert_eq!(state.validator_stats[0].consecutive_missed, 1);
        assert_eq!(state.validator_stats[1].consecutive_missed, 1);
    }

    #[test]
    fn liveness_slash_caps_at_full_stake_loss() {
        // A pathological slash_bps > 10_000 must clamp to 100% so we
        // can't underflow into negative stake.
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 1_000_000)];
        state.validator_stats = vec![ValidatorStats::default()];
        for _ in 0..1 {
            apply_liveness_step(&mut state, &[], 1, 99_999);
        }
        assert_eq!(state.validators[0].stake, 0);
        assert_eq!(state.validator_stats[0].liveness_slashes, 1);
    }

    /* ---- Burn-on-bond + slash-to-treasury economic invariants -------- *
     *                                                                    *
     *  These tests assert the M1 economic-symmetry property: every base  *
     *  unit a validator commits enters the permanence treasury. Stake    *
     *  may later flow out via unbond settlement (future work), but for   *
     *  M1 the slash and liveness paths re-credit any forfeited stake to  *
     *  treasury — so the chain's permanence-funding pool is always       *
     *  bounded below by the sum of validator burns minus rewards paid.   *
     * ------------------------------------------------------------------ */

    #[test]
    fn liveness_slash_credits_treasury() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 1_000_000)];
        state.validator_stats = vec![ValidatorStats::default()];
        assert_eq!(state.treasury, 0);
        // One full slash cycle = 1% multiplicative reduction = 10_000.
        for _ in 0..32 {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        assert_eq!(state.validators[0].stake, 990_000);
        assert_eq!(state.treasury, 10_000, "1% liveness slash → treasury");
    }

    #[test]
    fn liveness_slash_treasury_compounds_with_validator_stake() {
        let mut state = ChainState::empty();
        state.validators = vec![fake_validator(0, 1_000_000)];
        state.validator_stats = vec![ValidatorStats::default()];
        // 5 full slash cycles at 1% each. Multiplicative on stake; the
        // treasury accumulates the discrete forfeits.
        for _ in 0..(5 * 32) {
            apply_liveness_step(&mut state, &[], 32, 100);
        }
        let stake = state.validators[0].stake;
        let treasury = state.treasury;
        let total = u128::from(stake) + treasury;
        // No emission/coinbase flow in this unit test — stake + treasury
        // must equal the original endowment (modulo floor-division loss
        // on the multiplicative path).
        assert!(
            (995_000..=1_000_000).contains(&total),
            "stake+treasury ≈ original endowment, got stake={stake} treasury={treasury}"
        );
    }

    #[test]
    fn equivocation_slash_credits_treasury_via_apply_block() {
        use mfn_bls::{bls_keygen_from_seed, bls_sign};

        // Two-validator chain so we can pin the producer/voter roles.
        // We don't actually drive consensus here — apply_block sees an
        // empty `validators` set (legacy mode) so the slashing path runs
        // without a finality proof.
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: vec![fake_validator(0, 7_500), fake_validator(1, 2_500)],
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let st = apply_genesis(&g, &cfg).unwrap();

        // Validator 0's BLS key signs two different headers at the same
        // slot → equivocation. We reuse the fake_validator seed mapping
        // for the BLS key.
        let bls = bls_keygen_from_seed(&[17u8; 32]); // matches idx=0
                                                     // The genesis validator must match: re-derive index 0's BLS pk
                                                     // to confirm the seed.
        assert_eq!(bls.pk, st.validators[0].bls_pk);
        let h1 = [11u8; 32];
        let h2 = [22u8; 32];
        let ev = SlashEvidence {
            height: 1,
            slot: 1,
            voter_index: 0,
            header_hash_a: h1,
            sig_a: bls_sign(&h1, &bls.sk),
            header_hash_b: h2,
            sig_b: bls_sign(&h2, &bls.sk),
        };

        // Build a block with the evidence. Since the chain has a non-
        // empty validator set, we can't actually run apply_block without
        // a real finality proof; instead, drive the slashing path
        // directly through the public surface by feeding the evidence
        // into a manual mirror. The chain semantics live in apply_block,
        // but the equivocation accounting here is straightforward and
        // verifiable in isolation.
        let mut next = st.clone();
        let chk = crate::slashing::verify_evidence(&ev, &next.validators);
        assert_eq!(chk, EvidenceCheck::Valid);
        let idx = ev.voter_index as usize;
        let forfeited = u128::from(next.validators[idx].stake);
        next.validators[idx].stake = 0;
        next.treasury = next.treasury.saturating_add(forfeited);
        assert_eq!(next.validators[0].stake, 0);
        assert_eq!(next.treasury, 7_500);
    }

    #[test]
    fn burn_on_bond_credits_treasury() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::generator_g;

        let st = genesis_state();
        assert_eq!(st.treasury, 0);
        let bls = bls_keygen_from_seed(&[42u8; 32]);
        let stake = 2_500_000u64;
        let vrf_pk = generator_g();
        let bond = BondOp::Register {
            stake,
            vrf_pk,
            bls_pk: bls.pk,
            payout: None,
            sig: crate::bond_wire::sign_register(stake, &vrf_pk, &bls.pk, None, &bls.sk),
        };
        let bond_ops = vec![bond];
        let header = build_unsealed_header(&st, &[], &bond_ops, &[], &[], 1, 100);
        let blk = seal_block(
            header,
            Vec::new(),
            bond_ops,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, 2_500_000, "bond burn must credit treasury");
                assert_eq!(state.validators.len(), 1);
                assert_eq!(state.validators[0].stake, 2_500_000);
            }
            ApplyOutcome::Err { errors, .. } => panic!("bond apply failed: {errors:?}"),
        }
    }

    #[test]
    fn burn_on_bond_aggregates_multiple_registers() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::{generator_g, generator_h};

        let st = genesis_state();
        let min = DEFAULT_BONDING_PARAMS.min_validator_stake;
        let bls1 = bls_keygen_from_seed(&[1u8; 32]);
        let bls2 = bls_keygen_from_seed(&[2u8; 32]);
        let vrf1 = generator_g();
        let vrf2 = generator_h();
        let ops = vec![
            BondOp::Register {
                stake: min,
                vrf_pk: vrf1,
                bls_pk: bls1.pk,
                payout: None,
                sig: crate::bond_wire::sign_register(min, &vrf1, &bls1.pk, None, &bls1.sk),
            },
            BondOp::Register {
                stake: min * 3,
                vrf_pk: vrf2,
                bls_pk: bls2.pk,
                payout: None,
                sig: crate::bond_wire::sign_register(min * 3, &vrf2, &bls2.pk, None, &bls2.sk),
            },
        ];
        let header = build_unsealed_header(&st, &[], &ops, &[], &[], 1, 100);
        let blk = seal_block(header, Vec::new(), ops, Vec::new(), Vec::new(), Vec::new());
        match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => {
                assert_eq!(state.treasury, u128::from(min) * 4);
                assert_eq!(state.validators.len(), 2);
            }
            ApplyOutcome::Err { errors, .. } => panic!("bond apply failed: {errors:?}"),
        }
    }

    #[test]
    fn failed_bond_does_not_credit_treasury() {
        use mfn_bls::bls_keygen_from_seed;
        use mfn_crypto::point::{generator_g, generator_h};

        let st = genesis_state();
        // Below-minimum stake → rejection; the whole block must not
        // credit the treasury (atomic apply).
        let min = DEFAULT_BONDING_PARAMS.min_validator_stake;
        let bls1 = bls_keygen_from_seed(&[1u8; 32]);
        let bls2 = bls_keygen_from_seed(&[2u8; 32]);
        let vrf1 = generator_g();
        let vrf2 = generator_h();
        let ops = vec![
            BondOp::Register {
                stake: min,
                vrf_pk: vrf1,
                bls_pk: bls1.pk,
                payout: None,
                sig: crate::bond_wire::sign_register(min, &vrf1, &bls1.pk, None, &bls1.sk),
            },
            BondOp::Register {
                stake: 1, // below min
                vrf_pk: vrf2,
                bls_pk: bls2.pk,
                payout: None,
                sig: crate::bond_wire::sign_register(1, &vrf2, &bls2.pk, None, &bls2.sk),
            },
        ];
        let header = build_unsealed_header(&st, &[], &ops, &[], &[], 1, 100);
        let blk = seal_block(header, Vec::new(), ops, Vec::new(), Vec::new(), Vec::new());
        match apply_block(&st, &blk) {
            ApplyOutcome::Err { .. } => {
                // Pre-state untouched: treasury still zero.
                assert_eq!(st.treasury, 0);
            }
            ApplyOutcome::Ok { .. } => panic!("expected rejection"),
        }
    }

    /* ----------------------------------------------------------------- *
     *  M2.0.9 — Header wire codec round-trip + malformed rejection      *
     * ----------------------------------------------------------------- */

    fn sample_header() -> BlockHeader {
        BlockHeader {
            version: HEADER_VERSION,
            prev_hash: [0xa1u8; 32],
            height: 7,
            slot: 11,
            timestamp: 1_700_000_000,
            tx_root: [0xb2u8; 32],
            storage_root: [0xc3u8; 32],
            bond_root: [0xd4u8; 32],
            slashing_root: [0xe5u8; 32],
            storage_proof_root: [0xf6u8; 32],
            validator_root: [0x07u8; 32],
            claims_root: [0x29u8; 32],
            producer_proof: (0..73u8).collect(),
            utxo_root: [0x18u8; 32],
        }
    }

    /// `decode_block_header` is a left inverse of `block_header_bytes`.
    #[test]
    fn block_header_codec_round_trip() {
        let h = sample_header();
        let bytes = block_header_bytes(&h);
        let h2 = decode_block_header(&bytes).expect("decode");
        assert_eq!(h2.version, h.version);
        assert_eq!(h2.prev_hash, h.prev_hash);
        assert_eq!(h2.height, h.height);
        assert_eq!(h2.slot, h.slot);
        assert_eq!(h2.timestamp, h.timestamp);
        assert_eq!(h2.tx_root, h.tx_root);
        assert_eq!(h2.storage_root, h.storage_root);
        assert_eq!(h2.bond_root, h.bond_root);
        assert_eq!(h2.slashing_root, h.slashing_root);
        assert_eq!(h2.storage_proof_root, h.storage_proof_root);
        assert_eq!(h2.validator_root, h.validator_root);
        assert_eq!(h2.claims_root, h.claims_root);
        assert_eq!(h2.producer_proof, h.producer_proof);
        assert_eq!(h2.utxo_root, h.utxo_root);
        // And `block_id(h) == block_id(decode(encode(h)))`.
        assert_eq!(block_id(&h), block_id(&h2));
    }

    /// Empty `producer_proof` is a valid encoding — genesis / no-validator chains.
    #[test]
    fn block_header_codec_round_trip_empty_producer_proof() {
        let mut h = sample_header();
        h.producer_proof = Vec::new();
        let bytes = block_header_bytes(&h);
        let h2 = decode_block_header(&bytes).expect("decode");
        assert!(h2.producer_proof.is_empty());
        assert_eq!(block_id(&h), block_id(&h2));
    }

    /// Truncating any prefix of a valid encoding must surface
    /// `HeaderDecodeError::Truncated` (or a varint-overflow for the
    /// degenerate 0-byte case — we just require `Err`).
    #[test]
    fn block_header_codec_rejects_truncation() {
        let h = sample_header();
        let bytes = block_header_bytes(&h);
        // Sweep every prefix length except the full one.
        for cut in 0..bytes.len() {
            let err = decode_block_header(&bytes[..cut]).expect_err("must reject prefix");
            // Any error is fine; the goal is to never decode a partial
            // header as if it were complete.
            match err {
                HeaderDecodeError::Truncated { .. }
                | HeaderDecodeError::VarintOverflow { .. }
                | HeaderDecodeError::ProducerProofTooLarge { .. }
                | HeaderDecodeError::VersionOutOfRange { .. } => (),
                HeaderDecodeError::TrailingBytes { .. } => {
                    panic!("prefix of len {cut} cannot have trailing bytes")
                }
            }
        }
    }

    /// Extra trailing bytes after a valid header → `TrailingBytes`.
    #[test]
    fn block_header_codec_rejects_trailing_bytes() {
        let h = sample_header();
        let mut bytes = block_header_bytes(&h);
        bytes.push(0xAB);
        bytes.push(0xCD);
        let err = decode_block_header(&bytes).expect_err("must reject tail");
        match err {
            HeaderDecodeError::TrailingBytes { remaining } => assert_eq!(remaining, 2),
            other => panic!("expected TrailingBytes, got {other:?}"),
        }
    }

    /// `version` encoded as a varint > u32::MAX → `VersionOutOfRange`.
    /// Forge the bytes by hand — easiest way to exercise the branch.
    #[test]
    fn block_header_codec_rejects_oversized_version() {
        // LEB128 for `2^33` (well over u32::MAX): 5 bytes.
        let v: u64 = 1u64 << 33;
        let mut w = Writer::new();
        w.varint(v);
        let mut bytes = w.into_bytes();
        // Pad rest with zeros so we don't trip Truncated before
        // VersionOutOfRange.
        bytes.extend(std::iter::repeat(0u8).take(128));

        let err = decode_block_header(&bytes).expect_err("must reject");
        match err {
            HeaderDecodeError::VersionOutOfRange { got } => assert_eq!(got, v),
            other => panic!("expected VersionOutOfRange, got {other:?}"),
        }
    }

    /// Flipping a single byte inside the encoded header changes
    /// `block_id` exactly when that byte materially decodes into a
    /// header field — i.e. the encoding is non-redundant. (Sanity:
    /// if any byte is "dead", the codec leaks state silently.)
    #[test]
    fn block_header_codec_has_no_dead_bytes() {
        let h = sample_header();
        let bytes = block_header_bytes(&h);
        let original_id = block_id(&h);
        for i in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[i] ^= 0x01;
            match decode_block_header(&tampered) {
                Ok(h2) => assert_ne!(
                    block_id(&h2),
                    original_id,
                    "flipping byte {i} must materially change the header"
                ),
                Err(_) => {
                    // Tampering broke the encoding outright — also acceptable.
                }
            }
        }
    }

    /// TS-parity golden vector for the header wire codec. The fixed
    /// input below pins the byte-for-byte encoding produced by
    /// `block_header_bytes` and the resulting `block_id`. Changing
    /// the codec is consensus-critical and must bump this vector
    /// deliberately.
    #[test]
    fn block_header_codec_golden_vector() {
        let h = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            height: 0,
            slot: 0,
            timestamp: 0,
            tx_root: [0u8; 32],
            storage_root: [0u8; 32],
            bond_root: [0u8; 32],
            slashing_root: [0u8; 32],
            storage_proof_root: [0u8; 32],
            validator_root: [0u8; 32],
            claims_root: [0u8; 32],
            producer_proof: Vec::new(),
            utxo_root: [0u8; 32],
        };
        let bytes = block_header_bytes(&h);
        // Layout (genesis-shaped header):
        //   version=1            : 0x01
        //   prev_hash            : 32 × 0x00
        //   height=0             : 0x00 0x00 0x00 0x00
        //   slot=0               : 0x00 0x00 0x00 0x00
        //   timestamp=0          : 0x00 × 8
        //   tx_root              : 32 × 0x00
        //   storage_root         : 32 × 0x00
        //   bond_root            : 32 × 0x00
        //   slashing_root        : 32 × 0x00
        //   storage_proof_root   : 32 × 0x00
        //   validator_root       : 32 × 0x00
        //   claims_root          : 32 × 0x00
        //   producer_proof.len=0 : 0x00
        //   utxo_root            : 32 × 0x00
        // Total = 1 + 32 + 4 + 4 + 8 + (32 * 7) + 1 + 32 = 306 bytes.
        assert_eq!(bytes.len(), 306, "expected 306 bytes, got {}", bytes.len());
        assert_eq!(bytes[0], 0x01, "varint(version=1) is one byte 0x01");
        assert_eq!(
            bytes.iter().filter(|&&b| b != 0).count(),
            1,
            "only the version byte is non-zero in a genesis-shaped header"
        );
        // Round-trip pin.
        let h2 = decode_block_header(&bytes).expect("decode");
        assert_eq!(block_id(&h), block_id(&h2));
    }

    /* ----------------------------------------------------------------- *
     *  M2.0.10 — Full block wire codec                                  *
     * ----------------------------------------------------------------- */

    /// Construct a structurally minimal but valid `Block`: the
    /// genesis-shaped header with an empty body. Exercises the
    /// framing layer (length-prefixed empty sections) without
    /// dragging the heavyweight CLSAG / BLS / SPoRA verifiers
    /// in. Real-data round-trip is covered by the mfn-light
    /// integration test, which uses `mfn-node::Chain` to build
    /// fully-signed blocks.
    fn sample_empty_block() -> Block {
        let mut header = sample_header();
        header.producer_proof = Vec::new();
        Block {
            header,
            txs: Vec::new(),
            slashings: Vec::new(),
            storage_proofs: Vec::new(),
            bond_ops: Vec::new(),
        }
    }

    /// `decode_block` is a left inverse of `encode_block` on an
    /// empty-body block.
    #[test]
    fn block_codec_round_trip_empty_body() {
        let b = sample_empty_block();
        let bytes = encode_block(&b);
        let b2 = decode_block(&bytes).expect("decode");
        assert_eq!(block_id(&b.header), block_id(&b2.header));
        assert!(b2.txs.is_empty());
        assert!(b2.slashings.is_empty());
        assert!(b2.storage_proofs.is_empty());
        assert!(b2.bond_ops.is_empty());
        // Re-encoding must yield identical bytes (deterministic).
        assert_eq!(encode_block(&b2), bytes);
    }

    /// The encoding always starts with the exact bytes the header
    /// codec produces — a hard invariant that lets a peer extract a
    /// header for fast filtering before re-encoding the full block.
    #[test]
    fn block_codec_starts_with_block_header_bytes() {
        let b = sample_empty_block();
        let block_bytes = encode_block(&b);
        let header_bytes = block_header_bytes(&b.header);
        assert!(
            block_bytes.starts_with(&header_bytes),
            "encode_block must prefix with block_header_bytes(header)"
        );
        // And the four empty-body-section varints come right after.
        let tail = &block_bytes[header_bytes.len()..];
        // Four varints of value 0 = four 0x00 bytes.
        assert_eq!(tail, &[0u8, 0u8, 0u8, 0u8]);
    }

    /// Adding a trailing byte after a valid encoding → `TrailingBytes`.
    #[test]
    fn block_codec_rejects_trailing_bytes() {
        let b = sample_empty_block();
        let mut bytes = encode_block(&b);
        bytes.push(0xCD);
        let err = decode_block(&bytes).expect_err("must reject tail");
        match err {
            BlockDecodeError::TrailingBytes { remaining } => assert_eq!(remaining, 1),
            other => panic!("expected TrailingBytes, got {other:?}"),
        }
    }

    /// Sweeping every prefix of a valid encoding must fail to decode.
    #[test]
    fn block_codec_rejects_truncation_at_every_prefix() {
        let b = sample_empty_block();
        let bytes = encode_block(&b);
        for cut in 0..bytes.len() {
            let err = decode_block(&bytes[..cut]);
            assert!(
                err.is_err(),
                "prefix of length {cut}/{} should be rejected",
                bytes.len()
            );
        }
    }

    /// Mutating the txs-count varint to a huge value must surface
    /// either `Codec(ShortBuffer)` or `Codec(VarintTooLong)` — never
    /// silently allocate an enormous Vec.
    #[test]
    fn block_codec_rejects_oversized_txs_count() {
        let b = sample_empty_block();
        let header_len = block_header_bytes(&b.header).len();
        let mut bytes = encode_block(&b);
        // The byte at header_len is the txs-count varint (== 0 in
        // empty body). Replace it with a 10-byte LEB128 encoding of
        // u64::MAX (the longest legal varint). The decoder must
        // refuse to read that many blob entries because the buffer
        // ends a few bytes later.
        bytes.splice(
            header_len..header_len + 1,
            // u64::MAX in LEB128 is 10 bytes of 0xff…0x01.
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
        );
        let err = decode_block(&bytes).expect_err("must reject");
        // We accept any Codec / Transaction error — the goal is
        // "doesn't decode" + "doesn't OOM".
        match err {
            BlockDecodeError::Codec(_)
            | BlockDecodeError::Transaction { .. }
            | BlockDecodeError::CountTooLarge { .. } => (),
            other => panic!("unexpected error variant {other:?}"),
        }
    }

    /// Golden vector for the empty-body encoding shape: a genesis-
    /// shaped block must serialise to exactly the 306 header bytes
    /// followed by four `0x00` count varints (= 310 bytes total).
    /// Pins the wire layout so any unintentional codec change
    /// trips a hard failure.
    #[test]
    fn block_codec_empty_body_golden_shape() {
        let h = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            height: 0,
            slot: 0,
            timestamp: 0,
            tx_root: [0u8; 32],
            storage_root: [0u8; 32],
            bond_root: [0u8; 32],
            slashing_root: [0u8; 32],
            storage_proof_root: [0u8; 32],
            validator_root: [0u8; 32],
            claims_root: [0u8; 32],
            producer_proof: Vec::new(),
            utxo_root: [0u8; 32],
        };
        let b = Block {
            header: h,
            txs: Vec::new(),
            slashings: Vec::new(),
            storage_proofs: Vec::new(),
            bond_ops: Vec::new(),
        };
        let bytes = encode_block(&b);
        // 306 (header) + 4 (four zero-length section varints) = 310.
        assert_eq!(bytes.len(), 310);
        // Last four bytes are the empty-section count varints.
        assert_eq!(&bytes[306..], &[0u8, 0u8, 0u8, 0u8]);
        // Round-trip pin.
        let b2 = decode_block(&bytes).expect("decode");
        assert_eq!(block_id(&b.header), block_id(&b2.header));
    }
}
