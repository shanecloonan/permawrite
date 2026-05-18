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

#![allow(unused_imports)]

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
    authorship_claim_key, check_claim_key_unique, check_claim_storage_binding, claim_to_record,
    claims_merkle_root, collect_claim_merkle_leaves_for_txs, verified_claims_for_tx,
    AuthorshipClaimVerifyError, VerifiedClaimsForTxResult,
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
