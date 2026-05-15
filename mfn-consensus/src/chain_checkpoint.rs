//! `ChainState` checkpoint codec (M2.0.15).
//!
//! Deterministic, IO-free byte serialisation of every field on
//! [`crate::block::ChainState`] plus the chain's `genesis_id` pointer.
//! Pair the encoder with any persistence backend (file, RocksDB, S3 …);
//! this module concerns itself only with *what* the bytes are.
//!
//! ## Wire layout (v2, current)
//!
//! v2 extends v1 by inserting authorship-claim persistence **after** the
//! `storage` map and **before** the `utxo_tree` blob:
//!
//! ```text
//!   claims.len()              varint   (sorted ascending by 32-byte data_root key)
//!     data_root                 [32]
//!     records.len()           varint
//!       wire.len()            varint
//!       wire                    bytes   MFCL authorship claim
//!       tx_id                   [32]
//!       height                  u32
//!       tx_index                u32
//!       claim_index             u32
//!
//!   claim_submitted.len()    varint   (sorted ascending 32-byte leaf hashes)
//!     leaf_hash                 [32]
//! ```
//!
//! v1 checkpoints (version field `1`) omit this section entirely; decoders
//! populate empty `claims` / `claim_submitted` maps.
//!
//! ```text
//!   magic                       [4]   "MFCC" (M(oney)F(und) C(hain) C(heckpoint))
//!   version                      u32   currently 2 (v1 supported on decode only)
//!
//!   genesis_id                  [32]
//!   height_flag                   u8   0 = pre-genesis, 1 = present
//!   height                       u32   only if height_flag == 1
//!
//!   block_ids.len()           varint
//!     block_ids[i]              [32]
//!
//!   ConsensusParams            (4×u32 + 1×u64 of f64 bits)
//!   BondingParams              (1×u64 + 4×u32)
//!   EmissionParams             (4×u64 + 1×u32 + 1×u16)
//!   EndowmentParams            (4×u64 + 2×u8 + 2×u64)
//!
//!   treasury                    u128
//!
//!   bond_counters              (1×u64 + 3×u32)
//!
//!   validators.len()          varint
//!     validator                (validator_codec wire layout — matches
//!                                mfn-light's CheckpointParts codec)
//!
//!   validator_stats.len()     varint   (== validators.len)
//!     ValidatorStats           (1×u32 + 2×u64 + 1×u32)
//!
//!   pending_unbonds.len()     varint
//!     PendingUnbond            (3×u32 + 1×u64)
//!
//!   utxo.len()                varint   (sorted ascending by 32-byte key)
//!     key                       [32]
//!     UtxoEntry                (32-byte commit + u32 height)
//!
//!   spent_key_images.len()    varint   (sorted ascending by 32-byte key)
//!     key                       [32]
//!
//!   storage.len()             varint   (sorted ascending by 32-byte key)
//!     key                       [32]
//!     StorageEntry             (encode_storage_commitment + u32 + u64 + u128)
//!
//!   (v2 only) authorship `claims` + `claim_submitted` — see the v2 section above
//!
//!   utxo_tree                  bytes   (encode_utxo_tree_state wire form,
//!                                       length-prefixed)
//!
//!   tag                        [32]   dhash(CHAIN_CHECKPOINT, &[payload])
//! ```
//!
//! Hash-map / set fields are emitted **sorted by key** so two
//! `ChainState` values that are semantically equal always encode to the
//! same bytes.  The trailing `tag` covers every byte before it: a single
//! flip detects truncation, payload tamper, or tag tamper.
//!
//! Domain-separated from [`mfn_crypto::domain::LIGHT_CHECKPOINT`] via
//! [`mfn_crypto::domain::CHAIN_CHECKPOINT`] so a light-client checkpoint
//! handed to the full-node decoder (or vice-versa) fails the integrity
//! check rather than producing a partial decode.

use std::collections::{BTreeMap, HashMap, HashSet};

use mfn_crypto::authorship::{decode_authorship_claim, encode_authorship_claim};
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::CHAIN_CHECKPOINT;
use mfn_crypto::hash::dhash;
use mfn_crypto::utxo_tree::{
    decode_utxo_tree_state, encode_utxo_tree_state, UtxoTreeDecodeError, UtxoTreeState,
};
use mfn_storage::{
    decode_storage_commitment, encode_storage_commitment, EndowmentParams, DEFAULT_ENDOWMENT_PARAMS,
};

use crate::block::{ChainState, PendingUnbond, StorageEntry, UtxoEntry, DEFAULT_CONSENSUS_PARAMS};
use crate::bonding::DEFAULT_BONDING_PARAMS;
use crate::checkpoint_codec::{
    check_validator_assignment, decode_bonding_params, decode_consensus_params,
    decode_pending_unbond, decode_validator, decode_validator_stats, encode_bonding_params,
    encode_consensus_params, encode_pending_unbond, encode_validator, encode_validator_stats,
    read_edwards_point, read_fixed, read_len, read_u128, read_u16, read_u32, read_u64, read_u8,
    CheckpointReadError, EdwardsReadError,
};
use crate::claims::AuthorshipClaimRecord;
use crate::emission::{EmissionParams, DEFAULT_EMISSION_PARAMS};
use crate::validator_evolution::BondEpochCounters;

/// 4-byte magic header. ASCII `"MFCC"` = `M(oney)F(und) C(hain) C(heckpoint)`.
pub const CHAIN_CHECKPOINT_MAGIC: [u8; 4] = *b"MFCC";

/// Currently-supported chain-checkpoint format version. Bumped only on
/// wire-incompatible changes.
pub const CHAIN_CHECKPOINT_VERSION: u32 = 2;

/// Errors produced by the chain-checkpoint codec.
///
/// `encode_chain_checkpoint` is infallible — every variant here is a
/// **decode** failure. Per-field decode failures (truncation, invalid
/// public keys, validator-list invariants) flow through a single
/// [`Read`](Self::Read) variant carrying the shared
/// [`CheckpointReadError`] (M2.0.16).
#[derive(Debug, thiserror::Error)]
pub enum ChainCheckpointError {
    /// Magic bytes did not match [`CHAIN_CHECKPOINT_MAGIC`].
    #[error("bad chain-checkpoint magic: got {got:02x?}, want {want:02x?}", want = CHAIN_CHECKPOINT_MAGIC)]
    BadMagic {
        /// Raw 4-byte prefix found in the payload.
        got: [u8; 4],
    },

    /// Format version is not supported by this build.
    #[error("unsupported chain-checkpoint version {got}; this build supports versions 1 and 2")]
    UnsupportedVersion {
        /// The version encoded in the payload.
        got: u32,
    },

    /// A shared per-field decode failure (truncation, invalid public
    /// key, validator-list invariant violation, etc.). Surfaced
    /// verbatim from [`mfn_consensus::checkpoint_codec`](crate::checkpoint_codec).
    #[error(transparent)]
    Read(#[from] CheckpointReadError),

    /// `height_flag` byte was not 0 or 1.
    #[error("chain-checkpoint invalid height_flag {flag} (must be 0 or 1)")]
    InvalidHeightFlag {
        /// Raw byte read.
        flag: u8,
    },

    /// A `utxo` map entry's key did not strictly exceed the previous
    /// one — duplicate or out-of-order.
    #[error("chain-checkpoint utxo entries not strictly ascending at position {index}")]
    UtxoNotSorted {
        /// Position in the `utxo` list.
        index: usize,
    },

    /// A `UtxoEntry::commit` failed to decompress.
    #[error("chain-checkpoint utxo[{index}]: invalid amount commitment")]
    InvalidUtxoCommit {
        /// Position in the `utxo` list.
        index: usize,
    },

    /// `spent_key_images` entries were not strictly ascending.
    #[error("chain-checkpoint spent_key_images not strictly ascending at position {index}")]
    SpentKeyImagesNotSorted {
        /// Position in the `spent_key_images` list.
        index: usize,
    },

    /// `storage` map entries were not strictly ascending by data-root key.
    #[error("chain-checkpoint storage entries not strictly ascending at position {index}")]
    StorageNotSorted {
        /// Position in the `storage` list.
        index: usize,
    },

    /// `claims` map keys were not strictly ascending.
    #[error("chain-checkpoint claims entries not strictly ascending at position {index}")]
    ClaimsNotSorted {
        /// Position in the sorted `claims` key list.
        index: usize,
    },

    /// A claim record's `data_root` key did not match the embedded MFCL payload.
    #[error("chain-checkpoint claims[{outer}].records[{inner}]: data_root key mismatch")]
    ClaimsRecordKeyMismatch {
        /// Claim map entry index.
        outer: usize,
        /// Record index within that entry.
        inner: usize,
    },

    /// `claim_submitted` hashes were not strictly ascending.
    #[error("chain-checkpoint claim_submitted not strictly ascending at position {index}")]
    ClaimSubmittedNotSorted {
        /// Position in the sorted leaf list.
        index: usize,
    },

    /// MFCL decode failed for a persisted claim record.
    #[error("chain-checkpoint authorship claim wire: {0}")]
    AuthorshipClaimWire(String),

    /// A `StorageEntry.commit` failed to decode.
    #[error("chain-checkpoint storage[{index}]: invalid storage commitment: {source}")]
    InvalidStorageCommitment {
        /// Position in the `storage` list.
        index: usize,
        /// The underlying storage-commitment decode error.
        #[source]
        source: mfn_crypto::CryptoError,
    },

    /// The embedded `utxo_tree` blob failed to decode.
    #[error("chain-checkpoint invalid utxo_tree: {source}")]
    InvalidUtxoTree {
        /// The underlying utxo-tree decode error.
        #[source]
        source: UtxoTreeDecodeError,
    },

    /// The trailing integrity tag did not match a recomputation over
    /// the payload — payload was tampered, truncated, or wired into
    /// the wrong decoder.
    #[error("chain-checkpoint integrity check failed (payload tampered or truncated)")]
    IntegrityCheckFailed,

    /// Bytes remained after a successful decode.
    #[error("{remaining} trailing byte(s) after chain-checkpoint tag")]
    TrailingBytes {
        /// Number of unread bytes after a successful payload decode.
        remaining: usize,
    },
}

/// All the data persisted by a chain checkpoint, plus the genesis-id
/// pointer the [`crate::block::Chain`] driver caches alongside its
/// [`ChainState`].
///
/// This is the **logical** unit of persistence: encode it on shutdown,
/// decode it on startup. Internally it is a thin re-shape of
/// [`ChainState`] + `genesis_id`; persistence intentionally does not
/// touch the in-memory `zeros` chain of the UTXO accumulator (it is
/// derived from [`mfn_crypto::utxo_tree::UTXO_TREE_DEPTH`] and
/// reconstructed on decode).
#[derive(Clone, Debug)]
pub struct ChainCheckpoint {
    /// Cached genesis block id. Stored explicitly so a restored chain
    /// can answer "what's our chain id" without re-running `build_genesis`.
    pub genesis_id: [u8; 32],

    /// Full chain state at the tip the checkpoint was taken at.
    pub state: ChainState,
}

/* ----------------------------------------------------------------------- *
 *  Encode                                                                   *
 * ----------------------------------------------------------------------- */

fn encode_emission_params(w: &mut Writer, p: &EmissionParams) {
    w.u64(p.initial_reward);
    w.u64(p.halving_period);
    w.u32(p.halving_count);
    w.u64(p.tail_emission);
    w.u64(p.storage_proof_reward);
    // u16 — emit as 2 BE bytes.
    w.push(&p.fee_to_treasury_bps.to_be_bytes());
}

fn encode_endowment_params(w: &mut Writer, p: &EndowmentParams) {
    w.u64(p.cost_per_byte_year_ppb);
    w.u64(p.inflation_ppb);
    w.u64(p.real_yield_ppb);
    w.u8(p.min_replication);
    w.u8(p.max_replication);
    w.u64(p.slots_per_year);
    w.u64(p.proof_reward_window_slots);
}

fn encode_u128(w: &mut Writer, v: u128) {
    w.push(&v.to_be_bytes());
}

fn encode_utxo_entry(w: &mut Writer, e: &UtxoEntry) {
    w.push(&e.commit.compress().to_bytes());
    w.u32(e.height);
}

fn encode_storage_entry(w: &mut Writer, e: &StorageEntry) {
    let commit_bytes = encode_storage_commitment(&e.commit);
    w.varint(commit_bytes.len() as u64);
    w.push(&commit_bytes);
    w.u32(e.last_proven_height);
    w.u64(e.last_proven_slot);
    encode_u128(w, e.pending_yield_ppb);
}

fn encode_authorship_claim_record(w: &mut Writer, rec: &AuthorshipClaimRecord) {
    let wire = encode_authorship_claim(&rec.claim)
        .expect("checkpoint only serializes consensus-valid authorship claims");
    w.varint(wire.len() as u64);
    w.push(&wire);
    w.push(&rec.tx_id);
    w.u32(rec.height);
    w.u32(rec.tx_index);
    w.u32(rec.claim_index);
}

fn encode_claims_state(w: &mut Writer, state: &ChainState) {
    w.varint(state.claims.len() as u64);
    for (data_root, records) in &state.claims {
        w.push(data_root);
        w.varint(records.len() as u64);
        for rec in records {
            encode_authorship_claim_record(w, rec);
        }
    }
    let mut submitted: Vec<&[u8; 32]> = state.claim_submitted.iter().collect();
    submitted.sort();
    w.varint(submitted.len() as u64);
    for h in submitted {
        w.push(h.as_slice());
    }
}

/// Encode a [`ChainCheckpoint`] to its canonical bytes.
///
/// Always produces the same output for the same input — including the
/// final integrity tag. Length grows linearly in the unioned size of
/// `utxo`, `spent_key_images`, `storage`, `block_ids`, `validators`,
/// `validator_stats`, `pending_unbonds`, and the sparse `utxo_tree`.
#[must_use]
pub fn encode_chain_checkpoint(parts: &ChainCheckpoint) -> Vec<u8> {
    let mut w = Writer::new();

    // ---- Header ----
    w.push(&CHAIN_CHECKPOINT_MAGIC);
    w.u32(CHAIN_CHECKPOINT_VERSION);

    // ---- Identity ----
    w.push(&parts.genesis_id);

    // ---- Optional height ----
    match parts.state.height {
        None => {
            w.u8(0);
        }
        Some(h) => {
            w.u8(1);
            w.u32(h);
        }
    }

    // ---- Block-id chain ----
    w.varint(parts.state.block_ids.len() as u64);
    for id in &parts.state.block_ids {
        w.push(id);
    }

    // ---- Frozen params ----
    encode_consensus_params(&mut w, &parts.state.params);
    encode_bonding_params(&mut w, &parts.state.bonding_params);
    encode_emission_params(&mut w, &parts.state.emission_params);
    encode_endowment_params(&mut w, &parts.state.endowment_params);

    // ---- Treasury ----
    encode_u128(&mut w, parts.state.treasury);

    // ---- Bond counters (flat on ChainState) ----
    w.u64(parts.state.bond_epoch_id);
    w.u32(parts.state.bond_epoch_entry_count);
    w.u32(parts.state.bond_epoch_exit_count);
    w.u32(parts.state.next_validator_index);

    // ---- Validators (preserved order — consensus root depends on it) ----
    w.varint(parts.state.validators.len() as u64);
    for v in &parts.state.validators {
        encode_validator(&mut w, v);
    }

    // ---- Validator stats (1:1 with validators) ----
    w.varint(parts.state.validator_stats.len() as u64);
    for s in &parts.state.validator_stats {
        encode_validator_stats(&mut w, s);
    }

    // ---- Pending unbonds (BTreeMap iterates ascending by key) ----
    w.varint(parts.state.pending_unbonds.len() as u64);
    for p in parts.state.pending_unbonds.values() {
        encode_pending_unbond(&mut w, p);
    }

    // ---- UTXO map (sorted by 32-byte key) ----
    let mut utxo_keys: Vec<&[u8; 32]> = parts.state.utxo.keys().collect();
    utxo_keys.sort();
    w.varint(utxo_keys.len() as u64);
    for k in utxo_keys {
        w.push(k);
        encode_utxo_entry(&mut w, &parts.state.utxo[k]);
    }

    // ---- Spent key images (sorted) ----
    let mut spent_keys: Vec<&[u8; 32]> = parts.state.spent_key_images.iter().collect();
    spent_keys.sort();
    w.varint(spent_keys.len() as u64);
    for k in spent_keys {
        w.push(k);
    }

    // ---- Storage map (sorted by data-root key) ----
    let mut storage_keys: Vec<&[u8; 32]> = parts.state.storage.keys().collect();
    storage_keys.sort();
    w.varint(storage_keys.len() as u64);
    for k in storage_keys {
        w.push(k);
        encode_storage_entry(&mut w, &parts.state.storage[k]);
    }

    encode_claims_state(&mut w, &parts.state);

    // ---- UTXO accumulator (length-prefixed nested blob) ----
    let utxo_tree_bytes = encode_utxo_tree_state(&parts.state.utxo_tree);
    w.varint(utxo_tree_bytes.len() as u64);
    w.push(&utxo_tree_bytes);

    // ---- Trailing integrity tag ----
    let payload = w.into_bytes();
    let tag = dhash(CHAIN_CHECKPOINT, &[&payload]);
    let mut out = payload;
    out.extend_from_slice(&tag);
    out
}

/* ----------------------------------------------------------------------- *
 *  Decode                                                                   *
 * ----------------------------------------------------------------------- */

fn decode_emission_params(r: &mut Reader<'_>) -> Result<EmissionParams, ChainCheckpointError> {
    Ok(EmissionParams {
        initial_reward: read_u64(r, "emission_params.initial_reward")?,
        halving_period: read_u64(r, "emission_params.halving_period")?,
        halving_count: read_u32(r, "emission_params.halving_count")?,
        tail_emission: read_u64(r, "emission_params.tail_emission")?,
        storage_proof_reward: read_u64(r, "emission_params.storage_proof_reward")?,
        fee_to_treasury_bps: read_u16(r, "emission_params.fee_to_treasury_bps")?,
    })
}

fn decode_endowment_params(r: &mut Reader<'_>) -> Result<EndowmentParams, ChainCheckpointError> {
    Ok(EndowmentParams {
        cost_per_byte_year_ppb: read_u64(r, "endowment_params.cost_per_byte_year_ppb")?,
        inflation_ppb: read_u64(r, "endowment_params.inflation_ppb")?,
        real_yield_ppb: read_u64(r, "endowment_params.real_yield_ppb")?,
        min_replication: read_u8(r, "endowment_params.min_replication")?,
        max_replication: read_u8(r, "endowment_params.max_replication")?,
        slots_per_year: read_u64(r, "endowment_params.slots_per_year")?,
        proof_reward_window_slots: read_u64(r, "endowment_params.proof_reward_window_slots")?,
    })
}

fn decode_utxo_entry(r: &mut Reader<'_>, index: usize) -> Result<UtxoEntry, ChainCheckpointError> {
    let commit = read_edwards_point(r, "utxo[i].commit").map_err(|e| match e {
        EdwardsReadError::Truncated { field, needed } => {
            ChainCheckpointError::Read(CheckpointReadError::Truncated { field, needed })
        }
        EdwardsReadError::InvalidPoint => ChainCheckpointError::InvalidUtxoCommit { index },
    })?;
    let height = read_u32(r, "utxo[i].height")?;
    Ok(UtxoEntry { commit, height })
}

fn decode_storage_entry(
    r: &mut Reader<'_>,
    index: usize,
) -> Result<StorageEntry, ChainCheckpointError> {
    // The inner storage-commitment codec enforces "no trailing bytes"
    // itself, so we hand it exactly the slice we framed on the encode
    // side and propagate any structural error verbatim.
    let commit_len = read_len(r, "storage[i].commit.len")?;
    let commit_slice = r
        .bytes(commit_len)
        .map_err(|_| CheckpointReadError::Truncated {
            field: "storage[i].commit",
            needed: commit_len,
        })?;
    let commit = decode_storage_commitment(commit_slice)
        .map_err(|source| ChainCheckpointError::InvalidStorageCommitment { index, source })?;
    let last_proven_height = read_u32(r, "storage[i].last_proven_height")?;
    let last_proven_slot = read_u64(r, "storage[i].last_proven_slot")?;
    let pending_yield_ppb = read_u128(r, "storage[i].pending_yield_ppb")?;
    Ok(StorageEntry {
        commit,
        last_proven_height,
        last_proven_slot,
        pending_yield_ppb,
    })
}

fn decode_authorship_claim_record(
    r: &mut Reader<'_>,
    outer: usize,
    inner: usize,
    expected_data_root: &[u8; 32],
) -> Result<AuthorshipClaimRecord, ChainCheckpointError> {
    let wire_len = read_len(r, "claims.record.wire.len")?;
    let wire = r
        .bytes(wire_len)
        .map_err(|_| CheckpointReadError::Truncated {
            field: "claims.record.wire",
            needed: wire_len,
        })?;
    let claim = decode_authorship_claim(wire).map_err(|e| {
        ChainCheckpointError::AuthorshipClaimWire(format!("claims[{outer}].records[{inner}]: {e}"))
    })?;
    if &claim.data_root != expected_data_root {
        return Err(ChainCheckpointError::ClaimsRecordKeyMismatch { outer, inner });
    }
    let tx_id = read_fixed(r, "claims.record.tx_id")?;
    let height = read_u32(r, "claims.record.height")?;
    let tx_index = read_u32(r, "claims.record.tx_index")?;
    let claim_index = read_u32(r, "claims.record.claim_index")?;
    Ok(AuthorshipClaimRecord {
        claim,
        tx_id,
        height,
        tx_index,
        claim_index,
    })
}

type DecodedClaimsState = (
    BTreeMap<[u8; 32], Vec<AuthorshipClaimRecord>>,
    HashSet<[u8; 32]>,
);

fn decode_claims_state(r: &mut Reader<'_>) -> Result<DecodedClaimsState, ChainCheckpointError> {
    let claims_n = read_len(r, "claims.len")?;
    let mut claims: BTreeMap<[u8; 32], Vec<AuthorshipClaimRecord>> = BTreeMap::new();
    let mut prev_key: Option<[u8; 32]> = None;
    for i in 0..claims_n {
        let data_root: [u8; 32] = read_fixed(r, "claims[i].key")?;
        if let Some(prev) = prev_key {
            if data_root <= prev {
                return Err(ChainCheckpointError::ClaimsNotSorted { index: i });
            }
        }
        prev_key = Some(data_root);
        let rec_n = read_len(r, "claims[i].records.len")?;
        let mut vec = Vec::with_capacity(rec_n);
        for j in 0..rec_n {
            vec.push(decode_authorship_claim_record(r, i, j, &data_root)?);
        }
        claims.insert(data_root, vec);
    }

    let submitted_n = read_len(r, "claim_submitted.len")?;
    let mut claim_submitted: HashSet<[u8; 32]> = HashSet::with_capacity(submitted_n);
    let mut prev_leaf: Option<[u8; 32]> = None;
    for i in 0..submitted_n {
        let h: [u8; 32] = read_fixed(r, "claim_submitted[i]")?;
        if let Some(prev) = prev_leaf {
            if h <= prev {
                return Err(ChainCheckpointError::ClaimSubmittedNotSorted { index: i });
            }
        }
        prev_leaf = Some(h);
        claim_submitted.insert(h);
    }
    Ok((claims, claim_submitted))
}

/// Decode a [`ChainCheckpoint`] from canonical bytes produced by
/// [`encode_chain_checkpoint`]. Strict on every invariant:
///
/// - magic + version must match;
/// - every length must fit `usize`;
/// - sorted-map fields must be **strictly ascending** (rejects duplicates);
/// - validator-stats length must equal validator length;
/// - `next_validator_index` must exceed every assigned validator index;
/// - trailing integrity tag must reproduce `dhash(CHAIN_CHECKPOINT, &[payload])`;
/// - no trailing bytes after the tag.
///
/// # Errors
///
/// See [`ChainCheckpointError`].
pub fn decode_chain_checkpoint(bytes: &[u8]) -> Result<ChainCheckpoint, ChainCheckpointError> {
    // Need at least magic + version + tag.
    const MIN_LEN: usize = 4 + 4 + 32;
    if bytes.len() < MIN_LEN {
        return Err(CheckpointReadError::Truncated {
            field: "magic+version+tag",
            needed: MIN_LEN.saturating_sub(bytes.len()),
        }
        .into());
    }
    let payload_len = bytes.len() - 32;
    let payload = &bytes[..payload_len];
    let tag_bytes = &bytes[payload_len..];
    let expected_tag = dhash(CHAIN_CHECKPOINT, &[payload]);
    if tag_bytes != expected_tag {
        return Err(ChainCheckpointError::IntegrityCheckFailed);
    }

    let mut r = Reader::new(payload);

    let magic: [u8; 4] = read_fixed(&mut r, "magic")?;
    if magic != CHAIN_CHECKPOINT_MAGIC {
        return Err(ChainCheckpointError::BadMagic { got: magic });
    }
    let version = read_u32(&mut r, "version")?;
    if version != 1 && version != 2 {
        return Err(ChainCheckpointError::UnsupportedVersion { got: version });
    }

    let genesis_id: [u8; 32] = read_fixed(&mut r, "genesis_id")?;

    let height_flag = read_u8(&mut r, "height_flag")?;
    let height = match height_flag {
        0 => None,
        1 => Some(read_u32(&mut r, "height")?),
        other => return Err(ChainCheckpointError::InvalidHeightFlag { flag: other }),
    };

    let block_ids_n = read_len(&mut r, "block_ids.len")?;
    let mut block_ids = Vec::with_capacity(block_ids_n);
    for _ in 0..block_ids_n {
        block_ids.push(read_fixed::<32>(&mut r, "block_ids[i]")?);
    }

    let params = decode_consensus_params(&mut r)?;
    let bonding_params = decode_bonding_params(&mut r)?;
    let emission_params = decode_emission_params(&mut r)?;
    let endowment_params = decode_endowment_params(&mut r)?;

    let treasury = read_u128(&mut r, "treasury")?;

    let bond_epoch_id = read_u64(&mut r, "bond_counters.bond_epoch_id")?;
    let bond_epoch_entry_count = read_u32(&mut r, "bond_counters.bond_epoch_entry_count")?;
    let bond_epoch_exit_count = read_u32(&mut r, "bond_counters.bond_epoch_exit_count")?;
    let next_validator_index = read_u32(&mut r, "bond_counters.next_validator_index")?;

    let validators_n = read_len(&mut r, "validators.len")?;
    let mut validators = Vec::with_capacity(validators_n);
    for i in 0..validators_n {
        validators.push(decode_validator(&mut r, i)?);
    }

    let stats_n = read_len(&mut r, "validator_stats.len")?;
    if stats_n != validators_n {
        return Err(CheckpointReadError::StatsLengthMismatch {
            validators: validators_n,
            stats: stats_n,
        }
        .into());
    }
    let mut validator_stats = Vec::with_capacity(stats_n);
    for _ in 0..stats_n {
        validator_stats.push(decode_validator_stats(&mut r)?);
    }

    let pending_n = read_len(&mut r, "pending_unbonds.len")?;
    let mut pending_unbonds: BTreeMap<u32, PendingUnbond> = BTreeMap::new();
    let mut prev_pidx: Option<u32> = None;
    for i in 0..pending_n {
        let p = decode_pending_unbond(&mut r)?;
        if let Some(prev) = prev_pidx {
            if p.validator_index <= prev {
                return Err(CheckpointReadError::PendingUnbondsNotSorted { index: i }.into());
            }
        }
        prev_pidx = Some(p.validator_index);
        if pending_unbonds.insert(p.validator_index, p).is_some() {
            return Err(CheckpointReadError::PendingUnbondsNotSorted { index: i }.into());
        }
    }

    // ---- UTXO map ----
    let utxo_n = read_len(&mut r, "utxo.len")?;
    let mut utxo: HashMap<[u8; 32], UtxoEntry> = HashMap::with_capacity(utxo_n);
    let mut prev_utxo_key: Option<[u8; 32]> = None;
    for i in 0..utxo_n {
        let key: [u8; 32] = read_fixed(&mut r, "utxo[i].key")?;
        if let Some(prev) = prev_utxo_key {
            if key <= prev {
                return Err(ChainCheckpointError::UtxoNotSorted { index: i });
            }
        }
        prev_utxo_key = Some(key);
        let entry = decode_utxo_entry(&mut r, i)?;
        utxo.insert(key, entry);
    }

    // ---- Spent key images ----
    let spent_n = read_len(&mut r, "spent_key_images.len")?;
    let mut spent_key_images: HashSet<[u8; 32]> = HashSet::with_capacity(spent_n);
    let mut prev_spent_key: Option<[u8; 32]> = None;
    for i in 0..spent_n {
        let key: [u8; 32] = read_fixed(&mut r, "spent_key_images[i]")?;
        if let Some(prev) = prev_spent_key {
            if key <= prev {
                return Err(ChainCheckpointError::SpentKeyImagesNotSorted { index: i });
            }
        }
        prev_spent_key = Some(key);
        spent_key_images.insert(key);
    }

    // ---- Storage map ----
    let storage_n = read_len(&mut r, "storage.len")?;
    let mut storage: HashMap<[u8; 32], StorageEntry> = HashMap::with_capacity(storage_n);
    let mut prev_storage_key: Option<[u8; 32]> = None;
    for i in 0..storage_n {
        let key: [u8; 32] = read_fixed(&mut r, "storage[i].key")?;
        if let Some(prev) = prev_storage_key {
            if key <= prev {
                return Err(ChainCheckpointError::StorageNotSorted { index: i });
            }
        }
        prev_storage_key = Some(key);
        let entry = decode_storage_entry(&mut r, i)?;
        storage.insert(key, entry);
    }

    let (claims, claim_submitted) = if version >= 2 {
        decode_claims_state(&mut r)?
    } else {
        (BTreeMap::new(), HashSet::new())
    };

    // ---- UTXO accumulator ----
    let utxo_tree_n = read_len(&mut r, "utxo_tree.len")?;
    let utxo_tree_bytes = r
        .bytes(utxo_tree_n)
        .map_err(|_| CheckpointReadError::Truncated {
            field: "utxo_tree",
            needed: utxo_tree_n,
        })?;
    let utxo_tree: UtxoTreeState = decode_utxo_tree_state(utxo_tree_bytes)
        .map_err(|source| ChainCheckpointError::InvalidUtxoTree { source })?;

    if !r.end() {
        return Err(ChainCheckpointError::TrailingBytes {
            remaining: r.remaining(),
        });
    }

    // Cross-validator invariants (duplicate-index + next-index) live
    // in the shared codec.
    check_validator_assignment(&validators, next_validator_index)?;

    let counters = BondEpochCounters {
        bond_epoch_id,
        bond_epoch_entry_count,
        bond_epoch_exit_count,
        next_validator_index,
    };

    // Silence "unused" warnings for the params defaults we don't need
    // here — they exist to document the genesis defaults that match the
    // codec. (Touching them keeps `cargo doc` cross-links honest.)
    let _ = DEFAULT_CONSENSUS_PARAMS;
    let _ = DEFAULT_BONDING_PARAMS;
    let _ = DEFAULT_EMISSION_PARAMS;
    let _ = DEFAULT_ENDOWMENT_PARAMS;

    let state = ChainState {
        height,
        utxo,
        spent_key_images,
        storage,
        claims,
        claim_submitted,
        block_ids,
        validators,
        validator_stats,
        params,
        emission_params,
        endowment_params,
        treasury,
        utxo_tree,
        bonding_params,
        bond_epoch_id: counters.bond_epoch_id,
        bond_epoch_entry_count: counters.bond_epoch_entry_count,
        bond_epoch_exit_count: counters.bond_epoch_exit_count,
        next_validator_index: counters.next_validator_index,
        pending_unbonds,
    };

    Ok(ChainCheckpoint { genesis_id, state })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ValidatorStats;
    use crate::consensus::{Validator, ValidatorPayout};
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use mfn_bls::{bls_keygen_from_seed, encode_public_key};
    use mfn_crypto::point::{generator_g, generator_h};
    use mfn_crypto::utxo_tree::{append_utxo, empty_utxo_tree, utxo_leaf_hash};
    use mfn_storage::{StorageCommitment, DEFAULT_CHUNK_SIZE};

    fn fresh_state() -> ChainState {
        ChainState {
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

    fn point_for(seed: u64) -> EdwardsPoint {
        generator_g() * Scalar::from(seed)
    }

    fn commit_for(seed: u64) -> EdwardsPoint {
        generator_h() * Scalar::from(seed)
    }

    fn make_validator(index: u32, stake: u64, with_payout: bool) -> Validator {
        let bls = bls_keygen_from_seed(&[index as u8; 32]);
        let payout = if with_payout {
            Some(ValidatorPayout {
                view_pub: point_for(0xa000 + index as u64),
                spend_pub: point_for(0xb000 + index as u64),
            })
        } else {
            None
        };
        Validator {
            index,
            vrf_pk: point_for(0xc000 + index as u64),
            bls_pk: bls.pk,
            stake,
            payout,
        }
    }

    fn make_storage_commitment(seed: u8) -> StorageCommitment {
        StorageCommitment {
            data_root: [seed; 32],
            size_bytes: 1024 * (seed as u64 + 1),
            chunk_size: DEFAULT_CHUNK_SIZE as u32,
            num_chunks: 1 + seed as u32,
            replication: 3,
            endowment: commit_for(0xd000 + seed as u64),
        }
    }

    #[test]
    fn pre_genesis_round_trip() {
        let s = fresh_state();
        let cp = ChainCheckpoint {
            genesis_id: [9u8; 32],
            state: s.clone(),
        };
        let bytes = encode_chain_checkpoint(&cp);
        let cp2 = decode_chain_checkpoint(&bytes).unwrap();
        assert_eq!(cp2.genesis_id, cp.genesis_id);
        assert_eq!(cp2.state.height, None);
        assert!(cp2.state.utxo.is_empty());
        assert!(cp2.state.spent_key_images.is_empty());
        assert!(cp2.state.storage.is_empty());
        assert!(cp2.state.claims.is_empty());
        assert!(cp2.state.claim_submitted.is_empty());
        assert!(cp2.state.validators.is_empty());
        // Re-encode must produce identical bytes.
        let bytes2 = encode_chain_checkpoint(&cp2);
        assert_eq!(bytes, bytes2);
    }

    fn rich_state() -> ChainState {
        let mut s = fresh_state();
        s.height = Some(7);
        s.block_ids = (0u8..8).map(|i| [i; 32]).collect();
        s.treasury = 12_345_678_901_234_567_890u128;
        s.validators.push(make_validator(0, 1_000_000, true));
        s.validators.push(make_validator(1, 2_000_000, false));
        s.validators.push(make_validator(2, 3_000_000, true));
        s.validator_stats.push(ValidatorStats {
            consecutive_missed: 0,
            total_signed: 7,
            total_missed: 0,
            liveness_slashes: 0,
        });
        s.validator_stats.push(ValidatorStats {
            consecutive_missed: 3,
            total_signed: 4,
            total_missed: 3,
            liveness_slashes: 1,
        });
        s.validator_stats.push(ValidatorStats {
            consecutive_missed: 0,
            total_signed: 5,
            total_missed: 2,
            liveness_slashes: 0,
        });
        s.pending_unbonds.insert(
            1,
            PendingUnbond {
                validator_index: 1,
                unlock_height: 100,
                stake_at_request: 2_000_000,
                request_height: 50,
            },
        );
        s.next_validator_index = 3;
        s.bond_epoch_id = 4;
        s.bond_epoch_entry_count = 1;
        s.bond_epoch_exit_count = 0;
        for i in 0u64..10 {
            let key_pt = point_for(0x1000 + i);
            let key = key_pt.compress().to_bytes();
            s.utxo.insert(
                key,
                UtxoEntry {
                    commit: commit_for(0x2000 + i),
                    height: i as u32,
                },
            );
        }
        for i in 0u64..5 {
            let ki = point_for(0x3000 + i).compress().to_bytes();
            s.spent_key_images.insert(ki);
        }
        for seed in 0u8..4 {
            let c = make_storage_commitment(seed);
            let key = mfn_storage::storage_commitment_hash(&c);
            s.storage.insert(
                key,
                StorageEntry {
                    commit: c,
                    last_proven_height: 100 + seed as u32,
                    last_proven_slot: 1_000 + seed as u64,
                    pending_yield_ppb: 1234 * (seed as u128 + 1),
                },
            );
        }
        // Populate the UTXO accumulator with the same leaves that match
        // the utxo entries (so utxo_tree_root is non-trivial).
        let mut t = empty_utxo_tree();
        for (i, (k, v)) in {
            let mut keys: Vec<&[u8; 32]> = s.utxo.keys().collect();
            keys.sort();
            keys.into_iter().map(|k| (k, &s.utxo[k]))
        }
        .enumerate()
        {
            let _ = i;
            let key_pt = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(k)
                .unwrap()
                .decompress()
                .unwrap();
            let leaf = utxo_leaf_hash(&key_pt, &v.commit, v.height);
            t = append_utxo(&t, leaf).unwrap();
        }
        s.utxo_tree = t;
        s
    }

    #[test]
    fn rich_round_trip_preserves_every_field() {
        let s = rich_state();
        let cp = ChainCheckpoint {
            genesis_id: [0xab; 32],
            state: s.clone(),
        };
        let bytes = encode_chain_checkpoint(&cp);
        let cp2 = decode_chain_checkpoint(&bytes).unwrap();
        assert_eq!(cp2.genesis_id, cp.genesis_id);
        let r = &cp2.state;
        assert_eq!(r.height, s.height);
        assert_eq!(r.block_ids, s.block_ids);
        assert_eq!(r.treasury, s.treasury);
        assert_eq!(r.bond_epoch_id, s.bond_epoch_id);
        assert_eq!(r.bond_epoch_entry_count, s.bond_epoch_entry_count);
        assert_eq!(r.bond_epoch_exit_count, s.bond_epoch_exit_count);
        assert_eq!(r.next_validator_index, s.next_validator_index);
        assert_eq!(r.validators.len(), s.validators.len());
        for (a, b) in r.validators.iter().zip(s.validators.iter()) {
            assert_eq!(a.index, b.index);
            assert_eq!(a.stake, b.stake);
            assert_eq!(
                a.vrf_pk.compress().to_bytes(),
                b.vrf_pk.compress().to_bytes()
            );
            assert_eq!(encode_public_key(&a.bls_pk), encode_public_key(&b.bls_pk));
            assert_eq!(a.payout.is_some(), b.payout.is_some());
        }
        assert_eq!(r.validator_stats, s.validator_stats);
        assert_eq!(r.pending_unbonds, s.pending_unbonds);
        assert_eq!(r.utxo.len(), s.utxo.len());
        for (k, v) in &s.utxo {
            let rv = r.utxo.get(k).expect("utxo key preserved");
            assert_eq!(
                rv.commit.compress().to_bytes(),
                v.commit.compress().to_bytes()
            );
            assert_eq!(rv.height, v.height);
        }
        assert_eq!(r.spent_key_images, s.spent_key_images);
        assert_eq!(r.claims, s.claims);
        assert_eq!(r.claim_submitted, s.claim_submitted);
        assert_eq!(r.storage.len(), s.storage.len());
        for (k, v) in &s.storage {
            let rv = r.storage.get(k).expect("storage key preserved");
            assert_eq!(
                mfn_storage::storage_commitment_hash(&rv.commit),
                mfn_storage::storage_commitment_hash(&v.commit)
            );
            assert_eq!(rv.last_proven_height, v.last_proven_height);
            assert_eq!(rv.last_proven_slot, v.last_proven_slot);
            assert_eq!(rv.pending_yield_ppb, v.pending_yield_ppb);
        }
        assert_eq!(
            mfn_crypto::utxo_tree_root(&r.utxo_tree),
            mfn_crypto::utxo_tree_root(&s.utxo_tree)
        );
        assert_eq!(r.params.quorum_stake_bps, s.params.quorum_stake_bps);
        assert_eq!(r.emission_params, s.emission_params);
        assert_eq!(r.endowment_params, s.endowment_params);
        assert_eq!(r.bonding_params, s.bonding_params);
        // Determinism: re-encode round 2 yields identical bytes.
        let bytes2 = encode_chain_checkpoint(&cp2);
        assert_eq!(bytes, bytes2, "encoder must be deterministic");
    }

    #[test]
    fn encode_is_independent_of_hashmap_iteration_order() {
        let s_a = rich_state();
        // Build a "shuffled" duplicate by inserting in reverse — its
        // HashMap iteration order will differ, but the canonical sort
        // inside the encoder must produce identical bytes.
        let mut s_b = ChainState {
            height: s_a.height,
            utxo: HashMap::new(),
            spent_key_images: HashSet::new(),
            storage: HashMap::new(),
            claims: s_a.claims.clone(),
            claim_submitted: s_a.claim_submitted.clone(),
            block_ids: s_a.block_ids.clone(),
            validators: s_a.validators.clone(),
            validator_stats: s_a.validator_stats.clone(),
            params: s_a.params,
            emission_params: s_a.emission_params,
            endowment_params: s_a.endowment_params,
            treasury: s_a.treasury,
            utxo_tree: s_a.utxo_tree.clone(),
            bonding_params: s_a.bonding_params,
            bond_epoch_id: s_a.bond_epoch_id,
            bond_epoch_entry_count: s_a.bond_epoch_entry_count,
            bond_epoch_exit_count: s_a.bond_epoch_exit_count,
            next_validator_index: s_a.next_validator_index,
            pending_unbonds: s_a.pending_unbonds.clone(),
        };
        let mut utxo_pairs: Vec<_> = s_a.utxo.iter().collect();
        utxo_pairs.reverse();
        for (k, v) in utxo_pairs {
            s_b.utxo.insert(*k, v.clone());
        }
        let mut spent: Vec<_> = s_a.spent_key_images.iter().collect();
        spent.reverse();
        for k in spent {
            s_b.spent_key_images.insert(*k);
        }
        let mut storage: Vec<_> = s_a.storage.iter().collect();
        storage.reverse();
        for (k, v) in storage {
            s_b.storage.insert(*k, v.clone());
        }
        let cp_a = ChainCheckpoint {
            genesis_id: [7u8; 32],
            state: s_a,
        };
        let cp_b = ChainCheckpoint {
            genesis_id: [7u8; 32],
            state: s_b,
        };
        assert_eq!(
            encode_chain_checkpoint(&cp_a),
            encode_chain_checkpoint(&cp_b),
            "encoding must be independent of HashMap insertion order"
        );
    }

    #[test]
    fn rejects_bad_magic() {
        let cp = ChainCheckpoint {
            genesis_id: [0u8; 32],
            state: fresh_state(),
        };
        let mut bytes = encode_chain_checkpoint(&cp);
        bytes[0] ^= 0xff;
        // Flipping the magic changes the payload → integrity tag mismatch
        // triggers first. Recompute the tag so the magic check actually
        // fires.
        let plen = bytes.len() - 32;
        let new_tag = dhash(CHAIN_CHECKPOINT, &[&bytes[..plen]]);
        bytes[plen..].copy_from_slice(&new_tag);
        match decode_chain_checkpoint(&bytes) {
            Err(ChainCheckpointError::BadMagic { .. }) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unsupported_version() {
        let cp = ChainCheckpoint {
            genesis_id: [0u8; 32],
            state: fresh_state(),
        };
        let mut bytes = encode_chain_checkpoint(&cp);
        // Bytes 4..8 are the version, big-endian. Flip to 9.
        bytes[4..8].copy_from_slice(&9u32.to_be_bytes());
        let plen = bytes.len() - 32;
        let new_tag = dhash(CHAIN_CHECKPOINT, &[&bytes[..plen]]);
        bytes[plen..].copy_from_slice(&new_tag);
        match decode_chain_checkpoint(&bytes) {
            Err(ChainCheckpointError::UnsupportedVersion { got }) => assert_eq!(got, 9),
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn detects_payload_tamper() {
        let cp = ChainCheckpoint {
            genesis_id: [0u8; 32],
            state: rich_state(),
        };
        let mut bytes = encode_chain_checkpoint(&cp);
        // Flip a payload byte but leave the trailing tag alone — the
        // recomputed tag will no longer match.
        let pos = bytes.len() / 2;
        bytes[pos] ^= 0xff;
        match decode_chain_checkpoint(&bytes) {
            Err(ChainCheckpointError::IntegrityCheckFailed) => {}
            other => panic!("expected IntegrityCheckFailed, got {other:?}"),
        }
    }

    #[test]
    fn detects_tag_tamper() {
        let cp = ChainCheckpoint {
            genesis_id: [0u8; 32],
            state: fresh_state(),
        };
        let mut bytes = encode_chain_checkpoint(&cp);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        match decode_chain_checkpoint(&bytes) {
            Err(ChainCheckpointError::IntegrityCheckFailed) => {}
            other => panic!("expected IntegrityCheckFailed, got {other:?}"),
        }
    }

    #[test]
    fn rejects_truncated_below_minimum() {
        let bytes = vec![0u8; 8];
        match decode_chain_checkpoint(&bytes) {
            Err(ChainCheckpointError::Read(CheckpointReadError::Truncated { .. })) => {}
            other => panic!("expected Read(Truncated), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_validator_index() {
        // Manually craft a tiny payload with two validators sharing index 0.
        let mut w = Writer::new();
        w.push(&CHAIN_CHECKPOINT_MAGIC);
        w.u32(1); // v1 wire (no claims section)
        w.push(&[0u8; 32]); // genesis_id
        w.u8(0); // height_flag = pre-genesis
        w.varint(0); // block_ids
        encode_consensus_params(&mut w, &DEFAULT_CONSENSUS_PARAMS);
        encode_bonding_params(&mut w, &DEFAULT_BONDING_PARAMS);
        encode_emission_params(&mut w, &DEFAULT_EMISSION_PARAMS);
        encode_endowment_params(&mut w, &DEFAULT_ENDOWMENT_PARAMS);
        encode_u128(&mut w, 0);
        w.u64(0); // bond_epoch_id
        w.u32(0);
        w.u32(0);
        w.u32(100); // next_validator_index
        w.varint(2); // validators.len
        encode_validator(&mut w, &make_validator(7, 1, false));
        encode_validator(&mut w, &make_validator(7, 2, false));
        w.varint(2); // stats.len
        for _ in 0..2 {
            encode_validator_stats(&mut w, &ValidatorStats::default());
        }
        w.varint(0); // pending_unbonds
        w.varint(0); // utxo
        w.varint(0); // spent
        w.varint(0); // storage
        let tree = encode_utxo_tree_state(&empty_utxo_tree());
        w.varint(tree.len() as u64);
        w.push(&tree);
        let payload = w.into_bytes();
        let tag = dhash(CHAIN_CHECKPOINT, &[&payload]);
        let mut bytes = payload;
        bytes.extend_from_slice(&tag);
        match decode_chain_checkpoint(&bytes) {
            Err(ChainCheckpointError::Read(CheckpointReadError::DuplicateValidatorIndex {
                index,
            })) => {
                assert_eq!(index, 7);
            }
            other => panic!("expected Read(DuplicateValidatorIndex), got {other:?}"),
        }
    }

    #[test]
    fn rejects_stats_validators_mismatch() {
        let mut w = Writer::new();
        w.push(&CHAIN_CHECKPOINT_MAGIC);
        w.u32(1); // v1 wire (no claims section)
        w.push(&[0u8; 32]);
        w.u8(0);
        w.varint(0);
        encode_consensus_params(&mut w, &DEFAULT_CONSENSUS_PARAMS);
        encode_bonding_params(&mut w, &DEFAULT_BONDING_PARAMS);
        encode_emission_params(&mut w, &DEFAULT_EMISSION_PARAMS);
        encode_endowment_params(&mut w, &DEFAULT_ENDOWMENT_PARAMS);
        encode_u128(&mut w, 0);
        w.u64(0);
        w.u32(0);
        w.u32(0);
        w.u32(100);
        w.varint(1);
        encode_validator(&mut w, &make_validator(0, 1, false));
        w.varint(2); // mismatch
        for _ in 0..2 {
            encode_validator_stats(&mut w, &ValidatorStats::default());
        }
        w.varint(0);
        w.varint(0);
        w.varint(0);
        w.varint(0);
        let tree = encode_utxo_tree_state(&empty_utxo_tree());
        w.varint(tree.len() as u64);
        w.push(&tree);
        let payload = w.into_bytes();
        let tag = dhash(CHAIN_CHECKPOINT, &[&payload]);
        let mut bytes = payload;
        bytes.extend_from_slice(&tag);
        match decode_chain_checkpoint(&bytes) {
            Err(ChainCheckpointError::Read(CheckpointReadError::StatsLengthMismatch {
                validators,
                stats,
            })) => {
                assert_eq!(validators, 1);
                assert_eq!(stats, 2);
            }
            other => panic!("expected Read(StatsLengthMismatch), got {other:?}"),
        }
    }

    #[test]
    fn rejects_next_index_at_or_below_max_assigned() {
        let mut w = Writer::new();
        w.push(&CHAIN_CHECKPOINT_MAGIC);
        w.u32(1); // v1 wire (no claims section)
        w.push(&[0u8; 32]);
        w.u8(0);
        w.varint(0);
        encode_consensus_params(&mut w, &DEFAULT_CONSENSUS_PARAMS);
        encode_bonding_params(&mut w, &DEFAULT_BONDING_PARAMS);
        encode_emission_params(&mut w, &DEFAULT_EMISSION_PARAMS);
        encode_endowment_params(&mut w, &DEFAULT_ENDOWMENT_PARAMS);
        encode_u128(&mut w, 0);
        w.u64(0);
        w.u32(0);
        w.u32(0);
        w.u32(5); // next_validator_index = 5
        w.varint(1);
        encode_validator(&mut w, &make_validator(5, 1, false));
        w.varint(1);
        encode_validator_stats(&mut w, &ValidatorStats::default());
        w.varint(0);
        w.varint(0);
        w.varint(0);
        w.varint(0);
        let tree = encode_utxo_tree_state(&empty_utxo_tree());
        w.varint(tree.len() as u64);
        w.push(&tree);
        let payload = w.into_bytes();
        let tag = dhash(CHAIN_CHECKPOINT, &[&payload]);
        let mut bytes = payload;
        bytes.extend_from_slice(&tag);
        match decode_chain_checkpoint(&bytes) {
            Err(ChainCheckpointError::Read(CheckpointReadError::NextIndexBelowAssigned {
                next,
                max_assigned,
            })) => {
                assert_eq!(next, 5);
                assert_eq!(max_assigned, 5);
            }
            other => panic!("expected Read(NextIndexBelowAssigned), got {other:?}"),
        }
    }

    #[test]
    fn rejects_trailing_bytes_after_tag() {
        let cp = ChainCheckpoint {
            genesis_id: [0u8; 32],
            state: fresh_state(),
        };
        let mut bytes = encode_chain_checkpoint(&cp);
        bytes.push(0u8);
        // After the integrity check, decoder reads the payload via the
        // inner reader and would see trailing bytes inside the payload.
        // But pushing a byte AFTER the tag changes the payload-vs-tag
        // split: now the "tag" is the last 32 bytes (which include
        // payload bytes + the appended byte), and the recomputed tag
        // won't match.  In that case `IntegrityCheckFailed` is the
        // expected behavior — the codec doesn't have a separate
        // "trailing-after-tag" path because every byte before the tag
        // is part of the integrity-checked payload by definition.
        match decode_chain_checkpoint(&bytes) {
            Err(ChainCheckpointError::IntegrityCheckFailed) => {}
            other => panic!("expected IntegrityCheckFailed, got {other:?}"),
        }
    }

    #[test]
    fn light_checkpoint_bytes_fail_chain_decode() {
        // Sanity check that the two checkpoint families are
        // domain-separated: feeding a (well-formed) byte stream that
        // happens to start with a different magic must fail the magic
        // check, not silently decode part of the way through.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"MFLC"); // light magic
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 32]); // fake payload
                                             // 32-byte tag at the end so length >= MIN_LEN.
        bytes.extend_from_slice(&[0u8; 32]);
        // Integrity check fails first (the tag isn't a real
        // CHAIN_CHECKPOINT tag), which is the correct rejection mode.
        match decode_chain_checkpoint(&bytes) {
            Err(ChainCheckpointError::IntegrityCheckFailed) => {}
            other => panic!("expected IntegrityCheckFailed, got {other:?}"),
        }
    }
}
