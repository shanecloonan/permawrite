//! `ChainState` checkpoint codec (M2.0.15).
//!
//! Deterministic, IO-free byte serialisation of every field on
//! [`crate::block::ChainState`] plus the chain's `genesis_id` pointer.
//! Pair the encoder with any persistence backend (file, RocksDB, S3 …);
//! this module concerns itself only with *what* the bytes are.
//!
//! ## Wire layout (v3, current)
//!
//! v3 extends v2 by replacing the nested `data_root → Vec<record>` map and the
//! separate `claim_submitted` set with a flat map keyed by
//! (`data_root`, `claim_pubkey`):
//!
//! ```text
//!   claims.len()              varint   (sorted ascending by (data_root, claim_pubkey))
//!     data_root                 [32]
//!     claim_pubkey              [32]
//!     wire.len()                varint
//!     wire                      bytes   MFCL authorship claim
//!     tx_id                     [32]
//!     height                    u32
//!     tx_index                  u32
//!     claim_index               u32
//! ```
//!
//! v2 checkpoints decode into the v3 in-memory shape (legacy nested map +
//! `claim_submitted` are not persisted on re-encode). v1 omits claims entirely.
//!
//! ```text
//!   magic                       [4]   "MFCC" (M(oney)F(und) C(hain) C(heckpoint))
//!   version                      u32   currently 3 (v1–v2 supported on decode)
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
//!   (v2/v3) authorship `claims` — see the v3 section above (v2 legacy layout)
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

use crate::block::ChainState;
use crate::checkpoint_codec::CheckpointReadError;
use mfn_crypto::utxo_tree::UtxoTreeDecodeError;

/// 4-byte magic header. ASCII `"MFCC"` = `M(oney)F(und) C(hain) C(heckpoint)`.
pub const CHAIN_CHECKPOINT_MAGIC: [u8; 4] = *b"MFCC";

/// Currently-supported chain-checkpoint format version. Bumped only on
/// wire-incompatible changes.
pub const CHAIN_CHECKPOINT_VERSION: u32 = 7;

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
    #[error(
        "unsupported chain-checkpoint version {got}; this build supports versions 1 through 7"
    )]
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

    /// `storage_operators` map entries were not strictly ascending by key.
    #[error(
        "chain-checkpoint storage_operators entries not strictly ascending at position {index}"
    )]
    StorageOperatorsNotSorted {
        /// Position in the `storage_operators` list.
        index: usize,
    },

    /// A `StorageOperatorEntry` pubkey failed to decode.
    #[error("chain-checkpoint storage_operators[{index}]: invalid operator payout point")]
    InvalidStorageOperatorPoint {
        /// Position in the `storage_operators` list.
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

mod decode;
mod encode;
mod internal;

#[cfg(test)]
mod tests;

pub use decode::decode_chain_checkpoint;
pub use encode::encode_chain_checkpoint;

#[cfg(test)]
pub(crate) use encode::{encode_emission_params, encode_endowment_params, encode_u128};
