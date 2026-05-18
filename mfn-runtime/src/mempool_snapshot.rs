//! Canonical on-disk mempool snapshot (**M2.3.21**).
//!
//! Format (`mempool.bytes`):
//! - magic `MFNMPOOL1` (8 bytes)
//! - version `u8` = 1
//! - `varint` entry count
//! - per entry: `u32` admitted height (`0xffff_ffff` = unknown), `blob` tx wire

use mfn_consensus::{decode_transaction, encode_transaction, TransactionWire};
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::dhash;
use mfn_crypto::domain::MEMPOOL_ROOT;

use crate::mempool::{AdmitError, Mempool};
use mfn_consensus::ChainState;

/// Magic prefix for [`encode_mempool_snapshot`].
pub const MEMPOOL_SNAPSHOT_MAGIC: &[u8] = b"MFNMPOOL1";

/// Current snapshot version byte.
pub const MEMPOOL_SNAPSHOT_VERSION: u8 = 1;

/// Sentinel `admitted_at_height` when the height was not recorded.
pub const MEMPOOL_HEIGHT_UNKNOWN: u32 = 0xffff_ffff;

/// One persisted mempool entry.
#[derive(Clone, Debug)]
pub struct MempoolSnapshotEntry {
    /// Canonical transaction.
    pub tx: TransactionWire,
    /// Chain height at admission, if known.
    pub admitted_at_height: Option<u32>,
}

/// Failure encoding or decoding a snapshot.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MempoolSnapshotError {
    /// File shorter than the magic header.
    #[error("snapshot too short")]
    TooShort,
    /// Magic bytes do not match.
    #[error("bad magic")]
    BadMagic,
    /// Unsupported version byte.
    #[error("unsupported snapshot version {0}")]
    UnsupportedVersion(u8),
    /// Codec or tx decode failure.
    #[error("decode: {0}")]
    Decode(String),
}

/// Outcome of [`Mempool::restore_snapshot`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MempoolRestoreStats {
    /// Entries read from the snapshot file.
    pub loaded: u32,
    /// Entries successfully re-admitted.
    pub admitted: u32,
    /// Entries skipped (stale, invalid, or duplicate under current chain state).
    pub skipped: u32,
}

/// Deterministic diagnostic root over sorted `tx_id`s (not consensus-critical).
#[must_use]
pub fn mempool_root(pool: &Mempool) -> [u8; 32] {
    let mut ids: Vec<[u8; 32]> = pool.iter().map(|e| e.tx_id).collect();
    ids.sort();
    let parts: Vec<&[u8]> = ids.iter().map(AsRef::as_ref).collect();
    dhash(MEMPOOL_ROOT, &parts)
}

/// Encode the mempool to canonical bytes.
pub fn encode_mempool_snapshot(pool: &Mempool) -> Vec<u8> {
    let entries: Vec<MempoolSnapshotEntry> = pool
        .iter()
        .map(|e| MempoolSnapshotEntry {
            tx: e.tx.clone(),
            admitted_at_height: e.admitted_at_height,
        })
        .collect();
    encode_mempool_snapshot_entries(&entries)
}

/// Encode a pre-built entry list.
pub fn encode_mempool_snapshot_entries(entries: &[MempoolSnapshotEntry]) -> Vec<u8> {
    let mut w = Writer::new();
    w.blob(MEMPOOL_SNAPSHOT_MAGIC);
    w.u8(MEMPOOL_SNAPSHOT_VERSION);
    w.varint(entries.len() as u64);
    for e in entries {
        let h = e.admitted_at_height.unwrap_or(MEMPOOL_HEIGHT_UNKNOWN);
        w.u32(h);
        let wire = encode_transaction(&e.tx);
        w.blob(&wire);
    }
    w.into_bytes()
}

/// Decode a snapshot blob.
pub fn decode_mempool_snapshot(bytes: &[u8]) -> Result<Vec<MempoolSnapshotEntry>, MempoolSnapshotError> {
    let mut r = Reader::new(bytes);
    let magic = r
        .blob()
        .map_err(|e| MempoolSnapshotError::Decode(e.to_string()))?;
    if magic != MEMPOOL_SNAPSHOT_MAGIC {
        return Err(if bytes.len() < MEMPOOL_SNAPSHOT_MAGIC.len() {
            MempoolSnapshotError::TooShort
        } else {
            MempoolSnapshotError::BadMagic
        });
    }
    let version = r
        .u8()
        .map_err(|e| MempoolSnapshotError::Decode(e.to_string()))?;
    if version != MEMPOOL_SNAPSHOT_VERSION {
        return Err(MempoolSnapshotError::UnsupportedVersion(version));
    }
    let count = r
        .varint()
        .map_err(|e| MempoolSnapshotError::Decode(e.to_string()))?;
    let count = usize::try_from(count).map_err(|_| MempoolSnapshotError::Decode("count overflow".into()))?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let h = r
            .u32()
            .map_err(|e| MempoolSnapshotError::Decode(e.to_string()))?;
        let wire = r
            .blob()
            .map_err(|e| MempoolSnapshotError::Decode(e.to_string()))?;
        let tx = decode_transaction(&wire)
            .map_err(|e| MempoolSnapshotError::Decode(format!("tx: {e}")))?;
        let admitted_at_height = if h == MEMPOOL_HEIGHT_UNKNOWN {
            None
        } else {
            Some(h)
        };
        out.push(MempoolSnapshotEntry {
            tx,
            admitted_at_height,
        });
    }
    Ok(out)
}

impl Mempool {
    /// Re-admit every entry from a decoded snapshot against `state`.
    ///
    /// Invalid or stale txs are skipped silently (counts in [`MempoolRestoreStats`]).
    pub fn restore_snapshot(
        &mut self,
        entries: impl IntoIterator<Item = MempoolSnapshotEntry>,
        state: &ChainState,
    ) -> MempoolRestoreStats {
        let mut stats = MempoolRestoreStats::default();
        for e in entries {
            stats.loaded = stats.loaded.saturating_add(1);
            match self.admit(e.tx, state) {
                Ok(_) => stats.admitted = stats.admitted.saturating_add(1),
                Err(AdmitError::DuplicateTx { .. }) => {
                    stats.skipped = stats.skipped.saturating_add(1);
                }
                Err(_) => stats.skipped = stats.skipped.saturating_add(1),
            }
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::MempoolConfig;

    #[test]
    fn snapshot_empty_round_trip() {
        let pool = Mempool::new(MempoolConfig::default());
        let bytes = encode_mempool_snapshot(&pool);
        let decoded = decode_mempool_snapshot(&bytes).expect("decode");
        assert!(decoded.is_empty());
        let root = mempool_root(&pool);
        assert_eq!(root, mempool_root(&Mempool::new(MempoolConfig::default())));
    }

    #[test]
    fn snapshot_rejects_bad_magic() {
        let err = decode_mempool_snapshot(b"not-a-pool").unwrap_err();
        assert!(matches!(err, MempoolSnapshotError::BadMagic | MempoolSnapshotError::TooShort));
    }
}
