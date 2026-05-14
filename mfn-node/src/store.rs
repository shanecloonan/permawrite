//! Filesystem-backed chain checkpoint store (M2.1.0 + M2.1.7 block sidecar).
//!
//! This module is the first deliberately-IO-bearing piece of
//! `mfn-node`: a tiny persistence adapter over
//! [`Chain::encode_checkpoint`] and [`Chain::from_checkpoint_bytes`].
//! It does not introduce RocksDB, async IO, networking, or fork choice.
//! **M2.1.7** adds `chain.blocks`: after each successful `mfnd step` apply,
//! canonical [`mfn_consensus::encode_block`] payloads are appended
//! (length-prefixed) for local replay / wallet bootstrap in tests.
//! The daemon can now express the essential restart lifecycle:
//!
//! ```text
//!   boot:     load checkpoint if present, otherwise build genesis
//!   runtime:  apply blocks through Chain
//!   shutdown: save the latest checkpoint
//! ```
//!
//! ## File layout
//!
//! A [`ChainStore`] owns one directory and uses these files inside it:
//!
//! - `chain.checkpoint` — primary snapshot.
//! - `chain.checkpoint.bak` — previous primary, kept for recovery if a
//!   process dies after rotating the primary away but before publishing
//!   the replacement.
//! - `chain.checkpoint.tmp` — staging file for the next snapshot.
//! - `chain.blocks` — optional append-only block log (M2.1.7): each record is
//!   `u64_be(length) || encode_block(bytes)` so wallets can replay `mfnd step`
//!   history without a full archive node yet.
//!
//! Saves write and `sync_all` the temp file before rotating. The old
//! primary is moved to the backup slot, then the temp file is renamed
//! into the primary slot. On platforms where replacing an existing file
//! with [`std::fs::rename`] is not portable (notably Windows), the
//! backup slot gives us deterministic recovery without pulling a
//! platform-specific filesystem dependency into this early milestone.
//!
//! ## Scope
//!
//! Checkpoints remain full-snapshot. The block log is a **sidecar** (no
//! fork-choice replay engine yet). Future `store` milestones can add
//! pruning, checksums, column families, and compaction on top of the same
//! bytes.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use mfn_consensus::{decode_block, encode_block, Block};

use crate::{Chain, ChainConfig, ChainError};

const CHECKPOINT_FILE: &str = "chain.checkpoint";
const BACKUP_FILE: &str = "chain.checkpoint.bak";
const TEMP_FILE: &str = "chain.checkpoint.tmp";
const BLOCK_LOG_FILE: &str = "chain.blocks";

/// Result metadata returned after a successful checkpoint save.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreSave {
    /// Number of bytes written to the primary checkpoint file.
    pub bytes_written: usize,
    /// Path to the primary checkpoint file that now contains the saved
    /// chain state.
    pub checkpoint_path: PathBuf,
    /// Path to the backup checkpoint file. It may or may not exist
    /// after the first save, but subsequent saves keep the previous
    /// primary here for interrupted-write recovery.
    pub backup_path: PathBuf,
}

/// Errors produced by [`ChainStore`].
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A filesystem operation failed.
    #[error("store io `{op}` failed for `{}`: {source}", path.display())]
    Io {
        /// Short operation label, useful for logs and tests.
        op: &'static str,
        /// Path involved in the failing operation.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The checkpoint bytes decoded, but could not be restored against
    /// the caller's [`ChainConfig`] (or genesis construction failed in
    /// [`ChainStore::load_or_genesis`]).
    #[error("chain restore failed: {0}")]
    Chain(#[from] ChainError),

    /// Append-only block log framing / decode failure.
    #[error("block log: {0}")]
    BlockLog(String),
}

fn io_error(op: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> StoreError {
    StoreError::Io {
        op,
        path: path.into(),
        source,
    }
}

fn is_not_found(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotFound
}

fn remove_if_exists(path: &Path, op: &'static str) -> Result<(), StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if is_not_found(&e) => Ok(()),
        Err(e) => Err(io_error(op, path, e)),
    }
}

/// A directory-backed store for the latest [`Chain`] checkpoint.
///
/// The store is deliberately single-writer. Future daemon code should
/// route all state mutation through one owner of [`Chain`] and one
/// owner of [`ChainStore`], rather than allowing concurrent writers to
/// race on the snapshot files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStore {
    root: PathBuf,
}

impl ChainStore {
    /// Create a store rooted at `root`.
    ///
    /// This does not touch the filesystem; directories are created on
    /// [`save`](Self::save).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Root directory owned by this store.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Primary checkpoint path.
    #[must_use]
    pub fn checkpoint_path(&self) -> PathBuf {
        self.root.join(CHECKPOINT_FILE)
    }

    /// Backup checkpoint path.
    #[must_use]
    pub fn backup_path(&self) -> PathBuf {
        self.root.join(BACKUP_FILE)
    }

    /// Temporary checkpoint path used while staging a save.
    #[must_use]
    pub fn temp_path(&self) -> PathBuf {
        self.root.join(TEMP_FILE)
    }

    /// Append-only block log path (`chain.blocks`).
    #[must_use]
    pub fn block_log_path(&self) -> PathBuf {
        self.root.join(BLOCK_LOG_FILE)
    }

    /// Append one canonical [`encode_block`] record to `chain.blocks`.
    ///
    /// Framing: `u64` length in **big-endian**, followed by exactly that many
    /// bytes (the output of [`mfn_consensus::encode_block`]). The file is
    /// created on first append. Intended to be called after every successful
    /// `apply` in `mfnd step` (M2.1.7).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] on filesystem failures or [`StoreError::BlockLog`]
    /// if the encoded block exceeds `u64::MAX` bytes (impossible in practice).
    pub fn append_block(&self, block: &Block) -> Result<(), StoreError> {
        fs::create_dir_all(&self.root).map_err(|e| io_error("create_dir_all", &self.root, e))?;
        let path = self.block_log_path();
        let payload = encode_block(block);
        let len_u64 = u64::try_from(payload.len())
            .map_err(|_| StoreError::BlockLog("encoded block length does not fit u64".into()))?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| io_error("open_block_log", &path, e))?;
        f.write_all(&len_u64.to_be_bytes())
            .map_err(|e| io_error("write_block_log_len", &path, e))?;
        f.write_all(&payload)
            .map_err(|e| io_error("write_block_log_payload", &path, e))?;
        f.sync_all()
            .map_err(|e| io_error("sync_block_log", &path, e))?;
        Ok(())
    }

    /// Read every block stored in `chain.blocks` in order.
    ///
    /// Missing file ⇒ empty vector. Malformed trailing bytes ⇒
    /// [`StoreError::BlockLog`].
    pub fn read_block_log(&self) -> Result<Vec<Block>, StoreError> {
        let path = self.block_log_path();
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if is_not_found(&e) => return Ok(Vec::new()),
            Err(e) => return Err(io_error("read_block_log", &path, e)),
        };
        let mut out = Vec::new();
        let mut off = 0usize;
        while off < bytes.len() {
            if off + 8 > bytes.len() {
                return Err(StoreError::BlockLog(format!(
                    "truncated length header at offset {off}"
                )));
            }
            let len_u64 = u64::from_be_bytes(bytes[off..off + 8].try_into().expect("8 bytes"));
            off += 8;
            let len = usize::try_from(len_u64).map_err(|_| {
                StoreError::BlockLog(format!("record byte length {len_u64} does not fit usize"))
            })?;
            if off + len > bytes.len() {
                return Err(StoreError::BlockLog(format!(
                    "truncated payload at offset {off}: need {len} bytes"
                )));
            }
            let block = decode_block(&bytes[off..off + len]).map_err(|e| {
                StoreError::BlockLog(format!("decode_block at payload offset {}: {e}", off - 8))
            })?;
            off += len;
            out.push(block);
        }
        Ok(out)
    }

    /// Returns true if a durable checkpoint file exists (primary or backup).
    ///
    /// Staging files (`chain.checkpoint.tmp`) are ignored: an interrupted
    /// save may leave a temp without a publishable primary.
    #[must_use]
    pub fn has_any_checkpoint(&self) -> bool {
        self.checkpoint_path().exists() || self.backup_path().exists()
    }

    /// Save `chain` to the primary checkpoint file.
    ///
    /// Existing primary bytes are retained as `chain.checkpoint.bak`.
    /// Any stale temp file from a previous interrupted save is removed
    /// before the new temp file is written.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] if directory creation, write, sync,
    /// rotation, or rename fails.
    pub fn save(&self, chain: &Chain) -> Result<StoreSave, StoreError> {
        fs::create_dir_all(&self.root).map_err(|e| io_error("create_dir_all", &self.root, e))?;

        let checkpoint_path = self.checkpoint_path();
        let backup_path = self.backup_path();
        let temp_path = self.temp_path();
        remove_if_exists(&temp_path, "remove_stale_temp")?;

        let bytes = chain.encode_checkpoint();
        {
            let mut file =
                File::create(&temp_path).map_err(|e| io_error("create_temp", &temp_path, e))?;
            file.write_all(&bytes)
                .map_err(|e| io_error("write_temp", &temp_path, e))?;
            file.sync_all()
                .map_err(|e| io_error("sync_temp", &temp_path, e))?;
        }

        remove_if_exists(&backup_path, "remove_old_backup")?;
        match fs::rename(&checkpoint_path, &backup_path) {
            Ok(()) => {}
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(io_error("rotate_primary_to_backup", &checkpoint_path, e)),
        }

        fs::rename(&temp_path, &checkpoint_path)
            .map_err(|e| io_error("publish_temp", &checkpoint_path, e))?;

        Ok(StoreSave {
            bytes_written: bytes.len(),
            checkpoint_path,
            backup_path,
        })
    }

    /// Load the latest checkpoint if one exists.
    ///
    /// Primary checkpoint bytes are preferred. If no primary exists,
    /// the backup checkpoint is tried; this covers the interrupted-save
    /// window after the old primary was rotated into backup but before
    /// a new primary was published.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] for filesystem failures other than a
    /// missing snapshot, or [`StoreError::Chain`] if checkpoint bytes
    /// fail to restore against `cfg`.
    pub fn load(&self, cfg: ChainConfig) -> Result<Option<Chain>, StoreError> {
        let checkpoint_path = self.checkpoint_path();
        match fs::read(&checkpoint_path) {
            Ok(bytes) => return Ok(Some(Chain::from_checkpoint_bytes(cfg, &bytes)?)),
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(io_error("read_checkpoint", checkpoint_path, e)),
        }

        let backup_path = self.backup_path();
        match fs::read(&backup_path) {
            Ok(bytes) => Ok(Some(Chain::from_checkpoint_bytes(cfg, &bytes)?)),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(io_error("read_backup", backup_path, e)),
        }
    }

    /// Load a checkpoint if present; otherwise construct a fresh
    /// genesis chain from `cfg`.
    ///
    /// This is the daemon boot primitive for M2.1: the caller can boot
    /// with one line and then periodically call [`save`](Self::save).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for any load failure or genesis
    /// construction failure.
    pub fn load_or_genesis(&self, cfg: ChainConfig) -> Result<Chain, StoreError> {
        match self.load(cfg.clone())? {
            Some(chain) => Ok(chain),
            None => Ok(Chain::from_genesis(cfg)?),
        }
    }

    /// Remove primary, backup, and temp snapshot files if present.
    ///
    /// The root directory is left in place.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] if any existing file cannot be
    /// removed.
    pub fn clear(&self) -> Result<(), StoreError> {
        remove_if_exists(&self.checkpoint_path(), "remove_checkpoint")?;
        remove_if_exists(&self.backup_path(), "remove_backup")?;
        remove_if_exists(&self.temp_path(), "remove_temp")?;
        remove_if_exists(&self.block_log_path(), "remove_block_log")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_consensus::{ConsensusParams, GenesisConfig, DEFAULT_EMISSION_PARAMS};
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn empty_genesis_cfg(timestamp: u64) -> GenesisConfig {
        GenesisConfig {
            timestamp,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            validators: Vec::new(),
            params: ConsensusParams {
                expected_proposers_per_slot: 1.0,
                quorum_stake_bps: 6667,
                ..ConsensusParams::default()
            },
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        }
    }

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mfn-node-store-{test_name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn store_for(test_name: &str) -> ChainStore {
        ChainStore::new(temp_root(test_name))
    }

    #[test]
    fn missing_snapshot_loads_none_and_boots_genesis() {
        let store = store_for("missing_snapshot_loads_none_and_boots_genesis");
        let cfg = ChainConfig::new(empty_genesis_cfg(0));

        assert!(store.load(cfg.clone()).unwrap().is_none());

        let chain = store.load_or_genesis(cfg).unwrap();
        assert_eq!(chain.tip_height(), Some(0));
        assert!(!store.checkpoint_path().exists());
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn save_then_load_round_trips_chain_checkpoint() {
        let store = store_for("save_then_load_round_trips_chain_checkpoint");
        let cfg = ChainConfig::new(empty_genesis_cfg(0));
        assert!(!store.has_any_checkpoint());
        let chain = Chain::from_genesis(cfg.clone()).unwrap();

        let saved = store.save(&chain).unwrap();
        assert_eq!(saved.checkpoint_path, store.checkpoint_path());
        assert!(saved.bytes_written > 32);
        assert!(store.checkpoint_path().exists());
        assert!(!store.temp_path().exists());

        let restored = store.load(cfg).unwrap().expect("checkpoint must exist");
        assert_eq!(restored.stats(), chain.stats());
        assert_eq!(restored.encode_checkpoint(), chain.encode_checkpoint());
        assert!(store.has_any_checkpoint());
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn has_any_checkpoint_false_when_only_stale_temp_exists() {
        let store = store_for("has_any_checkpoint_false_when_only_stale_temp_exists");
        fs::create_dir_all(store.root()).unwrap();
        fs::write(store.temp_path(), b"x").unwrap();
        assert!(!store.has_any_checkpoint());
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn load_rejects_checkpoint_from_foreign_genesis() {
        let store = store_for("load_rejects_checkpoint_from_foreign_genesis");
        let chain = Chain::from_genesis(ChainConfig::new(empty_genesis_cfg(0))).unwrap();
        store.save(&chain).unwrap();

        let foreign = ChainConfig::new(empty_genesis_cfg(99));
        match store.load(foreign) {
            Err(StoreError::Chain(ChainError::GenesisMismatch { .. })) => {}
            other => panic!("expected foreign genesis mismatch, got {other:?}"),
        }
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn load_recovers_from_backup_when_primary_is_missing() {
        let store = store_for("load_recovers_from_backup_when_primary_is_missing");
        let cfg = ChainConfig::new(empty_genesis_cfg(0));
        let chain = Chain::from_genesis(cfg.clone()).unwrap();
        store.save(&chain).unwrap();

        fs::rename(store.checkpoint_path(), store.backup_path()).unwrap();
        assert!(!store.checkpoint_path().exists());
        assert!(store.backup_path().exists());
        assert!(store.has_any_checkpoint());

        let restored = store.load(cfg).unwrap().expect("backup should restore");
        assert_eq!(restored.encode_checkpoint(), chain.encode_checkpoint());
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn save_removes_stale_temp_file_and_clear_removes_all_store_files() {
        let store = store_for("save_removes_stale_temp_file_and_clear_removes_all_store_files");
        fs::create_dir_all(store.root()).unwrap();
        fs::write(store.temp_path(), b"stale temp").unwrap();

        let chain = Chain::from_genesis(ChainConfig::new(empty_genesis_cfg(0))).unwrap();
        store.save(&chain).unwrap();
        assert!(!store.temp_path().exists());

        // A second save creates a backup slot.
        store.save(&chain).unwrap();
        assert!(store.checkpoint_path().exists());
        assert!(store.backup_path().exists());

        store.clear().unwrap();
        assert!(!store.checkpoint_path().exists());
        assert!(!store.backup_path().exists());
        assert!(!store.temp_path().exists());
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn read_block_log_empty_when_missing() {
        let store = store_for("read_block_log_empty_when_missing");
        assert!(store.read_block_log().unwrap().is_empty());
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn clear_removes_block_log() {
        let store = store_for("clear_removes_block_log");
        fs::create_dir_all(store.root()).unwrap();
        fs::write(store.block_log_path(), b"x").unwrap();
        store.clear().unwrap();
        assert!(!store.block_log_path().exists());
        fs::remove_dir_all(store.root()).ok();
    }
}
