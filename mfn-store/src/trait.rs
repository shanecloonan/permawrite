//! Persistence trait — swap filesystem for KV without touching the daemon.

use std::path::{Path, PathBuf};

use mfn_consensus::Block;
use mfn_runtime::{Chain, ChainConfig};

use crate::{StoreError, StoreSave};

/// Chain checkpoint + block-log persistence.
///
/// The default implementation is [`crate::fs::ChainStore`] (directory-backed).
/// Future milestones (`redb`, etc.) add additional implementors behind this trait.
pub trait ChainPersistence {
    /// Root directory or datastore identifier (filesystem: data dir).
    fn root(&self) -> &Path;

    /// Primary checkpoint path (filesystem layout only; KV backends may return a sentinel).
    fn checkpoint_path(&self) -> PathBuf;

    /// Backup checkpoint path.
    fn backup_path(&self) -> PathBuf;

    /// Staging checkpoint path used while saving.
    fn temp_path(&self) -> PathBuf;

    /// Append-only block log path.
    fn block_log_path(&self) -> PathBuf;

    /// True if a durable checkpoint exists (primary or backup).
    fn has_any_checkpoint(&self) -> bool;

    /// Persist the live chain snapshot.
    fn save(&self, chain: &Chain) -> Result<StoreSave, StoreError>;

    /// Load the latest checkpoint, if any.
    fn load(&self, cfg: ChainConfig) -> Result<Option<Chain>, StoreError>;

    /// Load checkpoint or construct genesis.
    fn load_or_genesis(&self, cfg: ChainConfig) -> Result<Chain, StoreError>;

    /// Append one canonical block to the block log.
    fn append_block(&self, block: &Block) -> Result<(), StoreError>;

    /// Read the block log without validation.
    fn read_block_log(&self) -> Result<Vec<Block>, StoreError>;

    /// Read and validate the block log against `chain`.
    fn read_block_log_validated(&self, chain: &Chain) -> Result<Vec<Block>, StoreError>;

    /// Remove checkpoint and block-log files (root directory kept).
    fn clear(&self) -> Result<(), StoreError>;
}
