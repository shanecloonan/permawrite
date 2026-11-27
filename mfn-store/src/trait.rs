//! Persistence trait — swap filesystem for KV without touching the daemon.

use std::path::{Path, PathBuf};

use mfn_consensus::Block;
use mfn_runtime::{Chain, ChainConfig};

use crate::{StoreError, StoreSave};

/// Chain checkpoint + block-log persistence.
///
/// Implementations: [`crate::fs::ChainStore`] (flat files) and [`crate::RedbChainStore`] (`redb`).
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

    /// Read up to `count` blocks starting at `start_height` (1-based), checked against `chain`.
    ///
    /// P2P block sync and light follow serve a handful of blocks per request. Decoding the
    /// whole log for each request is O(tip) CPU and memory while holding the chain lock, which
    /// stalled a tall-tip public devnet (peers timed out waiting and the producer grew until
    /// it was OOM-killed). Backends override this to decode only the requested records; the
    /// default keeps the old full-read behaviour.
    fn read_block_range_validated(
        &self,
        chain: &Chain,
        start_height: u32,
        count: u32,
    ) -> Result<Vec<Block>, StoreError> {
        let blocks = self.read_block_log_validated(chain)?;
        Ok(blocks
            .into_iter()
            .filter(|b| b.header.height >= start_height)
            .take(count as usize)
            .collect())
    }

    /// Remove checkpoint and block-log files (root directory kept).
    fn clear(&self) -> Result<(), StoreError>;
}
