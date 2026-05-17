//! `mfnd` persistence backend selection (`--store fs` or `--store redb`).

use std::path::{Path, PathBuf};

use mfn_consensus::Block;
use mfn_runtime::{Chain, ChainConfig};
use mfn_store::{ChainPersistence, ChainStore, RedbChainStore, StoreError, StoreSave};

/// Checkpoint / block-log backend selected on the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreBackend {
    /// Flat files: `chain.checkpoint` + `chain.blocks`.
    Fs,
    /// Embedded `chain.redb`.
    Redb,
}

impl StoreBackend {
    /// Parse `fs` / `redb` (also accepts `filesystem`).
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "fs" | "filesystem" => Ok(Self::Fs),
            "redb" => Ok(Self::Redb),
            other => Err(format!("unknown --store `{other}` (use `fs` or `redb`)")),
        }
    }

    /// Stable label for status output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::Redb => "redb",
        }
    }
}

impl Default for StoreBackend {
    fn default() -> Self {
        Self::Fs
    }
}

/// Opened node store (filesystem or `redb`).
pub enum NodeStore {
    /// [`ChainStore`].
    Fs(ChainStore),
    /// [`RedbChainStore`].
    Redb(RedbChainStore),
}

impl NodeStore {
    /// Open the configured backend under `root`.
    pub fn open(backend: StoreBackend, root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        match backend {
            StoreBackend::Fs => Ok(Self::Fs(ChainStore::new(root))),
            StoreBackend::Redb => Ok(Self::Redb(RedbChainStore::new(root)?)),
        }
    }
}

impl ChainPersistence for NodeStore {
    fn root(&self) -> &Path {
        match self {
            Self::Fs(s) => ChainPersistence::root(s),
            Self::Redb(s) => ChainPersistence::root(s),
        }
    }

    fn checkpoint_path(&self) -> PathBuf {
        match self {
            Self::Fs(s) => ChainPersistence::checkpoint_path(s),
            Self::Redb(s) => ChainPersistence::checkpoint_path(s),
        }
    }

    fn backup_path(&self) -> PathBuf {
        match self {
            Self::Fs(s) => ChainPersistence::backup_path(s),
            Self::Redb(s) => ChainPersistence::backup_path(s),
        }
    }

    fn temp_path(&self) -> PathBuf {
        match self {
            Self::Fs(s) => ChainPersistence::temp_path(s),
            Self::Redb(s) => ChainPersistence::temp_path(s),
        }
    }

    fn block_log_path(&self) -> PathBuf {
        match self {
            Self::Fs(s) => ChainPersistence::block_log_path(s),
            Self::Redb(s) => ChainPersistence::block_log_path(s),
        }
    }

    fn has_any_checkpoint(&self) -> bool {
        match self {
            Self::Fs(s) => ChainPersistence::has_any_checkpoint(s),
            Self::Redb(s) => ChainPersistence::has_any_checkpoint(s),
        }
    }

    fn save(&self, chain: &Chain) -> Result<StoreSave, StoreError> {
        match self {
            Self::Fs(s) => ChainPersistence::save(s, chain),
            Self::Redb(s) => ChainPersistence::save(s, chain),
        }
    }

    fn load(&self, cfg: ChainConfig) -> Result<Option<Chain>, StoreError> {
        match self {
            Self::Fs(s) => ChainPersistence::load(s, cfg),
            Self::Redb(s) => ChainPersistence::load(s, cfg),
        }
    }

    fn load_or_genesis(&self, cfg: ChainConfig) -> Result<Chain, StoreError> {
        match self {
            Self::Fs(s) => ChainPersistence::load_or_genesis(s, cfg),
            Self::Redb(s) => ChainPersistence::load_or_genesis(s, cfg),
        }
    }

    fn append_block(&self, block: &Block) -> Result<(), StoreError> {
        match self {
            Self::Fs(s) => ChainPersistence::append_block(s, block),
            Self::Redb(s) => ChainPersistence::append_block(s, block),
        }
    }

    fn read_block_log(&self) -> Result<Vec<Block>, StoreError> {
        match self {
            Self::Fs(s) => ChainPersistence::read_block_log(s),
            Self::Redb(s) => ChainPersistence::read_block_log(s),
        }
    }

    fn read_block_log_validated(&self, chain: &Chain) -> Result<Vec<Block>, StoreError> {
        match self {
            Self::Fs(s) => ChainPersistence::read_block_log_validated(s, chain),
            Self::Redb(s) => ChainPersistence::read_block_log_validated(s, chain),
        }
    }

    fn clear(&self) -> Result<(), StoreError> {
        match self {
            Self::Fs(s) => ChainPersistence::clear(s),
            Self::Redb(s) => ChainPersistence::clear(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_backend_parse_accepts_aliases() {
        assert_eq!(StoreBackend::parse("fs").unwrap(), StoreBackend::Fs);
        assert_eq!(StoreBackend::parse("filesystem").unwrap(), StoreBackend::Fs);
        assert_eq!(StoreBackend::parse("redb").unwrap(), StoreBackend::Redb);
        assert!(StoreBackend::parse("sled").is_err());
    }
}
