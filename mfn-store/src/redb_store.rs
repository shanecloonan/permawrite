//! [`redb`](https://crates.io/crates/redb)-backed [`ChainPersistence`] (single `chain.redb` file).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mfn_consensus::{decode_block, encode_block, Block};
use mfn_runtime::{Chain, ChainConfig};
use redb::{Database, ReadableTable, TableDefinition};

use crate::fs::io_error;
use crate::r#trait::ChainPersistence;
use crate::validate::validate_block_log;
use crate::{StoreError, StoreSave};

const DB_FILE: &str = "chain.redb";
const CHECKPOINT: TableDefinition<&str, &[u8]> = TableDefinition::new("checkpoint");
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");
const KEY_PRIMARY: &str = "primary";
const KEY_BACKUP: &str = "backup";

fn db_err(context: &str, e: impl std::fmt::Display) -> StoreError {
    StoreError::Database(format!("{context}: {e}"))
}

/// Directory-backed store using an embedded `redb` database (`chain.redb`).
///
/// Same logical layout as [`crate::fs::ChainStore`]: primary/backup checkpoints and
/// height-keyed canonical blocks. Single-writer by convention.
#[derive(Debug)]
pub struct RedbChainStore {
    root: PathBuf,
    db: Arc<Database>,
}

impl PartialEq for RedbChainStore {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}

impl Eq for RedbChainStore {}

impl Clone for RedbChainStore {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            db: Arc::clone(&self.db),
        }
    }
}

impl RedbChainStore {
    /// Open or create `root/chain.redb`.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| io_error("create_dir_all", &root, e))?;
        let db_path = root.join(DB_FILE);
        let db = Database::create(&db_path).map_err(|e| db_err("create database", e))?;
        let write_txn = db
            .begin_write()
            .map_err(|e| db_err("begin_write init tables", e))?;
        {
            let _ = write_txn
                .open_table(CHECKPOINT)
                .map_err(|e| db_err("open_table checkpoint init", e))?;
            let _ = write_txn
                .open_table(BLOCKS)
                .map_err(|e| db_err("open_table blocks init", e))?;
        }
        write_txn
            .commit()
            .map_err(|e| db_err("commit init tables", e))?;
        Ok(Self {
            root,
            db: Arc::new(db),
        })
    }

    /// Root directory containing `chain.redb`.
    #[must_use]
    pub fn root(&self) -> &Path {
        ChainPersistence::root(self)
    }

    /// Path to the embedded `redb` database file.
    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        self.root.join(DB_FILE)
    }

    /// Primary checkpoint location (the `chain.redb` file for this backend).
    #[must_use]
    pub fn checkpoint_path(&self) -> PathBuf {
        ChainPersistence::checkpoint_path(self)
    }

    /// Backup checkpoint location (same file; logical backup key inside `redb`).
    #[must_use]
    pub fn backup_path(&self) -> PathBuf {
        ChainPersistence::backup_path(self)
    }

    /// Staging path sentinel (writes are transactional; no separate temp file).
    #[must_use]
    pub fn temp_path(&self) -> PathBuf {
        ChainPersistence::temp_path(self)
    }

    /// Block storage location sentinel (`blocks` table in `chain.redb`).
    #[must_use]
    pub fn block_log_path(&self) -> PathBuf {
        ChainPersistence::block_log_path(self)
    }

    /// Returns true if a durable checkpoint exists (primary or backup key).
    #[must_use]
    pub fn has_any_checkpoint(&self) -> bool {
        ChainPersistence::has_any_checkpoint(self)
    }

    /// Persist the live chain snapshot.
    pub fn save(&self, chain: &Chain) -> Result<StoreSave, StoreError> {
        ChainPersistence::save(self, chain)
    }

    /// Load the latest checkpoint, if any.
    pub fn load(&self, cfg: ChainConfig) -> Result<Option<Chain>, StoreError> {
        ChainPersistence::load(self, cfg)
    }

    /// Load checkpoint or construct genesis.
    pub fn load_or_genesis(&self, cfg: ChainConfig) -> Result<Chain, StoreError> {
        ChainPersistence::load_or_genesis(self, cfg)
    }

    /// Append one canonical block (keyed by `header.height`).
    pub fn append_block(&self, block: &Block) -> Result<(), StoreError> {
        ChainPersistence::append_block(self, block)
    }

    /// Read all blocks in height order.
    pub fn read_block_log(&self) -> Result<Vec<Block>, StoreError> {
        ChainPersistence::read_block_log(self)
    }

    /// Read and validate the block log against `chain`.
    pub fn read_block_log_validated(&self, chain: &Chain) -> Result<Vec<Block>, StoreError> {
        ChainPersistence::read_block_log_validated(self, chain)
    }

    /// Remove all checkpoint and block data from the database.
    pub fn clear(&self) -> Result<(), StoreError> {
        ChainPersistence::clear(self)
    }

    fn read_checkpoint_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| db_err("begin_read checkpoint", e))?;
        let table = txn
            .open_table(CHECKPOINT)
            .map_err(|e| db_err("open_table checkpoint", e))?;
        match table.get(key).map_err(|e| db_err("get checkpoint", e))? {
            Some(v) => Ok(Some(v.value().to_vec())),
            None => Ok(None),
        }
    }
}

impl ChainPersistence for RedbChainStore {
    fn root(&self) -> &Path {
        &self.root
    }

    fn checkpoint_path(&self) -> PathBuf {
        self.db_path()
    }

    fn backup_path(&self) -> PathBuf {
        self.db_path()
    }

    fn temp_path(&self) -> PathBuf {
        self.db_path()
    }

    fn block_log_path(&self) -> PathBuf {
        self.db_path()
    }

    fn has_any_checkpoint(&self) -> bool {
        self.read_checkpoint_bytes(KEY_PRIMARY)
            .map(|o| o.is_some())
            .unwrap_or(false)
            || self
                .read_checkpoint_bytes(KEY_BACKUP)
                .map(|o| o.is_some())
                .unwrap_or(false)
    }

    fn save(&self, chain: &Chain) -> Result<StoreSave, StoreError> {
        let bytes = chain.encode_checkpoint();
        let old_primary = self.read_checkpoint_bytes(KEY_PRIMARY)?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| db_err("begin_write save", e))?;
        {
            let mut table = write_txn
                .open_table(CHECKPOINT)
                .map_err(|e| db_err("open_table save", e))?;
            if let Some(prev) = old_primary {
                table
                    .insert(KEY_BACKUP, prev.as_slice())
                    .map_err(|e| db_err("insert backup", e))?;
            }
            table
                .insert(KEY_PRIMARY, bytes.as_slice())
                .map_err(|e| db_err("insert primary", e))?;
        }
        write_txn.commit().map_err(|e| db_err("commit save", e))?;

        Ok(StoreSave {
            bytes_written: bytes.len(),
            checkpoint_path: self.checkpoint_path(),
            backup_path: self.backup_path(),
        })
    }

    fn load(&self, cfg: ChainConfig) -> Result<Option<Chain>, StoreError> {
        if let Some(bytes) = self.read_checkpoint_bytes(KEY_PRIMARY)? {
            return Ok(Some(Chain::from_checkpoint_bytes(cfg, &bytes)?));
        }
        if let Some(bytes) = self.read_checkpoint_bytes(KEY_BACKUP)? {
            return Ok(Some(Chain::from_checkpoint_bytes(cfg, &bytes)?));
        }
        Ok(None)
    }

    fn load_or_genesis(&self, cfg: ChainConfig) -> Result<Chain, StoreError> {
        match self.load(cfg.clone())? {
            Some(chain) => Ok(chain),
            None => Ok(Chain::from_genesis(cfg)?),
        }
    }

    fn append_block(&self, block: &Block) -> Result<(), StoreError> {
        let height = u64::from(block.header.height);
        let payload = encode_block(block);
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| db_err("begin_write append_block", e))?;
        {
            let mut table = write_txn
                .open_table(BLOCKS)
                .map_err(|e| db_err("open_table blocks", e))?;
            if table
                .get(height)
                .map_err(|e| db_err("get block height", e))?
                .is_some()
            {
                return Err(StoreError::BlockLog(format!(
                    "block height {height} already stored"
                )));
            }
            table
                .insert(height, payload.as_slice())
                .map_err(|e| db_err("insert block", e))?;
        }
        write_txn
            .commit()
            .map_err(|e| db_err("commit append_block", e))?;
        Ok(())
    }

    fn read_block_log(&self) -> Result<Vec<Block>, StoreError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| db_err("begin_read blocks", e))?;
        let table = txn
            .open_table(BLOCKS)
            .map_err(|e| db_err("open_table blocks", e))?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(|e| db_err("iter blocks", e))? {
            let (_, v) = entry.map_err(|e| db_err("iter entry blocks", e))?;
            let block = decode_block(v.value()).map_err(|e| {
                StoreError::BlockLog(format!("decode_block at height-indexed key: {e}"))
            })?;
            out.push(block);
        }
        Ok(out)
    }

    fn read_block_log_validated(&self, chain: &Chain) -> Result<Vec<Block>, StoreError> {
        let blocks = self.read_block_log()?;
        validate_block_log(chain, &blocks)?;
        Ok(blocks)
    }

    fn clear(&self) -> Result<(), StoreError> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| db_err("begin_write clear", e))?;
        {
            let mut cp = write_txn
                .open_table(CHECKPOINT)
                .map_err(|e| db_err("open_table checkpoint clear", e))?;
            let _ = cp.remove(KEY_PRIMARY);
            let _ = cp.remove(KEY_BACKUP);

            let mut blocks = write_txn
                .open_table(BLOCKS)
                .map_err(|e| db_err("open_table blocks clear", e))?;
            let heights: Vec<u64> = blocks
                .iter()
                .map_err(|e| db_err("iter blocks clear", e))?
                .map(|res| {
                    res.map_err(|e| db_err("iter entry blocks clear", e))
                        .map(|(k, _)| k.value())
                })
                .collect::<Result<Vec<_>, _>>()?;
            for h in heights {
                blocks
                    .remove(h)
                    .map_err(|e| db_err("remove block clear", e))?;
            }
        }
        write_txn.commit().map_err(|e| db_err("commit clear", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_consensus::{build_genesis, ConsensusParams, GenesisConfig, DEFAULT_EMISSION_PARAMS};
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
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mfn-redb-store-{test_name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn store_for(test_name: &str) -> RedbChainStore {
        let root = temp_root(test_name);
        let _ = fs::remove_dir_all(&root);
        RedbChainStore::new(&root).expect("open redb store")
    }

    #[test]
    fn missing_snapshot_loads_none_and_boots_genesis() {
        let store = store_for("redb_missing_snapshot");
        let cfg = ChainConfig::new(empty_genesis_cfg(0));
        assert!(store.load(cfg.clone()).unwrap().is_none());
        let chain = store.load_or_genesis(cfg).unwrap();
        assert_eq!(chain.tip_height(), Some(0));
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn save_then_load_round_trips_chain_checkpoint() {
        let store = store_for("redb_save_load_roundtrip");
        let cfg = ChainConfig::new(empty_genesis_cfg(0));
        assert!(!store.has_any_checkpoint());
        let chain = Chain::from_genesis(cfg.clone()).unwrap();
        let saved = store.save(&chain).unwrap();
        assert!(saved.bytes_written > 32);
        assert!(store.db_path().exists());
        let restored = store.load(cfg).unwrap().expect("checkpoint");
        assert_eq!(restored.stats(), chain.stats());
        assert_eq!(restored.encode_checkpoint(), chain.encode_checkpoint());
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn load_recovers_from_backup_when_primary_is_missing() {
        let store = store_for("redb_backup_recovery");
        let cfg = ChainConfig::new(empty_genesis_cfg(0));
        let chain = Chain::from_genesis(cfg.clone()).unwrap();
        store.save(&chain).unwrap();
        store.save(&chain).unwrap();

        let write_txn = store.db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(CHECKPOINT).unwrap();
            table.remove(KEY_PRIMARY).unwrap();
        }
        write_txn.commit().unwrap();
        assert!(store.read_checkpoint_bytes(KEY_PRIMARY).unwrap().is_none());

        let restored = store.load(cfg).unwrap().expect("backup restores");
        assert_eq!(restored.encode_checkpoint(), chain.encode_checkpoint());
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn read_block_log_validated_ok_at_genesis_empty_log() {
        let store = store_for("redb_validated_genesis");
        let chain = Chain::from_genesis(ChainConfig::new(empty_genesis_cfg(0))).unwrap();
        assert!(store.read_block_log_validated(&chain).unwrap().is_empty());
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn append_and_read_block_log() {
        let store = store_for("redb_block_log");
        let cfg = ChainConfig::new(empty_genesis_cfg(0));
        let gb = build_genesis(&cfg.genesis);
        store.append_block(&gb).unwrap();
        let blocks = store.read_block_log().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].header.height, 0);
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn clear_empties_tables() {
        let store = store_for("redb_clear");
        let chain = Chain::from_genesis(ChainConfig::new(empty_genesis_cfg(0))).unwrap();
        store.save(&chain).unwrap();
        assert!(store.has_any_checkpoint());
        store.clear().unwrap();
        assert!(!store.has_any_checkpoint());
        fs::remove_dir_all(store.root()).ok();
    }
}
