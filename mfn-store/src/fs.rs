//! Filesystem-backed [`ChainStore`] (M2.1.0 checkpoint + M2.1.7 block sidecar).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use mfn_consensus::{decode_block, encode_block, Block};
use mfn_runtime::{Chain, ChainConfig};

use crate::r#trait::ChainPersistence;
use crate::validate::validate_block_log;
use crate::{StoreError, StoreSave};

const CHECKPOINT_FILE: &str = "chain.checkpoint";
const BACKUP_FILE: &str = "chain.checkpoint.bak";
const TEMP_FILE: &str = "chain.checkpoint.tmp";
const BLOCK_LOG_FILE: &str = "chain.blocks";

pub(crate) fn io_error(
    op: &'static str,
    path: impl Into<PathBuf>,
    source: std::io::Error,
) -> StoreError {
    StoreError::Io {
        op,
        path: path.into(),
        source,
    }
}

pub(crate) fn is_not_found(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotFound
}

pub(crate) fn remove_if_exists(path: &Path, op: &'static str) -> Result<(), StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if is_not_found(&e) => Ok(()),
        Err(e) => Err(io_error(op, path, e)),
    }
}

/// Directory-backed store for the latest [`Chain`] checkpoint and `chain.blocks` log.
///
/// Single-writer by convention: one daemon process owns mutations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStore {
    root: PathBuf,
}

impl ChainStore {
    /// Create a store rooted at `root` (no IO until [`Self::save`]).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Root directory owned by this store.
    #[must_use]
    pub fn root(&self) -> &Path {
        ChainPersistence::root(self)
    }

    /// Primary checkpoint path.
    #[must_use]
    pub fn checkpoint_path(&self) -> PathBuf {
        ChainPersistence::checkpoint_path(self)
    }

    /// Backup checkpoint path.
    #[must_use]
    pub fn backup_path(&self) -> PathBuf {
        ChainPersistence::backup_path(self)
    }

    /// Temporary checkpoint path used while staging a save.
    #[must_use]
    pub fn temp_path(&self) -> PathBuf {
        ChainPersistence::temp_path(self)
    }

    /// Append-only block log path (`chain.blocks`).
    #[must_use]
    pub fn block_log_path(&self) -> PathBuf {
        ChainPersistence::block_log_path(self)
    }

    /// Returns true if a durable checkpoint file exists (primary or backup).
    #[must_use]
    pub fn has_any_checkpoint(&self) -> bool {
        ChainPersistence::has_any_checkpoint(self)
    }

    /// Save `chain` to the primary checkpoint file.
    pub fn save(&self, chain: &Chain) -> Result<StoreSave, StoreError> {
        ChainPersistence::save(self, chain)
    }

    /// Load the latest checkpoint if one exists.
    pub fn load(&self, cfg: ChainConfig) -> Result<Option<Chain>, StoreError> {
        ChainPersistence::load(self, cfg)
    }

    /// Load a checkpoint if present; otherwise construct a fresh genesis chain.
    pub fn load_or_genesis(&self, cfg: ChainConfig) -> Result<Chain, StoreError> {
        ChainPersistence::load_or_genesis(self, cfg)
    }

    /// Append one canonical block record to `chain.blocks`.
    pub fn append_block(&self, block: &Block) -> Result<(), StoreError> {
        ChainPersistence::append_block(self, block)
    }

    /// Read every block in `chain.blocks` in order.
    pub fn read_block_log(&self) -> Result<Vec<Block>, StoreError> {
        ChainPersistence::read_block_log(self)
    }

    /// Read `chain.blocks` and verify it replays consistently with `chain`.
    pub fn read_block_log_validated(&self, chain: &Chain) -> Result<Vec<Block>, StoreError> {
        ChainPersistence::read_block_log_validated(self, chain)
    }

    /// Remove primary, backup, temp, and block-log files if present.
    pub fn clear(&self) -> Result<(), StoreError> {
        ChainPersistence::clear(self)
    }
}

impl ChainPersistence for ChainStore {
    fn root(&self) -> &Path {
        &self.root
    }

    fn checkpoint_path(&self) -> PathBuf {
        self.root.join(CHECKPOINT_FILE)
    }

    fn backup_path(&self) -> PathBuf {
        self.root.join(BACKUP_FILE)
    }

    fn temp_path(&self) -> PathBuf {
        self.root.join(TEMP_FILE)
    }

    fn block_log_path(&self) -> PathBuf {
        self.root.join(BLOCK_LOG_FILE)
    }

    fn has_any_checkpoint(&self) -> bool {
        self.checkpoint_path().exists() || self.backup_path().exists()
    }

    fn save(&self, chain: &Chain) -> Result<StoreSave, StoreError> {
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

    fn load(&self, cfg: ChainConfig) -> Result<Option<Chain>, StoreError> {
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

    fn load_or_genesis(&self, cfg: ChainConfig) -> Result<Chain, StoreError> {
        match self.load(cfg.clone())? {
            Some(chain) => Ok(chain),
            None => Ok(Chain::from_genesis(cfg)?),
        }
    }

    fn append_block(&self, block: &Block) -> Result<(), StoreError> {
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

    fn read_block_log(&self) -> Result<Vec<Block>, StoreError> {
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

    fn read_block_log_validated(&self, chain: &Chain) -> Result<Vec<Block>, StoreError> {
        let blocks = self.read_block_log()?;
        validate_block_log(chain, &blocks)?;
        Ok(blocks)
    }

    fn clear(&self) -> Result<(), StoreError> {
        remove_if_exists(&self.checkpoint_path(), "remove_checkpoint")?;
        remove_if_exists(&self.backup_path(), "remove_backup")?;
        remove_if_exists(&self.temp_path(), "remove_temp")?;
        remove_if_exists(&self.block_log_path(), "remove_block_log")?;
        crate::mempool_persist::remove_mempool_file(self.root())?;
        crate::peers_persist::remove_peers_file(self.root())?;
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
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: ConsensusParams {
                expected_proposers_per_slot: 1.0,
                quorum_stake_bps: 6667,
                ..ConsensusParams::default()
            },
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
            header_version: 1,
        }
    }

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "mfn-store-{test_name}-{}-{nanos}",
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
            Err(StoreError::Chain(mfn_runtime::ChainError::GenesisMismatch { .. })) => {}
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
    fn read_block_log_validated_ok_at_genesis_empty_log() {
        let store = store_for("read_block_log_validated_ok_at_genesis_empty_log");
        let chain = Chain::from_genesis(ChainConfig::new(empty_genesis_cfg(0))).unwrap();
        let blocks = store.read_block_log_validated(&chain).unwrap();
        assert!(blocks.is_empty());
        fs::remove_dir_all(store.root()).ok();
    }

    #[test]
    fn read_block_log_validated_rejects_count_mismatch() {
        let store = store_for("read_block_log_validated_rejects_count_mismatch");
        let cfg = ChainConfig::new(empty_genesis_cfg(0));
        let chain = Chain::from_genesis(cfg.clone()).unwrap();
        let gb = build_genesis(&cfg.genesis);
        store.append_block(&gb).unwrap();
        let err = store.read_block_log_validated(&chain).unwrap_err();
        match err {
            StoreError::BlockLog(s) => {
                assert!(
                    s.contains('1') && s.contains('0'),
                    "expected length vs tip_height mismatch: {s}"
                );
            }
            e => panic!("expected BlockLog error, got {e:?}"),
        }
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
