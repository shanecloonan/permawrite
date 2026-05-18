//! Durable mempool snapshot under the node data directory (**M2.3.21**).

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use mfn_consensus::ChainState;
use mfn_runtime::{
    decode_mempool_snapshot, encode_mempool_snapshot, Mempool, MempoolRestoreStats,
};

use crate::error::StoreError;
use crate::fs::{io_error, is_not_found, remove_if_exists};
use crate::ChainPersistence;

/// Filename for the mempool snapshot in the data directory.
pub const MEMPOOL_FILE: &str = "mempool.bytes";
const MEMPOOL_TEMP_FILE: &str = "mempool.bytes.tmp";

/// Path to `mempool.bytes` under a persistence root.
#[must_use]
pub fn mempool_path(root: &Path) -> PathBuf {
    root.join(MEMPOOL_FILE)
}

fn mempool_temp_path(root: &Path) -> PathBuf {
    root.join(MEMPOOL_TEMP_FILE)
}

/// Metadata returned after a successful mempool save.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MempoolSaveMeta {
    /// Bytes written to `mempool.bytes`.
    pub bytes_written: usize,
    /// Number of transactions in the snapshot.
    pub tx_count: usize,
    /// Path to the primary snapshot file.
    pub path: PathBuf,
}

/// Persist `pool` atomically to `mempool.bytes`.
pub fn save_mempool(store: &dyn ChainPersistence, pool: &Mempool) -> Result<MempoolSaveMeta, StoreError> {
    let root = store.root();
    std::fs::create_dir_all(root).map_err(|e| io_error("create_dir_all", root, e))?;

    let path = mempool_path(root);
    let temp_path = mempool_temp_path(root);
    remove_if_exists(&temp_path, "remove_stale_mempool_temp")?;

    let bytes = encode_mempool_snapshot(pool);
    let tx_count = pool.len();
    {
        let mut file =
            File::create(&temp_path).map_err(|e| io_error("create_mempool_temp", &temp_path, e))?;
        file.write_all(&bytes)
            .map_err(|e| io_error("write_mempool_temp", &temp_path, e))?;
        file.sync_all()
            .map_err(|e| io_error("sync_mempool_temp", &temp_path, e))?;
    }
    std::fs::rename(&temp_path, &path).map_err(|e| io_error("publish_mempool", &path, e))?;

    Ok(MempoolSaveMeta {
        bytes_written: bytes.len(),
        tx_count,
        path,
    })
}

/// Load `mempool.bytes` if present and re-admit txs against `state`.
pub fn load_mempool(
    store: &dyn ChainPersistence,
    pool: &mut Mempool,
    state: &ChainState,
) -> Result<MempoolRestoreStats, StoreError> {
    let path = mempool_path(store.root());
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if is_not_found(&e) => return Ok(MempoolRestoreStats::default()),
        Err(e) => return Err(io_error("read_mempool", &path, e)),
    };
    let entries = decode_mempool_snapshot(&bytes).map_err(|e| StoreError::MempoolSnapshot {
        path: path.clone(),
        detail: e.to_string(),
    })?;
    Ok(pool.restore_snapshot(entries, state))
}

/// Remove the mempool snapshot file (no error if missing).
pub fn remove_mempool_file(root: &Path) -> Result<(), StoreError> {
    remove_if_exists(&mempool_path(root), "remove_mempool")?;
    remove_if_exists(&mempool_temp_path(root), "remove_mempool_temp")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_consensus::ChainState;
    use mfn_runtime::MempoolConfig;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::ChainStore;

    fn store_for(test: &str) -> ChainStore {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "permawrite-mempool-persist-{test}-{}-{nanos}",
            std::process::id()
        ));
        ChainStore::new(dir)
    }

    #[test]
    fn save_load_round_trip_empty() {
        let store = store_for("empty");
        let pool = Mempool::new(MempoolConfig::default());
        let meta = save_mempool(&store, &pool).expect("save");
        assert_eq!(meta.tx_count, 0);
        assert!(mempool_path(store.root()).exists());

        let mut pool2 = Mempool::new(MempoolConfig::default());
        let state = ChainState::default();
        let stats = load_mempool(&store, &mut pool2, &state).expect("load mempool");
        assert_eq!(stats.loaded, 0);
        assert!(pool2.is_empty());
        std::fs::remove_dir_all(store.root()).ok();
    }
}
