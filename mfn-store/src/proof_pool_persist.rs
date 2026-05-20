//! Durable proof-pool snapshot under the node data directory (**M3.23**).

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use mfn_consensus::ChainState;
use mfn_runtime::{
    decode_proof_pool_snapshot, encode_proof_pool_snapshot, ProofPool, ProofPoolRestoreStats,
};

use crate::error::StoreError;
use crate::fs::{io_error, is_not_found, remove_if_exists};
use crate::ChainPersistence;

/// Filename for the proof-pool snapshot in the data directory.
pub const PROOF_POOL_FILE: &str = "proof_pool.bytes";
const PROOF_POOL_TEMP_FILE: &str = "proof_pool.bytes.tmp";

/// Path to `proof_pool.bytes` under a persistence root.
#[must_use]
pub fn proof_pool_path(root: &Path) -> PathBuf {
    root.join(PROOF_POOL_FILE)
}

fn proof_pool_temp_path(root: &Path) -> PathBuf {
    root.join(PROOF_POOL_TEMP_FILE)
}

/// Metadata returned after a successful proof-pool save.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofPoolSaveMeta {
    /// Bytes written to `proof_pool.bytes`.
    pub bytes_written: usize,
    /// Number of proofs in the snapshot.
    pub proof_count: usize,
    /// Path to the primary snapshot file.
    pub path: PathBuf,
}

/// Persist `pool` atomically to `proof_pool.bytes`.
pub fn save_proof_pool(
    store: &dyn ChainPersistence,
    pool: &ProofPool,
) -> Result<ProofPoolSaveMeta, StoreError> {
    let root = store.root();
    std::fs::create_dir_all(root).map_err(|e| io_error("create_dir_all", root, e))?;

    let path = proof_pool_path(root);
    let temp_path = proof_pool_temp_path(root);
    remove_if_exists(&temp_path, "remove_stale_proof_pool_temp")?;

    let bytes = encode_proof_pool_snapshot(pool);
    let proof_count = pool.len();
    {
        let mut file = File::create(&temp_path)
            .map_err(|e| io_error("create_proof_pool_temp", &temp_path, e))?;
        file.write_all(&bytes)
            .map_err(|e| io_error("write_proof_pool_temp", &temp_path, e))?;
        file.sync_all()
            .map_err(|e| io_error("sync_proof_pool_temp", &temp_path, e))?;
    }
    std::fs::rename(&temp_path, &path).map_err(|e| io_error("publish_proof_pool", &path, e))?;

    Ok(ProofPoolSaveMeta {
        bytes_written: bytes.len(),
        proof_count,
        path,
    })
}

/// Load `proof_pool.bytes` if present and re-admit proofs for the next block.
pub fn load_proof_pool(
    store: &dyn ChainPersistence,
    pool: &mut ProofPool,
    state: &ChainState,
    prev_block_id: &[u8; 32],
    next_height: u32,
) -> Result<ProofPoolRestoreStats, StoreError> {
    let path = proof_pool_path(store.root());
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if is_not_found(&e) => return Ok(ProofPoolRestoreStats::default()),
        Err(e) => return Err(io_error("read_proof_pool", &path, e)),
    };
    let proofs = decode_proof_pool_snapshot(&bytes).map_err(|e| StoreError::ProofPoolSnapshot {
        path: path.clone(),
        detail: e.to_string(),
    })?;
    Ok(pool.restore_snapshot(proofs, state, prev_block_id, next_height))
}

/// Remove the proof-pool snapshot file (no error if missing).
pub fn remove_proof_pool_file(root: &Path) -> Result<(), StoreError> {
    remove_if_exists(&proof_pool_path(root), "remove_proof_pool")?;
    remove_if_exists(&proof_pool_temp_path(root), "remove_proof_pool_temp")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_runtime::ProofPoolConfig;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::ChainStore;

    fn store_for(test: &str) -> ChainStore {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "permawrite-proof-pool-persist-{test}-{}-{nanos}",
            std::process::id()
        ));
        ChainStore::new(dir)
    }

    #[test]
    fn save_load_round_trip_empty() {
        let store = store_for("empty");
        let pool = ProofPool::new(ProofPoolConfig::default());
        let meta = save_proof_pool(&store, &pool).expect("save");
        assert_eq!(meta.proof_count, 0);
        assert!(proof_pool_path(store.root()).exists());

        let mut pool2 = ProofPool::new(ProofPoolConfig::default());
        let state = mfn_consensus::ChainState::default();
        let prev = [0u8; 32];
        let stats = load_proof_pool(&store, &mut pool2, &state, &prev, 1).expect("load");
        assert_eq!(stats.loaded, 0);
        assert!(pool2.is_empty());
        std::fs::remove_dir_all(store.root()).ok();
    }
}
