//! Persistent P2P peer set under the data directory (**M2.3.22**).

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::StoreError;
use crate::fs::{io_error, is_not_found, remove_if_exists};

/// Filename for the saved peer list in the data directory.
pub const PEERS_FILE: &str = "peers.json";
const PEERS_TEMP_FILE: &str = "peers.json.tmp";

/// Default cap on outbound reconnect dials per `mfnd serve` boot.
pub const DEFAULT_MAX_OUTBOUND_PEERS: u32 = 8;

const PEERS_FILE_VERSION: u8 = 1;

/// On-disk `peers.json` schema (version 1).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeersFileV1 {
    /// Schema version (must be [`PEERS_FILE_VERSION`]).
    pub version: u8,
    /// Maximum outbound reconnect attempts on boot.
    pub max_outbound_peers: u32,
    /// Dialable `HOST:PORT` strings (sorted on save).
    pub peers: Vec<String>,
}

impl PeersFileV1 {
    /// Empty file with default reconnect cap.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            version: PEERS_FILE_VERSION,
            max_outbound_peers: DEFAULT_MAX_OUTBOUND_PEERS,
            peers: Vec::new(),
        }
    }
}

/// Path to `peers.json` under a data directory root.
#[must_use]
pub fn peers_path(root: &Path) -> PathBuf {
    root.join(PEERS_FILE)
}

fn peers_temp_path(root: &Path) -> PathBuf {
    root.join(PEERS_TEMP_FILE)
}

/// Load the peer set from disk (missing file → empty set).
pub fn load_peers(root: &Path) -> Result<(BTreeSet<String>, u32), StoreError> {
    let path = peers_path(root);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if is_not_found(&e) => {
            return Ok((BTreeSet::new(), DEFAULT_MAX_OUTBOUND_PEERS));
        }
        Err(e) => return Err(io_error("read_peers", &path, e)),
    };
    let file: PeersFileV1 = serde_json::from_slice(&bytes).map_err(|e| StoreError::PeersJson {
        path: path.clone(),
        detail: e.to_string(),
    })?;
    if file.version != PEERS_FILE_VERSION {
        return Err(StoreError::PeersJson {
            path,
            detail: format!("unsupported version {}", file.version),
        });
    }
    let max_outbound = if file.max_outbound_peers == 0 {
        DEFAULT_MAX_OUTBOUND_PEERS
    } else {
        file.max_outbound_peers
    };
    let mut peers = BTreeSet::new();
    for p in file.peers {
        if let Some(norm) = normalize_peer_addr(&p) {
            peers.insert(norm);
        }
    }
    Ok((peers, max_outbound))
}

/// Atomically persist the peer set.
pub fn save_peers(root: &Path, peers: &BTreeSet<String>, max_outbound_peers: u32) -> Result<(), StoreError> {
    std::fs::create_dir_all(root).map_err(|e| io_error("create_dir_all", root, e))?;

    let path = peers_path(root);
    let temp_path = peers_temp_path(root);
    remove_if_exists(&temp_path, "remove_stale_peers_temp")?;

    let mut sorted: Vec<String> = peers.iter().cloned().collect();
    sorted.sort();
    let file = PeersFileV1 {
        version: PEERS_FILE_VERSION,
        max_outbound_peers: max_outbound_peers.max(1),
        peers: sorted,
    };
    let bytes = serde_json::to_vec_pretty(&file).map_err(|e| StoreError::PeersJson {
        path: path.clone(),
        detail: e.to_string(),
    })?;
    {
        let mut f =
            File::create(&temp_path).map_err(|e| io_error("create_peers_temp", &temp_path, e))?;
        f.write_all(&bytes)
            .map_err(|e| io_error("write_peers_temp", &temp_path, e))?;
        f.sync_all()
            .map_err(|e| io_error("sync_peers_temp", &temp_path, e))?;
    }
    std::fs::rename(&temp_path, &path).map_err(|e| io_error("publish_peers", &path, e))?;
    Ok(())
}

/// Remove `peers.json` (no error if missing).
pub fn remove_peers_file(root: &Path) -> Result<(), StoreError> {
    remove_if_exists(&peers_path(root), "remove_peers")?;
    remove_if_exists(&peers_temp_path(root), "remove_peers_temp")?;
    Ok(())
}

fn normalize_peer_addr(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    s.parse::<SocketAddr>().ok().map(|a| a.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn dir_for(test: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "permawrite-peers-persist-{test}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn save_load_round_trip_sorted() {
        let dir = dir_for("round_trip");
        let mut peers = BTreeSet::new();
        peers.insert("127.0.0.1:9001".to_string());
        peers.insert("127.0.0.1:9000".to_string());
        save_peers(&dir, &peers, 4).expect("save");
        let (loaded, max) = load_peers(&dir).expect("load");
        assert_eq!(max, 4);
        assert_eq!(loaded.len(), 2);
        let v: Vec<_> = loaded.into_iter().collect();
        assert_eq!(v[0], "127.0.0.1:9000");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_missing_returns_empty() {
        let dir = dir_for("missing");
        let (peers, max) = load_peers(&dir).expect("load");
        assert!(peers.is_empty());
        assert_eq!(max, DEFAULT_MAX_OUTBOUND_PEERS);
    }
}
