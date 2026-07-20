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
/// Hard cap for `peers.json`-controlled reconnect fan-out.
pub const MAX_OUTBOUND_PEERS_LIMIT: u32 = 64;
/// Ports at or above this are treated as non-durable (IANA dynamic / typical
/// Linux `ip_local_port_range` floor). Listen addrs for committee/socat must stay below.
pub const MIN_EPHEMERAL_PEER_PORT: u16 = 32768;

const PEERS_FILE_VERSION: u8 = 1;

fn clamp_max_outbound_peers(value: u32) -> u32 {
    if value == 0 {
        DEFAULT_MAX_OUTBOUND_PEERS
    } else {
        value.min(MAX_OUTBOUND_PEERS_LIMIT)
    }
}

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

/// Normalized result of loading `peers.json`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeersLoadReport {
    /// Valid normalized peer addresses.
    pub peers: BTreeSet<String>,
    /// Reconnect cap after defaulting and clamping.
    pub max_outbound_peers: u32,
    /// Number of peer strings read from disk before filtering.
    pub raw_peer_count: usize,
    /// Number of empty, malformed, or duplicate peer entries ignored during normalization.
    pub filtered_peer_count: usize,
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
    let report = load_peers_with_report(root)?;
    Ok((report.peers, report.max_outbound_peers))
}

/// Load the peer set with normalization/filtering metadata for operator logs.
pub fn load_peers_with_report(root: &Path) -> Result<PeersLoadReport, StoreError> {
    let path = peers_path(root);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if is_not_found(&e) => {
            return Ok(PeersLoadReport {
                peers: BTreeSet::new(),
                max_outbound_peers: DEFAULT_MAX_OUTBOUND_PEERS,
                raw_peer_count: 0,
                filtered_peer_count: 0,
            });
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
    let max_outbound = clamp_max_outbound_peers(file.max_outbound_peers);
    let raw_peer_count = file.peers.len();
    let mut peers = BTreeSet::new();
    for p in file.peers {
        if let Some(norm) = normalize_peer_addr(&p) {
            peers.insert(norm);
        }
    }
    let filtered_peer_count = raw_peer_count.saturating_sub(peers.len());
    Ok(PeersLoadReport {
        peers,
        max_outbound_peers: max_outbound,
        raw_peer_count,
        filtered_peer_count,
    })
}

/// Atomically persist the peer set.
pub fn save_peers(
    root: &Path,
    peers: &BTreeSet<String>,
    max_outbound_peers: u32,
) -> Result<(), StoreError> {
    std::fs::create_dir_all(root).map_err(|e| io_error("create_dir_all", root, e))?;

    let path = peers_path(root);
    let temp_path = peers_temp_path(root);
    remove_if_exists(&temp_path, "remove_stale_peers_temp")?;

    let mut sorted: Vec<String> = peers
        .iter()
        .filter(|p| is_persistable_peer_addr(p))
        .cloned()
        .collect();
    sorted.sort();
    let file = PeersFileV1 {
        version: PEERS_FILE_VERSION,
        max_outbound_peers: clamp_max_outbound_peers(max_outbound_peers),
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

/// Whether `HOST:PORT` is safe to persist as a durable dial target (**B-71**).
///
/// Rejects unspecified (`0.0.0.0` / `::`), multicast, port 0, and dynamic ports
/// (>= [`MIN_EPHEMERAL_PEER_PORT`]) so inbound NAT / advertise-on-0 pollution
/// cannot re-enter `peers.json` after ops scrub.
#[must_use]
pub fn is_persistable_peer_addr(raw: &str) -> bool {
    normalize_peer_addr(raw).is_some()
}

fn normalize_peer_addr(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let addr: SocketAddr = s.parse().ok()?;
    if addr.port() == 0 || addr.port() >= MIN_EPHEMERAL_PEER_PORT {
        return None;
    }
    if addr.ip().is_unspecified() || addr.ip().is_multicast() {
        return None;
    }
    Some(addr.to_string())
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
    fn load_report_counts_filtered_peer_entries() {
        let dir = dir_for("load_report");
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            peers_path(&dir),
            r#"{"version":1,"max_outbound_peers":4,"peers":["127.0.0.1:9000"," 127.0.0.1:9000 ","bad peer",""]}"#,
        )
        .expect("write peers");

        let report = load_peers_with_report(&dir).expect("load");

        assert_eq!(report.raw_peer_count, 4);
        assert_eq!(report.filtered_peer_count, 3);
        assert_eq!(report.max_outbound_peers, 4);
        assert_eq!(report.peers.len(), 1);
        assert!(report.peers.contains("127.0.0.1:9000"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_missing_returns_empty() {
        let dir = dir_for("missing");
        let (peers, max) = load_peers(&dir).expect("load");
        assert!(peers.is_empty());
        assert_eq!(max, DEFAULT_MAX_OUTBOUND_PEERS);
    }

    #[test]
    fn load_clamps_peer_reconnect_cap() {
        let dir = dir_for("clamp_load");
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            peers_path(&dir),
            format!(
                r#"{{"version":1,"max_outbound_peers":{},"peers":["127.0.0.1:9000"]}}"#,
                MAX_OUTBOUND_PEERS_LIMIT + 1
            ),
        )
        .expect("write peers");

        let (_, max) = load_peers(&dir).expect("load");

        assert_eq!(max, MAX_OUTBOUND_PEERS_LIMIT);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_zero_peer_reconnect_cap_uses_default() {
        let dir = dir_for("zero_load");
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            peers_path(&dir),
            r#"{"version":1,"max_outbound_peers":0,"peers":["127.0.0.1:9000"]}"#,
        )
        .expect("write peers");

        let (_, max) = load_peers(&dir).expect("load");

        assert_eq!(max, DEFAULT_MAX_OUTBOUND_PEERS);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_clamps_peer_reconnect_cap() {
        let dir = dir_for("clamp_save");
        let mut peers = BTreeSet::new();
        peers.insert("127.0.0.1:9000".to_string());

        save_peers(&dir, &peers, MAX_OUTBOUND_PEERS_LIMIT + 1).expect("save");
        let raw = std::fs::read_to_string(peers_path(&dir)).expect("read peers");
        let file: PeersFileV1 = serde_json::from_str(&raw).expect("parse peers");

        assert_eq!(file.max_outbound_peers, MAX_OUTBOUND_PEERS_LIMIT);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn b71_filters_unspecified_and_dynamic_ports_on_load() {
        let dir = dir_for("b71_filter");
        std::fs::create_dir_all(&dir).expect("tmpdir");
        std::fs::write(
            peers_path(&dir),
            r#"{"version":1,"max_outbound_peers":8,"peers":["127.0.0.1:19101","0.0.0.0:55124","127.0.0.1:49614","5.161.201.73:19001"]}"#,
        )
        .expect("write peers");
        let report = load_peers_with_report(&dir).expect("load");
        assert_eq!(report.peers.len(), 2);
        assert!(report.peers.contains("127.0.0.1:19101"));
        assert!(report.peers.contains("5.161.201.73:19001"));
        assert!(!is_persistable_peer_addr("0.0.0.0:19001"));
        assert!(!is_persistable_peer_addr("127.0.0.1:49614"));
        assert!(is_persistable_peer_addr("127.0.0.1:19101"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
