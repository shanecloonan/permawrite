//! On-disk objects addressed by their chunk-Merkle root.

use std::fs;
use std::path::PathBuf;

use mfn_storage::{chunk_data, merkle_tree_from_chunks, DEFAULT_CHUNK_SIZE};
use thiserror::Error;

/// Why a file was not stored or not served.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GatewayError {
    /// The chunk size is not a positive power of two.
    #[error("chunk size {0} is not a power of two")]
    ChunkSize(usize),
    /// The content id is not 32 bytes of hex.
    #[error("content id must be 64 hex characters")]
    BadId,
    /// The bytes on disk no longer hash to the content id.
    #[error("stored bytes do not match the content id")]
    RootMismatch,
    /// Nothing is stored under that id.
    #[error("not found")]
    NotFound,
    /// A path escaped the store directory.
    #[error("path escaped the store")]
    Escape,
    /// The listen address is not loopback.
    #[error("gateway listen address must be loopback")]
    NotLoopback,
    /// Filesystem error, kept as text so the library stays `Eq` in tests.
    #[error("io: {0}")]
    Io(String),
}

/// A directory of verified objects.
#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Open or create `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, GatewayError> {
        let root = dir.into();
        fs::create_dir_all(&root).map_err(|e| GatewayError::Io(e.to_string()))?;
        Ok(Self { root })
    }
}

/// Chunk-Merkle root, the same `data_root` an upload commits.
pub fn data_root(bytes: &[u8], chunk_size: usize) -> Result<[u8; 32], GatewayError> {
    if chunk_size == 0 || !chunk_size.is_power_of_two() {
        return Err(GatewayError::ChunkSize(chunk_size));
    }
    let chunks = chunk_data(bytes, chunk_size).map_err(|_| GatewayError::ChunkSize(chunk_size))?;
    let tree = merkle_tree_from_chunks(&chunks).map_err(|_| GatewayError::ChunkSize(chunk_size))?;
    Ok(tree.root())
}

/// Write `bytes` under their root. Returns the lower-case hex id.
pub fn ingest(store: &Store, bytes: &[u8]) -> Result<String, GatewayError> {
    let root = data_root(bytes, DEFAULT_CHUNK_SIZE)?;
    let id = hex::encode(root);
    let dir = object_dir(store, &id)?;
    fs::create_dir_all(&dir).map_err(|e| GatewayError::Io(e.to_string()))?;
    let payload = dir.join("payload");
    let tmp = dir.join("payload.tmp");
    fs::write(&tmp, bytes).map_err(|e| GatewayError::Io(e.to_string()))?;
    fs::rename(&tmp, &payload).map_err(|e| GatewayError::Io(e.to_string()))?;
    fs::write(dir.join("chunk_size"), DEFAULT_CHUNK_SIZE.to_string())
        .map_err(|e| GatewayError::Io(e.to_string()))?;
    // Read back and refuse to leave a file whose root drifted.
    let _ = load_verified(store, &id)?;
    Ok(id)
}

/// Load `id` only when the bytes still hash to that root.
pub fn load_verified(store: &Store, id: &str) -> Result<Vec<u8>, GatewayError> {
    let id = check_id(id)?;
    let dir = object_dir(store, &id)?;
    let payload_path = dir.join("payload");
    if !payload_path.is_file() {
        return Err(GatewayError::NotFound);
    }
    let bytes = fs::read(&payload_path).map_err(|e| GatewayError::Io(e.to_string()))?;
    let size_text =
        fs::read_to_string(dir.join("chunk_size")).map_err(|e| GatewayError::Io(e.to_string()))?;
    let chunk_size: usize = size_text
        .trim()
        .parse()
        .map_err(|_| GatewayError::ChunkSize(0))?;
    let actual = data_root(&bytes, chunk_size)?;
    if hex::encode(actual) != id {
        return Err(GatewayError::RootMismatch);
    }
    Ok(bytes)
}

fn check_id(id: &str) -> Result<String, GatewayError> {
    if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(GatewayError::BadId);
    }
    Ok(id.to_ascii_lowercase())
}

fn object_dir(store: &Store, id: &str) -> Result<PathBuf, GatewayError> {
    if id.contains('/') || id.contains('.') || id.contains('\\') {
        return Err(GatewayError::Escape);
    }
    let dir = store.root.join(id);
    if !dir.starts_with(&store.root) {
        return Err(GatewayError::Escape);
    }
    Ok(dir)
}

/// Tor hidden-service snippet that forwards to a loopback gateway.
pub fn onion_snippet(listen: &str, port: u16) -> Result<String, GatewayError> {
    if !is_loopback_host(listen) {
        return Err(GatewayError::NotLoopback);
    }
    if port == 0 {
        return Err(GatewayError::NotLoopback);
    }
    Ok(format!(
        "\
SocksPort 127.0.0.1:9050
HiddenServiceDir /var/lib/tor/permawrite-gateway
HiddenServicePort 80 {listen}:{port}
"
    ))
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mfn-gateway-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn ingest_then_load_round_trips_and_tamper_fails() {
        let dir = tmp();
        let store = Store::open(&dir).unwrap();
        let id = ingest(&store, b"permanent hello").unwrap();
        assert_eq!(load_verified(&store, &id).unwrap(), b"permanent hello");
        let payload = dir.join(&id).join("payload");
        let mut bytes = fs::read(&payload).unwrap();
        bytes[0] ^= 0xff;
        fs::write(&payload, &bytes).unwrap();
        assert_eq!(
            load_verified(&store, &id).unwrap_err(),
            GatewayError::RootMismatch
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_matches_the_storage_crate_and_empty_is_stable() {
        let bytes = b"abc";
        let root = data_root(bytes, DEFAULT_CHUNK_SIZE).unwrap();
        let chunks = chunk_data(bytes, DEFAULT_CHUNK_SIZE).unwrap();
        let again = merkle_tree_from_chunks(&chunks).unwrap().root();
        assert_eq!(root, again);
        let empty = data_root(b"", DEFAULT_CHUNK_SIZE).unwrap();
        assert_eq!(empty, data_root(b"", DEFAULT_CHUNK_SIZE).unwrap());
        assert_ne!(empty, root);
    }

    #[test]
    fn bad_id_and_public_onion_forward_are_refused() {
        let dir = tmp();
        let store = Store::open(&dir).unwrap();
        assert_eq!(
            load_verified(&store, "../secret").unwrap_err(),
            GatewayError::BadId
        );
        assert!(onion_snippet("127.0.0.1", 8788)
            .unwrap()
            .contains("127.0.0.1:8788"));
        assert_eq!(
            onion_snippet("0.0.0.0", 8788).unwrap_err(),
            GatewayError::NotLoopback
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
