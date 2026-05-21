//! P2P-received storage chunks under the node data directory (**M7** / **M7.2**).

use std::io::Write;
use std::path::{Path, PathBuf};

/// Subdirectory under the chain store root for gossip-received chunks.
pub const CHUNK_INBOX_DIR: &str = "chunk-inbox";

/// Chunk inbox I/O errors.
#[derive(Debug, thiserror::Error)]
pub enum ChunkInboxError {
    /// Filesystem failure.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Missing chunk or invalid path.
    #[error("{0}")]
    Usage(String),
}

/// Directory for one commitment's inbox chunks.
pub fn chunk_inbox_commit_dir(data_root: &Path, commitment_hash_hex: &str) -> PathBuf {
    data_root
        .join(CHUNK_INBOX_DIR)
        .join(normalize_commit_hex(commitment_hash_hex))
}

/// Path to `{data_root}/chunk-inbox/{commit_hex}/{index}.bin`.
pub fn chunk_inbox_path(data_root: &Path, commitment_hash_hex: &str, chunk_index: u32) -> PathBuf {
    chunk_inbox_commit_dir(data_root, commitment_hash_hex).join(format!("{chunk_index}.bin"))
}

/// Write one chunk atomically (**M7**).
pub fn save_chunk_inbox(
    data_root: &Path,
    commit_hash: &[u8; 32],
    chunk_index: u32,
    chunk_bytes: &[u8],
) -> Result<PathBuf, ChunkInboxError> {
    let commit_hex = hex::encode(commit_hash);
    let dir = chunk_inbox_commit_dir(data_root, &commit_hex);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{chunk_index}.bin"));
    let temp = dir.join(format!("{chunk_index}.bin.tmp"));
    {
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(chunk_bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temp, &path)?;
    Ok(path)
}

/// Read one inbox chunk if present.
pub fn read_chunk_inbox(
    data_root: &Path,
    commitment_hash_hex: &str,
    chunk_index: u32,
) -> Result<Vec<u8>, ChunkInboxError> {
    let path = chunk_inbox_path(data_root, commitment_hash_hex, chunk_index);
    std::fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ChunkInboxError::Usage(format!(
                "missing chunk index {chunk_index} at {}",
                path.display()
            ))
        } else {
            ChunkInboxError::Io(e)
        }
    })
}

/// Indices of `{index}.bin` files present under the commitment inbox dir.
pub fn list_chunk_inbox_indices(
    data_root: &Path,
    commitment_hash_hex: &str,
) -> Result<Vec<u32>, ChunkInboxError> {
    let dir = chunk_inbox_commit_dir(data_root, commitment_hash_hex);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut indices = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(idx_str) = name.strip_suffix(".bin") {
            if let Ok(idx) = idx_str.parse::<u32>() {
                indices.push(idx);
            }
        }
    }
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}

/// Which chunk indices in `0..num_chunks` are missing from the inbox.
pub fn missing_chunk_inbox_indices(
    data_root: &Path,
    commitment_hash_hex: &str,
    num_chunks: u32,
) -> Result<Vec<u32>, ChunkInboxError> {
    let present: std::collections::BTreeSet<u32> =
        list_chunk_inbox_indices(data_root, commitment_hash_hex)?
            .into_iter()
            .collect();
    Ok((0..num_chunks).filter(|i| !present.contains(i)).collect())
}

/// Whether every chunk index `0..num_chunks` exists in the inbox.
pub fn chunk_inbox_complete(
    data_root: &Path,
    commitment_hash_hex: &str,
    num_chunks: u32,
) -> Result<bool, ChunkInboxError> {
    Ok(missing_chunk_inbox_indices(data_root, commitment_hash_hex, num_chunks)?.is_empty())
}

fn normalize_commit_hex(s: &str) -> String {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    t.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_read_and_list_chunk_inbox() {
        let dir = std::env::temp_dir().join(format!("mfn-store-inbox-{}", std::process::id()));
        let hash = [0x22u8; 32];
        let commit_hex = hex::encode(hash);
        let a = save_chunk_inbox(&dir, &hash, 0, b"aaa").expect("save0");
        let b = save_chunk_inbox(&dir, &hash, 2, b"ccc").expect("save2");
        assert!(a.is_file());
        assert!(b.is_file());
        assert_eq!(
            read_chunk_inbox(&dir, &commit_hex, 0).expect("read0"),
            b"aaa"
        );
        assert_eq!(
            read_chunk_inbox(&dir, &commit_hex, 2).expect("read2"),
            b"ccc"
        );
        assert_eq!(
            list_chunk_inbox_indices(&dir, &commit_hex).expect("list"),
            vec![0, 2]
        );
        assert_eq!(
            missing_chunk_inbox_indices(&dir, &commit_hex, 3).expect("missing"),
            vec![1]
        );
        assert!(!chunk_inbox_complete(&dir, &commit_hex, 3).expect("complete"));
        save_chunk_inbox(&dir, &hash, 1, b"bbb").expect("save1");
        assert!(chunk_inbox_complete(&dir, &commit_hex, 3).expect("complete2"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
