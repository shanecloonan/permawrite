//! Persist inbound P2P storage chunks under the node data directory (**M7**).

use std::io::Write;
use std::path::{Path, PathBuf};

/// Subdirectory under the chain store root for gossip-received chunks.
pub const CHUNK_INBOX_DIR: &str = "chunk-inbox";

/// Write one chunk to `{data_root}/chunk-inbox/{commit_hex}/{index}.bin`.
pub fn save_chunk_inbox(
    data_root: &Path,
    commit_hash: &[u8; 32],
    chunk_index: u32,
    chunk_bytes: &[u8],
) -> Result<PathBuf, String> {
    let commit_hex = hex::encode(commit_hash);
    let dir = data_root.join(CHUNK_INBOX_DIR).join(&commit_hex);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir_all: {e}"))?;
    let path = dir.join(format!("{chunk_index}.bin"));
    let temp = dir.join(format!("{chunk_index}.bin.tmp"));
    {
        let mut file = std::fs::File::create(&temp).map_err(|e| format!("create: {e}"))?;
        file.write_all(chunk_bytes)
            .map_err(|e| format!("write: {e}"))?;
        file.sync_all().map_err(|e| format!("sync: {e}"))?;
    }
    std::fs::rename(&temp, &path).map_err(|e| format!("rename: {e}"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_chunk_inbox_round_trip() {
        let dir = std::env::temp_dir().join(format!("mfn-chunk-inbox-{}", std::process::id()));
        let hash = [0x22u8; 32];
        let bytes = b"permawrite-chunk";
        let path = save_chunk_inbox(&dir, &hash, 3, bytes).expect("save");
        let got = std::fs::read(&path).expect("read");
        assert_eq!(got.as_slice(), bytes);
        let _ = std::fs::remove_dir_all(dir);
    }
}
