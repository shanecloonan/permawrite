//! Assemble wallet upload artifacts from a node's P2P `chunk-inbox/` (**M7.2**).

use std::path::{Path, PathBuf};

use mfn_store::{
    chunk_inbox_complete, list_chunk_inbox_indices, missing_chunk_inbox_indices, read_chunk_inbox,
    ChunkInboxError,
};

use crate::backfill::{persist_backfill_artifact, BackfillError};
use crate::rpc::StorageChallenge;
use crate::upload_artifact_store::has_upload_artifact;

/// Inbox assembly errors.
#[derive(Debug, thiserror::Error)]
pub enum InboxBackfillError {
    /// Chunk inbox read failure.
    #[error("{0}")]
    Inbox(#[from] ChunkInboxError),
    /// Artifact persistence failure.
    #[error("{0}")]
    Backfill(#[from] BackfillError),
    /// Validation / usage.
    #[error("{0}")]
    Usage(String),
}

/// Snapshot of which inbox chunks are present for a commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxChunkStatus {
    /// Commitment hash hex (64 chars).
    pub commitment_hash_hex: String,
    /// Node data directory root.
    pub data_dir: PathBuf,
    /// On-chain chunk count from the challenge.
    pub num_chunks: u32,
    /// Indices present on disk.
    pub present_indices: Vec<u32>,
    /// Indices still missing.
    pub missing_indices: Vec<u32>,
    /// True when `missing_indices` is empty.
    pub complete: bool,
}

/// Inspect `chunk-inbox/` for one commitment.
pub fn inbox_chunk_status(
    data_dir: &Path,
    commitment_hash_hex: &str,
    num_chunks: u32,
) -> Result<InboxChunkStatus, InboxBackfillError> {
    let present = list_chunk_inbox_indices(data_dir, commitment_hash_hex)?;
    let missing = missing_chunk_inbox_indices(data_dir, commitment_hash_hex, num_chunks)?;
    let complete = chunk_inbox_complete(data_dir, commitment_hash_hex, num_chunks)?;
    Ok(InboxChunkStatus {
        commitment_hash_hex: commitment_hash_hex.to_string(),
        data_dir: data_dir.to_path_buf(),
        num_chunks,
        present_indices: present,
        missing_indices: missing,
        complete,
    })
}

/// Concatenate all inbox chunks `0..num_chunks` using challenge dimensions.
pub fn fetch_payload_from_inbox(
    data_dir: &Path,
    commitment_hash_hex: &str,
    ch: &StorageChallenge,
) -> Result<Vec<u8>, InboxBackfillError> {
    let status = inbox_chunk_status(data_dir, commitment_hash_hex, ch.num_chunks)?;
    if !status.complete {
        return Err(InboxBackfillError::Usage(format!(
            "chunk-inbox incomplete: missing indices {:?} (have {:?})",
            status.missing_indices, status.present_indices
        )));
    }

    let mut payload = Vec::new();
    for idx in 0..ch.num_chunks {
        let chunk = read_chunk_inbox(data_dir, commitment_hash_hex, idx)?;
        payload.extend_from_slice(&chunk);
    }
    let expected_len = usize::try_from(ch.size_bytes)
        .map_err(|_| InboxBackfillError::Usage("size_bytes overflow".into()))?;
    if payload.len() != expected_len {
        return Err(InboxBackfillError::Usage(format!(
            "assembled payload len {} != on-chain size_bytes {}",
            payload.len(),
            ch.size_bytes
        )));
    }
    Ok(payload)
}

/// Assemble inbox chunks + `get_storage_challenge` metadata into a wallet artifact (**M7.2**).
pub fn backfill_upload_artifact_from_inbox(
    wallet_path: &Path,
    data_dir: &Path,
    commitment_hash_hex: &str,
    ch: &StorageChallenge,
    force: bool,
) -> Result<crate::backfill::BackfillResult, InboxBackfillError> {
    if has_upload_artifact(wallet_path, commitment_hash_hex) && !force {
        return Err(InboxBackfillError::Usage(format!(
            "upload artifact already exists for {commitment_hash_hex} (use `replace` to overwrite)"
        )));
    }
    let payload = fetch_payload_from_inbox(data_dir, commitment_hash_hex, ch)?;
    let source_label = format!("inbox:{}", data_dir.display());
    let save = persist_backfill_artifact(wallet_path, ch, &source_label, &payload)?;
    Ok(crate::backfill::BackfillResult {
        commitment_hash_hex: commitment_hash_hex.to_string(),
        chunks_fetched: ch.num_chunks,
        payload_bytes: save.payload_bytes,
        artifact_dir: save.dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upload_artifact_store::load_upload_artifact;
    use mfn_storage::{
        build_storage_commitment, storage_commitment_hash, DEFAULT_ENDOWMENT_PARAMS,
    };
    use mfn_store::save_chunk_inbox;

    fn sample_challenge(
        commit_hex: &str,
        built: &mfn_storage::BuiltCommitment,
    ) -> StorageChallenge {
        StorageChallenge {
            commitment_hash: commit_hex.to_string(),
            commitment_wire_hex: hex::encode(mfn_storage::encode_storage_commitment(&built.commit)),
            data_root: hex::encode(built.commit.data_root),
            size_bytes: built.commit.size_bytes,
            replication: built.commit.replication,
            num_chunks: built.commit.num_chunks,
            chunk_size: built.commit.chunk_size,
            next_height: 2,
            next_slot: 2,
            prev_block_id: "00".repeat(32),
            chunk_index: 0,
        }
    }

    #[test]
    fn assemble_inbox_into_wallet_artifact() {
        let dir = std::env::temp_dir().join(format!("mfn-inbox-bf-{}", std::process::id()));
        let wallet = dir.join("w.json");
        let data_dir = dir.join("node");
        std::fs::create_dir_all(&data_dir).expect("dir");
        std::fs::write(&wallet, b"{}").expect("wallet");

        let payload: Vec<u8> = (0u32..8000).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(4096),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let commit = storage_commitment_hash(&built.commit);
        let commit_hex = hex::encode(commit);
        let chunks =
            mfn_storage::chunk_data(&payload, built.commit.chunk_size as usize).expect("chunks");
        for (i, bytes) in chunks.iter().enumerate() {
            save_chunk_inbox(&data_dir, &commit, u32::try_from(i).unwrap(), bytes)
                .expect("save chunk");
        }

        let ch = sample_challenge(&commit_hex, &built);
        let result =
            backfill_upload_artifact_from_inbox(&wallet, &data_dir, &commit_hex, &ch, false)
                .expect("assemble");
        assert_eq!(result.payload_bytes, payload.len());
        let loaded = load_upload_artifact(&wallet, &commit_hex).expect("load");
        assert_eq!(loaded.payload, payload);
        let _ = std::fs::remove_dir_all(dir);
    }
}
