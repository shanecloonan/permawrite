//! Replicate anchored payload bytes from a peer chunk server into wallet
//! upload artifacts (**M6.6**).

use std::path::{Path, PathBuf};

use curve25519_dalek::scalar::Scalar;
use mfn_storage::{decode_storage_commitment, storage_commitment_hash};
use mfn_wallet::{rebuild_built_commitment, UploadArtifactMeta};

use crate::chunk_client::{fetch_chunk_http, ChunkFetchError};
use crate::rpc::StorageChallenge;
use crate::upload_artifact_store::{
    has_upload_artifact, save_upload_artifact, UploadArtifactSaveMeta, UploadArtifactStoreError,
};

/// Backfill errors.
#[derive(Debug, thiserror::Error)]
pub enum BackfillError {
    /// Peer fetch failure.
    #[error("{0}")]
    Fetch(#[from] ChunkFetchError),
    /// Artifact store failure.
    #[error("{0}")]
    Store(#[from] UploadArtifactStoreError),
    /// Validation / usage.
    #[error("{0}")]
    Usage(String),
}

/// Outcome of a successful backfill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfillResult {
    /// Commitment hash hex (64 chars).
    pub commitment_hash_hex: String,
    /// Chunks fetched from the peer.
    pub chunks_fetched: u32,
    /// Assembled payload length.
    pub payload_bytes: usize,
    /// Persisted artifact directory.
    pub artifact_dir: PathBuf,
}

/// Fetch every chunk from `peer` and persist under `wallet_path` (**M6.6**).
///
/// Uses `ch` from `get_storage_challenge` for on-chain wire + dimensions.
/// Skips when an artifact already exists unless `force` is true.
/// Endowment Pedersen blinding is unknown for replicas; stored as zero — sufficient
/// for SPoRA proving (payload + Merkle tree + commitment wire).
pub fn backfill_upload_artifact_from_challenge(
    wallet_path: &Path,
    commitment_hash_hex: &str,
    peer: &str,
    ch: &StorageChallenge,
    force: bool,
) -> Result<BackfillResult, BackfillError> {
    if has_upload_artifact(wallet_path, commitment_hash_hex) && !force {
        return Err(BackfillError::Usage(format!(
            "upload artifact already exists for {commitment_hash_hex} (use `replace` to overwrite)"
        )));
    }
    let payload = fetch_payload_from_peer(peer, commitment_hash_hex, ch)?;
    let save = persist_backfill_artifact(wallet_path, ch, peer, &payload)?;
    Ok(BackfillResult {
        commitment_hash_hex: commitment_hash_hex.to_string(),
        chunks_fetched: ch.num_chunks,
        payload_bytes: save.payload_bytes,
        artifact_dir: save.dir,
    })
}

/// Fetch and concatenate all chunks for a commitment.
pub fn fetch_payload_from_peer(
    peer: &str,
    commitment_hash_hex: &str,
    ch: &StorageChallenge,
) -> Result<Vec<u8>, BackfillError> {
    let commit = commitment_from_challenge(ch)?;
    verify_challenge_commit_hash(ch, &commit)?;

    let mut payload = Vec::new();
    for idx in 0..ch.num_chunks {
        let chunk = fetch_chunk_http(peer, commitment_hash_hex, idx)?;
        payload.extend_from_slice(&chunk);
    }
    let expected_len = usize::try_from(ch.size_bytes)
        .map_err(|_| BackfillError::Usage("size_bytes overflow".into()))?;
    if payload.len() != expected_len {
        return Err(BackfillError::Usage(format!(
            "assembled payload len {} != on-chain size_bytes {}",
            payload.len(),
            ch.size_bytes
        )));
    }
    Ok(payload)
}

/// Persist assembled bytes after Merkle / size verification.
pub fn persist_backfill_artifact(
    wallet_path: &Path,
    ch: &StorageChallenge,
    peer: &str,
    payload: &[u8],
) -> Result<UploadArtifactSaveMeta, BackfillError> {
    let commit = commitment_from_challenge(ch)?;
    verify_challenge_commit_hash(ch, &commit)?;

    let meta = UploadArtifactMeta {
        commitment_wire: hex::decode(&ch.commitment_wire_hex)
            .map_err(|e| BackfillError::Usage(format!("commitment_wire_hex: {e}")))?,
        blinding: Scalar::ZERO,
        source_path: format!("backfill:{peer}"),
        tx_id: None,
    };
    let built = rebuild_built_commitment(&meta, payload)
        .map_err(|e| BackfillError::Usage(format!("rebuild commitment: {e}")))?;
    let source = Path::new(&meta.source_path);
    save_upload_artifact(wallet_path, &built, payload, source, None).map_err(Into::into)
}

fn commitment_from_challenge(
    ch: &StorageChallenge,
) -> Result<mfn_storage::StorageCommitment, BackfillError> {
    let wire = hex::decode(&ch.commitment_wire_hex)
        .map_err(|e| BackfillError::Usage(format!("commitment_wire_hex: {e}")))?;
    decode_storage_commitment(&wire)
        .map_err(|e| BackfillError::Usage(format!("decode commit: {e}")))
}

fn verify_challenge_commit_hash(
    ch: &StorageChallenge,
    commit: &mfn_storage::StorageCommitment,
) -> Result<(), BackfillError> {
    let on_chain = parse_hex32(&ch.commitment_hash)?;
    let local = storage_commitment_hash(commit);
    if local != on_chain {
        return Err(BackfillError::Usage(
            "commitment wire does not match commitment_hash".into(),
        ));
    }
    let data_root = parse_hex32(&ch.data_root)?;
    if commit.data_root != data_root {
        return Err(BackfillError::Usage(
            "commitment wire data_root does not match challenge".into(),
        ));
    }
    Ok(())
}

fn parse_hex32(s: &str) -> Result<[u8; 32], BackfillError> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() != 64 {
        return Err(BackfillError::Usage(format!(
            "expected 64 hex chars, got {}",
            t.len()
        )));
    }
    let bytes = hex::decode(t).map_err(|e| BackfillError::Usage(format!("hex: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_http::{serve_chunks, ChunkServeConfig};
    use crate::upload_artifact_store::save_upload_artifact;
    use mfn_storage::{
        build_storage_commitment, storage_commitment_hash, BuiltCommitment,
        DEFAULT_ENDOWMENT_PARAMS,
    };
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn ephemeral_listen_addr() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        format!("127.0.0.1:{port}")
    }

    fn sample_challenge(commit_hex: &str, built: &BuiltCommitment) -> StorageChallenge {
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
    fn fetch_and_persist_backfill_round_trip() {
        let dir = std::env::temp_dir().join(format!("mfn-backfill-{}", std::process::id()));
        let wallet = dir.join("op.json");
        std::fs::create_dir_all(&dir).expect("dir");
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
        let commit_hex = hex::encode(storage_commitment_hash(&built.commit));
        save_upload_artifact(&wallet, &built, &payload, Path::new("orig"), None).expect("save");

        let listen = ephemeral_listen_addr();
        let stop = Arc::new(AtomicBool::new(false));
        let wallet_serve = wallet.clone();
        let listen_bg = listen.clone();
        let stop_bg = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            serve_chunks(
                ChunkServeConfig {
                    wallet_path: wallet_serve,
                    listen_addr: listen_bg,
                },
                stop_bg,
            )
            .expect("serve");
        });
        std::thread::sleep(std::time::Duration::from_millis(150));

        let wallet2 = dir.join("replica.json");
        std::fs::write(&wallet2, b"{}").expect("wallet2");
        let ch = sample_challenge(&commit_hex, &built);
        let fetched = fetch_payload_from_peer(&listen, &commit_hex, &ch).expect("fetch");
        assert_eq!(fetched, payload);
        let save = persist_backfill_artifact(&wallet2, &ch, &listen, &fetched).expect("persist");
        assert!(save.dir.is_dir());
        let loaded = crate::upload_artifact_store::load_upload_artifact(&wallet2, &commit_hex)
            .expect("load");
        assert_eq!(loaded.payload, payload);
        assert_eq!(loaded.built.commit.data_root, built.commit.data_root);

        stop.store(true, Ordering::SeqCst);
        server.join().expect("join");
        let _ = std::fs::remove_dir_all(dir);
    }
}
