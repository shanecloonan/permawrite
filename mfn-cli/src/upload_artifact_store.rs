//! Wallet-side upload artifact persistence (**M3.24**).
//!
//! Layout: `{wallet_stem}.upload-artifacts/{commit_hash_hex}/`
//!   - `payload.bin` — exact bytes anchored on-chain
//!   - `meta.bytes` — canonical [`UploadArtifactMeta`] wire

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use mfn_storage::storage_commitment_hash;
use mfn_storage::BuiltCommitment;
use mfn_wallet::{
    decode_upload_artifact_meta, encode_upload_artifact_meta, rebuild_built_commitment,
    upload_artifact_meta_from_upload, UploadArtifactRebuildError,
};

/// Filename for anchored payload bytes.
pub const PAYLOAD_FILE: &str = "payload.bin";
/// Filename for metadata snapshot.
pub const META_FILE: &str = "meta.bytes";
const META_TEMP_FILE: &str = "meta.bytes.tmp";
const PAYLOAD_TEMP_FILE: &str = "payload.bin.tmp";

/// Loaded upload artifact (payload + rebuilt Merkle tree).
#[derive(Debug, Clone)]
pub struct LoadedUploadArtifact {
    /// Exact bytes that were uploaded.
    pub payload: Vec<u8>,
    /// Reconstructed prover-side commitment bundle.
    pub built: mfn_storage::BuiltCommitment,
    /// Original path at upload time (may be empty).
    pub source_path: String,
    /// `submit_tx` id when recorded.
    pub tx_id: Option<String>,
}

/// Filesystem / validation errors for upload artifacts.
#[derive(Debug, thiserror::Error)]
pub enum UploadArtifactStoreError {
    /// IO failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Metadata codec failure.
    #[error("meta: {0}")]
    Meta(#[from] mfn_wallet::UploadArtifactMetaError),
    /// Rebuild failure.
    #[error("rebuild: {0}")]
    Rebuild(#[from] UploadArtifactRebuildError),
    /// Invalid path / hash / layout.
    #[error("{0}")]
    Invalid(String),
}

/// Metadata returned after a successful save.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadArtifactSaveMeta {
    /// Directory holding this commitment's artifacts.
    pub dir: PathBuf,
    /// Payload bytes written.
    pub payload_bytes: usize,
    /// Metadata bytes written.
    pub meta_bytes: usize,
}

/// Root directory for all uploads tied to a wallet file.
///
/// `wallet.json` → `./wallet.upload-artifacts/`
#[must_use]
pub fn upload_artifacts_root(wallet_path: &Path) -> PathBuf {
    let parent = wallet_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = wallet_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("wallet");
    parent.join(format!("{stem}.upload-artifacts"))
}

/// Per-commitment artifact directory.
#[must_use]
pub fn upload_artifact_dir(wallet_path: &Path, commit_hash: &[u8; 32]) -> PathBuf {
    upload_artifacts_root(wallet_path).join(hex::encode(commit_hash))
}

/// Persist payload + metadata for an upload (atomic meta write).
pub fn save_upload_artifact(
    wallet_path: &Path,
    built: &BuiltCommitment,
    payload: &[u8],
    source_path: &Path,
    tx_id: Option<&str>,
) -> Result<UploadArtifactSaveMeta, UploadArtifactStoreError> {
    let commit_hash = storage_commitment_hash(&built.commit);
    let dir = upload_artifact_dir(wallet_path, &commit_hash);
    std::fs::create_dir_all(&dir)?;

    let payload_path = dir.join(PAYLOAD_FILE);
    let payload_temp = dir.join(PAYLOAD_TEMP_FILE);
    remove_if_exists(&payload_temp)?;
    write_atomic_bytes(&payload_temp, payload)?;
    std::fs::rename(&payload_temp, &payload_path)?;

    let meta = upload_artifact_meta_from_upload(built, &source_path.display().to_string(), tx_id);
    let meta_bytes = encode_upload_artifact_meta(&meta);
    let meta_path = dir.join(META_FILE);
    let meta_temp = dir.join(META_TEMP_FILE);
    remove_if_exists(&meta_temp)?;
    write_atomic_bytes(&meta_temp, &meta_bytes)?;
    std::fs::rename(&meta_temp, &meta_path)?;

    Ok(UploadArtifactSaveMeta {
        dir,
        payload_bytes: payload.len(),
        meta_bytes: meta_bytes.len(),
    })
}

/// Load a persisted upload by commitment hash (hex).
pub fn load_upload_artifact(
    wallet_path: &Path,
    commitment_hash_hex: &str,
) -> Result<LoadedUploadArtifact, UploadArtifactStoreError> {
    let commit_hash = parse_commit_hash_hex(commitment_hash_hex)?;
    let dir = upload_artifact_dir(wallet_path, &commit_hash);
    if !dir.is_dir() {
        return Err(UploadArtifactStoreError::Invalid(format!(
            "no upload artifact for {commitment_hash_hex} under {}",
            upload_artifacts_root(wallet_path).display()
        )));
    }
    let payload_path = dir.join(PAYLOAD_FILE);
    let meta_path = dir.join(META_FILE);
    let payload = std::fs::read(&payload_path).map_err(|e| {
        UploadArtifactStoreError::Invalid(format!("read {}: {e}", payload_path.display()))
    })?;
    let meta_bytes = std::fs::read(&meta_path).map_err(|e| {
        UploadArtifactStoreError::Invalid(format!("read {}: {e}", meta_path.display()))
    })?;
    let meta = decode_upload_artifact_meta(&meta_bytes)?;
    let wire_hash = storage_commitment_hash(
        &mfn_storage::decode_storage_commitment(&meta.commitment_wire).map_err(|e| {
            UploadArtifactStoreError::Invalid(format!("commitment wire in meta: {e}"))
        })?,
    );
    if wire_hash != commit_hash {
        return Err(UploadArtifactStoreError::Invalid(
            "artifact directory name does not match commitment wire hash".into(),
        ));
    }
    let built = rebuild_built_commitment(&meta, &payload)?;
    Ok(LoadedUploadArtifact {
        payload,
        built,
        source_path: meta.source_path,
        tx_id: meta.tx_id,
    })
}

/// Whether an artifact exists for `commitment_hash_hex`.
#[must_use]
pub fn has_upload_artifact(wallet_path: &Path, commitment_hash_hex: &str) -> bool {
    parse_commit_hash_hex(commitment_hash_hex)
        .ok()
        .is_some_and(|h| upload_artifact_dir(wallet_path, &h).is_dir())
}

fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), UploadArtifactStoreError> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), UploadArtifactStoreError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn parse_commit_hash_hex(s: &str) -> Result<[u8; 32], UploadArtifactStoreError> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() != 64 {
        return Err(UploadArtifactStoreError::Invalid(format!(
            "commitment hash must be 64 hex chars, got {}",
            t.len()
        )));
    }
    let bytes =
        hex::decode(t).map_err(|e| UploadArtifactStoreError::Invalid(format!("hex: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_storage::{build_storage_commitment, DEFAULT_ENDOWMENT_PARAMS};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_wallet(test: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "permawrite-upload-artifact-{test}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    #[test]
    fn save_load_round_trip() {
        let wallet = temp_wallet("rt");
        let payload: Vec<u8> = (0u32..1024).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(512),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let hash = storage_commitment_hash(&built.commit);
        let meta =
            save_upload_artifact(&wallet, &built, &payload, Path::new("doc.bin"), Some("tx1"))
                .expect("save");
        assert!(meta.dir.exists());
        let loaded = load_upload_artifact(&wallet, &hex::encode(hash)).expect("load");
        assert_eq!(loaded.payload, payload);
        assert_eq!(loaded.built.commit, built.commit);
        assert_eq!(loaded.built.tree.root(), built.tree.root());
        assert_eq!(loaded.tx_id.as_deref(), Some("tx1"));
        std::fs::remove_dir_all(upload_artifacts_root(&wallet)).ok();
        std::fs::remove_file(&wallet).ok();
    }
}
