//! Canonical upload-artifact metadata codec (**M3.24**).
//!
//! Payload bytes live beside this blob as `payload.bin`; metadata holds the
//! on-wire [`StorageCommitment`], Pedersen blinding, and optional provenance.

use curve25519_dalek::scalar::Scalar;

use mfn_crypto::codec::{Reader, Writer};
use mfn_storage::{
    chunk_data, decode_storage_commitment, encode_storage_commitment, merkle_tree_from_chunks,
    BuiltCommitment, SporaError,
};

/// Magic prefix for [`encode_upload_artifact_meta`].
pub const UPLOAD_ARTIFACT_META_MAGIC: &[u8] = b"MFNUPLD1";

/// Current metadata version byte.
pub const UPLOAD_ARTIFACT_META_VERSION: u8 = 1;

/// Failure encoding or decoding upload-artifact metadata.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum UploadArtifactMetaError {
    /// File shorter than the magic header.
    #[error("metadata too short")]
    TooShort,
    /// Magic bytes do not match.
    #[error("bad magic")]
    BadMagic,
    /// Unsupported version byte.
    #[error("unsupported metadata version {0}")]
    UnsupportedVersion(u8),
    /// Codec or field decode failure.
    #[error("decode: {0}")]
    Decode(String),
}

/// Metadata persisted next to `payload.bin` for one upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadArtifactMeta {
    /// On-wire storage commitment (matches the mined tx output).
    pub commitment_wire: Vec<u8>,
    /// Pedersen blinding for `commit.endowment` (endowment opening later).
    pub blinding: Scalar,
    /// Original local path at upload time (informational).
    pub source_path: String,
    /// `submit_tx` tx id when known (64-char hex without prefix).
    pub tx_id: Option<String>,
}

/// Encode metadata to canonical bytes.
#[must_use]
pub fn encode_upload_artifact_meta(meta: &UploadArtifactMeta) -> Vec<u8> {
    let mut w = Writer::new();
    w.blob(UPLOAD_ARTIFACT_META_MAGIC);
    w.u8(UPLOAD_ARTIFACT_META_VERSION);
    w.blob(&meta.commitment_wire);
    w.scalar(&meta.blinding);
    w.blob(meta.source_path.as_bytes());
    if let Some(tx_id) = &meta.tx_id {
        w.u8(1);
        w.blob(tx_id.as_bytes());
    } else {
        w.u8(0);
    }
    w.into_bytes()
}

/// Decode metadata written by [`encode_upload_artifact_meta`].
pub fn decode_upload_artifact_meta(
    bytes: &[u8],
) -> Result<UploadArtifactMeta, UploadArtifactMetaError> {
    let mut r = Reader::new(bytes);
    let magic = r.blob().map_err(decode_err)?;
    if magic != UPLOAD_ARTIFACT_META_MAGIC {
        return Err(if bytes.len() < UPLOAD_ARTIFACT_META_MAGIC.len() {
            UploadArtifactMetaError::TooShort
        } else {
            UploadArtifactMetaError::BadMagic
        });
    }
    let version = r.u8().map_err(decode_err)?;
    if version != UPLOAD_ARTIFACT_META_VERSION {
        return Err(UploadArtifactMetaError::UnsupportedVersion(version));
    }
    let commitment_wire = r.blob().map_err(decode_err)?.to_vec();
    let blinding = r.scalar().map_err(decode_err)?;
    let source_path = String::from_utf8(r.blob().map_err(decode_err)?.to_vec())
        .map_err(|e| UploadArtifactMetaError::Decode(format!("source_path utf8: {e}")))?;
    let has_tx = r.u8().map_err(decode_err)?;
    let tx_id = match has_tx {
        0 => None,
        1 => Some(
            String::from_utf8(r.blob().map_err(decode_err)?.to_vec())
                .map_err(|e| UploadArtifactMetaError::Decode(format!("tx_id utf8: {e}")))?,
        ),
        other => {
            return Err(UploadArtifactMetaError::Decode(format!(
                "tx_id flag {other}"
            )));
        }
    };
    Ok(UploadArtifactMeta {
        commitment_wire,
        blinding,
        source_path,
        tx_id,
    })
}

/// Failure rebuilding a [`BuiltCommitment`] from disk.
#[derive(Debug, thiserror::Error)]
pub enum UploadArtifactRebuildError {
    /// On-wire commitment decode failed.
    #[error("commitment wire: {0}")]
    CommitmentWire(String),
    /// Payload length does not match `commit.size_bytes`.
    #[error("payload size {actual} != on-chain size_bytes {expected}")]
    PayloadSize {
        /// Bytes read from `payload.bin`.
        actual: usize,
        /// `StorageCommitment::size_bytes`.
        expected: u64,
    },
    /// Merkle root over payload does not match `commit.data_root`.
    #[error("payload bytes do not match on-chain data_root")]
    DataRootMismatch,
    /// Chunking / Merkle construction failed.
    #[error(transparent)]
    Spora(#[from] SporaError),
}

/// Rebuild [`BuiltCommitment`] from persisted metadata + payload bytes.
///
/// Verifies `size_bytes`, `data_root`, and `num_chunks` against the payload.
pub fn rebuild_built_commitment(
    meta: &UploadArtifactMeta,
    payload: &[u8],
) -> Result<BuiltCommitment, UploadArtifactRebuildError> {
    let commit = decode_storage_commitment(&meta.commitment_wire)
        .map_err(|e| UploadArtifactRebuildError::CommitmentWire(e.to_string()))?;
    if u64::try_from(payload.len()).unwrap_or(u64::MAX) != commit.size_bytes {
        return Err(UploadArtifactRebuildError::PayloadSize {
            actual: payload.len(),
            expected: commit.size_bytes,
        });
    }
    let chunks = chunk_data(payload, commit.chunk_size as usize)?;
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| &**c).collect();
    let tree = merkle_tree_from_chunks(&chunk_refs)?;
    if tree.root() != commit.data_root {
        return Err(UploadArtifactRebuildError::DataRootMismatch);
    }
    Ok(BuiltCommitment {
        commit,
        tree,
        blinding: meta.blinding,
    })
}

/// Build metadata from a fresh upload before persistence.
#[must_use]
pub fn upload_artifact_meta_from_upload(
    built: &BuiltCommitment,
    source_path: &str,
    tx_id: Option<&str>,
) -> UploadArtifactMeta {
    UploadArtifactMeta {
        commitment_wire: encode_storage_commitment(&built.commit),
        blinding: built.blinding,
        source_path: source_path.to_string(),
        tx_id: tx_id.map(str::to_string),
    }
}

fn decode_err(e: mfn_crypto::CryptoError) -> UploadArtifactMetaError {
    UploadArtifactMetaError::Decode(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_storage::{build_storage_commitment, DEFAULT_ENDOWMENT_PARAMS};

    #[test]
    fn meta_round_trip_empty_source_and_tx() {
        let payload: Vec<u8> = (0u32..512).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(256),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let meta = upload_artifact_meta_from_upload(&built, "", None);
        let bytes = encode_upload_artifact_meta(&meta);
        let decoded = decode_upload_artifact_meta(&bytes).expect("decode");
        assert_eq!(decoded.commitment_wire, meta.commitment_wire);
        assert_eq!(decoded.blinding, meta.blinding);
        assert_eq!(decoded.source_path, "");
        assert!(decoded.tx_id.is_none());
    }

    #[test]
    fn meta_rejects_bad_magic() {
        let mut w = Writer::new();
        w.blob(b"NOTMAGIC!");
        let err = decode_upload_artifact_meta(&w.into_bytes()).unwrap_err();
        assert_eq!(err, UploadArtifactMetaError::BadMagic);
    }

    #[test]
    fn rebuild_built_commitment_matches_original() {
        let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(512),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let meta = upload_artifact_meta_from_upload(&built, "/tmp/doc.bin", Some("abc123"));
        let rebuilt = rebuild_built_commitment(&meta, &payload).expect("rebuild");
        assert_eq!(rebuilt.commit, built.commit);
        assert_eq!(rebuilt.tree.root(), built.tree.root());
        assert_eq!(rebuilt.blinding, built.blinding);
    }
}
