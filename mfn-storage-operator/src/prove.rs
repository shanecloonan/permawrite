//! SPoRA proof construction + `submit_storage_proof` (**M3.22** / **M6**).

use std::path::Path;

use mfn_crypto::merkle::MerkleTree;
use mfn_storage::{
    build_storage_proof, chunk_data, decode_storage_commitment, merkle_tree_from_chunks,
    storage_commitment_hash,
};

use crate::rpc::{RpcClient, RpcError, StorageChallenge, SubmitStorageProofResult};
use crate::upload_artifact_store::{load_upload_artifact, LoadedUploadArtifact};

/// Operator prove errors.
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    /// Node RPC failure.
    #[error("{0}")]
    Rpc(#[from] RpcError),
    /// Local validation / artifact failure.
    #[error("{0}")]
    Usage(String),
}

/// Successful proof submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProveSuccess {
    /// Node admission summary.
    pub submit: SubmitStorageProofResult,
    /// Original upload path when from wallet artifact.
    pub artifact_source_path: Option<String>,
}

/// Build and submit a proof using bytes from a local file.
pub fn prove_from_file(
    client: &mut RpcClient,
    commitment_hash_hex: &str,
    data_path: &Path,
) -> Result<ProveSuccess, ProveError> {
    let ch = client.get_storage_challenge(commitment_hash_hex)?;
    let on_chain_hash = parse_hex32(&ch.commitment_hash)?;
    let commit = decode_storage_commitment(
        &hex::decode(&ch.commitment_wire_hex)
            .map_err(|e| ProveError::Usage(format!("commitment_wire_hex: {e}")))?,
    )
    .map_err(|e| ProveError::Usage(format!("decode_storage_commitment: {e}")))?;
    let local_hash = storage_commitment_hash(&commit);
    if local_hash != on_chain_hash {
        return Err(ProveError::Usage(
            "commitment wire does not match commitment_hash".into(),
        ));
    }
    let data = std::fs::read(data_path)
        .map_err(|e| ProveError::Usage(format!("read {}: {e}", data_path.display())))?;
    if u64::try_from(data.len()).unwrap_or(u64::MAX) != ch.size_bytes {
        return Err(ProveError::Usage(format!(
            "file size {} != on-chain size_bytes {}",
            data.len(),
            ch.size_bytes
        )));
    }
    let tree = merkle_tree_from_file_bytes(&commit, &data)?;
    if tree.root() != commit.data_root {
        return Err(ProveError::Usage(
            "file bytes do not match on-chain data_root".into(),
        ));
    }
    prove_with_parts(client, &ch, &commit, &data, &tree, None)
}

/// Build and submit a proof from a persisted wallet upload artifact (**M3.24**).
pub fn prove_from_wallet_artifact(
    client: &mut RpcClient,
    wallet_path: &Path,
    commitment_hash_hex: &str,
) -> Result<ProveSuccess, ProveError> {
    let ch = client.get_storage_challenge(commitment_hash_hex)?;
    let on_chain_hash = parse_hex32(&ch.commitment_hash)?;
    let loaded = load_upload_artifact(wallet_path, commitment_hash_hex)
        .map_err(|e| ProveError::Usage(format!("upload artifact: {e}")))?;
    validate_loaded_artifact(&loaded, &ch, on_chain_hash)?;
    let source = if loaded.source_path.is_empty() {
        None
    } else {
        Some(loaded.source_path)
    };
    prove_with_parts(
        client,
        &ch,
        &loaded.built.commit,
        &loaded.payload,
        &loaded.built.tree,
        source,
    )
}

fn validate_loaded_artifact(
    loaded: &LoadedUploadArtifact,
    ch: &StorageChallenge,
    on_chain_hash: [u8; 32],
) -> Result<(), ProveError> {
    let local_hash = storage_commitment_hash(&loaded.built.commit);
    if local_hash != on_chain_hash {
        return Err(ProveError::Usage(
            "artifact commitment does not match RPC commitment_hash".into(),
        ));
    }
    if loaded.built.commit.data_root != commit_data_root_from_challenge(ch)? {
        return Err(ProveError::Usage(
            "artifact data_root does not match on-chain commitment".into(),
        ));
    }
    Ok(())
}

fn prove_with_parts(
    client: &mut RpcClient,
    ch: &StorageChallenge,
    commit: &mfn_storage::StorageCommitment,
    data: &[u8],
    tree: &MerkleTree,
    artifact_source_path: Option<String>,
) -> Result<ProveSuccess, ProveError> {
    let prev = parse_hex32(&ch.prev_block_id)?;
    let proof = build_storage_proof(commit, &prev, ch.next_slot, data, tree)
        .map_err(|e| ProveError::Usage(format!("build_storage_proof: {e}")))?;
    if proof.proof.index as u32 != ch.chunk_index {
        return Err(ProveError::Usage(format!(
            "built proof chunk index {} != challenge {}",
            proof.proof.index, ch.chunk_index
        )));
    }
    let submit = client.submit_storage_proof(&proof)?;
    Ok(ProveSuccess {
        submit,
        artifact_source_path,
    })
}

fn merkle_tree_from_file_bytes(
    commit: &mfn_storage::StorageCommitment,
    data: &[u8],
) -> Result<MerkleTree, ProveError> {
    let chunks = chunk_data(data, commit.chunk_size as usize)
        .map_err(|e| ProveError::Usage(format!("chunk_data: {e}")))?;
    let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| &**c).collect();
    merkle_tree_from_chunks(&chunk_refs)
        .map_err(|e| ProveError::Usage(format!("merkle_tree_from_chunks: {e}")))
}

fn commit_data_root_from_challenge(ch: &StorageChallenge) -> Result<[u8; 32], ProveError> {
    let bytes =
        hex::decode(&ch.data_root).map_err(|e| ProveError::Usage(format!("data_root hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(ProveError::Usage(format!(
            "data_root must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex32(s: &str) -> Result<[u8; 32], ProveError> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() != 64 {
        return Err(ProveError::Usage(format!(
            "expected 64 hex chars, got {}",
            t.len()
        )));
    }
    let bytes = hex::decode(t).map_err(|e| ProveError::Usage(format!("hex: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
