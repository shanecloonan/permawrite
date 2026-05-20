//! Storage-operator helpers (**M3.22**): SPoRA challenge preview + proof submit.

use std::path::Path;

use mfn_storage::{
    build_storage_proof, chunk_data, decode_storage_commitment, merkle_tree_from_chunks,
    storage_commitment_hash,
};

use crate::rpc::RpcClient;

/// Operator command errors.
#[derive(Debug, thiserror::Error)]
pub enum OperatorCmdError {
    /// Node RPC error.
    #[error("{0}")]
    Rpc(#[from] crate::rpc::RpcError),
    /// Usage / validation.
    #[error("{0}")]
    Usage(String),
}

/// Preview the next-block SPoRA challenge for a commitment.
pub fn operator_challenge(
    client: &mut RpcClient,
    commitment_hash_hex: &str,
) -> Result<(), OperatorCmdError> {
    let ch = client.get_storage_challenge(commitment_hash_hex)?;
    println!("commitment_hash={}", ch.commitment_hash);
    println!("data_root={}", ch.data_root);
    println!("size_bytes={}", ch.size_bytes);
    println!("replication={}", ch.replication);
    println!("num_chunks={}", ch.num_chunks);
    println!("chunk_size={}", ch.chunk_size);
    println!("next_height={}", ch.next_height);
    println!("next_slot={}", ch.next_slot);
    println!("prev_block_id={}", ch.prev_block_id);
    println!("chunk_index={}", ch.chunk_index);
    Ok(())
}

/// Build a SPoRA proof from local file bytes or a wallet upload artifact, then
/// submit via `submit_storage_proof`.
///
/// When `data_path` is `None`, `wallet_path` must be set and
/// [`crate::upload_artifact_store::load_upload_artifact`] supplies payload + tree.
pub fn operator_prove(
    client: &mut RpcClient,
    commitment_hash_hex: &str,
    data_path: Option<&Path>,
    wallet_path: Option<&Path>,
) -> Result<(), OperatorCmdError> {
    let ch = client.get_storage_challenge(commitment_hash_hex)?;
    let on_chain_hash = parse_hex32(&ch.commitment_hash)?;

    let (data, tree, artifact_source) = match (data_path, wallet_path) {
        (Some(path), _) => {
            let commit = decode_storage_commitment(
                &hex::decode(&ch.commitment_wire_hex)
                    .map_err(|e| OperatorCmdError::Usage(format!("commitment_wire_hex: {e}")))?,
            )
            .map_err(|e| OperatorCmdError::Usage(format!("decode_storage_commitment: {e}")))?;
            let local_hash = storage_commitment_hash(&commit);
            if local_hash != on_chain_hash {
                return Err(OperatorCmdError::Usage(
                    "commitment wire does not match commitment_hash".into(),
                ));
            }
            let data = std::fs::read(path)
                .map_err(|e| OperatorCmdError::Usage(format!("read {}: {e}", path.display())))?;
            if u64::try_from(data.len()).unwrap_or(u64::MAX) != ch.size_bytes {
                return Err(OperatorCmdError::Usage(format!(
                    "file size {} != on-chain size_bytes {}",
                    data.len(),
                    ch.size_bytes
                )));
            }
            let chunks = chunk_data(&data, commit.chunk_size as usize)
                .map_err(|e| OperatorCmdError::Usage(format!("chunk_data: {e}")))?;
            let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| &**c).collect();
            let tree = merkle_tree_from_chunks(&chunk_refs)
                .map_err(|e| OperatorCmdError::Usage(format!("merkle_tree_from_chunks: {e}")))?;
            if tree.root() != commit.data_root {
                return Err(OperatorCmdError::Usage(
                    "file bytes do not match on-chain data_root (wrong payload or chunk_size)"
                        .into(),
                ));
            }
            (data, tree, None)
        }
        (None, Some(wallet)) => {
            let loaded =
                crate::upload_artifact_store::load_upload_artifact(wallet, commitment_hash_hex)
                    .map_err(|e| OperatorCmdError::Usage(format!("upload artifact: {e}")))?;
            let local_hash = storage_commitment_hash(&loaded.built.commit);
            if local_hash != on_chain_hash {
                return Err(OperatorCmdError::Usage(
                    "artifact commitment does not match RPC commitment_hash".into(),
                ));
            }
            if loaded.built.commit.data_root != commit_data_root_from_challenge(&ch)? {
                return Err(OperatorCmdError::Usage(
                    "artifact data_root does not match on-chain commitment".into(),
                ));
            }
            let source = if loaded.source_path.is_empty() {
                None
            } else {
                Some(loaded.source_path)
            };
            (loaded.payload, loaded.built.tree, source)
        }
        (None, None) => {
            return Err(OperatorCmdError::Usage(
                "operator prove requires FILE or --wallet with a persisted upload artifact".into(),
            ));
        }
    };

    let commit = decode_storage_commitment(
        &hex::decode(&ch.commitment_wire_hex)
            .map_err(|e| OperatorCmdError::Usage(format!("commitment_wire_hex: {e}")))?,
    )
    .map_err(|e| OperatorCmdError::Usage(format!("decode_storage_commitment: {e}")))?;
    let prev = parse_hex32(&ch.prev_block_id)?;
    let proof = build_storage_proof(&commit, &prev, ch.next_slot, &data, &tree)
        .map_err(|e| OperatorCmdError::Usage(format!("build_storage_proof: {e}")))?;
    if proof.proof.index as u32 != ch.chunk_index {
        return Err(OperatorCmdError::Usage(format!(
            "built proof chunk index {} != challenge {}",
            proof.proof.index, ch.chunk_index
        )));
    }
    let submit = client.submit_storage_proof(&proof)?;
    println!("commit_hash={}", submit.commit_hash);
    println!("pool_len={}", submit.pool_len);
    println!("outcome={}", submit.outcome_kind);
    println!("next_height={}", submit.next_height);
    if let Some(src) = artifact_source {
        println!("artifact_source_path={src}");
    }
    Ok(())
}

fn commit_data_root_from_challenge(
    ch: &crate::rpc::StorageChallenge,
) -> Result<[u8; 32], OperatorCmdError> {
    let bytes = hex::decode(&ch.data_root)
        .map_err(|e| OperatorCmdError::Usage(format!("data_root hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(OperatorCmdError::Usage(format!(
            "data_root must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// List pending proofs in the node proof pool.
pub fn operator_pool(client: &mut RpcClient) -> Result<(), OperatorCmdError> {
    let pool = client.get_proof_pool()?;
    println!("pool_len={}", pool.pool_len);
    for h in &pool.commit_hashes {
        println!("commit_hash={h}");
    }
    Ok(())
}

fn parse_hex32(s: &str) -> Result<[u8; 32], OperatorCmdError> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() != 64 {
        return Err(OperatorCmdError::Usage(format!(
            "expected 64 hex chars, got {}",
            t.len()
        )));
    }
    let bytes = hex::decode(t).map_err(|e| OperatorCmdError::Usage(format!("hex: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
