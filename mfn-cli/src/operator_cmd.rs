//! Storage-operator helpers (**M3.22**): SPoRA challenge preview + proof submit.

use std::path::Path;

use mfn_net::ChainTipV1;
use mfn_storage::{
    build_storage_proof, chunk_data, decode_storage_commitment, merkle_tree_from_chunks,
    storage_commitment_hash,
};
use mfn_storage_operator::{
    backfill_upload_artifact_from_challenge, backfill_upload_artifact_from_inbox, fetch_chunk_http,
    inbox_chunk_status, push_wallet_artifact_chunks_to_peers_with_handshake,
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
            let loaded = mfn_storage_operator::load_upload_artifact(wallet, commitment_hash_hex)
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

/// Fetch all chunks from a peer and persist a wallet upload artifact (**M6.6**).
pub fn operator_backfill(
    client: &mut RpcClient,
    wallet_path: &Path,
    commitment_hash_hex: &str,
    peer: &str,
    force: bool,
) -> Result<(), OperatorCmdError> {
    let ch = client.get_storage_challenge(commitment_hash_hex)?;
    let op_ch = storage_challenge_for_operator(&ch);
    let result = backfill_upload_artifact_from_challenge(
        wallet_path,
        commitment_hash_hex,
        peer,
        &op_ch,
        force,
    )
    .map_err(|e| OperatorCmdError::Usage(e.to_string()))?;
    println!("commitment_hash={}", result.commitment_hash_hex);
    println!("peer={peer}");
    println!("chunks_fetched={}", result.chunks_fetched);
    println!("payload_bytes={}", result.payload_bytes);
    println!("artifact_dir={}", result.artifact_dir.display());
    println!("backfill=ok");
    Ok(())
}

/// Push all wallet artifact chunks to one or more P2P peers (**M7.1**).
pub fn operator_push_chunks(
    client: &mut RpcClient,
    wallet_path: &Path,
    commitment_hash_hex: &str,
    peers: &[String],
) -> Result<(), OperatorCmdError> {
    if peers.is_empty() {
        return Err(OperatorCmdError::Usage(
            "operator push-chunks requires at least one PEER (HOST:PORT)".into(),
        ));
    }
    let tip = client.get_tip()?;
    let genesis_id = parse_hex32(&tip.genesis_id)?;
    let height = u32::try_from(tip.tip_height.unwrap_or(0))
        .map_err(|_| OperatorCmdError::Usage("tip_height overflow".into()))?;
    let tip_id = if tip.tip_id == "none" {
        genesis_id
    } else {
        parse_hex32(&tip.tip_id)?
    };
    let local_tip = ChainTipV1 { height, tip_id };
    let results = push_wallet_artifact_chunks_to_peers_with_handshake(
        wallet_path,
        commitment_hash_hex,
        peers,
        &genesis_id,
        &local_tip,
    )
    .map_err(|e| OperatorCmdError::Usage(e.to_string()))?;
    println!("commitment_hash={commitment_hash_hex}");
    for r in &results {
        println!("peer={} ok={} chunks_sent={}", r.peer, r.ok, r.chunks_sent);
        if let Some(err) = &r.error {
            println!("peer_error={err}");
        }
    }
    let ok_count = results.iter().filter(|r| r.ok).count();
    if ok_count != results.len() {
        return Err(OperatorCmdError::Usage(format!(
            "push-chunks failed for {} of {} peers",
            results.len() - ok_count,
            results.len()
        )));
    }
    println!("push_chunks=ok");
    Ok(())
}

/// Report which chunk indices exist under a node's `chunk-inbox/` (**M7.2**).
pub fn operator_inbox_status(
    client: &mut RpcClient,
    data_dir: &Path,
    commitment_hash_hex: &str,
) -> Result<(), OperatorCmdError> {
    let ch = client.get_storage_challenge(commitment_hash_hex)?;
    let status = inbox_chunk_status(data_dir, commitment_hash_hex, ch.num_chunks)
        .map_err(|e| OperatorCmdError::Usage(e.to_string()))?;
    println!("commitment_hash={}", status.commitment_hash_hex);
    println!("data_dir={}", status.data_dir.display());
    println!("num_chunks={}", status.num_chunks);
    println!("chunks_present={}", status.present_indices.len());
    println!("chunks_missing={}", status.missing_indices.len());
    println!("inbox_complete={}", status.complete);
    if !status.present_indices.is_empty() {
        let present: Vec<String> = status
            .present_indices
            .iter()
            .map(|i| i.to_string())
            .collect();
        println!("present_indices={}", present.join(","));
    }
    if !status.missing_indices.is_empty() {
        let missing: Vec<String> = status
            .missing_indices
            .iter()
            .map(|i| i.to_string())
            .collect();
        println!("missing_indices={}", missing.join(","));
    }
    Ok(())
}

/// Assemble `chunk-inbox/` bytes into a wallet upload artifact (**M7.2**).
pub fn operator_assemble_inbox(
    client: &mut RpcClient,
    wallet_path: &Path,
    data_dir: &Path,
    commitment_hash_hex: &str,
    force: bool,
) -> Result<(), OperatorCmdError> {
    let ch = client.get_storage_challenge(commitment_hash_hex)?;
    let op_ch = storage_challenge_for_operator(&ch);
    let result = backfill_upload_artifact_from_inbox(
        wallet_path,
        data_dir,
        commitment_hash_hex,
        &op_ch,
        force,
    )
    .map_err(|e| OperatorCmdError::Usage(e.to_string()))?;
    println!("commitment_hash={}", result.commitment_hash_hex);
    println!("data_dir={}", data_dir.display());
    println!("chunks_assembled={}", result.chunks_fetched);
    println!("payload_bytes={}", result.payload_bytes);
    println!("artifact_dir={}", result.artifact_dir.display());
    println!("assemble_inbox=ok");
    Ok(())
}

/// List wallet-local upload artifacts (same as `uploads local`) (**M3.25**).
pub fn operator_artifacts(wallet_path: &std::path::Path) -> Result<(), OperatorCmdError> {
    crate::uploads_cmd::uploads_local(wallet_path).map_err(OperatorCmdError::Usage)
}

/// Fetch a chunk from a peer HTTP chunk server and optionally verify against a
/// wallet upload artifact (**M6.5**).
pub fn operator_fetch_chunk(
    peer: &str,
    commitment_hash_hex: &str,
    chunk_index: u32,
    wallet_path: Option<&Path>,
) -> Result<(), OperatorCmdError> {
    let body = fetch_chunk_http(peer, commitment_hash_hex, chunk_index)
        .map_err(|e| OperatorCmdError::Usage(e.to_string()))?;
    println!("peer={peer}");
    println!("commitment_hash={commitment_hash_hex}");
    println!("chunk_index={chunk_index}");
    println!("chunk_len={}", body.len());

    if let Some(wallet) = wallet_path {
        let loaded = mfn_storage_operator::load_upload_artifact(wallet, commitment_hash_hex)
            .map_err(|e| OperatorCmdError::Usage(format!("upload artifact: {e}")))?;
        let chunks = chunk_data(&loaded.payload, loaded.built.commit.chunk_size as usize)
            .map_err(|e| OperatorCmdError::Usage(format!("chunk_data: {e}")))?;
        let idx = usize::try_from(chunk_index)
            .map_err(|_| OperatorCmdError::Usage("chunk_index overflow".into()))?;
        let expected = chunks.get(idx).ok_or_else(|| {
            OperatorCmdError::Usage(format!(
                "chunk_index {chunk_index} >= num_chunks {}",
                chunks.len()
            ))
        })?;
        if expected[..] != body[..] {
            return Err(OperatorCmdError::Usage(
                "peer chunk bytes do not match wallet upload artifact".into(),
            ));
        }
        println!("verify=artifact_match");
    }
    Ok(())
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

fn storage_challenge_for_operator(
    ch: &crate::rpc::StorageChallenge,
) -> mfn_storage_operator::rpc::StorageChallenge {
    mfn_storage_operator::rpc::StorageChallenge {
        commitment_hash: ch.commitment_hash.clone(),
        commitment_wire_hex: ch.commitment_wire_hex.clone(),
        data_root: ch.data_root.clone(),
        size_bytes: ch.size_bytes,
        replication: ch.replication,
        num_chunks: ch.num_chunks,
        chunk_size: ch.chunk_size,
        next_height: ch.next_height,
        next_slot: ch.next_slot,
        prev_block_id: ch.prev_block_id.clone(),
        chunk_index: ch.chunk_index,
    }
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
