//! Push wallet upload chunks to peers over P2P `ChunkV2` gossip (**B2**).

use std::path::Path;

use mfn_net::{push_chunks_gossip_to_peer, ChainTipV1, PushTxGossipError};
use mfn_storage::{chunk_data, encode_merkle_proof_wire, storage_commitment_hash};

use crate::rpc::{RpcClient, RpcError};
use crate::upload_artifact_store::load_upload_artifact;

/// Chunk index, payload bytes, and Merkle proof wire for **B2** gossip.
type ChunkV2GossipPiece = (u32, Vec<u8>, Vec<u8>);

/// Chunk push errors.
#[derive(Debug, thiserror::Error)]
pub enum ChunkPushError {
    /// Node RPC failure.
    #[error("{0}")]
    Rpc(#[from] RpcError),
    /// Local artifact / chunking failure.
    #[error("{0}")]
    Usage(String),
    /// P2P dial or write failure.
    #[error("{0}")]
    P2p(#[from] PushTxGossipError),
}

/// Outcome of pushing all chunks to one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkPushPeerResult {
    /// Peer `HOST:PORT`.
    pub peer: String,
    /// Chunks sent on the wire.
    pub chunks_sent: u32,
    /// Whether the push completed without error.
    pub ok: bool,
    /// Error message when `ok` is false.
    pub error: Option<String>,
}

/// Push every chunk of a wallet upload artifact to one `mfnd --p2p-listen` peer.
pub fn push_wallet_artifact_chunks_to_peer(
    client: &mut RpcClient,
    wallet_path: &Path,
    commitment_hash_hex: &str,
    peer: &str,
) -> Result<ChunkPushPeerResult, ChunkPushError> {
    let (genesis_id, local_tip) = p2p_handshake_material(client)?;
    push_wallet_artifact_chunks_to_peer_with_handshake(
        wallet_path,
        commitment_hash_hex,
        peer,
        &genesis_id,
        &local_tip,
    )
}

/// Push artifact chunks using caller-supplied P2P handshake material (e.g. from `mfn-cli` RPC).
pub fn push_wallet_artifact_chunks_to_peer_with_handshake(
    wallet_path: &Path,
    commitment_hash_hex: &str,
    peer: &str,
    genesis_id: &[u8; 32],
    local_tip: &ChainTipV1,
) -> Result<ChunkPushPeerResult, ChunkPushError> {
    let chunks = wallet_artifact_chunks_v2(wallet_path, commitment_hash_hex)?;
    let commit_hash = parse_commit_hash_hex(commitment_hash_hex)?;
    match push_chunks_gossip_to_peer(peer, genesis_id, local_tip, &commit_hash, &chunks) {
        Ok(()) => Ok(ChunkPushPeerResult {
            peer: peer.to_string(),
            chunks_sent: u32::try_from(chunks.len()).unwrap_or(u32::MAX),
            ok: true,
            error: None,
        }),
        Err(e) => Ok(ChunkPushPeerResult {
            peer: peer.to_string(),
            chunks_sent: 0,
            ok: false,
            error: Some(e.to_string()),
        }),
    }
}

/// Push artifact chunks to each peer (independent sessions).
pub fn push_wallet_artifact_chunks_to_peers(
    client: &mut RpcClient,
    wallet_path: &Path,
    commitment_hash_hex: &str,
    peers: &[String],
) -> Result<Vec<ChunkPushPeerResult>, ChunkPushError> {
    let (genesis_id, local_tip) = p2p_handshake_material(client)?;
    push_wallet_artifact_chunks_to_peers_with_handshake(
        wallet_path,
        commitment_hash_hex,
        peers,
        &genesis_id,
        &local_tip,
    )
}

/// Push artifact chunks to each peer using explicit handshake material.
pub fn push_wallet_artifact_chunks_to_peers_with_handshake(
    wallet_path: &Path,
    commitment_hash_hex: &str,
    peers: &[String],
    genesis_id: &[u8; 32],
    local_tip: &ChainTipV1,
) -> Result<Vec<ChunkPushPeerResult>, ChunkPushError> {
    let mut out = Vec::with_capacity(peers.len());
    for peer in peers {
        out.push(push_wallet_artifact_chunks_to_peer_with_handshake(
            wallet_path,
            commitment_hash_hex,
            peer,
            genesis_id,
            local_tip,
        )?);
    }
    Ok(out)
}

fn wallet_artifact_chunks_v2(
    wallet_path: &Path,
    commitment_hash_hex: &str,
) -> Result<Vec<ChunkV2GossipPiece>, ChunkPushError> {
    let loaded = load_upload_artifact(wallet_path, commitment_hash_hex)
        .map_err(|e| ChunkPushError::Usage(format!("upload artifact: {e}")))?;
    let on_chain = storage_commitment_hash(&loaded.built.commit);
    let local = parse_commit_hash_hex(commitment_hash_hex)?;
    if on_chain != local {
        return Err(ChunkPushError::Usage(
            "artifact commitment does not match commitment_hash_hex".into(),
        ));
    }
    let slices = chunk_data(&loaded.payload, loaded.built.commit.chunk_size as usize)
        .map_err(|e| ChunkPushError::Usage(format!("chunk_data: {e}")))?;
    if slices.len() != loaded.built.commit.num_chunks as usize {
        return Err(ChunkPushError::Usage(format!(
            "chunk count {} != commitment num_chunks {}",
            slices.len(),
            loaded.built.commit.num_chunks
        )));
    }
    let mut out = Vec::with_capacity(slices.len());
    for (i, bytes) in slices.iter().enumerate() {
        let proof = mfn_crypto::merkle::merkle_proof(&loaded.built.tree, i)
            .map_err(|e| ChunkPushError::Usage(format!("merkle_proof: {e}")))?;
        let proof_wire = encode_merkle_proof_wire(&proof);
        out.push((
            u32::try_from(i).unwrap_or(u32::MAX),
            bytes.to_vec(),
            proof_wire,
        ));
    }
    Ok(out)
}

fn p2p_handshake_material(
    client: &mut RpcClient,
) -> Result<([u8; 32], ChainTipV1), ChunkPushError> {
    let tip = client.get_tip()?;
    let genesis_id = parse_commit_hash_hex(&tip.genesis_id)?;
    let height = u32::try_from(tip.tip_height.unwrap_or(0))
        .map_err(|_| ChunkPushError::Usage("tip_height overflow".into()))?;
    let tip_id = if tip.tip_id == "none" {
        genesis_id
    } else {
        parse_commit_hash_hex(&tip.tip_id)?
    };
    Ok((genesis_id, ChainTipV1 { height, tip_id }))
}

fn parse_commit_hash_hex(s: &str) -> Result<[u8; 32], ChunkPushError> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() != 64 {
        return Err(ChunkPushError::Usage(format!(
            "expected 64 hex chars, got {}",
            t.len()
        )));
    }
    let bytes = hex::decode(t).map_err(|e| ChunkPushError::Usage(format!("hex: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upload_artifact_store::save_upload_artifact;
    use mfn_storage::{build_storage_commitment, DEFAULT_ENDOWMENT_PARAMS};

    #[test]
    fn wallet_artifact_chunks_matches_commitment_layout() {
        let dir = std::env::temp_dir().join(format!("mfn-chunk-push-{}", std::process::id()));
        let wallet = dir.join("w.json");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(&wallet, b"{}").expect("wallet");
        let payload: Vec<u8> = (0u32..5000).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(4096),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let hash = hex::encode(storage_commitment_hash(&built.commit));
        save_upload_artifact(&wallet, &built, &payload, Path::new("x"), None).expect("save");
        let chunks = wallet_artifact_chunks_v2(&wallet, &hash).expect("chunks");
        assert_eq!(chunks.len(), built.commit.num_chunks as usize);
        assert_eq!(chunks[0].1.len(), 4096);
        assert!(
            !chunks[0].2.is_empty(),
            "B2 push includes Merkle proof wire"
        );
    }
}
