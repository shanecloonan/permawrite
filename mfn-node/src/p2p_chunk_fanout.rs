//! Helpers to fan out storage chunks from `chunk-inbox/` when new uploads land on-chain (**M7.5**).

use std::collections::HashSet;
use std::path::Path;

use mfn_consensus::{storage_commitment_hash, Block};
use mfn_storage::StorageCommitment;
use mfn_store::{chunk_inbox_complete, read_chunk_inbox};

/// Storage commitments newly anchored by `block` (not present in `known_before`).
pub fn new_storage_commits_in_block(
    block: &Block,
    known_before: &HashSet<[u8; 32]>,
) -> Vec<([u8; 32], StorageCommitment)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for tx in &block.txs {
        for output in &tx.outputs {
            let Some(sc) = &output.storage else {
                continue;
            };
            let hash = storage_commitment_hash(sc);
            if known_before.contains(&hash) || !seen.insert(hash) {
                continue;
            }
            out.push((hash, sc.clone()));
        }
    }
    out
}

pub(crate) fn load_complete_inbox_chunks(
    data_root: &Path,
    commit_hash: &[u8; 32],
    commit: &StorageCommitment,
) -> Option<Vec<(u32, Vec<u8>)>> {
    let commit_hex = hex::encode(commit_hash);
    if !chunk_inbox_complete(data_root, &commit_hex, commit.num_chunks).ok()? {
        return None;
    }
    let mut chunks = Vec::with_capacity(commit.num_chunks as usize);
    for idx in 0..commit.num_chunks {
        let bytes = read_chunk_inbox(data_root, &commit_hex, idx).ok()?;
        chunks.push((idx, bytes));
    }
    // (M7.12) Verify against the anchored data_root before fanning out:
    // a node must never replicate bytes it cannot prove are the payload,
    // or corrupted inboxes would spread through the mesh as if permanent.
    let refs: Vec<&[u8]> = chunks.iter().map(|(_, b)| b.as_slice()).collect();
    let tree = match mfn_storage::merkle_tree_from_chunks(&refs) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("mfnd_p2p_chunk_fanout_skip commit={commit_hex} merkle_err={e}");
            return None;
        }
    };
    if tree.root() != commit.data_root {
        eprintln!("mfnd_p2p_chunk_fanout_skip commit={commit_hex} data_root_mismatch=1");
        return None;
    }
    Some(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_storage::{build_storage_commitment, DEFAULT_ENDOWMENT_PARAMS};
    use mfn_store::{save_chunk_inbox, CHUNK_INBOX_DIR};

    #[test]
    fn load_complete_inbox_chunks_round_trip() {
        let dir = std::env::temp_dir().join(format!("mfn-chunk-fanout-{}", std::process::id()));
        let payload: Vec<u8> = (0u32..512).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            None,
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let hash = storage_commitment_hash(&built.commit);
        let slices =
            mfn_storage::chunk_data(&payload, built.commit.chunk_size as usize).expect("chunks");
        for (i, bytes) in slices.iter().enumerate() {
            save_chunk_inbox(&dir, &hash, u32::try_from(i).unwrap(), bytes).expect("save");
        }
        let loaded = load_complete_inbox_chunks(&dir, &hash, &built.commit).expect("load");
        assert_eq!(loaded.len(), built.commit.num_chunks as usize);
        let mut rebuilt = Vec::new();
        for (_, bytes) in loaded {
            rebuilt.extend_from_slice(&bytes);
        }
        assert_eq!(rebuilt, payload);
        assert!(dir.join(CHUNK_INBOX_DIR).is_dir());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_complete_inbox_chunks_refuses_corrupted_inbox() {
        // (M7.12) A complete-but-corrupted inbox must never fan out: the
        // Merkle root over the loaded chunks has to match the anchored
        // data_root byte-for-byte.
        let dir = std::env::temp_dir().join(format!(
            "mfn-chunk-fanout-corrupt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let payload: Vec<u8> = (0u32..512).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            None,
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let hash = storage_commitment_hash(&built.commit);
        let mut corrupted = payload.clone();
        corrupted[0] ^= 0xff;
        let slices =
            mfn_storage::chunk_data(&corrupted, built.commit.chunk_size as usize).expect("chunks");
        for (i, bytes) in slices.iter().enumerate() {
            save_chunk_inbox(&dir, &hash, u32::try_from(i).unwrap(), bytes).expect("save");
        }
        assert!(
            load_complete_inbox_chunks(&dir, &hash, &built.commit).is_none(),
            "corrupted inbox must not be eligible for fan-out"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
