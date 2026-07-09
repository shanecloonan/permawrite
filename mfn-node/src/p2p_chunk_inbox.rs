//! Persist inbound P2P storage chunks under the node data directory (**M7**).
//!
//! **M7.12 hardening:** gossip peers are untrusted, so `chunk-inbox/`
//! writes are gated on the on-chain storage registry. A chunk is only
//! persisted when its commitment is anchored, its index is in range, and
//! its length matches the commitment's declared geometry — and an
//! existing same-length chunk file is never overwritten, so a malicious
//! peer cannot corrupt bytes an operator already holds.

use mfn_storage::StorageCommitment;

/// Why an inbound gossip chunk was refused before touching disk (**M7.12**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkGossipReject {
    /// `chunk_index` is not in `0..num_chunks` for the anchored commitment.
    IndexOutOfRange {
        /// Index the peer sent.
        got: u32,
        /// Anchored `num_chunks`.
        num_chunks: u32,
    },
    /// Chunk byte length disagrees with the commitment's geometry.
    LengthMismatch {
        /// Bytes the peer sent.
        got: usize,
        /// Length implied by `size_bytes` / `chunk_size` at this index.
        expected: u64,
    },
    /// Single-chunk commitment whose leaf hash is the `data_root` itself —
    /// full verification is possible and the bytes failed it.
    DataRootMismatch,
    /// Merkle proof index does not match the gossip chunk index (**B2**).
    ProofIndexMismatch {
        /// Index in the proof wire.
        proof_index: u32,
        /// Index in the frame header.
        chunk_index: u32,
    },
    /// Merkle proof does not anchor chunk bytes to `data_root` (**B2**).
    MerkleProofMismatch,
    /// Merkle proof wire could not be decoded (**B2**).
    InvalidProofWire,
}

/// Exact byte length the anchored commitment implies for `chunk_index`.
///
/// Robust to any geometry (clamps against `size_bytes`), so it stays
/// safe even for pre-M5.49 genesis commitments that never went through
/// shape validation.
pub fn expected_chunk_len(commit: &StorageCommitment, chunk_index: u32) -> u64 {
    let cs = u64::from(commit.chunk_size);
    let start = cs
        .saturating_mul(u64::from(chunk_index))
        .min(commit.size_bytes);
    let end = start.saturating_add(cs).min(commit.size_bytes);
    end - start
}

/// Validate inbound gossip chunk bytes against the anchored commitment
/// before any disk write (**M7.12**).
pub fn validate_gossip_chunk(
    commit: &StorageCommitment,
    chunk_index: u32,
    chunk_bytes: &[u8],
) -> Result<(), ChunkGossipReject> {
    if chunk_index >= commit.num_chunks {
        return Err(ChunkGossipReject::IndexOutOfRange {
            got: chunk_index,
            num_chunks: commit.num_chunks,
        });
    }
    let expected = expected_chunk_len(commit, chunk_index);
    if chunk_bytes.len() as u64 != expected {
        return Err(ChunkGossipReject::LengthMismatch {
            got: chunk_bytes.len(),
            expected,
        });
    }
    // A single-chunk tree has root == leaf, so the bytes can be verified
    // outright without a Merkle path (which ChunkV1 frames don't carry).
    if commit.num_chunks == 1 && mfn_storage::chunk_hash(chunk_bytes) != commit.data_root {
        return Err(ChunkGossipReject::DataRootMismatch);
    }
    Ok(())
}

/// Validate inbound [`ChunkV2`] gossip before any disk write (**B2**).
pub fn validate_gossip_chunk_v2(
    commit: &StorageCommitment,
    chunk_index: u32,
    chunk_bytes: &[u8],
    merkle_proof_wire: &[u8],
) -> Result<(), ChunkGossipReject> {
    validate_gossip_chunk(commit, chunk_index, chunk_bytes)?;
    let proof = mfn_storage::decode_merkle_proof_wire(merkle_proof_wire)
        .map_err(|_| ChunkGossipReject::InvalidProofWire)?;
    let proof_index =
        u32::try_from(proof.index).map_err(|_| ChunkGossipReject::InvalidProofWire)?;
    if proof_index != chunk_index {
        return Err(ChunkGossipReject::ProofIndexMismatch {
            proof_index,
            chunk_index,
        });
    }
    let leaf = mfn_storage::chunk_hash(chunk_bytes);
    if !mfn_crypto::merkle::verify_merkle_proof(&leaf, &proof, &commit.data_root) {
        return Err(ChunkGossipReject::MerkleProofMismatch);
    }
    Ok(())
}

/// Default chunk-inbox disk budget when [`MFND_CHUNK_INBOX_MAX_BYTES`] is unset (**B7**).
pub const DEFAULT_CHUNK_INBOX_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Environment variable for chunk-inbox disk quota (**B7**). `0` disables enforcement.
pub const MFND_CHUNK_INBOX_MAX_BYTES_ENV: &str = "MFND_CHUNK_INBOX_MAX_BYTES";

/// Parse [`MFND_CHUNK_INBOX_MAX_BYTES`]; `0` means unlimited.
pub fn chunk_inbox_max_bytes_from_env() -> Result<u64, String> {
    match std::env::var(MFND_CHUNK_INBOX_MAX_BYTES_ENV) {
        Ok(v) => v.trim().parse::<u64>().map_err(|_| {
            format!("{MFND_CHUNK_INBOX_MAX_BYTES_ENV} must be a non-negative integer")
        }),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_CHUNK_INBOX_MAX_BYTES),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "{MFND_CHUNK_INBOX_MAX_BYTES_ENV} must be valid UTF-8"
        )),
    }
}

/// Quota enforcement failure before a gossip chunk write (**B7**).
#[derive(Debug)]
pub enum ChunkInboxQuotaReject {
    /// Inbox is at budget and no incomplete commit set could be evicted.
    QuotaExceeded {
        /// Configured cap in bytes (`0` = unlimited).
        max_bytes: u64,
        /// Bytes currently on disk.
        used_bytes: u64,
        /// Additional bytes required for this write.
        needed_bytes: u64,
    },
    /// Underlying inbox I/O error.
    Store(mfn_store::ChunkInboxError),
}

impl std::fmt::Display for ChunkInboxQuotaReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QuotaExceeded {
                max_bytes,
                used_bytes,
                needed_bytes,
            } => write!(
                f,
                "chunk inbox quota exceeded (max={max_bytes} used={used_bytes} need={needed_bytes})"
            ),
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

/// Look up anchored `num_chunks` for a commit hex dir (lowercase).
fn num_chunks_for_inbox_hex(
    storage: &std::collections::HashMap<[u8; 32], mfn_consensus::block::StorageEntry>,
    commit_hex: &str,
) -> Option<u32> {
    let bytes = hex::decode(commit_hex).ok()?;
    let hash: [u8; 32] = bytes.try_into().ok()?;
    storage.get(&hash).map(|e| e.commit.num_chunks)
}

/// Persist a gossip chunk, evicting **incomplete** inbox sets when over budget (**B7**).
///
/// Complete sets (`chunk_inbox_complete`) are never evicted — they may be pending
/// repair fan-out. Orphan dirs (unknown to `storage`) are treated as incomplete.
pub fn save_chunk_inbox_with_quota(
    data_root: &std::path::Path,
    storage: &std::collections::HashMap<[u8; 32], mfn_consensus::block::StorageEntry>,
    commit_hash: &[u8; 32],
    chunk_index: u32,
    chunk_bytes: &[u8],
    max_bytes: u64,
) -> Result<std::path::PathBuf, ChunkInboxQuotaReject> {
    if max_bytes == 0 {
        return mfn_store::save_chunk_inbox(data_root, commit_hash, chunk_index, chunk_bytes)
            .map_err(ChunkInboxQuotaReject::Store);
    }

    let commit_hex = hex::encode(commit_hash);
    let path = mfn_store::chunk_inbox_path(data_root, &commit_hex, chunk_index);
    let old_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let delta = chunk_bytes.len() as u64;
    let net_add = delta.saturating_sub(old_len);

    let used =
        mfn_store::chunk_inbox_total_bytes(data_root).map_err(ChunkInboxQuotaReject::Store)?;
    if used.saturating_add(net_add) <= max_bytes {
        return mfn_store::save_chunk_inbox(data_root, commit_hash, chunk_index, chunk_bytes)
            .map_err(ChunkInboxQuotaReject::Store);
    }

    let need = used.saturating_add(net_add).saturating_sub(max_bytes);
    let mut freed = 0u64;
    let mut candidates: Vec<(String, u64, Option<std::time::SystemTime>)> = Vec::new();
    for hex in
        mfn_store::list_chunk_inbox_commit_hexes(data_root).map_err(ChunkInboxQuotaReject::Store)?
    {
        if hex == commit_hex {
            continue;
        }
        let complete = match num_chunks_for_inbox_hex(storage, &hex) {
            Some(nc) => mfn_store::chunk_inbox_complete(data_root, &hex, nc)
                .map_err(ChunkInboxQuotaReject::Store)?,
            None => false,
        };
        if complete {
            continue;
        }
        let bytes = mfn_store::chunk_inbox_commit_bytes(data_root, &hex)
            .map_err(ChunkInboxQuotaReject::Store)?;
        if bytes == 0 {
            continue;
        }
        let mtime = mfn_store::chunk_inbox_commit_mtime(data_root, &hex)
            .map_err(ChunkInboxQuotaReject::Store)?;
        candidates.push((hex, bytes, mtime));
    }

    candidates.sort_by(|a, b| {
        let at = a.2.unwrap_or(std::time::UNIX_EPOCH);
        let bt = b.2.unwrap_or(std::time::UNIX_EPOCH);
        at.cmp(&bt).then_with(|| b.1.cmp(&a.1))
    });

    for (hex, bytes, _) in candidates {
        if freed >= need {
            break;
        }
        let evicted = mfn_store::remove_chunk_inbox_commit(data_root, &hex)
            .map_err(ChunkInboxQuotaReject::Store)?;
        freed = freed.saturating_add(evicted);
        println!("mfnd_chunk_inbox_evict commit={hex} bytes={evicted}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let _ = bytes;
    }

    let used_after =
        mfn_store::chunk_inbox_total_bytes(data_root).map_err(ChunkInboxQuotaReject::Store)?;
    if used_after.saturating_add(net_add) > max_bytes {
        return Err(ChunkInboxQuotaReject::QuotaExceeded {
            max_bytes,
            used_bytes: used_after,
            needed_bytes: net_add,
        });
    }

    mfn_store::save_chunk_inbox(data_root, commit_hash, chunk_index, chunk_bytes)
        .map_err(ChunkInboxQuotaReject::Store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_storage::build_storage_commitment;

    fn built_for(payload: &[u8], chunk_size: usize) -> mfn_storage::BuiltCommitment {
        let padded = mfn_storage::pad_to_storage_size_bucket(payload);
        build_storage_commitment(&padded, 1_000, Some(chunk_size), 3, None).expect("build")
    }

    #[test]
    fn expected_chunk_len_covers_full_and_tail_chunks() {
        let payload = mfn_storage::pad_to_storage_size_bucket(&vec![7u8; 2_500]);
        let built = built_for(&payload, 1_024);
        assert_eq!(built.commit.num_chunks, 4);
        assert_eq!(expected_chunk_len(&built.commit, 0), 1_024);
        assert_eq!(expected_chunk_len(&built.commit, 1), 1_024);
        assert_eq!(expected_chunk_len(&built.commit, 2), 1_024);
        assert_eq!(expected_chunk_len(&built.commit, 3), 1_024);
        // Out-of-range index clamps to zero rather than under/overflowing.
        assert_eq!(expected_chunk_len(&built.commit, 4), 0);
    }

    #[test]
    fn validate_accepts_true_chunks() {
        let payload = mfn_storage::pad_to_storage_size_bucket(
            &(0u32..2_500).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
        );
        let built = built_for(&payload, 1_024);
        let chunks = mfn_storage::chunk_data(&payload, 1_024).expect("chunks");
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(
                validate_gossip_chunk(&built.commit, i as u32, c),
                Ok(()),
                "chunk {i}"
            );
        }
    }

    #[test]
    fn validate_rejects_out_of_range_index() {
        let payload = mfn_storage::pad_to_storage_size_bucket(&vec![7u8; 2_500]);
        let built = built_for(&payload, 1_024);
        assert_eq!(
            validate_gossip_chunk(&built.commit, 4, &[0u8; 1_024]),
            Err(ChunkGossipReject::IndexOutOfRange {
                got: 4,
                num_chunks: 4
            })
        );
    }

    #[test]
    fn validate_rejects_wrong_length() {
        let payload = mfn_storage::pad_to_storage_size_bucket(&vec![7u8; 2_500]);
        let built = built_for(&payload, 1_024);
        assert_eq!(
            validate_gossip_chunk(&built.commit, 0, &[0u8; 100]),
            Err(ChunkGossipReject::LengthMismatch {
                got: 100,
                expected: 1_024
            })
        );
    }

    #[test]
    fn validate_fully_verifies_single_chunk_commitments() {
        let payload = mfn_storage::pad_to_storage_size_bucket(&vec![9u8; 500]);
        let built = built_for(&payload, 1_024);
        assert_eq!(built.commit.num_chunks, 1);
        assert_eq!(validate_gossip_chunk(&built.commit, 0, &payload), Ok(()));
        let mut forged = payload.clone();
        forged[0] ^= 0xff;
        assert_eq!(
            validate_gossip_chunk(&built.commit, 0, &forged),
            Err(ChunkGossipReject::DataRootMismatch)
        );
    }

    #[test]
    fn validate_v2_accepts_true_multi_chunk_proofs() {
        let payload = mfn_storage::pad_to_storage_size_bucket(
            &(0u32..2_500).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
        );
        let built = built_for(&payload, 1_024);
        let chunks = mfn_storage::chunk_data(&payload, 1_024).expect("chunks");
        for (i, c) in chunks.iter().enumerate() {
            let proof = mfn_crypto::merkle::merkle_proof(&built.tree, i).expect("proof");
            let wire = mfn_storage::encode_merkle_proof_wire(&proof);
            assert_eq!(
                validate_gossip_chunk_v2(&built.commit, i as u32, c, &wire),
                Ok(()),
                "chunk {i}"
            );
        }
    }

    #[test]
    fn validate_v2_rejects_forged_multi_chunk_bytes() {
        let payload = mfn_storage::pad_to_storage_size_bucket(&vec![7u8; 2_500]);
        let built = built_for(&payload, 1_024);
        let proof = mfn_crypto::merkle::merkle_proof(&built.tree, 0).expect("proof");
        let wire = mfn_storage::encode_merkle_proof_wire(&proof);
        let forged = vec![0xffu8; 1_024];
        assert_eq!(
            validate_gossip_chunk_v2(&built.commit, 0, &forged, &wire),
            Err(ChunkGossipReject::MerkleProofMismatch)
        );
    }

    #[test]
    fn validate_v2_rejects_proof_index_mismatch() {
        let payload = mfn_storage::pad_to_storage_size_bucket(&vec![7u8; 2_500]);
        let built = built_for(&payload, 1_024);
        let chunks = mfn_storage::chunk_data(&payload, 1_024).expect("chunks");
        let proof = mfn_crypto::merkle::merkle_proof(&built.tree, 1).expect("proof");
        let wire = mfn_storage::encode_merkle_proof_wire(&proof);
        assert_eq!(
            validate_gossip_chunk_v2(&built.commit, 0, chunks[0], &wire),
            Err(ChunkGossipReject::ProofIndexMismatch {
                proof_index: 1,
                chunk_index: 0
            })
        );
    }

    #[test]
    fn chunk_inbox_quota_evicts_incomplete_before_save() {
        use mfn_consensus::block::StorageEntry;
        use std::collections::HashMap;

        let dir = std::env::temp_dir().join(format!("mfn-inbox-quota-{}", std::process::id()));
        let hash_a = [0x11u8; 32];
        let hash_b = [0x22u8; 32];
        mfn_store::save_chunk_inbox(&dir, &hash_a, 0, &[1u8; 100]).expect("seed a");
        mfn_store::save_chunk_inbox(&dir, &hash_b, 0, &[2u8; 100]).expect("seed b");

        let payload = mfn_storage::pad_to_storage_size_bucket(&vec![9u8; 500]);
        let built = build_storage_commitment(&payload, 1_000, Some(1_024), 3, None).expect("build");
        let commit_hash = mfn_storage::storage_commitment_hash(&built.commit);
        let mut storage = HashMap::new();
        storage.insert(
            commit_hash,
            StorageEntry {
                commit: built.commit,
                last_proven_height: 0,
                last_proven_slot: 0,
                pending_yield_ppb: 0,
            },
        );

        let path = save_chunk_inbox_with_quota(&dir, &storage, &commit_hash, 0, &[3u8; 80], 150)
            .expect("save with eviction");
        assert!(path.is_file());
        assert!(
            !mfn_store::chunk_inbox_commit_dir(&dir, &hex::encode(hash_a)).exists()
                || !mfn_store::chunk_inbox_commit_dir(&dir, &hex::encode(hash_b)).exists(),
            "an incomplete dir should have been evicted"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn chunk_inbox_quota_never_evicts_complete_set() {
        use mfn_consensus::block::StorageEntry;
        use std::collections::HashMap;

        let dir =
            std::env::temp_dir().join(format!("mfn-inbox-quota-complete-{}", std::process::id()));
        let payload = mfn_storage::pad_to_storage_size_bucket(&vec![9u8; 500]);
        let built = build_storage_commitment(&payload, 1_000, Some(1_024), 3, None).expect("build");
        let commit_hash = mfn_storage::storage_commitment_hash(&built.commit);
        let hex = hex::encode(commit_hash);
        let chunks = mfn_storage::chunk_data(&payload, 1_024).expect("chunks");
        for (i, c) in chunks.iter().enumerate() {
            mfn_store::save_chunk_inbox(&dir, &commit_hash, i as u32, c).expect("save chunk");
        }
        let mut storage = HashMap::new();
        storage.insert(
            commit_hash,
            StorageEntry {
                commit: built.commit.clone(),
                last_proven_height: 0,
                last_proven_slot: 0,
                pending_yield_ppb: 0,
            },
        );
        assert!(
            mfn_store::chunk_inbox_complete(&dir, &hex, built.commit.num_chunks).expect("complete")
        );

        let other = [0x99u8; 32];
        mfn_store::save_chunk_inbox(&dir, &other, 0, &[0u8; 200]).expect("filler");

        let err = save_chunk_inbox_with_quota(&dir, &storage, &other, 1, &[0u8; 200], 250)
            .expect_err("complete set must not be evicted");
        assert!(matches!(err, ChunkInboxQuotaReject::QuotaExceeded { .. }));
        assert!(
            mfn_store::chunk_inbox_complete(&dir, &hex, built.commit.num_chunks)
                .expect("still complete")
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
