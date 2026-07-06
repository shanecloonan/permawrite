//! Persist inbound P2P storage chunks under the node data directory (**M7**).
//!
//! **M7.12 hardening:** gossip peers are untrusted, so `chunk-inbox/`
//! writes are gated on the on-chain storage registry. A chunk is only
//! persisted when its commitment is anchored, its index is in range, and
//! its length matches the commitment's declared geometry — and an
//! existing same-length chunk file is never overwritten, so a malicious
//! peer cannot corrupt bytes an operator already holds.

use mfn_storage::StorageCommitment;

pub use mfn_store::save_chunk_inbox;

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

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_storage::build_storage_commitment;

    fn built_for(payload: &[u8], chunk_size: usize) -> mfn_storage::BuiltCommitment {
        build_storage_commitment(payload, 1_000, Some(chunk_size), 3, None).expect("build")
    }

    #[test]
    fn expected_chunk_len_covers_full_and_tail_chunks() {
        let payload = vec![7u8; 2_500];
        let built = built_for(&payload, 1_024);
        assert_eq!(built.commit.num_chunks, 3);
        assert_eq!(expected_chunk_len(&built.commit, 0), 1_024);
        assert_eq!(expected_chunk_len(&built.commit, 1), 1_024);
        assert_eq!(expected_chunk_len(&built.commit, 2), 452);
        // Out-of-range index clamps to zero rather than under/overflowing.
        assert_eq!(expected_chunk_len(&built.commit, 3), 0);
    }

    #[test]
    fn validate_accepts_true_chunks() {
        let payload: Vec<u8> = (0u32..2_500).map(|i| (i % 251) as u8).collect();
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
        let payload = vec![7u8; 2_500];
        let built = built_for(&payload, 1_024);
        assert_eq!(
            validate_gossip_chunk(&built.commit, 3, &[0u8; 1_024]),
            Err(ChunkGossipReject::IndexOutOfRange {
                got: 3,
                num_chunks: 3
            })
        );
    }

    #[test]
    fn validate_rejects_wrong_length() {
        let payload = vec![7u8; 2_500];
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
        let payload = vec![9u8; 500];
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
}
