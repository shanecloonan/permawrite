//! SPoRA — Succinct Proofs of Random Access.
//!
//! Port of the chunking + Merkle-tree + storage-proof subset of
//! `cloonan-group/lib/network/storage.ts`. Lets the chain audit storage
//! operators with `O(log N)`-sized Merkle proofs of random chunk access.
//!
//! ## Workflow
//!
//! 1. Uploader calls [`build_storage_commitment`] to chunk raw bytes,
//!    build a leaf-domain-separated Merkle tree, and produce a
//!    [`crate::commitment::StorageCommitment`]. The commitment lands
//!    on-chain inside a tx output.
//! 2. Each block deterministically derives one chunk index per active
//!    commitment via [`chunk_index_for_challenge`]. Operators MAY answer
//!    by including a [`StorageProof`] in the block they propose.
//! 3. Verifiers call [`verify_storage_proof`]. Successful proofs update
//!    the commitment's last-proven slot and accrue per-proof yield
//!    against the locked endowment.
//!
//! ## Leaf domain separation
//!
//! Leaves use `dhash(MERKLE_LEAF, chunk)` so a chunk can never be confused
//! with an interior Merkle node (whose hashing uses `MERKLE_NODE`). This
//! is the same scheme Bitcoin and Zcash use.

use sha2::{Digest as ShaDigest, Sha512};

use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::domain::{CHUNK_HASH, MERKLE_LEAF, STORAGE_PROOF_LEAF};
use mfn_crypto::hash::dhash;
use mfn_crypto::merkle::{
    merkle_proof, merkle_root_or_zero, merkle_tree_from_leaves, verify_merkle_proof, MerkleError,
    MerkleProof, MerkleTree,
};

use crate::commitment::{storage_commitment_hash, StorageCommitment};

/* ----------------------------------------------------------------------- *
 *  Chunking                                                                *
 * ----------------------------------------------------------------------- */

/// Canonical chunk size (256 KiB). Matches the TS reference's
/// `DEFAULT_CHUNK_SIZE`.
pub const DEFAULT_CHUNK_SIZE: usize = 1 << 18;

/// Split `data` into fixed-size chunks of `chunk_size` bytes each. The
/// final chunk may be short.
///
/// `data.is_empty()` returns a single empty chunk so the Merkle tree has at
/// least one leaf and the storage commitment is well-defined.
///
/// # Errors
///
/// [`SporaError::InvalidChunkSize`] when `chunk_size == 0` or is not a
/// power of two.
pub fn chunk_data(data: &[u8], chunk_size: usize) -> Result<Vec<&[u8]>, SporaError> {
    if chunk_size == 0 || !chunk_size.is_power_of_two() {
        return Err(SporaError::InvalidChunkSize(chunk_size));
    }
    if data.is_empty() {
        return Ok(vec![data]);
    }
    let mut out = Vec::with_capacity(data.len().div_ceil(chunk_size));
    let mut i = 0;
    while i < data.len() {
        let end = (i + chunk_size).min(data.len());
        out.push(&data[i..end]);
        i += chunk_size;
    }
    Ok(out)
}

/// Hash a single chunk for use as a Merkle leaf.
///
/// `dhash(MERKLE_LEAF, chunk)` — domain-separated so a chunk's bytes can
/// never collide with an interior node hash.
pub fn chunk_hash(chunk: &[u8]) -> [u8; 32] {
    dhash(MERKLE_LEAF, &[chunk])
}

/// Build the chunk-Merkle tree for `chunks`.
pub fn merkle_tree_from_chunks(chunks: &[&[u8]]) -> Result<MerkleTree, SporaError> {
    if chunks.is_empty() {
        return Err(SporaError::EmptyInput);
    }
    let leaves: Vec<[u8; 32]> = chunks.iter().map(|c| chunk_hash(c)).collect();
    merkle_tree_from_leaves(&leaves).map_err(SporaError::Merkle)
}

/* ----------------------------------------------------------------------- *
 *  Commitment construction                                                 *
 * ----------------------------------------------------------------------- */

/// Output of [`build_storage_commitment`].
#[derive(Clone, Debug)]
pub struct BuiltCommitment {
    /// The on-chain commitment.
    pub commit: StorageCommitment,
    /// The Merkle tree the prover keeps locally to answer audits.
    pub tree: MerkleTree,
    /// The Pedersen blinding used for `commit.endowment` (the prover's
    /// secret — needed if anyone ever opens the endowment).
    pub blinding: curve25519_dalek::scalar::Scalar,
}

/// Build a storage commitment from raw bytes + the locked endowment.
///
/// Returns the commitment, the Merkle tree (the prover keeps this around
/// to answer SPoRA audits), and the Pedersen blinding for the endowment.
///
/// # Arguments
///
/// - `data` — the payload to anchor permanently.
/// - `endowment_amount` — base-unit endowment locked into the storage
///   treasury (the actual value computed via
///   [`crate::endowment::required_endowment`]).
/// - `chunk_size` — chunking granularity; power of two; defaults to
///   [`DEFAULT_CHUNK_SIZE`] when `None`.
/// - `replication` — minimum independent replicas the network must keep;
///   must satisfy `replication >= 1`. The chain enforces additional
///   bounds via [`crate::endowment::EndowmentParams`].
/// - `blinding` — optional explicit Pedersen blinding (defaults to a
///   freshly random scalar).
///
/// # Errors
///
/// [`SporaError::InvalidChunkSize`] / [`SporaError::Merkle`] /
/// [`SporaError::InvalidReplication`].
pub fn build_storage_commitment(
    data: &[u8],
    endowment_amount: u64,
    chunk_size: Option<usize>,
    replication: u8,
    blinding: Option<curve25519_dalek::scalar::Scalar>,
) -> Result<BuiltCommitment, SporaError> {
    if replication == 0 {
        return Err(SporaError::InvalidReplication);
    }
    let cs = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    let chunks = chunk_data(data, cs)?;
    let tree = merkle_tree_from_chunks(&chunks)?;
    let ped = mfn_crypto::pedersen::pedersen_commit(
        curve25519_dalek::scalar::Scalar::from(endowment_amount),
        blinding,
    );
    let commit = StorageCommitment {
        data_root: tree.root(),
        size_bytes: data.len() as u64,
        chunk_size: u32::try_from(cs).map_err(|_| SporaError::InvalidChunkSize(cs))?,
        num_chunks: u32::try_from(chunks.len()).map_err(|_| SporaError::TooManyChunks)?,
        replication,
        endowment: ped.c,
    };
    Ok(BuiltCommitment {
        commit,
        tree,
        blinding: ped.blinding,
    })
}

/// Verifier-side: confirm an opened endowment amount matches the Pedersen
/// commitment in a storage commitment.
pub fn verify_endowment_opening(
    c: &StorageCommitment,
    amount: u64,
    blinding: &curve25519_dalek::scalar::Scalar,
) -> bool {
    let recomputed = mfn_crypto::pedersen::PedersenCommitment {
        c: c.endowment,
        value: curve25519_dalek::scalar::Scalar::from(amount),
        blinding: *blinding,
    };
    mfn_crypto::pedersen::pedersen_verify(&recomputed)
}

/* ----------------------------------------------------------------------- *
 *  Per-block challenge                                                     *
 * ----------------------------------------------------------------------- */

/// Compute the deterministic chunk index a storage commitment is
/// challenged to open at `(prev_block_id, slot)`.
///
/// `dhash(CHUNK_HASH, prev_block_id || u32(slot) || commit_hash)` → first
/// 8 bytes as a big-endian `u64` → mod `num_chunks`.
///
/// Returns `0` if `num_chunks == 0` (degenerate, shouldn't happen in
/// practice).
pub fn chunk_index_for_challenge(
    prev_block_id: &[u8; 32],
    slot: u32,
    commit_hash: &[u8; 32],
    num_chunks: u32,
) -> u32 {
    if num_chunks == 0 {
        return 0;
    }
    let mut w = Writer::new();
    w.push(prev_block_id);
    w.u32(slot);
    w.push(commit_hash);
    let h = dhash(CHUNK_HASH, &[w.bytes()]);
    let r = u64::from_be_bytes(h[..8].try_into().expect("32-byte digest"));
    (r % u64::from(num_chunks)) as u32
}

/// Same as [`chunk_index_for_challenge`] but accepts a SHA-512 digest
/// over `commit_hash || seed` for arbitrary-seed callers (matches the
/// TS reference's `challengeFromSeed`).
pub fn challenge_index_from_seed(commit: &StorageCommitment, seed: &[u8]) -> u32 {
    if commit.num_chunks == 0 {
        return 0;
    }
    let mut hasher = Sha512::new();
    ShaDigest::update(&mut hasher, storage_commitment_hash(commit));
    ShaDigest::update(&mut hasher, seed);
    let digest = ShaDigest::finalize(hasher);
    let r = u64::from_be_bytes(digest[..8].try_into().expect("64-byte digest"));
    (r % u64::from(commit.num_chunks)) as u32
}

/* ----------------------------------------------------------------------- *
 *  StorageProof                                                            *
 * ----------------------------------------------------------------------- */

/// Wire-format storage proof. Included in `Block.storage_proofs`.
///
/// The block's `(prev_block_id, slot)` plus the on-chain commitment
/// determine the expected chunk index uniquely, so we don't store it in
/// the proof itself — the verifier re-derives it.
#[derive(Clone, Debug)]
pub struct StorageProof {
    /// Hash of the storage commitment being proven.
    pub commit_hash: [u8; 32],
    /// The actual chunk bytes the prover holds at the challenged index.
    pub chunk: Vec<u8>,
    /// Merkle inclusion proof anchoring `chunk_hash(chunk)` to
    /// `commit.data_root`.
    pub proof: MerkleProof,
}

/// Encode a [`StorageProof`] to bytes (consensus-critical).
pub fn encode_storage_proof(p: &StorageProof) -> Vec<u8> {
    let mut w = Writer::new();
    w.push(&p.commit_hash);
    w.blob(&p.chunk);
    w.varint(p.proof.index as u64);
    w.varint(p.proof.siblings.len() as u64);
    for (sib, right) in p.proof.siblings.iter().zip(p.proof.right_side.iter()) {
        w.push(sib);
        w.u8(if *right { 1 } else { 0 });
    }
    w.into_bytes()
}

/// Decode bytes produced by [`encode_storage_proof`].
pub fn decode_storage_proof(bytes: &[u8]) -> Result<StorageProof, SporaError> {
    let mut r = Reader::new(bytes);
    let mut commit_hash = [0u8; 32];
    commit_hash.copy_from_slice(r.bytes(32).map_err(SporaError::Codec)?);
    let chunk = r.blob().map_err(SporaError::Codec)?.to_vec();
    let index = r.varint().map_err(SporaError::Codec)?;
    let n = r.varint().map_err(SporaError::Codec)?;
    let n_usize: usize = usize::try_from(n).map_err(|_| SporaError::TooManyChunks)?;
    let mut siblings: Vec<[u8; 32]> = Vec::with_capacity(n_usize);
    let mut right_side: Vec<bool> = Vec::with_capacity(n_usize);
    for _ in 0..n_usize {
        let mut s = [0u8; 32];
        s.copy_from_slice(r.bytes(32).map_err(SporaError::Codec)?);
        siblings.push(s);
        right_side.push(r.u8().map_err(SporaError::Codec)? != 0);
    }
    Ok(StorageProof {
        commit_hash,
        chunk,
        proof: MerkleProof {
            siblings,
            right_side,
            index: usize::try_from(index).map_err(|_| SporaError::TooManyChunks)?,
        },
    })
}

/* ----------------------------------------------------------------------- *
 *  Merkle commitment (M2.0.2)                                              *
 * ----------------------------------------------------------------------- */

/// 32-byte Merkle leaf hash for a single [`StorageProof`].
///
/// Hashes the canonical wire bytes from [`encode_storage_proof`] under
/// the [`STORAGE_PROOF_LEAF`] domain. The wire form is itself
/// deterministic, so this is a pure function of the proof's contents.
#[must_use]
pub fn storage_proof_leaf_hash(p: &StorageProof) -> [u8; 32] {
    dhash(STORAGE_PROOF_LEAF, &[&encode_storage_proof(p)])
}

/// Merkle root over the block's storage proofs in the producer's
/// emit order. Returns the 32-byte zero sentinel for an empty list
/// (matches every other consensus root).
///
/// **Why not sort by `commit_hash`?** The chain already rejects
/// duplicate proofs for the same commitment in a single block, so
/// the only ordering choice left is across distinct commitments —
/// and the producer's emit order is what gets paid out (the first
/// proof that lands accrues that slot's yield). Keeping that order
/// in the commitment avoids forcing the applier to re-sort.
#[must_use]
pub fn storage_proof_merkle_root(proofs: &[StorageProof]) -> [u8; 32] {
    if proofs.is_empty() {
        return [0u8; 32];
    }
    let leaves: Vec<[u8; 32]> = proofs.iter().map(storage_proof_leaf_hash).collect();
    merkle_root_or_zero(&leaves)
}

/// Result of [`verify_storage_proof`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageProofCheck {
    /// All checks passed.
    Valid,
    /// Proof's `commit_hash` didn't match the recomputed commitment hash.
    CommitHashMismatch,
    /// Proof targeted a different chunk than the per-block challenge.
    WrongChunkIndex {
        /// What the challenge demanded.
        expected: u32,
        /// What the proof referenced.
        got: u32,
    },
    /// Merkle path didn't open under `data_root`.
    MerkleInvalid,
}

impl StorageProofCheck {
    /// Convenience boolean.
    #[inline]
    pub fn is_valid(&self) -> bool {
        matches!(self, StorageProofCheck::Valid)
    }
}

/// Verify a storage proof against the on-chain commitment and the block
/// context that issued the challenge.
///
/// Returns [`StorageProofCheck::Valid`] iff:
///
/// 1. `proof.commit_hash == storage_commitment_hash(commit)`,
/// 2. `proof.proof.index == chunk_index_for_challenge(prev_block_id, slot, commit_hash, num_chunks)`,
/// 3. the Merkle proof opens `chunk_hash(proof.chunk)` under `commit.data_root`.
pub fn verify_storage_proof(
    commit: &StorageCommitment,
    prev_block_id: &[u8; 32],
    slot: u32,
    proof: &StorageProof,
) -> StorageProofCheck {
    let c_hash = storage_commitment_hash(commit);
    if c_hash != proof.commit_hash {
        return StorageProofCheck::CommitHashMismatch;
    }
    let expected = chunk_index_for_challenge(prev_block_id, slot, &c_hash, commit.num_chunks);
    let got = proof.proof.index as u32;
    if got != expected {
        return StorageProofCheck::WrongChunkIndex { expected, got };
    }
    let leaf = chunk_hash(&proof.chunk);
    if !verify_merkle_proof(&leaf, &proof.proof, &commit.data_root) {
        return StorageProofCheck::MerkleInvalid;
    }
    StorageProofCheck::Valid
}

/// Producer-side helper: build the storage proof for the current block
/// context, given the full data + locally-held Merkle tree.
pub fn build_storage_proof(
    commit: &StorageCommitment,
    prev_block_id: &[u8; 32],
    slot: u32,
    data: &[u8],
    tree: &MerkleTree,
) -> Result<StorageProof, SporaError> {
    let c_hash = storage_commitment_hash(commit);
    let idx = chunk_index_for_challenge(prev_block_id, slot, &c_hash, commit.num_chunks);
    let chunks = chunk_data(data, commit.chunk_size as usize)?;
    let chunk_bytes = chunks
        .get(idx as usize)
        .ok_or(SporaError::ChunkIndexOutOfRange)?
        .to_vec();
    let mp = merkle_proof(tree, idx as usize).map_err(SporaError::Merkle)?;
    Ok(StorageProof {
        commit_hash: c_hash,
        chunk: chunk_bytes,
        proof: mp,
    })
}

/* ----------------------------------------------------------------------- *
 *  Errors                                                                  *
 * ----------------------------------------------------------------------- */

/// SPoRA construction / decoding errors.
#[derive(Debug, thiserror::Error)]
pub enum SporaError {
    /// `chunk_size` was zero or not a power of two.
    #[error("chunk size {0} must be a positive power of two")]
    InvalidChunkSize(usize),
    /// Caller asked to chunk zero leaves (degenerate).
    #[error("empty input to merkle tree")]
    EmptyInput,
    /// Number of chunks exceeded `u32::MAX`.
    #[error("too many chunks (exceeds u32)")]
    TooManyChunks,
    /// Replication factor must be at least 1.
    #[error("replication must be ≥ 1")]
    InvalidReplication,
    /// Underlying Merkle helper failed.
    #[error(transparent)]
    Merkle(#[from] MerkleError),
    /// Underlying codec read failed during proof decoding.
    #[error(transparent)]
    Codec(mfn_crypto::CryptoError),
    /// Build helper computed an out-of-range chunk index.
    #[error("chunk index out of range")]
    ChunkIndexOutOfRange,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_1mib() -> Vec<u8> {
        // 1 MiB of deterministic content (not zero — zero blocks can mask
        // off-by-one bugs in chunking).
        let mut v = Vec::with_capacity(1 << 20);
        for i in 0..(1 << 20) {
            v.push((i % 251) as u8);
        }
        v
    }

    #[test]
    fn chunk_data_default_size_round_trip() {
        let d = data_1mib();
        // 1 MiB / 256 KiB = 4 chunks of 256 KiB each.
        let chunks = chunk_data(&d, DEFAULT_CHUNK_SIZE).unwrap();
        assert_eq!(chunks.len(), 4);
        let mut joined = Vec::new();
        for c in &chunks {
            joined.extend_from_slice(c);
        }
        assert_eq!(joined, d);
    }

    #[test]
    fn chunk_data_rejects_bad_chunk_size() {
        assert!(matches!(
            chunk_data(&[1u8; 100], 0),
            Err(SporaError::InvalidChunkSize(0))
        ));
        assert!(matches!(
            chunk_data(&[1u8; 100], 3),
            Err(SporaError::InvalidChunkSize(3))
        ));
    }

    #[test]
    fn chunk_data_handles_short_tail() {
        let d = vec![1u8, 2, 3, 4, 5, 6, 7];
        let c = chunk_data(&d, 4).unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], &[1, 2, 3, 4]);
        assert_eq!(c[1], &[5, 6, 7]);
    }

    #[test]
    fn chunk_data_empty_input_yields_one_empty_chunk() {
        let c = chunk_data(&[], DEFAULT_CHUNK_SIZE).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].len(), 0);
    }

    #[test]
    fn build_storage_commitment_round_trip() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        assert_eq!(built.commit.num_chunks, 4);
        assert_eq!(built.commit.size_bytes, d.len() as u64);
        assert_eq!(built.commit.replication, 3);
        // Endowment opens.
        assert!(verify_endowment_opening(
            &built.commit,
            1_000,
            &built.blinding
        ));
    }

    #[test]
    fn build_storage_commitment_rejects_zero_replication() {
        assert!(matches!(
            build_storage_commitment(b"x", 0, None, 0, None),
            Err(SporaError::InvalidReplication)
        ));
    }

    #[test]
    fn chunk_index_in_range_for_random_seeds() {
        let prev = [9u8; 32];
        let ch = [3u8; 32];
        for slot in 0u32..32 {
            let idx = chunk_index_for_challenge(&prev, slot, &ch, 16);
            assert!(idx < 16);
        }
    }

    #[test]
    fn chunk_index_handles_zero_chunks() {
        let prev = [0u8; 32];
        let ch = [0u8; 32];
        assert_eq!(chunk_index_for_challenge(&prev, 0, &ch, 0), 0);
    }

    #[test]
    fn build_and_verify_storage_proof_round_trip() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        let prev = [42u8; 32];
        for slot in 0u32..8 {
            let p = build_storage_proof(&built.commit, &prev, slot, &d, &built.tree).unwrap();
            assert_eq!(
                verify_storage_proof(&built.commit, &prev, slot, &p),
                StorageProofCheck::Valid,
                "slot {slot}"
            );
        }
    }

    #[test]
    fn proof_with_wrong_chunk_is_rejected() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        let prev = [1u8; 32];
        let slot = 0u32;
        let mut p = build_storage_proof(&built.commit, &prev, slot, &d, &built.tree).unwrap();
        // Corrupt one byte of the chunk.
        p.chunk[0] ^= 0xff;
        assert_eq!(
            verify_storage_proof(&built.commit, &prev, slot, &p),
            StorageProofCheck::MerkleInvalid
        );
    }

    #[test]
    fn proof_with_wrong_index_is_rejected() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        let prev = [1u8; 32];
        let slot = 0u32;
        let p = build_storage_proof(&built.commit, &prev, slot, &d, &built.tree).unwrap();
        // Verify against a DIFFERENT slot that maps to a different chunk
        // index. With only 4 chunks any given slot has a 1/4 chance of
        // colliding with the base slot's index — explicitly search for
        // the first non-colliding slot before asserting.
        let c_hash = storage_commitment_hash(&built.commit);
        let base_idx = chunk_index_for_challenge(&prev, slot, &c_hash, built.commit.num_chunks);
        let mut other_slot = slot + 1;
        while chunk_index_for_challenge(&prev, other_slot, &c_hash, built.commit.num_chunks)
            == base_idx
        {
            other_slot += 1;
            assert!(
                other_slot - slot < 256,
                "couldn't find a non-colliding slot"
            );
        }
        let v = verify_storage_proof(&built.commit, &prev, other_slot, &p);
        assert!(
            matches!(v, StorageProofCheck::WrongChunkIndex { .. }),
            "expected wrong-index rejection at slot {other_slot}, got {v:?}"
        );
    }

    #[test]
    fn proof_with_wrong_commit_hash_is_rejected() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        let prev = [1u8; 32];
        let slot = 0u32;
        let mut p = build_storage_proof(&built.commit, &prev, slot, &d, &built.tree).unwrap();
        p.commit_hash[0] ^= 1;
        assert_eq!(
            verify_storage_proof(&built.commit, &prev, slot, &p),
            StorageProofCheck::CommitHashMismatch
        );
    }

    #[test]
    fn storage_proof_encode_decode_round_trip() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        let prev = [0u8; 32];
        let slot = 5u32;
        let p = build_storage_proof(&built.commit, &prev, slot, &d, &built.tree).unwrap();
        let bytes = encode_storage_proof(&p);
        let dec = decode_storage_proof(&bytes).unwrap();
        assert_eq!(dec.commit_hash, p.commit_hash);
        assert_eq!(dec.chunk, p.chunk);
        assert_eq!(dec.proof.index, p.proof.index);
        assert_eq!(dec.proof.siblings, p.proof.siblings);
        assert_eq!(dec.proof.right_side, p.proof.right_side);
        // And re-verifies against the same context.
        assert_eq!(
            verify_storage_proof(&built.commit, &prev, slot, &dec),
            StorageProofCheck::Valid
        );
    }

    #[test]
    fn challenge_index_from_seed_is_deterministic() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        assert_eq!(
            challenge_index_from_seed(&built.commit, b"seed-x"),
            challenge_index_from_seed(&built.commit, b"seed-x"),
        );
        // Different seeds typically give different indices (probabilistic;
        // we just check that the function reacts at all).
        let mut differ = false;
        for s in 0..8u8 {
            if challenge_index_from_seed(&built.commit, &[s])
                != challenge_index_from_seed(&built.commit, &[0])
            {
                differ = true;
                break;
            }
        }
        assert!(differ);
    }

    /* ----------------------------------------------------------- *
     *  Merkle commitment (M2.0.2)                                  *
     * ----------------------------------------------------------- */

    #[test]
    fn storage_proof_merkle_root_empty_is_zero_sentinel() {
        assert_eq!(storage_proof_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn storage_proof_leaf_hash_is_deterministic() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        let prev = [0u8; 32];
        let p = build_storage_proof(&built.commit, &prev, 0, &d, &built.tree).unwrap();
        assert_eq!(storage_proof_leaf_hash(&p), storage_proof_leaf_hash(&p));
    }

    #[test]
    fn storage_proof_leaf_hash_changes_with_proof_content() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        let prev = [0u8; 32];
        let p0 = build_storage_proof(&built.commit, &prev, 0, &d, &built.tree).unwrap();
        let mut p1 = p0.clone();
        p1.commit_hash[0] ^= 0xff;
        assert_ne!(storage_proof_leaf_hash(&p0), storage_proof_leaf_hash(&p1));
    }

    #[test]
    fn storage_proof_merkle_root_changes_with_addition() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        let prev = [0u8; 32];
        let p0 = build_storage_proof(&built.commit, &prev, 0, &d, &built.tree).unwrap();
        // Build a "different" proof by flipping the chunk under the same
        // commitment — the leaf hash will differ even though the proof
        // wouldn't itself verify. (We're testing the commitment helper,
        // not the verifier, so any structurally distinct proof bytes
        // suffice.)
        let mut p1 = p0.clone();
        p1.chunk[0] ^= 0x55;

        let r_one = storage_proof_merkle_root(std::slice::from_ref(&p0));
        let r_two = storage_proof_merkle_root(&[p0, p1]);
        assert_ne!(r_one, r_two);
    }

    #[test]
    fn storage_proof_merkle_root_is_order_sensitive() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        let prev = [0u8; 32];
        let p0 = build_storage_proof(&built.commit, &prev, 0, &d, &built.tree).unwrap();
        let mut p1 = p0.clone();
        p1.chunk[0] ^= 0x55;
        let r_a = storage_proof_merkle_root(&[p0.clone(), p1.clone()]);
        let r_b = storage_proof_merkle_root(&[p1, p0]);
        assert_ne!(r_a, r_b);
    }

    #[test]
    fn storage_proof_leaf_is_domain_separated() {
        let d = data_1mib();
        let built = build_storage_commitment(&d, 1_000, Some(DEFAULT_CHUNK_SIZE), 3, None).unwrap();
        let prev = [0u8; 32];
        let p = build_storage_proof(&built.commit, &prev, 0, &d, &built.tree).unwrap();
        let leaf = storage_proof_leaf_hash(&p);
        let other = dhash(
            b"MFBN-1/not-a-storage-proof-leaf",
            &[&encode_storage_proof(&p)],
        );
        assert_ne!(leaf, other);
    }

    /// **TS-parity reference vector (M2.0.2).**
    ///
    /// A TypeScript port (or any independent implementation) of
    /// `storage_proof_leaf_hash` / `storage_proof_merkle_root` MUST
    /// produce these exact hex values from the deterministic inputs
    /// `p0` and `p1` below.
    ///
    /// `p0` exercises a 0-sibling proof (root == leaf, single-chunk
    /// commitment). `p1` exercises a 2-sibling proof with a mixed
    /// `right_side` pattern (so encoders cannot accidentally swap the
    /// boolean column).
    ///
    /// We intentionally construct the `StorageProof`s by hand here:
    /// the goal is to pin the *encoding + hashing* surface, not the
    /// Merkle-membership semantics (which are exercised elsewhere).
    ///
    /// ## Reproducing in TS
    ///
    /// 1. Build each leaf as
    ///    ```text
    ///    encode_storage_proof(p) =
    ///        commit_hash(32) ‖ blob(chunk) ‖ varint(index) ‖
    ///        varint(siblings.len) ‖
    ///        [ siblings[i](32) ‖ u8(right_side[i] ? 1 : 0) ]*
    ///    ```
    ///    where `blob(x) = varint(x.len) ‖ x`.
    /// 2. `leaf_hash(p) = SHA-512/256(dhash) over
    ///    "MFBN-1/storage-proof-leaf" ‖ varint-len-prefix encoding of
    ///    `encode_storage_proof(p)`.
    /// 3. `root = merkle_root_or_zero([leaf(p0), leaf(p1)])` with the
    ///    same canonical Merkle scheme (`MERKLE_NODE` interior domain,
    ///    odd-leaf duplication).
    ///
    /// See `docs/interop/TS_STORAGE_PROOF_ROOT_GOLDEN_VECTORS.md`.
    #[test]
    fn storage_proof_root_wire_matches_cloonan_ts_smoke_reference() {
        // Deterministic, hand-constructed proofs (no randomness, no
        // dependency on the chunking pipeline).
        let p0 = StorageProof {
            commit_hash: [0xaau8; 32],
            chunk: vec![0u8, 1, 2, 3, 4, 5, 6, 7],
            proof: MerkleProof {
                siblings: Vec::new(),
                right_side: Vec::new(),
                index: 0,
            },
        };
        let p1 = StorageProof {
            commit_hash: [0xbbu8; 32],
            chunk: b"permawrite".to_vec(),
            proof: MerkleProof {
                siblings: vec![[0x11u8; 32], [0x22u8; 32]],
                right_side: vec![true, false],
                index: 1,
            },
        };

        let leaf0 = storage_proof_leaf_hash(&p0);
        let leaf1 = storage_proof_leaf_hash(&p1);
        let root = storage_proof_merkle_root(&[p0, p1]);

        assert_eq!(
            hex::encode(leaf0),
            "694b5a17a842c528d24f24e53cdd9a1601fff4018c365d8a7f448411daf4709d",
            "storage-proof leaf for p0 (0-sibling) drifted"
        );
        assert_eq!(
            hex::encode(leaf1),
            "00bc55e1545fa11184cd2aeb450173fdf8d940cb6f18e294d6f0be454b6c05f6",
            "storage-proof leaf for p1 (2-sibling, mixed right_side) drifted"
        );
        assert_eq!(
            hex::encode(root),
            "aaae83fcbc777d692c7fbc0f469213faae63082e8c040c163256ef751c889c6b",
            "storage_proof_merkle_root over [p0, p1] drifted"
        );
    }
}
