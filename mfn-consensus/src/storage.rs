//! Storage commitments — the **permanence binding** that a transaction
//! output can optionally carry to anchor a permanent data payload to the
//! chain.
//!
//! ## What's in v0
//!
//! Just the wire shape and its canonical hash. That's all the consensus
//! transaction-verifier needs: when an output declares `storage = Some(c)`,
//! the tx preimage commits to `storage_commitment_hash(c)`, so any later
//! tamper with the commitment fields invalidates the transaction's CLSAG
//! signatures.
//!
//! The actual storage prover — chunking, Merkle tree, SPoRA challenge
//! protocol, slashing — will live in a future `mfn-storage` crate. The
//! `StorageCommitment` struct will move there; this module re-exports it for
//! backwards-compatibility.
//!
//! ## Wire format (must match `lib/network/storage.ts`)
//!
//! ```text
//! data_root    [32]  Merkle root of chunk hashes
//! size_bytes   [u64] total payload size in bytes (big-endian)
//! chunk_size   [u32] chunk granularity (power of two)
//! num_chunks   [u32] derived: ceil(size_bytes / chunk_size)
//! replication  [u8]  minimum replicas the network promises
//! endowment    [32]  Pedersen commitment (compressed Edwards point)
//! ```
//!
//! All fields are big-endian. The hash is
//! `dhash(STORAGE_COMMIT, write(data_root) || u64(size) || u32(chunk) || u32(num) || u8(rep) || point(end))`.

use curve25519_dalek::edwards::EdwardsPoint;
use mfn_crypto::codec::Writer;
use mfn_crypto::dhash;
use mfn_crypto::domain::STORAGE_COMMIT;

/// A storage commitment: content-addressed binding of a permanent payload
/// to a transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageCommitment {
    /// Merkle root of chunk hashes.
    pub data_root: [u8; 32],
    /// Total size of the original data, in bytes.
    pub size_bytes: u64,
    /// Chunk size used by the Merkle tree (must be a power of two).
    pub chunk_size: u32,
    /// Number of leaves in the Merkle tree (== number of chunks).
    pub num_chunks: u32,
    /// Minimum replication factor the network must maintain.
    pub replication: u8,
    /// Pedersen commitment to the endowment amount paid for permanence.
    pub endowment: EdwardsPoint,
}

/// Canonical hash of a storage commitment. This is the storage's unique
/// on-chain identity — the value transactions reference and that blocks
/// merkleize.
///
/// Byte-for-byte compatible with `storageCommitmentHash` in
/// `lib/network/storage.ts`.
pub fn storage_commitment_hash(c: &StorageCommitment) -> [u8; 32] {
    let mut w = Writer::new();
    w.push(&c.data_root);
    w.u64(c.size_bytes);
    w.u32(c.chunk_size);
    w.u32(c.num_chunks);
    w.u8(c.replication);
    w.point(&c.endowment);
    dhash(STORAGE_COMMIT, &[w.bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use mfn_crypto::point::generator_g;

    fn sample_commit() -> StorageCommitment {
        StorageCommitment {
            data_root: [7u8; 32],
            size_bytes: 1_048_576,
            chunk_size: 65_536,
            num_chunks: 16,
            replication: 3,
            endowment: generator_g() * Scalar::from(42u64),
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let c = sample_commit();
        assert_eq!(storage_commitment_hash(&c), storage_commitment_hash(&c));
    }

    #[test]
    fn hash_changes_when_any_field_changes() {
        let base = sample_commit();
        let base_h = storage_commitment_hash(&base);

        let mut c2 = base.clone();
        c2.data_root[0] ^= 1;
        assert_ne!(storage_commitment_hash(&c2), base_h, "data_root sensitive");

        let mut c3 = base.clone();
        c3.size_bytes ^= 1;
        assert_ne!(storage_commitment_hash(&c3), base_h, "size_bytes sensitive");

        let mut c4 = base.clone();
        c4.chunk_size ^= 1;
        assert_ne!(storage_commitment_hash(&c4), base_h, "chunk_size sensitive");

        let mut c5 = base.clone();
        c5.num_chunks ^= 1;
        assert_ne!(storage_commitment_hash(&c5), base_h, "num_chunks sensitive");

        let mut c6 = base.clone();
        c6.replication = c6.replication.wrapping_add(1);
        assert_ne!(
            storage_commitment_hash(&c6),
            base_h,
            "replication sensitive"
        );

        let mut c7 = base;
        c7.endowment += generator_g();
        assert_ne!(storage_commitment_hash(&c7), base_h, "endowment sensitive");
    }
}
