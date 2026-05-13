//! Storage commitment — the content-addressed binding a transaction output
//! can carry to anchor a permanent data payload on-chain.
//!
//! Port of the struct + hasher from `cloonan-group/lib/network/storage.ts`.
//! The actual SPoRA prover/verifier lives in [`crate::spora`]; this module
//! is the wire-format truth.
//!
//! ## Wire format (must match the TS reference)
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
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::dhash;
use mfn_crypto::domain::STORAGE_COMMIT;

/// A storage commitment: content-addressed binding of a permanent payload
/// to a transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageCommitment {
    /// Merkle root of chunk hashes (computed by [`crate::spora`]).
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

/* ----------------------------------------------------------------------- *
 *  Wire codec (M2.0.10)                                                    *
 * ----------------------------------------------------------------------- */

/// Lossless canonical byte encoding of a [`StorageCommitment`].
///
/// Same field order and primitive layout as [`storage_commitment_hash`]
/// — the hash and the encoding are derived from the identical byte
/// stream so cross-implementation parity is automatic.
///
/// This is the encoder a full-block wire codec uses to round-trip the
/// optional permanence binding on a tx output: the hash alone is not
/// sufficient there, the full struct must travel with the block.
#[must_use]
pub fn encode_storage_commitment(c: &StorageCommitment) -> Vec<u8> {
    let mut w = Writer::new();
    w.push(&c.data_root);
    w.u64(c.size_bytes);
    w.u32(c.chunk_size);
    w.u32(c.num_chunks);
    w.u8(c.replication);
    w.point(&c.endowment);
    w.into_bytes()
}

/// Decode a [`StorageCommitment`] from its canonical bytes.
///
/// Strict: any trailing byte after the final field is a hard reject.
///
/// # Errors
///
/// Returns [`mfn_crypto::CryptoError`] on truncation, invalid Edwards
/// point compression, or trailing bytes.
pub fn decode_storage_commitment(
    bytes: &[u8],
) -> Result<StorageCommitment, mfn_crypto::CryptoError> {
    let mut r = Reader::new(bytes);
    let mut data_root = [0u8; 32];
    data_root.copy_from_slice(r.bytes(32)?);
    let size_bytes = r.u64()?;
    let chunk_size = r.u32()?;
    let num_chunks = r.u32()?;
    let replication = r.u8()?;
    let endowment = r.point()?;
    if !r.end() {
        return Err(mfn_crypto::CryptoError::TrailingBytes {
            remaining: r.remaining(),
        });
    }
    Ok(StorageCommitment {
        data_root,
        size_bytes,
        chunk_size,
        num_chunks,
        replication,
        endowment,
    })
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
    fn encode_decode_round_trip() {
        let c = sample_commit();
        let bytes = encode_storage_commitment(&c);
        let recovered = decode_storage_commitment(&bytes).expect("decode");
        assert_eq!(recovered, c);
        // Re-encoding the decoded value must produce identical bytes.
        assert_eq!(encode_storage_commitment(&recovered), bytes);
    }

    #[test]
    fn encoded_length_is_fixed_81_bytes() {
        // data_root(32) + size_bytes(8) + chunk_size(4) + num_chunks(4)
        // + replication(1) + endowment(32) = 81 bytes.
        let c = sample_commit();
        let bytes = encode_storage_commitment(&c);
        assert_eq!(bytes.len(), 81);
    }

    #[test]
    fn decode_rejects_truncation_at_every_prefix() {
        let c = sample_commit();
        let bytes = encode_storage_commitment(&c);
        for prefix in 0..bytes.len() {
            let err = decode_storage_commitment(&bytes[..prefix]);
            assert!(err.is_err(), "prefix of length {prefix} should be rejected");
        }
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let c = sample_commit();
        let mut bytes = encode_storage_commitment(&c);
        bytes.push(0xff);
        let err = decode_storage_commitment(&bytes).unwrap_err();
        assert!(matches!(
            err,
            mfn_crypto::CryptoError::TrailingBytes { remaining: 1 }
        ));
    }

    #[test]
    fn decode_then_hash_equals_original_hash() {
        // The most important consensus invariant: a decoded commitment
        // hashes to the same `commit_hash` as the original.
        let c = sample_commit();
        let bytes = encode_storage_commitment(&c);
        let recovered = decode_storage_commitment(&bytes).expect("decode");
        assert_eq!(
            storage_commitment_hash(&recovered),
            storage_commitment_hash(&c)
        );
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
