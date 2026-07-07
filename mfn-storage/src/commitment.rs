//! Storage commitment — the content-addressed binding a transaction output
//! can carry to anchor a permanent data payload on-chain.
//!
//! Canonical storage commitment struct and hasher.
//! The actual SPoRA prover/verifier lives in [`crate::spora`]; this module
//! is the wire-format truth.
//!
//! ## Wire format (is canonical for the protocol)
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

/// Structural (shape) validation errors for a [`StorageCommitment`].
///
/// These are *consensus* rejections: a commitment whose declared geometry
/// is inconsistent breaks the SPoRA audit surface (challenges are derived
/// `mod num_chunks`, provers re-chunk with `chunk_size`), so the chain
/// must never anchor one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitmentShapeError {
    /// `chunk_size` was zero or not a power of two.
    #[error("chunk_size {0} must be a positive power of two")]
    InvalidChunkSize(u32),
    /// `num_chunks` disagrees with `ceil(size_bytes / chunk_size)`
    /// (or `1` for an empty payload).
    #[error(
        "num_chunks {got} != expected {expected} \
         (size_bytes={size_bytes}, chunk_size={chunk_size})"
    )]
    NumChunksMismatch {
        /// Declared chunk count.
        got: u32,
        /// Count implied by `size_bytes` / `chunk_size`.
        expected: u32,
        /// Declared payload size.
        size_bytes: u64,
        /// Declared chunk granularity.
        chunk_size: u32,
    },
    /// The implied chunk count exceeds `u32::MAX` — the commitment could
    /// never have been produced by [`crate::spora::build_storage_commitment`].
    #[error(
        "size_bytes {size_bytes} at chunk_size {chunk_size} implies more than u32::MAX chunks"
    )]
    TooManyChunks {
        /// Declared payload size.
        size_bytes: u64,
        /// Declared chunk granularity.
        chunk_size: u32,
    },
    /// `size_bytes` is not a canonical power-of-two bucket (**F5-P15** /
    /// B13). Non-reference uploaders must declare the same bucket the
    /// reference wallet pads to — exact byte lengths leak file size.
    #[error(
        "size_bytes {got} is not a canonical bucket (expected {expected} \
         from storage_size_bucket)"
    )]
    SizeNotCanonicalBucket {
        /// Declared payload size.
        got: u64,
        /// Bucket implied by `got`.
        expected: u64,
    },
}

/// Chunk count [`crate::spora::build_storage_commitment`] produces for a
/// payload of `size_bytes` at `chunk_size` granularity.
///
/// An empty payload still yields one (empty) chunk so the Merkle tree has
/// a leaf. Returns [`CommitmentShapeError`] when `chunk_size` is invalid
/// or the count would overflow `u32`.
pub fn expected_num_chunks(size_bytes: u64, chunk_size: u32) -> Result<u32, CommitmentShapeError> {
    if chunk_size == 0 || !chunk_size.is_power_of_two() {
        return Err(CommitmentShapeError::InvalidChunkSize(chunk_size));
    }
    if size_bytes == 0 {
        return Ok(1);
    }
    let n = size_bytes.div_ceil(u64::from(chunk_size));
    u32::try_from(n).map_err(|_| CommitmentShapeError::TooManyChunks {
        size_bytes,
        chunk_size,
    })
}

/// Round a payload length up to the next power-of-two **size bucket**
/// (**F5-P15** / B13). Zero-length payloads stay at zero (empty-commitment
/// shape). Reference wallets pad to this bucket before anchoring so the
/// on-chain `size_bytes` field does not leak exact file lengths.
#[must_use]
pub fn storage_size_bucket(size_bytes: u64) -> u64 {
    if size_bytes == 0 {
        0
    } else {
        size_bytes.next_power_of_two()
    }
}

/// Pad `data` with trailing zero bytes up to [`storage_size_bucket`].
#[must_use]
pub fn pad_to_storage_size_bucket(data: &[u8]) -> Vec<u8> {
    let bucket = storage_size_bucket(data.len() as u64) as usize;
    if data.len() >= bucket {
        return data.to_vec();
    }
    let mut out = data.to_vec();
    out.resize(bucket, 0);
    out
}

/// Validate that a [`StorageCommitment`]'s declared geometry is
/// internally consistent (**M5.49**).
///
/// SPoRA's per-block challenge is `H(...) mod num_chunks` and endowment
/// pricing keys off `size_bytes` — a commitment that declares
/// `num_chunks: 1` for a gigabyte payload would be "provable" while the
/// network audits (and effectively stores) a single chunk, silently
/// voiding the permanence guarantee. `apply_block` and the mempool call
/// this before anchoring any NEW commitment.
///
/// Checks:
///
/// 1. `chunk_size` is a positive power of two,
/// 2. `num_chunks == ceil(size_bytes / chunk_size)` (`1` when
///    `size_bytes == 0`) — which also forces `num_chunks >= 1`, ruling
///    out the degenerate zero-chunk challenge,
/// 3. `size_bytes == storage_size_bucket(size_bytes)` — on-chain length
///    must be a power-of-two bucket (zero stays zero).
///
/// # Errors
///
/// [`CommitmentShapeError`] describing the first failed check.
pub fn validate_storage_commitment_shape(
    c: &StorageCommitment,
) -> Result<(), CommitmentShapeError> {
    let expected = expected_num_chunks(c.size_bytes, c.chunk_size)?;
    if c.num_chunks != expected {
        return Err(CommitmentShapeError::NumChunksMismatch {
            got: c.num_chunks,
            expected,
            size_bytes: c.size_bytes,
            chunk_size: c.chunk_size,
        });
    }
    let bucket = storage_size_bucket(c.size_bytes);
    if c.size_bytes != bucket {
        return Err(CommitmentShapeError::SizeNotCanonicalBucket {
            got: c.size_bytes,
            expected: bucket,
        });
    }
    Ok(())
}

/// Canonical hash of a storage commitment. This is the storage's unique
/// on-chain identity — the value transactions reference and that blocks
/// merkleize.
///
/// Byte-for-byte compatible with `storageCommitmentHash` in
/// the Rust protocol.
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
    fn storage_size_bucket_rounds_up_to_power_of_two() {
        assert_eq!(storage_size_bucket(0), 0);
        assert_eq!(storage_size_bucket(1), 1);
        assert_eq!(storage_size_bucket(900), 1024);
        assert_eq!(storage_size_bucket(1024), 1024);
    }

    #[test]
    fn pad_to_storage_size_bucket_zero_fills() {
        let data = b"hello";
        let padded = pad_to_storage_size_bucket(data);
        assert_eq!(padded.len(), 8);
        assert_eq!(&padded[..5], data);
        assert!(padded[5..].iter().all(|b| *b == 0));
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

    /* ------------------------- shape validation (M5.49) ------------- */

    #[test]
    fn shape_accepts_consistent_commitment() {
        assert_eq!(validate_storage_commitment_shape(&sample_commit()), Ok(()));
    }

    #[test]
    fn shape_accepts_empty_payload_single_chunk() {
        let mut c = sample_commit();
        c.size_bytes = 0;
        c.num_chunks = 1;
        assert_eq!(validate_storage_commitment_shape(&c), Ok(()));
    }

    #[test]
    fn shape_accepts_builder_output() {
        // Whatever build_storage_commitment produces must validate —
        // including the short-tail and empty-payload cases.
        for payload_len in [0usize, 1, 255, 256, 257, 1024, 100_000] {
            let payload = pad_to_storage_size_bucket(&vec![0xa5u8; payload_len]);
            let built = crate::spora::build_storage_commitment(&payload, 1_000, Some(256), 3, None)
                .expect("build");
            assert_eq!(
                validate_storage_commitment_shape(&built.commit),
                Ok(()),
                "payload_len={payload_len}"
            );
        }
    }

    #[test]
    fn shape_rejects_non_bucket_size_bytes() {
        let mut c = sample_commit();
        c.size_bytes = 900; // bucket would be 1024
        c.chunk_size = 256;
        c.num_chunks = 4; // ceil(900/256)
        assert_eq!(
            validate_storage_commitment_shape(&c),
            Err(CommitmentShapeError::SizeNotCanonicalBucket {
                got: 900,
                expected: 1024,
            })
        );
    }

    #[test]
    fn shape_rejects_zero_chunk_size() {
        let mut c = sample_commit();
        c.chunk_size = 0;
        assert_eq!(
            validate_storage_commitment_shape(&c),
            Err(CommitmentShapeError::InvalidChunkSize(0))
        );
    }

    #[test]
    fn shape_rejects_non_power_of_two_chunk_size() {
        let mut c = sample_commit();
        c.chunk_size = 65_537;
        assert_eq!(
            validate_storage_commitment_shape(&c),
            Err(CommitmentShapeError::InvalidChunkSize(65_537))
        );
    }

    #[test]
    fn shape_rejects_zero_num_chunks() {
        let mut c = sample_commit();
        c.num_chunks = 0;
        assert!(matches!(
            validate_storage_commitment_shape(&c),
            Err(CommitmentShapeError::NumChunksMismatch { got: 0, .. })
        ));
    }

    #[test]
    fn shape_rejects_understated_num_chunks() {
        // The "1 GiB payload, 1 declared chunk" attack: SPoRA would only
        // ever audit chunk 0 while pricing charges for the full size.
        let mut c = sample_commit();
        c.num_chunks = 1; // real: 16
        assert!(matches!(
            validate_storage_commitment_shape(&c),
            Err(CommitmentShapeError::NumChunksMismatch {
                got: 1,
                expected: 16,
                ..
            })
        ));
    }

    #[test]
    fn shape_rejects_overstated_num_chunks() {
        let mut c = sample_commit();
        c.num_chunks = 17; // real: 16
        assert!(matches!(
            validate_storage_commitment_shape(&c),
            Err(CommitmentShapeError::NumChunksMismatch {
                got: 17,
                expected: 16,
                ..
            })
        ));
    }

    #[test]
    fn shape_rejects_chunk_count_overflowing_u32() {
        let mut c = sample_commit();
        c.size_bytes = u64::MAX;
        c.chunk_size = 1;
        c.num_chunks = u32::MAX;
        assert!(matches!(
            validate_storage_commitment_shape(&c),
            Err(CommitmentShapeError::TooManyChunks { .. })
        ));
    }

    #[test]
    fn expected_num_chunks_matches_ceiling_division() {
        assert_eq!(expected_num_chunks(0, 256), Ok(1));
        assert_eq!(expected_num_chunks(1, 256), Ok(1));
        assert_eq!(expected_num_chunks(256, 256), Ok(1));
        assert_eq!(expected_num_chunks(257, 256), Ok(2));
        assert_eq!(expected_num_chunks(1_048_576, 65_536), Ok(16));
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
