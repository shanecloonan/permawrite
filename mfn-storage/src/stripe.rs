//! Header v9 shard uploads.
//!
//! A file is split into 4 data shards and 8 parity shards. The bytes
//! anchored on chain are those 12 shards laid end to end. `data_root` is
//! the Merkle root of the shard hashes, so a storage proof of chunk `i` is
//! a proof of shard `i`. Any 4 shards rebuild the file.
//!
//! Header versions below [`HEADER_VERSION_SHARDS`] keep the power-of-two
//! size bucket. Path A and F-A stay there.

use crate::commitment::{
    validate_storage_commitment_shape, CommitmentShapeError, StorageCommitment,
};
use crate::erasure::{
    encode_stripe, reconstruct_systematic, ErasureError, ErasureLayout, RECOMMENDED_DATA_SHARDS,
    RECOMMENDED_PARITY_SHARDS,
};

/// Header version that anchors shard stripes instead of size buckets.
///
/// Seat B uses header versions 4 through 8. Version 8 is left unused here.
/// Path A and F-A stay on version 1.
pub const HEADER_VERSION_SHARDS: u32 = 9;

/// Shards in one stripe. Four data, eight parity.
pub const STRIPE_SHARDS: u32 = 12;

/// One file prepared for a header v9 upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedStripe {
    /// Concatenation of the 12 shards. This is what the wallet anchors.
    pub bytes: Vec<u8>,
    /// Length of one shard. Also the commitment `chunk_size`.
    pub chunk_size: u32,
    /// Shard bytes, index 0..12.
    pub shards: Vec<Vec<u8>>,
}

/// Why a stripe could not be built or opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StripeError {
    /// Reed–Solomon failure.
    Erasure(ErasureError),
    /// The byte string is not 12 equal power-of-two shards.
    NotAStripe,
    /// The parity shards do not match a re-encode of the data shards.
    Inconsistent,
    /// The length prefix inside the systematic bytes is out of range.
    BadLength,
}

/// Build the 12-shard payload for `plaintext`.
///
/// # Errors
///
/// [`StripeError::Erasure`] when the code cannot be built.
pub fn prepare_shard_stripe(plaintext: &[u8]) -> Result<PreparedStripe, StripeError> {
    let layout = stripe_layout();
    let per_data = shard_len_for(plaintext.len());
    let mut logical = Vec::with_capacity(8 + plaintext.len());
    let len = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
    logical.extend_from_slice(&len.to_be_bytes());
    logical.extend_from_slice(plaintext);
    logical.resize(per_data * usize::from(layout.data_shards), 0);
    let stripe = encode_stripe(&[0u8; 32], &logical, layout).map_err(StripeError::Erasure)?;
    let shards: Vec<Vec<u8>> = stripe
        .shards
        .into_iter()
        .map(|s| s.unwrap_or_default())
        .collect();
    if shards.len() != usize::try_from(STRIPE_SHARDS).unwrap_or(12) {
        return Err(StripeError::Inconsistent);
    }
    let mut bytes = Vec::with_capacity(shards.len() * per_data);
    for shard in &shards {
        bytes.extend_from_slice(shard);
    }
    Ok(PreparedStripe {
        bytes,
        chunk_size: u32::try_from(per_data).unwrap_or(u32::MAX),
        shards,
    })
}

/// `true` when `data` is exactly 12 shards of `chunk_size` bytes.
#[must_use]
pub fn is_exact_shard_stripe(data: &[u8], chunk_size: Option<usize>) -> bool {
    let Some(chunk_size) = chunk_size else {
        return false;
    };
    chunk_size.is_power_of_two()
        && chunk_size >= 32
        && data.len() == chunk_size * usize::try_from(STRIPE_SHARDS).unwrap_or(12)
}

/// Split a committed stripe. `None` when the bytes are not a consistent code.
#[must_use]
pub fn split_committed_stripe(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    if bytes.len() % usize::try_from(STRIPE_SHARDS).unwrap_or(12) != 0 {
        return None;
    }
    let shard_len = bytes.len() / usize::try_from(STRIPE_SHARDS).unwrap_or(12);
    if !is_exact_shard_stripe(bytes, Some(shard_len)) {
        return None;
    }
    let shards: Vec<Vec<u8>> = bytes.chunks(shard_len).map(<[u8]>::to_vec).collect();
    let mut present: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
    for slot in present
        .iter_mut()
        .skip(usize::from(RECOMMENDED_DATA_SHARDS))
    {
        *slot = None;
    }
    let logical = reconstruct_systematic(&present, stripe_layout()).ok()?;
    let again = encode_stripe(&[0u8; 32], &logical, stripe_layout()).ok()?;
    let rebuilt: Vec<Vec<u8>> = again
        .shards
        .into_iter()
        .map(|s| s.unwrap_or_default())
        .collect();
    if rebuilt != shards {
        return None;
    }
    Some(shards)
}

/// Rebuild plaintext from shard slots. Missing shards are `None`.
///
/// # Errors
///
/// [`StripeError`] when the set is short, inconsistent, or the length prefix lies.
pub fn open_shard_stripe(shards: &[Option<Vec<u8>>]) -> Result<Vec<u8>, StripeError> {
    if shards.len() != usize::try_from(STRIPE_SHARDS).unwrap_or(12) {
        return Err(StripeError::NotAStripe);
    }
    let logical = reconstruct_systematic(shards, stripe_layout()).map_err(StripeError::Erasure)?;
    if logical.len() < 8 {
        return Err(StripeError::BadLength);
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&logical[..8]);
    let len = usize::try_from(u64::from_be_bytes(len_bytes)).unwrap_or(usize::MAX);
    if len > logical.len() - 8 {
        return Err(StripeError::BadLength);
    }
    Ok(logical[8..8 + len].to_vec())
}

/// Shape rule for a commitment at `header_version`.
///
/// Below version 9 this is the existing bucket check. At version 9 and
/// above the commitment must be exactly 12 equal shards.
///
/// # Errors
///
/// [`CommitmentShapeError`] when the geometry does not match the version.
pub fn validate_storage_commitment_for_header(
    commitment: &StorageCommitment,
    header_version: u32,
) -> Result<(), CommitmentShapeError> {
    if header_version < HEADER_VERSION_SHARDS {
        return validate_storage_commitment_shape(commitment);
    }
    if commitment.chunk_size == 0 || !commitment.chunk_size.is_power_of_two() {
        return Err(CommitmentShapeError::InvalidChunkSize(
            commitment.chunk_size,
        ));
    }
    let expect = u64::from(commitment.chunk_size) * u64::from(STRIPE_SHARDS);
    if commitment.num_chunks != STRIPE_SHARDS || commitment.size_bytes != expect {
        return Err(CommitmentShapeError::NotShardStripe {
            shards: STRIPE_SHARDS,
            got: commitment.num_chunks,
            size_bytes: commitment.size_bytes,
            chunk_size: commitment.chunk_size,
        });
    }
    Ok(())
}

/// `true` when an upload should be a 12-shard stripe.
///
/// Header version 9 and above always stripe. Below that, only an explicit
/// request does. Path A stays header version 1.
#[must_use]
pub fn upload_should_stripe(header_version: u32, requested: bool) -> bool {
    requested || header_version >= HEADER_VERSION_SHARDS
}

fn stripe_layout() -> ErasureLayout {
    ErasureLayout {
        data_shards: RECOMMENDED_DATA_SHARDS,
        parity_shards: RECOMMENDED_PARITY_SHARDS,
    }
}

fn shard_len_for(plaintext_len: usize) -> usize {
    let logical = 8usize.saturating_add(plaintext_len);
    let per_data = logical.div_ceil(usize::from(RECOMMENDED_DATA_SHARDS));
    per_data.max(32).next_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spora::build_storage_commitment;

    #[test]
    fn header_v9_stripes_without_a_flag_and_path_a_does_not() {
        assert!(upload_should_stripe(HEADER_VERSION_SHARDS, false));
        assert!(upload_should_stripe(1, true));
        assert!(!upload_should_stripe(1, false));
        assert!(!upload_should_stripe(8, false));
    }

    #[test]
    fn four_of_twelve_rebuild_and_v9_accepts_only_the_stripe() {
        let plain = b"a file that must survive eight operators leaving".to_vec();
        let prepared = prepare_shard_stripe(&plain).expect("stripe");
        assert_eq!(prepared.shards.len(), 12);
        assert!(is_exact_shard_stripe(
            &prepared.bytes,
            Some(prepared.chunk_size as usize)
        ));
        let mut slots: Vec<Option<Vec<u8>>> = prepared.shards.iter().cloned().map(Some).collect();
        for slot in slots.iter_mut().take(8) {
            *slot = None;
        }
        assert_eq!(open_shard_stripe(&slots).expect("open"), plain);

        let built = build_storage_commitment(
            &prepared.bytes,
            1,
            Some(prepared.chunk_size as usize),
            3,
            None,
        )
        .expect("commit");
        assert!(validate_storage_commitment_for_header(&built.commit, 9).is_ok());
        assert!(validate_storage_commitment_for_header(&built.commit, 1).is_err());

        let bucket = build_storage_commitment(&[7u8; 32], 1, Some(32), 3, None).expect("bucket");
        assert!(validate_storage_commitment_for_header(&bucket.commit, 1).is_ok());
        assert!(matches!(
            validate_storage_commitment_for_header(&bucket.commit, HEADER_VERSION_SHARDS),
            Err(CommitmentShapeError::NotShardStripe { .. })
        ));
        assert!(split_committed_stripe(&prepared.bytes).is_some());
    }
}
