//! Check that fetched bytes are the chunk the chain committed to.
//!
//! A peer can return any body. Agreement among peers is not integrity:
//! several peers can return the same wrong bytes. A chunk is accepted only
//! when its [`chunk_hash`] is the Merkle leaf at the requested index under
//! the commitment's `data_root`.

use mfn_crypto::merkle::{verify_merkle_proof, MerkleProof};

use crate::spora::{chunk_hash, decode_merkle_proof_wire, encode_merkle_proof_wire};

/// Why an opened chunk was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityError {
    /// The frame is shorter than a length prefix.
    #[error("truncated opened-chunk frame")]
    Truncated,
    /// The length prefix does not match the frame.
    #[error("opened-chunk length does not match the frame")]
    LengthMismatch,
    /// The Merkle proof bytes are not canonical.
    #[error("merkle proof: {0}")]
    Proof(String),
    /// `proof.index` is not the index that was requested.
    #[error("proof index {got} != requested {expected}")]
    WrongIndex {
        /// Index the caller asked for.
        expected: u32,
        /// Index inside the proof.
        got: usize,
    },
    /// The chunk hash is not the leaf under `data_root`.
    #[error("chunk does not open data_root")]
    RootMismatch,
}

/// `true` when `chunk` is the leaf `proof` opens under `data_root`.
#[must_use]
pub fn chunk_opens_data_root(chunk: &[u8], proof: &MerkleProof, data_root: &[u8; 32]) -> bool {
    let leaf = chunk_hash(chunk);
    verify_merkle_proof(&leaf, proof, data_root)
}

/// Length-prefixed chunk followed by a canonical Merkle proof.
///
/// # Errors
///
/// [`IntegrityError::LengthMismatch`] when the chunk does not fit in a `u32`.
pub fn encode_opened_chunk(chunk: &[u8], proof: &MerkleProof) -> Result<Vec<u8>, IntegrityError> {
    let len = u32::try_from(chunk.len()).map_err(|_| IntegrityError::LengthMismatch)?;
    let mut out = Vec::with_capacity(4 + chunk.len() + 64);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(chunk);
    out.extend_from_slice(&encode_merkle_proof_wire(proof));
    Ok(out)
}

/// Split a frame into chunk bytes and a proof.
///
/// # Errors
///
/// [`IntegrityError`] when the frame is truncated or the proof is not canonical.
pub fn decode_opened_chunk(frame: &[u8]) -> Result<(Vec<u8>, MerkleProof), IntegrityError> {
    if frame.len() < 4 {
        return Err(IntegrityError::Truncated);
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let len_usize = usize::try_from(len).unwrap_or(usize::MAX);
    let rest = frame.get(4..).ok_or(IntegrityError::Truncated)?;
    if rest.len() < len_usize {
        return Err(IntegrityError::LengthMismatch);
    }
    let (chunk, proof_bytes) = rest.split_at(len_usize);
    let proof =
        decode_merkle_proof_wire(proof_bytes).map_err(|e| IntegrityError::Proof(e.to_string()))?;
    Ok((chunk.to_vec(), proof))
}

/// Decode a frame and accept it only when it opens `data_root` at `index`.
///
/// # Errors
///
/// [`IntegrityError`] on a bad frame, the wrong index, or a root mismatch.
pub fn accept_opened_chunk(
    frame: &[u8],
    index: u32,
    data_root: &[u8; 32],
) -> Result<Vec<u8>, IntegrityError> {
    let (chunk, proof) = decode_opened_chunk(frame)?;
    if proof.index != usize::try_from(index).unwrap_or(usize::MAX) {
        return Err(IntegrityError::WrongIndex {
            expected: index,
            got: proof.index,
        });
    }
    if !chunk_opens_data_root(&chunk, &proof, data_root) {
        return Err(IntegrityError::RootMismatch);
    }
    Ok(chunk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spora::{build_storage_commitment, chunk_data};
    use mfn_crypto::merkle::merkle_proof;

    #[test]
    fn honest_chunk_opens_and_a_flipped_byte_does_not() {
        let payload: Vec<u8> = (0u32..5000).map(|i| (i % 251) as u8).collect();
        let built = build_storage_commitment(&payload, 1, Some(1024), 3, None).expect("commit");
        let chunks = chunk_data(&payload, 1024).expect("chunks");
        let proof = merkle_proof(&built.tree, 1).expect("proof");
        let frame = encode_opened_chunk(chunks[1], &proof).expect("frame");
        let got = accept_opened_chunk(&frame, 1, &built.commit.data_root).expect("accept");
        assert_eq!(got, chunks[1]);

        let mut flipped = chunks[1].to_vec();
        flipped[0] ^= 0xff;
        let bad = encode_opened_chunk(&flipped, &proof).expect("bad frame");
        assert_eq!(
            accept_opened_chunk(&bad, 1, &built.commit.data_root),
            Err(IntegrityError::RootMismatch)
        );
        assert_eq!(
            accept_opened_chunk(&frame, 0, &built.commit.data_root),
            Err(IntegrityError::WrongIndex {
                expected: 0,
                got: 1
            })
        );
    }

    #[test]
    fn truncated_frame_is_rejected() {
        assert!(matches!(
            decode_opened_chunk(&[0, 0, 0, 4, 1, 2]),
            Err(IntegrityError::LengthMismatch)
        ));
        assert!(matches!(
            decode_opened_chunk(&[0, 0]),
            Err(IntegrityError::Truncated)
        ));
    }
}
