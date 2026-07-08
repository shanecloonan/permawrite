//! Storage chunk gossip with Merkle inclusion proof (**B2** / PERMANENCE_HARDENING §B2).
//!
//! Wire: tag [`CHUNK_V2_TAG`] + 32-byte commitment hash + BE `chunk_index` +
//! [`encode_merkle_proof_wire`] bytes + raw chunk bytes. Receivers verify
//! `chunk_hash(chunk_bytes)` against `data_root` before inbox writes.

/// Gossip tag for a Merkle-proven storage chunk payload (**B2**).
/// Distinct from [`crate::chunk_v1::CHUNK_V1_TAG`] (`0x10`) and
/// [`crate::frame::TX_STEM_V1_TAG`] (`0x11`).
pub const CHUNK_V2_TAG: u8 = 0x12;

/// Header size: tag + commitment hash + chunk index.
pub const CHUNK_V2_HEADER_LEN: usize = 1 + 32 + 4;

/// Max chunk body bytes (same slack as [`crate::chunk_v1::MAX_CHUNK_V1_BODY_LEN`]).
pub const MAX_CHUNK_V2_BODY_LEN: usize = crate::chunk_v1::MAX_CHUNK_V1_BODY_LEN;

/// Max Merkle proof wire bytes (20 siblings × 33 bytes ≈ 660 + varints).
pub const MAX_CHUNK_V2_PROOF_WIRE_LEN: usize = 4096;

/// Decoded [`ChunkV2`] frame body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkV2 {
    /// Storage commitment hash.
    pub commit_hash: [u8; 32],
    /// Chunk index within the commitment.
    pub chunk_index: u32,
    /// Canonical Merkle proof wire (see `mfn-storage::encode_merkle_proof_wire`).
    pub merkle_proof_wire: Vec<u8>,
    /// Raw chunk bytes.
    pub chunk_bytes: Vec<u8>,
}

impl ChunkV2 {
    /// Encode for a length-prefixed P2P frame.
    pub fn encode_payload(
        commit_hash: &[u8; 32],
        chunk_index: u32,
        merkle_proof_wire: &[u8],
        chunk_bytes: &[u8],
    ) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(CHUNK_V2_HEADER_LEN + merkle_proof_wire.len() + chunk_bytes.len());
        out.push(CHUNK_V2_TAG);
        out.extend_from_slice(commit_hash);
        out.extend_from_slice(&chunk_index.to_be_bytes());
        out.extend_from_slice(merkle_proof_wire);
        out.extend_from_slice(chunk_bytes);
        out
    }

    /// Decode a frame body from [`crate::read_frame`].
    pub fn decode_payload(payload: &[u8]) -> Result<Self, ChunkV2DecodeError> {
        if payload.len() < CHUNK_V2_HEADER_LEN {
            return Err(ChunkV2DecodeError::TooShort {
                got: payload.len(),
                need: CHUNK_V2_HEADER_LEN,
            });
        }
        if payload[0] != CHUNK_V2_TAG {
            return Err(ChunkV2DecodeError::UnknownTag(payload[0]));
        }
        let mut commit_hash = [0u8; 32];
        commit_hash.copy_from_slice(&payload[1..33]);
        let chunk_index = u32::from_be_bytes(payload[33..37].try_into().map_err(|_| {
            ChunkV2DecodeError::TooShort {
                got: payload.len(),
                need: CHUNK_V2_HEADER_LEN,
            }
        })?);
        let tail = &payload[CHUNK_V2_HEADER_LEN..];
        if tail.is_empty() {
            return Err(ChunkV2DecodeError::MissingProofAndBody);
        }
        if tail.len() > MAX_CHUNK_V2_PROOF_WIRE_LEN + MAX_CHUNK_V2_BODY_LEN {
            return Err(ChunkV2DecodeError::PayloadTooLarge {
                got: tail.len(),
                max: MAX_CHUNK_V2_PROOF_WIRE_LEN + MAX_CHUNK_V2_BODY_LEN,
            });
        }
        // Proof wire is a strict prefix; the node layer parses it with
        // `mfn-storage::decode_merkle_proof_reader`. Here we only split on
        // the minimum valid proof (index varint + zero siblings) for framing.
        let proof_len = merkle_proof_wire_len(tail)?;
        let chunk_bytes = tail[proof_len..].to_vec();
        if chunk_bytes.is_empty() {
            return Err(ChunkV2DecodeError::MissingChunkBody);
        }
        if chunk_bytes.len() > MAX_CHUNK_V2_BODY_LEN {
            return Err(ChunkV2DecodeError::BodyTooLarge {
                got: chunk_bytes.len(),
                max: MAX_CHUNK_V2_BODY_LEN,
            });
        }
        Ok(Self {
            commit_hash,
            chunk_index,
            merkle_proof_wire: tail[..proof_len].to_vec(),
            chunk_bytes,
        })
    }
}

/// Parse Merkle proof wire length without full decode (framing only).
fn merkle_proof_wire_len(tail: &[u8]) -> Result<usize, ChunkV2DecodeError> {
    let mut offset = 0usize;
    read_varint(tail, &mut offset)?;
    let n = read_varint(tail, &mut offset)?;
    let n_usize = usize::try_from(n).map_err(|_| ChunkV2DecodeError::InvalidProofWire)?;
    let sibling_bytes = n_usize
        .checked_mul(33)
        .ok_or(ChunkV2DecodeError::InvalidProofWire)?;
    offset = offset
        .checked_add(sibling_bytes)
        .ok_or(ChunkV2DecodeError::InvalidProofWire)?;
    if offset > tail.len() || offset > MAX_CHUNK_V2_PROOF_WIRE_LEN {
        return Err(ChunkV2DecodeError::InvalidProofWire);
    }
    Ok(offset)
}

fn read_varint(buf: &[u8], offset: &mut usize) -> Result<u64, ChunkV2DecodeError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *offset >= buf.len() {
            return Err(ChunkV2DecodeError::InvalidProofWire);
        }
        if shift > 63 {
            return Err(ChunkV2DecodeError::InvalidProofWire);
        }
        let byte = buf[*offset];
        *offset += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

/// Failure decoding a [`ChunkV2`] payload.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ChunkV2DecodeError {
    /// Payload shorter than the fixed header.
    #[error("chunk v2 payload too short (got {got}, need {need})")]
    TooShort {
        /// Observed length.
        got: usize,
        /// Required minimum.
        need: usize,
    },
    /// Wrong tag byte.
    #[error("unknown chunk v2 tag: 0x{0:02x}")]
    UnknownTag(u8),
    /// No bytes after the fixed header.
    #[error("chunk v2 missing merkle proof and body")]
    MissingProofAndBody,
    /// Merkle proof wire could not be framed.
    #[error("chunk v2 invalid merkle proof wire")]
    InvalidProofWire,
    /// Proof parsed but no chunk body followed.
    #[error("chunk v2 missing chunk body after proof")]
    MissingChunkBody,
    /// Total tail exceeds the gossip cap.
    #[error("chunk v2 tail too large (got {got}, max {max})")]
    PayloadTooLarge {
        /// Observed tail length.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Chunk body exceeds [`MAX_CHUNK_V2_BODY_LEN`].
    #[error("chunk v2 body too large (got {got}, max {max})")]
    BodyTooLarge {
        /// Observed body length.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_v2_round_trip() {
        let hash = [0xabu8; 32];
        let proof_wire = vec![0u8, 0]; // index 0, zero siblings
        let body = vec![0xcdu8; 512];
        let wire = ChunkV2::encode_payload(&hash, 3, &proof_wire, &body);
        let decoded = ChunkV2::decode_payload(&wire).expect("decode");
        assert_eq!(decoded.commit_hash, hash);
        assert_eq!(decoded.chunk_index, 3);
        assert_eq!(decoded.merkle_proof_wire, proof_wire);
        assert_eq!(decoded.chunk_bytes, body);
    }

    #[test]
    fn chunk_v2_rejects_missing_body() {
        let hash = [0u8; 32];
        let proof_wire = vec![0u8, 0];
        let wire = ChunkV2::encode_payload(&hash, 0, &proof_wire, &[]);
        assert!(ChunkV2::decode_payload(&wire).is_err());
    }
}
