//! Storage chunk gossip frame (**M7**).
//!
//! Wire: tag `0x10` + 32-byte commitment hash + BE `chunk_index` + raw chunk bytes.

/// Gossip tag for a single storage chunk payload.
pub const CHUNK_V1_TAG: u8 = 0x10;

/// Header size: tag + commitment hash + chunk index.
pub const CHUNK_V1_HEADER_LEN: usize = 1 + 32 + 4;

/// Max chunk body bytes (256 KiB default chunk + slack for short tail chunks).
pub const MAX_CHUNK_V1_BODY_LEN: usize = (256 * 1024) + 4096;

/// Decoded [`ChunkV1`] frame body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkV1 {
    /// Storage commitment hash.
    pub commit_hash: [u8; 32],
    /// Chunk index within the commitment.
    pub chunk_index: u32,
    /// Raw chunk bytes.
    pub chunk_bytes: Vec<u8>,
}

impl ChunkV1 {
    /// Encode for a length-prefixed P2P frame.
    pub fn encode_payload(commit_hash: &[u8; 32], chunk_index: u32, chunk_bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHUNK_V1_HEADER_LEN + chunk_bytes.len());
        out.push(CHUNK_V1_TAG);
        out.extend_from_slice(commit_hash);
        out.extend_from_slice(&chunk_index.to_be_bytes());
        out.extend_from_slice(chunk_bytes);
        out
    }

    /// Decode a frame body from [`crate::read_frame`].
    pub fn decode_payload(payload: &[u8]) -> Result<Self, ChunkV1DecodeError> {
        if payload.len() < CHUNK_V1_HEADER_LEN {
            return Err(ChunkV1DecodeError::TooShort {
                got: payload.len(),
                need: CHUNK_V1_HEADER_LEN,
            });
        }
        if payload[0] != CHUNK_V1_TAG {
            return Err(ChunkV1DecodeError::UnknownTag(payload[0]));
        }
        let mut commit_hash = [0u8; 32];
        commit_hash.copy_from_slice(&payload[1..33]);
        let chunk_index = u32::from_be_bytes(payload[33..37].try_into().map_err(|_| {
            ChunkV1DecodeError::TooShort {
                got: payload.len(),
                need: CHUNK_V1_HEADER_LEN,
            }
        })?);
        let chunk_bytes = payload[37..].to_vec();
        if chunk_bytes.len() > MAX_CHUNK_V1_BODY_LEN {
            return Err(ChunkV1DecodeError::BodyTooLarge {
                got: chunk_bytes.len(),
                max: MAX_CHUNK_V1_BODY_LEN,
            });
        }
        Ok(Self {
            commit_hash,
            chunk_index,
            chunk_bytes,
        })
    }
}

/// Failure decoding a [`ChunkV1`] payload.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ChunkV1DecodeError {
    /// Payload shorter than the fixed header.
    #[error("chunk v1 payload too short (got {got}, need {need})")]
    TooShort {
        /// Observed length.
        got: usize,
        /// Required minimum.
        need: usize,
    },
    /// Wrong tag byte.
    #[error("unknown chunk v1 tag: 0x{0:02x}")]
    UnknownTag(u8),
    /// Chunk body exceeds [`MAX_CHUNK_V1_BODY_LEN`].
    #[error("chunk v1 body too large (got {got}, max {max})")]
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
    fn chunk_v1_round_trip() {
        let hash = [0xabu8; 32];
        let body = vec![0xcdu8; 1024];
        let wire = ChunkV1::encode_payload(&hash, 7, &body);
        let decoded = ChunkV1::decode_payload(&wire).expect("decode");
        assert_eq!(decoded.commit_hash, hash);
        assert_eq!(decoded.chunk_index, 7);
        assert_eq!(decoded.chunk_bytes, body);
    }

    #[test]
    fn chunk_v1_rejects_oversized_body() {
        let hash = [0u8; 32];
        let body = vec![0u8; MAX_CHUNK_V1_BODY_LEN + 1];
        let wire = ChunkV1::encode_payload(&hash, 0, &body);
        assert!(ChunkV1::decode_payload(&wire).is_err());
    }
}
