//! Light-wallet follow batch over P2P (**M4.13**).
//!
//! Peers can request compact header + validator-evolution rows without full blocks,
//! mirroring JSON-RPC [`get_light_follow`] for browser sync with less round-trip trust
//! in the RPC layer (fetch the same payload from multiple P2P peers in future).

use std::io::{Read, Write};

use crate::block_sync::MAX_BLOCKS_PER_GET_V1;
use crate::frame::{
    read_frame, write_frame_io, FrameReadError, FrameWriteError, MAX_FRAME_PAYLOAD_LEN,
};

/// Post-handshake light-follow pull request tag.
pub const GET_LIGHT_FOLLOW_V1_TAG: u8 = 0x0e;
/// Post-handshake light-follow response tag.
pub const LIGHT_FOLLOW_V1_TAG: u8 = 0x0f;

const GET_LIGHT_FOLLOW_V1_LEN: usize = 1 + 4 + 4;

/// Maximum rows per [`GetLightFollowV1`] (aligned with block-sync batch cap).
pub const MAX_LIGHT_FOLLOW_PER_GET_V1: u32 = MAX_BLOCKS_PER_GET_V1;

/// One block's header + evolution payloads for a light follower.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct LightFollowRow {
    /// Block height (≥ 1).
    pub height: u32,
    /// `block_id` of the header.
    pub block_id: [u8; 32],
    /// Canonical `block_header_bytes` wire.
    pub header_wire: Vec<u8>,
    /// Encoded [`SlashEvidence`] blobs.
    pub slashings: Vec<Vec<u8>>,
    /// Encoded [`BondOp`] blobs.
    pub bond_ops: Vec<Vec<u8>>,
}

/// Request inclusive header+evolution rows from `start_height`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetLightFollowV1 {
    /// First block height (≥ 1).
    pub start_height: u32,
    /// Maximum rows to return (capped at [`MAX_LIGHT_FOLLOW_PER_GET_V1`]).
    pub count: u32,
}

impl GetLightFollowV1 {
    /// Encode the on-wire payload (without the length prefix).
    pub fn encode_payload(self) -> [u8; GET_LIGHT_FOLLOW_V1_LEN] {
        let mut out = [0u8; GET_LIGHT_FOLLOW_V1_LEN];
        out[0] = GET_LIGHT_FOLLOW_V1_TAG;
        out[1..5].copy_from_slice(&self.start_height.to_be_bytes());
        out[5..9].copy_from_slice(&self.count.to_be_bytes());
        out
    }

    /// Decode a frame body from [`read_frame`].
    pub fn decode_payload(payload: &[u8]) -> Result<Self, LightFollowDecodeError> {
        if payload.len() != GET_LIGHT_FOLLOW_V1_LEN {
            return Err(LightFollowDecodeError::WrongLength {
                expected: GET_LIGHT_FOLLOW_V1_LEN,
                got: payload.len(),
            });
        }
        if payload[0] != GET_LIGHT_FOLLOW_V1_TAG {
            return Err(LightFollowDecodeError::UnknownTag(payload[0]));
        }
        let start_height = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let count = u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]);
        Ok(Self {
            start_height,
            count,
        })
    }
}

/// Response with zero or more light-follow rows.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct LightFollowV1 {
    /// Chain identity both peers must share.
    pub genesis_id: [u8; 32],
    /// Rows in ascending height order.
    pub rows: Vec<LightFollowRow>,
}

impl LightFollowV1 {
    /// Encode the on-wire payload (without the length prefix).
    pub fn encode_payload(&self) -> Result<Vec<u8>, LightFollowEncodeError> {
        let mut out = Vec::new();
        out.push(LIGHT_FOLLOW_V1_TAG);
        out.extend_from_slice(&self.genesis_id);
        let n = u32::try_from(self.rows.len())
            .map_err(|_| LightFollowEncodeError::TooManyRows(self.rows.len()))?;
        out.extend_from_slice(&n.to_be_bytes());
        for row in &self.rows {
            encode_row(&mut out, row)?;
        }
        if out.len() > MAX_FRAME_PAYLOAD_LEN as usize {
            return Err(LightFollowEncodeError::PayloadTooLarge(out.len()));
        }
        Ok(out)
    }

    /// Decode a frame body from [`read_frame`].
    pub fn decode_payload(payload: &[u8]) -> Result<Self, LightFollowDecodeError> {
        if payload.is_empty() {
            return Err(LightFollowDecodeError::Empty);
        }
        if payload[0] != LIGHT_FOLLOW_V1_TAG {
            return Err(LightFollowDecodeError::UnknownTag(payload[0]));
        }
        if payload.len() < 1 + 32 + 4 {
            return Err(LightFollowDecodeError::Truncated);
        }
        let mut genesis_id = [0u8; 32];
        genesis_id.copy_from_slice(&payload[1..33]);
        let count =
            u32::from_be_bytes([payload[33], payload[34], payload[35], payload[36]]) as usize;
        let mut off = 37;
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            let (row, next) = decode_row(&payload[off..])?;
            off += next;
            rows.push(row);
        }
        if off != payload.len() {
            return Err(LightFollowDecodeError::TrailingBytes {
                extra: payload.len() - off,
            });
        }
        Ok(Self { genesis_id, rows })
    }
}

fn encode_row(out: &mut Vec<u8>, row: &LightFollowRow) -> Result<(), LightFollowEncodeError> {
    out.extend_from_slice(&row.height.to_be_bytes());
    out.extend_from_slice(&row.block_id);
    push_len_prefixed(out, &row.header_wire)?;
    let ns = u32::try_from(row.slashings.len())
        .map_err(|_| LightFollowEncodeError::TooManySlashings(row.slashings.len()))?;
    out.extend_from_slice(&ns.to_be_bytes());
    for s in &row.slashings {
        push_len_prefixed(out, s)?;
    }
    let nb = u32::try_from(row.bond_ops.len())
        .map_err(|_| LightFollowEncodeError::TooManyBondOps(row.bond_ops.len()))?;
    out.extend_from_slice(&nb.to_be_bytes());
    for b in &row.bond_ops {
        push_len_prefixed(out, b)?;
    }
    Ok(())
}

fn decode_row(payload: &[u8]) -> Result<(LightFollowRow, usize), LightFollowDecodeError> {
    if payload.len() < 4 + 32 + 4 {
        return Err(LightFollowDecodeError::Truncated);
    }
    let height = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let mut block_id = [0u8; 32];
    block_id.copy_from_slice(&payload[4..36]);
    let mut off = 36;
    let (header_wire, n1) = read_len_prefixed(&payload[off..])?;
    off += n1;
    if off + 4 > payload.len() {
        return Err(LightFollowDecodeError::Truncated);
    }
    let n_slash = u32::from_be_bytes([
        payload[off],
        payload[off + 1],
        payload[off + 2],
        payload[off + 3],
    ]) as usize;
    off += 4;
    let mut slashings = Vec::with_capacity(n_slash);
    for _ in 0..n_slash {
        let (bytes, n) = read_len_prefixed(&payload[off..])?;
        off += n;
        slashings.push(bytes);
    }
    if off + 4 > payload.len() {
        return Err(LightFollowDecodeError::Truncated);
    }
    let n_bond = u32::from_be_bytes([
        payload[off],
        payload[off + 1],
        payload[off + 2],
        payload[off + 3],
    ]) as usize;
    off += 4;
    let mut bond_ops = Vec::with_capacity(n_bond);
    for _ in 0..n_bond {
        let (bytes, n) = read_len_prefixed(&payload[off..])?;
        off += n;
        bond_ops.push(bytes);
    }
    Ok((
        LightFollowRow {
            height,
            block_id,
            header_wire,
            slashings,
            bond_ops,
        },
        off,
    ))
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), LightFollowEncodeError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| LightFollowEncodeError::BlobTooLarge(bytes.len()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_len_prefixed(payload: &[u8]) -> Result<(Vec<u8>, usize), LightFollowDecodeError> {
    if payload.len() < 4 {
        return Err(LightFollowDecodeError::Truncated);
    }
    let len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if payload.len() < 4 + len {
        return Err(LightFollowDecodeError::Truncated);
    }
    Ok((payload[4..4 + len].to_vec(), 4 + len))
}

/// Serve [`GetLightFollowV1`] from the local block log (implemented in `mfn-node`).
pub trait LightFollowProvider: Send + Sync {
    /// Build up to `count` rows starting at `start_height`.
    fn light_follow_from_height(&self, start_height: u32, count: u32) -> LightFollowV1;
}

/// Send a [`GetLightFollowV1`] request.
pub fn send_get_light_follow_v1<W: Write>(
    w: &mut W,
    req: GetLightFollowV1,
) -> Result<(), FrameWriteError> {
    write_frame_io(w, &req.encode_payload())
}

/// Receive a [`LightFollowV1`] response.
pub fn recv_light_follow_v1<R: Read>(r: &mut R) -> Result<LightFollowV1, LightFollowRecvError> {
    let payload = read_frame(r).map_err(LightFollowRecvError::Frame)?;
    LightFollowV1::decode_payload(&payload).map_err(LightFollowRecvError::Decode)
}

/// Failed to encode a light-follow payload.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LightFollowEncodeError {
    /// Row count does not fit in `u32`.
    #[error("too many rows: {0}")]
    TooManyRows(usize),
    /// Too many slashings in one row.
    #[error("too many slashings: {0}")]
    TooManySlashings(usize),
    /// Too many bond ops in one row.
    #[error("too many bond ops: {0}")]
    TooManyBondOps(usize),
    /// A length-prefixed blob is too large.
    #[error("blob too large: {0} bytes")]
    BlobTooLarge(usize),
    /// Encoded payload exceeds [`MAX_FRAME_PAYLOAD_LEN`].
    #[error("payload too large: {0} bytes")]
    PayloadTooLarge(usize),
}

/// Failed to decode a light-follow payload.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LightFollowDecodeError {
    /// Empty payload.
    #[error("empty payload")]
    Empty,
    /// Unknown tag byte.
    #[error("unknown tag: 0x{0:02x}")]
    UnknownTag(u8),
    /// Payload ended early.
    #[error("truncated payload")]
    Truncated,
    /// Bytes remain after the structured section.
    #[error("trailing bytes: {extra}")]
    TrailingBytes {
        /// Number of unconsumed trailing bytes.
        extra: usize,
    },
    /// Wrong fixed size for [`GetLightFollowV1`].
    #[error("wrong length: expected {expected}, got {got}")]
    WrongLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
}

/// Failed to receive a [`LightFollowV1`] frame.
#[derive(Debug, thiserror::Error)]
pub enum LightFollowRecvError {
    /// Frame read failed.
    #[error("frame read: {0}")]
    Frame(#[from] FrameReadError),
    /// Decode failed.
    #[error("decode: {0}")]
    Decode(#[from] LightFollowDecodeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row(height: u32) -> LightFollowRow {
        LightFollowRow {
            height,
            block_id: [height as u8; 32],
            header_wire: vec![0xab, height as u8],
            slashings: vec![vec![1, 2]],
            bond_ops: vec![vec![3, 4, 5]],
        }
    }

    #[test]
    fn get_light_follow_round_trip() {
        let req = GetLightFollowV1 {
            start_height: 10,
            count: 3,
        };
        assert_eq!(
            GetLightFollowV1::decode_payload(&req.encode_payload()).unwrap(),
            req
        );
    }

    #[test]
    fn light_follow_v1_round_trip_two_rows() {
        let msg = LightFollowV1 {
            genesis_id: [7u8; 32],
            rows: vec![sample_row(1), sample_row(2)],
        };
        let wire = msg.encode_payload().unwrap();
        assert_eq!(LightFollowV1::decode_payload(&wire).unwrap(), msg);
    }
}
