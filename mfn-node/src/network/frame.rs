//! Length-prefixed binary frames for P2P (**M2.3.1**).
//!
//! Wire shape: **`[u32_be length][payload]`** where `length` counts only `payload`
//! bytes. Every frame is self-delimiting so blocking TCP `read_exact` loops can
//! recover stream boundaries without JSON or line discipline.
//!
//! [`HelloV1`] is the first structured payload: it binds a connection to an
//! expected **genesis id** (same 32-byte id [`Chain::genesis_id`](crate::Chain::genesis_id)
//! materializes from config) before any block or tx bytes are accepted.

use std::io::{Read, Write};

/// Upper bound on a single frame payload (defense in depth for RAM on small nodes).
pub const MAX_FRAME_PAYLOAD_LEN: u32 = 4 * 1024 * 1024;

const HELLO_V1_TAG: u8 = 0x01;
const HELLO_V1_LEN: usize = 1 + 32;

/// First gossip handshake: advertises which chain instance the peer expects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloV1 {
    /// Expected chain genesis id (`Chain::genesis_id()`).
    pub genesis_id: [u8; 32],
}

impl HelloV1 {
    /// Canonical on-wire size (tag + genesis id).
    pub const WIRE_LEN: usize = HELLO_V1_LEN;

    /// Encode to exactly [`HelloV1::WIRE_LEN`] bytes.
    pub fn encode(&self) -> [u8; HELLO_V1_LEN] {
        let mut out = [0u8; HELLO_V1_LEN];
        out[0] = HELLO_V1_TAG;
        out[1..].copy_from_slice(&self.genesis_id);
        out
    }

    /// Decode from a payload taken from [`decode_frame_prefix`] / [`read_frame`].
    pub fn decode(payload: &[u8]) -> Result<Self, HelloDecodeError> {
        if payload.len() != HELLO_V1_LEN {
            return Err(HelloDecodeError::WrongLength { got: payload.len() });
        }
        if payload[0] != HELLO_V1_TAG {
            return Err(HelloDecodeError::UnknownTag(payload[0]));
        }
        let mut genesis_id = [0u8; 32];
        genesis_id.copy_from_slice(&payload[1..]);
        Ok(Self { genesis_id })
    }
}

/// Failed to interpret a `HelloV1` payload.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HelloDecodeError {
    /// Payload size is not exactly [`HelloV1::WIRE_LEN`].
    #[error("hello v1 payload must be {} bytes, got {got}", HelloV1::WIRE_LEN)]
    WrongLength {
        /// Observed byte length.
        got: usize,
    },
    /// First byte is not the `HelloV1` tag.
    #[error("unknown hello tag: 0x{0:02x}")]
    UnknownTag(u8),
}

/// `encode_frame` rejected the payload size.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FrameEncodeError {
    /// Payload exceeds [`MAX_FRAME_PAYLOAD_LEN`].
    #[error("payload length {0} exceeds max {MAX_FRAME_PAYLOAD_LEN}")]
    PayloadTooLarge(usize),
}

/// Declared frame length is illegal for this implementation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FrameDecodeError {
    /// Length prefix decodes to more than [`MAX_FRAME_PAYLOAD_LEN`].
    #[error("declared payload length {0} exceeds max {MAX_FRAME_PAYLOAD_LEN}")]
    PayloadTooLarge(u32),
}

/// I/O or framing failure while reading a single frame from a stream.
#[derive(Debug, thiserror::Error)]
pub enum FrameReadError {
    /// Underlying `Read` error (includes unexpected EOF from `read_exact`).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Declared length violates [`MAX_FRAME_PAYLOAD_LEN`].
    #[error("declared payload length {0} exceeds max {MAX_FRAME_PAYLOAD_LEN}")]
    PayloadTooLarge(u32),
}

/// Encode `payload` as `u32_be len || payload`.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameEncodeError> {
    let n = payload.len();
    let n_u32 = u32::try_from(n).map_err(|_| FrameEncodeError::PayloadTooLarge(n))?;
    if n_u32 > MAX_FRAME_PAYLOAD_LEN {
        return Err(FrameEncodeError::PayloadTooLarge(n));
    }
    let mut out = Vec::with_capacity(4 + n);
    out.extend_from_slice(&n_u32.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// If `buf` begins with a full frame, return its payload slice.
/// Returns `Ok(None)` when fewer than 4 bytes are present, or when the length prefix is valid
/// but the body has not fully arrived yet.
/// Returns `Err` when the declared length exceeds [`MAX_FRAME_PAYLOAD_LEN`].
pub fn decode_frame_prefix(buf: &[u8]) -> Result<Option<&[u8]>, FrameDecodeError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if len > MAX_FRAME_PAYLOAD_LEN {
        return Err(FrameDecodeError::PayloadTooLarge(len));
    }
    let need = 4 + len as usize;
    if buf.len() < need {
        return Ok(None);
    }
    Ok(Some(&buf[4..need]))
}

/// Read one length-prefixed frame from `r` (blocking until full frame or EOF/error).
pub fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, FrameReadError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_PAYLOAD_LEN {
        return Err(FrameReadError::PayloadTooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

/// Write one frame (`u32_be len || payload`), surfacing I/O errors.
pub fn write_frame_io<W: Write>(w: &mut W, payload: &[u8]) -> Result<(), FrameWriteError> {
    let bytes = encode_frame(payload)?;
    w.write_all(&bytes)?;
    Ok(())
}

/// I/O error while writing a frame.
#[derive(Debug, thiserror::Error)]
pub enum FrameWriteError {
    /// Payload too large for a single frame.
    #[error(transparent)]
    Encode(#[from] FrameEncodeError),
    /// Underlying `Write` error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_prefix_empty_returns_none() {
        assert_eq!(decode_frame_prefix(&[]).unwrap(), None);
        assert_eq!(decode_frame_prefix(&[1, 2, 3]).unwrap(), None);
    }

    #[test]
    fn write_frame_io_read_frame_round_trip() {
        let payload = vec![0xabu8; 512];
        let mut buf = Vec::new();
        write_frame_io(&mut buf, &payload).unwrap();
        let mut cur = std::io::Cursor::new(buf);
        let got = read_frame(&mut cur).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn encode_decode_round_trip_empty() {
        let wire = encode_frame(&[]).unwrap();
        assert_eq!(wire, vec![0, 0, 0, 0]);
        assert_eq!(decode_frame_prefix(&wire).unwrap().unwrap(), &[] as &[u8]);
    }

    #[test]
    fn encode_decode_round_trip_payload() {
        let p = vec![1u8, 2, 3, 255];
        let wire = encode_frame(&p).unwrap();
        assert_eq!(decode_frame_prefix(&wire).unwrap().unwrap(), p.as_slice());
    }

    #[test]
    fn decode_prefix_incomplete_returns_none() {
        let wire = encode_frame(&[9u8; 100]).unwrap();
        assert!(decode_frame_prefix(&wire[..wire.len() - 1])
            .unwrap()
            .is_none());
    }

    #[test]
    fn decode_prefix_rejects_oversized_length() {
        let mut bad = vec![0xffu8; 4];
        bad.extend_from_slice(&[0u8; 10]);
        assert!(matches!(
            decode_frame_prefix(&bad),
            Err(FrameDecodeError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn read_frame_round_trip_cursor() {
        let payload = b"permawrite-test-payload";
        let wire = encode_frame(payload).unwrap();
        let mut cur = std::io::Cursor::new(wire);
        let out = read_frame(&mut cur).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn hello_v1_round_trip() {
        let g = [7u8; 32];
        let h = HelloV1 { genesis_id: g };
        let wire = h.encode();
        let back = HelloV1::decode(&wire).unwrap();
        assert_eq!(back, h);
        let framed = encode_frame(&wire).unwrap();
        let body = decode_frame_prefix(&framed).unwrap().unwrap();
        assert_eq!(HelloV1::decode(body).unwrap(), h);
    }

    #[test]
    fn hello_v1_decode_rejects_unknown_tag() {
        let mut bad = [0u8; 33];
        bad[0] = 0x99;
        assert!(HelloV1::decode(&bad).is_err());
    }

    #[test]
    fn hello_v1_decode_rejects_wrong_length() {
        assert!(HelloV1::decode(&[0u8; 10]).is_err());
    }
}
