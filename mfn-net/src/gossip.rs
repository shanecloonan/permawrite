//! Post-handshake tx/block gossip (**M2.3.16**).
//!
//! After [`crate::handshake::exchange_goodbye_v1_as_listener`] / dialer goodbye, peers may
//! exchange [`crate::frame::TxV1`] / [`crate::frame::BlockV1`] frames until
//! [`crate::frame::GossipEndV1`]. Admission and chain apply live in `mfn-node` via [`GossipHandler`].

use std::io::{Read, Write};
use std::time::Duration;

use crate::frame::{
    read_frame, write_frame_io, BlockV1, FrameReadError, FrameWriteError, GossipEndV1,
    GossipPayloadDecodeError, TxV1,
};

/// Per-frame I/O budget while reading a gossip burst (post-goodbye).
pub const P2P_GOSSIP_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Apply gossip payloads to chain/mempool (implemented in `mfn-node`).
pub trait GossipHandler: Send + Sync {
    /// Admit or reject a transaction wire blob; return a short outcome label for stdout.
    fn on_tx_v1(&self, tx_wire: &[u8]) -> String;

    /// Apply or reject a block wire blob; return a short outcome label for stdout.
    fn on_block_v1(&self, block_wire: &[u8]) -> String;
}

/// Counts of gossip frames handled in one burst.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GossipRecvStats {
    /// Number of [`TxV1`] frames accepted for handling.
    pub tx_frames: u32,
    /// Number of [`BlockV1`] frames accepted for handling.
    pub block_frames: u32,
}

/// Failure while receiving a gossip burst.
#[derive(Debug, thiserror::Error)]
pub enum GossipRecvError {
    /// Framing or payload decode error.
    #[error("frame: {0}")]
    Frame(#[from] FrameReadError),
    /// Payload tag or shape error.
    #[error("decode: {0}")]
    Decode(#[from] GossipPayloadDecodeError),
    /// Unknown gossip tag during the burst.
    #[error("unknown gossip tag 0x{0:02x}")]
    UnknownTag(u8),
}

/// Read gossip frames until [`GossipEndV1`].
pub fn recv_gossip_v1<R: Read>(
    r: &mut R,
    handler: &dyn GossipHandler,
) -> Result<GossipRecvStats, GossipRecvError> {
    let mut stats = GossipRecvStats::default();
    loop {
        let payload = read_frame(r)?;
        if payload.is_empty() {
            return Err(GossipPayloadDecodeError::Empty.into());
        }
        match payload[0] {
            0x06 => {
                let tx = TxV1::decode_payload(&payload)?;
                let _ = handler.on_tx_v1(tx.tx_wire());
                stats.tx_frames = stats.tx_frames.saturating_add(1);
            }
            0x07 => {
                let block = BlockV1::decode_payload(&payload)?;
                let _ = handler.on_block_v1(block.block_wire());
                stats.block_frames = stats.block_frames.saturating_add(1);
            }
            0x08 => {
                GossipEndV1::decode(&payload)?;
                return Ok(stats);
            }
            tag => return Err(GossipRecvError::UnknownTag(tag)),
        }
    }
}

/// Send one [`TxV1`] frame.
pub fn send_tx_v1<W: Write>(w: &mut W, tx_wire: &[u8]) -> Result<(), FrameWriteError> {
    write_frame_io(w, &TxV1::encode_payload(tx_wire))?;
    Ok(())
}

/// Send one [`BlockV1`] frame.
pub fn send_block_v1<W: Write>(w: &mut W, block_wire: &[u8]) -> Result<(), FrameWriteError> {
    write_frame_io(w, &BlockV1::encode_payload(block_wire))?;
    Ok(())
}

/// Send [`GossipEndV1`] (empty burst terminator).
pub fn send_gossip_end_v1<W: Write>(w: &mut W) -> Result<(), FrameWriteError> {
    write_frame_io(w, &GossipEndV1.encode())?;
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct MockHandler {
        tx: std::sync::Mutex<Vec<Vec<u8>>>,
        blocks: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl MockHandler {
        fn new() -> Self {
            Self {
                tx: std::sync::Mutex::new(Vec::new()),
                blocks: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl GossipHandler for MockHandler {
        fn on_tx_v1(&self, tx_wire: &[u8]) -> String {
            self.tx.lock().unwrap().push(tx_wire.to_vec());
            "mock_ok".into()
        }

        fn on_block_v1(&self, block_wire: &[u8]) -> String {
            self.blocks.lock().unwrap().push(block_wire.to_vec());
            "mock_ok".into()
        }
    }

    #[test]
    fn recv_gossip_v1_tx_then_end() {
        let tx_wire = vec![1u8, 2, 3];
        let mut wire = Vec::new();
        send_tx_v1(&mut wire, &tx_wire).unwrap();
        send_gossip_end_v1(&mut wire).unwrap();
        let handler = MockHandler::new();
        let stats = recv_gossip_v1(&mut Cursor::new(wire), &handler).unwrap();
        assert_eq!(stats.tx_frames, 1);
        assert_eq!(stats.block_frames, 0);
        assert_eq!(handler.tx.lock().unwrap()[0], tx_wire);
    }
}
