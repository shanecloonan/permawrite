//! Post-handshake tx/block gossip (**M2.3.16**) and outbound tx push (**M2.3.20**).
//!
//! After [`crate::handshake::exchange_goodbye_v1_as_listener`] / dialer goodbye, peers may
//! exchange [`crate::frame::TxV1`] / [`crate::frame::BlockV1`] frames until
//! [`crate::frame::GossipEndV1`]. Admission and chain apply live in `mfn-node` via [`GossipHandler`].

use std::io::{Read, Write};
use std::time::Duration;

use crate::frame::{
    read_frame, write_frame_io, BlockV1, ChainTipV1, FrameReadError, FrameWriteError, GossipEndV1,
    GossipPayloadDecodeError, TxV1,
};
use crate::handshake::{tcp_connect_peer_v1_handshake_with_tip_exchange, HelloHandshakeError};

/// Per-frame I/O budget while reading a gossip burst (post-goodbye).
pub const P2P_GOSSIP_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Push a freshly admitted tx to known peers (**M2.3.20**, implemented in `mfn-node`).
pub trait FanoutPeerSet: Send + Sync {
    /// Remember a peer after a successful handshake.
    fn register_peer(&self, peer_addr: &str);
    /// Keep a duplex session for in-band proposal/vote fan-out (**M2.3.24**).
    fn register_session(&self, _peer_addr: &str, _stream: std::net::TcpStream) {}
    /// Send one proposal on a registered session; `false` if none or write failed.
    fn send_proposal_on_session(&self, _peer_addr: &str, _proposal_wire: &[u8]) -> bool {
        false
    }
    /// Send one vote on a registered session; `false` if none or write failed.
    fn send_vote_on_session(&self, _peer_addr: &str, _vote_wire: &[u8]) -> bool {
        false
    }
    /// Forward `tx_wire` to every registered peer except `except_peer`.
    fn fanout_fresh_tx(&self, tx_wire: &[u8], except_peer: Option<&str>);
}

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

const P2P_ADVERTISE_V1_TAG: u8 = 0x0b;
const P2P_ADVERTISE_ADDR_MAX_LEN: usize = 128;

/// Failure decoding [`P2pAdvertiseV1`].
#[derive(Debug, thiserror::Error)]
pub enum P2pAdvertiseDecodeError {
    /// Empty payload.
    #[error("empty advertise payload")]
    Empty,
    /// Wrong tag byte.
    #[error("unknown tag 0x{0:02x}")]
    UnknownTag(u8),
    /// Address string is not valid UTF-8.
    #[error("advertise address not utf-8")]
    NotUtf8,
    /// Address string too long.
    #[error("advertise address too long (max {P2P_ADVERTISE_ADDR_MAX_LEN})")]
    TooLong,
}

/// Dialer's P2P listener address for mempool fan-out (**M2.3.20**).
///
/// Sent once after handshake when the dialing peer also runs `--p2p-listen`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pAdvertiseV1;

impl P2pAdvertiseV1 {
    /// Encode `HOST:PORT` (without the length prefix).
    pub fn encode_payload(listen_addr: &str) -> Result<Vec<u8>, P2pAdvertiseDecodeError> {
        if listen_addr.is_empty() || listen_addr.len() > P2P_ADVERTISE_ADDR_MAX_LEN {
            return Err(P2pAdvertiseDecodeError::TooLong);
        }
        let mut out = Vec::with_capacity(1 + listen_addr.len());
        out.push(P2P_ADVERTISE_V1_TAG);
        out.extend_from_slice(listen_addr.as_bytes());
        Ok(out)
    }

    /// Decode a frame body from [`read_frame`].
    pub fn decode_payload(payload: &[u8]) -> Result<&str, P2pAdvertiseDecodeError> {
        if payload.is_empty() {
            return Err(P2pAdvertiseDecodeError::Empty);
        }
        if payload[0] != P2P_ADVERTISE_V1_TAG {
            return Err(P2pAdvertiseDecodeError::UnknownTag(payload[0]));
        }
        let addr =
            std::str::from_utf8(&payload[1..]).map_err(|_| P2pAdvertiseDecodeError::NotUtf8)?;
        if addr.is_empty() || addr.len() > P2P_ADVERTISE_ADDR_MAX_LEN {
            return Err(P2pAdvertiseDecodeError::TooLong);
        }
        Ok(addr)
    }
}

/// Send [`P2pAdvertiseV1`] so the peer can dial us for fan-out.
pub fn send_p2p_advertise_v1<W: Write>(
    w: &mut W,
    listen_addr: &str,
) -> Result<(), FrameWriteError> {
    let payload = P2pAdvertiseV1::encode_payload(listen_addr).map_err(|e| {
        FrameWriteError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            e.to_string(),
        ))
    })?;
    write_frame_io(w, &payload)?;
    w.flush()?;
    Ok(())
}

/// Send [`GossipEndV1`] (empty burst terminator).
pub fn send_gossip_end_v1<W: Write>(w: &mut W) -> Result<(), FrameWriteError> {
    write_frame_io(w, &GossipEndV1.encode())?;
    w.flush()?;
    Ok(())
}

/// Failure while opening a short-lived session to push one transaction.
#[derive(Debug, thiserror::Error)]
pub enum PushTxGossipError {
    /// Handshake failed.
    #[error("handshake: {0}")]
    Handshake(#[from] HelloHandshakeError),
    /// Framing or write failure while sending gossip frames.
    #[error("write: {0}")]
    Write(#[from] FrameWriteError),
}

/// Dial a peer, complete the full handshake, send one [`BlockV1`], then [`GossipEndV1`].
pub fn push_block_gossip_to_peer(
    peer_addr: &str,
    genesis_id: &[u8; 32],
    local_tip: &ChainTipV1,
    block_wire: &[u8],
) -> Result<(), PushTxGossipError> {
    let (mut sock, _remote) =
        tcp_connect_peer_v1_handshake_with_tip_exchange(peer_addr, genesis_id, local_tip)?;
    let _ = sock.set_read_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    send_block_v1(&mut sock, block_wire)?;
    send_gossip_end_v1(&mut sock)?;
    Ok(())
}

/// Dial a peer, complete the full handshake, send one [`TxV1`], then [`GossipEndV1`] (**M2.3.20**).
pub fn push_tx_gossip_to_peer(
    peer_addr: &str,
    genesis_id: &[u8; 32],
    local_tip: &ChainTipV1,
    tx_wire: &[u8],
) -> Result<(), PushTxGossipError> {
    let (mut sock, _remote) =
        tcp_connect_peer_v1_handshake_with_tip_exchange(peer_addr, genesis_id, local_tip)?;
    let _ = sock.set_read_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    send_tx_v1(&mut sock, tx_wire)?;
    send_gossip_end_v1(&mut sock)?;
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
