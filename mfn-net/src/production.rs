//! Post-handshake block proposal and committee vote frames (**M2.3.23**).

use std::io::Write;

use crate::frame::ChainTipV1;
use crate::frame::{read_frame, write_frame_io, FrameReadError, FrameWriteError};
use crate::gossip::{send_gossip_end_v1, P2P_GOSSIP_IO_TIMEOUT};
use crate::handshake::{tcp_connect_peer_v1_handshake_with_tip_exchange, HelloHandshakeError};

/// Post-handshake block proposal: tag `0x0c` + proposal wire bytes.
pub const PROPOSAL_V1_TAG: u8 = 0x0c;
/// Post-handshake committee vote: tag `0x0d` + vote wire bytes.
pub const VOTE_V1_TAG: u8 = 0x0d;

/// Apply inbound proposal/vote payloads (implemented in `mfn-node`).
pub trait ProductionHandler: Send + Sync {
    /// Handle a `ProposalV1` payload; return a short outcome label for stdout.
    fn on_proposal_v1(&self, proposal_wire: &[u8]) -> String;
    /// Handle a `VoteV1` payload; return a short outcome label for stdout.
    fn on_vote_v1(&self, vote_wire: &[u8]) -> String;
}

/// Send one `ProposalV1` frame.
pub fn send_proposal_v1<W: Write>(w: &mut W, proposal_wire: &[u8]) -> Result<(), FrameWriteError> {
    let mut payload = Vec::with_capacity(1 + proposal_wire.len());
    payload.push(PROPOSAL_V1_TAG);
    payload.extend_from_slice(proposal_wire);
    write_frame_io(w, &payload)?;
    w.flush()?;
    Ok(())
}

/// Send one `VoteV1` frame.
pub fn send_vote_v1<W: Write>(w: &mut W, vote_wire: &[u8]) -> Result<(), FrameWriteError> {
    let mut payload = Vec::with_capacity(1 + vote_wire.len());
    payload.push(VOTE_V1_TAG);
    payload.extend_from_slice(vote_wire);
    write_frame_io(w, &payload)?;
    w.flush()?;
    Ok(())
}

/// Failure while opening a short-lived session to push one production message.
#[derive(Debug, thiserror::Error)]
pub enum PushProductionError {
    /// Handshake failed.
    #[error("handshake: {0}")]
    Handshake(#[from] HelloHandshakeError),
    /// Framing or write failure.
    #[error("write: {0}")]
    Write(#[from] FrameWriteError),
}

fn push_production_frames_to_peer(
    peer_addr: &str,
    genesis_id: &[u8; 32],
    local_tip: &ChainTipV1,
    frames: impl IntoIterator<Item = Vec<u8>>,
) -> Result<(), PushProductionError> {
    let (mut sock, _remote) =
        tcp_connect_peer_v1_handshake_with_tip_exchange(peer_addr, genesis_id, local_tip)?;
    let _ = sock.set_read_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(P2P_GOSSIP_IO_TIMEOUT));
    for payload in frames {
        write_frame_io(&mut sock, &payload)?;
    }
    send_gossip_end_v1(&mut sock)?;
    Ok(())
}

/// Dial a peer and send one `ProposalV1` frame, then [`GossipEndV1`].
pub fn push_proposal_v1_to_peer(
    peer_addr: &str,
    genesis_id: &[u8; 32],
    local_tip: &ChainTipV1,
    proposal_wire: &[u8],
) -> Result<(), PushProductionError> {
    let mut payload = Vec::with_capacity(1 + proposal_wire.len());
    payload.push(PROPOSAL_V1_TAG);
    payload.extend_from_slice(proposal_wire);
    push_production_frames_to_peer(peer_addr, genesis_id, local_tip, [payload])
}

/// Dial a peer and send one `VoteV1` frame, then [`GossipEndV1`].
pub fn push_vote_v1_to_peer(
    peer_addr: &str,
    genesis_id: &[u8; 32],
    local_tip: &ChainTipV1,
    vote_wire: &[u8],
) -> Result<(), PushProductionError> {
    let mut payload = Vec::with_capacity(1 + vote_wire.len());
    payload.push(VOTE_V1_TAG);
    payload.extend_from_slice(vote_wire);
    push_production_frames_to_peer(peer_addr, genesis_id, local_tip, [payload])
}

/// Read one production frame payload (tag byte + body) from a stream.
pub fn read_production_payload<R: std::io::Read>(r: &mut R) -> Result<Vec<u8>, FrameReadError> {
    read_frame(r)
}
