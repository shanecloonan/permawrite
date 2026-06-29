//! Block-sync request/response over P2P (**M2.3.18**) and outbound catch-up (**M2.3.19**).
//!
//! After the Hello → Ping/Pong → Tip → Goodbye handshake, peers may exchange
//! [`GetBlocksByHeightV1`] / [`BlocksV1`] frames before or instead of the gossip
//! burst ([`crate::gossip`]).

use std::io::{Read, Write};

use crate::chunk_v1::CHUNK_V1_TAG;
use crate::frame::{
    read_frame, write_frame_io, ChainTipV1, FrameReadError, FrameWriteError, MAX_FRAME_PAYLOAD_LEN,
};
use crate::gossip::{
    recv_gossip_v1, FanoutPeerSet, GossipHandler, GossipRecvError, GossipRecvStats,
};
use crate::light_follow::{
    GetLightFollowV1, LightFollowProvider, GET_LIGHT_FOLLOW_V1_TAG, LIGHT_FOLLOW_V1_TAG,
};
use crate::production::{ProductionHandler, PROPOSAL_V1_TAG, VOTE_V1_TAG};

/// Maximum blocks returned per [`GetBlocksByHeightV1`] (defense in depth).
pub const MAX_BLOCKS_PER_GET_V1: u32 = 64;

/// Post-handshake height pull request tag.
pub const GET_BLOCKS_BY_HEIGHT_V1_TAG: u8 = 0x09;
const GET_BLOCKS_BY_HEIGHT_V1_LEN: usize = 1 + 4 + 4;

const BLOCKS_V1_TAG: u8 = 0x0a;

/// Request canonical blocks by inclusive starting height (**M2.3.18**).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetBlocksByHeightV1 {
    /// First block height to include (typically `local_tip_height + 1`).
    pub start_height: u32,
    /// Maximum number of blocks to return (capped at [`MAX_BLOCKS_PER_GET_V1`]).
    pub count: u32,
}

impl GetBlocksByHeightV1 {
    /// Encode the on-wire payload (without the length prefix).
    pub fn encode_payload(self) -> [u8; GET_BLOCKS_BY_HEIGHT_V1_LEN] {
        let mut out = [0u8; GET_BLOCKS_BY_HEIGHT_V1_LEN];
        out[0] = GET_BLOCKS_BY_HEIGHT_V1_TAG;
        out[1..5].copy_from_slice(&self.start_height.to_be_bytes());
        out[5..9].copy_from_slice(&self.count.to_be_bytes());
        out
    }

    /// Decode a frame body from [`read_frame`].
    pub fn decode_payload(payload: &[u8]) -> Result<Self, BlockSyncDecodeError> {
        if payload.len() != GET_BLOCKS_BY_HEIGHT_V1_LEN {
            return Err(BlockSyncDecodeError::WrongLength {
                expected: GET_BLOCKS_BY_HEIGHT_V1_LEN,
                got: payload.len(),
            });
        }
        if payload[0] != GET_BLOCKS_BY_HEIGHT_V1_TAG {
            return Err(BlockSyncDecodeError::UnknownTag(payload[0]));
        }
        let start_height = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let count = u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]);
        Ok(Self {
            start_height,
            count,
        })
    }
}

/// Response carrying zero or more consensus `encode_block` blobs (**M2.3.18**).
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct BlocksV1 {
    /// Canonical block wire bytes (each without the tag byte).
    pub block_wires: Vec<Vec<u8>>,
}

impl BlocksV1 {
    /// Encode the on-wire payload (without the length prefix).
    pub fn encode_payload(block_wires: &[&[u8]]) -> Result<Vec<u8>, BlockSyncEncodeError> {
        if block_wires.len() > MAX_BLOCKS_PER_GET_V1 as usize {
            return Err(BlockSyncEncodeError::TooManyBlocks(block_wires.len()));
        }
        let mut out = Vec::with_capacity(1 + 4);
        out.push(BLOCKS_V1_TAG);
        let n = u32::try_from(block_wires.len())
            .map_err(|_| BlockSyncEncodeError::TooManyBlocks(block_wires.len()))?;
        out.extend_from_slice(&n.to_be_bytes());
        for wire in block_wires {
            let len = u32::try_from(wire.len())
                .map_err(|_| BlockSyncEncodeError::BlockTooLarge(wire.len()))?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(wire);
        }
        if out.len() > MAX_FRAME_PAYLOAD_LEN as usize {
            return Err(BlockSyncEncodeError::PayloadTooLarge(out.len()));
        }
        Ok(out)
    }

    /// Decode a frame body from [`read_frame`].
    pub fn decode_payload(payload: &[u8]) -> Result<Self, BlockSyncDecodeError> {
        if payload.is_empty() {
            return Err(BlockSyncDecodeError::Empty);
        }
        if payload[0] != BLOCKS_V1_TAG {
            return Err(BlockSyncDecodeError::UnknownTag(payload[0]));
        }
        if payload.len() < 5 {
            return Err(BlockSyncDecodeError::Truncated);
        }
        let count = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
        if count > MAX_BLOCKS_PER_GET_V1 as usize {
            return Err(BlockSyncDecodeError::TooManyBlocks {
                max: MAX_BLOCKS_PER_GET_V1,
                got: count,
            });
        }
        let mut off = 5;
        let mut block_wires = Vec::with_capacity(count);
        for _ in 0..count {
            if off + 4 > payload.len() {
                return Err(BlockSyncDecodeError::Truncated);
            }
            let len = u32::from_be_bytes([
                payload[off],
                payload[off + 1],
                payload[off + 2],
                payload[off + 3],
            ]) as usize;
            off += 4;
            if off + len > payload.len() {
                return Err(BlockSyncDecodeError::Truncated);
            }
            block_wires.push(payload[off..off + len].to_vec());
            off += len;
        }
        if off != payload.len() {
            return Err(BlockSyncDecodeError::TrailingBytes {
                leftover: payload.len() - off,
            });
        }
        Ok(Self { block_wires })
    }
}

/// Serve [`GetBlocksByHeightV1`] by reading the local block log (implemented in `mfn-node`).
pub trait BlockSyncProvider: Send + Sync {
    /// Return up to `count` canonical block wire blobs with `header.height >= start_height`.
    fn blocks_from_height(&self, start_height: u32, count: u32) -> Vec<Vec<u8>>;

    /// Canonical tip for P2P handshake height exchange (reads live chain, not a cached cell).
    fn chain_tip_v1(&self) -> ChainTipV1;
}

/// Apply blocks pulled from a peer (implemented in `mfn-node`).
pub trait BlockSyncApplier: Send + Sync {
    /// Apply one canonical `encode_block` blob; returns the new chain tip height on success.
    fn apply_synced_block(&self, block_wire: &[u8]) -> Result<u32, String>;
}

/// Outcome of [`pull_blocks_to_tip`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PullBlocksStats {
    /// Local tip height before any pull.
    pub local_height_before: u32,
    /// Remote tip height advertised in handshake.
    pub remote_height: u32,
    /// Blocks successfully applied during this pull.
    pub blocks_applied: u32,
    /// Local tip height after pull (unchanged if nothing applied).
    pub local_height_after: u32,
}

/// Failed to encode a [`BlocksV1`] payload.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BlockSyncEncodeError {
    /// Block count does not fit in `u32`.
    #[error("too many blocks: {0}")]
    TooManyBlocks(usize),
    /// A single block wire exceeds `u32::MAX`.
    #[error("block wire length {0} exceeds u32::MAX")]
    BlockTooLarge(usize),
    /// Encoded payload would exceed [`MAX_FRAME_PAYLOAD_LEN`].
    #[error("blocks v1 payload length {0} exceeds max frame size")]
    PayloadTooLarge(usize),
}

/// Failed to decode a block-sync payload.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BlockSyncDecodeError {
    /// Empty payload.
    #[error("block-sync payload is empty")]
    Empty,
    /// Payload ended early.
    #[error("block-sync payload truncated")]
    Truncated,
    /// Bytes remain after parsing.
    #[error("block-sync payload has {leftover} trailing bytes")]
    TrailingBytes {
        /// Unparsed suffix length.
        leftover: usize,
    },
    /// Wrong fixed size for [`GetBlocksByHeightV1`].
    #[error("expected {expected} bytes, got {got}")]
    WrongLength {
        /// Expected length.
        expected: usize,
        /// Observed length.
        got: usize,
    },
    /// Unknown leading tag byte.
    #[error("unknown block-sync tag: 0x{0:02x}")]
    UnknownTag(u8),
    /// Too many non-[`BlocksV1`] frames before a block-sync reply.
    #[error("exceeded max interleaved frames waiting for BlocksV1")]
    TooManyInterleaved,
    /// Response advertised more blocks than one capped reply may carry.
    #[error("blocks v1 advertised {got} blocks, max {max}")]
    TooManyBlocks {
        /// Maximum legal response block count.
        max: u32,
        /// Count advertised by the peer.
        got: usize,
    },
}

/// Send a [`GetBlocksByHeightV1`] request.
pub fn send_get_blocks_by_height_v1<W: Write>(
    w: &mut W,
    req: GetBlocksByHeightV1,
) -> Result<(), FrameWriteError> {
    write_frame_io(w, &req.encode_payload())?;
    Ok(())
}

/// Max gossip/production frames to skip while waiting for a [`BlocksV1`] reply.
const MAX_INTERLEAVED_BEFORE_BLOCKS_V1: u32 = 512;

/// Read a [`BlocksV1`] response frame.
///
/// On live `--produce` sessions the peer may interleave [`PROPOSAL_V1_TAG`] /
/// [`VOTE_V1_TAG`] (and gossip) before answering [`GetBlocksByHeightV1`]; skip those
/// until a [`BLOCKS_V1_TAG`] frame arrives.
pub fn recv_blocks_v1<R: Read>(r: &mut R) -> Result<BlocksV1, BlockSyncRecvError> {
    for _ in 0..MAX_INTERLEAVED_BEFORE_BLOCKS_V1 {
        let payload = read_frame(r).map_err(BlockSyncRecvError::Frame)?;
        if payload.is_empty() {
            return Err(BlockSyncRecvError::Decode(BlockSyncDecodeError::Empty));
        }
        match payload[0] {
            BLOCKS_V1_TAG => {
                return BlocksV1::decode_payload(&payload).map_err(BlockSyncRecvError::Decode);
            }
            PROPOSAL_V1_TAG | VOTE_V1_TAG | CHUNK_V1_TAG | 0x06 | 0x07 | 0x08 | 0x0b => continue,
            tag => {
                return Err(BlockSyncRecvError::Decode(
                    BlockSyncDecodeError::UnknownTag(tag),
                ));
            }
        }
    }
    Err(BlockSyncRecvError::Decode(
        BlockSyncDecodeError::TooManyInterleaved,
    ))
}

/// Request and apply blocks until local height reaches `remote_height`.
///
/// No-op when `remote_height <= local_height`. Issues one or more
/// [`GetBlocksByHeightV1`] / [`BlocksV1`] round-trips in batches of up to
/// [`MAX_BLOCKS_PER_GET_V1`]. Every applied block must advance exactly one
/// height from the last accepted local tip; skipped or duplicate heights abort
/// the pull even if the [`BlockSyncApplier`] accepted the bytes.
pub fn pull_blocks_to_tip<S: Read + Write>(
    stream: &mut S,
    local_height: u32,
    remote_height: u32,
    applier: &dyn BlockSyncApplier,
) -> Result<PullBlocksStats, PullBlocksError> {
    let mut stats = PullBlocksStats {
        local_height_before: local_height,
        remote_height,
        blocks_applied: 0,
        local_height_after: local_height,
    };
    if remote_height <= local_height {
        return Ok(stats);
    }
    let mut cur = local_height;
    while cur < remote_height {
        let start = cur.saturating_add(1);
        let need = remote_height - cur;
        let count = need.min(MAX_BLOCKS_PER_GET_V1);
        send_get_blocks_by_height_v1(
            stream,
            GetBlocksByHeightV1 {
                start_height: start,
                count,
            },
        )?;
        let blocks = recv_blocks_v1(stream)?;
        if blocks.block_wires.is_empty() {
            return Err(PullBlocksError::NoProgress {
                requested_start: start,
                requested: count,
                local_height: cur,
                remote_height,
            });
        }
        let got = blocks.block_wires.len();
        if got > count as usize {
            return Err(PullBlocksError::TooManyResponseBlocks {
                requested: count,
                got,
            });
        }
        let prev = cur;
        for wire in &blocks.block_wires {
            let height = applier
                .apply_synced_block(wire)
                .map_err(PullBlocksError::Apply)?;
            let expected = cur.saturating_add(1);
            if height != expected {
                return Err(PullBlocksError::NonSequentialHeight {
                    expected,
                    got: height,
                });
            }
            stats.blocks_applied = stats.blocks_applied.saturating_add(1);
            cur = height;
            stats.local_height_after = height;
        }
        if cur == prev {
            break;
        }
        if cur >= remote_height {
            break;
        }
    }
    Ok(stats)
}

/// Read post-handshake frames until the peer closes or sends gossip.
///
/// Handles zero or more [`GetBlocksByHeightV1`] requests (each answered with [`BlocksV1`]),
/// then delegates to [`recv_gossip_v1`] when a gossip tag (`0x06`–`0x08`, `0x10`) arrives.
#[allow(clippy::too_many_arguments)]
pub fn serve_post_handshake_v1(
    stream: &mut std::net::TcpStream,
    peer: &str,
    sync: &dyn BlockSyncProvider,
    gossip: &dyn GossipHandler,
    fanout_peers: Option<&dyn FanoutPeerSet>,
    production: Option<&dyn ProductionHandler>,
    block_applier: Option<&dyn BlockSyncApplier>,
    light_follow: Option<&dyn LightFollowProvider>,
) -> Result<Option<GossipRecvStats>, PostHandshakeError> {
    loop {
        let payload = match read_frame(stream) {
            Ok(p) => p,
            Err(FrameReadError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };
        if payload.is_empty() {
            return Err(BlockSyncDecodeError::Empty.into());
        }
        match payload[0] {
            GET_BLOCKS_BY_HEIGHT_V1_TAG => {
                let req = GetBlocksByHeightV1::decode_payload(&payload)?;
                let capped = req.count.min(MAX_BLOCKS_PER_GET_V1);
                let wires = sync.blocks_from_height(req.start_height, capped);
                let refs: Vec<&[u8]> = wires.iter().map(Vec::as_slice).collect();
                let reply = BlocksV1::encode_payload(&refs)?;
                write_frame_io(stream, &reply).map_err(PostHandshakeError::Write)?;
                stream
                    .flush()
                    .map_err(|e| PostHandshakeError::Write(FrameWriteError::Io(e)))?;
                if let Some(ps) = fanout_peers {
                    ps.fanout_onchain_storage_chunks_to_peer(peer);
                }
            }
            GET_LIGHT_FOLLOW_V1_TAG => {
                let req = GetLightFollowV1::decode_payload(&payload)
                    .map_err(PostHandshakeError::LightFollowDecode)?;
                let provider = light_follow.ok_or(PostHandshakeError::LightFollowUnavailable)?;
                let capped = req
                    .count
                    .min(crate::light_follow::MAX_LIGHT_FOLLOW_PER_GET_V1);
                let reply = provider.light_follow_from_height(req.start_height, capped);
                let wire = reply
                    .encode_payload()
                    .map_err(PostHandshakeError::LightFollowEncode)?;
                write_frame_io(stream, &wire).map_err(PostHandshakeError::Write)?;
                stream
                    .flush()
                    .map_err(|e| PostHandshakeError::Write(FrameWriteError::Io(e)))?;
            }
            LIGHT_FOLLOW_V1_TAG => {
                // Dialer-side response; full nodes do not apply light-follow batches inbound.
            }
            BLOCKS_V1_TAG => {
                if let Some(applier) = block_applier {
                    let blocks = BlocksV1::decode_payload(&payload)?;
                    apply_unsolicited_blocks_v1(applier, &blocks)?;
                }
            }
            0x0b => {
                let addr = crate::gossip::P2pAdvertiseV1::decode_payload(&payload)
                    .map_err(|e| PostHandshakeError::Advertise(e.to_string()))?;
                if let Some(ps) = fanout_peers {
                    ps.register_peer(addr);
                    match stream.try_clone() {
                        Ok(clone) => ps.register_session(addr, clone),
                        Err(e) => eprintln!("mfnd_p2p_session_clone_abort peer={addr} {e}"),
                    }
                }
            }
            PROPOSAL_V1_TAG => {
                if let Some(h) = production {
                    let _ = h.on_proposal_v1(&payload[1..]);
                    if let Some(reply) = h.proposal_vote_reply_v1(&payload[1..]) {
                        write_frame_io(stream, &reply).map_err(PostHandshakeError::Write)?;
                        stream
                            .flush()
                            .map_err(|e| PostHandshakeError::Write(FrameWriteError::Io(e)))?;
                    }
                }
            }
            VOTE_V1_TAG => {
                if let Some(h) = production {
                    let _ = h.on_vote_v1(&payload[1..]);
                }
            }
            tag if matches!(tag, 0x06..=0x08 | CHUNK_V1_TAG) => {
                recv_gossip_v1_from_first(stream, &payload, tag, gossip)?;
                // Keep the duplex session alive for later producer fan-out (**M7.5**).
            }
            tag => return Err(PostHandshakeError::UnknownTag(tag)),
        }
    }
}

fn recv_gossip_v1_from_first<R: Read>(
    r: &mut R,
    first_payload: &[u8],
    first_tag: u8,
    handler: &dyn GossipHandler,
) -> Result<GossipRecvStats, GossipRecvError> {
    let mut stats = GossipRecvStats::default();
    let mut handle_first = |payload: &[u8]| -> Result<(), GossipRecvError> {
        match payload[0] {
            0x06 => {
                let tx = crate::frame::TxV1::decode_payload(payload)?;
                let _ = handler.on_tx_v1(tx.tx_wire());
                stats.tx_frames = stats.tx_frames.saturating_add(1);
            }
            0x07 => {
                let block = crate::frame::BlockV1::decode_payload(payload)?;
                let _ = handler.on_block_v1(block.block_wire());
                stats.block_frames = stats.block_frames.saturating_add(1);
            }
            CHUNK_V1_TAG => {
                let chunk = crate::chunk_v1::ChunkV1::decode_payload(payload)?;
                let _ =
                    handler.on_chunk_v1(&chunk.commit_hash, chunk.chunk_index, &chunk.chunk_bytes);
                stats.chunk_frames = stats.chunk_frames.saturating_add(1);
            }
            0x08 => {
                crate::frame::GossipEndV1::decode(payload)?;
                return Ok(());
            }
            tag => return Err(GossipRecvError::UnknownTag(tag)),
        }
        Ok(())
    };
    handle_first(first_payload)?;
    if first_tag == 0x08 {
        return Ok(stats);
    }
    recv_gossip_v1(r, handler)
}

/// Failure while serving the post-handshake session.
#[derive(Debug, thiserror::Error)]
pub enum PostHandshakeError {
    /// Framing or I/O while reading a frame.
    #[error("frame: {0}")]
    Frame(#[from] FrameReadError),
    /// Failed to write a reply.
    #[error("write: {0}")]
    Write(#[from] FrameWriteError),
    /// Block-sync encode/decode failure.
    #[error("block-sync: {0}")]
    BlockSyncDecode(#[from] BlockSyncDecodeError),
    /// Block-sync reply too large.
    #[error("block-sync encode: {0}")]
    BlockSyncEncode(#[from] BlockSyncEncodeError),
    /// Gossip burst failure.
    #[error("gossip: {0}")]
    Gossip(#[from] GossipRecvError),
    /// Unknown post-handshake tag.
    #[error("unknown post-handshake tag 0x{0:02x}")]
    UnknownTag(u8),
    /// Invalid [`P2pAdvertiseV1`] payload.
    #[error("p2p advertise: {0}")]
    Advertise(String),
    /// Block apply failed while handling an unprompted [`BlocksV1`].
    #[error("apply: {0}")]
    Apply(String),
    /// A post-handshake [`BlocksV1`] batch was not internally contiguous.
    #[error("non-sequential post-handshake block height: expected {expected}, got {got}")]
    NonSequentialHeight {
        /// Next height expected after the previous block in the batch.
        expected: u32,
        /// Height reported after applying the returned block.
        got: u32,
    },
    /// Light-follow decode failure.
    #[error("light-follow decode: {0}")]
    LightFollowDecode(#[from] crate::light_follow::LightFollowDecodeError),
    /// Light-follow encode failure.
    #[error("light-follow encode: {0}")]
    LightFollowEncode(#[from] crate::light_follow::LightFollowEncodeError),
    /// Peer requested light-follow but this node does not serve it.
    #[error("light-follow not available on this peer")]
    LightFollowUnavailable,
}

fn apply_unsolicited_blocks_v1(
    applier: &dyn BlockSyncApplier,
    blocks: &BlocksV1,
) -> Result<(), PostHandshakeError> {
    let mut previous_height: Option<u32> = None;
    for wire in &blocks.block_wires {
        let height = applier
            .apply_synced_block(wire)
            .map_err(PostHandshakeError::Apply)?;
        if let Some(previous) = previous_height {
            let expected = previous.saturating_add(1);
            if height != expected {
                return Err(PostHandshakeError::NonSequentialHeight {
                    expected,
                    got: height,
                });
            }
        }
        previous_height = Some(height);
    }
    Ok(())
}

/// Failure while pulling blocks from a peer.
#[derive(Debug, thiserror::Error)]
pub enum PullBlocksError {
    /// Failed to send a request frame.
    #[error("write: {0}")]
    Write(#[from] FrameWriteError),
    /// Failed to read a response frame.
    #[error("recv: {0}")]
    Recv(#[from] BlockSyncRecvError),
    /// Block application rejected the wire blob.
    #[error("apply: {0}")]
    Apply(String),
    /// The peer/applier advanced to a height other than the requested next height.
    #[error("non-sequential block height during sync: expected {expected}, got {got}")]
    NonSequentialHeight {
        /// Next height requested from the peer.
        expected: u32,
        /// Height reported after applying the returned block.
        got: u32,
    },
    /// Peer returned more blocks than requested for this round trip.
    #[error("blocks v1 response returned {got} blocks, requested {requested}")]
    TooManyResponseBlocks {
        /// Number of blocks requested in the round trip.
        requested: u32,
        /// Number of block wires returned by the peer.
        got: usize,
    },
    /// Peer advertised a higher tip but returned no blocks for the next requested height.
    #[error(
        "blocks v1 response made no progress: start={requested_start} requested={requested} local_height={local_height} remote_height={remote_height}"
    )]
    NoProgress {
        /// First height requested from the peer.
        requested_start: u32,
        /// Number of blocks requested in the round trip.
        requested: u32,
        /// Local height before this round trip.
        local_height: u32,
        /// Remote height advertised by the peer.
        remote_height: u32,
    },
}

/// Failure while receiving a [`BlocksV1`] frame.
#[derive(Debug, thiserror::Error)]
pub enum BlockSyncRecvError {
    /// Framing or I/O while reading.
    #[error("frame: {0}")]
    Frame(#[from] FrameReadError),
    /// Payload decode failure.
    #[error("decode: {0}")]
    Decode(#[from] BlockSyncDecodeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Result as IoResult, Write};

    #[derive(Default)]
    struct HeightByteApplier;

    impl BlockSyncApplier for HeightByteApplier {
        fn apply_synced_block(&self, block_wire: &[u8]) -> Result<u32, String> {
            block_wire
                .first()
                .copied()
                .map(u32::from)
                .ok_or_else(|| "empty test block".to_string())
        }
    }

    #[derive(Default)]
    struct CountingApplier(std::sync::atomic::AtomicUsize);

    impl CountingApplier {
        fn count(&self) -> usize {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl BlockSyncApplier for CountingApplier {
        fn apply_synced_block(&self, block_wire: &[u8]) -> Result<u32, String> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            block_wire
                .first()
                .copied()
                .map(u32::from)
                .ok_or_else(|| "empty test block".to_string())
        }
    }

    struct ScriptedStream {
        reads: Cursor<Vec<u8>>,
        writes: Vec<u8>,
    }

    impl ScriptedStream {
        fn new(reads: Vec<u8>) -> Self {
            Self {
                reads: Cursor::new(reads),
                writes: Vec::new(),
            }
        }
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
            self.reads.read(buf)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            self.writes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    #[test]
    fn get_blocks_by_height_v1_round_trip() {
        let req = GetBlocksByHeightV1 {
            start_height: 3,
            count: 10,
        };
        assert_eq!(
            GetBlocksByHeightV1::decode_payload(&req.encode_payload()).unwrap(),
            req
        );
    }

    #[test]
    fn blocks_v1_round_trip() {
        let wires = [vec![1u8, 2], vec![3u8; 100]];
        let refs: Vec<&[u8]> = wires.iter().map(Vec::as_slice).collect();
        let enc = BlocksV1::encode_payload(&refs).unwrap();
        let back = BlocksV1::decode_payload(&enc).unwrap();
        assert_eq!(back.block_wires, wires);
    }

    #[test]
    fn blocks_v1_encode_rejects_count_above_cap() {
        let wires = vec![&[][..]; MAX_BLOCKS_PER_GET_V1 as usize + 1];

        let err = BlocksV1::encode_payload(&wires).expect_err("oversized response must reject");

        match err {
            BlockSyncEncodeError::TooManyBlocks(got) => {
                assert_eq!(got, MAX_BLOCKS_PER_GET_V1 as usize + 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn blocks_v1_decode_rejects_advertised_count_above_cap() {
        let mut payload = Vec::new();
        payload.push(BLOCKS_V1_TAG);
        payload.extend_from_slice(&(MAX_BLOCKS_PER_GET_V1 + 1).to_be_bytes());

        let err = BlocksV1::decode_payload(&payload).expect_err("oversized count must reject");

        match err {
            BlockSyncDecodeError::TooManyBlocks { max, got } => {
                assert_eq!(max, MAX_BLOCKS_PER_GET_V1);
                assert_eq!(got, MAX_BLOCKS_PER_GET_V1 as usize + 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn recv_blocks_v1_skips_interleaved_vote() {
        use std::io::Cursor;

        use crate::production::VOTE_V1_TAG;

        let wires = [vec![9u8, 8, 7]];
        let blocks = BlocksV1::encode_payload(&[&wires[0]]).unwrap();
        let mut buf = Vec::new();
        write_frame_io(&mut buf, &[VOTE_V1_TAG, 0xAA]).unwrap();
        write_frame_io(&mut buf, &blocks).unwrap();
        let mut cursor = Cursor::new(buf);
        let back = recv_blocks_v1(&mut cursor).expect("blocks after vote");
        assert_eq!(back.block_wires, wires[..1]);
    }

    #[test]
    fn recv_blocks_v1_rejects_too_many_interleaved_frames() {
        use std::io::Cursor;

        use crate::production::VOTE_V1_TAG;

        let mut buf = Vec::new();
        for _ in 0..MAX_INTERLEAVED_BEFORE_BLOCKS_V1 {
            write_frame_io(&mut buf, &[VOTE_V1_TAG, 0xAA]).unwrap();
        }
        let mut cursor = Cursor::new(buf);
        let err = recv_blocks_v1(&mut cursor).expect_err("interleaved frame cap must abort");

        match err {
            BlockSyncRecvError::Decode(BlockSyncDecodeError::TooManyInterleaved) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn pull_blocks_to_tip_accepts_sequential_progress() {
        let reply = BlocksV1::encode_payload(&[&[1u8][..], &[2u8][..]]).unwrap();
        let mut reads = Vec::new();
        write_frame_io(&mut reads, &reply).unwrap();
        let mut stream = ScriptedStream::new(reads);

        let stats =
            pull_blocks_to_tip(&mut stream, 0, 2, &HeightByteApplier).expect("sequential sync");

        assert_eq!(stats.blocks_applied, 2);
        assert_eq!(stats.local_height_after, 2);
        assert!(!stream.writes.is_empty(), "expected GetBlocks request");
    }

    #[test]
    fn pull_blocks_to_tip_caps_get_blocks_request_count() {
        let empty_reply = BlocksV1::encode_payload(&[]).unwrap();
        let mut reads = Vec::new();
        write_frame_io(&mut reads, &empty_reply).unwrap();
        let mut stream = ScriptedStream::new(reads);

        let err = pull_blocks_to_tip(
            &mut stream,
            0,
            MAX_BLOCKS_PER_GET_V1 + 100,
            &HeightByteApplier,
        )
        .expect_err("empty reply must abort when remote advertised progress");
        let req_payload = read_frame(&mut Cursor::new(stream.writes)).expect("get blocks request");
        let req = GetBlocksByHeightV1::decode_payload(&req_payload).expect("decode request");

        assert_eq!(req.start_height, 1);
        assert_eq!(req.count, MAX_BLOCKS_PER_GET_V1);
        match err {
            PullBlocksError::NoProgress {
                requested_start,
                requested,
                local_height,
                remote_height,
            } => {
                assert_eq!(requested_start, 1);
                assert_eq!(requested, MAX_BLOCKS_PER_GET_V1);
                assert_eq!(local_height, 0);
                assert_eq!(remote_height, MAX_BLOCKS_PER_GET_V1 + 100);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn pull_blocks_to_tip_rejects_skipped_height() {
        let reply = BlocksV1::encode_payload(&[&[2u8][..]]).unwrap();
        let mut reads = Vec::new();
        write_frame_io(&mut reads, &reply).unwrap();
        let mut stream = ScriptedStream::new(reads);

        let err = pull_blocks_to_tip(&mut stream, 0, 2, &HeightByteApplier)
            .expect_err("skipped height must abort");

        match err {
            PullBlocksError::NonSequentialHeight { expected, got } => {
                assert_eq!(expected, 1);
                assert_eq!(got, 2);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn pull_blocks_to_tip_rejects_response_larger_than_request_before_apply() {
        let reply = BlocksV1::encode_payload(&[&[1u8][..], &[2u8][..]]).unwrap();
        let mut reads = Vec::new();
        write_frame_io(&mut reads, &reply).unwrap();
        let mut stream = ScriptedStream::new(reads);
        let applier = CountingApplier::default();

        let err = pull_blocks_to_tip(&mut stream, 0, 1, &applier)
            .expect_err("oversized response must abort");

        assert_eq!(applier.count(), 0, "must reject before applying extras");
        match err {
            PullBlocksError::TooManyResponseBlocks { requested, got } => {
                assert_eq!(requested, 1);
                assert_eq!(got, 2);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unsolicited_blocks_v1_accepts_contiguous_batch() {
        let blocks = BlocksV1 {
            block_wires: vec![vec![9u8], vec![10u8], vec![11u8]],
        };

        apply_unsolicited_blocks_v1(&HeightByteApplier, &blocks).expect("contiguous batch");
    }

    #[test]
    fn unsolicited_blocks_v1_rejects_skipped_batch_height() {
        let blocks = BlocksV1 {
            block_wires: vec![vec![9u8], vec![11u8]],
        };

        let err = apply_unsolicited_blocks_v1(&HeightByteApplier, &blocks)
            .expect_err("skipped post-handshake height must abort");

        match err {
            PostHandshakeError::NonSequentialHeight { expected, got } => {
                assert_eq!(expected, 10);
                assert_eq!(got, 11);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
