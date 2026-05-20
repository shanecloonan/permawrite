//! # `mfn-net`
//!
//! Blocking TCP P2P: length-prefixed frames, versioned handshakes, and optional
//! `mfnd serve` accept/dial loops (stdout harness lines for integration tests).
//!
//! ## Crate boundaries
//!
//! | Crate | Role |
//! |-------|------|
//! | `mfn-consensus` | Pure STF + wire formats |
//! | `mfn-runtime` | In-memory chain + mempool |
//! | `mfn-store` | Persistence |
//! | `mfn-rpc` | JSON-RPC dispatch |
//! | **`mfn-net`** | P2P framing + handshakes + serve P2P threads |
//! | `mfn-node` | RPC TCP loop + `mfnd` binary |
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]`.
//! - No async runtime in this crate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod block_sync;
pub mod frame;
pub mod gossip;
pub mod handshake;
pub mod light_follow;
pub mod production;
pub mod serve;

pub use block_sync::{
    pull_blocks_to_tip, recv_blocks_v1, send_get_blocks_by_height_v1, serve_post_handshake_v1,
    BlockSyncApplier, BlockSyncDecodeError, BlockSyncEncodeError, BlockSyncProvider,
    BlockSyncRecvError, BlocksV1, GetBlocksByHeightV1, PostHandshakeError, PullBlocksError,
    PullBlocksStats, MAX_BLOCKS_PER_GET_V1,
};
pub use frame::{
    decode_frame_prefix, encode_frame, read_frame, write_frame_io, BlockV1, ChainTipV1,
    FrameDecodeError, FrameEncodeError, FrameReadError, FrameWriteError, GoodbyeV1,
    GoodbyeV1DecodeError, GossipEndV1, GossipPayloadDecodeError, HelloDecodeError, HelloV1,
    PingPongDecodeError, PingV1, PongV1, TipV1DecodeError, TxV1, MAX_FRAME_PAYLOAD_LEN,
};
pub use gossip::{
    push_block_gossip_to_peer, push_tx_gossip_to_peer, recv_gossip_v1, send_block_v1,
    send_gossip_end_v1, send_tx_v1, FanoutPeerSet, GossipHandler, GossipRecvError, GossipRecvStats,
    PushTxGossipError, P2P_GOSSIP_IO_TIMEOUT,
};
pub use handshake::{
    exchange_chain_tip_v1_as_dialer, exchange_chain_tip_v1_as_listener,
    exchange_goodbye_v1_as_dialer, exchange_goodbye_v1_as_listener, hello_v1_handshake,
    recv_chain_tip_v1, recv_hello, recv_hello_expect, recv_ping_send_pong, send_chain_tip_v1,
    send_hello, send_ping_recv_pong, tcp_connect_hello_v1_handshake, tcp_connect_peer_v1_handshake,
    tcp_connect_peer_v1_handshake_with_tip_exchange, HelloHandshakeError, P2P_HANDSHAKE_IO_TIMEOUT,
};
pub use light_follow::{
    light_follow_rows_quorum, recv_light_follow_v1, send_get_light_follow_v1, GetLightFollowV1,
    LightFollowDecodeError, LightFollowEncodeError, LightFollowProvider, LightFollowQuorumError,
    LightFollowRecvError, LightFollowRow, LightFollowV1, GET_LIGHT_FOLLOW_V1_TAG,
    LIGHT_FOLLOW_V1_TAG, MAX_LIGHT_FOLLOW_PER_GET_V1,
};
pub use production::{
    push_proposal_v1_to_peer, push_vote_v1_to_peer, read_vote_v1_reply, send_proposal_v1,
    send_vote_v1, ProductionHandler, PushProductionError, PROPOSAL_V1_TAG, VOTE_V1_TAG,
};
pub use serve::{
    height_cmp_label, spawn_catch_up_dial, spawn_inbound_handshake_loop, spawn_outbound_dial,
    BlockSyncApplierHook, BlockSyncHook, FanoutPeerSetHook, GossipHook, HidCounter, InboundP2pLoop,
    LightFollowHook, OutboundP2pDial, P2pSessionHooks, ProductionHook, TipSnapshot,
};

/// Tunables for a future gossip listener + dialer (no sockets are opened by this struct).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkConfig {
    /// Host/port (or future multiaddr string) to bind for inbound peers.
    pub listen_addr: String,
    /// Cap on simultaneous outbound dials the node will attempt to maintain.
    pub max_outbound_peers: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".into(),
            max_outbound_peers: 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_config_default_is_loopback_unspecified_port() {
        let c = NetworkConfig::default();
        assert_eq!(c.listen_addr, "127.0.0.1:0");
        assert_eq!(c.max_outbound_peers, 8);
    }

    #[test]
    fn height_cmp_label_orders_remote_vs_local() {
        assert_eq!(height_cmp_label(0, 0), "equal");
        assert_eq!(height_cmp_label(0, 1), "ahead");
        assert_eq!(height_cmp_label(2, 1), "behind");
    }
}
