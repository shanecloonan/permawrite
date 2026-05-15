//! P2P gossip and block/tx propagation (**M2.3 — Multi-node testnet**).
//!
//! **M2.3.0** reserved this module path and [`NetworkConfig`]. **M2.3.1** adds
//! [`frame`]: length-prefixed binary frames plus a minimal [`frame::HelloV1`]
//! payload. **M2.3.2** adds [`handshake`]: send/recv that payload over `Read` /
//! `Write` (including symmetric [`hello_v1_handshake`] on a TCP stream). **M2.3.4** adds
//! [`handshake::tcp_connect_hello_v1_handshake`] for outbound dials. **M2.3.5** adds [`PingV1`] /
//! [`PongV1`] and [`tcp_connect_peer_v1_handshake`] (hello + dialer ping / listener pong).
//!
//! Integration with [`crate::Mempool`] / [`crate::Chain`] lands in later M2.3.x
//! milestones (full gossip, admission, fork choice). **M2.3.3** wires an optional P2P listen into
//! `mfnd serve` (`--p2p-listen`; accepts hello then ping/pong **M2.3.5**). No async runtime in [`network`] itself.

pub mod frame;
pub mod handshake;

pub use frame::{
    decode_frame_prefix, encode_frame, read_frame, write_frame_io, FrameDecodeError,
    FrameEncodeError, FrameReadError, FrameWriteError, HelloDecodeError, HelloV1,
    PingPongDecodeError, PingV1, PongV1, MAX_FRAME_PAYLOAD_LEN,
};
pub use handshake::{
    hello_v1_handshake, recv_hello, recv_hello_expect, recv_ping_send_pong, send_hello,
    send_ping_recv_pong, tcp_connect_hello_v1_handshake, tcp_connect_peer_v1_handshake,
    HelloHandshakeError,
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
}
