//! P2P gossip and block/tx propagation (**M2.3 — Multi-node testnet**).
//!
//! This module is intentionally a **thin scaffold** today: it reserves the
//! `mfn_node::network` path, documents the integration boundary with
//! [`crate::Mempool`] and [`crate::Chain`], and carries **operator-tunable defaults**
//! so later commits can add transports without reshuffling crate exports.
//!
//! Non-goals for the first wire landings: consensus rule changes, fork-choice,
//! and async runtimes — those stay in `mfn-consensus` / future `runner` work.

/// Tunables for a future gossip listener + dialer (no sockets are opened yet).
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
