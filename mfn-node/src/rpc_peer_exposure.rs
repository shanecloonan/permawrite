//! What a JSON-RPC caller is allowed to learn about this node's peers.
//!
//! Loopback RPC is the operator console and keeps addresses. A public bind
//! keeps overlay addresses (`.onion`, `.i2p`) and drops clearnet host:port
//! values, which are other people's IP addresses.

/// Filter `peers` for an RPC response.
///
/// `public_bind` is true when the RPC listener is not loopback.
#[must_use]
pub fn peers_visible_on_rpc(peers: Vec<String>, public_bind: bool) -> Vec<String> {
    if !public_bind {
        return peers;
    }
    peers
        .into_iter()
        .filter(|peer| overlay_peer(peer))
        .collect()
}

/// Whether `get_status` may include this node's P2P listen address.
#[must_use]
pub fn p2p_listen_visible_on_rpc(public_bind: bool) -> bool {
    !public_bind
}

fn overlay_peer(peer: &str) -> bool {
    let host = peer.rsplit_once(':').map(|(host, _)| host).unwrap_or(peer);
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    host.ends_with(".onion") || host.ends_with(".i2p")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_rpc_keeps_clearnet_peers() {
        let peers = vec!["203.0.113.4:8333".into(), "abc.onion:8333".into()];
        assert_eq!(peers_visible_on_rpc(peers.clone(), false), peers);
    }

    #[test]
    fn public_rpc_keeps_only_overlay_peers() {
        let peers = vec![
            "203.0.113.4:8333".into(),
            "abc.onion:8333".into(),
            "zzzz.b32.i2p:8333".into(),
            "[2001:db8::1]:8333".into(),
        ];
        assert_eq!(
            peers_visible_on_rpc(peers, true),
            vec![
                "abc.onion:8333".to_string(),
                "zzzz.b32.i2p:8333".to_string()
            ]
        );
    }

    #[test]
    fn public_rpc_hides_p2p_listen() {
        assert!(!p2p_listen_visible_on_rpc(true));
        assert!(p2p_listen_visible_on_rpc(false));
    }
}
