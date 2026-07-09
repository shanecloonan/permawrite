//! P2P peer dial address parsing (`HOST:PORT`, bracketed IPv6, `.onion` v3).

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// Parse a peer dial string (`127.0.0.1:8333`, `[::1]:8333`, `abc…xyz.onion:8333`).
pub fn parse_peer_host_port(peer: &str) -> Result<(String, u16), String> {
    let trimmed = peer.trim();
    if trimmed.is_empty() {
        return Err("peer address must not be empty".into());
    }
    if trimmed.starts_with('[') {
        let end = trimmed
            .find(']')
            .ok_or_else(|| format!("peer address {peer:?}: missing ']' in bracketed IPv6 form"))?;
        let host = trimmed[1..end].to_string();
        let rest = trimmed
            .get(end + 1..)
            .ok_or_else(|| format!("peer address {peer:?}: truncated after ']'"))?;
        if !rest.starts_with(':') {
            return Err(format!("peer address {peer:?}: expected :PORT after ']'"));
        }
        let port = parse_port(&rest[1..], peer)?;
        return Ok((host, port));
    }
    let (host, port_str) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| format!("peer address {peer:?}: expected HOST:PORT"))?;
    if host.is_empty() || port_str.is_empty() {
        return Err(format!(
            "peer address {peer:?}: host and port must be non-empty"
        ));
    }
    let port = parse_port(port_str, peer)?;
    Ok((host.to_string(), port))
}

fn parse_port(raw: &str, peer: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|_| format!("peer address {peer:?}: invalid port {raw:?}"))
}

/// True when `host` is a Tor v2/v3 onion service label (`.onion` suffix).
pub fn is_onion_host(host: &str) -> bool {
    host.to_ascii_lowercase().ends_with(".onion")
}

/// True when `host` is a literal IP address (not a DNS name).
pub fn is_literal_ip_host(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// Resolve a cleartext peer to socket addresses (fails for `.onion` hostnames).
pub fn resolve_cleartext_peer(peer: &str) -> std::io::Result<Vec<SocketAddr>> {
    let (host, port) = parse_peer_host_port(peer)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    if is_onion_host(&host) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "peer {peer:?}: .onion addresses require MFND_P2P_TRANSPORT=tor and a reachable SOCKS5 proxy"
            ),
        ));
    }
    let addrs: Vec<SocketAddr> = (host.as_str(), port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("peer {peer:?}: resolved to no socket addresses"),
        ));
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_peer() {
        let (host, port) = parse_peer_host_port("127.0.0.1:19998").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 19998);
    }

    #[test]
    fn parse_bracketed_ipv6_peer() {
        let (host, port) = parse_peer_host_port("[::1]:8333").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 8333);
    }

    #[test]
    fn parse_onion_v3_peer() {
        let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:8333";
        let (host, port) = parse_peer_host_port(onion).unwrap();
        assert!(is_onion_host(&host));
        assert_eq!(port, 8333);
    }

    #[test]
    fn cleartext_resolve_rejects_onion() {
        let err = resolve_cleartext_peer("foo.onion:8333").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains(".onion"));
    }
}
