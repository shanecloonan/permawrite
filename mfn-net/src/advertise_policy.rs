//! Which peer advertisements are safe to dial.
//!
//! A remote node can claim any listen address. Unspecified, broadcast, and
//! multicast targets are not peers; dialing them wastes slots and can be used
//! to point the node at a local broadcast domain.

use std::net::IpAddr;

use crate::peer_addr::parse_peer_host_port;

/// `Ok(())` when `addr` is a host:port this node may dial.
pub fn dialable_advertised_peer(addr: &str) -> Result<(), String> {
    let (host, _port) = parse_peer_host_port(addr)?;
    let lower = host.to_ascii_lowercase();
    if lower.ends_with(".onion") || lower.ends_with(".i2p") {
        return Ok(());
    }
    let Ok(ip) = host.parse::<IpAddr>() else {
        if host.is_empty() || host.chars().any(char::is_whitespace) {
            return Err("advertised host is empty or contains whitespace".into());
        }
        return Ok(());
    };
    if ip.is_unspecified() {
        return Err(format!("advertised address {addr} is unspecified"));
    }
    if ip.is_multicast() {
        return Err(format!("advertised address {addr} is multicast"));
    }
    if let IpAddr::V4(v4) = ip {
        if v4.is_broadcast() {
            return Err(format!("advertised address {addr} is broadcast"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unspecified_broadcast_and_multicast() {
        assert!(dialable_advertised_peer("0.0.0.0:8333").is_err());
        assert!(dialable_advertised_peer("[::]:8333").is_err());
        assert!(dialable_advertised_peer("255.255.255.255:8333").is_err());
        assert!(dialable_advertised_peer("224.0.0.1:8333").is_err());
    }

    #[test]
    fn allows_overlay_loopback_and_public() {
        assert!(dialable_advertised_peer("127.0.0.1:8333").is_ok());
        assert!(dialable_advertised_peer("203.0.113.8:8333").is_ok());
        assert!(dialable_advertised_peer(
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:8333"
        )
        .is_ok());
        assert!(dialable_advertised_peer(
            "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p:8333"
        )
        .is_ok());
    }
}
