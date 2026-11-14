//! Decide whether JSON-RPC should go through Tor.
//!
//! An `.onion` address without Tor is a refusal. A clearnet address uses Tor
//! when a local SOCKS port is open, unless the caller passed `--no-tor`.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// How the caller asked for Tor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorRequest {
    /// Use Tor when a SOCKS port is open, and require it for `.onion`.
    Auto,
    /// Always use Tor.
    On,
    /// Never use Tor. Illegal for an `.onion` address.
    Off,
}

/// Why Tor could not be chosen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TorError {
    /// Hidden service with Tor turned off or unavailable.
    #[error(
        "{addr} is a .onion address. Refusing to dial it in the clear. Start Tor on 127.0.0.1:9050 or pass --tor."
    )]
    OnionWithoutTor {
        /// The address that was refused.
        addr: String,
    },
}

/// True when `addr` accepts a TCP connection within `timeout`.
pub fn tcp_port_open(addr: &str, timeout: Duration) -> bool {
    let Ok(socket) = addr.parse::<SocketAddr>() else {
        return false;
    };
    TcpStream::connect_timeout(&socket, timeout).is_ok()
}

/// `true` when the RPC client should use SOCKS.
pub fn decide_tor(addr: &str, socks_open: bool, request: TorRequest) -> Result<bool, TorError> {
    let onion = addr.to_ascii_lowercase().contains(".onion");
    match request {
        TorRequest::On => Ok(true),
        TorRequest::Off if onion => Err(TorError::OnionWithoutTor {
            addr: addr.to_string(),
        }),
        TorRequest::Off => Ok(false),
        TorRequest::Auto if onion && !socks_open => Err(TorError::OnionWithoutTor {
            addr: addr.to_string(),
        }),
        TorRequest::Auto => Ok(socks_open),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clearnet_uses_tor_only_when_socks_is_open() {
        assert!(!decide_tor("127.0.0.1:18731", false, TorRequest::Auto).unwrap());
        assert!(decide_tor("127.0.0.1:18731", true, TorRequest::Auto).unwrap());
        assert!(!decide_tor("127.0.0.1:18731", true, TorRequest::Off).unwrap());
    }

    #[test]
    fn onion_is_refused_without_tor() {
        let err = decide_tor("abc.onion:18731", false, TorRequest::Auto).unwrap_err();
        assert!(err.to_string().contains("Refusing"));
        let err = decide_tor("abc.onion:18731", true, TorRequest::Off).unwrap_err();
        assert!(err.to_string().contains(".onion"));
        assert!(decide_tor("abc.onion:18731", true, TorRequest::Auto).unwrap());
        assert!(decide_tor("abc.onion:18731", false, TorRequest::On).unwrap());
    }
}
