//! Optional P2P dial transport (**B8.0**–**B8.2** / `F5:P4`).
//!
//! Default is cleartext TCP (`TcpStream::connect_timeout`). Tor dials route via SOCKS5 (**B8.1**);
//! `.onion` hidden-service peers use SOCKS5 domain connect (**B8.2**).

use crate::peer_addr::{
    is_literal_ip_host, is_onion_host, parse_peer_host_port, resolve_cleartext_peer,
};
use std::io::{Error, ErrorKind};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::OnceLock;
use std::time::Duration;

/// TCP connect timeout for outbound P2P boot, reconnect, and catch-up dials.
pub const P2P_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Environment variable: `tcp` (default) or `tor` (stub until B8.1).
pub const MFND_P2P_TRANSPORT_ENV: &str = "MFND_P2P_TRANSPORT";
/// Environment variable: SOCKS5 proxy for Tor dials (default `127.0.0.1:9050`).
pub const MFND_TOR_SOCKS5_ENV: &str = "MFND_TOR_SOCKS5";
/// Environment variable: operator-published v3 onion P2P address (`HOST.onion:PORT`, optional).
pub const MFND_P2P_ONION_ENV: &str = "MFND_P2P_ONION";
/// Default local Tor SOCKS5 listen address.
pub const DEFAULT_TOR_SOCKS5: &str = "127.0.0.1:9050";

static ACTIVE_P2P_TRANSPORT: OnceLock<P2pTransportConfig> = OnceLock::new();

/// Install the active outbound P2P transport (call once from `mfnd serve` startup).
pub fn init_active_p2p_transport(cfg: P2pTransportConfig) -> Result<(), String> {
    ACTIVE_P2P_TRANSPORT
        .set(cfg)
        .map_err(|_| "active P2P transport already initialized".to_string())
}

/// Parse environment and install the active outbound P2P transport.
pub fn init_active_p2p_transport_from_env() -> Result<P2pTransportConfig, String> {
    let cfg = P2pTransportConfig::from_env()?;
    init_active_p2p_transport(cfg.clone())?;
    Ok(cfg)
}

/// Active outbound dial transport (defaults to cleartext TCP when unset).
pub fn active_p2p_transport() -> &'static P2pTransportConfig {
    ACTIVE_P2P_TRANSPORT.get_or_init(P2pTransportConfig::default)
}

/// Outbound P2P transport selection (no consensus impact).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P2pTransportKind {
    /// Cleartext TCP (production default).
    Tcp,
    /// Onion-routed dials via SOCKS5 (**B8.1**).
    Tor,
}

impl P2pTransportKind {
    /// Parse `tcp` / `tor` (case-insensitive).
    pub fn parse_env(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "tcp" | "cleartext" => Ok(Self::Tcp),
            "tor" | "onion" => Ok(Self::Tor),
            other => Err(format!(
                "{MFND_P2P_TRANSPORT_ENV}={other:?} must be `tcp` or `tor`"
            )),
        }
    }
}

/// Dial transport configuration parsed from environment or set explicitly in tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pTransportConfig {
    /// Selected transport kind.
    pub kind: P2pTransportKind,
    /// SOCKS5 endpoint when `kind == Tor`.
    pub tor_socks5: String,
}

impl Default for P2pTransportConfig {
    fn default() -> Self {
        Self {
            kind: P2pTransportKind::Tcp,
            tor_socks5: DEFAULT_TOR_SOCKS5.into(),
        }
    }
}

impl P2pTransportConfig {
    /// Read [`MFND_P2P_TRANSPORT_ENV`] and [`MFND_TOR_SOCKS5_ENV`].
    pub fn from_env() -> Result<Self, String> {
        let kind = match std::env::var(MFND_P2P_TRANSPORT_ENV) {
            Ok(raw) => P2pTransportKind::parse_env(&raw)?,
            Err(std::env::VarError::NotPresent) => P2pTransportKind::Tcp,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!("{MFND_P2P_TRANSPORT_ENV} must be valid UTF-8"));
            }
        };
        let tor_socks5 = match std::env::var(MFND_TOR_SOCKS5_ENV) {
            Ok(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(format!("{MFND_TOR_SOCKS5_ENV} must not be empty"));
                }
                trimmed.to_string()
            }
            Err(std::env::VarError::NotPresent) => DEFAULT_TOR_SOCKS5.into(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!("{MFND_TOR_SOCKS5_ENV} must be valid UTF-8"));
            }
        };
        Ok(Self { kind, tor_socks5 })
    }

    /// Optional operator-published onion P2P dial address from [`MFND_P2P_ONION_ENV`].
    pub fn p2p_onion_from_env() -> Result<Option<String>, String> {
        match std::env::var(MFND_P2P_ONION_ENV) {
            Ok(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(format!("{MFND_P2P_ONION_ENV} must not be empty"));
                }
                let (host, _port) = parse_peer_host_port(trimmed)?;
                if !is_onion_host(&host) {
                    return Err(format!(
                        "{MFND_P2P_ONION_ENV}={trimmed:?} must be a .onion HOST:PORT"
                    ));
                }
                Ok(Some(trimmed.to_string()))
            }
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(format!("{MFND_P2P_ONION_ENV} must be valid UTF-8"))
            }
        }
    }

    /// Log-friendly label for `mfnd_p2p_transport=…` harness lines.
    pub fn harness_label(&self) -> &'static str {
        match self.kind {
            P2pTransportKind::Tcp => "tcp",
            P2pTransportKind::Tor => "tor",
        }
    }

    /// Connect to a peer dial string (`HOST:PORT`, `[IPv6]:PORT`, or `.onion:PORT`).
    pub fn connect_peer(&self, peer: &str) -> std::io::Result<TcpStream> {
        let (host, port) =
            parse_peer_host_port(peer).map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
        match self.kind {
            P2pTransportKind::Tcp => {
                if is_onion_host(&host) {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "peer {peer:?}: cleartext TCP cannot dial .onion; set {MFND_P2P_TRANSPORT_ENV}=tor"
                        ),
                    ));
                }
                let addrs = resolve_cleartext_peer(peer)?;
                tcp_connect_with_timeout(&addrs[..], P2P_CONNECT_TIMEOUT)
            }
            P2pTransportKind::Tor => {
                if is_onion_host(&host) || !is_literal_ip_host(&host) {
                    crate::socks5::socks5_connect_domain_with_timeout(
                        &self.tor_socks5,
                        &host,
                        port,
                        P2P_CONNECT_TIMEOUT,
                    )
                } else {
                    crate::socks5::socks5_connect_with_timeout(
                        &self.tor_socks5,
                        (host.as_str(), port),
                        P2P_CONNECT_TIMEOUT,
                    )
                }
            }
        }
    }

    /// Connect to `addrs` using the configured transport.
    pub fn connect<A: ToSocketAddrs>(&self, addrs: A) -> std::io::Result<TcpStream> {
        match self.kind {
            P2pTransportKind::Tcp => tcp_connect_with_timeout(addrs, P2P_CONNECT_TIMEOUT),
            P2pTransportKind::Tor => crate::socks5::socks5_connect_with_timeout(
                &self.tor_socks5,
                addrs,
                P2P_CONNECT_TIMEOUT,
            ),
        }
    }
}

/// Cleartext TCP connect with bounded per-address attempts (shared by TCP transport and tests).
pub fn tcp_connect_with_timeout<A: ToSocketAddrs>(
    addrs: A,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    let mut last_err = None;
    for addr in addrs.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "peer address resolved to no socket addresses",
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn p2p_transport_kind_parse_env() {
        assert_eq!(
            P2pTransportKind::parse_env("tcp").unwrap(),
            P2pTransportKind::Tcp
        );
        assert_eq!(
            P2pTransportKind::parse_env("TOR").unwrap(),
            P2pTransportKind::Tor
        );
        assert!(P2pTransportKind::parse_env("quic").is_err());
    }

    #[test]
    fn p2p_transport_config_from_env_defaults_tcp() {
        std::env::remove_var(MFND_P2P_TRANSPORT_ENV);
        std::env::remove_var(MFND_TOR_SOCKS5_ENV);
        let cfg = P2pTransportConfig::from_env().unwrap();
        assert_eq!(cfg.kind, P2pTransportKind::Tcp);
        assert_eq!(cfg.tor_socks5, DEFAULT_TOR_SOCKS5);
    }

    #[test]
    fn tor_transport_rejects_onion_without_tor_mode() {
        let cfg = P2pTransportConfig::default();
        let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:8333";
        let err = cfg.connect_peer(onion).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains(".onion"));
    }

    #[test]
    fn tor_transport_without_proxy_fails_connect() {
        let cfg = P2pTransportConfig {
            kind: P2pTransportKind::Tor,
            tor_socks5: "127.0.0.1:1".into(),
        };
        assert!(cfg.connect("127.0.0.1:1").is_err());
    }

    #[test]
    fn tcp_connect_with_timeout_tries_later_resolved_addr() {
        let unused = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let live = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            drop(sock);
        });

        let sock = tcp_connect_with_timeout(&[unused, live][..], P2P_CONNECT_TIMEOUT).unwrap();
        assert_eq!(sock.peer_addr().unwrap(), live);
        drop(sock);
        server.join().unwrap();
    }

    #[test]
    fn tcp_connect_with_timeout_rejects_empty_resolution() {
        let addrs: [std::net::SocketAddr; 0] = [];
        let err = tcp_connect_with_timeout(&addrs[..], P2P_CONNECT_TIMEOUT).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("no socket addresses"));
    }

    #[test]
    fn tcp_transport_config_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            drop(sock);
        });
        let cfg = P2pTransportConfig::default();
        let sock = cfg.connect(addr).unwrap();
        drop(sock);
        server.join().unwrap();
    }
}
