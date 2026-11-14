//! Optional P2P dial transport (**B8.0**–**B8.2** / `F5:P4`).
//!
//! Default is cleartext TCP (`TcpStream::connect_timeout`). Tor dials route via SOCKS5 (**B8.1**);
//! `.onion` hidden-service peers use SOCKS5 domain connect (**B8.2**).

use crate::peer_addr::{
    is_i2p_host, is_literal_ip_host, is_onion_host, parse_peer_host_port, resolve_cleartext_peer,
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
/// Environment variable: refuse non-onion dials (`1` / `true` / `yes`).
pub const MFND_P2P_ONION_ONLY_ENV: &str = "MFND_P2P_ONION_ONLY";
/// Default local Tor SOCKS5 listen address.
pub const DEFAULT_TOR_SOCKS5: &str = "127.0.0.1:9050";
/// Environment variable: I2P SOCKS proxy (default `127.0.0.1:4447`).
pub const MFND_I2P_SOCKS5_ENV: &str = "MFND_I2P_SOCKS5";
/// Default local I2P SOCKS port (Java I2P and i2pd).
pub const DEFAULT_I2P_SOCKS5: &str = "127.0.0.1:4447";

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
    /// I2P destinations via a local SOCKS proxy. Clearnet hosts are refused.
    I2p,
}

impl P2pTransportKind {
    /// Parse `tcp` / `tor` (case-insensitive).
    pub fn parse_env(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "tcp" | "cleartext" => Ok(Self::Tcp),
            "tor" | "onion" => Ok(Self::Tor),
            "i2p" => Ok(Self::I2p),
            other => Err(format!(
                "{MFND_P2P_TRANSPORT_ENV}={other:?} must be `tcp`, `tor`, or `i2p`"
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
    /// SOCKS5 endpoint when `kind == I2p`.
    pub i2p_socks5: String,
    /// When true, outbound dials must be `.onion` (no clearnet via a Tor exit).
    pub onion_only: bool,
    /// When true, only `.onion` and `.i2p` destinations may be dialed.
    pub overlay_only: bool,
}

impl Default for P2pTransportConfig {
    fn default() -> Self {
        Self {
            kind: P2pTransportKind::Tcp,
            tor_socks5: DEFAULT_TOR_SOCKS5.into(),
            i2p_socks5: DEFAULT_I2P_SOCKS5.into(),
            onion_only: false,
            overlay_only: false,
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
        let i2p_socks5 = match std::env::var(MFND_I2P_SOCKS5_ENV) {
            Ok(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(format!("{MFND_I2P_SOCKS5_ENV} must not be empty"));
                }
                trimmed.to_string()
            }
            Err(std::env::VarError::NotPresent) => DEFAULT_I2P_SOCKS5.into(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!("{MFND_I2P_SOCKS5_ENV} must be valid UTF-8"));
            }
        };
        let onion_only = match std::env::var(MFND_P2P_ONION_ONLY_ENV) {
            Ok(raw) => {
                parse_env_flag(&raw).map_err(|e| format!("{MFND_P2P_ONION_ONLY_ENV}={e}"))?
            }
            Err(std::env::VarError::NotPresent) => false,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!("{MFND_P2P_ONION_ONLY_ENV} must be valid UTF-8"));
            }
        };
        let overlay_only = match std::env::var("MFND_P2P_OVERLAY_ONLY") {
            Ok(raw) => matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ),
            Err(std::env::VarError::NotPresent) => false,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err("MFND_P2P_OVERLAY_ONLY must be valid UTF-8".into());
            }
        };
        Ok(Self {
            kind,
            tor_socks5,
            i2p_socks5,
            onion_only,
            overlay_only,
        })
    }

    /// Address to tell a peer so it can dial us back.
    ///
    /// A published onion replaces the TCP listen address. Tor mode also refuses
    /// to hand out a non-loopback clearnet listen address.
    pub fn advertise_addr(&self, local_listen: &str, onion: Option<&str>) -> Option<String> {
        if let Some(onion) = onion.map(str::trim).filter(|s| !s.is_empty()) {
            return Some(onion.to_string());
        }
        if self.kind == P2pTransportKind::Tor && !listen_host_is_loopback(local_listen) {
            return None;
        }
        if local_listen.is_empty() {
            return None;
        }
        Some(local_listen.to_string())
    }

    /// `.onion` and `.i2p` hosts are the only destinations overlay-only mode dials.
    pub fn overlay_destination(host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        host.ends_with(".onion") || host.ends_with(".i2p")
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
            P2pTransportKind::I2p => "i2p",
        }
    }

    /// Connect to a peer dial string (`HOST:PORT`, `[IPv6]:PORT`, or `.onion:PORT`).
    pub fn connect_peer(&self, peer: &str) -> std::io::Result<TcpStream> {
        let (host, port) =
            parse_peer_host_port(peer).map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
        if self.overlay_only && !Self::overlay_destination(&host) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("peer {peer:?}: overlay-only mode refuses clearnet dials"),
            ));
        }
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
                if is_i2p_host(&host) {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "peer {peer:?}: .i2p destinations require {MFND_P2P_TRANSPORT_ENV}=i2p"
                        ),
                    ));
                }
                if self.onion_only && !is_onion_host(&host) {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("peer {peer:?}: {MFND_P2P_ONION_ONLY_ENV} refuses non-onion dials"),
                    ));
                }
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
            P2pTransportKind::I2p => {
                if !is_i2p_host(&host) {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("peer {peer:?}: I2P transport dials only .i2p destinations"),
                    ));
                }
                crate::socks5::socks5_connect_domain_with_timeout(
                    &self.i2p_socks5,
                    &host,
                    port,
                    P2P_CONNECT_TIMEOUT,
                )
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
            P2pTransportKind::I2p => Err(Error::new(
                ErrorKind::InvalidInput,
                "I2P transport has no clearnet address dial",
            )),
        }
    }
}

fn parse_env_flag(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        other => Err(format!(
            "{other:?} must be 1/0, true/false, yes/no, or on/off"
        )),
    }
}

/// True when `listen` is loopback (`127.0.0.1`, `::1`, `localhost`).
fn listen_host_is_loopback(listen: &str) -> bool {
    let host = match crate::peer_addr::parse_peer_host_port(listen) {
        Ok((host, _)) => host,
        Err(_) => listen.to_string(),
    };
    let host = host.trim_matches(['[', ']']);
    host == "localhost" || host == "::1" || host.starts_with("127.")
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
        std::env::remove_var(MFND_P2P_ONION_ONLY_ENV);
        let cfg = P2pTransportConfig::from_env().unwrap();
        assert_eq!(cfg.kind, P2pTransportKind::Tcp);
        assert_eq!(cfg.tor_socks5, DEFAULT_TOR_SOCKS5);
        assert!(!cfg.onion_only);
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
            i2p_socks5: DEFAULT_I2P_SOCKS5.into(),
            onion_only: false,
            overlay_only: false,
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
    fn tor_advertise_uses_onion_and_hides_public_ip() {
        let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:8333";
        let tor = P2pTransportConfig {
            kind: P2pTransportKind::Tor,
            tor_socks5: DEFAULT_TOR_SOCKS5.into(),
            i2p_socks5: DEFAULT_I2P_SOCKS5.into(),
            onion_only: false,
            overlay_only: false,
        };
        assert_eq!(
            tor.advertise_addr("203.0.113.8:8333", Some(onion))
                .as_deref(),
            Some(onion)
        );
        assert_eq!(tor.advertise_addr("203.0.113.8:8333", None), None);
        assert_eq!(
            tor.advertise_addr("127.0.0.1:8333", None).as_deref(),
            Some("127.0.0.1:8333")
        );
        let tcp = P2pTransportConfig::default();
        assert_eq!(
            tcp.advertise_addr("203.0.113.8:8333", None).as_deref(),
            Some("203.0.113.8:8333")
        );
    }

    #[test]
    fn onion_only_refuses_clearnet_dial() {
        let cfg = P2pTransportConfig {
            kind: P2pTransportKind::Tor,
            tor_socks5: "127.0.0.1:1".into(),
            i2p_socks5: DEFAULT_I2P_SOCKS5.into(),
            onion_only: true,
            overlay_only: false,
        };
        let err = cfg.connect_peer("203.0.113.8:8333").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains(MFND_P2P_ONION_ONLY_ENV));
        let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:8333";
        let onion_err = cfg.connect_peer(onion).unwrap_err();
        assert!(!onion_err.to_string().contains(MFND_P2P_ONION_ONLY_ENV));
    }

    #[test]
    fn i2p_transport_dials_only_through_socks_and_refuses_clearnet() {
        use std::io::{Read, Write};
        use std::sync::{Arc, Mutex};

        let seen = Arc::new(Mutex::new(String::new()));
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let seen_thread = Arc::clone(&seen);
        let proxy_thread = thread::spawn(move || {
            let (mut client, _) = proxy.accept().unwrap();
            let mut greet = [0u8; 3];
            client.read_exact(&mut greet).unwrap();
            client.write_all(&[5, 0]).unwrap();
            let mut head = [0u8; 4];
            client.read_exact(&mut head).unwrap();
            assert_eq!(head[3], 3, "I2P dial must use a domain, not an IP");
            let mut len = [0u8; 1];
            client.read_exact(&mut len).unwrap();
            let mut host = vec![0u8; len[0] as usize];
            client.read_exact(&mut host).unwrap();
            let mut port = [0u8; 2];
            client.read_exact(&mut port).unwrap();
            *seen_thread.lock().unwrap() = String::from_utf8(host).unwrap();
            client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        });
        let cfg = P2pTransportConfig {
            kind: P2pTransportKind::I2p,
            tor_socks5: DEFAULT_TOR_SOCKS5.into(),
            i2p_socks5: proxy_addr.to_string(),
            onion_only: false,
            overlay_only: false,
        };
        let dest = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p:8333";
        cfg.connect_peer(dest).unwrap();
        proxy_thread.join().unwrap();
        assert!(seen.lock().unwrap().ends_with(".b32.i2p"));
        let err = cfg.connect_peer("203.0.113.8:8333").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains(".i2p"));
    }

    #[test]
    fn overlay_only_never_connects_a_clearnet_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = P2pTransportConfig {
            kind: P2pTransportKind::Tcp,
            tor_socks5: DEFAULT_TOR_SOCKS5.into(),
            i2p_socks5: DEFAULT_I2P_SOCKS5.into(),
            onion_only: false,
            overlay_only: true,
        };
        let err = cfg.connect_peer(&addr.to_string()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(err.to_string().contains("overlay-only"));
        assert!(
            listener.accept().is_err(),
            "clearnet listener was contacted"
        );
        let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:8333";
        let onion_err = cfg.connect_peer(onion).unwrap_err();
        assert!(!onion_err.to_string().contains("overlay-only"));
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
