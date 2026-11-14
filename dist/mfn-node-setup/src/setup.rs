//! Render the unit, torrc, environment, and container file.

use thiserror::Error;

/// Why a plan was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SetupError {
    /// A listen or SOCKS address is not loopback.
    #[error("address must be loopback, got {0}")]
    NotLoopback(String),
    /// A peer is not a v3 onion address.
    #[error("peer is not a v3 onion: {0}")]
    NotOnion(String),
    /// A port is missing or out of range.
    #[error("bad port in {0}")]
    BadPort(String),
    /// The data directory is absolute-or-empty in a way the unit cannot use.
    #[error("data directory must be a relative state name, got {0}")]
    BadDataDir(String),
}

/// A host:port the node binds or uses as SOCKS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listen {
    /// Loopback host.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl Listen {
    /// Parse `host:port`. IPv6 loopback is `[::1]:port`.
    pub fn parse(text: &str) -> Result<Self, SetupError> {
        let (host, port) = split_host_port(text)?;
        if !is_loopback(&host) {
            return Err(SetupError::NotLoopback(text.to_string()));
        }
        Ok(Self { host, port })
    }

    /// `host:port` for a command line.
    pub fn render(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Inputs for a Tor-only observer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodePlan {
    /// systemd `StateDirectory` name. No slashes.
    pub state_dir: String,
    /// JSON-RPC bind.
    pub rpc: Listen,
    /// P2P bind, reached only by the local Tor hidden service.
    pub p2p: Listen,
    /// Tor SOCKS port on loopback.
    pub socks: Listen,
    /// v3 onion peers, each `name.onion` or `name.onion:port`.
    pub onion_peers: Vec<String>,
}

impl NodePlan {
    /// Observer defaults: RPC 18731, P2P 8333, SOCKS 9050, no peers yet.
    pub fn tor_only_observer() -> Self {
        Self {
            state_dir: "permawrite".into(),
            rpc: Listen {
                host: "127.0.0.1".into(),
                port: 18731,
            },
            p2p: Listen {
                host: "127.0.0.1".into(),
                port: 8333,
            },
            socks: Listen {
                host: "127.0.0.1".into(),
                port: 9050,
            },
            onion_peers: Vec::new(),
        }
    }
}

/// Files the operator writes to disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupFiles {
    /// `Environment=` lines and the serve command.
    pub env_file: String,
    /// systemd unit.
    pub systemd_unit: String,
    /// Tor configuration snippet.
    pub torrc: String,
    /// Container build file. It publishes no ports.
    pub containerfile: String,
    /// How to start the container without host networking.
    pub container_run: String,
}

/// Render every file, or refuse the plan.
pub fn render(plan: &NodePlan) -> Result<SetupFiles, SetupError> {
    if plan.state_dir.is_empty()
        || plan.state_dir.contains('/')
        || plan.state_dir.contains('\\')
        || plan.state_dir.contains('.')
    {
        return Err(SetupError::BadDataDir(plan.state_dir.clone()));
    }
    for addr in [&plan.rpc, &plan.p2p, &plan.socks] {
        if !is_loopback(&addr.host) || addr.port == 0 {
            return Err(SetupError::NotLoopback(addr.render()));
        }
    }
    let mut peers = Vec::new();
    for peer in &plan.onion_peers {
        peers.push(normalize_onion(peer)?);
    }
    let rpc = plan.rpc.render();
    let p2p = plan.p2p.render();
    let socks = plan.socks.render();
    let mut dials = String::new();
    for peer in &peers {
        dials.push_str(" --p2p-dial ");
        dials.push_str(peer);
    }
    let env_file = format!(
        "\
MFND_P2P_TRANSPORT=tor
MFND_P2P_OVERLAY_ONLY=1
MFND_TOR_SOCKS5={socks}
MFND_RPC_LISTEN={rpc}
MFND_P2P_LISTEN={p2p}
"
    );
    let systemd_unit = format!(
        "\
[Unit]
Description=Permawrite observer (Tor only)
After=network-online.target tor.service
Wants=tor.service

[Service]
Type=simple
User=permawrite
StateDirectory={state}
Environment=MFND_P2P_TRANSPORT=tor
Environment=MFND_P2P_OVERLAY_ONLY=1
Environment=MFND_TOR_SOCKS5={socks}
ExecStart=/usr/local/bin/mfnd serve --data-dir %S/{state} --rpc-listen {rpc} --p2p-listen {p2p}{dials}
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictSUIDSGID=true
LockPersonality=true
UMask=0077
IPAddressDeny=any
IPAddressAllow=localhost
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
",
        state = plan.state_dir,
    );
    let torrc = format!(
        "\
SocksPort {socks}
HiddenServiceDir /var/lib/tor/permawrite
HiddenServicePort {p2p_port} {p2p}
",
        p2p_port = plan.p2p.port,
    );
    let containerfile = "\
# The node talks only to Tor on localhost inside the container. No ports are published.
FROM scratch
COPY mfnd /mfnd
USER 65532:65532
ENV MFND_P2P_TRANSPORT=tor
ENV MFND_P2P_OVERLAY_ONLY=1
ENV MFND_TOR_SOCKS5=127.0.0.1:9050
ENTRYPOINT [\"/mfnd\", \"serve\", \"--rpc-listen\", \"127.0.0.1:18731\", \"--p2p-listen\", \"127.0.0.1:8333\"]
"
    .to_string();
    let container_run = "\
#!/bin/sh
# Refuses host networking. Tor must already be on 127.0.0.1:9050 in this netns.
if [ \"$1\" = \"--network=host\" ]; then
  echo \"refusing host networking\" >&2
  exit 1
fi
exec podman run --rm --network=none --read-only --user 65532:65532 --cap-drop=ALL permawrite-observer
"
    .to_string();
    let files = SetupFiles {
        env_file,
        systemd_unit,
        torrc,
        containerfile,
        container_run,
    };
    assert_no_clearnet_leak(&files)?;
    Ok(files)
}

fn assert_no_clearnet_leak(files: &SetupFiles) -> Result<(), SetupError> {
    let joined = format!(
        "{}\n{}\n{}\n{}",
        files.env_file, files.systemd_unit, files.torrc, files.containerfile
    );
    for banned in [
        "0.0.0.0",
        "EXPOSE",
        "--network=host",
        "MFND_P2P_TRANSPORT=tcp",
    ] {
        if joined.contains(banned) {
            return Err(SetupError::NotLoopback(banned.into()));
        }
    }
    if !files.systemd_unit.contains("IPAddressDeny=any")
        || !files.env_file.contains("MFND_P2P_OVERLAY_ONLY=1")
        || !files.env_file.contains("MFND_P2P_TRANSPORT=tor")
    {
        return Err(SetupError::NotLoopback("missing tor lock".into()));
    }
    Ok(())
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn split_host_port(text: &str) -> Result<(String, u16), SetupError> {
    if let Some(rest) = text.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| SetupError::BadPort(text.into()))?;
        return Ok((host.to_string(), parse_port(port, text)?));
    }
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| SetupError::BadPort(text.into()))?;
    if host.is_empty() {
        return Err(SetupError::BadPort(text.into()));
    }
    Ok((host.to_string(), parse_port(port, text)?))
}

fn parse_port(text: &str, original: &str) -> Result<u16, SetupError> {
    let port: u16 = text
        .parse()
        .map_err(|_| SetupError::BadPort(original.into()))?;
    if port == 0 {
        return Err(SetupError::BadPort(original.into()));
    }
    Ok(port)
}

fn normalize_onion(peer: &str) -> Result<String, SetupError> {
    let (host, port) = if let Some((host, port)) = peer.rsplit_once(':') {
        if host.ends_with(".onion") {
            (host, Some(parse_port(port, peer)?))
        } else {
            (peer, None)
        }
    } else {
        (peer, None)
    };
    let name = host
        .strip_suffix(".onion")
        .ok_or_else(|| SetupError::NotOnion(peer.into()))?;
    if name.len() != 56 || !name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return Err(SetupError::NotOnion(peer.into()));
    }
    let port = port.unwrap_or(8333);
    Ok(format!("{name}.onion:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_observer_locks_tor_and_localhost() {
        let files = render(&NodePlan::tor_only_observer()).unwrap();
        assert!(files.env_file.contains("MFND_P2P_TRANSPORT=tor"));
        assert!(files.env_file.contains("MFND_P2P_OVERLAY_ONLY=1"));
        assert!(files.env_file.contains("MFND_TOR_SOCKS5=127.0.0.1:9050"));
        assert!(files.systemd_unit.contains("IPAddressDeny=any"));
        assert!(files.systemd_unit.contains("IPAddressAllow=localhost"));
        assert!(files.systemd_unit.contains("--rpc-listen 127.0.0.1:18731"));
        assert!(files.systemd_unit.contains("--p2p-listen 127.0.0.1:8333"));
        assert!(files.torrc.contains("SocksPort 127.0.0.1:9050"));
        assert!(files
            .torrc
            .contains("HiddenServicePort 8333 127.0.0.1:8333"));
        assert!(!files
            .containerfile
            .lines()
            .any(|line| line.starts_with("EXPOSE")));
        assert!(files.container_run.contains("--network=none"));
        assert!(files.container_run.contains("refusing host networking"));
        let script = include_str!("../../../scripts/setup-node.sh");
        assert!(script.contains("MFND_P2P_OVERLAY_ONLY=1"));
        assert!(script.contains("IPAddressDeny=any"));
    }

    #[test]
    fn public_bind_and_clearnet_peer_are_refused() {
        let mut plan = NodePlan::tor_only_observer();
        plan.rpc = Listen {
            host: "0.0.0.0".into(),
            port: 18731,
        };
        assert!(matches!(render(&plan), Err(SetupError::NotLoopback(_))));
        let mut plan = NodePlan::tor_only_observer();
        plan.socks = Listen {
            host: "8.8.8.8".into(),
            port: 9050,
        };
        assert!(matches!(render(&plan), Err(SetupError::NotLoopback(_))));
        assert!(matches!(
            Listen::parse("1.2.3.4:9050"),
            Err(SetupError::NotLoopback(_))
        ));
        let mut plan = NodePlan::tor_only_observer();
        plan.onion_peers.push("203.0.113.5:8333".into());
        assert!(matches!(render(&plan), Err(SetupError::NotOnion(_))));
        plan.onion_peers = vec!["not-an-onion.example:8333".into()];
        assert!(matches!(render(&plan), Err(SetupError::NotOnion(_))));
    }

    #[test]
    fn v3_onion_peer_is_dialed_and_ipv6_loopback_is_accepted() {
        let onion = format!("{}.onion:8333", "a".repeat(56).replace('a', "b"));
        // 56 b's is valid base32 (b is in a-z).
        assert_eq!(
            onion
                .trim_end_matches(":8333")
                .trim_end_matches(".onion")
                .len(),
            56
        );
        let mut plan = NodePlan::tor_only_observer();
        plan.rpc = Listen::parse("[::1]:18731").unwrap();
        plan.onion_peers.push(onion.clone());
        let files = render(&plan).unwrap();
        assert!(files.systemd_unit.contains(&format!("--p2p-dial {onion}")));
        assert!(files.systemd_unit.contains("--rpc-listen [::1]:18731"));
    }
}
