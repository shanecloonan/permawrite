//! Tor-only node setup.
//!
//! The generated systemd unit lets `mfnd` talk only to localhost, where Tor's
//! SOCKS port lives. Clearnet seeds are skipped. The unit does not publish
//! RPC. An explicit clearnet mode exists and is never the default.
//!
//! Nothing here changes consensus or dials the network.

/// Loopback RPC. Never a wildcard.
pub const RPC_LISTEN: &str = "127.0.0.1:18734";

/// Loopback P2P. Tor forwards a hidden service to this port.
pub const P2P_LISTEN: &str = "127.0.0.1:8333";

/// Tor SOCKS on the same machine.
pub const TOR_SOCKS: &str = "127.0.0.1:9050";

/// Files the generator writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeLayout {
    /// systemd unit for mfnd.
    pub systemd: String,
    /// torrc drop-in.
    pub torrc: String,
    /// Container build file. Publishes no host ports.
    pub containerfile: String,
    /// Process supervisor used inside the container.
    pub entrypoint: String,
    /// `podman run` / `docker run` line with no published ports.
    pub run_sh: String,
}

/// How the node may dial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialMode {
    /// SOCKS only. The process is confined to localhost.
    TorOnly {
        /// Optional `name.onion:port` seed, already validated.
        onion: Option<String>,
    },
    /// Explicit opt-in. Not the default. The localhost lock is not applied.
    Clearnet {
        /// `host:port` the operator typed.
        seed: String,
    },
}

/// Why a setup was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum SetupError {
    /// Onion or seed text was not acceptable.
    BadDial,
    /// Rendered config would leak or bind a wildcard.
    Leak(&'static str),
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadDial => write!(
                f,
                "dial must be a v3 onion host:port, or an explicit clearnet seed"
            ),
            Self::Leak(what) => write!(f, "refusing leaky config: {what}"),
        }
    }
}

impl std::error::Error for SetupError {}

/// A v3 onion dial string: 56 lowercase base32 chars, `.onion`, colon, port.
pub fn parse_onion_dial(text: &str) -> Result<String, SetupError> {
    let Some((host, port)) = text.rsplit_once(':') else {
        return Err(SetupError::BadDial);
    };
    let Some(name) = host.strip_suffix(".onion") else {
        return Err(SetupError::BadDial);
    };
    if name.len() != 56 || !name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return Err(SetupError::BadDial);
    }
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) || port.len() > 5 {
        return Err(SetupError::BadDial);
    }
    let port_n: u16 = port.parse().map_err(|_| SetupError::BadDial)?;
    if port_n == 0 {
        return Err(SetupError::BadDial);
    }
    Ok(format!("{name}.onion:{port_n}"))
}

fn quote_arg(text: &str) -> Result<String, SetupError> {
    if text.is_empty()
        || text
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':')))
    {
        return Err(SetupError::BadDial);
    }
    Ok(text.to_string())
}

/// Render every file. Refuses a wildcard bind and a clearnet address in Tor-only mode.
pub fn render(data_dir: &str, genesis: &str, mode: &DialMode) -> Result<NodeLayout, SetupError> {
    let data_dir = quote_arg(data_dir)?;
    let genesis = quote_arg(genesis)?;
    let (lock, dial, banner) = match mode {
        DialMode::TorOnly { onion } => {
            let dial = match onion {
                Some(onion) => {
                    let onion = parse_onion_dial(onion)?;
                    format!(" --p2p-dial {onion}")
                }
                None => String::new(),
            };
            (
                true,
                dial,
                "tor-only: mfnd may open sockets to localhost and nowhere else",
            )
        }
        DialMode::Clearnet { seed } => {
            let seed = quote_arg(seed)?;
            if seed.contains(".onion") {
                return Err(SetupError::BadDial);
            }
            (
                false,
                format!(" --p2p-dial {seed}"),
                "CLEARNET OPT-IN: this unit is allowed to dial the public internet",
            )
        }
    };
    let ip_lock = if lock {
        "IPAddressDeny=any\nIPAddressAllow=localhost\n"
    } else {
        ""
    };
    let transport = if lock {
        format!("Environment=MFND_P2P_TRANSPORT=tor\nEnvironment=MFND_TOR_SOCKS5={TOR_SOCKS}\nEnvironment=MFND_SKIP_MANIFEST_SEEDS=1\n")
    } else {
        "Environment=MFND_P2P_TRANSPORT=clearnet\n".to_string()
    };
    let systemd = format!(
        "# {banner}\n\
         [Unit]\n\
         Description=Permawrite node\n\
         After=network-online.target tor.service\n\
         Wants=tor.service\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=permawrite\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         ReadWritePaths={data_dir}\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\
         {ip_lock}\
         {transport}\
         ExecStart=/usr/local/bin/mfnd --data-dir {data_dir} --genesis {genesis} --store fs --rpc-listen {RPC_LISTEN} --p2p-listen {P2P_LISTEN}{dial} serve\n\
         Restart=on-failure\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    let torrc = "\
SocksPort 127.0.0.1:9050
SocksPolicy accept 127.0.0.1
SocksPolicy accept6 [::1]
SocksPolicy reject *
SafeLogging 1
Log notice stderr
DisableDebuggerAttachment 1
HiddenServiceDir /var/lib/tor/permawrite
HiddenServicePort 8333 127.0.0.1:8333
"
    .to_string();
    let containerfile = "\
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends tor ca-certificates adduser \\
    && rm -rf /var/lib/apt/lists/* \\
    && adduser --disabled-password --gecos '' permawrite
COPY mfnd /usr/local/bin/mfnd
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
USER permawrite
WORKDIR /var/lib/permawrite
ENTRYPOINT [\"/usr/local/bin/entrypoint.sh\"]
"
    .to_string();
    let entrypoint = entrypoint_script(lock);
    let run_sh = "\
#!/bin/sh
# No published ports. RPC and P2P stay on loopback inside the container.
exec podman run --rm --name permawrite-node \\
  --cap-drop=ALL \\
  --security-opt=no-new-privileges \\
  --read-only \\
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \\
  -v permawrite-data:/var/lib/permawrite:Z \\
  permawrite-node
"
    .to_string();
    let layout = NodeLayout {
        systemd,
        torrc,
        containerfile,
        entrypoint,
        run_sh,
    };
    audit(&layout, lock)?;
    Ok(layout)
}

fn entrypoint_script(tor_only: bool) -> String {
    let guard = if tor_only {
        "\
if [ \"${MFND_P2P_TRANSPORT:-tor}\" != tor ]; then
  echo 'refusing to start: transport is not tor' >&2
  exit 1
fi
"
    } else {
        "echo 'clearnet opt-in' >&2\n"
    };
    format!(
        "#!/bin/sh\nset -eu\n{guard}exec /usr/local/bin/mfnd --data-dir /var/lib/permawrite --genesis /var/lib/permawrite/genesis.json --store fs --rpc-listen {RPC_LISTEN} --p2p-listen {P2P_LISTEN} serve\n"
    )
}

/// Fail if a Tor-only layout binds a wildcard, names a public seed, or drops the lock.
pub fn audit(layout: &NodeLayout, tor_only: bool) -> Result<(), SetupError> {
    let all = format!(
        "{}\n{}\n{}\n{}\n{}",
        layout.systemd, layout.torrc, layout.containerfile, layout.entrypoint, layout.run_sh
    );
    if all.contains("0.0.0.0") {
        return Err(SetupError::Leak("wildcard 0.0.0.0"));
    }
    if all.contains("5.161.201.73") {
        return Err(SetupError::Leak("public testnet seed"));
    }
    if layout.containerfile.contains("EXPOSE")
        || layout.run_sh.contains("--publish")
        || layout.run_sh.contains("-p ")
    {
        return Err(SetupError::Leak("published port"));
    }
    if !layout.torrc.contains("SafeLogging 1") || !layout.torrc.contains("SocksPolicy reject *") {
        return Err(SetupError::Leak("tor logging or socks policy"));
    }
    if tor_only {
        for needle in [
            "MFND_P2P_TRANSPORT=tor",
            "MFND_SKIP_MANIFEST_SEEDS=1",
            "IPAddressDeny=any",
            "IPAddressAllow=localhost",
            &format!("--rpc-listen {RPC_LISTEN}"),
            &format!("--p2p-listen {P2P_LISTEN}"),
        ] {
            if !layout.systemd.contains(needle) {
                return Err(SetupError::Leak("missing tor lock"));
            }
        }
        if layout.systemd.contains("MFND_P2P_TRANSPORT=clearnet") {
            return Err(SetupError::Leak("clearnet transport"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:8333";

    #[test]
    fn default_layout_is_tor_only_and_stable() {
        let a = render(
            "/var/lib/permawrite",
            "/var/lib/permawrite/genesis.json",
            &DialMode::TorOnly { onion: None },
        )
        .unwrap();
        let b = render(
            "/var/lib/permawrite",
            "/var/lib/permawrite/genesis.json",
            &DialMode::TorOnly { onion: None },
        )
        .unwrap();
        assert_eq!(a, b);
        assert!(a.systemd.contains("IPAddressDeny=any"));
        assert!(a.systemd.contains("MFND_SKIP_MANIFEST_SEEDS=1"));
        assert!(!a.systemd.contains("clearnet"));
        assert!(!a.run_sh.contains("--publish"));
        assert!(!a.containerfile.contains("EXPOSE"));
        assert!(audit(&a, true).is_ok());
    }

    #[test]
    fn onion_seed_is_accepted_and_garbage_is_not() {
        let ok = render(
            "/var/lib/permawrite",
            "/var/lib/permawrite/genesis.json",
            &DialMode::TorOnly {
                onion: Some(ONION.to_string()),
            },
        )
        .unwrap();
        assert!(ok.systemd.contains(ONION));
        assert!(parse_onion_dial("not-an-onion:8333").is_err());
        assert!(parse_onion_dial(&format!("{}:0", &ONION[..ONION.len() - 5])).is_err());
        assert!(render(
            "/tmp/x y",
            "/var/lib/permawrite/genesis.json",
            &DialMode::TorOnly { onion: None }
        )
        .is_err());
    }

    #[test]
    fn clearnet_is_opt_in_and_a_wildcard_cannot_hide() {
        let clear = render(
            "/var/lib/permawrite",
            "/var/lib/permawrite/genesis.json",
            &DialMode::Clearnet {
                seed: "203.0.113.5:19001".into(),
            },
        )
        .unwrap();
        assert!(clear.systemd.contains("CLEARNET OPT-IN"));
        assert!(!clear.systemd.contains("IPAddressDeny"));
        let mut leaked = clear.clone();
        leaked.systemd = leaked.systemd.replace(RPC_LISTEN, "0.0.0.0:18734");
        assert_eq!(
            audit(&leaked, false),
            Err(SetupError::Leak("wildcard 0.0.0.0"))
        );
    }

    #[test]
    fn public_testnet_address_is_rejected_by_the_audit() {
        let mut layout = render(
            "/var/lib/permawrite",
            "/var/lib/permawrite/genesis.json",
            &DialMode::TorOnly { onion: None },
        )
        .unwrap();
        layout.systemd.push_str("\n# 5.161.201.73:19001\n");
        assert!(audit(&layout, true).is_err());
    }
}
