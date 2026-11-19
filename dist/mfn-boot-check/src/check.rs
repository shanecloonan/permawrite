//! Rules for a Tor-only boot.

use thiserror::Error;

/// Why the node must not be started.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootError {
    /// A required lock is missing.
    #[error("missing {0}")]
    Missing(&'static str),
    /// A clearnet dial, a public bind, or TCP transport is present.
    #[error("clearnet path: {0}")]
    Clearnet(String),
    /// A peer is not a v3 onion.
    #[error("peer is not a v3 onion: {0}")]
    Peer(String),
}

/// Check `env` and `unit` text. Does not start a process and does not dial.
pub fn check_boot(env: &str, unit: &str) -> Result<(), BootError> {
    require_line(env, "MFND_P2P_TRANSPORT=tor", "MFND_P2P_TRANSPORT=tor")?;
    require_line(env, "MFND_P2P_OVERLAY_ONLY=1", "MFND_P2P_OVERLAY_ONLY=1")?;
    require_line(unit, "IPAddressDeny=any", "IPAddressDeny=any")?;
    require_line(unit, "IPAddressAllow=localhost", "IPAddressAllow=localhost")?;
    if env.contains("MFND_P2P_TRANSPORT=tcp") || unit.contains("MFND_P2P_TRANSPORT=tcp") {
        return Err(BootError::Clearnet("tcp transport".into()));
    }
    if env.contains("0.0.0.0") || unit.contains("0.0.0.0") {
        return Err(BootError::Clearnet("0.0.0.0".into()));
    }
    let socks = value(env, "MFND_TOR_SOCKS5=").ok_or(BootError::Missing("MFND_TOR_SOCKS5"))?;
    if !is_loopback_addr(&socks) {
        return Err(BootError::Clearnet(format!("socks {socks}")));
    }
    for flag in ["--rpc-listen", "--p2p-listen"] {
        let addr = flag_value(unit, flag).ok_or(BootError::Missing(flag_name(flag)))?;
        if !is_loopback_addr(&addr) {
            return Err(BootError::Clearnet(format!("{flag} {addr}")));
        }
    }
    let mut rest = unit;
    while let Some(idx) = rest.find("--p2p-dial ") {
        let after = &rest[idx + "--p2p-dial ".len()..];
        let peer = after.split_whitespace().next().unwrap_or("");
        if !is_v3_onion(peer) {
            return Err(BootError::Peer(peer.to_string()));
        }
        rest = &after[peer.len()..];
    }
    Ok(())
}

fn flag_name(flag: &str) -> &'static str {
    match flag {
        "--rpc-listen" => "--rpc-listen",
        _ => "--p2p-listen",
    }
}

fn require_line(text: &str, needle: &str, label: &'static str) -> Result<(), BootError> {
    if text
        .lines()
        .any(|line| line.trim() == needle || line.contains(needle))
    {
        Ok(())
    } else {
        Err(BootError::Missing(label))
    }
}

fn value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim().trim_start_matches("Environment=");
        if let Some(rest) = line.strip_prefix(key) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn flag_value(text: &str, flag: &str) -> Option<String> {
    let needle = format!("{flag} ");
    let rest = text.split(&needle).nth(1)?;
    rest.split_whitespace().next().map(str::to_string)
}

fn is_loopback_addr(addr: &str) -> bool {
    let host = if let Some(rest) = addr.strip_prefix('[') {
        rest.split("]:").next().unwrap_or(rest)
    } else {
        addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr)
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn is_v3_onion(peer: &str) -> bool {
    let host = peer.rsplit_once(':').map(|(h, _)| h).unwrap_or(peer);
    let Some(name) = host.strip_suffix(".onion") else {
        return false;
    };
    name.len() == 56 && name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> (String, String) {
        let onion = format!("{}.onion:8333", "d".repeat(56));
        let env = "\
MFND_P2P_TRANSPORT=tor
MFND_P2P_OVERLAY_ONLY=1
MFND_TOR_SOCKS5=127.0.0.1:9050
"
        .to_string();
        let unit = format!(
            "\
ExecStart=/usr/local/bin/mfnd serve --rpc-listen 127.0.0.1:18731 --p2p-listen 127.0.0.1:8333 --p2p-dial {onion}
IPAddressDeny=any
IPAddressAllow=localhost
"
        );
        (env, unit)
    }

    #[test]
    fn a_tor_only_unit_passes() {
        let (env, unit) = good();
        check_boot(&env, &unit).unwrap();
    }

    #[test]
    fn clearnet_transport_bind_and_peer_fail() {
        let (mut env, unit) = good();
        env = env.replace("MFND_P2P_TRANSPORT=tor", "MFND_P2P_TRANSPORT=tcp");
        assert!(matches!(
            check_boot(&env, &unit),
            Err(BootError::Missing("MFND_P2P_TRANSPORT=tor"))
        ));
        let (env, unit) = good();
        let unit = unit.replace("127.0.0.1:18731", "0.0.0.0:18731");
        assert!(matches!(
            check_boot(&env, &unit),
            Err(BootError::Clearnet(_))
        ));
        let (env, unit) = good();
        let unit = unit.replace(".onion:8333", ".example:8333");
        assert!(matches!(check_boot(&env, &unit), Err(BootError::Peer(_))));
        let (env, mut unit) = good();
        unit = unit.replace("IPAddressDeny=any", "IPAddressDeny=none");
        assert!(matches!(
            check_boot(&env, &unit),
            Err(BootError::Missing("IPAddressDeny=any"))
        ));
    }

    #[test]
    fn socks_must_be_loopback() {
        let (env, unit) = good();
        let env = env.replace("127.0.0.1:9050", "8.8.8.8:9050");
        assert!(matches!(
            check_boot(&env, &unit),
            Err(BootError::Clearnet(_))
        ));
    }
}
