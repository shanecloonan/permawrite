//! Three ways to learn a first peer: DNS seeds, hardcoded onion seeds, and
//! addresses a peer already handed us. Any one of them is enough.

use std::net::{IpAddr, ToSocketAddrs};

use crate::p2p_boot::push_unique_peer_addr;

/// Onion seeds compiled into the binary. They are dialed only when
/// `MFND_P2P_HARDCODED_ONIONS=1`, so a default node does not open circuits to
/// placeholders. Replace these before a public launch.
pub const HARDCODED_ONION_SEEDS: &[&str] = &[
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:19101",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion:19101",
];

/// Comma-separated DNS names in `MFND_DNS_SEEDS`. Port is `MFND_DNS_SEED_PORT` (default 19101).
pub const DNS_SEEDS_ENV: &str = "MFND_DNS_SEEDS";

/// Port applied to every DNS answer.
pub const DNS_SEED_PORT_ENV: &str = "MFND_DNS_SEED_PORT";

/// `1`/`true`/`yes`/`on` merges [`HARDCODED_ONION_SEEDS`].
pub const HARDCODED_ONIONS_ENV: &str = "MFND_P2P_HARDCODED_ONIONS";

/// Addresses learned from all three paths, in path order.
#[must_use]
pub fn discover_peers(dns: &[String], onions: &[String], exchanged: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for addr in dns.iter().chain(onions).chain(exchanged) {
        if let Some(addr) = accept_discovery_addr(addr) {
            push_unique_peer_addr(&mut out, addr);
        }
    }
    out
}

/// `MFND_DNS_SEEDS` looked up through `resolver`. A failed name is skipped.
#[must_use]
pub fn dns_seed_addrs(
    names: &[String],
    port: u16,
    resolver: &dyn Fn(&str) -> Vec<IpAddr>,
) -> Vec<String> {
    let mut out = Vec::new();
    for name in names {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        for ip in resolver(name) {
            let addr = match ip {
                IpAddr::V4(v4) => format!("{v4}:{port}"),
                IpAddr::V6(v6) => format!("[{v6}]:{port}"),
            };
            push_unique_peer_addr(&mut out, addr);
        }
    }
    out
}

/// System DNS. Errors and empty answers become an empty list.
#[must_use]
pub fn system_dns_lookup(name: &str, port: u16) -> Vec<IpAddr> {
    let query = format!("{name}:{port}");
    match query.to_socket_addrs() {
        Ok(iter) => iter.map(|addr| addr.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Names from the environment. Missing or empty is no DNS path.
#[must_use]
pub fn dns_seed_names_from_env() -> Vec<String> {
    split_env(DNS_SEEDS_ENV)
}

/// Port from the environment, or 19101.
#[must_use]
pub fn dns_seed_port_from_env() -> u16 {
    std::env::var(DNS_SEED_PORT_ENV)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .filter(|p| *p != 0)
        .unwrap_or(19101)
}

/// Hardcoded onions when the operator turns that path on.
#[must_use]
pub fn hardcoded_onion_seeds_from_env() -> Vec<String> {
    if !env_flag(HARDCODED_ONIONS_ENV) {
        return Vec::new();
    }
    HARDCODED_ONION_SEEDS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// `MFND_P2P_EXCHANGED_SEEDS`, comma-separated `host:port` (what peer exchange recorded).
#[must_use]
pub fn exchanged_seeds_from_env() -> Vec<String> {
    split_env("MFND_P2P_EXCHANGED_SEEDS")
}

fn split_env(key: &str) -> Vec<String> {
    std::env::var(key)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn accept_discovery_addr(addr: &str) -> Option<String> {
    let addr = addr.trim();
    if addr.is_empty() || addr.chars().any(char::is_whitespace) {
        return None;
    }
    let (host, port) = addr.rsplit_once(':')?;
    if host.is_empty() || port.parse::<u16>().ok()? == 0 {
        return None;
    }
    Some(addr.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> Vec<IpAddr> {
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))]
    }

    #[test]
    fn any_single_path_still_yields_a_peer() {
        let dns = vec!["203.0.113.1:19101".to_string()];
        let onions = vec![
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:19101".to_string(),
        ];
        let exchanged = vec!["198.51.100.4:19101".to_string()];
        let all = discover_peers(&dns, &onions, &exchanged);
        assert_eq!(all.len(), 3);
        assert_eq!(discover_peers(&[], &onions, &exchanged).len(), 2);
        assert_eq!(discover_peers(&dns, &[], &exchanged).len(), 2);
        assert_eq!(discover_peers(&dns, &onions, &[]).len(), 2);
        assert_eq!(discover_peers(&dns, &[], &[]).len(), 1);
        assert_eq!(discover_peers(&[], &onions, &[]).len(), 1);
        assert_eq!(discover_peers(&[], &[], &exchanged).len(), 1);
        assert!(discover_peers(&[], &[], &[]).is_empty());
    }

    #[test]
    fn dns_resolver_skips_a_blocked_name() {
        let names = vec!["blocked.example".into(), "open.example".into()];
        let addrs = dns_seed_addrs(&names, 19101, &|name| {
            if name == "blocked.example" {
                Vec::new()
            } else {
                ip(9)
            }
        });
        assert_eq!(addrs, vec!["203.0.113.9:19101".to_string()]);
    }
}
