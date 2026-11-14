//! Anti-eclipse peer diversity helpers (**P31** phase 0–1).
//!
//! Counts distinct IPv4 /16 buckets among live P2P session peers, surfaces
//! low-diversity warnings, and selects redial candidates in underrepresented /16
//! blocks when diversity drops.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use crate::peer_addr::{is_onion_host, parse_peer_host_port};

/// Default minimum distinct IPv4 /16 buckets when ≥2 IPv4 session peers exist.
pub const DEFAULT_MIN_DISTINCT_IPV4_PREFIX16: u32 = 2;

/// Environment knob: minimum distinct IPv4 /16 among session peers (`0` disables).
pub const MFND_P2P_MIN_DISTINCT_PREFIX16_ENV: &str = "MFND_P2P_MIN_DISTINCT_PREFIX16";
/// Environment knob: enable automatic redial when diversity is low (`1` default when min > 0).
pub const MFND_P2P_DIVERSITY_REDIAL_ENV: &str = "MFND_P2P_DIVERSITY_REDIAL";
/// Default outbound dials per diversity-redial sweep.
pub const DEFAULT_DIVERSITY_REDIAL_PER_SWEEP: u32 = 2;
/// Default anchor peers embedded in checkpoint trusted-summary JSON (**F12** phase 0).
pub const DEFAULT_CHECKPOINT_ANCHOR_PEER_COUNT: usize = 8;

/// Diversity snapshot for live P2P session peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDiversitySnapshot {
    /// Total session peer count.
    pub session_count: usize,
    /// Distinct IPv4 /16 buckets (literal IPv4 hosts only).
    pub distinct_ipv4_prefix16: usize,
    /// Distinct `.onion` host labels.
    pub distinct_onion: usize,
    /// Distinct non-onion, non-literal-IPv4 host labels (DNS names, bracketed IPv6).
    pub distinct_other_hosts: usize,
    /// Session peers whose host parses as literal IPv4.
    pub ipv4_session_count: usize,
}

/// Diversity bucket for `host`.
///
/// When `asn` contains the literal IPv4 address, the bucket is `AS<n>`.
/// Otherwise the bucket is the IPv4 /16. Non-IPv4 hosts have no bucket.
/// An empty table is the P31 /16 behavior. There is no network lookup.
#[must_use]
pub fn diversity_bucket_key(host: &str, asn: &BTreeMap<Ipv4Addr, u32>) -> Option<String> {
    let ip: IpAddr = host.parse().ok()?;
    match ip {
        IpAddr::V4(v4) => {
            if let Some(n) = asn.get(&v4) {
                Some(format!("AS{n}"))
            } else {
                let o = v4.octets();
                Some(format!("{}.{}.0.0/16", o[0], o[1]))
            }
        }
        IpAddr::V6(_) => None,
    }
}

/// Distinct IPv4 diversity buckets in `peers`, using `asn` when a host is listed.
#[must_use]
pub fn distinct_diversity_buckets(peers: &[String], asn: &BTreeMap<Ipv4Addr, u32>) -> usize {
    let mut buckets = BTreeSet::new();
    for peer in peers {
        let Ok((host, _)) = parse_peer_host_port(peer) else {
            continue;
        };
        if let Some(key) = diversity_bucket_key(&host, asn) {
            buckets.insert(key);
        }
    }
    buckets.len()
}

/// IPv4 /16 bucket label (`a.b.0.0/16`), or `None` for non-IPv4 hosts.
#[must_use]
pub fn ipv4_prefix16_key(host: &str) -> Option<String> {
    let ip: IpAddr = host.parse().ok()?;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.0.0/16", o[0], o[1]))
        }
        IpAddr::V6(_) => None,
    }
}

/// Summarize diversity buckets for `peers` (`HOST:PORT` dial strings).
#[must_use]
pub fn peer_diversity_snapshot(peers: &[String]) -> PeerDiversitySnapshot {
    let mut prefix16 = BTreeSet::new();
    let mut onion = BTreeSet::new();
    let mut other = BTreeSet::new();
    let mut ipv4_session_count = 0usize;
    for peer in peers {
        let Ok((host, _)) = parse_peer_host_port(peer) else {
            continue;
        };
        if is_onion_host(&host) {
            onion.insert(host);
        } else if let Some(key) = ipv4_prefix16_key(&host) {
            prefix16.insert(key);
            ipv4_session_count = ipv4_session_count.saturating_add(1);
        } else {
            other.insert(host);
        }
    }
    PeerDiversitySnapshot {
        session_count: peers.len(),
        distinct_ipv4_prefix16: prefix16.len(),
        distinct_onion: onion.len(),
        distinct_other_hosts: other.len(),
        ipv4_session_count,
    }
}

/// Read [`MFND_P2P_MIN_DISTINCT_PREFIX16_ENV`] (default [`DEFAULT_MIN_DISTINCT_IPV4_PREFIX16`]).
pub fn min_distinct_ipv4_prefix16_from_env() -> Result<u32, String> {
    match std::env::var(MFND_P2P_MIN_DISTINCT_PREFIX16_ENV) {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(format!(
                    "{MFND_P2P_MIN_DISTINCT_PREFIX16_ENV} must not be empty"
                ));
            }
            trimmed
                .parse::<u32>()
                .map_err(|_| format!("{MFND_P2P_MIN_DISTINCT_PREFIX16_ENV}={raw:?} must be u32"))
        }
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_MIN_DISTINCT_IPV4_PREFIX16),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "{MFND_P2P_MIN_DISTINCT_PREFIX16_ENV} must be valid UTF-8"
        )),
    }
}

/// Read [`MFND_P2P_DIVERSITY_REDIAL_ENV`] (default **enabled**).
pub fn peer_diversity_redial_enabled_from_env() -> Result<bool, String> {
    match std::env::var(MFND_P2P_DIVERSITY_REDIAL_ENV) {
        Ok(raw) => parse_bool_env(MFND_P2P_DIVERSITY_REDIAL_ENV, &raw),
        Err(std::env::VarError::NotPresent) => Ok(true),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "{MFND_P2P_DIVERSITY_REDIAL_ENV} must be valid UTF-8"
        )),
    }
}

fn parse_bool_env(name: &str, raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!("{name}={other:?} must be 0/1 or true/false")),
    }
}

/// Peers to dial when live sessions fail the /16 diversity floor.
#[must_use]
pub fn peer_diversity_redial_candidates(
    session_peers: &[String],
    candidate_peers: &[String],
    min_distinct_prefix16: u32,
    max_redials: u32,
) -> Vec<String> {
    peer_diversity_redial_candidates_with_asn(
        session_peers,
        candidate_peers,
        &BTreeMap::new(),
        min_distinct_prefix16,
        max_redials,
    )
}

/// Same as [`peer_diversity_redial_candidates`], but a supplied ASN table
/// collapses addresses that share an AS even when their /16 differs.
///
/// The table is local. Missing addresses stay on /16. Default callers pass
/// an empty table, which is the existing /16 redial.
#[must_use]
pub fn peer_diversity_redial_candidates_with_asn(
    session_peers: &[String],
    candidate_peers: &[String],
    asn: &BTreeMap<Ipv4Addr, u32>,
    min_distinct_buckets: u32,
    max_redials: u32,
) -> Vec<String> {
    if min_distinct_buckets == 0 || max_redials == 0 {
        return Vec::new();
    }
    if asn.is_empty() {
        if peer_diversity_warning(session_peers, min_distinct_buckets).is_none() {
            return Vec::new();
        }
    } else if distinct_diversity_buckets(session_peers, asn) >= min_distinct_buckets as usize
        || ipv4_session_count(session_peers) < 2
    {
        return Vec::new();
    }

    let live: BTreeSet<String> = session_peers.iter().cloned().collect();
    let mut session_buckets = BTreeSet::new();
    for peer in session_peers {
        let Ok((host, _)) = parse_peer_host_port(peer) else {
            continue;
        };
        if let Some(key) = diversity_bucket_key(&host, asn) {
            session_buckets.insert(key);
        }
    }

    let mut picks = Vec::new();
    for candidate in candidate_peers {
        if picks.len() >= max_redials as usize {
            break;
        }
        if live.contains(candidate) {
            continue;
        }
        let Ok((host, _)) = parse_peer_host_port(candidate) else {
            continue;
        };
        let Some(key) = diversity_bucket_key(&host, asn) else {
            continue;
        };
        if session_buckets.contains(&key) {
            continue;
        }
        picks.push(candidate.clone());
        session_buckets.insert(key);
    }
    picks
}

fn ipv4_session_count(peers: &[String]) -> usize {
    peers
        .iter()
        .filter(|peer| {
            parse_peer_host_port(peer)
                .ok()
                .and_then(|(host, _)| host.parse::<IpAddr>().ok())
                .is_some_and(|ip| ip.is_ipv4())
        })
        .count()
}

/// Select diverse `HOST:PORT` peers to ship with checkpoint summaries (**F12** phase 0).
///
/// Prefers live session peers, then fills from `durable_peers` in new /16, `.onion`, or
/// other-host buckets.
#[must_use]
pub fn checkpoint_anchor_peer_candidates(
    session_peers: &[String],
    durable_peers: &[String],
    max_peers: usize,
) -> Vec<String> {
    if max_peers == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut prefix16 = BTreeSet::new();
    let mut onion = BTreeSet::new();
    let mut other_hosts = BTreeSet::new();

    let try_add = |out: &mut Vec<String>,
                   seen: &mut BTreeSet<String>,
                   prefix16: &mut BTreeSet<String>,
                   onion: &mut BTreeSet<String>,
                   other_hosts: &mut BTreeSet<String>,
                   peer: &str,
                   require_new_bucket: bool|
     -> bool {
        if seen.contains(peer) {
            return false;
        }
        let Ok((host, _)) = parse_peer_host_port(peer) else {
            return false;
        };
        if is_onion_host(&host) {
            if require_new_bucket && onion.contains(&host) {
                return false;
            }
            onion.insert(host);
        } else if let Some(key) = ipv4_prefix16_key(&host) {
            if require_new_bucket && prefix16.contains(&key) {
                return false;
            }
            prefix16.insert(key);
        } else if require_new_bucket && other_hosts.contains(&host) {
            return false;
        } else {
            other_hosts.insert(host);
        }
        seen.insert(peer.to_string());
        out.push(peer.to_string());
        true
    };

    for peer in session_peers {
        if out.len() >= max_peers {
            break;
        }
        try_add(
            &mut out,
            &mut seen,
            &mut prefix16,
            &mut onion,
            &mut other_hosts,
            peer,
            false,
        );
    }
    for peer in durable_peers {
        if out.len() >= max_peers {
            break;
        }
        try_add(
            &mut out,
            &mut seen,
            &mut prefix16,
            &mut onion,
            &mut other_hosts,
            peer,
            true,
        );
    }
    out
}

/// Warn when ≥2 IPv4 session peers share fewer than `min_distinct_prefix16` /16 buckets.
#[must_use]
pub fn peer_diversity_warning(peers: &[String], min_distinct_prefix16: u32) -> Option<String> {
    if min_distinct_prefix16 == 0 {
        return None;
    }
    let snap = peer_diversity_snapshot(peers);
    if snap.ipv4_session_count < 2 {
        return None;
    }
    if snap.distinct_ipv4_prefix16 >= min_distinct_prefix16 as usize {
        return None;
    }
    Some(format!(
        "mfnd_p2p_diversity_warning sessions={} ipv4_sessions={} distinct_prefix16={} min_distinct_prefix16={min_distinct_prefix16}; add peers in other /16 blocks to reduce eclipse risk (P31)",
        snap.session_count,
        snap.ipv4_session_count,
        snap.distinct_ipv4_prefix16,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_prefix16_key_labels_slash16() {
        assert_eq!(
            ipv4_prefix16_key("192.168.1.5").as_deref(),
            Some("192.168.0.0/16")
        );
        assert!(ipv4_prefix16_key("::1").is_none());
        assert!(ipv4_prefix16_key("example.com").is_none());
    }

    #[test]
    fn snapshot_counts_distinct_buckets() {
        let peers = vec![
            "10.0.0.1:8333".into(),
            "10.0.0.2:8334".into(),
            "10.1.0.3:8335".into(),
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:8333".into(),
            "other.example:8333".into(),
        ];
        let snap = peer_diversity_snapshot(&peers);
        assert_eq!(snap.session_count, 5);
        assert_eq!(snap.ipv4_session_count, 3);
        assert_eq!(snap.distinct_ipv4_prefix16, 2);
        assert_eq!(snap.distinct_onion, 1);
        assert_eq!(snap.distinct_other_hosts, 1);
    }

    #[test]
    fn warning_when_same_prefix16() {
        let peers = vec!["10.0.0.1:8333".into(), "10.0.0.2:8334".into()];
        let msg = peer_diversity_warning(&peers, 2).expect("warning");
        assert!(msg.contains("mfnd_p2p_diversity_warning"));
        assert!(msg.contains("distinct_prefix16=1"));
    }

    #[test]
    fn no_warning_when_diverse_or_disabled() {
        let peers = vec!["10.0.0.1:8333".into(), "10.1.0.2:8334".into()];
        assert!(peer_diversity_warning(&peers, 2).is_none());
        assert!(peer_diversity_warning(&peers, 0).is_none());
    }

    #[test]
    fn redial_candidates_pick_new_prefix16() {
        let sessions = vec!["10.0.0.1:8333".into(), "10.0.0.2:8334".into()];
        let candidates = vec![
            "10.0.0.3:8335".into(),
            "10.1.0.4:8336".into(),
            "10.2.0.5:8337".into(),
        ];
        let picks = peer_diversity_redial_candidates(&sessions, &candidates, 2, 2);
        assert_eq!(
            picks,
            vec!["10.1.0.4:8336".to_string(), "10.2.0.5:8337".to_string(),]
        );
    }

    #[test]
    fn b17_asn_collapses_distinct_prefix16_and_splits_one_prefix() {
        let mut asn = BTreeMap::new();
        asn.insert("10.0.0.1".parse().unwrap(), 100);
        asn.insert("10.1.0.2".parse().unwrap(), 100);
        asn.insert("10.0.0.9".parse().unwrap(), 200);
        asn.insert("10.2.0.3".parse().unwrap(), 100);
        let peers = vec!["10.0.0.1:8333".into(), "10.1.0.2:8334".into()];
        assert_eq!(distinct_diversity_buckets(&peers, &BTreeMap::new()), 2);
        assert_eq!(distinct_diversity_buckets(&peers, &asn), 1);

        let sessions = vec!["10.0.0.1:8333".into(), "10.1.0.2:8334".into()];
        let candidates = vec!["10.0.0.9:8335".into(), "10.2.0.3:8336".into()];
        let picks = peer_diversity_redial_candidates_with_asn(&sessions, &candidates, &asn, 2, 2);
        assert_eq!(picks, vec!["10.0.0.9:8335".to_string()]);
        assert!(
            peer_diversity_redial_candidates(&sessions, &candidates, 2, 2).is_empty(),
            "empty ASN table keeps /16 redial: these sessions are already two /16s"
        );
    }

    #[test]
    fn redial_candidates_empty_when_diverse() {
        let sessions = vec!["10.0.0.1:8333".into(), "10.1.0.2:8334".into()];
        let candidates = vec!["10.2.0.3:8335".into()];
        assert!(peer_diversity_redial_candidates(&sessions, &candidates, 2, 2).is_empty());
    }

    #[test]
    fn checkpoint_anchor_peers_prefers_sessions_then_diverse_durable() {
        let sessions = vec!["10.0.0.1:8333".into(), "10.0.0.2:8334".into()];
        let durable = vec![
            "10.0.0.3:8335".into(),
            "10.1.0.4:8336".into(),
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:8333".into(),
        ];
        let picks = checkpoint_anchor_peer_candidates(&sessions, &durable, 4);
        assert_eq!(
            picks,
            vec![
                "10.0.0.1:8333".to_string(),
                "10.0.0.2:8334".to_string(),
                "10.1.0.4:8336".to_string(),
                "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:8333".to_string(),
            ]
        );
    }
}
