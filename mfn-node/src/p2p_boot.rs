//! Boot-time P2P peer list: CLI dials + optional genesis manifest seeds (**M2.4.4**).

use std::path::Path;

use serde::Deserialize;

/// Hard cap for boot-time CLI + manifest seed dials.
///
/// This matches the saved-peer `max_outbound_peers` hard limit so a stale public
/// manifest cannot spawn an unbounded number of outbound dial threads at startup.
pub const MAX_BOOT_PEER_DIALS: usize = mfn_store::MAX_OUTBOUND_PEERS_LIMIT as usize;

/// Subset of network manifest JSON read for `seed_nodes`.
#[derive(Debug, Deserialize)]
struct NetworkManifestSeeds {
    seed_nodes: Vec<String>,
}

/// Subset of trusted-summary JSON read for checkpoint anchor peers (**F12** phase 0).
#[derive(Debug, Deserialize)]
struct TrustedSummaryAnchors {
    #[serde(default)]
    anchor_peers: Vec<String>,
}

/// Summary of boot-peer merge/capping before outbound dial threads are spawned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootPeerDialMergeReport {
    /// Unique, valid boot peers before applying [`MAX_BOOT_PEER_DIALS`].
    pub configured: usize,
    /// Boot peers retained for outbound dial attempts.
    pub retained: usize,
    /// Valid unique peers dropped by the hard cap.
    pub dropped: usize,
    /// Hard cap applied to the merged list.
    pub cap: usize,
}

/// Append `addr` if not already present (preserve first-seen order).
pub fn push_unique_peer_addr(addrs: &mut Vec<String>, addr: String) {
    if addrs.iter().any(|a| a == &addr) {
        return;
    }
    addrs.push(addr);
}

fn normalize_peer_addr(addr: &str) -> Result<Option<String>, String> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(format!("peer address `{addr}` must not contain whitespace"));
    }
    let Some((host, port_s)) = trimmed.rsplit_once(':') else {
        return Err(format!("peer address `{addr}` must be HOST:PORT"));
    };
    if host.is_empty() {
        return Err(format!("peer address `{addr}` has empty host"));
    }
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return Err(format!(
            "peer address `{addr}` has unbracketed IPv6; use [IPv6]:PORT"
        ));
    }
    let port: u16 = port_s
        .parse()
        .map_err(|_| format!("peer address `{addr}` has invalid port `{port_s}`"))?;
    if port == 0 {
        return Err(format!(
            "peer address `{addr}` port must be greater than zero"
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn normalize_peer_addrs(addrs: Vec<String>, source: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for addr in addrs {
        if let Some(normalized) =
            normalize_peer_addr(&addr).map_err(|e| format!("{source}: {e}"))?
        {
            push_unique_peer_addr(&mut out, normalized);
        }
    }
    Ok(out)
}

/// Read `seed_nodes` from an explicit manifest path.
pub fn seed_nodes_from_manifest_path(path: &Path) -> Result<Vec<String>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("read p2p seeds manifest `{}`: {e}", path.display()))?;
    let manifest: NetworkManifestSeeds = serde_json::from_str(&raw)
        .map_err(|e| format!("parse p2p seeds manifest `{}`: {e}", path.display()))?;
    normalize_peer_addrs(
        manifest.seed_nodes,
        &format!("p2p seeds manifest `{}`", path.display()),
    )
}

/// If `<genesis_stem>.manifest.json` exists beside the genesis spec, return its `seed_nodes`.
pub fn seed_nodes_from_genesis_manifest(genesis_spec: &Path) -> Result<Vec<String>, String> {
    let Some(parent) = genesis_spec.parent() else {
        return Ok(Vec::new());
    };
    let Some(stem) = genesis_spec.file_stem().and_then(|s| s.to_str()) else {
        return Ok(Vec::new());
    };
    let manifest = parent.join(format!("{stem}.manifest.json"));
    if !manifest.is_file() {
        return Ok(Vec::new());
    }
    seed_nodes_from_manifest_path(&manifest)
}

/// When true, [`merge_boot_peer_dials`] ignores sibling-manifest `seed_nodes`.
///
/// Set `MFN_SKIP_MANIFEST_SEEDS=1` for isolated local meshes (Nightly / `start-all`
/// loopback rehearsal). Public VPS boot must leave this unset so published
/// `seed_nodes` still dial. Explicit `--p2p-dial` addresses are never skipped.
pub fn env_skip_manifest_seeds() -> bool {
    matches!(
        std::env::var("MFN_SKIP_MANIFEST_SEEDS")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Merge manifest seeds (when present) into explicit `--p2p-dial` addresses.
pub fn merge_boot_peer_dials(
    explicit: &mut Vec<String>,
    genesis_spec: Option<&Path>,
) -> Result<BootPeerDialMergeReport, String> {
    merge_boot_peer_dials_inner(explicit, genesis_spec, env_skip_manifest_seeds())
}

fn merge_boot_peer_dials_inner(
    explicit: &mut Vec<String>,
    genesis_spec: Option<&Path>,
    skip_manifest_seeds: bool,
) -> Result<BootPeerDialMergeReport, String> {
    *explicit = normalize_peer_addrs(std::mem::take(explicit), "explicit --p2p-dial")?;
    if let Some(g) = genesis_spec {
        if !skip_manifest_seeds {
            for addr in seed_nodes_from_genesis_manifest(g)? {
                push_unique_peer_addr(explicit, addr);
            }
        }
    }
    let configured = explicit.len();
    if explicit.len() > MAX_BOOT_PEER_DIALS {
        explicit.truncate(MAX_BOOT_PEER_DIALS);
    }
    Ok(BootPeerDialMergeReport {
        configured,
        retained: explicit.len(),
        dropped: configured.saturating_sub(explicit.len()),
        cap: MAX_BOOT_PEER_DIALS,
    })
}

/// Read `anchor_peers` from a trusted-summary JSON file (`get_light_snapshot.summary` shape).
pub fn anchor_peers_from_trusted_summary(path: &Path) -> Result<Vec<String>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("read checkpoint anchor summary `{}`: {e}", path.display()))?;
    let summary: TrustedSummaryAnchors = serde_json::from_str(&raw)
        .map_err(|e| format!("parse checkpoint anchor summary `{}`: {e}", path.display()))?;
    normalize_peer_addrs(
        summary.anchor_peers,
        &format!("checkpoint anchor summary `{}`", path.display()),
    )
}

/// Merge `anchor_peers` from a trusted-summary file into boot dial addresses.
pub fn merge_checkpoint_anchor_peers(
    explicit: &mut Vec<String>,
    summary_path: Option<&Path>,
) -> Result<usize, String> {
    let Some(path) = summary_path else {
        return Ok(0);
    };
    let before = explicit.len();
    for addr in anchor_peers_from_trusted_summary(path)? {
        push_unique_peer_addr(explicit, addr);
    }
    Ok(explicit.len().saturating_sub(before))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn push_unique_peer_addr_dedupes() {
        let mut v = vec!["127.0.0.1:1".into()];
        push_unique_peer_addr(&mut v, "127.0.0.1:2".into());
        push_unique_peer_addr(&mut v, "127.0.0.1:1".into());
        assert_eq!(v, vec!["127.0.0.1:1", "127.0.0.1:2"]);
    }

    #[test]
    fn normalize_peer_addr_accepts_hosts_and_bracketed_ipv6() {
        assert_eq!(
            normalize_peer_addr(" seed.example.org:19001 ").unwrap(),
            Some("seed.example.org:19001".into())
        );
        assert_eq!(
            normalize_peer_addr("[2001:db8::1]:19001").unwrap(),
            Some("[2001:db8::1]:19001".into())
        );
        assert_eq!(normalize_peer_addr("   ").unwrap(), None);
    }

    #[test]
    fn normalize_peer_addr_rejects_bad_boot_addrs() {
        for bad in [
            "127.0.0.1",
            ":19001",
            "127.0.0.1:0",
            "127.0.0.1:notaport",
            "2001:db8::1:19001",
            "bad host:19001",
        ] {
            assert!(
                normalize_peer_addr(bad).is_err(),
                "expected bad peer addr: {bad}"
            );
        }
    }

    #[test]
    fn merge_boot_peer_dials_from_sibling_manifest() {
        let dir = std::env::temp_dir().join(format!(
            "permawrite-p2p-boot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let genesis = dir.join("net_a.json");
        std::fs::write(&genesis, b"{}").expect("genesis stub");
        let manifest = dir.join("net_a.manifest.json");
        let mut f = std::fs::File::create(&manifest).expect("manifest");
        write!(
            f,
            r#"{{"seed_nodes":["203.0.113.10:4001","203.0.113.11:4001"]}}"#
        )
        .expect("write manifest");
        let mut explicit = vec!["203.0.113.10:4001".into()];
        merge_boot_peer_dials_inner(&mut explicit, Some(&genesis), false).expect("merge");
        assert_eq!(explicit, vec!["203.0.113.10:4001", "203.0.113.11:4001",]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn merge_boot_peer_dials_skips_manifest_seeds_when_requested() {
        let dir = std::env::temp_dir().join(format!(
            "permawrite-p2p-boot-skip-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let genesis = dir.join("net_skip.json");
        std::fs::write(&genesis, b"{}").expect("genesis stub");
        let manifest = dir.join("net_skip.manifest.json");
        std::fs::write(
            &manifest,
            r#"{"seed_nodes":["5.161.201.73:19001","5.161.201.73:19002"]}"#,
        )
        .expect("write manifest");
        let mut explicit = vec!["127.0.0.1:19001".into()];
        merge_boot_peer_dials_inner(&mut explicit, Some(&genesis), true).expect("merge");
        assert_eq!(explicit, vec!["127.0.0.1:19001"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn merge_boot_peer_dials_trims_dedupes_and_rejects_bad_manifest_seed() {
        let dir = std::env::temp_dir().join(format!(
            "permawrite-p2p-boot-bad-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let genesis = dir.join("net_b.json");
        std::fs::write(&genesis, b"{}").expect("genesis stub");
        let manifest = dir.join("net_b.manifest.json");
        let mut f = std::fs::File::create(&manifest).expect("manifest");
        write!(
            f,
            r#"{{"seed_nodes":[" 203.0.113.10:4001 ","203.0.113.10:4001","bad host:4001"]}}"#
        )
        .expect("write manifest");
        let mut explicit = vec![" 203.0.113.10:4001 ".into()];
        let err = merge_boot_peer_dials_inner(&mut explicit, Some(&genesis), false)
            .expect_err("bad seed");
        assert!(err.contains("bad host"), "err={err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn merge_boot_peer_dials_caps_oversized_manifest_seed_list() {
        let dir = std::env::temp_dir().join(format!(
            "permawrite-p2p-boot-cap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let genesis = dir.join("net_c.json");
        std::fs::write(&genesis, b"{}").expect("genesis stub");
        let manifest = dir.join("net_c.manifest.json");
        let seeds = (0..(MAX_BOOT_PEER_DIALS + 10))
            .map(|idx| format!(r#""203.0.113.{idx}:4001""#))
            .collect::<Vec<_>>()
            .join(",");
        std::fs::write(&manifest, format!(r#"{{"seed_nodes":[{seeds}]}}"#))
            .expect("write manifest");

        let mut explicit = Vec::new();
        let report =
            merge_boot_peer_dials_inner(&mut explicit, Some(&genesis), false).expect("merge");
        assert_eq!(explicit.len(), MAX_BOOT_PEER_DIALS);
        assert_eq!(report.configured, MAX_BOOT_PEER_DIALS + 10);
        assert_eq!(report.retained, MAX_BOOT_PEER_DIALS);
        assert_eq!(report.dropped, 10);
        assert_eq!(report.cap, MAX_BOOT_PEER_DIALS);
        assert_eq!(explicit.first().unwrap(), "203.0.113.0:4001");
        assert_eq!(
            explicit.last().unwrap(),
            &format!("203.0.113.{}:4001", MAX_BOOT_PEER_DIALS - 1)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn merge_boot_peer_dials_preserves_explicit_priority_when_capped() {
        let dir = std::env::temp_dir().join(format!(
            "permawrite-p2p-boot-cap-explicit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let genesis = dir.join("net_d.json");
        std::fs::write(&genesis, b"{}").expect("genesis stub");
        let manifest = dir.join("net_d.manifest.json");
        let seeds = (0..MAX_BOOT_PEER_DIALS)
            .map(|idx| format!(r#""203.0.113.{idx}:4001""#))
            .collect::<Vec<_>>()
            .join(",");
        std::fs::write(&manifest, format!(r#"{{"seed_nodes":[{seeds}]}}"#))
            .expect("write manifest");

        let mut explicit = vec!["198.51.100.10:4001".into(), "198.51.100.11:4001".into()];
        let report =
            merge_boot_peer_dials_inner(&mut explicit, Some(&genesis), false).expect("merge");
        assert_eq!(explicit.len(), MAX_BOOT_PEER_DIALS);
        assert_eq!(report.configured, MAX_BOOT_PEER_DIALS + 2);
        assert_eq!(report.dropped, 2);
        assert_eq!(&explicit[..2], ["198.51.100.10:4001", "198.51.100.11:4001"]);
        assert!(!explicit.contains(&format!("203.0.113.{}:4001", MAX_BOOT_PEER_DIALS - 1)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn merge_checkpoint_anchor_peers_from_trusted_summary() {
        let dir = std::env::temp_dir().join(format!(
            "permawrite-p2p-boot-anchor-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let summary = dir.join("trusted-summary.json");
        std::fs::write(
            &summary,
            r#"{"genesis_id":"00","tip_height":0,"tip_block_id":"00","validator_count":1,"validator_set_root":"00","checkpoint_digest":"00","anchor_peers":["203.0.113.20:4001","203.0.113.21:4001"]}"#,
        )
        .expect("write summary");
        let mut explicit = vec!["203.0.113.20:4001".into()];
        let added = merge_checkpoint_anchor_peers(&mut explicit, Some(&summary)).expect("merge");
        assert_eq!(added, 1);
        assert_eq!(explicit, vec!["203.0.113.20:4001", "203.0.113.21:4001",]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
