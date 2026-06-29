//! Boot-time P2P peer list: CLI dials + optional genesis manifest seeds (**M2.4.4**).

use std::path::Path;

use serde::Deserialize;

/// Subset of network manifest JSON read for `seed_nodes`.
#[derive(Debug, Deserialize)]
struct NetworkManifestSeeds {
    seed_nodes: Vec<String>,
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

/// Merge manifest seeds (when present) into explicit `--p2p-dial` addresses.
pub fn merge_boot_peer_dials(
    explicit: &mut Vec<String>,
    genesis_spec: Option<&Path>,
) -> Result<(), String> {
    *explicit = normalize_peer_addrs(std::mem::take(explicit), "explicit --p2p-dial")?;
    if let Some(g) = genesis_spec {
        for addr in seed_nodes_from_genesis_manifest(g)? {
            push_unique_peer_addr(explicit, addr);
        }
    }
    Ok(())
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
        merge_boot_peer_dials(&mut explicit, Some(&genesis)).expect("merge");
        assert_eq!(explicit, vec!["203.0.113.10:4001", "203.0.113.11:4001",]);
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
        let err = merge_boot_peer_dials(&mut explicit, Some(&genesis)).expect_err("bad seed");
        assert!(err.contains("bad host"), "err={err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
