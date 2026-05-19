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

/// Read `seed_nodes` from an explicit manifest path.
pub fn seed_nodes_from_manifest_path(path: &Path) -> Result<Vec<String>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("read p2p seeds manifest `{}`: {e}", path.display()))?;
    let manifest: NetworkManifestSeeds = serde_json::from_str(&raw)
        .map_err(|e| format!("parse p2p seeds manifest `{}`: {e}", path.display()))?;
    Ok(manifest.seed_nodes)
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
    if let Some(g) = genesis_spec {
        for addr in seed_nodes_from_genesis_manifest(g)? {
            if !addr.trim().is_empty() {
                push_unique_peer_addr(explicit, addr);
            }
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
        assert_eq!(
            explicit,
            vec![
                "203.0.113.10:4001",
                "203.0.113.11:4001",
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
