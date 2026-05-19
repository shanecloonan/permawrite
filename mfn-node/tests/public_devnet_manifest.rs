//! Public devnet manifest matches live genesis (**M2.4.3**).

use std::path::PathBuf;

use mfn_node::{
    genesis_config_from_json_path, Chain, ChainConfig, ChainPersistence, NodeStore, StoreBackend,
};

const MANIFEST_GENESIS_ID: &str =
    "7fef4492dba32d7ba652cceb5465cae86d6630a9e0a4855adf3acdc5f6b2a2df";

fn spec_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

fn hex32(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[test]
fn public_devnet_v1_genesis_id_matches_manifest() {
    let spec = spec_path("public_devnet_v1.json");
    let cfg = ChainConfig::new(genesis_config_from_json_path(&spec).expect("spec"));
    let chain = Chain::from_genesis(cfg.clone()).expect("genesis");
    assert_eq!(hex32(chain.genesis_id()), MANIFEST_GENESIS_ID);

    let dir = std::env::temp_dir().join(format!(
        "permawrite-manifest-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let store = NodeStore::open(StoreBackend::Fs, &dir).expect("store");
    let loaded = store.load_or_genesis(cfg).expect("load");
    assert_eq!(hex32(loaded.genesis_id()), MANIFEST_GENESIS_ID);
    std::fs::remove_dir_all(&dir).ok();
}
