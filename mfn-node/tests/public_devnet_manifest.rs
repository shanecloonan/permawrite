//! Public devnet manifest matches live genesis (**M2.4.3**).

use std::path::PathBuf;

use mfn_consensus::{try_produce_slot, SlotContext, ValidatorSecrets};
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_node::{
    genesis_config_from_json_path, Chain, ChainConfig, ChainPersistence, NodeStore, StoreBackend,
};

const MANIFEST_GENESIS_ID: &str =
    "454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005";
const V0_VRF_SEED_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const V0_BLS_SEED_HEX: &str = "6565656565656565656565656565656565656565656565656565656565656565";

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

#[test]
fn public_devnet_validator0_needs_advancing_slots_for_liveness() {
    let spec = spec_path("public_devnet_v1.json");
    let cfg = ChainConfig::new(genesis_config_from_json_path(&spec).expect("spec"));
    let chain = Chain::from_genesis(cfg.clone()).expect("genesis");
    let validator = cfg
        .genesis
        .validators
        .iter()
        .find(|v| v.index == 0)
        .expect("validator 0");
    let mut vrf_seed = [0u8; 32];
    hex::decode_to_slice(V0_VRF_SEED_HEX, &mut vrf_seed).expect("vrf hex");
    let mut bls_seed = [0u8; 32];
    hex::decode_to_slice(V0_BLS_SEED_HEX, &mut bls_seed).expect("bls hex");
    let secrets = ValidatorSecrets {
        index: 0,
        vrf: vrf_keygen_from_seed(&vrf_seed).expect("vrf"),
        bls: mfn_bls::bls_keygen_from_seed(&bls_seed),
    };
    let total_stake: u64 = cfg.genesis.validators.iter().map(|v| v.stake).sum();
    let header_hash = [0x42u8; 32];
    let prev_hash = *chain.genesis_id();

    let slot1 = SlotContext {
        height: 1,
        slot: 1,
        prev_hash,
    };
    assert!(
        try_produce_slot(
            &slot1,
            &secrets,
            validator,
            total_stake,
            cfg.genesis.params.expected_proposers_per_slot,
            &header_hash,
        )
        .expect("slot 1 check")
        .is_none(),
        "slot 1 is known ineligible for public-devnet validator 0; retrying it stalls the faucet"
    );

    let first_eligible = (2u32..=300).find(|slot| {
        let ctx = SlotContext {
            height: 1,
            slot: *slot,
            prev_hash,
        };
        try_produce_slot(
            &ctx,
            &secrets,
            validator,
            total_stake,
            cfg.genesis.params.expected_proposers_per_slot,
            &header_hash,
        )
        .expect("slot check")
        .is_some()
    });
    assert!(
        first_eligible.is_some(),
        "advancing slots should give validator 0 an eligible public-devnet slot"
    );
    assert!(
        first_eligible.expect("checked above") <= 128,
        "first eligible slot must fall within mfnd producer scan window (MAX_SLOT_ELIGIBILITY_SCANS)"
    );
}
