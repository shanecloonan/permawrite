//! Public devnet manifest matches live genesis (**M2.4.3**).

use std::path::PathBuf;

use mfn_consensus::{try_produce_slot, SlotContext, Validator, ValidatorSecrets};
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

const V1_VRF_SEED_HEX: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const V1_BLS_SEED_HEX: &str = "7676767676767676767676767676767676767676767676767676767676767676";
const V2_VRF_SEED_HEX: &str = "0303030303030303030303030303030303030303030303030303030303030303";
const V2_BLS_SEED_HEX: &str = "8787878787878787878787878787878787878787878787878787878787878787";

fn validator_secrets(index: u32, vrf_hex: &str, bls_hex: &str) -> ValidatorSecrets {
    let mut vrf_seed = [0u8; 32];
    hex::decode_to_slice(vrf_hex, &mut vrf_seed).expect("vrf hex");
    let mut bls_seed = [0u8; 32];
    hex::decode_to_slice(bls_hex, &mut bls_seed).expect("bls hex");
    ValidatorSecrets {
        index,
        vrf: vrf_keygen_from_seed(&vrf_seed).expect("vrf"),
        bls: mfn_bls::bls_keygen_from_seed(&bls_seed),
    }
}

fn slot_eligible(
    cfg: &ChainConfig,
    secrets: &ValidatorSecrets,
    validator: &Validator,
    total_stake: u64,
    prev_hash: &[u8; 32],
    slot: u32,
) -> bool {
    let header_hash = [0x42u8; 32];
    let ctx = SlotContext {
        height: 1,
        slot,
        prev_hash: *prev_hash,
    };
    try_produce_slot(
        &ctx,
        secrets,
        validator,
        total_stake,
        cfg.genesis.params.expected_proposers_per_slot,
        &header_hash,
    )
    .expect("slot check")
    .is_some()
}

#[test]
fn public_devnet_sortition_multi_producer_liveness_bound() {
    let spec = spec_path("public_devnet_v1.json");
    let cfg = ChainConfig::new(genesis_config_from_json_path(&spec).expect("spec"));
    let chain = Chain::from_genesis(cfg.clone()).expect("genesis");
    let total_stake: u64 = cfg.genesis.validators.iter().map(|v| v.stake).sum();
    let prev_hash = *chain.genesis_id();

    let validators: Vec<(u32, &str, &str)> = vec![
        (0, V0_VRF_SEED_HEX, V0_BLS_SEED_HEX),
        (1, V1_VRF_SEED_HEX, V1_BLS_SEED_HEX),
        (2, V2_VRF_SEED_HEX, V2_BLS_SEED_HEX),
    ];

    let first_any = (1u32..=64).find(|slot| {
        validators.iter().any(|(index, vrf_hex, bls_hex)| {
            let validator = cfg
                .genesis
                .validators
                .iter()
                .find(|v| v.index == *index)
                .unwrap_or_else(|| panic!("validator {index}"));
            let secrets = validator_secrets(*index, vrf_hex, bls_hex);
            slot_eligible(&cfg, &secrets, validator, total_stake, &prev_hash, *slot)
        })
    });
    assert!(
        first_any.is_some(),
        "at least one public-devnet validator must be eligible within 64 slots"
    );
    assert!(
        first_any.unwrap() <= 16,
        "first pooled-eligible slot should be bounded for local mesh startup"
    );

    let v0 = cfg
        .genesis
        .validators
        .iter()
        .find(|v| v.index == 0)
        .expect("validator 0");
    let v0_secrets = validator_secrets(0, V0_VRF_SEED_HEX, V0_BLS_SEED_HEX);
    assert!(
        !slot_eligible(&cfg, &v0_secrets, v0, total_stake, &prev_hash, 1),
        "validator 0 is ineligible at slot 1; hub-only production can stall until later slots"
    );

    let first_v0 = (2u32..=300)
        .find(|slot| slot_eligible(&cfg, &v0_secrets, v0, total_stake, &prev_hash, *slot));
    assert!(
        first_v0.is_some(),
        "validator 0 should eventually become eligible on advancing slots"
    );
    assert!(
        first_any.unwrap() <= first_v0.unwrap(),
        "three-way --produce should reach first eligibility no later than hub-only"
    );
}
