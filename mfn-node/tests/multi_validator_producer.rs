//! In-process three-validator proposal → vote → seal (**M2.3.23**).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{build_coinbase, emission_at_height, PayoutAddress, ValidatorSecrets};
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_node::genesis_spec::{genesis_config_from_json_path, hex_seed32};
use mfn_node::network::ProductionHandler;
use mfn_node::{
    ChainConfig, Mempool, MempoolConfig, P2pPeerSet, ProduceConfig, ProductionEngine,
};
use mfn_node::store::{ChainPersistence, ChainStore};
use mfn_runtime::proposal_wire::encode_committee_vote;
use mfn_consensus::DEFAULT_EMISSION_PARAMS;
use mfn_runtime::{build_proposal, vote_on_proposal, BlockInputs};

#[test]
fn three_validators_proposal_vote_seal_in_process() {
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/devnet_three_validators.json");
    let genesis = genesis_config_from_json_path(&spec).expect("genesis spec");
    let cfg = ChainConfig::new(genesis.clone());
    let dir = std::env::temp_dir().join(format!(
        "permawrite-mv-producer-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let store: Arc<dyn ChainPersistence + Send + Sync> =
        Arc::new(ChainStore::new(&dir));

    let chain = Arc::new(Mutex::new(store.load_or_genesis(cfg).expect("genesis")));
    let pool = Arc::new(Mutex::new(Mempool::new(MempoolConfig::default())));
    let genesis_id = *chain.lock().unwrap().genesis_id();
    let tip = Arc::new(Mutex::new((0u32, genesis_id)));
    let fanout = P2pPeerSet::new(genesis_id, Arc::clone(&tip), &dir);

    let vals = chain.lock().unwrap().validators().to_vec();
    assert_eq!(vals.len(), 3);

    let vrf0 = vrf_keygen_from_seed(&hex_seed32("vrf0", "0101010101010101010101010101010101010101010101010101010101010101").unwrap()).unwrap();
    let bls0 = bls_keygen_from_seed(&hex_seed32("bls0", "6565656565656565656565656565656565656565656565656565656565656565").unwrap());
    let secrets0 = ValidatorSecrets {
        index: 0,
        vrf: vrf0,
        bls: bls0,
    };

    let engine = ProductionEngine::new(
        Arc::clone(&chain),
        Arc::clone(&pool),
        Arc::clone(&store),
        Arc::clone(&tip),
        genesis_id,
        genesis.timestamp,
        ProduceConfig {
            validator: vals[0].clone(),
            secrets: secrets0.clone(),
            slot_duration_ms: 1000,
        },
        fanout,
    );

    let payout = vals[0].payout.as_ref().expect("payout");
    let cb = build_coinbase(
        1,
        emission_at_height(1, &DEFAULT_EMISSION_PARAMS),
        &PayoutAddress {
            view_pub: payout.view_pub,
            spend_pub: payout.spend_pub,
        },
    )
    .expect("coinbase");
    let inputs = BlockInputs {
        height: 1,
        slot: 1,
        timestamp: genesis.timestamp.saturating_add(1),
        txs: vec![cb],
        bond_ops: vec![],
        slashings: vec![],
        storage_proofs: vec![],
    };

    let (params, proposal) = {
        let guard = chain.lock().unwrap();
        let state = guard.state();
        let params = state.params;
        let proposal =
            build_proposal(state, &vals[0], &secrets0, params, inputs).expect("propose");
        (params, proposal)
    };
    assert_eq!(
        engine.on_proposal_v1(&mfn_runtime::encode_block_proposal(&proposal)),
        "accepted:height=1"
    );

    let vrf1 = vrf_keygen_from_seed(&hex_seed32("vrf1", "0202020202020202020202020202020202020202020202020202020202020202").unwrap()).unwrap();
    let bls1 = bls_keygen_from_seed(&hex_seed32("bls1", "7676767676767676767676767676767676767676767676767676767676767676").unwrap());
    let s1 = ValidatorSecrets {
        index: 1,
        vrf: vrf1,
        bls: bls1,
    };
    let vrf2 = vrf_keygen_from_seed(&hex_seed32("vrf2", "0303030303030303030303030303030303030303030303030303030303030303").unwrap()).unwrap();
    let bls2 = bls_keygen_from_seed(&hex_seed32("bls2", "8787878787878787878787878787878787878787878787878787878787878787").unwrap());
    let s2 = ValidatorSecrets {
        index: 2,
        vrf: vrf2,
        bls: bls2,
    };

    let guard = chain.lock().unwrap();
    let state = guard.state();
    let vote1 = vote_on_proposal(&proposal, state, &vals[1], &s1, &vals[0], params).expect("v1");
    let vote2 = vote_on_proposal(&proposal, state, &vals[2], &s2, &vals[0], params).expect("v2");
    drop(guard);

    assert!(engine
        .on_vote_v1(&encode_committee_vote(&proposal.header_hash, &vote1))
        .starts_with("accepted"));
    assert!(engine
        .on_vote_v1(&encode_committee_vote(&proposal.header_hash, &vote2))
        .starts_with("accepted"));

    assert_eq!(chain.lock().unwrap().tip_height(), Some(1));

    std::fs::remove_dir_all(&dir).ok();
}
