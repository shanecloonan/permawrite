//! In-process three-validator proposal → vote → seal (**M2.3.23**).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::DEFAULT_EMISSION_PARAMS;
use mfn_consensus::{
    build_coinbase, emission_at_height, pick_winner, PayoutAddress, ValidatorSecrets,
};
use mfn_crypto::vrf::vrf_keygen_from_seed;
use mfn_node::genesis_spec::{genesis_config_from_json_path, hex_seed32};
use mfn_node::network::ProductionHandler;
use mfn_node::store::{ChainPersistence, ChainStore};
use mfn_node::{ChainConfig, Mempool, MempoolConfig, P2pPeerSet, ProduceConfig, ProductionEngine};
use mfn_runtime::encode_block_proposal;
use mfn_runtime::proposal_wire::encode_committee_vote;
use mfn_runtime::{build_proposal, vote_on_proposal, BlockInputs, ProofPool, ProofPoolConfig};

#[test]
fn three_validators_proposal_vote_seal_in_process() {
    let spec =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_three_validators.json");
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
    let store: Arc<dyn ChainPersistence + Send + Sync> = Arc::new(ChainStore::new(&dir));

    let chain = Arc::new(Mutex::new(store.load_or_genesis(cfg).expect("genesis")));
    let pool = Arc::new(Mutex::new(Mempool::new(MempoolConfig::default())));
    let proof_pool = Arc::new(Mutex::new(ProofPool::new(ProofPoolConfig::default())));
    let genesis_id = *chain.lock().unwrap().genesis_id();
    let tip = Arc::new(Mutex::new((0u32, genesis_id)));
    let fanout = P2pPeerSet::new(genesis_id, Arc::clone(&tip), &dir, Arc::clone(&chain));

    let vals = chain.lock().unwrap().validators().to_vec();
    assert_eq!(vals.len(), 3);

    let vrf0 = vrf_keygen_from_seed(
        &hex_seed32(
            "vrf0",
            "0101010101010101010101010101010101010101010101010101010101010101",
        )
        .unwrap(),
    )
    .unwrap();
    let bls0 = bls_keygen_from_seed(
        &hex_seed32(
            "bls0",
            "6565656565656565656565656565656565656565656565656565656565656565",
        )
        .unwrap(),
    );
    let secrets0 = ValidatorSecrets {
        index: 0,
        vrf: vrf0,
        bls: bls0,
    };

    let engine = ProductionEngine::new(mfn_node::ProductionEngineDeps {
        chain: Arc::clone(&chain),
        pool: Arc::clone(&pool),
        proof_pool: Arc::clone(&proof_pool),
        store: Arc::clone(&store),
        tip_cell: Arc::clone(&tip),
        genesis_timestamp: genesis.timestamp,
        local: ProduceConfig {
            validator: vals[0].clone(),
            secrets: secrets0.clone(),
            slot_duration_ms: 1000,
        },
        peers: fanout,
    });

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
        let proposal = build_proposal(state, &vals[0], &secrets0, params, inputs).expect("propose");
        (params, proposal)
    };
    assert_eq!(
        engine.on_proposal_v1(&mfn_runtime::encode_block_proposal(&proposal)),
        "accepted:height=1"
    );

    let vrf1 = vrf_keygen_from_seed(
        &hex_seed32(
            "vrf1",
            "0202020202020202020202020202020202020202020202020202020202020202",
        )
        .unwrap(),
    )
    .unwrap();
    let bls1 = bls_keygen_from_seed(
        &hex_seed32(
            "bls1",
            "7676767676767676767676767676767676767676767676767676767676767676",
        )
        .unwrap(),
    );
    let s1 = ValidatorSecrets {
        index: 1,
        vrf: vrf1,
        bls: bls1,
    };
    let vrf2 = vrf_keygen_from_seed(
        &hex_seed32(
            "vrf2",
            "0303030303030303030303030303030303030303030303030303030303030303",
        )
        .unwrap(),
    )
    .unwrap();
    let bls2 = bls_keygen_from_seed(
        &hex_seed32(
            "bls2",
            "8787878787878787878787878787878787878787878787878787878787878787",
        )
        .unwrap(),
    );
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
    assert_eq!(chain.lock().unwrap().tip_height(), Some(1));
    // Quorum is 2/3 stake (6666 bps); self-vote + v1 seals before v2 is applied.
    assert!(engine
        .on_vote_v1(&encode_committee_vote(&proposal.header_hash, &vote2))
        .starts_with("rejected"));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn competing_proposals_at_same_height_converge_on_pick_winner() {
    let spec =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_three_validators.json");
    let genesis = genesis_config_from_json_path(&spec).expect("genesis spec");
    let cfg = ChainConfig::new(genesis.clone());
    let dir = std::env::temp_dir().join(format!(
        "permawrite-mv-compete-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let store: Arc<dyn ChainPersistence + Send + Sync> = Arc::new(ChainStore::new(&dir));
    let chain = Arc::new(Mutex::new(store.load_or_genesis(cfg).expect("genesis")));
    let pool = Arc::new(Mutex::new(Mempool::new(MempoolConfig::default())));
    let proof_pool = Arc::new(Mutex::new(ProofPool::new(ProofPoolConfig::default())));
    let genesis_id = *chain.lock().unwrap().genesis_id();
    let tip = Arc::new(Mutex::new((0u32, genesis_id)));
    let fanout = P2pPeerSet::new(genesis_id, Arc::clone(&tip), &dir, Arc::clone(&chain));
    let vals = chain.lock().unwrap().validators().to_vec();

    fn secrets_for(
        idx: u32,
        vrf_hex: &str,
        bls_hex: &str,
    ) -> (
        ValidatorSecrets,
        mfn_crypto::vrf::VrfKeypair,
        mfn_bls::BlsKeypair,
    ) {
        let vrf = vrf_keygen_from_seed(&hex_seed32("vrf", vrf_hex).unwrap()).unwrap();
        let bls = bls_keygen_from_seed(&hex_seed32("bls", bls_hex).unwrap());
        (
            ValidatorSecrets {
                index: idx,
                vrf: vrf.clone(),
                bls: bls.clone(),
            },
            vrf,
            bls,
        )
    }

    let (s0, _, _) = secrets_for(
        0,
        "0101010101010101010101010101010101010101010101010101010101010101",
        "6565656565656565656565656565656565656565656565656565656565656565",
    );
    let (s1, _, _) = secrets_for(
        1,
        "0202020202020202020202020202020202020202020202020202020202020202",
        "7676767676767676767676767676767676767676767676767676767676767676",
    );
    let (s2, _, _) = secrets_for(
        2,
        "0303030303030303030303030303030303030303030303030303030303030303",
        "8787878787878787878787878787878787878787878787878787878787878787",
    );

    let engine = ProductionEngine::new(mfn_node::ProductionEngineDeps {
        chain: Arc::clone(&chain),
        pool: Arc::clone(&pool),
        proof_pool: Arc::clone(&proof_pool),
        store: Arc::clone(&store),
        tip_cell: Arc::clone(&tip),
        genesis_timestamp: genesis.timestamp,
        local: ProduceConfig {
            validator: vals[0].clone(),
            secrets: s0.clone(),
            slot_duration_ms: 1000,
        },
        peers: fanout,
    });

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

    let (params, p0, p1) = {
        let guard = chain.lock().unwrap();
        let state = guard.state();
        let params = state.params;
        let p0 = build_proposal(state, &vals[0], &s0, params, inputs.clone()).expect("p0");
        let p1 = build_proposal(state, &vals[1], &s1, params, inputs).expect("p1");
        (params, p0, p1)
    };
    let candidates = [p0.producer_proof.clone(), p1.producer_proof.clone()];
    let winner = pick_winner(&candidates).expect("winner");
    let winning = if winner.validator_index == p0.producer_proof.validator_index {
        &p0
    } else {
        &p1
    };

    assert!(engine
        .on_proposal_v1(&encode_block_proposal(&p0))
        .starts_with("accepted:"));
    let second_label = engine.on_proposal_v1(&encode_block_proposal(&p1));
    assert!(
        second_label.starts_with("accepted:") || second_label == "rejected:competing:height=1",
        "unexpected second adopt: {second_label}"
    );

    let guard = chain.lock().unwrap();
    let state = guard.state();
    let producer = &vals[winner.validator_index as usize];
    let vote1 = vote_on_proposal(winning, state, &vals[1], &s1, producer, params).expect("v1 vote");
    let vote2 = vote_on_proposal(winning, state, &vals[2], &s2, producer, params).expect("v2 vote");
    drop(guard);

    assert!(engine
        .on_vote_v1(&encode_committee_vote(&winning.header_hash, &vote1))
        .starts_with("accepted"));
    assert_eq!(chain.lock().unwrap().tip_height(), Some(1));
    assert!(engine
        .on_vote_v1(&encode_committee_vote(&winning.header_hash, &vote2))
        .starts_with("rejected"));

    std::fs::remove_dir_all(&dir).ok();
}
