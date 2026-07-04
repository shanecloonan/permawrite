//! Wallet claim smoke: MFCL authorship claim via `submit_tx`, mined by `mfnd step` (**M3.4**).

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mfn_cli::{KeyDerivation, WalletFile};
use mfn_node::{
    genesis_config_from_json_path, ChainConfig, Mempool, MempoolConfig, NodeStore, StoreBackend,
};
use mfn_store::{load_mempool, ChainPersistence};
use mfn_wallet::ClaimingIdentity;

const DEVNET_SOLO_VRF_SEED_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
const DEVNET_SOLO_BLS_SEED_HEX: &str =
    "6565656565656565656565656565656565656565656565656565656565656565";
const CLAIM_DATA_ROOT_HEX: &str =
    "7777777777777777777777777777777777777777777777777777777777777777";
const CLAIM_FEE: u64 = 10_000;

fn mfnd_bin() -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut target_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    target_path.push("..");
    target_path.push("target");
    target_path.push(profile);
    target_path.push(format!("mfnd{}", std::env::consts::EXE_SUFFIX));
    if target_path.is_file() {
        return target_path;
    }
    if let Some(p) = std::env::var_os("CARGO_BIN_EXE_mfnd") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return path;
        }
    }
    panic!(
        "mfnd binary not found at {}; run `cargo build -p mfn-node --bin mfnd --{profile}`",
        target_path.display()
    );
}

fn mfnd() -> Command {
    Command::new(mfnd_bin())
}

fn mfn_cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mfn-cli"))
}

fn unique_data_dir(test: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "permawrite-claim-{test}-{}-{nanos}",
        std::process::id()
    ))
}

fn read_serve_listening(child: &mut Child) -> SocketAddr {
    let stdout = child.stdout.as_mut().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if std::time::Instant::now() >= deadline {
            panic!("timeout waiting for mfnd_serve_listening=");
        }
        line.clear();
        let n = reader.read_line(&mut line).expect("read stdout");
        if n == 0 {
            panic!("mfnd exited before listen line");
        }
        if let Some(rest) = line.strip_prefix("mfnd_serve_listening=") {
            return rest.trim().parse().expect("rpc addr");
        }
    }
}

fn shutdown_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn wallet_claim_mined_by_step_indexed_on_chain() {
    let dir = unique_data_dir("claim_mine");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator_synth_decoys.json");

    let mut bls_seed = [0u8; 32];
    hex::decode_to_slice(DEVNET_SOLO_BLS_SEED_HEX, &mut bls_seed).expect("bls hex");
    let alice_path = dir.join("alice.json");
    WalletFile::new(&bls_seed, KeyDerivation::PayoutStealthV1)
        .save(&alice_path)
        .expect("alice wallet");

    let step1 = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("--store")
        .arg("fs")
        .arg("step")
        .arg("--blocks")
        .arg("1")
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .output()
        .expect("step1");
    assert!(
        step1.status.success(),
        "step1 stderr={}",
        String::from_utf8_lossy(&step1.stderr)
    );

    let mut serve = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("--store")
        .arg("fs")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("serve")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("serve");
    let rpc_addr = read_serve_listening(&mut serve);
    let rpc = rpc_addr.to_string();

    let claim_out = mfn_cli()
        .args(["--rpc", &rpc, "--wallet"])
        .arg(&alice_path)
        .args([
            "wallet",
            "claim",
            CLAIM_DATA_ROOT_HEX,
            "--message",
            "signed by claiming key",
            "--fee",
            &CLAIM_FEE.to_string(),
            "--ring-size",
            "16",
        ])
        .output()
        .expect("claim");
    assert!(
        claim_out.status.success(),
        "wallet claim failed: stdout={} stderr={}",
        String::from_utf8_lossy(&claim_out.stdout),
        String::from_utf8_lossy(&claim_out.stderr)
    );
    let claim_stdout = String::from_utf8_lossy(&claim_out.stdout);
    assert!(
        claim_stdout.contains("outcome=Fresh"),
        "stdout={claim_stdout}"
    );
    assert!(
        claim_stdout.contains("mempool_len=1"),
        "claim tx should be alone in mempool; stdout={claim_stdout}"
    );

    let mempool_file = dir.join("mempool.bytes");
    assert!(
        mempool_file.is_file(),
        "mempool.bytes missing under {}",
        dir.display()
    );
    let mempool_bytes = std::fs::read(&mempool_file).expect("read mempool.bytes");
    assert!(
        mempool_bytes.len() > 32,
        "mempool snapshot too small ({} bytes)",
        mempool_bytes.len()
    );

    let gc = genesis_config_from_json_path(&spec).expect("genesis");
    let store = NodeStore::open(StoreBackend::Fs, &dir).expect("store");
    let chain = store
        .load_or_genesis(ChainConfig::new(gc.clone()))
        .expect("chain");
    let mut pool = Mempool::new(MempoolConfig::default());
    let preload = load_mempool(&store, &mut pool, chain.state()).expect("preload");
    assert_eq!(
        preload.admitted, 1,
        "preload loaded={} admitted={} skipped={}",
        preload.loaded, preload.admitted, preload.skipped
    );

    shutdown_child(&mut serve);

    let step2 = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("--store")
        .arg("fs")
        .arg("step")
        .arg("--blocks")
        .arg("1")
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .output()
        .expect("step2");
    assert!(
        step2.status.success(),
        "step2 stderr={}",
        String::from_utf8_lossy(&step2.stderr)
    );
    let step2_out = String::from_utf8_lossy(&step2.stdout);
    let step2_err = String::from_utf8_lossy(&step2.stderr);
    assert!(
        step2_out.contains("new_tip_height=2"),
        "step2 stdout={step2_out} stderr={step2_err}"
    );
    assert!(
        (step2_out.contains("mfnd_step_mempool_load")
            || step2_err.contains("mfnd_step_mempool_load"))
            && (step2_out.contains("admitted=1") || step2_err.contains("admitted=1")),
        "step2 should mine persisted claim tx; stdout={step2_out} stderr={step2_err}"
    );

    let store2 = NodeStore::open(StoreBackend::Fs, &dir).expect("store2");
    let blocks = store2.read_block_log().expect("blocks");
    assert_eq!(blocks.len(), 2, "expected two blocks in log");
    assert!(
        blocks[1].txs.len() >= 2,
        "block at height 2 should include coinbase + claim, got {} txs",
        blocks[1].txs.len()
    );

    let chain = store2.load_or_genesis(ChainConfig::new(gc)).expect("chain");
    assert_eq!(chain.tip_height(), Some(2));
    let mut data_root = [0u8; 32];
    hex::decode_to_slice(CLAIM_DATA_ROOT_HEX, &mut data_root).expect("data_root hex");
    let pk_bytes = ClaimingIdentity::from_seed(&bls_seed)
        .claim_pubkey()
        .compress()
        .to_bytes();
    let rec = chain
        .state()
        .claims
        .get(&(data_root, pk_bytes))
        .expect("claim must be indexed after step");
    assert_eq!(rec.claim.message, b"signed by claiming key".as_slice());
    assert_eq!(rec.claim.data_root, data_root);

    std::fs::remove_dir_all(&dir).ok();
}
