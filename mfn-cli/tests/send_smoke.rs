//! Wallet send smoke: CLSAG transfer via `submit_tx`, mined by `mfnd step` (**M3.2**).

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
use mfn_wallet::Wallet;

const DEVNET_SOLO_VRF_SEED_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
const DEVNET_SOLO_BLS_SEED_HEX: &str =
    "6565656565656565656565656565656565656565656565656565656565656565";
const BOB_SEED: [u8; 32] = [0xc0; 32];
const TRANSFER_AMOUNT: u64 = 50_000;
const TRANSFER_FEE: u64 = 10_000;

fn mfnd_bin() -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("target");
    path.push(profile);
    path.push(format!("mfnd{}", std::env::consts::EXE_SUFFIX));
    if path.is_file() {
        return path;
    }
    if let Some(p) = std::env::var_os("CARGO_BIN_EXE_mfnd") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return path;
        }
    }
    panic!(
        "mfnd binary not found at {}; run `cargo build -p mfn-node --bin mfnd --{profile}`",
        path.display()
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
        "permawrite-send-{test}-{}-{nanos}",
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

fn bob_recipient_hex() -> (String, String) {
    let bob = Wallet::from_seed(&BOB_SEED);
    let view = hex::encode(bob.keys().view_pub().compress().to_bytes());
    let spend = hex::encode(bob.keys().spend_pub().compress().to_bytes());
    (view, spend)
}

#[test]
fn wallet_send_mined_by_step_reaches_recipient() {
    let dir = unique_data_dir("send_mine");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator_synth_decoys.json");

    let mut bls_seed = [0u8; 32];
    hex::decode_to_slice(DEVNET_SOLO_BLS_SEED_HEX, &mut bls_seed).expect("bls hex");
    let alice_path = dir.join("alice.json");
    let bob_path = dir.join("bob.json");
    WalletFile::new(&bls_seed, KeyDerivation::PayoutStealthV1)
        .save(&alice_path)
        .expect("alice wallet");
    WalletFile::new(&BOB_SEED, KeyDerivation::MfnWalletV1)
        .save(&bob_path)
        .expect("bob wallet");

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
        .expect("step 1");
    assert!(
        step1.status.success(),
        "step1 stderr={}",
        String::from_utf8_lossy(&step1.stderr)
    );

    let mut child = mfnd()
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
        .expect("spawn mfnd");
    let rpc = read_serve_listening(&mut child);

    let (bob_view, bob_spend) = bob_recipient_hex();
    let send = mfn_cli()
        .args([
            "--rpc",
            &rpc.to_string(),
            "--wallet",
            alice_path.to_str().expect("utf8"),
            "wallet",
            "send",
            &bob_view,
            &bob_spend,
            &TRANSFER_AMOUNT.to_string(),
            "--fee",
            &TRANSFER_FEE.to_string(),
            "--ring-size",
            "16",
        ])
        .output()
        .expect("wallet send");
    assert!(
        send.status.success(),
        "send stderr={}",
        String::from_utf8_lossy(&send.stderr)
    );
    let send_out = String::from_utf8_lossy(&send.stdout);
    assert!(send_out.contains("outcome=Fresh"), "stdout={send_out}");
    assert!(
        send_out.contains("mempool_len=1") || send_out.contains("mempool_len=2"),
        "stdout={send_out}"
    );

    let mp = mfn_cli()
        .args(["--rpc", &rpc.to_string(), "mempool"])
        .output()
        .expect("mempool");
    assert!(mp.status.success());
    let mp_out = String::from_utf8_lossy(&mp.stdout);
    assert!(
        mp_out.contains("mempool_len=1"),
        "mempool before step: {mp_out}"
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

    shutdown_child(&mut child);

    let mfnd_exe = mfnd_bin();
    let step2 = Command::new(&mfnd_exe)
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
        .expect("step 2");
    assert!(
        step2.status.success(),
        "step2 stderr={}",
        String::from_utf8_lossy(&step2.stderr)
    );
    let step2_out = String::from_utf8_lossy(&step2.stdout);
    assert!(
        step2_out.contains("new_tip_height=2"),
        "step2 stdout={step2_out}"
    );
    let step2_err = String::from_utf8_lossy(&step2.stderr);
    assert!(
        (step2_out.contains("mfnd_step_mempool_load")
            || step2_err.contains("mfnd_step_mempool_load"))
            && (step2_out.contains("admitted=1") || step2_err.contains("admitted=1")),
        "step2 should mine persisted mempool tx (mfnd={}), stdout={step2_out} stderr={step2_err}",
        mfnd_exe.display()
    );

    let store2 = NodeStore::open(StoreBackend::Fs, &dir).expect("store2");
    let chain = store2.load_or_genesis(ChainConfig::new(gc)).expect("chain");
    let blocks = store2.read_block_log().expect("blocks");
    assert_eq!(blocks.len(), 2, "expected two blocks in log");
    assert!(
        blocks[1].txs.len() >= 2,
        "block at height 2 should include coinbase + transfer, got {} txs",
        blocks[1].txs.len()
    );
    let _ = chain;

    let mut child2 = mfnd()
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
        .expect("spawn mfnd 2");
    let rpc2 = read_serve_listening(&mut child2);

    let bal = mfn_cli()
        .args([
            "--rpc",
            &rpc2.to_string(),
            "--wallet",
            bob_path.to_str().expect("utf8"),
            "wallet",
            "balance",
        ])
        .output()
        .expect("bob balance");
    assert!(
        bal.status.success(),
        "balance stderr={}",
        String::from_utf8_lossy(&bal.stderr)
    );
    let bal_out = String::from_utf8_lossy(&bal.stdout);
    assert!(
        bal_out.contains(&format!("balance={TRANSFER_AMOUNT}")),
        "stdout={bal_out}"
    );
    assert!(bal_out.contains("owned_count=1"));

    shutdown_child(&mut child2);
    std::fs::remove_dir_all(&dir).ok();
}
