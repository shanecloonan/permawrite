//! Wallet upload smoke: storage commitment via `submit_tx`, mined by `mfnd step` (**M3.3**).

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mfn_cli::{KeyDerivation, WalletFile};
use mfn_node::{genesis_config_from_json_path, ChainConfig, NodeStore, StoreBackend};
use mfn_store::ChainPersistence;

const DEVNET_SOLO_VRF_SEED_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
const DEVNET_SOLO_BLS_SEED_HEX: &str =
    "6565656565656565656565656565656565656565656565656565656565656565";
const UPLOAD_BYTES: usize = 1024;

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
        return PathBuf::from(p);
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
        "permawrite-upload-{test}-{}-{nanos}",
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

fn parse_stdout_field(stdout: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::to_string))
        .unwrap_or_else(|| panic!("stdout missing {prefix}:\n{stdout}"))
}

#[test]
fn wallet_upload_mined_by_step_anchors_storage() {
    let dir = unique_data_dir("upload_mine");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator_synth_decoys.json");

    let mut bls_seed = [0u8; 32];
    hex::decode_to_slice(DEVNET_SOLO_BLS_SEED_HEX, &mut bls_seed).expect("bls hex");
    let wallet_path = dir.join("alice.json");
    WalletFile::new(&bls_seed, KeyDerivation::PayoutStealthV1)
        .save(&wallet_path)
        .expect("wallet");

    let payload_path = dir.join("payload.bin");
    let payload: Vec<u8> = (0u8..255u8).cycle().take(UPLOAD_BYTES).collect();
    std::fs::write(&payload_path, &payload).expect("write payload");

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
    assert!(step1.status.success(), "step1 stderr={}", String::from_utf8_lossy(&step1.stderr));

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

    let upload = mfn_cli()
        .args([
            "--rpc",
            &rpc.to_string(),
            "--wallet",
            wallet_path.to_str().expect("utf8"),
            "wallet",
            "upload",
            payload_path.to_str().expect("utf8"),
            "--replication",
            "3",
        ])
        .output()
        .expect("wallet upload");
    assert!(
        upload.status.success(),
        "upload stderr={}",
        String::from_utf8_lossy(&upload.stderr)
    );
    let upload_out = String::from_utf8_lossy(&upload.stdout);
    assert!(upload_out.contains("outcome=Fresh"), "stdout={upload_out}");
    let commitment_hash = parse_stdout_field(&upload_out, "storage_commitment_hash");
    assert_eq!(commitment_hash.len(), 64);

    let mp = mfn_cli()
        .args(["--rpc", &rpc.to_string(), "mempool"])
        .output()
        .expect("mempool");
    assert!(mp.status.success());
    assert!(
        String::from_utf8_lossy(&mp.stdout).contains("mempool_len=1"),
        "mempool after upload"
    );

    shutdown_child(&mut child);

    let step2 = Command::new(mfnd_bin())
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
        step2_out.contains("mfnd_step_mempool_load") && step2_out.contains("admitted=1"),
        "step2 stdout={step2_out}"
    );

    let gc = genesis_config_from_json_path(&spec).expect("genesis");
    let store = NodeStore::open(StoreBackend::Fs, &dir).expect("store");
    let chain = store
        .load_or_genesis(ChainConfig::new(gc))
        .expect("chain");
    let mut hash_bytes = [0u8; 32];
    hex::decode_to_slice(&commitment_hash, &mut hash_bytes).expect("commitment hex");
    assert!(
        chain.state().storage.contains_key(&hash_bytes),
        "upload not in chain state after step"
    );

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

    let listed = mfn_cli()
        .args([
            "--rpc",
            &rpc2.to_string(),
            "call",
            "list_recent_uploads",
            "--params",
            r#"{"limit":10}"#,
        ])
        .output()
        .expect("list_recent_uploads");
    assert!(listed.status.success());
    let list_json: serde_json::Value = serde_json::from_slice(&listed.stdout).expect("json");
    let uploads = list_json["uploads"].as_array().expect("uploads array");
    assert!(
        uploads.iter().any(|u| {
            u.get("commitment_hash")
                .and_then(|x| x.as_str())
                .is_some_and(|h| h.eq_ignore_ascii_case(&commitment_hash))
        }),
        "list_recent_uploads missing commitment: {list_json}"
    );

    shutdown_child(&mut child2);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn wallet_upload_with_message_mines_bound_authorship_claim() {
    let dir = unique_data_dir("upload_claim");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator_synth_decoys.json");

    let mut bls_seed = [0u8; 32];
    hex::decode_to_slice(DEVNET_SOLO_BLS_SEED_HEX, &mut bls_seed).expect("bls hex");
    let wallet_path = dir.join("alice.json");
    WalletFile::new(&bls_seed, KeyDerivation::PayoutStealthV1)
        .save(&wallet_path)
        .expect("wallet");

    let payload_path = dir.join("payload.bin");
    std::fs::write(&payload_path, b"permawrite upload attribution").expect("write payload");

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
    assert!(step1.status.success(), "step1 stderr={}", String::from_utf8_lossy(&step1.stderr));

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

    let upload = mfn_cli()
        .args([
            "--rpc",
            &rpc.to_string(),
            "--wallet",
            wallet_path.to_str().expect("utf8"),
            "wallet",
            "upload",
            payload_path.to_str().expect("utf8"),
            "--replication",
            "3",
            "--message",
            "authored on upload",
        ])
        .output()
        .expect("wallet upload");
    assert!(
        upload.status.success(),
        "upload stderr={}",
        String::from_utf8_lossy(&upload.stderr)
    );
    let upload_out = String::from_utf8_lossy(&upload.stdout);
    assert!(upload_out.contains("authorship_claim=bound"), "stdout={upload_out}");
    let commitment_hash = parse_stdout_field(&upload_out, "storage_commitment_hash");
    let data_root_hex = parse_stdout_field(&upload_out, "data_root");

    shutdown_child(&mut child);

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
        .expect("step 2");
    assert!(step2.status.success(), "step2 stderr={}", String::from_utf8_lossy(&step2.stderr));

    let gc = genesis_config_from_json_path(&spec).expect("genesis");
    let store = NodeStore::open(StoreBackend::Fs, &dir).expect("store");
    let chain = store
        .load_or_genesis(ChainConfig::new(gc))
        .expect("chain");
    let mut commit_bytes = [0u8; 32];
    hex::decode_to_slice(&commitment_hash, &mut commit_bytes).expect("commit hex");
    assert!(chain.state().storage.contains_key(&commit_bytes));

    let mut data_root = [0u8; 32];
    hex::decode_to_slice(&data_root_hex, &mut data_root).expect("data_root hex");
    let pk_bytes = mfn_wallet::ClaimingIdentity::from_seed(&bls_seed)
        .claim_pubkey()
        .compress()
        .to_bytes();
    let rec = chain
        .state()
        .claims
        .get(&(data_root, pk_bytes))
        .expect("bound claim indexed");
    assert_eq!(rec.claim.message, b"authored on upload".as_slice());
    assert_eq!(rec.claim.commit_hash, commit_bytes);
    assert_eq!(rec.claim.data_root, data_root);

    std::fs::remove_dir_all(&dir).ok();
}
