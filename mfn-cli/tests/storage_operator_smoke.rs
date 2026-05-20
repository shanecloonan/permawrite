//! End-to-end smoke: wallet upload artifact → operator prove → mined SPoRA proof (**M6.1**).

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mfn_cli::{KeyDerivation, WalletFile};

const DEVNET_SOLO_VRF_SEED_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
const DEVNET_SOLO_BLS_SEED_HEX: &str =
    "6565656565656565656565656565656565656565656565656565656565656565";
const UPLOAD_BYTES: usize = 512;

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

fn storage_operator_bin() -> PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("target");
    path.push(profile);
    path.push(format!(
        "mfn-storage-operator{}",
        std::env::consts::EXE_SUFFIX
    ));
    if path.is_file() {
        return path;
    }
    if let Some(p) = std::env::var_os("CARGO_BIN_EXE_mfn-storage-operator") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return path;
        }
    }
    panic!(
        "mfn-storage-operator binary not found at {}; run `cargo build -p mfn-storage-operator --release`",
        path.display()
    );
}

fn mfnd() -> Command {
    Command::new(mfnd_bin())
}

fn mfn_cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mfn-cli"))
}

fn storage_operator() -> Command {
    Command::new(storage_operator_bin())
}

fn unique_data_dir(test: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "permawrite-storage-op-{test}-{}-{nanos}",
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

fn mfnd_step(dir: &PathBuf, spec: &PathBuf, blocks: &str) {
    let out = mfnd()
        .args(["--data-dir"])
        .arg(dir)
        .arg("--genesis")
        .arg(spec)
        .arg("--store")
        .arg("fs")
        .arg("step")
        .arg("--blocks")
        .arg(blocks)
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .output()
        .expect("mfnd step");
    assert!(
        out.status.success(),
        "step blocks={blocks} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn operator_prove_from_wallet_artifact_then_mine_proof() {
    let dir = unique_data_dir("prove_pool");
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

    mfnd_step(&dir, &spec, "1");

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
    let rpc = read_serve_listening(&mut serve).to_string();

    let upload_out = mfn_cli()
        .args(["--rpc", &rpc, "--wallet"])
        .arg(&wallet_path)
        .args([
            "wallet",
            "upload",
            payload_path.to_str().expect("utf8 path"),
            "--fee",
            "10000",
            "--ring-size",
            "8",
        ])
        .output()
        .expect("wallet upload");
    assert!(
        upload_out.status.success(),
        "upload stderr={}",
        String::from_utf8_lossy(&upload_out.stderr)
    );
    let upload_stdout = String::from_utf8_lossy(&upload_out.stdout);
    let commitment_hash = parse_stdout_field(&upload_stdout, "storage_commitment_hash");
    assert!(
        upload_stdout.contains("artifact_dir="),
        "expected upload artifact persistence:\n{upload_stdout}"
    );

    shutdown_child(&mut serve);
    mfnd_step(&dir, &spec, "1");

    let mut serve2 = mfnd()
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
        .expect("serve2");
    let rpc2 = read_serve_listening(&mut serve2).to_string();

    let prove_out = mfn_cli()
        .args(["--rpc", &rpc2, "--wallet"])
        .arg(&wallet_path)
        .args(["operator", "prove", &commitment_hash])
        .output()
        .expect("operator prove");
    assert!(
        prove_out.status.success(),
        "prove stderr={}",
        String::from_utf8_lossy(&prove_out.stderr)
    );
    let prove_stdout = String::from_utf8_lossy(&prove_out.stdout);
    assert!(prove_stdout.contains("pool_len="), "stdout={prove_stdout}");
    let pool_len: u64 = parse_stdout_field(&prove_stdout, "pool_len")
        .parse()
        .expect("pool_len u64");
    assert!(pool_len >= 1, "pool_len={pool_len}");

    let pool_out = mfn_cli()
        .args(["--rpc", &rpc2, "operator", "pool"])
        .output()
        .expect("operator pool");
    assert!(pool_out.status.success());
    let pool_stdout = String::from_utf8_lossy(&pool_out.stdout);
    assert!(
        pool_stdout.contains("pool_len=1") || pool_stdout.contains(&format!("pool_len={pool_len}")),
        "stdout={pool_stdout}"
    );

    shutdown_child(&mut serve2);
    mfnd_step(&dir, &spec, "1");

    let mut serve3 = mfnd()
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
        .expect("serve3");
    let rpc3 = read_serve_listening(&mut serve3).to_string();

    let list_out = mfn_cli()
        .args(["--rpc", &rpc3, "uploads", "list", "--limit", "10"])
        .output()
        .expect("uploads list");
    assert!(list_out.status.success());
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(
        list_stdout.contains(&format!("commitment_hash={commitment_hash}")),
        "stdout={list_stdout}"
    );
    assert!(
        list_stdout.contains("last_proven_height=3"),
        "stdout={list_stdout}"
    );

    let status_out = mfn_cli()
        .args(["--rpc", &rpc3, "--wallet"])
        .arg(&wallet_path)
        .args(["uploads", "status"])
        .output()
        .expect("uploads status");
    assert!(status_out.status.success());
    let status_stdout = String::from_utf8_lossy(&status_out.stdout);
    assert!(
        status_stdout.contains("reconcile_matched=1"),
        "stdout={status_stdout}"
    );
    assert!(
        status_stdout.contains("local_artifact=yes"),
        "stdout={status_stdout}"
    );

    shutdown_child(&mut serve3);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn storage_operator_run_once_submits_proof() {
    let dir = unique_data_dir("daemon_once");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator_synth_decoys.json");

    let mut bls_seed = [0u8; 32];
    hex::decode_to_slice(DEVNET_SOLO_BLS_SEED_HEX, &mut bls_seed).expect("bls hex");
    let wallet_path = dir.join("bob.json");
    WalletFile::new(&bls_seed, KeyDerivation::PayoutStealthV1)
        .save(&wallet_path)
        .expect("wallet");

    let payload_path = dir.join("payload.bin");
    std::fs::write(&payload_path, b"mfn-storage-operator M6.1").expect("write payload");

    mfnd_step(&dir, &spec, "1");

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
    let rpc = read_serve_listening(&mut serve).to_string();

    let upload_out = mfn_cli()
        .args(["--rpc", &rpc, "--wallet"])
        .arg(&wallet_path)
        .args([
            "wallet",
            "upload",
            payload_path.to_str().expect("utf8 path"),
            "--fee",
            "10000",
            "--ring-size",
            "8",
        ])
        .output()
        .expect("wallet upload");
    assert!(upload_out.status.success());

    shutdown_child(&mut serve);
    mfnd_step(&dir, &spec, "1");

    let mut serve2 = mfnd()
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
        .expect("serve2");
    let rpc2 = read_serve_listening(&mut serve2).to_string();

    let daemon_out = storage_operator()
        .args([
            "run",
            "--rpc",
            &rpc2,
            "--wallet",
            wallet_path.to_str().expect("utf8"),
            "--once",
        ])
        .output()
        .expect("mfn-storage-operator run --once");
    assert!(
        daemon_out.status.success(),
        "daemon stderr={}",
        String::from_utf8_lossy(&daemon_out.stderr)
    );
    let daemon_stdout = String::from_utf8_lossy(&daemon_out.stdout);
    assert!(
        daemon_stdout.contains("mfno_cycle_summary") && daemon_stdout.contains("submitted=1"),
        "stdout={daemon_stdout}"
    );

    shutdown_child(&mut serve2);
    std::fs::remove_dir_all(&dir).ok();
}
