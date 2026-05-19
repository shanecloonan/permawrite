//! `mfn-cli uploads` smoke: list mined storage via `list_recent_uploads` (**M3.9**).

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
        "permawrite-uploads-{test}-{}-{nanos}",
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
fn uploads_list_shows_mined_storage_commitment() {
    let dir = unique_data_dir("uploads_list");
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
        .expect("step1");
    assert!(step1.status.success(), "step1");

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
    assert!(step2.status.success(), "step2");

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

    let list_out = mfn_cli()
        .args(["--rpc", &rpc2, "uploads", "list", "--limit", "10"])
        .output()
        .expect("uploads list");
    assert!(
        list_out.status.success(),
        "uploads list stderr={}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(
        list_stdout.contains("uploads_returned=1"),
        "stdout={list_stdout}"
    );
    assert!(
        list_stdout.contains(&format!("commitment_hash={commitment_hash}")),
        "stdout={list_stdout}"
    );
    assert!(
        list_stdout.contains("last_proven_height=2"),
        "stdout={list_stdout}"
    );

    let with_claims = mfn_cli()
        .args([
            "--rpc",
            &rpc2,
            "uploads",
            "list",
            "--limit",
            "5",
            "--include-claims",
        ])
        .output()
        .expect("uploads list include-claims");
    assert!(with_claims.status.success());
    let claims_stdout = String::from_utf8_lossy(&with_claims.stdout);
    assert!(
        claims_stdout.contains("include_claims=true"),
        "stdout={claims_stdout}"
    );
    assert!(
        claims_stdout.contains("claims_count=0"),
        "stdout={claims_stdout}"
    );

    shutdown_child(&mut serve2);
    std::fs::remove_dir_all(&dir).ok();
}
