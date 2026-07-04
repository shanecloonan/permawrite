//! `mfn-cli claims` smoke: query indexed authorship after claim mined (**M3.8**).

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mfn_cli::{KeyDerivation, WalletFile};
use mfn_wallet::ClaimingIdentity;

const DEVNET_SOLO_VRF_SEED_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
const DEVNET_SOLO_BLS_SEED_HEX: &str =
    "6565656565656565656565656565656565656565656565656565656565656565";
const CLAIM_DATA_ROOT_HEX: &str =
    "7777777777777777777777777777777777777777777777777777777777777777";

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
        "permawrite-claims-{test}-{}-{nanos}",
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
fn claims_for_lists_mined_authorship_claim() {
    let dir = unique_data_dir("claims_for");
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
            "claims smoke",
            "--fee",
            "10000",
            "--ring-size",
            "16",
        ])
        .output()
        .expect("wallet claim");
    assert!(claim_out.status.success(), "claim failed");

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

    let pk_hex = hex::encode(
        ClaimingIdentity::from_seed(&bls_seed)
            .claim_pubkey()
            .compress()
            .to_bytes(),
    );

    let for_out = mfn_cli()
        .args(["--rpc", &rpc2, "claims", "for", CLAIM_DATA_ROOT_HEX])
        .output()
        .expect("claims for");
    assert!(
        for_out.status.success(),
        "claims for stderr={}",
        String::from_utf8_lossy(&for_out.stderr)
    );
    let for_stdout = String::from_utf8_lossy(&for_out.stdout);
    assert!(for_stdout.contains("claim_count=1"), "stdout={for_stdout}");
    assert!(
        for_stdout.contains(&format!("claim_pubkey={pk_hex}")),
        "stdout={for_stdout}"
    );
    assert!(
        for_stdout.contains("message_hex=636c61696d7320736d6f6b65"),
        "stdout={for_stdout}"
    );

    let recent = mfn_cli()
        .args(["--rpc", &rpc2, "claims", "recent", "--limit", "5"])
        .output()
        .expect("claims recent");
    assert!(recent.status.success());
    let recent_out = String::from_utf8_lossy(&recent.stdout);
    assert!(
        recent_out.contains("claims_returned=1"),
        "stdout={recent_out}"
    );

    let by_pk = mfn_cli()
        .args(["--rpc", &rpc2, "claims", "by-pubkey", &pk_hex])
        .output()
        .expect("claims by-pubkey");
    assert!(
        by_pk.status.success(),
        "by-pubkey stderr={} stdout={}",
        String::from_utf8_lossy(&by_pk.stderr),
        String::from_utf8_lossy(&by_pk.stdout)
    );
    let by_pk_out = String::from_utf8_lossy(&by_pk.stdout);
    assert!(
        by_pk_out.contains(CLAIM_DATA_ROOT_HEX),
        "stdout={by_pk_out}"
    );

    let roots = mfn_cli()
        .args(["--rpc", &rpc2, "claims", "roots"])
        .output()
        .expect("claims roots");
    assert!(roots.status.success());
    let roots_out = String::from_utf8_lossy(&roots.stdout);
    assert!(
        roots_out.contains(CLAIM_DATA_ROOT_HEX),
        "stdout={roots_out}"
    );

    shutdown_child(&mut serve2);
    std::fs::remove_dir_all(&dir).ok();
}
