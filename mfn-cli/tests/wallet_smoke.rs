//! Wallet CLI smoke: scan coinbase from `mfnd step` via JSON-RPC (**M3.1**).

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mfn_cli::{KeyDerivation, WalletFile};
use mfn_consensus::emission_at_height;
use mfn_consensus::DEFAULT_EMISSION_PARAMS;

const PAYOUT_SEED: [u8; 32] = [0xab; 32];

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
        "permawrite-wallet-{test}-{}-{nanos}",
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
fn wallet_balance_after_solo_step_coinbase() {
    let dir = unique_data_dir("wallet_bal");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let wallet_path = dir.join("wallet.json");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator_wallet_payout.json");

    let file = WalletFile::new(&PAYOUT_SEED, KeyDerivation::PayoutStealthV1);
    file.save(&wallet_path).expect("write wallet");

    let step = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("--store")
        .arg("fs")
        .arg("step")
        .arg("--blocks")
        .arg("1")
        .env("MFND_SOLO_VRF_SEED_HEX", "0101010101010101010101010101010101010101010101010101010101010101")
        .env(
            "MFND_SOLO_BLS_SEED_HEX",
            "6565656565656565656565656565656565656565656565656565656565656565",
        )
        .output()
        .expect("mfnd step");
    assert!(
        step.status.success(),
        "step stderr={}",
        String::from_utf8_lossy(&step.stderr)
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

    let out = mfn_cli()
        .args([
            "--rpc",
            &rpc.to_string(),
            "--wallet",
            wallet_path.to_str().expect("utf8 path"),
            "wallet",
            "balance",
        ])
        .output()
        .expect("wallet balance");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let expected = emission_at_height(1, &DEFAULT_EMISSION_PARAMS);
    assert!(
        stdout.contains(&format!("balance={expected}")),
        "stdout={stdout}"
    );
    assert!(stdout.contains("owned_count=1"));
    assert!(stdout.contains("scan_height=1"));

    shutdown_child(&mut child);
    std::fs::remove_dir_all(&dir).ok();
}
