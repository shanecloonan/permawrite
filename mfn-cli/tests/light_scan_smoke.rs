//! Light-wallet CLI smoke: `wallet light-scan` after `mfnd step` (**M3.11**).

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
        "permawrite-light-scan-{test}-{}-{nanos}",
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
fn wallet_light_scan_after_solo_step_coinbase() {
    let dir = unique_data_dir("light_scan");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let wallet_path = dir.join("wallet.json");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator_wallet_payout.json");

    let mut file = WalletFile::new(&PAYOUT_SEED, KeyDerivation::PayoutStealthV1);
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
        .env(
            "MFND_SOLO_VRF_SEED_HEX",
            "0101010101010101010101010101010101010101010101010101010101010101",
        )
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
            "light-scan",
            "--pin-trusted-summary",
        ])
        .output()
        .expect("wallet light-scan");
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
    assert!(stdout.contains("sync_mode=light"));
    assert!(stdout.contains("weak_subjectivity=pinned"));
    assert!(stdout.contains("light_checkpoint_tip=1"));

    let reloaded = WalletFile::load(&wallet_path).expect("reload wallet");
    assert!(
        reloaded
            .light_checkpoint_hex
            .as_ref()
            .is_some_and(|h| h.len() > 64),
        "expected persisted light checkpoint"
    );

    let summary_path = dir.join("trusted-summary.json");
    let export = mfn_cli()
        .args([
            "--rpc",
            &rpc.to_string(),
            "--wallet",
            wallet_path.to_str().expect("utf8 path"),
            "wallet",
            "export-trusted-summary",
            "--height",
            "1",
            "--out",
            summary_path.to_str().expect("utf8 path"),
            "--pin",
        ])
        .output()
        .expect("export-trusted-summary");
    assert!(
        export.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&export.stderr)
    );
    let exported = std::fs::read_to_string(&summary_path).expect("read summary");
    assert!(exported.contains("checkpoint_digest"));

    let reloaded = WalletFile::load(&wallet_path).expect("reload after pin");
    assert!(reloaded.trusted_light_summary.is_some());

    let mut cleared = reloaded;
    cleared.trusted_light_summary = None;
    cleared
        .save(&wallet_path)
        .expect("clear pin for import test");

    let import = mfn_cli()
        .args([
            "--wallet",
            wallet_path.to_str().expect("utf8 path"),
            "wallet",
            "import-trusted-summary",
            "--verify-checkpoint",
            summary_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("import-trusted-summary");
    assert!(
        import.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&import.stderr)
    );
    let after_import = WalletFile::load(&wallet_path).expect("reload after import");
    assert!(after_import.trusted_light_summary.is_some());

    shutdown_child(&mut child);
    std::fs::remove_dir_all(&dir).ok();
}
