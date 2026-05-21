//! End-to-end smoke: wallet upload → P2P ChunkV1 push → chunk-inbox → assemble → prove (**M7.3**).

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
        "permawrite-chunk-p2p-{test}-{}-{nanos}",
        std::process::id()
    ))
}

fn read_stdout_line_with_prefix(child: &mut Child, prefix: &str, timeout: Duration) -> String {
    let stdout = child.stdout.as_mut().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::time::Instant::now() >= deadline {
            panic!("timeout waiting for {prefix}");
        }
        line.clear();
        let n = reader.read_line(&mut line).expect("read stdout");
        if n == 0 {
            panic!("process exited before {prefix}");
        }
        if let Some(rest) = line.strip_prefix(prefix) {
            return rest.trim().to_string();
        }
    }
}

fn read_serve_addrs(child: &mut Child) -> (SocketAddr, SocketAddr) {
    let rpc = read_stdout_line_with_prefix(child, "mfnd_serve_listening=", Duration::from_secs(30))
        .parse()
        .expect("rpc addr");
    let p2p = read_stdout_line_with_prefix(child, "mfnd_p2p_listening=", Duration::from_secs(30))
        .parse()
        .expect("p2p addr");
    (rpc, p2p)
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

fn wait_for_inbox_complete(rpc: &str, data_dir: &Path, commitment_hash: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let inbox_out = mfn_cli()
            .args(["--rpc", rpc, "operator", "inbox-status", commitment_hash])
            .arg(data_dir)
            .output()
            .expect("inbox-status");
        assert!(
            inbox_out.status.success(),
            "inbox-status stderr={}",
            String::from_utf8_lossy(&inbox_out.stderr)
        );
        let stdout = String::from_utf8_lossy(&inbox_out.stdout).into_owned();
        if stdout.contains("inbox_complete=true") {
            return stdout;
        }
        if std::time::Instant::now() >= deadline {
            panic!("timeout waiting for chunk-inbox; last stdout:\n{stdout}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn mfnd_step(dir: &Path, spec: &Path, blocks: &str) {
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

fn spawn_serve(dir: &Path, spec: &Path) -> Child {
    mfnd()
        .args(["--data-dir"])
        .arg(dir)
        .arg("--genesis")
        .arg(spec)
        .arg("--store")
        .arg("fs")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-listen")
        .arg("127.0.0.1:0")
        .arg("serve")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("serve")
}

#[test]
fn push_chunks_inbox_assemble_then_prove() {
    let dir = unique_data_dir("p2p_inbox");
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

    let mut serve = spawn_serve(&dir, &spec);
    let (rpc, _) = read_serve_addrs(&mut serve);
    let rpc = rpc.to_string();

    let upload_out = mfn_cli()
        .args(["--rpc", &rpc, "--wallet"])
        .arg(&wallet_path)
        .args([
            "wallet",
            "upload",
            payload_path.to_str().expect("utf8"),
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
    let artifact_dir = PathBuf::from(parse_stdout_field(&upload_stdout, "upload_artifact_dir"));

    shutdown_child(&mut serve);
    mfnd_step(&dir, &spec, "1");

    let mut serve2 = spawn_serve(&dir, &spec);
    let (rpc2, p2p2) = read_serve_addrs(&mut serve2);
    let rpc2 = rpc2.to_string();
    let p2p2 = p2p2.to_string();

    let push_out = mfn_cli()
        .args(["--rpc", &rpc2, "--wallet"])
        .arg(&wallet_path)
        .args(["operator", "push-chunks", &commitment_hash, &p2p2])
        .output()
        .expect("push-chunks");
    assert!(
        push_out.status.success(),
        "push-chunks stderr={}",
        String::from_utf8_lossy(&push_out.stderr)
    );
    let push_stdout = String::from_utf8_lossy(&push_out.stdout);
    assert!(
        push_stdout.contains("push_chunks=ok"),
        "stdout={push_stdout}"
    );

    std::fs::remove_dir_all(&artifact_dir).expect("remove local artifact");

    wait_for_inbox_complete(&rpc2, &dir, &commitment_hash);

    let assemble_out = mfn_cli()
        .args(["--rpc", &rpc2, "--wallet"])
        .arg(&wallet_path)
        .args([
            "operator",
            "assemble-inbox",
            &commitment_hash,
            dir.to_str().expect("utf8"),
        ])
        .output()
        .expect("assemble-inbox");
    assert!(
        assemble_out.status.success(),
        "assemble-inbox stderr={}",
        String::from_utf8_lossy(&assemble_out.stderr)
    );
    assert!(String::from_utf8_lossy(&assemble_out.stdout).contains("assemble_inbox=ok"));
    assert!(artifact_dir.is_dir(), "artifact restored from inbox");

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

    shutdown_child(&mut serve2);
    mfnd_step(&dir, &spec, "1");

    let mut serve3 = spawn_serve(&dir, &spec);
    let rpc3 = read_stdout_line_with_prefix(
        &mut serve3,
        "mfnd_serve_listening=",
        Duration::from_secs(30),
    );

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
        "expected mined SPoRA proof at height 3:\n{list_stdout}"
    );

    shutdown_child(&mut serve3);
    std::fs::remove_dir_all(&dir).ok();
}
