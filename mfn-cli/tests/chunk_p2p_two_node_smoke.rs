//! Two-node smoke: hub mines upload, pushes ChunkV1 to replica P2P, replica assembles
//! matching bytes from `chunk-inbox/` (**M7.4**).

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
        "mfnd binary not found at {}; run `cargo build -p mfn-node --bin mfnd --release`",
        path.display()
    );
}

fn mfnd() -> Command {
    let mut cmd = Command::new(mfnd_bin());
    cmd.env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX);
    cmd
}

fn mfn_cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mfn-cli"))
}

fn unique_pair_dir(test: &str) -> (PathBuf, PathBuf) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "permawrite-chunk-p2p-2n-{test}-{}-{nanos}",
        std::process::id()
    ));
    (base.join("hub"), base.join("replica"))
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

fn rpc_tip_height(rpc: &str) -> u64 {
    let out = mfn_cli().args(["--rpc", rpc, "tip"]).output().expect("tip");
    assert!(
        out.status.success(),
        "tip stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_stdout_field(&stdout, "tip_height")
        .parse()
        .expect("tip_height u64")
}

fn wait_for_matching_tip(hub_rpc: &str, replica_rpc: &str, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let hub_h = rpc_tip_height(hub_rpc);
        let replica_h = rpc_tip_height(replica_rpc);
        if hub_h == replica_h {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("timeout: hub tip={hub_h} replica tip={replica_h}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_inbox_complete(rpc: &str, data_dir: &Path, commitment_hash: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
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
        let stdout = String::from_utf8_lossy(&inbox_out.stdout);
        if stdout.contains("inbox_complete=true") {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("timeout waiting for replica chunk-inbox:\n{stdout}");
        }
        std::thread::sleep(Duration::from_millis(100));
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
        .output()
        .expect("mfnd step");
    assert!(
        out.status.success(),
        "step blocks={blocks} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn spawn_serve(dir: &Path, spec: &Path, p2p_dial: Option<&str>) -> Child {
    let mut cmd = mfnd();
    cmd.args(["--data-dir"])
        .arg(dir)
        .arg("--genesis")
        .arg(spec)
        .arg("--store")
        .arg("fs")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-listen")
        .arg("127.0.0.1:0");
    if let Some(dial) = p2p_dial {
        cmd.arg("--p2p-dial").arg(dial);
    }
    cmd.arg("serve")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("serve")
}

#[test]
fn hub_push_chunks_replica_inbox_assembles_matching_payload() {
    let (hub_dir, replica_dir) = unique_pair_dir("replicate");
    std::fs::create_dir_all(&hub_dir).expect("hub dir");
    std::fs::create_dir_all(&replica_dir).expect("replica dir");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator_synth_decoys.json");

    let mut bls_seed = [0u8; 32];
    hex::decode_to_slice(DEVNET_SOLO_BLS_SEED_HEX, &mut bls_seed).expect("bls hex");
    let hub_wallet = hub_dir.join("alice.json");
    let replica_wallet = replica_dir.join("bob.json");
    WalletFile::new(&bls_seed, KeyDerivation::PayoutStealthV1)
        .save(&hub_wallet)
        .expect("hub wallet");
    WalletFile::new(&bls_seed, KeyDerivation::PayoutStealthV1)
        .save(&replica_wallet)
        .expect("replica wallet");

    let payload_path = hub_dir.join("payload.bin");
    let payload: Vec<u8> = (0u8..255u8).cycle().take(UPLOAD_BYTES).collect();
    std::fs::write(&payload_path, &payload).expect("write payload");

    mfnd_step(&hub_dir, &spec, "1");

    let mut hub_serve = spawn_serve(&hub_dir, &spec, None);
    let (hub_rpc, _) = read_serve_addrs(&mut hub_serve);
    let hub_rpc = hub_rpc.to_string();

    let upload_out = mfn_cli()
        .args(["--rpc", &hub_rpc, "--wallet"])
        .arg(&hub_wallet)
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
    let hub_artifact_dir = PathBuf::from(parse_stdout_field(&upload_stdout, "upload_artifact_dir"));
    let hub_payload_path = hub_artifact_dir.join("payload.bin");

    shutdown_child(&mut hub_serve);
    mfnd_step(&hub_dir, &spec, "1");

    let mut hub_live = spawn_serve(&hub_dir, &spec, None);
    let (hub_rpc_live, hub_p2p) = read_serve_addrs(&mut hub_live);
    let hub_rpc_live = hub_rpc_live.to_string();
    let hub_p2p = hub_p2p.to_string();

    let mut replica_live = spawn_serve(&replica_dir, &spec, Some(&hub_p2p));
    let (replica_rpc, replica_p2p) = read_serve_addrs(&mut replica_live);
    let replica_rpc = replica_rpc.to_string();
    let replica_p2p = replica_p2p.to_string();

    wait_for_matching_tip(&hub_rpc_live, &replica_rpc, Duration::from_secs(60));

    let push_out = mfn_cli()
        .args(["--rpc", &hub_rpc_live, "--wallet"])
        .arg(&hub_wallet)
        .args(["operator", "push-chunks", &commitment_hash, &replica_p2p])
        .output()
        .expect("push-chunks to replica");
    assert!(
        push_out.status.success(),
        "push-chunks stderr={}",
        String::from_utf8_lossy(&push_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&push_out.stdout).contains("push_chunks=ok"),
        "push stdout={}",
        String::from_utf8_lossy(&push_out.stdout)
    );

    wait_for_inbox_complete(&replica_rpc, &replica_dir, &commitment_hash);

    let assemble_out = mfn_cli()
        .args(["--rpc", &replica_rpc, "--wallet"])
        .arg(&replica_wallet)
        .args([
            "operator",
            "assemble-inbox",
            &commitment_hash,
            replica_dir.to_str().expect("utf8"),
        ])
        .output()
        .expect("assemble-inbox");
    assert!(
        assemble_out.status.success(),
        "assemble-inbox stderr={}",
        String::from_utf8_lossy(&assemble_out.stderr)
    );
    let assemble_stdout = String::from_utf8_lossy(&assemble_out.stdout);
    assert!(assemble_stdout.contains("assemble_inbox=ok"));
    let replica_artifact_dir = PathBuf::from(parse_stdout_field(&assemble_stdout, "artifact_dir"));
    let replica_payload_path = replica_artifact_dir.join("payload.bin");

    let hub_bytes = std::fs::read(&hub_payload_path).expect("hub payload");
    let replica_bytes = std::fs::read(&replica_payload_path).expect("replica payload");
    assert_eq!(
        hub_bytes, replica_bytes,
        "replica assembled payload must match hub upload artifact"
    );
    assert_eq!(replica_bytes, payload);

    shutdown_child(&mut hub_live);
    shutdown_child(&mut replica_live);
    let _ = std::fs::remove_dir_all(hub_dir.parent().expect("parent"));
}
