//! Two-node smoke: hub has on-chain storage + complete `chunk-inbox/`; replica receives
//! chunks via **M7.5** session fan-out (no `push-chunks`) when it dials the hub (**M7.8**).

use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mfn_cli::{KeyDerivation, WalletFile};
use mfn_storage_operator::load_upload_artifact;
use mfn_store::mempool_path;

const DEVNET_SOLO_VRF_SEED_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
const DEVNET_SOLO_BLS_SEED_HEX: &str =
    "6565656565656565656565656565656565656565656565656565656565656565";
const UPLOAD_BYTES: usize = 512;
const INBOX_WAIT_SECS: u64 = 180;

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
        "permawrite-chunk-auto-fanout-{test}-{}-{nanos}",
        std::process::id()
    ));
    (base.join("hub"), base.join("replica"))
}

fn read_serve_addrs_from_reader(
    reader: &mut impl BufRead,
    timeout: Duration,
) -> (SocketAddr, SocketAddr) {
    let mut rpc = None;
    let mut p2p = None;
    let mut line = String::new();
    let deadline = std::time::Instant::now() + timeout;
    while rpc.is_none() || p2p.is_none() {
        if std::time::Instant::now() >= deadline {
            panic!("timeout waiting for mfnd listen addrs (rpc={rpc:?} p2p={p2p:?})");
        }
        line.clear();
        let n = reader.read_line(&mut line).expect("read stdout");
        if n == 0 {
            panic!("mfnd exited before listen addrs");
        }
        if let Some(rest) = line.strip_prefix("mfnd_serve_listening=") {
            rpc = Some(rest.trim().parse().expect("rpc addr"));
        } else if let Some(rest) = line.strip_prefix("mfnd_p2p_listening=") {
            p2p = Some(rest.trim().parse().expect("p2p addr"));
        }
    }
    (rpc.unwrap(), p2p.unwrap())
}

fn spawn_stdout_drain(reader: impl Read + Send + 'static) {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        while reader.read_line(&mut line).ok().is_some_and(|n| n > 0) {
            line.clear();
        }
    });
}

fn read_serve_addrs(child: &mut Child) -> (SocketAddr, SocketAddr) {
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let addrs = read_serve_addrs_from_reader(&mut reader, Duration::from_secs(30));
    spawn_stdout_drain(reader);
    addrs
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
        "tip rpc={rpc} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    parse_stdout_field(&String::from_utf8_lossy(&out.stdout), "tip_height")
        .parse()
        .expect("tip_height u64")
}

fn wait_for_matching_tip_at_least(
    hub_rpc: &str,
    replica_rpc: &str,
    min_height: u64,
    timeout: Duration,
) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let hub_h = rpc_tip_height(hub_rpc);
        let replica_h = rpc_tip_height(replica_rpc);
        if hub_h >= min_height && hub_h == replica_h {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("timeout: need matching tip >= {min_height} (hub={hub_h} replica={replica_h})");
        }
        thread::sleep(Duration::from_millis(300));
    }
}

fn wait_for_local_inbox_complete(data_dir: &Path, commitment_hash: &str, num_chunks: u32) {
    let deadline = std::time::Instant::now() + Duration::from_secs(INBOX_WAIT_SECS);
    loop {
        if mfn_store::chunk_inbox_complete(data_dir, commitment_hash, num_chunks).unwrap_or(false) {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "timeout waiting for replica chunk-inbox (M7.5 fan-out) under {}",
                data_dir.display()
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn assemble_inbox_with_transport_retry(
    rpc: &str,
    wallet: &Path,
    commitment_hash: &str,
    data_dir: &Path,
) -> Output {
    let mut last_out = None;
    for _ in 0..5 {
        let out = mfn_cli()
            .args(["--rpc", rpc, "--wallet"])
            .arg(wallet)
            .args([
                "operator",
                "assemble-inbox",
                commitment_hash,
                data_dir.to_str().expect("utf8"),
            ])
            .output()
            .expect("assemble-inbox");
        if out.status.success() {
            return out;
        }
        let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
        let transient_transport = stderr.contains("forcibly closed")
            || stderr.contains("connection reset")
            || stderr.contains("connection refused");
        last_out = Some(out);
        if !transient_transport {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    last_out.expect("assemble-inbox attempted")
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

fn populate_chunk_inbox_from_artifact(data_dir: &Path, wallet: &Path, commitment_hash_hex: &str) {
    let loaded = load_upload_artifact(wallet, commitment_hash_hex).expect("load artifact");
    let mut hash = [0u8; 32];
    hex::decode_to_slice(commitment_hash_hex, &mut hash).expect("commit hex");
    let slices = mfn_storage::chunk_data(&loaded.payload, loaded.built.commit.chunk_size as usize)
        .expect("chunk slices");
    for (i, bytes) in slices.iter().enumerate() {
        mfn_store::save_chunk_inbox(
            data_dir,
            &hash,
            u32::try_from(i).expect("chunk index"),
            bytes,
        )
        .expect("save_chunk_inbox");
    }
}

/// Hub on-chain storage + inbox; replica dial triggers **M7.5** chunk catch-up (no `push-chunks`).
#[test]
#[cfg_attr(
    windows,
    ignore = "Windows duplex P2P session fanout is flaky; participant smoke covers Windows permanence end-to-end"
)]
fn hub_produce_seal_auto_fanout_replica_inbox_assembles_matching_payload() {
    let (hub_dir, replica_dir) = unique_pair_dir("fanout");
    std::fs::create_dir_all(&hub_dir).expect("hub dir");
    std::fs::create_dir_all(&replica_dir).expect("replica dir");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator_fast_produce.json");

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

    // Fund, admit upload, populate inbox, then mine storage offline (same pattern as M7.4 two-node).
    mfnd_step(&hub_dir, &spec, "1");

    let mut hub_prep = spawn_serve(&hub_dir, &spec, None);
    let (hub_rpc_prep, _) = read_serve_addrs(&mut hub_prep);
    let hub_rpc_prep = hub_rpc_prep.to_string();

    let upload_out = mfn_cli()
        .args(["--rpc", &hub_rpc_prep, "--wallet"])
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
    let num_chunks = load_upload_artifact(&hub_wallet, &commitment_hash)
        .expect("hub artifact")
        .built
        .commit
        .num_chunks;
    populate_chunk_inbox_from_artifact(&hub_dir, &hub_wallet, &commitment_hash);
    assert!(
        mempool_path(&hub_dir).is_file(),
        "upload must persist mempool.bytes before hub restart (submit_tx admit)"
    );
    shutdown_child(&mut hub_prep);

    mfnd_step(&hub_dir, &spec, "1");

    let mut hub_live = spawn_serve(&hub_dir, &spec, None);
    let (hub_rpc_live, hub_p2p) = read_serve_addrs(&mut hub_live);
    let hub_rpc_live = hub_rpc_live.to_string();
    let hub_p2p = hub_p2p.to_string();
    let storage_height = rpc_tip_height(&hub_rpc_live);
    assert!(
        storage_height >= 2,
        "storage must be mined before replica dial (tip={storage_height})"
    );

    let mut replica_live = spawn_serve(&replica_dir, &spec, Some(&hub_p2p));
    let (replica_rpc, _) = read_serve_addrs(&mut replica_live);
    let replica_rpc = replica_rpc.to_string();

    wait_for_matching_tip_at_least(
        &hub_rpc_live,
        &replica_rpc,
        storage_height,
        Duration::from_secs(180),
    );
    // Fresh dial forces `pull_blocks_to_tip` on a clean outbound session (M7.5 catch-up).
    shutdown_child(&mut replica_live);
    let mut replica_live = spawn_serve(&replica_dir, &spec, Some(&hub_p2p));
    let (replica_rpc, _) = read_serve_addrs(&mut replica_live);
    let replica_rpc = replica_rpc.to_string();
    wait_for_matching_tip_at_least(
        &hub_rpc_live,
        &replica_rpc,
        storage_height,
        Duration::from_secs(120),
    );
    thread::sleep(Duration::from_secs(3));

    wait_for_local_inbox_complete(&replica_dir, &commitment_hash, num_chunks);

    let assemble_out = assemble_inbox_with_transport_retry(
        &replica_rpc,
        &replica_wallet,
        &commitment_hash,
        &replica_dir,
    );
    assert!(
        assemble_out.status.success(),
        "assemble-inbox stderr={}",
        String::from_utf8_lossy(&assemble_out.stderr)
    );
    let assemble_stdout = String::from_utf8_lossy(&assemble_out.stdout);
    assert!(assemble_stdout.contains("assemble_inbox=ok"));
    let artifact_dir = PathBuf::from(parse_stdout_field(&assemble_stdout, "artifact_dir"));
    let replica_bytes = std::fs::read(artifact_dir.join("payload.bin")).expect("replica payload");
    assert_eq!(replica_bytes, payload);

    shutdown_child(&mut hub_live);
    shutdown_child(&mut replica_live);
    let _ = std::fs::remove_dir_all(hub_dir.parent().expect("parent"));
}
