//! Three-validator `--produce` mesh: hub uploads on live chain, `push-chunks` to both
//! committee voters, both assemble matching payload (**M7.7**).
//!
//! **M7.9** — same mesh without `push-chunks`; hub `chunk-inbox/` + **M7.5** session fan-out.
//!
//! Run via nightly `scripts/ci-ignored` (slow; ~4 min).

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mfn_cli::{KeyDerivation, WalletFile};
use mfn_storage_operator::load_upload_artifact;

const THREE_VALIDATOR_SPEC: &str = "devnet_three_validators.json";
/// Hub-friendly VRF cadence for **M7.9** auto fan-out (hub seals storage more often).
const THREE_VALIDATOR_FAST_PRODUCE_SPEC: &str = "devnet_three_validators_produce.json";
const SLOT_DURATION_MS: u64 = 10_000;
const UPLOAD_BYTES: usize = 512;

const V0_VRF: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const V0_BLS: &str = "6565656565656565656565656565656565656565656565656565656565656565";
const V1_VRF: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const V1_BLS: &str = "7676767676767676767676767676767676767676767676767676767676767676";
const V2_VRF: &str = "0303030303030303030303030303030303030303030303030303030303030303";
const V2_BLS: &str = "8787878787878787878787878787878787878787878787878787878787878787";

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
    Command::new(mfnd_bin())
}

fn mfn_cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mfn-cli"))
}

fn spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata")
        .join(THREE_VALIDATOR_SPEC)
}

fn unique_data_dir(test: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "permawrite-chunk-3v-produce-{test}-{}-{nanos}",
        std::process::id()
    ))
}

fn tcp_request_json(addr: SocketAddr, request_line: &str) -> String {
    let mut last_err = None;
    for _ in 0..40 {
        match TcpStream::connect(addr) {
            Ok(mut tcp) => {
                writeln!(tcp, "{request_line}").expect("write request");
                let mut resp = String::new();
                BufReader::new(&tcp)
                    .read_line(&mut resp)
                    .expect("read response");
                return resp;
            }
            Err(e) if e.kind() == ErrorKind::AddrInUse || e.kind() == ErrorKind::WouldBlock => {
                last_err = Some(e);
                thread::sleep(Duration::from_millis(250));
            }
            Err(e) => panic!("tcp connect: {e}"),
        }
    }
    panic!("tcp connect: {:?}", last_err);
}

fn rpc_result(resp: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(resp.trim()).expect("json");
    assert!(
        v.get("error").is_none() || v["error"].is_null(),
        "rpc error: {v}"
    );
    v["result"].clone()
}

struct ValidatorNode {
    child: Child,
    rpc: SocketAddr,
    p2p: SocketAddr,
    data_dir: PathBuf,
}

struct SpawnOpts<'a> {
    data_dir: &'a Path,
    genesis_spec: &'a Path,
    index: u32,
    vrf_hex: &'a str,
    bls_hex: &'a str,
    p2p_dial: Option<&'a str>,
    produce: bool,
}

fn read_startup_addrs(
    out: &mut BufReader<impl Read>,
    slot_producer: bool,
    need_dial: bool,
) -> (SocketAddr, SocketAddr) {
    let role_prefix = if slot_producer {
        "mfnd_producer_start "
    } else {
        "mfnd_committee_vote_start "
    };
    let mut rpc = None;
    let mut p2p = None;
    let mut got_role = false;
    let mut got_dial = !need_dial;
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut line = String::new();
    while rpc.is_none() || p2p.is_none() || !got_role || !got_dial {
        if Instant::now() >= deadline {
            panic!(
                "timeout during mfnd startup (rpc={rpc:?} p2p={p2p:?} role={got_role} dial={got_dial})"
            );
        }
        line.clear();
        let n = out.read_line(&mut line).expect("read mfnd stdout");
        if n == 0 {
            panic!("mfnd exited during startup");
        }
        if let Some(rest) = line.strip_prefix("mfnd_serve_listening=") {
            rpc = Some(rest.trim().parse().expect("rpc addr"));
        } else if let Some(rest) = line.strip_prefix("mfnd_p2p_listening=") {
            p2p = Some(rest.trim().parse().expect("p2p addr"));
        } else if line.starts_with(role_prefix) {
            got_role = true;
        } else if line.starts_with("mfnd_p2p_dial_ok=") {
            got_dial = true;
        }
    }
    (rpc.unwrap(), p2p.unwrap())
}

fn watch_stdout(
    mut reader: BufReader<impl Read + Send + 'static>,
    log: Arc<Mutex<Vec<String>>>,
    sealed_flag: Option<Arc<AtomicBool>>,
) {
    thread::spawn(move || {
        let mut line = String::new();
        while reader.read_line(&mut line).ok().is_some_and(|n| n > 0) {
            if let Some(flag) = sealed_flag.as_ref() {
                if line.contains("mfnd_producer_sealed") {
                    flag.store(true, Ordering::Relaxed);
                }
            }
            if let Ok(mut g) = log.lock() {
                if g.len() < 500 {
                    g.push(line.trim_end().to_string());
                }
            }
            line.clear();
        }
    });
}

fn spawn_validator(opts: &SpawnOpts<'_>) -> (ValidatorNode, BufReader<impl Read + Send + 'static>) {
    let mut cmd = mfnd();
    cmd.args(["--data-dir"])
        .arg(opts.data_dir)
        .arg("--genesis")
        .arg(opts.genesis_spec)
        .arg("--store")
        .arg("fs")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-listen")
        .arg("127.0.0.1:0")
        .arg("--slot-duration-ms")
        .arg(SLOT_DURATION_MS.to_string())
        .env("MFND_VALIDATOR_INDEX", opts.index.to_string())
        .env("MFND_VRF_SEED_HEX", opts.vrf_hex)
        .env("MFND_BLS_SEED_HEX", opts.bls_hex)
        .arg("serve");
    if opts.produce {
        cmd.arg("--produce");
    } else {
        cmd.arg("--committee-vote");
    }
    if let Some(dial) = opts.p2p_dial {
        cmd.arg("--p2p-dial").arg(dial);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mfnd");
    let stdout = child.stdout.take().expect("stdout");
    let mut out = BufReader::new(stdout);
    let (rpc, p2p) = read_startup_addrs(&mut out, opts.produce, opts.p2p_dial.is_some());
    (
        ValidatorNode {
            child,
            rpc,
            p2p,
            data_dir: opts.data_dir.to_path_buf(),
        },
        out,
    )
}

fn shutdown_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn get_tip(rpc: SocketAddr) -> (u64, String) {
    let resp = tcp_request_json(rpc, r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#);
    let r = rpc_result(&resp);
    let height = r["tip_height"].as_u64().expect("tip_height");
    let tip_id = r["tip_id"].as_str().expect("tip_id").to_string();
    (height, tip_id)
}

fn wait_first_block(
    hub: SocketAddr,
    followers: &[SocketAddr],
    sealed_flag: &AtomicBool,
    timeout: Duration,
) -> (u64, String) {
    let deadline = Instant::now() + timeout;
    loop {
        let (hh, hid) = get_tip(hub);
        if hh >= 1
            && followers.iter().all(|&rpc| {
                let (fh, fid) = get_tip(rpc);
                fh >= 1 && fid == hid
            })
        {
            return (hh, hid);
        }
        if sealed_flag.load(Ordering::Relaxed) {
            let (hh, hid) = get_tip(hub);
            if hh >= 1
                && followers.iter().all(|&rpc| {
                    let (fh, fid) = get_tip(rpc);
                    fh >= 1 && fid == hid
                })
            {
                return (hh, hid);
            }
        }
        if Instant::now() >= deadline {
            let tips: Vec<_> = std::iter::once(hub)
                .chain(followers.iter().copied())
                .map(get_tip)
                .collect();
            panic!("timeout waiting for first sealed block (tips={tips:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn wait_common_tip(
    hub: SocketAddr,
    followers: &[SocketAddr],
    min_height: u64,
    timeout: Duration,
) -> (u64, String) {
    let deadline = Instant::now() + timeout;
    loop {
        let (hh, hid) = get_tip(hub);
        if hh >= min_height
            && followers.iter().all(|&rpc| {
                let (fh, fid) = get_tip(rpc);
                fh == hh && fid == hid
            })
        {
            return (hh, hid);
        }
        if Instant::now() >= deadline {
            let tips: Vec<_> = std::iter::once(hub)
                .chain(followers.iter().copied())
                .map(get_tip)
                .collect();
            panic!("timeout waiting for common tip >= {min_height} (tips={tips:?})");
        }
        thread::sleep(Duration::from_millis(1000));
    }
}

fn start_three_validator_mesh(spec: &Path) -> (ValidatorNode, ValidatorNode, ValidatorNode) {
    let dir0 = unique_data_dir("v0");
    let dir1 = unique_data_dir("v1");
    let dir2 = unique_data_dir("v2");
    std::fs::create_dir_all(&dir0).expect("v0 dir");
    std::fs::create_dir_all(&dir1).expect("v1 dir");
    std::fs::create_dir_all(&dir2).expect("v2 dir");

    let sealed = Arc::new(AtomicBool::new(false));
    let log0 = Arc::new(Mutex::new(Vec::new()));
    let log1 = Arc::new(Mutex::new(Vec::new()));

    let (v0, out0) = spawn_validator(&SpawnOpts {
        data_dir: &dir0,
        genesis_spec: spec,
        index: 0,
        vrf_hex: V0_VRF,
        bls_hex: V0_BLS,
        p2p_dial: None,
        produce: true,
    });
    watch_stdout(out0, Arc::clone(&log0), Some(Arc::clone(&sealed)));

    thread::sleep(Duration::from_millis(500));
    let hub_p2p = v0.p2p.to_string();

    let (v1, out1) = spawn_validator(&SpawnOpts {
        data_dir: &dir1,
        genesis_spec: spec,
        index: 1,
        vrf_hex: V1_VRF,
        bls_hex: V1_BLS,
        p2p_dial: Some(&hub_p2p),
        produce: false,
    });
    watch_stdout(out1, Arc::clone(&log1), Some(Arc::clone(&sealed)));

    thread::sleep(Duration::from_millis(1500));
    let (_, _) = wait_first_block(v0.rpc, &[v1.rpc], &sealed, Duration::from_secs(90));
    let (h1, _) = wait_common_tip(v0.rpc, &[v1.rpc], 1, Duration::from_secs(15));
    assert_eq!(h1, 1, "hub should be at height 1 before v2 joins");

    let (v2, out2) = spawn_validator(&SpawnOpts {
        data_dir: &dir2,
        genesis_spec: spec,
        index: 2,
        vrf_hex: V2_VRF,
        bls_hex: V2_BLS,
        p2p_dial: Some(&hub_p2p),
        produce: false,
    });
    watch_stdout(out2, Arc::new(Mutex::new(Vec::new())), None);

    thread::sleep(Duration::from_millis(500));
    let (height, _) = wait_common_tip(v0.rpc, &[v1.rpc, v2.rpc], 1, Duration::from_secs(180));
    assert!(height >= 1, "mesh should converge before upload");

    (v0, v1, v2)
}

fn parse_stdout_field(stdout: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::to_string))
        .unwrap_or_else(|| panic!("stdout missing {prefix}:\n{stdout}"))
}

fn wallet_balance_cached(rpc: &str, wallet: &Path) -> u64 {
    let out = mfn_cli()
        .args(["--rpc", rpc, "--wallet"])
        .arg(wallet)
        .args(["wallet", "status"])
        .output()
        .expect("wallet status");
    assert!(
        out.status.success(),
        "status stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_stdout_field(&stdout, "balance_cached")
        .parse()
        .expect("balance u64")
}

fn wallet_scan(rpc: &str, wallet: &Path) {
    let out = mfn_cli()
        .args(["--rpc", rpc, "--wallet"])
        .arg(wallet)
        .args(["wallet", "scan"])
        .output()
        .expect("wallet scan");
    assert!(
        out.status.success(),
        "scan stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn wait_wallet_funded(rpc: &str, wallet: &Path, min_balance: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        wallet_scan(rpc, wallet);
        if wallet_balance_cached(rpc, wallet) >= min_balance {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timeout: hub wallet balance still below {min_balance} (last={})",
                wallet_balance_cached(rpc, wallet)
            );
        }
        thread::sleep(Duration::from_millis(2000));
    }
}

fn wait_storage_on_hub(rpc: &str, commitment_hash: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let out = mfn_cli()
            .args(["--rpc", rpc, "uploads", "list"])
            .output()
            .expect("uploads list");
        assert!(
            out.status.success(),
            "uploads list stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains(commitment_hash) {
            return;
        }
        if Instant::now() >= deadline {
            panic!("timeout waiting for storage on hub chain:\n{stdout}");
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn wait_tip_at_least(rpc: SocketAddr, min_height: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let (h, _) = get_tip(rpc);
        if h >= min_height {
            return;
        }
        if Instant::now() >= deadline {
            panic!("timeout waiting for tip >= {min_height} (last={h})");
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn wait_for_inbox_complete(rpc: &str, data_dir: &Path, commitment_hash: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
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
        if Instant::now() >= deadline {
            panic!("timeout waiting for chunk-inbox:\n{stdout}");
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn assert_replica_payload(
    replica_rpc: &str,
    replica_wallet: &Path,
    replica_dir: &Path,
    commitment_hash: &str,
    expected: &[u8],
) {
    let assemble_out = mfn_cli()
        .args(["--rpc", replica_rpc, "--wallet"])
        .arg(replica_wallet)
        .args([
            "operator",
            "assemble-inbox",
            commitment_hash,
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
    let artifact_dir = PathBuf::from(parse_stdout_field(&assemble_stdout, "artifact_dir"));
    let bytes = std::fs::read(artifact_dir.join("payload.bin")).expect("replica payload");
    assert_eq!(bytes, expected, "replica payload must match hub upload");
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

fn save_wallet(dir: &Path, name: &str, bls_hex: &str) -> PathBuf {
    let mut bls_seed = [0u8; 32];
    hex::decode_to_slice(bls_hex, &mut bls_seed).expect("bls hex");
    let path = dir.join(name);
    WalletFile::new(&bls_seed, KeyDerivation::PayoutStealthV1)
        .save(&path)
        .expect("wallet");
    path
}

/// Live `--produce` + `--committee-vote` mesh with P2P chunk replication (up to ~4 min).
#[test]
#[ignore = "slow three-validator produce + chunk P2P harness; run: cargo test -p mfn-cli --test chunk_p2p_three_validator_produce_smoke -- --ignored"]
fn produce_mesh_push_chunks_two_voters_assemble_matching_payload() {
    let spec = spec_path();
    assert!(spec.is_file(), "missing genesis {}", spec.display());

    let payload: Vec<u8> = (0u8..255u8).cycle().take(UPLOAD_BYTES).collect();

    let (mut v0, mut v1, mut v2) = start_three_validator_mesh(&spec);
    let (height, _) = wait_common_tip(v0.rpc, &[v1.rpc, v2.rpc], 3, Duration::from_secs(180));
    assert!(
        height >= 3,
        "need height >= 3 before upload (coinbase funding)"
    );

    let hub_rpc = v0.rpc.to_string();
    let hub_wallet = save_wallet(&v0.data_dir, "hub.json", V0_BLS);
    let voter1_wallet = save_wallet(&v1.data_dir, "voter1.json", V1_BLS);
    let voter2_wallet = save_wallet(&v2.data_dir, "voter2.json", V2_BLS);

    wait_wallet_funded(&hub_rpc, &hub_wallet, 20_000, Duration::from_secs(180));

    let payload_path = v0.data_dir.join("payload.bin");
    std::fs::write(&payload_path, &payload).expect("payload");

    let tip_before_upload = get_tip(v0.rpc).0;
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
            "16",
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

    wait_tip_at_least(
        v0.rpc,
        tip_before_upload.saturating_add(1),
        Duration::from_secs(120),
    );
    wait_common_tip(
        v0.rpc,
        &[v1.rpc, v2.rpc],
        get_tip(v0.rpc).0,
        Duration::from_secs(60),
    );

    let push_out = mfn_cli()
        .args(["--rpc", &hub_rpc, "--wallet"])
        .arg(&hub_wallet)
        .args([
            "operator",
            "push-chunks",
            &commitment_hash,
            &v1.p2p.to_string(),
            &v2.p2p.to_string(),
        ])
        .output()
        .expect("push-chunks");
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

    let v1_rpc = v1.rpc.to_string();
    let v2_rpc = v2.rpc.to_string();
    wait_for_inbox_complete(
        &v1_rpc,
        &v1.data_dir,
        &commitment_hash,
        Duration::from_secs(30),
    );
    wait_for_inbox_complete(
        &v2_rpc,
        &v2.data_dir,
        &commitment_hash,
        Duration::from_secs(30),
    );

    assert_replica_payload(
        &v1_rpc,
        &voter1_wallet,
        &v1.data_dir,
        &commitment_hash,
        &payload,
    );
    assert_replica_payload(
        &v2_rpc,
        &voter2_wallet,
        &v2.data_dir,
        &commitment_hash,
        &payload,
    );

    shutdown_child(&mut v0.child);
    shutdown_child(&mut v1.child);
    shutdown_child(&mut v2.child);
}

/// Live hub `--produce` mesh: **M7.5** auto fan-out fills voter `chunk-inbox/` (no `push-chunks`).
#[test]
#[ignore = "slow three-validator produce + M7.5 auto fan-out; run: cargo test -p mfn-cli --test chunk_p2p_three_validator_produce_smoke -- --ignored"]
fn produce_mesh_auto_fanout_two_voters_assemble_matching_payload() {
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata")
        .join(THREE_VALIDATOR_FAST_PRODUCE_SPEC);
    assert!(spec.is_file(), "missing genesis {}", spec.display());

    let payload: Vec<u8> = (0u8..255u8).cycle().take(UPLOAD_BYTES).collect();

    let (mut v0, mut v1, mut v2) = start_three_validator_mesh(&spec);
    let (height, _) = wait_common_tip(v0.rpc, &[v1.rpc, v2.rpc], 3, Duration::from_secs(180));
    assert!(
        height >= 3,
        "need height >= 3 before upload (coinbase funding)"
    );

    let hub_rpc = v0.rpc.to_string();
    let hub_wallet = save_wallet(&v0.data_dir, "hub.json", V0_BLS);
    let voter1_wallet = save_wallet(&v1.data_dir, "voter1.json", V1_BLS);
    let voter2_wallet = save_wallet(&v2.data_dir, "voter2.json", V2_BLS);

    wait_wallet_funded(&hub_rpc, &hub_wallet, 20_000, Duration::from_secs(180));

    let payload_path = v0.data_dir.join("payload.bin");
    std::fs::write(&payload_path, &payload).expect("payload");

    let tip_before_upload = get_tip(v0.rpc).0;
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
            "16",
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
    populate_chunk_inbox_from_artifact(&v0.data_dir, &hub_wallet, &commitment_hash);

    let target_height = tip_before_upload.saturating_add(1);
    wait_storage_on_hub(&hub_rpc, &commitment_hash, Duration::from_secs(150));
    wait_tip_at_least(v0.rpc, target_height, Duration::from_secs(30));
    wait_tip_at_least(v1.rpc, target_height, Duration::from_secs(150));
    wait_tip_at_least(v2.rpc, target_height, Duration::from_secs(150));
    // Chunk fan-out runs on a background thread after hub apply/seal.
    thread::sleep(Duration::from_secs(3));

    let v1_rpc = v1.rpc.to_string();
    let v2_rpc = v2.rpc.to_string();
    wait_for_inbox_complete(
        &v1_rpc,
        &v1.data_dir,
        &commitment_hash,
        Duration::from_secs(90),
    );
    wait_for_inbox_complete(
        &v2_rpc,
        &v2.data_dir,
        &commitment_hash,
        Duration::from_secs(90),
    );

    assert_replica_payload(
        &v1_rpc,
        &voter1_wallet,
        &v1.data_dir,
        &commitment_hash,
        &payload,
    );
    assert_replica_payload(
        &v2_rpc,
        &voter2_wallet,
        &v2.data_dir,
        &commitment_hash,
        &payload,
    );

    shutdown_child(&mut v0.child);
    shutdown_child(&mut v1.child);
    shutdown_child(&mut v2.child);
}
