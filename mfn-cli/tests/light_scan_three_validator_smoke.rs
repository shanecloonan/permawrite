//! `wallet light-scan` on a live three-validator `--produce` mesh (**M3.17** / **M3.19**).
//!
//! `mfnd step` only supports a single genesis validator; the default-CI check for
//! three-validator weak-subjectivity summaries lives in `light_subjectivity` unit tests.
//! Run the mesh harness via `cargo test … -- --ignored` (nightly `scripts/ci-ignored.sh`).

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mfn_cli::{KeyDerivation, WalletFile};
use mfn_consensus::emission_at_height;
use mfn_consensus::DEFAULT_EMISSION_PARAMS;
use serde_json::Value;

const PAYOUT_SEED: [u8; 32] = [0xab; 32];
const THREE_VALIDATOR_SPEC: &str = "devnet_three_validators_wallet_payout.json";

const V0_VRF: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const V0_BLS: &str = "6565656565656565656565656565656565656565656565656565656565656565";
const V1_VRF: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const V1_BLS: &str = "7676767676767676767676767676767676767676767676767676767676767676";
const V2_VRF: &str = "0303030303030303030303030303030303030303030303030303030303030303";
const V2_BLS: &str = "8787878787878787878787878787878787878787878787878787878787878787";

/// Match `three_validator_produce_smoke` (10s slots, ~90s first seal budget).
const SLOT_DURATION_MS: u64 = 10_000;

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
        "permawrite-light-scan-3v-{test}-{}-{nanos}",
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

fn rpc_result(resp: &str) -> Value {
    let v: Value = serde_json::from_str(resp.trim()).expect("json");
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
}

struct SpawnOpts<'a> {
    data_dir: &'a Path,
    genesis_spec: &'a Path,
    index: u32,
    vrf_hex: &'a str,
    bls_hex: &'a str,
    p2p_dial: Option<&'a str>,
    slot_duration_ms: u64,
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

fn watch_stderr(child: &mut Child, log: Arc<Mutex<Vec<String>>>) {
    let Some(stderr) = child.stderr.take() else {
        return;
    };
    thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        while reader.read_line(&mut line).ok().is_some_and(|n| n > 0) {
            if let Ok(mut g) = log.lock() {
                if g.len() < 200 {
                    g.push(format!("stderr: {}", line.trim_end()));
                }
            }
            line.clear();
        }
    });
}

fn dump_log(label: &str, log: &Arc<Mutex<Vec<String>>>) {
    eprintln!("--- {label} log (last lines) ---");
    if let Ok(g) = log.lock() {
        for line in g.iter().rev().take(40).rev() {
            eprintln!("{line}");
        }
    }
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
        .arg(opts.slot_duration_ms.to_string())
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
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mfnd");
    let stdout = child.stdout.take().expect("stdout");
    let mut out = BufReader::new(stdout);
    let (rpc, p2p) = read_startup_addrs(&mut out, opts.produce, opts.p2p_dial.is_some());
    (ValidatorNode { child, rpc, p2p }, out)
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
    logs: &[Arc<Mutex<Vec<String>>>],
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
            let sealed = sealed_flag.load(Ordering::Relaxed);
            for (i, log) in logs.iter().enumerate() {
                dump_log(&format!("v{i}"), log);
            }
            panic!("timeout waiting for first sealed block (tips={tips:?}, saw_sealed={sealed})");
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

/// Staged boot matches `three_validator_produce_smoke` (hub → voter1 → voter2).
fn start_three_validator_mesh(spec: &Path) -> (ValidatorNode, ValidatorNode, ValidatorNode) {
    let dir0 = unique_data_dir("v0");
    let dir1 = unique_data_dir("v1");
    let dir2 = unique_data_dir("v2");
    std::fs::create_dir_all(&dir0).ok();
    std::fs::create_dir_all(&dir1).ok();
    std::fs::create_dir_all(&dir2).ok();

    let sealed = Arc::new(AtomicBool::new(false));
    let log0 = Arc::new(Mutex::new(Vec::new()));
    let log1 = Arc::new(Mutex::new(Vec::new()));

    let (mut v0, out0) = spawn_validator(&SpawnOpts {
        data_dir: &dir0,
        genesis_spec: spec,
        index: 0,
        vrf_hex: V0_VRF,
        bls_hex: V0_BLS,
        p2p_dial: None,
        slot_duration_ms: SLOT_DURATION_MS,
        produce: true,
    });
    watch_stdout(out0, Arc::clone(&log0), Some(Arc::clone(&sealed)));
    watch_stderr(&mut v0.child, Arc::clone(&log0));

    thread::sleep(Duration::from_millis(500));
    let hub_p2p = v0.p2p.to_string();

    let (mut v1, out1) = spawn_validator(&SpawnOpts {
        data_dir: &dir1,
        genesis_spec: spec,
        index: 1,
        vrf_hex: V1_VRF,
        bls_hex: V1_BLS,
        p2p_dial: Some(&hub_p2p),
        slot_duration_ms: SLOT_DURATION_MS,
        produce: false,
    });
    watch_stdout(out1, Arc::clone(&log1), Some(Arc::clone(&sealed)));
    watch_stderr(&mut v1.child, Arc::clone(&log1));

    thread::sleep(Duration::from_millis(1500));

    let (_, _) = wait_first_block(
        v0.rpc,
        &[v1.rpc],
        &sealed,
        Duration::from_secs(90),
        &[Arc::clone(&log0), Arc::clone(&log1)],
    );
    let (h1, _) = wait_common_tip(v0.rpc, &[v1.rpc], 1, Duration::from_secs(15));
    assert_eq!(h1, 1, "hub should be at height 1 before v2 joins");

    let log2 = Arc::new(Mutex::new(Vec::new()));
    let (mut v2, out2) = spawn_validator(&SpawnOpts {
        data_dir: &dir2,
        genesis_spec: spec,
        index: 2,
        vrf_hex: V2_VRF,
        bls_hex: V2_BLS,
        p2p_dial: Some(&hub_p2p),
        slot_duration_ms: SLOT_DURATION_MS,
        produce: false,
    });
    watch_stdout(out2, Arc::clone(&log2), None);
    watch_stderr(&mut v2.child, Arc::clone(&log2));

    thread::sleep(Duration::from_millis(2000));

    let (height, _) = wait_first_block(
        v0.rpc,
        &[v1.rpc, v2.rpc],
        &sealed,
        Duration::from_secs(120),
        &[Arc::clone(&log0), Arc::clone(&log1), Arc::clone(&log2)],
    );
    assert!(
        height >= 1,
        "all validators should share tip at height >= 1"
    );

    (v0, v1, v2)
}

fn assert_light_scan_three_validator(stdout: &str, wallet_path: &Path, scan_height: u32) {
    let expected = emission_at_height(u64::from(scan_height), &DEFAULT_EMISSION_PARAMS);
    assert!(
        stdout.contains(&format!("balance={expected}")),
        "stdout={stdout}"
    );
    assert!(stdout.contains("sync_mode=light"));
    assert!(stdout.contains("weak_subjectivity=pinned"));
    let reloaded = WalletFile::load(wallet_path).expect("reload wallet");
    assert!(reloaded.trusted_light_summary.is_some());
    assert!(reloaded
        .light_checkpoint_hex
        .as_ref()
        .is_some_and(|h| h.len() > 64));
    let summary = reloaded.trusted_light_summary.expect("summary");
    assert_eq!(
        summary.validator_count, 3,
        "expected three validators in trusted summary"
    );
}

/// Live three-validator mesh + `wallet light-scan` (up to ~3 min). Skipped in default CI.
#[test]
#[ignore = "slow three-validator mesh (nightly scripts/ci-ignored); run: cargo test -p mfn-cli --test light_scan_three_validator_smoke -- --ignored"]
fn wallet_light_scan_three_validator_mesh() {
    let spec = spec_path();
    assert!(spec.is_file(), "missing genesis {}", spec.display());

    let wallet_dir = unique_data_dir("wallet");
    std::fs::create_dir_all(&wallet_dir).expect("tmpdir");
    let wallet_path = wallet_dir.join("wallet.json");
    let mut file = WalletFile::new(&PAYOUT_SEED, KeyDerivation::PayoutStealthV1);
    file.save(&wallet_path).expect("write wallet");

    let (mut v0, mut v1, mut v2) = start_three_validator_mesh(&spec);
    let hub_rpc = v0.rpc;

    let out = mfn_cli()
        .args([
            "--rpc",
            &hub_rpc.to_string(),
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
    assert_light_scan_three_validator(&String::from_utf8_lossy(&out.stdout), &wallet_path, 1);

    let reloaded = WalletFile::load(&wallet_path).expect("reload wallet");
    let snap = rpc_result(&tcp_request_json(
        hub_rpc,
        r#"{"jsonrpc":"2.0","method":"get_light_snapshot","params":{"height":1},"id":2}"#,
    ));
    let summary_path = wallet_dir.join("trusted-summary.json");
    let export = mfn_cli()
        .args([
            "--rpc",
            &hub_rpc.to_string(),
            "--wallet",
            wallet_path.to_str().expect("utf8 path"),
            "wallet",
            "export-trusted-summary",
            "--height",
            "1",
            "--out",
            summary_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("export");
    assert!(export.status.success());

    let compare = mfn_cli()
        .args([
            "--wallet",
            wallet_path.to_str().expect("utf8 path"),
            "wallet",
            "compare-trusted-summary",
            summary_path.to_str().expect("utf8 path"),
            "--against-checkpoint",
        ])
        .output()
        .expect("compare");
    assert!(
        compare.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&compare.stderr)
    );

    let pinned_tip_height = reloaded
        .trusted_light_summary
        .as_ref()
        .expect("pinned")
        .tip_height;

    let mut cleared = reloaded;
    cleared.trusted_light_summary = None;
    cleared
        .save(&wallet_path)
        .expect("clear pin for import-on-scan test");

    let scan_import = mfn_cli()
        .args([
            "--rpc",
            &hub_rpc.to_string(),
            "--wallet",
            wallet_path.to_str().expect("utf8 path"),
            "wallet",
            "light-scan",
            "--import-trusted-summary",
            summary_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("light-scan --import-trusted-summary");
    assert!(
        scan_import.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&scan_import.stderr)
    );
    let after_import = WalletFile::load(&wallet_path).expect("reload after import scan");
    assert!(after_import.trusted_light_summary.is_some());
    assert_eq!(
        after_import
            .trusted_light_summary
            .as_ref()
            .expect("summary")
            .validator_count,
        3
    );

    let rpc_summary = snap["summary"].as_object().expect("summary object");
    assert_eq!(
        pinned_tip_height,
        u32::try_from(rpc_summary["tip_height"].as_u64().unwrap_or(0)).unwrap_or(0)
    );

    shutdown_child(&mut v0.child);
    shutdown_child(&mut v1.child);
    shutdown_child(&mut v2.child);
    std::fs::remove_dir_all(&wallet_dir).ok();
}
