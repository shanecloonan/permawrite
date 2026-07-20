//! Hub `mfnd serve --produce` plus two `--committee-vote` peers converge on one tip (**M2.3.24**),
//! then advance through height 2 on the next slot (**M2.3.25**).

use std::io::ErrorKind;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

const THREE_VALIDATOR_SPEC: &str = "testdata/devnet_three_validators.json";

const V0_VRF: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const V0_BLS: &str = "6565656565656565656565656565656565656565656565656565656565656565";
const V1_VRF: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const V1_BLS: &str = "7676767676767676767676767676767676767676767676767676767676767676";
const V2_VRF: &str = "0303030303030303030303030303030303030303030303030303030303030303";
const V2_BLS: &str = "8787878787878787878787878787878787878787878787878787878787878787";

fn mfnd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mfnd"))
}

fn spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(THREE_VALIDATOR_SPEC)
}

fn unique_data_dir(test: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("permawrite-{test}-{}-{nanos}", std::process::id()))
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
                std::thread::sleep(Duration::from_millis(250));
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

fn dump_log(label: &str, log: &Arc<Mutex<Vec<String>>>) {
    eprintln!("--- {label} stdout (last lines) ---");
    if let Ok(g) = log.lock() {
        for line in g.iter().rev().take(40).rev() {
            eprintln!("{line}");
        }
    }
}

struct ValidatorNode {
    child: Child,
    rpc: SocketAddr,
    p2p: SocketAddr,
}

/// B-75 / B-71: free loopback port in persistable band (`< MIN_EPHEMERAL_PEER_PORT`).
fn reserve_persistable_p2p() -> SocketAddr {
    const LO: u16 = 19_000;
    let hi = mfn_store::MIN_EPHEMERAL_PEER_PORT;
    let span = hi - LO;
    let start = LO + (std::process::id() as u16 % span);
    for i in 0..span {
        let port = LO + ((start - LO + i) % span);
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            let addr = listener.local_addr().expect("local addr");
            drop(listener);
            return addr;
        }
    }
    panic!("no free persistable loopback port in {LO}..{hi}");
}

#[allow(clippy::too_many_arguments)]
fn spawn_produce_validator(
    data_dir: &Path,
    genesis_spec: &Path,
    index: u32,
    vrf_hex: &str,
    bls_hex: &str,
    p2p_dial: Option<&str>,
    slot_duration_ms: u64,
    slot_producer: bool,
) -> (ValidatorNode, BufReader<impl Read + Send + 'static>) {
    let p2p_listen = reserve_persistable_p2p();
    let mut cmd = mfnd();
    cmd.args(["--data-dir"])
        .arg(data_dir)
        .arg("--genesis")
        .arg(genesis_spec)
        .arg("--store")
        .arg("fs")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-listen")
        .arg(p2p_listen.to_string())
        .arg("--slot-duration-ms")
        .arg(slot_duration_ms.to_string())
        .env("MFND_VALIDATOR_INDEX", index.to_string())
        .env("MFND_VRF_SEED_HEX", vrf_hex)
        .env("MFND_BLS_SEED_HEX", bls_hex)
        // B-69 / B-29: isolate CI mesh from published public_devnet seed_nodes.
        .env("MFN_SKIP_MANIFEST_SEEDS", "1")
        .arg("serve");
    if slot_producer {
        cmd.arg("--produce");
    } else {
        cmd.arg("--committee-vote");
    }
    if let Some(dial) = p2p_dial {
        cmd.arg("--p2p-dial").arg(dial);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mfnd produce serve");
    let stderr = child.stderr.take().expect("stderr");
    drain_stderr(stderr);
    let stdout = child.stdout.take().expect("stdout");
    let mut out = BufReader::new(stdout);
    let (rpc, p2p) = read_startup_addrs(&mut child, &mut out, slot_producer, p2p_dial.is_some());
    (ValidatorNode { child, rpc, p2p }, out)
}

/// `mfnd serve` may print role/dial lines before listen addrs; accept any order.
fn read_startup_addrs(
    child: &mut Child,
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
                "timeout during mfnd startup (rpc={rpc:?} p2p={p2p:?} role={got_role} dial={got_dial} last={line:?})"
            );
        }
        line.clear();
        let n = out.read_line(&mut line).expect("read mfnd stdout");
        if n == 0 {
            let status = child.try_wait().ok().flatten();
            panic!("mfnd exited during startup (status={status:?} last={line:?})");
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

fn shutdown_child(child: &mut Child) {
    let _ = child.kill();
    for _ in 0..20 {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    #[cfg(windows)]
    {
        let pid = child.id();
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status();
    }
    for _ in 0..20 {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn get_tip(rpc: SocketAddr) -> (u64, String) {
    let resp = tcp_request_json(rpc, r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#);
    let r = rpc_result(&resp);
    let height = r["tip_height"].as_u64().expect("tip_height");
    let tip_id = r["tip_id"].as_str().expect("tip_id hex").to_string();
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
            let mut tips = vec![("hub".to_string(), get_tip(hub))];
            for (i, &rpc) in followers.iter().enumerate() {
                tips.push((format!("v{}", i + 1), get_tip(rpc)));
            }
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
            panic!(
                "timeout waiting for followers to match hub tip (min_height={min_height}): {tips:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
}

fn block_id_at_height(rpc: SocketAddr, height: u64) -> String {
    let req = format!(
        r#"{{"jsonrpc":"2.0","method":"get_block_header","params":{{"height":{height}}},"id":2}}"#
    );
    let resp = tcp_request_json(rpc, &req);
    let r = rpc_result(&resp);
    r["block_id"].as_str().expect("block_id").to_string()
}

/// Live `--produce` + `--committee-vote` convergence (up to ~3 min). Skipped in default CI.
#[test]
#[ignore = "slow multi-validator produce harness; run with cargo test -- --ignored"]
fn three_validators_produce_converge_on_shared_tip() {
    let spec = spec_path();
    let slot_ms = 10_000u64;
    let target_height = 2u64;

    let dir0 = unique_data_dir("produce_v0");
    let dir1 = unique_data_dir("produce_v1");
    let dir2 = unique_data_dir("produce_v2");

    let sealed = Arc::new(AtomicBool::new(false));
    let log0 = Arc::new(Mutex::new(Vec::new()));
    let log1 = Arc::new(Mutex::new(Vec::new()));
    let (mut v0, out0) =
        spawn_produce_validator(&dir0, &spec, 0, V0_VRF, V0_BLS, None, slot_ms, true);
    let hub_p2p = v0.p2p.to_string();
    watch_stdout(out0, Arc::clone(&log0), Some(Arc::clone(&sealed)));

    thread::sleep(Duration::from_millis(500));

    let (mut v1, out1) = spawn_produce_validator(
        &dir1,
        &spec,
        1,
        V1_VRF,
        V1_BLS,
        Some(&hub_p2p),
        slot_ms,
        false,
    );
    watch_stdout(out1, Arc::clone(&log1), Some(Arc::clone(&sealed)));

    thread::sleep(Duration::from_millis(1500));

    let (_, hub_tip) = wait_first_block(
        v0.rpc,
        &[v1.rpc],
        &sealed,
        Duration::from_secs(90),
        &[Arc::clone(&log0), Arc::clone(&log1)],
    );

    let (height, _tip_id) = wait_common_tip(v0.rpc, &[v1.rpc], 1, Duration::from_secs(15));
    assert_eq!(height, 1, "hub advanced before v2 joined");

    let log2 = Arc::new(Mutex::new(Vec::new()));
    let (mut v2, out2) = spawn_produce_validator(
        &dir2,
        &spec,
        2,
        V2_VRF,
        V2_BLS,
        Some(&hub_p2p),
        slot_ms,
        false,
    );
    watch_stdout(out2, Arc::clone(&log2), None);

    thread::sleep(Duration::from_millis(2000));

    let (height, tip_id) = wait_first_block(
        v0.rpc,
        &[v1.rpc, v2.rpc],
        &sealed,
        Duration::from_secs(120),
        &[Arc::clone(&log0), Arc::clone(&log1), log2],
    );
    assert!(height >= 1, "height={height}");
    let (_, hub_tip_now) = get_tip(v0.rpc);
    assert_eq!(
        tip_id, hub_tip_now,
        "tip drifted from hub after convergence at height 1"
    );

    let (height2, tip2) = wait_common_tip(
        v0.rpc,
        &[v1.rpc, v2.rpc],
        target_height,
        Duration::from_secs(150),
    );
    assert_eq!(height2, target_height, "expected height {target_height}");
    assert_eq!(
        get_tip(v0.rpc).1,
        tip2,
        "hub tip drifted before height-2 checks"
    );

    let block1_v0 = block_id_at_height(v0.rpc, 1);
    assert_eq!(
        block1_v0, hub_tip,
        "first sealed block id should match initial hub tip"
    );
    let block1_v1 = block_id_at_height(v1.rpc, 1);
    let block1_v2 = block_id_at_height(v2.rpc, 1);
    assert_eq!(block1_v0, block1_v1, "height-1 block mismatch v0/v1");
    assert_eq!(block1_v1, block1_v2, "height-1 block mismatch v1/v2");

    let block_at_tip_v0 = block_id_at_height(v0.rpc, height2);
    let block_at_tip_v2 = block_id_at_height(v2.rpc, height2);
    assert_eq!(
        block_at_tip_v0, block_at_tip_v2,
        "tip block id should match across validators at height {height2}"
    );
    assert_eq!(
        block_at_tip_v0, tip2,
        "get_tip tip_id should match get_block at tip height"
    );
    assert_ne!(
        block_at_tip_v0, hub_tip,
        "height-2 tip should differ from height-1 block id"
    );

    shutdown_child(&mut v0.child);
    shutdown_child(&mut v1.child);
    shutdown_child(&mut v2.child);
    std::fs::remove_dir_all(&dir0).ok();
    std::fs::remove_dir_all(&dir1).ok();
    std::fs::remove_dir_all(&dir2).ok();
}

fn drain_stdout(mut reader: BufReader<impl Read + Send + 'static>) {
    thread::spawn(move || {
        let mut line = String::new();
        while reader.read_line(&mut line).ok().is_some_and(|n| n > 0) {
            line.clear();
        }
    });
}

fn drain_stderr(mut reader: impl Read + Send + 'static) {
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while reader.read(&mut buf).ok().is_some_and(|n| n > 0) {}
    });
}

fn log_contains_any(log: &Arc<Mutex<Vec<String>>>, needle: &str) -> bool {
    log.lock()
        .ok()
        .is_some_and(|g| g.iter().any(|l| l.contains(needle)))
}

/// Public-devnet hub must not stall at genesis when validator 0 is ineligible at slot 1.
#[test]
fn public_devnet_hub_reaches_height_one_within_one_slot_duration() {
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/public_devnet_v1.json");
    let slot_ms = 2_000u64;
    let dir0 = unique_data_dir("public_devnet_hub");
    let dir1 = unique_data_dir("public_devnet_v1");
    let dir2 = unique_data_dir("public_devnet_v2");

    let sealed = Arc::new(AtomicBool::new(false));
    let log0 = Arc::new(Mutex::new(Vec::new()));
    let (mut v0, out0) =
        spawn_produce_validator(&dir0, &spec, 0, V0_VRF, V0_BLS, None, slot_ms, true);
    let hub_p2p = v0.p2p.to_string();
    watch_stdout(out0, Arc::clone(&log0), Some(Arc::clone(&sealed)));

    thread::sleep(Duration::from_millis(500));

    let (mut v1, out1) = spawn_produce_validator(
        &dir1,
        &spec,
        1,
        V1_VRF,
        V1_BLS,
        Some(&hub_p2p),
        slot_ms,
        false,
    );
    drain_stdout(out1);

    thread::sleep(Duration::from_millis(500));

    let (mut v2, out2) = spawn_produce_validator(
        &dir2,
        &spec,
        2,
        V2_VRF,
        V2_BLS,
        Some(&hub_p2p),
        slot_ms,
        false,
    );
    drain_stdout(out2);

    let mesh_ready = Instant::now();
    // Local dev: keep the one-slot SLA tight. GHA runners under the full
    // workspace test matrix need several slot periods before the three-validator
    // mesh seals block 1 (CI `#29715111633` timed out at 20s on all three OSes).
    let gha_runner = std::env::var("GITHUB_ACTIONS").is_ok() || std::env::var("CI").is_ok();
    let within_one_slot = if gha_runner {
        Duration::from_secs(60)
    } else {
        Duration::from_millis(slot_ms + 1_500)
    };
    let first_block_budget = if gha_runner {
        Duration::from_secs(60)
    } else {
        Duration::from_secs(20)
    };
    let (height, _) = wait_first_block(
        v0.rpc,
        &[v1.rpc, v2.rpc],
        &sealed,
        first_block_budget,
        &[Arc::clone(&log0)],
    );
    assert!(
        height >= 1,
        "expected at least one sealed block (got height={height})"
    );
    assert!(
        mesh_ready.elapsed() <= within_one_slot,
        "mesh should seal block 1 within one slot duration after startup (elapsed={:?}, budget={within_one_slot:?})",
        mesh_ready.elapsed()
    );

    // Under GHA matrix load the first seal may land without a captured
    // `slot_advance` line (stdout drain races). Accept sealed/proposal too.
    assert!(
        log_contains_any(&log0, "mfnd_producer_slot_advance")
            || log_contains_any(&log0, "mfnd_producer_sealed")
            || log_contains_any(&log0, "mfnd_producer_proposal"),
        "hub should produce (slot_advance|sealed|proposal) within one producer tick"
    );
    assert!(
        !log_contains_any(&log0, "scans_exhausted="),
        "slot scan window should not exhaust before first proposal"
    );
    assert!(
        !log_contains_any(&log0, "mfnd_p2p_catchup_cap_reached"),
        "hub --produce must not run periodic committee catch-up dials"
    );

    shutdown_child(&mut v0.child);
    shutdown_child(&mut v1.child);
    shutdown_child(&mut v2.child);
    std::fs::remove_dir_all(&dir0).ok();
    std::fs::remove_dir_all(&dir1).ok();
    std::fs::remove_dir_all(&dir2).ok();
}
