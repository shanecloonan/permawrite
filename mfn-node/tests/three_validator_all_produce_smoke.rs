//! Three validators each run `mfnd serve --produce` on a 1.5-proposer devnet spec (**M2.3.26**).
//!
//! Exercises cryptographic sortition (`expected_proposers_per_slot: 1.5`), competing proposals,
//! and `pick_winner` convergence when every node runs the slot loop.

use std::io::ErrorKind;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mfn_node::genesis_config_from_json_path;
use serde_json::Value;

const PRODUCE_SPEC: &str = "testdata/devnet_three_validators_produce.json";

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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PRODUCE_SPEC)
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

fn watch_stdout(
    mut reader: BufReader<impl Read + Send + 'static>,
    log: Arc<Mutex<Vec<String>>>,
    sealed_flag: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let mut line = String::new();
        while reader.read_line(&mut line).ok().is_some_and(|n| n > 0) {
            if line.contains("mfnd_producer_sealed") {
                sealed_flag.store(true, Ordering::Relaxed);
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

fn spawn_producer(
    data_dir: &Path,
    genesis_spec: &Path,
    index: u32,
    vrf_hex: &str,
    bls_hex: &str,
    p2p_dials: &[&str],
) -> (ValidatorNode, BufReader<impl Read + Send + 'static>) {
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
        .arg("127.0.0.1:0")
        .arg("--slot-duration-ms")
        .arg("8000")
        .env("MFND_VALIDATOR_INDEX", index.to_string())
        .env("MFND_VRF_SEED_HEX", vrf_hex)
        .env("MFND_BLS_SEED_HEX", bls_hex)
        .arg("serve")
        .arg("--produce");
    for dial in p2p_dials {
        cmd.arg("--p2p-dial").arg(*dial);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mfnd serve --produce");
    let stdout = child.stdout.take().expect("stdout");
    let mut out = BufReader::new(stdout);
    let (rpc, p2p) = read_startup_addrs(&mut out, !p2p_dials.is_empty());
    (ValidatorNode { child, rpc, p2p }, out)
}

fn read_startup_addrs(out: &mut BufReader<impl Read>, need_dial: bool) -> (SocketAddr, SocketAddr) {
    let mut rpc = None;
    let mut p2p = None;
    let mut got_role = false;
    let mut got_dial = !need_dial;
    let deadline = Instant::now() + Duration::from_secs(60);
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
            panic!("mfnd exited during startup (last={line:?})");
        }
        if let Some(rest) = line.strip_prefix("mfnd_serve_listening=") {
            rpc = Some(rest.trim().parse().expect("rpc addr"));
        } else if let Some(rest) = line.strip_prefix("mfnd_p2p_listening=") {
            p2p = Some(rest.trim().parse().expect("p2p addr"));
        } else if line.starts_with("mfnd_producer_start ") {
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

fn wait_common_tip(
    nodes: &[SocketAddr],
    min_height: u64,
    sealed: &[Arc<AtomicBool>],
    timeout: Duration,
    logs: &[Arc<Mutex<Vec<String>>>],
) -> (u64, String) {
    let deadline = Instant::now() + timeout;
    loop {
        let (h0, id0) = get_tip(nodes[0]);
        if h0 >= min_height
            && nodes[1..]
                .iter()
                .all(|&rpc| get_tip(rpc) == (h0, id0.clone()))
        {
            return (h0, id0);
        }
        if sealed.iter().any(|f| f.load(Ordering::Relaxed)) {
            let (h0, id0) = get_tip(nodes[0]);
            if h0 >= min_height
                && nodes[1..]
                    .iter()
                    .all(|&rpc| get_tip(rpc) == (h0, id0.clone()))
            {
                return (h0, id0);
            }
        }
        if Instant::now() >= deadline {
            let tips: Vec<_> = nodes.iter().map(|&rpc| get_tip(rpc)).collect();
            let saw: Vec<_> = sealed.iter().map(|f| f.load(Ordering::Relaxed)).collect();
            for (i, log) in logs.iter().enumerate() {
                dump_log(&format!("v{i}"), log);
            }
            panic!(
                "timeout waiting for common tip min_height={min_height} tips={tips:?} saw_sealed={saw:?}"
            );
        }
        thread::sleep(Duration::from_millis(500));
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

fn log_contains_any(log: &Arc<Mutex<Vec<String>>>, needle: &str) -> bool {
    log.lock()
        .ok()
        .is_some_and(|g| g.iter().any(|l| l.contains(needle)))
}

#[test]
fn produce_spec_uses_expected_proposers_per_slot_1_5() {
    let cfg = genesis_config_from_json_path(&spec_path()).expect("spec");
    assert!(
        (cfg.params.expected_proposers_per_slot - 1.5).abs() < f64::EPSILON,
        "got {}",
        cfg.params.expected_proposers_per_slot
    );
}

/// Three-way `--produce` slot timer (up to ~3 min). Skipped in default CI.
#[test]
#[ignore = "slow three-validator all-produce harness; run with cargo test -- --ignored"]
fn three_validators_all_produce_converge_on_shared_tip() {
    let spec = spec_path();
    let dir0 = unique_data_dir("all_produce_v0");
    let dir1 = unique_data_dir("all_produce_v1");
    let dir2 = unique_data_dir("all_produce_v2");

    let sealed0 = Arc::new(AtomicBool::new(false));
    let sealed1 = Arc::new(AtomicBool::new(false));
    let sealed2 = Arc::new(AtomicBool::new(false));
    let log0 = Arc::new(Mutex::new(Vec::new()));
    let log1 = Arc::new(Mutex::new(Vec::new()));
    let log2 = Arc::new(Mutex::new(Vec::new()));

    let (mut v0, out0) = spawn_producer(&dir0, &spec, 0, V0_VRF, V0_BLS, &[]);
    watch_stdout(out0, Arc::clone(&log0), Arc::clone(&sealed0));
    let hub_p2p = v0.p2p.to_string();

    thread::sleep(Duration::from_millis(500));

    let (mut v1, out1) = spawn_producer(&dir1, &spec, 1, V1_VRF, V1_BLS, &[&hub_p2p]);
    watch_stdout(out1, Arc::clone(&log1), Arc::clone(&sealed1));

    thread::sleep(Duration::from_millis(500));

    let v1_p2p = v1.p2p.to_string();
    let (mut v2, out2) = spawn_producer(&dir2, &spec, 2, V2_VRF, V2_BLS, &[&hub_p2p, &v1_p2p]);
    watch_stdout(out2, Arc::clone(&log2), Arc::clone(&sealed2));

    thread::sleep(Duration::from_millis(1500));

    let nodes = [v0.rpc, v1.rpc, v2.rpc];
    let sealed = [sealed0, sealed1, sealed2];
    let logs = [log0, log1, log2];

    let (height, tip_id) = wait_common_tip(&nodes, 3, &sealed, Duration::from_secs(240), &logs);
    assert!(
        height >= 3,
        "expected at least three sealed blocks, got {height}"
    );

    let b0 = block_id_at_height(v0.rpc, height);
    let b1 = block_id_at_height(v1.rpc, height);
    let b2 = block_id_at_height(v2.rpc, height);
    assert_eq!(
        b0, tip_id,
        "get_tip tip_id should match get_block_header at tip height"
    );
    assert_eq!(b0, b1, "canonical block mismatch v0/v1 at height {height}");
    assert_eq!(b1, b2, "canonical block mismatch v1/v2 at height {height}");

    let sortition_observed = logs.iter().any(|l| {
        log_contains_any(l, "mfnd_producer_slot_skip")
            || log_contains_any(l, "mfnd_producer_slot_advance")
    });
    assert!(
        sortition_observed,
        "expected sortition slot scan (skip or advance) under expected_proposers_per_slot=1.5 at height={height}"
    );

    shutdown_child(&mut v0.child);
    shutdown_child(&mut v1.child);
    shutdown_child(&mut v2.child);
    std::fs::remove_dir_all(&dir0).ok();
    std::fs::remove_dir_all(&dir1).ok();
    std::fs::remove_dir_all(&dir2).ok();
}
