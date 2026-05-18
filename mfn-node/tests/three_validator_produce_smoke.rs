//! Three `mfnd serve --produce` processes on a shared genesis converge on one tip (**M2.3.24**).

use std::io::ErrorKind;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

fn read_line_with_prefix(out: &mut BufReader<impl Read>, prefix: &str) -> String {
    let mut line = String::new();
    loop {
        line.clear();
        let n = out.read_line(&mut line).expect("read mfnd stdout");
        if n == 0 {
            panic!("mfnd exited before `{prefix}` (last={line:?})");
        }
        if line.starts_with(prefix) {
            return line;
        }
    }
}

fn drain_stdout(reader: BufReader<impl Read + Send + 'static>) {
    std::thread::spawn(move || {
        let mut out = reader;
        let mut line = String::new();
        while out.read_line(&mut line).ok().is_some_and(|n| n > 0) {
            line.clear();
        }
    });
}

fn watch_stdout_for_substring(
    mut reader: BufReader<impl Read + Send + 'static>,
    needle: &'static str,
    flag: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let mut line = String::new();
        while reader.read_line(&mut line).ok().is_some_and(|n| n > 0) {
            if line.contains(needle) {
                flag.store(true, Ordering::Relaxed);
            }
            line.clear();
        }
    });
}

struct ValidatorNode {
    child: Child,
    rpc: SocketAddr,
    p2p: SocketAddr,
}

fn spawn_produce_validator(
    data_dir: &Path,
    genesis_spec: &Path,
    index: u32,
    vrf_hex: &str,
    bls_hex: &str,
    p2p_dial: Option<&str>,
    slot_duration_ms: u64,
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
        .arg("--produce")
        .arg("--slot-duration-ms")
        .arg(slot_duration_ms.to_string())
        .env("MFND_VALIDATOR_INDEX", index.to_string())
        .env("MFND_VRF_SEED_HEX", vrf_hex)
        .env("MFND_BLS_SEED_HEX", bls_hex)
        .arg("serve");
    if let Some(dial) = p2p_dial {
        cmd.arg("--p2p-dial").arg(dial);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mfnd produce serve");
    let stdout = child.stdout.take().expect("stdout");
    let mut out = BufReader::new(stdout);
    let rpc_line = read_line_with_prefix(&mut out, "mfnd_serve_listening=");
    let rpc: SocketAddr = rpc_line
        .strip_prefix("mfnd_serve_listening=")
        .unwrap()
        .trim()
        .parse()
        .expect("rpc addr");
    let p2p_line = read_line_with_prefix(&mut out, "mfnd_p2p_listening=");
    let p2p: SocketAddr = p2p_line
        .strip_prefix("mfnd_p2p_listening=")
        .unwrap()
        .trim()
        .parse()
        .expect("p2p addr");
    if p2p_dial.is_some() {
        read_line_with_prefix(&mut out, "mfnd_p2p_dial_ok=");
    }
    (ValidatorNode { child, rpc, p2p }, out)
}

fn wait_for_p2p_catch_up(
    out: &mut BufReader<impl Read>,
    hub_rpc: SocketAddr,
    follower_rpc: SocketAddr,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    let mut line = String::new();
    loop {
        if Instant::now() >= deadline {
            let (_, hub_tip) = get_tip(hub_rpc);
            let (fh, ft) = get_tip(follower_rpc);
            assert_eq!(ft, hub_tip, "follower tip_id diverged at height {fh}");
            return;
        }
        line.clear();
        let n = out.read_line(&mut line).expect("read mfnd stdout");
        if n == 0 {
            panic!("mfnd exited while waiting for catch-up (last={line:?})");
        }
        if line.starts_with("mfnd_p2p_sync_end ") {
            return;
        }
        if line.starts_with("mfnd_p2p_sync_abort ") {
            panic!("catch-up failed: {line}");
        }
        let (_, hub_tip) = get_tip(hub_rpc);
        let (fh, ft) = get_tip(follower_rpc);
        if fh > 0 && ft == hub_tip {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn get_tip(rpc: SocketAddr) -> (u64, String) {
    let resp = tcp_request_json(rpc, r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#);
    let r = rpc_result(&resp);
    let height = r["tip_height"].as_u64().expect("tip_height");
    let tip_id = r["tip_id"].as_str().expect("tip_id hex").to_string();
    (height, tip_id)
}

fn wait_matching_tip(hub: SocketAddr, follower: SocketAddr, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let (hh, hid) = get_tip(hub);
        let (fh, fid) = get_tip(follower);
        if fh >= hh && fid == hid {
            return;
        }
        if Instant::now() >= deadline {
            panic!("timeout waiting for follower sync: hub=({hh},{hid}) follower=({fh},{fid})");
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
}

fn wait_first_block(
    rpcs: [SocketAddr; 2],
    sealed_flag: &AtomicBool,
    timeout: Duration,
) -> (u64, String) {
    let deadline = Instant::now() + timeout;
    loop {
        for &rpc in &rpcs {
            let (h, id) = get_tip(rpc);
            if h >= 1 {
                return (h, id);
            }
        }
        if sealed_flag.load(Ordering::Relaxed) {
            for &rpc in &rpcs {
                let (h, id) = get_tip(rpc);
                if h >= 1 {
                    return (h, id);
                }
            }
        }
        if Instant::now() >= deadline {
            let h0 = get_tip(rpcs[0]).0;
            let h1 = get_tip(rpcs[1]).0;
            let sealed = sealed_flag.load(Ordering::Relaxed);
            panic!(
                "timeout waiting for first sealed block (heights {h0},{h1}, saw_sealed={sealed})"
            );
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn wait_common_tip(rpcs: [SocketAddr; 3], min_height: u64, timeout: Duration) -> (u64, String) {
    let deadline = Instant::now() + timeout;
    loop {
        let tips: Vec<_> = rpcs.iter().map(|&a| get_tip(a)).collect();
        let heights: Vec<u64> = tips.iter().map(|(h, _)| *h).collect();
        let ids: Vec<&str> = tips.iter().map(|(_, id)| id.as_str()).collect();
        if heights.iter().all(|&h| h >= min_height) && ids[0] == ids[1] && ids[1] == ids[2] {
            return tips[0].clone();
        }
        if Instant::now() >= deadline {
            panic!(
                "timeout waiting for common tip >= {min_height}: heights={heights:?} ids={ids:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
}

fn block_id_at_height(rpc: SocketAddr, height: u64) -> String {
    let req = format!(
        r#"{{"jsonrpc":"2.0","method":"get_block","params":{{"height":{height}}},"id":2}}"#
    );
    let resp = tcp_request_json(rpc, &req);
    let r = rpc_result(&resp);
    r["block_id"].as_str().expect("block_id").to_string()
}

#[test]
#[ignore = "M2.3.24 process harness; in-process quorum works in multi_validator_producer"]
fn three_validators_produce_converge_on_shared_tip() {
    let spec = spec_path();
    let slot_ms = 800u64;
    let target_height = 2u64;
    let timeout = Duration::from_secs(180);

    let dir0 = unique_data_dir("produce_v0");
    let dir1 = unique_data_dir("produce_v1");
    let dir2 = unique_data_dir("produce_v2");

    let sealed = Arc::new(AtomicBool::new(false));
    let (mut v0, out0) = spawn_produce_validator(&dir0, &spec, 0, V0_VRF, V0_BLS, None, slot_ms);
    let hub_p2p = v0.p2p.to_string();
    watch_stdout_for_substring(out0, "mfnd_producer_sealed", Arc::clone(&sealed));

    thread::sleep(Duration::from_secs(1));

    let (mut v1, out1) =
        spawn_produce_validator(&dir1, &spec, 1, V1_VRF, V1_BLS, Some(&hub_p2p), slot_ms);
    watch_stdout_for_substring(out1, "mfnd_producer_sealed", Arc::clone(&sealed));

    let (_, hub_tip) = wait_first_block([v0.rpc, v1.rpc], &sealed, Duration::from_secs(120));
    wait_matching_tip(v0.rpc, v1.rpc, Duration::from_secs(60));

    let (mut v2, mut out2) =
        spawn_produce_validator(&dir2, &spec, 2, V2_VRF, V2_BLS, Some(&hub_p2p), slot_ms);
    wait_for_p2p_catch_up(&mut out2, v0.rpc, v2.rpc, Duration::from_secs(30));
    drain_stdout(out2);

    let (height, tip_id) = wait_common_tip([v0.rpc, v1.rpc, v2.rpc], target_height, timeout);
    assert!(height >= target_height, "height={height}");
    assert_eq!(tip_id, hub_tip, "tip drifted from hub after convergence");

    let block1_v0 = block_id_at_height(v0.rpc, 1);
    let block1_v1 = block_id_at_height(v1.rpc, 1);
    let block1_v2 = block_id_at_height(v2.rpc, 1);
    assert_eq!(block1_v0, block1_v1, "height-1 block mismatch v0/v1");
    assert_eq!(block1_v1, block1_v2, "height-1 block mismatch v1/v2");

    let block_at_tip_v0 = block_id_at_height(v0.rpc, height);
    let block_at_tip_v2 = block_id_at_height(v2.rpc, height);
    assert_eq!(
        block_at_tip_v0, block_at_tip_v2,
        "tip block id should match across validators"
    );
    assert_eq!(
        block_at_tip_v0, tip_id,
        "get_tip tip_id should match get_block at tip height"
    );

    let _ = v0.child.kill();
    let _ = v1.child.kill();
    let _ = v2.child.kill();
    let _ = v0.child.wait();
    let _ = v1.child.wait();
    let _ = v2.child.wait();
    std::fs::remove_dir_all(&dir0).ok();
    std::fs::remove_dir_all(&dir1).ok();
    std::fs::remove_dir_all(&dir2).ok();
}
