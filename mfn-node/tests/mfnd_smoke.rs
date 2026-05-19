//! Integration smoke tests for the `mfnd` binary (M2.1.1 + M2.1.2 + M2.1.3 + M2.1.4 + M2.1.5 + M2.1.6 + M2.1.6.1 + M2.1.7 + M2.1.8 + M2.1.8.1 + M2.1.9 + M2.1.10 + M2.1.11 + M2.1.12 + M2.1.13 + M2.1.14 + M2.1.15 + M2.1.16 + M2.1.17 + M2.1.18 + M2.2.8 + M2.2.10 + M2.3.3 + M2.3.4 + M2.3.5 + M2.3.6 + M2.3.7 + M2.3.8 + M2.3.9 + M2.3.10 + M2.3.11 + M2.3.12 + M2.3.13 + M2.3.14 + M2.3.15 + M2.3.16).

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mfn_consensus::{
    block_header_bytes, block_id, build_genesis, decode_block, decode_block_header, encode_block,
    encode_transaction, tx_id, TransactionWire, TX_VERSION,
};
use mfn_crypto::point::generator_g;
use mfn_crypto::seeded_rng;
use mfn_crypto::stealth_wallet_from_seed;
use mfn_node::{genesis_config_from_json_path, Chain, ChainConfig, NodeStore, StoreBackend};
use mfn_store::ChainPersistence;
use mfn_wallet::{TransferRecipient, Wallet, WalletKeys};
use serde_json::{json, Value};

#[path = "stdout_timeout.rs"]
mod stdout_timeout;

use stdout_timeout::{
    read_mfnd_serve_listening_addr, read_stdout_line_with_prefix, read_stdout_until_p2p_sync_end,
    P2P_LINE_TIMEOUT, P2P_SYNC_END_TIMEOUT, SERVE_LISTEN_TIMEOUT,
};

/// Seeds aligned with `testdata/devnet_one_validator.json` validator index 0.
const DEVNET_SOLO_VRF_SEED_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
const DEVNET_SOLO_BLS_SEED_HEX: &str =
    "6565656565656565656565656565656565656565656565656565656565656565";

fn mfnd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mfnd"))
}

/// Same backend `mfnd` uses when `--store` is omitted (currently `redb`).
fn open_mfnd_store(dir: &Path) -> NodeStore {
    open_mfnd_store_with_backend(dir, None)
}

fn open_mfnd_store_with_backend(dir: &Path, store: Option<&str>) -> NodeStore {
    let backend = match store {
        Some(s) => StoreBackend::parse(s).expect("parse store"),
        None => StoreBackend::default(),
    };
    NodeStore::open(backend, dir).expect("open mfnd store")
}

fn rpc_line(resp: &str) -> Value {
    serde_json::from_str(resp.trim()).expect("serve response must be JSON")
}

fn assert_rpc2_result(resp: &str) -> Value {
    let v = rpc_line(resp);
    assert_eq!(v["jsonrpc"], "2.0", "resp={v}");
    assert!(v.get("error").is_none() || v["error"].is_null(), "resp={v}");
    assert!(v.get("result").is_some(), "resp={v}");
    v["result"].clone()
}

fn assert_rpc2_error(resp: &str) -> (i64, String) {
    let v = rpc_line(resp);
    assert_eq!(v["jsonrpc"], "2.0", "resp={v}");
    let err = v
        .get("error")
        .expect("error object")
        .as_object()
        .expect("error must be object");
    (
        err["code"].as_i64().expect("code"),
        err["message"].as_str().expect("message").to_string(),
    )
}

fn assert_mfnd_p2p_handshake_ms_line(line: &str) {
    assert!(
        line.starts_with("mfnd_p2p_handshake_ms "),
        "expected mfnd_p2p_handshake_ms, got {line:?}"
    );
    let ms_s = line.split(" ms=").nth(1).expect("ms field").trim();
    let ms: u64 = ms_s.parse().expect("parse ms as u64");
    assert!(ms < 60_000, "handshake took {ms}ms, line={line:?}");
}

fn mfnd_p2p_hid_from_line(line: &str) -> u64 {
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("hid=") {
            return v.parse().expect("parse hid");
        }
    }
    panic!("no hid= token in line={line:?}");
}

/// Reads **`mfnd_p2p_peer_tip`** / **`mfnd_p2p_height_cmp`** / **`mfnd_p2p_handshake_ms`** from a listener
/// `mfnd serve` stdout after an external client has completed
/// [`mfn_node::network::tcp_connect_peer_v1_handshake_with_tip_exchange`]. Returns the session **`hid`**.
fn read_listener_p2p_handshake_session(
    child_out: &mut BufReader<ChildStdout>,
    tip_h: u32,
    tip_id_hex: &str,
) -> u64 {
    let mut peer_tip_line = String::new();
    child_out
        .read_line(&mut peer_tip_line)
        .expect("read mfnd_p2p_peer_tip from listener");
    assert!(
        peer_tip_line.starts_with("mfnd_p2p_peer_tip "),
        "expected mfnd_p2p_peer_tip, got {peer_tip_line:?}"
    );
    assert!(
        peer_tip_line.contains(&format!("height={tip_h} ")),
        "peer_tip_line={peer_tip_line:?}"
    );
    assert!(
        peer_tip_line.contains(&format!("tip_id={tip_id_hex}")),
        "peer_tip_line={peer_tip_line:?}"
    );
    let hid = mfnd_p2p_hid_from_line(&peer_tip_line);
    let mut height_cmp_line = String::new();
    child_out
        .read_line(&mut height_cmp_line)
        .expect("read mfnd_p2p_height_cmp from listener");
    assert!(
        height_cmp_line.starts_with("mfnd_p2p_height_cmp "),
        "expected mfnd_p2p_height_cmp, got {height_cmp_line:?}"
    );
    assert!(
        height_cmp_line.contains(&format!("local_height={tip_h} ")),
        "height_cmp_line={height_cmp_line:?}"
    );
    assert!(
        height_cmp_line.contains(&format!("remote_height={tip_h} ")),
        "height_cmp_line={height_cmp_line:?}"
    );
    assert!(
        height_cmp_line.contains("cmp=equal"),
        "height_cmp_line={height_cmp_line:?}"
    );
    assert_eq!(
        mfnd_p2p_hid_from_line(&height_cmp_line),
        hid,
        "height_cmp_line={height_cmp_line:?}"
    );
    let mut handshake_ms_line = String::new();
    child_out
        .read_line(&mut handshake_ms_line)
        .expect("read mfnd_p2p_handshake_ms from listener");
    assert_mfnd_p2p_handshake_ms_line(&handshake_ms_line);
    assert_eq!(
        mfnd_p2p_hid_from_line(&handshake_ms_line),
        hid,
        "handshake_ms_line={handshake_ms_line:?}"
    );
    hid
}

/// Spawns `mfnd serve` with `--rpc-listen 127.0.0.1:0`; caller must `kill` the child.
fn spawn_mfnd_serve(data_dir: &Path, genesis_spec: &Path) -> (Child, SocketAddr) {
    spawn_mfnd_serve_with_store(data_dir, genesis_spec, None)
}

fn spawn_mfnd_serve_with_store(
    data_dir: &Path,
    genesis_spec: &Path,
    store: Option<&str>,
) -> (Child, SocketAddr) {
    let mut cmd = mfnd();
    cmd.args(["--data-dir"])
        .arg(data_dir)
        .arg("--genesis")
        .arg(genesis_spec)
        .arg("--rpc-listen")
        .arg("127.0.0.1:0");
    if let Some(s) = store {
        cmd.arg("--store").arg(s);
    }
    let mut child = cmd
        .arg("serve")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mfnd serve");
    let stdout = child.stdout.take().expect("stdout pipe");
    let mut out_reader = BufReader::new(stdout);
    let sock = read_mfnd_serve_listening_addr(&mut out_reader, SERVE_LISTEN_TIMEOUT);
    thread::spawn(move || {
        let mut line = String::new();
        while let Ok(n) = out_reader.read_line(&mut line) {
            if n == 0 {
                break;
            }
            line.clear();
        }
    });
    (child, sock)
}

/// Spawns `mfnd serve` with `--rpc-listen` and `--p2p-listen` on ephemeral ports; reads
/// `mfnd_serve_listening=` then `mfnd_p2p_listening=` from stdout. Returns stdout and stderr
/// [`BufReader`]s so callers can read further lines (e.g. **`mfnd_p2p_peer_tip`** or
/// **`mfnd_p2p_handshake_abort`**).
fn spawn_mfnd_serve_with_p2p(
    data_dir: &Path,
    genesis_spec: &Path,
) -> (
    Child,
    BufReader<ChildStdout>,
    BufReader<ChildStderr>,
    SocketAddr,
    SocketAddr,
) {
    let mut child = mfnd()
        .args(["--data-dir"])
        .arg(data_dir)
        .arg("--genesis")
        .arg(genesis_spec)
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-listen")
        .arg("127.0.0.1:0")
        .arg("serve")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mfnd serve with p2p");
    let stdout = child.stdout.take().expect("stdout pipe");
    let stderr = child.stderr.take().expect("stderr pipe");
    let mut out_reader = BufReader::new(stdout);
    let err_reader = BufReader::new(stderr);
    let rpc_addr = read_mfnd_serve_listening_addr(&mut out_reader, SERVE_LISTEN_TIMEOUT);
    let p2p_line =
        read_stdout_line_with_prefix(&mut out_reader, "mfnd_p2p_listening=", SERVE_LISTEN_TIMEOUT);
    let p2p_s = p2p_line
        .strip_prefix("mfnd_p2p_listening=")
        .expect("p2p listening prefix")
        .trim();
    let p2p_addr: SocketAddr = p2p_s.parse().expect("parse p2p socket addr");
    (child, out_reader, err_reader, rpc_addr, p2p_addr)
}

fn wait_mempool_contains(rpc: SocketAddr, tx_id_hex: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let mp = tcp_request_json(rpc, r#"{"jsonrpc":"2.0","method":"get_mempool","id":99}"#);
        let mp_r = assert_rpc2_result(&mp);
        let ids = mp_r["tx_ids"].as_array().expect("tx_ids array");
        if ids.iter().any(|v| v.as_str() == Some(tx_id_hex)) {
            return;
        }
        if Instant::now() >= deadline {
            panic!("timeout waiting for tx_id={tx_id_hex} in mempool resp={mp_r}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn tcp_request_json(addr: SocketAddr, request_line: &str) -> String {
    let mut tcp = TcpStream::connect(addr).expect("tcp connect");
    writeln!(tcp, "{request_line}").expect("write request");
    let mut resp = String::new();
    BufReader::new(&tcp)
        .read_line(&mut resp)
        .expect("read response");
    resp
}

fn unique_data_dir(test: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "permawrite-mfnd-{test}-{}-{nanos}",
        std::process::id()
    ))
}

/// One `mfnd step` on `devnet_one_validator_synth_decoys.json`, then build a signed transfer from
/// the post-step chain state. Caller uses `data_dir` + `spec` for `serve` and `tx_hex` for
/// `submit_tx`; `tx_id_hex` matches `get_mempool` wire ids (64-char lowercase hex).
fn synth_decoy_one_step_signed_transfer_fixture(test: &str) -> (PathBuf, PathBuf, String, String) {
    synth_decoy_one_step_signed_transfer_fixture_with_store(test, None)
}

fn synth_decoy_one_step_signed_transfer_fixture_with_store(
    test: &str,
    store: Option<&str>,
) -> (PathBuf, PathBuf, String, String) {
    let dir = unique_data_dir(test);
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/devnet_one_validator_synth_decoys.json");
    let mut step = mfnd();
    step.args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX);
    if let Some(s) = store {
        step.arg("--store").arg(s);
    }
    let step_out = step.arg("step").output().expect("spawn mfnd step");
    assert!(
        step_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&step_out.stderr)
    );

    let store = open_mfnd_store_with_backend(&dir, store);
    let blocks = store.read_block_log().expect("read blocks");
    assert_eq!(
        blocks.len(),
        1,
        "expected one block log record after one step"
    );

    let gc = genesis_config_from_json_path(&spec).expect("genesis");
    let chain_cfg = ChainConfig::new(gc.clone());
    let genesis_block = build_genesis(&chain_cfg.genesis);

    let mut bls_seed = [0u8; 32];
    hex::decode_to_slice(DEVNET_SOLO_BLS_SEED_HEX, &mut bls_seed).expect("bls hex");
    let mut alice = Wallet::from_keys(WalletKeys::from_stealth(stealth_wallet_from_seed(
        &bls_seed,
    )));
    let bob = Wallet::from_seed(&[0xC0u8; 32]);

    alice.ingest_block(&genesis_block);
    alice.ingest_block(&blocks[0]);

    let chain = store
        .load_or_genesis(chain_cfg.clone())
        .expect("load chain");

    let mut rng = seeded_rng(0x7E11);
    let signed = alice
        .build_transfer(
            &[TransferRecipient {
                recipient: mfn_consensus::Recipient {
                    view_pub: bob.keys().view_pub(),
                    spend_pub: bob.keys().spend_pub(),
                },
                value: 50_000,
            }],
            10_000,
            8,
            chain.state(),
            b"mfnd-serve",
            &mut rng,
        )
        .expect("build transfer");

    let id_hex = hex::encode(tx_id(&signed.tx));
    let tx_hex = hex::encode(encode_transaction(&signed.tx));
    (dir, spec, tx_hex, id_hex)
}

#[test]
fn mfnd_status_boots_genesis_without_checkpoint() {
    let dir = unique_data_dir("status_no_ckpt");
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("status")
        .output()
        .expect("spawn mfnd");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tip_height=0"), "stdout={stdout}");
    assert!(
        stdout.contains("had_checkpoint_on_disk=false"),
        "stdout={stdout}"
    );
    assert!(stdout.contains("validator_count=0"), "stdout={stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_save_then_status_sees_checkpoint() {
    let dir = unique_data_dir("save_status");
    assert!(mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("save")
        .status()
        .expect("spawn")
        .success());
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("status")
        .output()
        .expect("spawn mfnd status");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("had_checkpoint_on_disk=true"),
        "stdout={stdout}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_status_with_json_genesis_spec() {
    let dir = unique_data_dir("genesis_spec");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("status")
        .output()
        .expect("spawn mfnd");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tip_height=0"), "stdout={stdout}");
    assert!(stdout.contains("validator_count=1"), "stdout={stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_errors_without_data_dir() {
    let out = mfnd().arg("status").output().expect("spawn");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--data-dir") || stderr.contains("data-dir"),
        "stderr={stderr}"
    );
}

#[test]
fn mfnd_step_requires_solo_seed_env() {
    let dir = unique_data_dir("step_no_env");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .env_remove("MFND_SOLO_VRF_SEED_HEX")
        .env_remove("MFND_SOLO_BLS_SEED_HEX")
        .arg("step")
        .output()
        .expect("spawn mfnd step");
    assert!(
        !out.status.success(),
        "expected failure without seeds, stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("MFND_SOLO_VRF_SEED_HEX") || stderr.contains("MFND_SOLO_BLS_SEED_HEX"),
        "stderr={stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_step_twice_advances_tip_under_devnet_spec() {
    let dir = unique_data_dir("step_twice");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let run_step = || {
        mfnd()
            .args(["--data-dir"])
            .arg(&dir)
            .arg("--genesis")
            .arg(&spec)
            .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
            .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
            .arg("step")
            .output()
            .expect("spawn mfnd step")
    };
    let o1 = run_step();
    assert!(
        o1.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&o1.stderr)
    );
    let stdout1 = String::from_utf8_lossy(&o1.stdout);
    assert!(stdout1.contains("new_tip_height=1"), "stdout={stdout1}");
    let o2 = run_step();
    assert!(
        o2.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&o2.stderr)
    );
    let stdout2 = String::from_utf8_lossy(&o2.stdout);
    assert!(stdout2.contains("new_tip_height=2"), "stdout={stdout2}");
    let st = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("status")
        .output()
        .expect("spawn mfnd status");
    assert!(st.status.success());
    let stout = String::from_utf8_lossy(&st.stdout);
    assert!(stout.contains("tip_height=2"), "stdout={stout}");
    assert!(
        stout.contains("had_checkpoint_on_disk=true"),
        "stdout={stout}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_step_blocks_advances_tip_in_one_invocation() {
    let dir = unique_data_dir("step_blocks");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("--blocks")
        .arg("3")
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .arg("step")
        .output()
        .expect("spawn mfnd step --blocks 3");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("new_tip_height=3"), "stdout={stdout}");
    let st = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("status")
        .output()
        .expect("spawn mfnd status");
    assert!(st.status.success());
    let stout = String::from_utf8_lossy(&st.stdout);
    assert!(stout.contains("tip_height=3"), "stdout={stout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_step_checkpoint_each_writes_after_each_block() {
    let dir = unique_data_dir("step_ckpt_each");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("--blocks")
        .arg("2")
        .arg("--checkpoint-each")
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .arg("step")
        .output()
        .expect("spawn mfnd step");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.matches("step_checkpoint").count(),
        2,
        "stdout={stdout}"
    );
    assert!(stdout.contains("new_tip_height=2"), "stdout={stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_get_tip_over_tcp() {
    let dir = unique_data_dir("serve_get_tip");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let resp = tcp_request_json(sock, "{\"method\":\"get_tip\"}");
    let r = assert_rpc2_result(&resp);
    assert!(r.get("tip_height").is_some(), "r={r}");
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_redb_store_get_tip_over_tcp() {
    let dir = unique_data_dir("serve_redb_get_tip");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let mut child = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("--store")
        .arg("redb")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("serve")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mfnd serve --store redb");
    let stdout = child.stdout.take().expect("stdout pipe");
    let mut out_reader = BufReader::new(stdout);
    let sock = read_mfnd_serve_listening_addr(&mut out_reader, SERVE_LISTEN_TIMEOUT);
    let resp = tcp_request_json(sock, "{\"method\":\"get_tip\"}");
    let r = assert_rpc2_result(&resp);
    assert!(r.get("tip_height").is_some(), "r={r}");
    assert!(
        dir.join("chain.redb").exists(),
        "expected chain.redb under data dir"
    );
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_p2p_hello_handshake_over_tcp() {
    let dir = unique_data_dir("serve_p2p_handshake");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, mut child_out, _child_err, rpc_addr, p2p_addr) =
        spawn_mfnd_serve_with_p2p(&dir, &spec);
    let resp = tcp_request_json(rpc_addr, r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#);
    let tip = assert_rpc2_result(&resp);
    let gid_hex = tip["genesis_id"].as_str().expect("genesis_id hex");
    let bytes = hex::decode(gid_hex).expect("decode genesis_id hex");
    assert_eq!(bytes.len(), 32);
    let mut genesis_id = [0u8; 32];
    genesis_id.copy_from_slice(&bytes);
    let tip_h = tip["tip_height"]
        .as_u64()
        .expect("tip_height must be a JSON number") as u32;
    let tip_id_hex = tip["tip_id"].as_str().expect("tip_id hex");
    let mut tip_id = [0u8; 32];
    hex::decode_to_slice(tip_id_hex, &mut tip_id).expect("decode tip_id hex");
    let local_tip = mfn_node::network::ChainTipV1 {
        height: tip_h,
        tip_id,
    };
    mfn_node::network::tcp_connect_peer_v1_handshake_with_tip_exchange(
        p2p_addr,
        &genesis_id,
        &local_tip,
    )
    .expect("p2p tcp_connect_peer_v1_handshake_with_tip_exchange");
    read_listener_p2p_handshake_session(&mut child_out, tip_h, tip_id_hex);
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_p2p_tx_gossip_after_handshake() {
    let (dir, spec, tx_hex, tx_id_hex) =
        synth_decoy_one_step_signed_transfer_fixture("serve_p2p_tx_gossip");
    let (mut child, mut child_out, _child_err, rpc_addr, p2p_addr) =
        spawn_mfnd_serve_with_p2p(&dir, &spec);
    let resp = tcp_request_json(rpc_addr, r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#);
    let tip = assert_rpc2_result(&resp);
    let gid_hex = tip["genesis_id"].as_str().expect("genesis_id hex");
    let bytes = hex::decode(gid_hex).expect("decode genesis_id hex");
    let mut genesis_id = [0u8; 32];
    genesis_id.copy_from_slice(&bytes);
    let tip_h = tip["tip_height"]
        .as_u64()
        .expect("tip_height must be a JSON number") as u32;
    let tip_id_hex = tip["tip_id"].as_str().expect("tip_id hex");
    let mut tip_id = [0u8; 32];
    hex::decode_to_slice(tip_id_hex, &mut tip_id).expect("decode tip_id hex");
    let local_tip = mfn_node::network::ChainTipV1 {
        height: tip_h,
        tip_id,
    };
    let (mut sock, _remote) = mfn_node::network::tcp_connect_peer_v1_handshake_with_tip_exchange(
        p2p_addr,
        &genesis_id,
        &local_tip,
    )
    .expect("p2p handshake with tip exchange");
    let tx_wire = hex::decode(tx_hex.trim()).expect("decode tx hex");
    mfn_node::network::send_tx_v1(&mut sock, &tx_wire).expect("send TxV1");
    mfn_node::network::send_gossip_end_v1(&mut sock).expect("send GossipEndV1");
    read_listener_p2p_handshake_session(&mut child_out, tip_h, tip_id_hex);
    let mut admit_line = String::new();
    child_out
        .read_line(&mut admit_line)
        .expect("read mfnd_p2p_tx_admit");
    assert!(
        admit_line.starts_with("mfnd_p2p_tx_admit "),
        "expected mfnd_p2p_tx_admit, got {admit_line:?}"
    );
    assert!(
        admit_line.contains("outcome=accepted"),
        "admit_line={admit_line:?}"
    );
    assert!(
        admit_line.contains(&format!("tx_id={tx_id_hex}")),
        "admit_line={admit_line:?}"
    );
    let mp = tcp_request_json(
        rpc_addr,
        r#"{"jsonrpc":"2.0","method":"get_mempool","id":2}"#,
    );
    let mp_r = assert_rpc2_result(&mp);
    let ids = mp_r["tx_ids"].as_array().expect("tx_ids array");
    assert!(
        ids.iter().any(|v| v.as_str() == Some(tx_id_hex.as_str())),
        "mempool missing gossiped tx_id={tx_id_hex} resp={mp_r}"
    );
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_p2p_blocks_reply_after_handshake() {
    let dir = unique_data_dir("serve_p2p_blocks_sync");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/devnet_one_validator_synth_decoys.json");
    let step_out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .arg("step")
        .output()
        .expect("spawn mfnd step");
    assert!(
        step_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&step_out.stderr)
    );

    let (mut child, mut child_out, _child_err, rpc_addr, p2p_addr) =
        spawn_mfnd_serve_with_p2p(&dir, &spec);
    let resp = tcp_request_json(rpc_addr, r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#);
    let tip = assert_rpc2_result(&resp);
    let gid_hex = tip["genesis_id"].as_str().expect("genesis_id hex");
    let bytes = hex::decode(gid_hex).expect("decode genesis_id hex");
    let mut genesis_id = [0u8; 32];
    genesis_id.copy_from_slice(&bytes);
    let tip_h = tip["tip_height"]
        .as_u64()
        .expect("tip_height must be a JSON number") as u32;
    assert_eq!(tip_h, 1, "expected one block after step");
    let tip_id_hex = tip["tip_id"].as_str().expect("tip_id hex");
    let mut tip_id = [0u8; 32];
    hex::decode_to_slice(tip_id_hex, &mut tip_id).expect("decode tip_id hex");
    let local_tip = mfn_node::network::ChainTipV1 {
        height: tip_h,
        tip_id,
    };
    let (mut sock, _remote) = mfn_node::network::tcp_connect_peer_v1_handshake_with_tip_exchange(
        p2p_addr,
        &genesis_id,
        &local_tip,
    )
    .expect("p2p handshake with tip exchange");
    let req = mfn_node::network::GetBlocksByHeightV1 {
        start_height: 1,
        count: 8,
    };
    mfn_node::network::send_get_blocks_by_height_v1(&mut sock, req)
        .expect("send GetBlocksByHeightV1");
    let blocks = mfn_node::network::recv_blocks_v1(&mut sock).expect("recv BlocksV1");
    assert_eq!(
        blocks.block_wires.len(),
        1,
        "expected one block in BlocksV1 reply"
    );
    let block = mfn_consensus::decode_block(&blocks.block_wires[0]).expect("decode block");
    assert_eq!(block.header.height, 1);

    read_listener_p2p_handshake_session(&mut child_out, tip_h, tip_id_hex);
    let mut reply_line = String::new();
    child_out
        .read_line(&mut reply_line)
        .expect("read mfnd_p2p_blocks_reply");
    assert!(
        reply_line.starts_with("mfnd_p2p_blocks_reply "),
        "expected mfnd_p2p_blocks_reply, got {reply_line:?}"
    );
    assert!(
        reply_line.contains("returned=1"),
        "reply_line={reply_line:?}"
    );
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

/// Full block-sync over `--p2p-dial` can hang on overloaded CI runners; run locally with:
/// `cargo test -p mfn-node mfnd_p2p_dial_syncs_blocks_from_ahead_peer --release -- --ignored`
#[test]
#[ignore = "slow P2P block-sync integration; run with cargo test -- --ignored"]
fn mfnd_p2p_dial_syncs_blocks_from_ahead_peer() {
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let dir_a = unique_data_dir("p2p_sync_a");
    let step_out = mfnd()
        .args(["--data-dir"])
        .arg(&dir_a)
        .arg("--genesis")
        .arg(&spec)
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .args(["step", "--blocks", "3"])
        .output()
        .expect("spawn mfnd step --blocks 3 on peer A");
    assert!(
        step_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&step_out.stderr)
    );

    let (mut child_a, _out_a, _err_a, rpc_a, p2p_a) = spawn_mfnd_serve_with_p2p(&dir_a, &spec);
    let tip_a = tcp_request_json(rpc_a, r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#);
    let tip_a_r = assert_rpc2_result(&tip_a);
    assert_eq!(
        tip_a_r["tip_height"].as_u64(),
        Some(3),
        "peer A tip_height resp={tip_a_r}"
    );

    let dir_b = unique_data_dir("p2p_sync_b");
    let mut child_b = mfnd()
        .args(["--data-dir"])
        .arg(&dir_b)
        .arg("--genesis")
        .arg(&spec)
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-dial")
        .arg(p2p_a.to_string())
        .arg("serve")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn dialer mfnd serve");
    let stdout = child_b.stdout.take().expect("stdout pipe");
    let mut out_b = BufReader::new(stdout);
    let rpc_b = read_mfnd_serve_listening_addr(&mut out_b, SERVE_LISTEN_TIMEOUT);
    let sync_end = read_stdout_until_p2p_sync_end(&mut out_b, P2P_SYNC_END_TIMEOUT);
    assert!(
        sync_end.contains("applied=3"),
        "expected three blocks applied, got {sync_end:?}"
    );
    assert!(sync_end.contains("final_height=3"), "sync_end={sync_end:?}");

    let tip_b = tcp_request_json(rpc_b, r#"{"jsonrpc":"2.0","method":"get_tip","id":2}"#);
    let tip_b_r = assert_rpc2_result(&tip_b);
    assert_eq!(
        tip_b_r["tip_height"].as_u64(),
        Some(3),
        "dialer tip after sync resp={tip_b_r}"
    );

    let _ = child_a.kill();
    let _ = child_b.kill();
    let _ = child_a.wait();
    let _ = child_b.wait();
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

#[test]
fn mfnd_p2p_reconnects_saved_peers_on_restart() {
    let dir_a = unique_data_dir("p2p_reconnect_a");
    let dir_b = unique_data_dir("p2p_reconnect_b");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child_a, mut out_a, _err_a, _rpc_a, p2p_a) = spawn_mfnd_serve_with_p2p(&dir_a, &spec);
    thread::spawn(move || {
        let mut line = String::new();
        while let Ok(n) = out_a.read_line(&mut line) {
            if n == 0 {
                break;
            }
            line.clear();
        }
    });

    let mut child_b = mfnd()
        .args(["--data-dir"])
        .arg(&dir_b)
        .arg("--genesis")
        .arg(&spec)
        .arg("--store")
        .arg("fs")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-dial")
        .arg(p2p_a.to_string())
        .arg("serve")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mfnd serve with dial");
    let stdout_b = child_b.stdout.take().expect("stdout b");
    let mut out_b = BufReader::new(stdout_b);
    let _rpc_b = read_mfnd_serve_listening_addr(&mut out_b, SERVE_LISTEN_TIMEOUT);
    read_stdout_line_with_prefix(&mut out_b, "mfnd_p2p_dial_ok=", P2P_LINE_TIMEOUT);
    thread::spawn(move || {
        let mut line = String::new();
        while let Ok(n) = out_b.read_line(&mut line) {
            if n == 0 {
                break;
            }
            line.clear();
        }
    });
    let peers_raw =
        std::fs::read_to_string(mfn_store::peers_path(&dir_b)).expect("read peers.json");
    assert!(
        peers_raw.contains(&p2p_a.to_string()),
        "peers.json should list peer A, got {peers_raw}"
    );

    let _ = child_b.kill();
    let _ = child_b.wait();
    std::thread::sleep(Duration::from_millis(300));

    let mut child_b2 = mfnd()
        .args(["--data-dir"])
        .arg(&dir_b)
        .arg("--genesis")
        .arg(&spec)
        .arg("--store")
        .arg("fs")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-listen")
        .arg("127.0.0.1:0")
        .arg("serve")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mfnd serve reconnect");
    let stdout_b2 = child_b2.stdout.take().expect("stdout b2");
    let mut out_b2 = BufReader::new(stdout_b2);
    read_stdout_line_with_prefix(&mut out_b2, "mfnd_peers_load_ok ", P2P_LINE_TIMEOUT);
    let _ = read_mfnd_serve_listening_addr(&mut out_b2, SERVE_LISTEN_TIMEOUT);
    read_stdout_line_with_prefix(&mut out_b2, "mfnd_p2p_listening=", P2P_LINE_TIMEOUT);
    read_stdout_line_with_prefix(&mut out_b2, "mfnd_p2p_reconnect_start ", P2P_LINE_TIMEOUT);
    read_stdout_line_with_prefix(&mut out_b2, "mfnd_p2p_dial_ok=", P2P_LINE_TIMEOUT);
    thread::spawn(move || {
        let mut line = String::new();
        while let Ok(n) = out_b2.read_line(&mut line) {
            if n == 0 {
                break;
            }
            line.clear();
        }
    });

    let _ = child_a.kill();
    let _ = child_b2.kill();
    let _ = child_a.wait();
    let _ = child_b2.wait();
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

/// Multi-hop gossip + mempool propagation; flaky/slow on CI. Run locally with `--ignored`.
#[test]
#[ignore = "slow P2P tx fanout integration; run with cargo test -- --ignored"]
fn mfnd_p2p_tx_fanout_reaches_third_hop_peer() {
    let (dir_a, spec, tx_hex, tx_id_hex) =
        synth_decoy_one_step_signed_transfer_fixture("p2p_tx_fanout_abc");
    let (mut child_a, _out_a, _err_a, rpc_a, p2p_a) = spawn_mfnd_serve_with_p2p(&dir_a, &spec);

    let dir_b = unique_data_dir("p2p_tx_fanout_b");
    let mut child_b = mfnd()
        .args(["--data-dir"])
        .arg(&dir_b)
        .arg("--genesis")
        .arg(&spec)
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-dial")
        .arg(p2p_a.to_string())
        .arg("serve")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn relay mfnd serve");
    let stdout_b = child_b.stdout.take().expect("stdout b");
    let mut out_b = BufReader::new(stdout_b);
    let rpc_b = read_mfnd_serve_listening_addr(&mut out_b, SERVE_LISTEN_TIMEOUT);
    let p2p_b_line =
        read_stdout_line_with_prefix(&mut out_b, "mfnd_p2p_listening=", P2P_LINE_TIMEOUT);
    let p2p_b: SocketAddr = p2p_b_line
        .strip_prefix("mfnd_p2p_listening=")
        .unwrap()
        .trim()
        .parse()
        .expect("parse p2p b");
    read_stdout_line_with_prefix(&mut out_b, "mfnd_p2p_dial_ok=", P2P_LINE_TIMEOUT);
    let sync_b = read_stdout_until_p2p_sync_end(&mut out_b, P2P_SYNC_END_TIMEOUT);
    assert!(
        sync_b.contains("applied=1"),
        "relay B should sync one block from A, got {sync_b:?}"
    );

    let dir_c = unique_data_dir("p2p_tx_fanout_c");
    let mut child_c = mfnd()
        .args(["--data-dir"])
        .arg(&dir_c)
        .arg("--genesis")
        .arg(&spec)
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-dial")
        .arg(p2p_b.to_string())
        .arg("serve")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn leaf mfnd serve");
    let stdout_c = child_c.stdout.take().expect("stdout c");
    let mut out_c = BufReader::new(stdout_c);
    let rpc_c = read_mfnd_serve_listening_addr(&mut out_c, SERVE_LISTEN_TIMEOUT);
    read_stdout_line_with_prefix(&mut out_c, "mfnd_p2p_listening=", P2P_LINE_TIMEOUT);
    read_stdout_line_with_prefix(&mut out_c, "mfnd_p2p_dial_ok=", P2P_LINE_TIMEOUT);
    let sync_c = read_stdout_until_p2p_sync_end(&mut out_c, P2P_SYNC_END_TIMEOUT);
    assert!(
        sync_c.contains("applied=1"),
        "leaf C should sync one block from B, got {sync_c:?}"
    );

    let submit = format!(
        r#"{{"jsonrpc":"2.0","method":"submit_tx","params":{{"tx_hex":"{tx_hex}"}},"id":1}}"#
    );
    let sub_r = assert_rpc2_result(&tcp_request_json(rpc_a, &submit));
    assert_eq!(
        sub_r["outcome"]["kind"].as_str(),
        Some("Fresh"),
        "submit on A resp={sub_r}"
    );

    wait_mempool_contains(rpc_b, &tx_id_hex, Duration::from_secs(15));
    wait_mempool_contains(rpc_c, &tx_id_hex, Duration::from_secs(15));

    let _ = child_a.kill();
    let _ = child_b.kill();
    let _ = child_c.kill();
    let _ = child_a.wait();
    let _ = child_b.wait();
    let _ = child_c.wait();
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
    std::fs::remove_dir_all(&dir_c).ok();
}

#[test]
fn mfnd_serve_p2p_listener_two_handshakes_increment_hid() {
    let dir = unique_data_dir("serve_p2p_two_hid");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, mut child_out, _child_err, rpc_addr, p2p_addr) =
        spawn_mfnd_serve_with_p2p(&dir, &spec);
    let resp = tcp_request_json(rpc_addr, r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#);
    let tip = assert_rpc2_result(&resp);
    let gid_hex = tip["genesis_id"].as_str().expect("genesis_id hex");
    let bytes = hex::decode(gid_hex).expect("decode genesis_id hex");
    assert_eq!(bytes.len(), 32);
    let mut genesis_id = [0u8; 32];
    genesis_id.copy_from_slice(&bytes);
    let tip_h = tip["tip_height"]
        .as_u64()
        .expect("tip_height must be a JSON number") as u32;
    let tip_id_hex = tip["tip_id"].as_str().expect("tip_id hex");
    let mut tip_id = [0u8; 32];
    hex::decode_to_slice(tip_id_hex, &mut tip_id).expect("decode tip_id hex");
    let local_tip = mfn_node::network::ChainTipV1 {
        height: tip_h,
        tip_id,
    };
    for _ in 0..2 {
        mfn_node::network::tcp_connect_peer_v1_handshake_with_tip_exchange(
            p2p_addr,
            &genesis_id,
            &local_tip,
        )
        .expect("p2p tcp_connect_peer_v1_handshake_with_tip_exchange");
    }
    let hid0 = read_listener_p2p_handshake_session(&mut child_out, tip_h, tip_id_hex);
    let hid1 = read_listener_p2p_handshake_session(&mut child_out, tip_h, tip_id_hex);
    assert_eq!(
        hid1,
        hid0 + 1,
        "expected monotonic hid across sequential accepts"
    );
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_p2p_listener_failed_hello_emits_abort_and_advances_hid() {
    let dir = unique_data_dir("serve_p2p_abort_hid");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, mut child_out, mut child_err, rpc_addr, p2p_addr) =
        spawn_mfnd_serve_with_p2p(&dir, &spec);
    let resp = tcp_request_json(rpc_addr, r#"{"jsonrpc":"2.0","method":"get_tip","id":1}"#);
    let tip = assert_rpc2_result(&resp);
    let gid_hex = tip["genesis_id"].as_str().expect("genesis_id hex");
    let bytes = hex::decode(gid_hex).expect("decode genesis_id hex");
    assert_eq!(bytes.len(), 32);
    let mut genesis_id = [0u8; 32];
    genesis_id.copy_from_slice(&bytes);
    let tip_h = tip["tip_height"]
        .as_u64()
        .expect("tip_height must be a JSON number") as u32;
    let tip_id_hex = tip["tip_id"].as_str().expect("tip_id hex");
    let mut tip_id = [0u8; 32];
    hex::decode_to_slice(tip_id_hex, &mut tip_id).expect("decode tip_id hex");
    let local_tip = mfn_node::network::ChainTipV1 {
        height: tip_h,
        tip_id,
    };

    let mut wrong_genesis = genesis_id;
    wrong_genesis[0] ^= 0xff;
    let mut bad = TcpStream::connect(p2p_addr).expect("tcp connect for bad hello");
    let _ = bad.set_read_timeout(Some(mfn_node::network::P2P_HANDSHAKE_IO_TIMEOUT));
    let _ = bad.set_write_timeout(Some(mfn_node::network::P2P_HANDSHAKE_IO_TIMEOUT));
    assert!(
        mfn_node::network::hello_v1_handshake(&mut bad, &wrong_genesis).is_err(),
        "expected client hello with wrong genesis to fail"
    );

    let mut abort_line = String::new();
    child_err
        .read_line(&mut abort_line)
        .expect("read mfnd_p2p_handshake_abort from stderr");
    assert!(
        abort_line.starts_with("mfnd_p2p_handshake_abort "),
        "expected mfnd_p2p_handshake_abort, got {abort_line:?}"
    );
    assert!(
        abort_line.contains("hid=0 "),
        "expected first session hid=0, line={abort_line:?}"
    );
    assert!(
        abort_line.contains("stage=hello"),
        "expected stage=hello, line={abort_line:?}"
    );

    mfn_node::network::tcp_connect_peer_v1_handshake_with_tip_exchange(
        p2p_addr,
        &genesis_id,
        &local_tip,
    )
    .expect("p2p tcp_connect_peer_v1_handshake_with_tip_exchange");
    let hid_ok = read_listener_p2p_handshake_session(&mut child_out, tip_h, tip_id_hex);
    assert_eq!(
        hid_ok, 1,
        "after failed accept hid=0, next success should print hid=1"
    );

    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_p2p_dial_hits_peer_listener() {
    let dir_a = unique_data_dir("serve_p2p_dial_a");
    let dir_b = unique_data_dir("serve_p2p_dial_b");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child_a, mut out_a, _err_a, _rpc_a, p2p_a) = spawn_mfnd_serve_with_p2p(&dir_a, &spec);
    thread::spawn(move || {
        let mut line = String::new();
        while let Ok(n) = out_a.read_line(&mut line) {
            if n == 0 {
                break;
            }
            line.clear();
        }
    });
    let mut child_b = mfnd()
        .args(["--data-dir"])
        .arg(&dir_b)
        .arg("--genesis")
        .arg(&spec)
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--p2p-dial")
        .arg(p2p_a.to_string())
        .arg("serve")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn dialer mfnd serve");
    let stdout = child_b.stdout.take().expect("stdout pipe");
    let mut out_reader = BufReader::new(stdout);
    let _rpc_b = read_mfnd_serve_listening_addr(&mut out_reader, SERVE_LISTEN_TIMEOUT);
    read_stdout_line_with_prefix(&mut out_reader, "mfnd_p2p_dial_ok=", P2P_LINE_TIMEOUT);
    let mut l3 = String::new();
    out_reader
        .read_line(&mut l3)
        .expect("read mfnd_p2p_peer_tip from dialer");
    assert!(
        l3.starts_with("mfnd_p2p_peer_tip "),
        "expected mfnd_p2p_peer_tip, got {l3:?}"
    );
    assert!(
        l3.contains("height=") && l3.contains("tip_id="),
        "l3={l3:?}"
    );
    let hid = mfnd_p2p_hid_from_line(&l3);
    let mut l4 = String::new();
    out_reader
        .read_line(&mut l4)
        .expect("read mfnd_p2p_height_cmp from dialer");
    assert!(
        l4.starts_with("mfnd_p2p_height_cmp "),
        "expected mfnd_p2p_height_cmp, got {l4:?}"
    );
    assert!(l4.contains("cmp=equal"), "l4={l4:?}");
    assert_eq!(mfnd_p2p_hid_from_line(&l4), hid, "l4={l4:?}");
    let mut l5 = String::new();
    out_reader
        .read_line(&mut l5)
        .expect("read mfnd_p2p_handshake_ms from dialer");
    assert_mfnd_p2p_handshake_ms_line(&l5);
    assert_eq!(mfnd_p2p_hid_from_line(&l5), hid, "l5={l5:?}");
    let _ = child_b.kill();
    let _ = child_b.wait();
    let _ = child_a.kill();
    let _ = child_a.wait();
    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

#[test]
fn mfnd_serve_get_tip_jsonrpc_echoes_id() {
    let dir = unique_data_dir("serve_jsonrpc_id");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let resp = tcp_request_json(sock, r#"{"jsonrpc":"2.0","method":"get_tip","id":"req-1"}"#);
    let v = rpc_line(&resp);
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], json!("req-1"));
    assert!(v.get("result").is_some());
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_mempool_survives_restart() {
    let (dir, spec, tx_hex, tx_id_hex) = synth_decoy_one_step_signed_transfer_fixture_with_store(
        "serve_mempool_restart",
        Some("fs"),
    );
    let (mut child1, rpc1) = spawn_mfnd_serve_with_store(&dir, &spec, Some("fs"));
    let submit = format!(
        r#"{{"jsonrpc":"2.0","method":"submit_tx","params":{{"tx_hex":"{tx_hex}"}},"id":1}}"#
    );
    let sub_r = assert_rpc2_result(&tcp_request_json(rpc1, &submit));
    assert_eq!(
        sub_r["outcome"]["kind"].as_str(),
        Some("Fresh"),
        "submit resp={sub_r}"
    );
    let tip1 = assert_rpc2_result(&tcp_request_json(
        rpc1,
        r#"{"jsonrpc":"2.0","method":"get_tip","id":2}"#,
    ));
    let root1 = tip1["mempool_root"]
        .as_str()
        .expect("mempool_root hex after submit");
    assert!(
        mfn_store::mempool_path(&dir).exists(),
        "expected mempool.bytes after submit"
    );
    let _ = child1.kill();
    let _ = child1.wait();
    std::thread::sleep(Duration::from_millis(500));

    let snap = std::fs::read(mfn_store::mempool_path(&dir)).expect("read mempool.bytes");
    let entries = mfn_runtime::decode_mempool_snapshot(&snap).expect("decode mempool.bytes");
    assert_eq!(entries.len(), 1, "snapshot should contain one tx");

    let (mut child2, rpc2) = spawn_mfnd_serve_with_store(&dir, &spec, Some("fs"));
    std::thread::sleep(Duration::from_millis(200));
    let mp = assert_rpc2_result(&tcp_request_json(
        rpc2,
        r#"{"jsonrpc":"2.0","method":"get_mempool","id":3}"#,
    ));
    assert_eq!(mp["mempool_len"], json!(1), "mp={mp}");
    let ids = mp["tx_ids"].as_array().expect("tx_ids");
    assert!(
        ids.iter().any(|v| v.as_str() == Some(tx_id_hex.as_str())),
        "restarted mempool missing tx_id={tx_id_hex} mp={mp}"
    );
    let tip2 = assert_rpc2_result(&tcp_request_json(
        rpc2,
        r#"{"jsonrpc":"2.0","method":"get_tip","id":4}"#,
    ));
    assert_eq!(
        tip2["mempool_root"].as_str(),
        Some(root1),
        "mempool_root changed across restart"
    );
    let _ = child2.kill();
    let _ = child2.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_get_mempool_over_tcp_empty() {
    let dir = unique_data_dir("serve_get_mempool");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let resp = tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"get_mempool","params":null,"id":9}"#,
    );
    let r = assert_rpc2_result(&resp);
    assert_eq!(r["mempool_len"], json!(0));
    assert_eq!(r["tx_ids"], json!([]));
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_submit_tx_rejects_bad_hex() {
    let dir = unique_data_dir("serve_bad_hex");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let req = r#"{"method":"submit_tx","params":{"tx_hex":"gg"}}"#;
    let resp = tcp_request_json(sock, req);
    let (code, msg) = assert_rpc2_error(&resp);
    assert_eq!(code, -32602, "msg={msg}");
    assert!(
        msg.to_lowercase().contains("hex"),
        "expected hex decode error, msg={msg}"
    );
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_submit_tx_array_params_rejects_bad_hex() {
    let dir = unique_data_dir("serve_bad_hex_arr");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let req = r#"{"method":"submit_tx","params":["gg"]}"#;
    let resp = tcp_request_json(sock, req);
    let (code, msg) = assert_rpc2_error(&resp);
    assert_eq!(code, -32602, "msg={msg}");
    assert!(
        msg.to_lowercase().contains("hex"),
        "expected hex decode error, msg={msg}"
    );
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_submit_tx_rejects_truncated_wire() {
    let dir = unique_data_dir("serve_trunc");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let req = r#"{"method":"submit_tx","params":{"tx_hex":"00"}}"#;
    let resp = tcp_request_json(sock, req);
    let (code, msg) = assert_rpc2_error(&resp);
    assert_eq!(code, -32602, "msg={msg}");
    assert!(
        msg.contains("decode_transaction") || msg.contains("decode"),
        "msg={msg}"
    );
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_submit_tx_rejects_coinbase_shaped_wire() {
    let dir = unique_data_dir("serve_no_inputs");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let bogus = TransactionWire {
        version: TX_VERSION,
        r_pub: generator_g(),
        inputs: Vec::new(),
        outputs: Vec::new(),
        fee: 0,
        extra: Vec::new(),
    };
    let tx_hex = hex::encode(encode_transaction(&bogus));
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let req = format!("{{\"method\":\"submit_tx\",\"params\":{{\"tx_hex\":\"{tx_hex}\"}}}}");
    let resp = tcp_request_json(sock, &req);
    let (code, msg) = assert_rpc2_error(&resp);
    assert_eq!(code, -32001, "msg={msg}");
    assert!(
        msg.contains("mempool admit") && (msg.contains("no inputs") || msg.contains("NoInputs")),
        "msg={msg}"
    );
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_submit_tx_rejects_missing_tx_hex() {
    let dir = unique_data_dir("serve_missing_hex");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let resp = tcp_request_json(sock, r#"{"method":"submit_tx","params":{}}"#);
    let (code, msg) = assert_rpc2_error(&resp);
    assert_eq!(code, -32602, "msg={msg}");
    assert!(msg.contains("tx_hex"), "msg={msg}");
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_step_writes_block_log_then_serve_submit_tx_admits_transfer() {
    let (dir, spec, tx_hex, _) = synth_decoy_one_step_signed_transfer_fixture("serve_submit_ok");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let req = format!("{{\"method\":\"submit_tx\",\"params\":{{\"tx_hex\":\"{tx_hex}\"}}}}");
    let resp = tcp_request_json(sock, &req);
    let r = assert_rpc2_result(&resp);
    assert_eq!(r["outcome"]["kind"], "Fresh", "r={r}");

    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_get_mempool_lists_tx_after_submit() {
    let (dir, spec, tx_hex, tx_id_hex) =
        synth_decoy_one_step_signed_transfer_fixture("serve_mempool_nonempty");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let req = format!(
        r#"{{"jsonrpc":"2.0","method":"submit_tx","params":{{"tx_hex":"{tx_hex}"}},"id":1}}"#
    );
    let resp = tcp_request_json(sock, &req);
    let r = assert_rpc2_result(&resp);
    assert_eq!(r["outcome"]["kind"], "Fresh", "r={r}");

    let resp_m = tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"get_mempool","params":null,"id":2}"#,
    );
    let m = assert_rpc2_result(&resp_m);
    assert_eq!(m["mempool_len"], json!(1), "m={m}");
    let ids = m["tx_ids"].as_array().expect("tx_ids");
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0], json!(tx_id_hex));

    let tid = r["tx_id"].as_str().expect("submit tx_id");
    assert_eq!(tid, tx_id_hex.as_str());
    let req_tx = format!(
        r#"{{"jsonrpc":"2.0","method":"get_mempool_tx","params":{{"tx_id":"{tid}"}},"id":3}}"#
    );
    let resp_tx = tcp_request_json(sock, &req_tx);
    let g = assert_rpc2_result(&resp_tx);
    assert_eq!(g["tx_id"], json!(tx_id_hex));
    assert_eq!(g["tx_hex"].as_str().expect("tx_hex"), tx_hex.as_str());

    let req_rm = format!(
        r#"{{"jsonrpc":"2.0","method":"remove_mempool_tx","params":{{"tx_id":"{tid}"}},"id":4}}"#
    );
    let resp_rm = tcp_request_json(sock, &req_rm);
    let rm = assert_rpc2_result(&resp_rm);
    assert_eq!(rm["removed"], json!(true));
    assert_eq!(rm["pool_len"], json!(0));

    let resp_empty = tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"get_mempool","params":null,"id":5}"#,
    );
    let me = assert_rpc2_result(&resp_empty);
    assert_eq!(me["mempool_len"], json!(0));
    assert_eq!(me["tx_ids"], json!([]));

    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_clear_mempool_after_submit() {
    let (dir, spec, tx_hex, tx_id_hex) =
        synth_decoy_one_step_signed_transfer_fixture("serve_clear_mempool");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let req = format!(
        r#"{{"jsonrpc":"2.0","method":"submit_tx","params":{{"tx_hex":"{tx_hex}"}},"id":1}}"#
    );
    let resp = tcp_request_json(sock, &req);
    let r = assert_rpc2_result(&resp);
    assert_eq!(r["outcome"]["kind"], "Fresh", "r={r}");

    let resp_m = tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"get_mempool","params":null,"id":2}"#,
    );
    let m = assert_rpc2_result(&resp_m);
    assert_eq!(m["mempool_len"], json!(1), "m={m}");
    assert_eq!(m["tx_ids"], json!([tx_id_hex]));

    let resp_clr = tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"clear_mempool","params":null,"id":3}"#,
    );
    let clr = assert_rpc2_result(&resp_clr);
    assert_eq!(clr["cleared_count"], json!(1));
    assert_eq!(clr["pool_len"], json!(0));

    let resp_empty = tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"get_mempool","params":null,"id":4}"#,
    );
    let me = assert_rpc2_result(&resp_empty);
    assert_eq!(me["mempool_len"], json!(0));
    assert_eq!(me["tx_ids"], json!([]));

    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_get_checkpoint_round_trips_over_tcp_after_step() {
    let dir = unique_data_dir("serve_gcp_step");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let step_out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .arg("step")
        .output()
        .expect("spawn mfnd step");
    assert!(
        step_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&step_out.stderr)
    );

    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let resp = tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"get_checkpoint","params":null,"id":1}"#,
    );
    let r = assert_rpc2_result(&resp);
    let hx = r["checkpoint_hex"].as_str().expect("checkpoint_hex");
    let bytes = hex::decode(hx).expect("checkpoint hex");
    assert_eq!(r["byte_len"], json!(bytes.len()));
    let gc = genesis_config_from_json_path(&spec).expect("genesis");
    let restored = Chain::from_checkpoint_bytes(ChainConfig::new(gc), &bytes).expect("restore");
    assert_eq!(restored.tip_height(), Some(1));

    let resp_tip = tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"get_tip","params":null,"id":2}"#,
    );
    let tip = assert_rpc2_result(&resp_tip);
    assert_eq!(tip["tip_height"], json!(1));

    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_save_checkpoint_creates_checkpoint_file() {
    let dir = unique_data_dir("serve_save_checkpoint");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    assert!(
        !dir.join("chain.redb").exists() && !dir.join("chain.checkpoint").exists(),
        "fresh data dir"
    );
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let resp = tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"save_checkpoint","params":null,"id":1}"#,
    );
    let r = assert_rpc2_result(&resp);
    assert!(r["bytes_written"].as_u64().unwrap() > 0);
    let cp = r["checkpoint_path"].as_str().expect("checkpoint_path");
    assert!(
        cp.contains("chain.checkpoint") || cp.contains("chain.redb"),
        "checkpoint_path={cp}"
    );
    let _ = child.kill();
    let _ = child.wait();
    let store2 = open_mfnd_store(&dir);
    assert!(store2.has_any_checkpoint());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_list_methods_over_tcp() {
    let dir = unique_data_dir("serve_list_methods");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let resp = tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"list_methods","params":null,"id":1}"#,
    );
    let r = assert_rpc2_result(&resp);
    let arr = r["methods"].as_array().expect("methods");
    let names: Vec<&str> = arr
        .iter()
        .map(|x| x.as_str().expect("method str"))
        .collect();
    assert!(names.contains(&"get_tip"));
    assert!(names.contains(&"list_methods"));
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_authorship_discovery_rpcs_over_tcp() {
    let dir = unique_data_dir("serve_authorship_rpc");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let z = "0000000000000000000000000000000000000000000000000000000000000000";
    let req_cf = format!(
        r#"{{"jsonrpc":"2.0","method":"get_claims_for","params":{{"data_root":"{z}"}},"id":1}}"#
    );
    let r1 = assert_rpc2_result(&tcp_request_json(sock, &req_cf));
    assert_eq!(r1["data_root"], json!(z));
    assert_eq!(r1["claims"], json!([]));

    let pk = "0101010101010101010101010101010101010101010101010101010101010101";
    let req_cb = format!(
        r#"{{"jsonrpc":"2.0","method":"get_claims_by_pubkey","params":{{"claim_pubkey":"{pk}","limit":2}},"id":2}}"#
    );
    let r2 = assert_rpc2_result(&tcp_request_json(sock, &req_cb));
    assert_eq!(r2["claim_pubkey"], json!(pk));
    assert_eq!(r2["limit"], json!(2));
    assert_eq!(r2["claims"], json!([]));

    let r3 = assert_rpc2_result(&tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"list_recent_uploads","params":{"limit":3,"offset":0},"id":3}"#,
    ));
    assert_eq!(r3["uploads"], json!([]));
    assert_eq!(r3["total"], json!(0));
    assert_eq!(r3["limit"], json!(3));

    let r4 = assert_rpc2_result(&tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"list_recent_claims","params":{"limit":2,"offset":0},"id":4}"#,
    ));
    assert_eq!(r4["claims"], json!([]));
    assert_eq!(r4["total"], json!(0));
    assert_eq!(r4["limit"], json!(2));

    let r5 = assert_rpc2_result(&tcp_request_json(
        sock,
        r#"{"jsonrpc":"2.0","method":"list_data_roots_with_claims","params":{},"id":5}"#,
    ));
    assert_eq!(r5["roots"], json!([]));
    assert_eq!(r5["total"], json!(0));

    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_step_block_log_passes_validated_read() {
    let dir = unique_data_dir("step_block_log_validated");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let step_out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .arg("step")
        .output()
        .expect("spawn mfnd step");
    assert!(
        step_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&step_out.stderr)
    );

    let store = open_mfnd_store(&dir);
    let gc = genesis_config_from_json_path(&spec).expect("genesis");
    let chain = store
        .load_or_genesis(ChainConfig::new(gc))
        .expect("load chain");
    assert_eq!(chain.tip_height(), Some(1));
    let blocks = store
        .read_block_log_validated(&chain)
        .expect("read_block_log_validated");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].header.height, 1);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_serve_get_block_over_tcp_after_step() {
    let dir = unique_data_dir("serve_get_block");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/devnet_one_validator.json");
    let step_out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .arg("step")
        .output()
        .expect("spawn mfnd step");
    assert!(
        step_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&step_out.stderr)
    );

    let (mut child, sock) = spawn_mfnd_serve(&dir, &spec);
    let req = r#"{"jsonrpc":"2.0","method":"get_block","params":{"height":1},"id":77}"#;
    let resp = tcp_request_json(sock, req);
    let r = assert_rpc2_result(&resp);
    assert_eq!(r["height"], json!(1));
    let hex_s = r["block_hex"].as_str().expect("block_hex");
    let bytes = hex::decode(hex_s).expect("hex decode");
    let blk = decode_block(&bytes).expect("decode_block");
    assert_eq!(blk.header.height, 1);

    let hdr_exp = block_header_bytes(&blk.header);
    let req_h = r#"{"jsonrpc":"2.0","method":"get_block_header","params":{"height":1},"id":78}"#;
    let resp_h = tcp_request_json(sock, req_h);
    let rh = assert_rpc2_result(&resp_h);
    assert_eq!(rh["height"], json!(1));
    let hhex = rh["header_hex"].as_str().expect("header_hex");
    let hb = hex::decode(hhex).expect("header hex");
    assert_eq!(hb, hdr_exp);
    let hdr = decode_block_header(&hb).expect("decode_block_header");
    let bid_hex = rh["block_id"].as_str().expect("block_id");
    assert_eq!(bid_hex, hex::encode(block_id(&hdr)));

    let _ = child.kill();
    let _ = child.wait();

    let store = open_mfnd_store(&dir);
    let gc = genesis_config_from_json_path(&spec).expect("genesis");
    let chain = store
        .load_or_genesis(ChainConfig::new(gc))
        .expect("load chain");
    let blocks = store
        .read_block_log_validated(&chain)
        .expect("read_block_log_validated");
    assert_eq!(bytes, encode_block(&blocks[0]));
    assert_eq!(blocks[0].header.height, 1);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfnd_step_rejects_empty_validator_genesis() {
    let dir = unique_data_dir("step_empty_vals");
    let out = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .env("MFND_SOLO_VRF_SEED_HEX", DEVNET_SOLO_VRF_SEED_HEX)
        .env("MFND_SOLO_BLS_SEED_HEX", DEVNET_SOLO_BLS_SEED_HEX)
        .arg("step")
        .output()
        .expect("spawn mfnd step");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("exactly one validator") || stderr.contains("got 0"),
        "stderr={stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
