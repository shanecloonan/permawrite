//! Integration smoke tests for the `mfnd` binary (M2.1.1 + M2.1.2 + M2.1.3 + M2.1.4 + M2.1.5 + M2.1.6 + M2.1.6.1 + M2.1.7 + M2.1.8).

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use mfn_consensus::{build_genesis, encode_transaction, TransactionWire, TX_VERSION};
use mfn_crypto::point::generator_g;
use mfn_crypto::seeded_rng;
use mfn_crypto::stealth_wallet_from_seed;
use mfn_node::{genesis_config_from_json_path, ChainConfig, ChainStore};
use mfn_wallet::{TransferRecipient, Wallet, WalletKeys};
use serde_json::{json, Value};

/// Seeds aligned with `testdata/devnet_one_validator.json` validator index 0.
const DEVNET_SOLO_VRF_SEED_HEX: &str =
    "0101010101010101010101010101010101010101010101010101010101010101";
const DEVNET_SOLO_BLS_SEED_HEX: &str =
    "6565656565656565656565656565656565656565656565656565656565656565";

fn mfnd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mfnd"))
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

/// Spawns `mfnd serve` with `--rpc-listen 127.0.0.1:0`; caller must `kill` the child.
fn spawn_mfnd_serve(data_dir: &Path, genesis_spec: &Path) -> (Child, SocketAddr) {
    let mut child = mfnd()
        .args(["--data-dir"])
        .arg(data_dir)
        .arg("--genesis")
        .arg(genesis_spec)
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("serve")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mfnd serve");
    let stdout = child.stdout.take().expect("stdout pipe");
    let mut out_reader = BufReader::new(stdout);
    let mut listen_line = String::new();
    out_reader
        .read_line(&mut listen_line)
        .expect("read mfnd_serve_listening");
    let addr_s = listen_line
        .strip_prefix("mfnd_serve_listening=")
        .expect("listening prefix")
        .trim();
    let sock: SocketAddr = addr_s.parse().expect("parse socket addr");
    (child, sock)
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
    let dir = unique_data_dir("serve_submit_ok");
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

    let store = ChainStore::new(&dir);
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

    let tx_hex = hex::encode(encode_transaction(&signed.tx));
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
