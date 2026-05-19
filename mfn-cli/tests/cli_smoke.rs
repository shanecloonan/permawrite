//! Integration smoke: `mfn-cli` against a live `mfnd serve` (**M3.0**).

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mfn_cli::RpcClient;
use serde_json::Value;

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
        return PathBuf::from(p);
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
    std::env::temp_dir().join(format!("permawrite-cli-{test}-{}-{nanos}", std::process::id()))
}

fn read_serve_listening(child: &mut Child) -> SocketAddr {
    let stdout = child.stdout.as_mut().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if std::time::Instant::now() >= deadline {
            panic!("timeout waiting for mfnd_serve_listening=");
        }
        line.clear();
        let n = reader.read_line(&mut line).expect("read stdout");
        if n == 0 {
            panic!("mfnd exited before listen line");
        }
        if let Some(rest) = line.strip_prefix("mfnd_serve_listening=") {
            return rest.trim().parse().expect("rpc addr");
        }
    }
}

fn shutdown_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn rpc_client_get_tip_over_live_serve() {
    let dir = unique_data_dir("rpc_tip");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator.json");

    let mut child = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("--store")
        .arg("fs")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("serve")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mfnd");
    let rpc = read_serve_listening(&mut child);

    let mut client = RpcClient::new(rpc.to_string());
    let tip = client.get_tip().expect("get_tip");
    assert_eq!(tip.tip_height, Some(0));
    assert_eq!(tip.tip_id.len(), 64);
    assert_eq!(tip.genesis_id.len(), 64);

    let methods = client.list_methods().expect("list_methods");
    assert!(methods.contains(&"get_tip".to_string()));
    assert!(methods.contains(&"submit_tx".to_string()));

    shutdown_child(&mut child);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfn_cli_tip_command_against_live_serve() {
    let dir = unique_data_dir("cli_tip");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator.json");

    let mut child = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("--store")
        .arg("fs")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("serve")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mfnd");
    let rpc = read_serve_listening(&mut child);

    let out = mfn_cli()
        .args(["--rpc", &rpc.to_string(), "tip"])
        .output()
        .expect("mfn-cli tip");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tip_height="));
    assert!(stdout.contains("genesis_id="));

    shutdown_child(&mut child);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mfn_cli_call_get_tip_json() {
    let dir = unique_data_dir("cli_call");
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let spec = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mfn-node/testdata/devnet_one_validator.json");

    let mut child = mfnd()
        .args(["--data-dir"])
        .arg(&dir)
        .arg("--genesis")
        .arg(&spec)
        .arg("--store")
        .arg("fs")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("serve")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mfnd");
    let rpc = read_serve_listening(&mut child);

    let out = mfn_cli()
        .args(["--rpc", &rpc.to_string(), "call", "get_tip"])
        .output()
        .expect("mfn-cli call");
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).expect("stdout json");
    assert!(v.get("tip_id").is_some());

    shutdown_child(&mut child);
    std::fs::remove_dir_all(&dir).ok();
}
