//! Integration smoke: `serve-chunks` serves bytes matching wallet upload artifacts (**M6.3**).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mfn_storage::{
    build_storage_commitment, chunk_data, storage_commitment_hash, DEFAULT_ENDOWMENT_PARAMS,
};
use mfn_storage_operator::save_upload_artifact;

fn storage_operator_bin() -> std::path::PathBuf {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("target");
    path.push(profile);
    path.push(format!(
        "mfn-storage-operator{}",
        std::env::consts::EXE_SUFFIX
    ));
    if path.is_file() {
        return path;
    }
    if let Some(p) = std::env::var_os("CARGO_BIN_EXE_mfn-storage-operator") {
        let p = std::path::PathBuf::from(p);
        if p.is_file() {
            return p;
        }
    }
    panic!(
        "mfn-storage-operator binary not found at {}; run `cargo build -p mfn-storage-operator --release`",
        path.display()
    );
}

fn ephemeral_listen_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("local_addr").port();
    format!("127.0.0.1:{port}")
}

fn http_get(addr: &str, path: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap_or_else(|e| panic!("connect {addr}: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).expect("write request");
    stream.flush().expect("flush");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> (u16, Vec<u8>) {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP header terminator");
    let header = std::str::from_utf8(&raw[..header_end]).expect("header utf8");
    let status_line = header.lines().next().expect("status line");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("status u16");
    let body = raw[header_end + 4..].to_vec();
    (code, body)
}

#[test]
fn serve_chunks_returns_upload_artifact_chunk_zero() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "mfn-chunk-http-smoke-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("dir");
    let wallet_path = dir.join("operator.json");
    std::fs::write(
        &wallet_path,
        br#"{"seed_hex":"0101010101010101010101010101010101010101010101010101010101010101"}"#,
    )
    .expect("wallet");

    let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
    let built = build_storage_commitment(
        &payload,
        1_000,
        Some(4096),
        DEFAULT_ENDOWMENT_PARAMS.min_replication,
        None,
    )
    .expect("commitment");
    let commit_hex = hex::encode(storage_commitment_hash(&built.commit));
    save_upload_artifact(
        &wallet_path,
        &built,
        &payload,
        Path::new("payload.bin"),
        None,
    )
    .expect("save artifact");

    let listen = ephemeral_listen_addr();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);
    let wallet_bg = wallet_path.clone();
    let listen_bg = listen.clone();
    let server = std::thread::spawn(move || {
        let mut child = Command::new(storage_operator_bin())
            .args([
                "serve-chunks",
                "--wallet",
                wallet_bg.to_str().expect("utf8"),
                "--listen",
                &listen_bg,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn serve-chunks");
        while !stop_bg.load(Ordering::SeqCst) {
            if child.try_wait().expect("try_wait").is_some() {
                panic!("serve-chunks exited early");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        let _ = child.wait();
    });

    std::thread::sleep(Duration::from_millis(200));

    let path = format!("/chunk/{commit_hex}/0");
    let (code, body) = http_get(&listen, &path);
    assert_eq!(code, 200, "GET chunk 0 should succeed");
    let chunks = chunk_data(&payload, built.commit.chunk_size as usize).expect("chunks");
    assert_eq!(body.as_slice(), chunks[0]);

    let missing_commit = "ab".repeat(32);
    let (code_404, _) = http_get(&listen, &format!("/chunk/{missing_commit}/0"));
    assert_eq!(code_404, 404, "unknown commit should 404");

    stop.store(true, Ordering::SeqCst);
    server.join().expect("server thread");
    let _ = std::fs::remove_dir_all(&dir);
}
