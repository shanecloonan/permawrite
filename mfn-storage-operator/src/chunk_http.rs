//! Minimal HTTP chunk server for wallet upload artifacts (**M6.2**).
//!
//! Serves raw chunk bytes from persisted `payload.bin` so peers can replicate
//! anchored data without the original upload path. One request per connection;
//! `GET /chunk/{commitment_hash_hex}/{chunk_index}` only.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mfn_storage::chunk_data;

use crate::upload_artifact_store::load_upload_artifact;

/// Chunk HTTP server configuration.
#[derive(Debug, Clone)]
pub struct ChunkServeConfig {
    /// Wallet whose `.upload-artifacts/` tree is served.
    pub wallet_path: std::path::PathBuf,
    /// `host:port` listen address (e.g. `127.0.0.1:18780`).
    pub listen_addr: String,
}

/// Chunk HTTP errors.
#[derive(Debug, thiserror::Error)]
pub enum ChunkServeError {
    /// Bind or I/O failure.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// Request / artifact handling.
    #[error("{0}")]
    Usage(String),
}

/// Run the HTTP listener until `stop` is set.
pub fn serve_chunks(cfg: ChunkServeConfig, stop: Arc<AtomicBool>) -> Result<(), ChunkServeError> {
    let listener = TcpListener::bind(&cfg.listen_addr)?;
    listener.set_nonblocking(true)?;
    println!(
        "mfno_chunk_listen addr={} wallet={}",
        cfg.listen_addr,
        cfg.wallet_path.display()
    );

    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if let Err(e) = handle_connection(&cfg.wallet_path, stream) {
                    eprintln!("mfno_chunk_error peer={peer} {e}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.into()),
        }
    }
    println!("mfno_chunk_stopping");
    Ok(())
}

fn handle_connection(wallet_path: &Path, mut stream: TcpStream) -> Result<(), ChunkServeError> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let req = std::str::from_utf8(&buf[..n]).map_err(|e| ChunkServeError::Usage(e.to_string()))?;
    let (method, path) = parse_request_line(req).ok_or_else(|| {
        ChunkServeError::Usage("expected GET /chunk/<commit_hex>/<index> HTTP/1.1".into())
    })?;
    if method != "GET" {
        return write_http_error(&mut stream, 405, "Method Not Allowed");
    }
    let Some((commit_hex, chunk_index)) = parse_chunk_path(path) else {
        return write_http_error(&mut stream, 404, "Not Found");
    };
    match chunk_bytes_for_artifact(wallet_path, &commit_hex, chunk_index) {
        Ok(bytes) => write_http_ok(&mut stream, &bytes),
        Err(_) => write_http_error(&mut stream, 404, "Not Found"),
    }
}

fn parse_request_line(req: &str) -> Option<(&str, &str)> {
    let line = req.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

/// Path shape: `/chunk/{64-hex-commit}/{chunk_index}`.
pub fn parse_chunk_path(path: &str) -> Option<(String, u32)> {
    let path = path.trim();
    let rest = path.strip_prefix("/chunk/")?;
    let (commit, idx_str) = rest.split_once('/')?;
    let commit = commit
        .strip_prefix("0x")
        .or_else(|| commit.strip_prefix("0X"))
        .unwrap_or(commit);
    if commit.len() != 64 || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let chunk_index = idx_str.parse().ok()?;
    Some((commit.to_ascii_lowercase(), chunk_index))
}

fn chunk_bytes_for_artifact(
    wallet_path: &Path,
    commit_hex: &str,
    chunk_index: u32,
) -> Result<Vec<u8>, String> {
    let loaded = load_upload_artifact(wallet_path, commit_hex).map_err(|e| e.to_string())?;
    let commit = &loaded.built.commit;
    let chunks = chunk_data(&loaded.payload, commit.chunk_size as usize)
        .map_err(|e| format!("chunk_data: {e}"))?;
    let idx = usize::try_from(chunk_index).map_err(|_| "chunk_index overflow".to_string())?;
    let slice = chunks
        .get(idx)
        .ok_or_else(|| format!("chunk_index {chunk_index} >= num_chunks {}", chunks.len()))?;
    Ok(slice.to_vec())
}

fn write_http_ok(stream: &mut TcpStream, body: &[u8]) -> Result<(), ChunkServeError> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn write_http_error(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
) -> Result<(), ChunkServeError> {
    let body = format!("{code} {reason}\n");
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upload_artifact_store::{save_upload_artifact, PAYLOAD_FILE};
    use mfn_storage::{build_storage_commitment, DEFAULT_ENDOWMENT_PARAMS};
    use std::fs;

    #[test]
    fn parse_chunk_path_accepts_hex_and_index() {
        let h = "ab".repeat(32);
        let (c, i) = parse_chunk_path(&format!("/chunk/{h}/2")).expect("path");
        assert_eq!(c.len(), 64);
        assert_eq!(i, 2);
    }

    #[test]
    fn chunk_bytes_for_saved_artifact_round_trip() {
        let dir = std::env::temp_dir().join(format!("mfn-chunk-http-{}", std::process::id()));
        let wallet = dir.join("w.json");
        fs::create_dir_all(&dir).expect("dir");
        fs::write(&wallet, b"{\"seed_hex\":\"00\"}").expect("wallet");
        let payload: Vec<u8> = (0u32..8000).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(4096),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let hash = mfn_storage::storage_commitment_hash(&built.commit);
        save_upload_artifact(&wallet, &built, &payload, Path::new("x"), None).expect("save");
        let out = chunk_bytes_for_artifact(&wallet, &hex::encode(hash), 1).expect("chunk");
        assert_eq!(out.len(), 3904); // 8000 - 4096
        let path = dir
            .join("w.upload-artifacts")
            .join(hex::encode(hash))
            .join(PAYLOAD_FILE);
        assert!(path.is_file());
        let _ = fs::remove_dir_all(&dir);
    }
}
