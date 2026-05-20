//! HTTP client for peer chunk replication (**M6.5**).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::chunk_http::parse_chunk_path;

/// Chunk fetch errors.
#[derive(Debug, thiserror::Error)]
pub enum ChunkFetchError {
    /// TCP / HTTP I/O.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// URL / response handling.
    #[error("{0}")]
    Usage(String),
}

/// `GET /chunk/{commit_hex}/{chunk_index}` from a peer serving **M6.2** chunks.
///
/// `peer` is `HOST:PORT` or `http://HOST:PORT` (no TLS).
pub fn fetch_chunk_http(
    peer: &str,
    commitment_hash_hex: &str,
    chunk_index: u32,
) -> Result<Vec<u8>, ChunkFetchError> {
    let commit = normalize_commit_hex(commitment_hash_hex)?;
    let path = format!("/chunk/{commit}/{chunk_index}");
    if parse_chunk_path(&path).is_none() {
        return Err(ChunkFetchError::Usage(
            "invalid commitment_hash_hex or chunk_index".into(),
        ));
    }
    let host_port = peer_addr_from_peer(peer)?;
    let (status, body) = http_get(&host_port, &path)?;
    if status != 200 {
        return Err(ChunkFetchError::Usage(format!(
            "peer returned HTTP {status} for {path}"
        )));
    }
    Ok(body)
}

fn normalize_commit_hex(s: &str) -> Result<String, ChunkFetchError> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ChunkFetchError::Usage(format!(
            "commitment_hash_hex must be 64 hex chars, got {}",
            t.len()
        )));
    }
    Ok(t.to_ascii_lowercase())
}

fn peer_addr_from_peer(peer: &str) -> Result<String, ChunkFetchError> {
    let peer = peer.trim();
    let stripped = peer
        .strip_prefix("http://")
        .or_else(|| peer.strip_prefix("HTTP://"))
        .unwrap_or(peer);
    if stripped.is_empty() || stripped.contains('/') {
        return Err(ChunkFetchError::Usage(format!(
            "peer must be HOST:PORT or http://HOST:PORT, got `{peer}`"
        )));
    }
    Ok(stripped.to_string())
}

fn http_get(host_port: &str, path: &str) -> Result<(u16, Vec<u8>), ChunkFetchError> {
    let mut stream = TcpStream::connect(host_port)
        .map_err(|e| ChunkFetchError::Usage(format!("connect {host_port}: {e}")))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), ChunkFetchError> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ChunkFetchError::Usage("HTTP response missing header terminator".into()))?;
    let header = std::str::from_utf8(&raw[..header_end])
        .map_err(|e| ChunkFetchError::Usage(format!("response header utf8: {e}")))?;
    let status_line = header
        .lines()
        .next()
        .ok_or_else(|| ChunkFetchError::Usage("HTTP response missing status line".into()))?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| ChunkFetchError::Usage("HTTP response missing status code".into()))?
        .parse()
        .map_err(|e| ChunkFetchError::Usage(format!("status code: {e}")))?;
    Ok((code, raw[header_end + 4..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_http::{serve_chunks, ChunkServeConfig};
    use crate::upload_artifact_store::save_upload_artifact;
    use mfn_storage::{
        build_storage_commitment, storage_commitment_hash, DEFAULT_ENDOWMENT_PARAMS,
    };
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn ephemeral_listen_addr() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        format!("127.0.0.1:{port}")
    }

    #[test]
    fn fetch_chunk_http_round_trip() {
        let dir = std::env::temp_dir().join(format!("mfn-chunk-fetch-{}", std::process::id()));
        let wallet = dir.join("w.json");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(&wallet, b"{}").expect("wallet");
        let payload: Vec<u8> = (0u32..8000).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(4096),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let hash = hex::encode(storage_commitment_hash(&built.commit));
        save_upload_artifact(&wallet, &built, &payload, Path::new("x"), None).expect("save");

        let listen = ephemeral_listen_addr();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);
        let wallet_bg = wallet.clone();
        let listen_bg = listen.clone();
        let server = std::thread::spawn(move || {
            serve_chunks(
                ChunkServeConfig {
                    wallet_path: wallet_bg,
                    listen_addr: listen_bg,
                },
                stop_bg,
            )
            .expect("serve");
        });
        std::thread::sleep(std::time::Duration::from_millis(150));

        let body = fetch_chunk_http(&listen, &hash, 1).expect("fetch");
        assert_eq!(body.len(), 3904);

        stop.store(true, Ordering::SeqCst);
        server.join().expect("join");
        let _ = std::fs::remove_dir_all(dir);
    }
}
