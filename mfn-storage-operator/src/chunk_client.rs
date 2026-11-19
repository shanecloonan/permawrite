//! HTTP client for peer chunk replication (**M6.5**).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::chunk_http::parse_chunk_path;
use crate::socks5::socks5_connect;

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

/// Fetch the same chunk from every peer; all bodies must match byte-for-byte (**M6.7**).
pub fn fetch_chunk_http_quorum(
    peers: &[String],
    commitment_hash_hex: &str,
    chunk_index: u32,
) -> Result<Vec<u8>, ChunkFetchError> {
    if peers.is_empty() {
        return Err(ChunkFetchError::Usage(
            "quorum fetch requires at least one peer".into(),
        ));
    }
    let mut bodies = Vec::with_capacity(peers.len());
    for peer in peers {
        bodies.push(fetch_chunk_http(peer, commitment_hash_hex, chunk_index)?);
    }
    let reference = &bodies[0];
    for (i, body) in bodies.iter().enumerate().skip(1) {
        if body.as_slice() != reference.as_slice() {
            return Err(ChunkFetchError::Usage(format!(
                "peer chunk mismatch at index {chunk_index}: peer0 len={} peer{i} len={} peers={peers:?}",
                reference.len(),
                body.len(),
            )));
        }
    }
    Ok(reference.clone())
}

/// Fetch one chunk through a SOCKS5 proxy (Tor's listener is one).
///
/// `proxy` and `peer` are `HOST:PORT`. No proxy authentication is sent.
pub fn fetch_chunk_via_socks(
    proxy: &str,
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
    let (host, port) = split_host_port(&host_port)?;
    let stream =
        socks5_connect(proxy, &host, port).map_err(|e| ChunkFetchError::Usage(e.to_string()))?;
    let (status, body) = http_exchange(stream, &host_port, &path)?;
    if status != 200 {
        return Err(ChunkFetchError::Usage(format!(
            "peer returned HTTP {status} for {path}"
        )));
    }
    Ok(body)
}

fn split_host_port(host_port: &str) -> Result<(String, u16), ChunkFetchError> {
    let (host, port) = host_port
        .rsplit_once(':')
        .ok_or_else(|| ChunkFetchError::Usage(format!("peer `{host_port}` is missing a port")))?;
    let port = port
        .parse()
        .map_err(|_| ChunkFetchError::Usage(format!("peer port `{port}` is not a u16")))?;
    if host.is_empty() {
        return Err(ChunkFetchError::Usage("peer host is empty".into()));
    }
    Ok((host.to_string(), port))
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
    let stream = TcpStream::connect(host_port)
        .map_err(|e| ChunkFetchError::Usage(format!("connect {host_port}: {e}")))?;
    http_exchange(stream, host_port, path)
}

fn http_exchange(
    mut stream: TcpStream,
    host_port: &str,
    path: &str,
) -> Result<(u16, Vec<u8>), ChunkFetchError> {
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
        let peers = vec![listen.clone(), listen.clone()];
        let quorum = fetch_chunk_http_quorum(&peers, &hash, 1).expect("quorum");
        assert_eq!(quorum, body);

        stop.store(true, Ordering::SeqCst);
        server.join().expect("join");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fetch_chunk_via_socks_reaches_the_chunk_server() {
        let dir = std::env::temp_dir().join(format!("mfn-chunk-socks-{}", std::process::id()));
        let wallet = dir.join("w.json");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(&wallet, b"{}").expect("wallet");
        let payload = b"through tor the bytes still have to match".to_vec();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(64),
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
        let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("proxy");
        let proxy_addr = proxy_listener.local_addr().expect("addr").to_string();
        let proxy = std::thread::spawn(move || run_one_socks(proxy_listener));
        std::thread::sleep(std::time::Duration::from_millis(150));

        let via = fetch_chunk_via_socks(&proxy_addr, &listen, &hash, 0).expect("socks");
        let direct = fetch_chunk_http(&listen, &hash, 0).expect("direct");
        assert_eq!(via, direct);
        assert_eq!(via, payload);

        stop.store(true, Ordering::SeqCst);
        server.join().expect("join");
        proxy.join().expect("proxy");
        let _ = std::fs::remove_dir_all(dir);
    }

    fn run_one_socks(listener: std::net::TcpListener) {
        let (mut client, _) = listener.accept().expect("socks accept");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");
        let mut greet = [0u8; 3];
        std::io::Read::read_exact(&mut client, &mut greet).expect("greet");
        std::io::Write::write_all(&mut client, &[5, 0]).expect("method");
        let mut head = [0u8; 4];
        std::io::Read::read_exact(&mut client, &mut head).expect("head");
        assert_eq!(&head[..3], &[5, 1, 0]);
        let dest = match head[3] {
            1 => {
                let mut addr = [0u8; 6];
                std::io::Read::read_exact(&mut client, &mut addr).expect("ipv4");
                let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
                let port = u16::from_be_bytes([addr[4], addr[5]]);
                format!("{ip}:{port}")
            }
            other => panic!("unexpected atyp {other}"),
        };
        let mut target = std::net::TcpStream::connect(&dest).expect("dial target");
        std::io::Write::write_all(&mut client, &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).expect("reply");
        let mut up_client = client.try_clone().expect("clone");
        let mut up_target = target.try_clone().expect("clone");
        let upload = std::thread::spawn(move || {
            let _ = std::io::copy(&mut up_client, &mut up_target);
        });
        let _ = std::io::copy(&mut target, &mut client);
        drop(client);
        drop(target);
        let _ = upload.join();
    }
}
