//! Fetch a file by its content id.
//!
//! The content id is the Merkle root of the 12 shard hashes. Operators serve
//! individual shards at `GET /chunk/{commitment}/{index}`. This client asks
//! every peer, keeps the shard bytes that most peers agree on, rebuilds the
//! file from any four shards, and refuses the result when that root does not
//! match the content id. An `MFUP` payload is decrypted with the upload key.
//!
//! Connections go through a SOCKS5 proxy unless the caller passes no proxy.
//! The CLI defaults that proxy to Tor at `127.0.0.1:9050`.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::Duration;

use mfn_net::socks5::socks5_connect_domain_with_timeout;
use mfn_storage::{
    build_storage_commitment, decrypt_upload, open_shard_stripe, prepare_shard_stripe,
    upload_blob_is_encrypted, StripeError, UploadCryptError, STRIPE_SHARDS,
};

use crate::chunk_client::{fetch_chunk_http, ChunkFetchError};

/// Why a content id could not be fetched.
#[derive(Debug, thiserror::Error)]
pub enum RetrieveError {
    /// A peer request failed in a way that stopped the fetch.
    #[error("chunk fetch: {0}")]
    Fetch(String),
    /// Fewer than four shards came back.
    #[error("only {0} shards were available; four are required")]
    Short(usize),
    /// The rebuilt stripe is not a valid code.
    #[error("stripe: {0:?}")]
    Stripe(StripeError),
    /// The rebuilt root is not the content id that was requested.
    #[error("rebuilt root does not match the content id")]
    RootMismatch,
    /// The payload is encrypted and no key was provided.
    #[error("content is encrypted; pass the upload key")]
    KeyRequired,
    /// The key does not open the payload.
    #[error("decrypt: {0}")]
    Crypt(UploadCryptError),
}

/// Fetch `content_root` from `peers`.
///
/// `socks_proxy` is `host:port` of a SOCKS5 proxy. `None` dials peers directly.
///
/// # Errors
///
/// [`RetrieveError`] when the peers cannot produce a stripe whose root is
/// `content_root`.
pub fn retrieve_content(
    content_root: &[u8; 32],
    commitment_hash_hex: &str,
    peers: &[String],
    socks_proxy: Option<&str>,
    key: Option<&[u8; 32]>,
) -> Result<Vec<u8>, RetrieveError> {
    if peers.is_empty() {
        return Err(RetrieveError::Fetch("no peers".into()));
    }
    let mut slots: Vec<Option<Vec<u8>>> = (0..STRIPE_SHARDS).map(|_| None).collect();
    for index in 0..STRIPE_SHARDS {
        if let Some(body) = shard_from_peers(commitment_hash_hex, index, peers, socks_proxy)? {
            let idx = usize::try_from(index).unwrap_or(0);
            if let Some(slot) = slots.get_mut(idx) {
                *slot = Some(body);
            }
        }
    }
    let have = slots.iter().filter(|s| s.is_some()).count();
    if have < 4 {
        return Err(RetrieveError::Short(have));
    }
    let plain = open_shard_stripe(&slots).map_err(RetrieveError::Stripe)?;
    let prepared = prepare_shard_stripe(&plain).map_err(RetrieveError::Stripe)?;
    let built = build_storage_commitment(
        &prepared.bytes,
        1,
        Some(prepared.chunk_size as usize),
        1,
        None,
    )
    .map_err(|e| RetrieveError::Fetch(e.to_string()))?;
    if built.commit.data_root != *content_root {
        return Err(RetrieveError::RootMismatch);
    }
    if upload_blob_is_encrypted(&plain) {
        let key = key.ok_or(RetrieveError::KeyRequired)?;
        return decrypt_upload(&plain, key).map_err(RetrieveError::Crypt);
    }
    Ok(plain)
}

fn shard_from_peers(
    commit: &str,
    index: u32,
    peers: &[String],
    socks_proxy: Option<&str>,
) -> Result<Option<Vec<u8>>, RetrieveError> {
    let mut votes: BTreeMap<Vec<u8>, u32> = BTreeMap::new();
    for peer in peers {
        let body = match socks_proxy {
            Some(proxy) => fetch_chunk_socks(proxy, peer, commit, index),
            None => fetch_chunk_http(peer, commit, index).map_err(|e| e.to_string()),
        };
        if let Ok(body) = body {
            *votes.entry(body).or_insert(0) += 1;
        }
    }
    Ok(votes
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(body, _)| body))
}

fn fetch_chunk_socks(proxy: &str, peer: &str, commit: &str, index: u32) -> Result<Vec<u8>, String> {
    let peer = peer.trim().strip_prefix("http://").unwrap_or(peer.trim());
    let (host, port) = peer
        .rsplit_once(':')
        .ok_or_else(|| format!("peer `{peer}` is not host:port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("peer `{peer}` has no port"))?;
    let mut stream = socks5_connect_domain_with_timeout(proxy, host, port, Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    let path = format!("/chunk/{commit}/{index}");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {peer}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let (status, body) = parse_status(&raw)?;
    if status != 200 {
        return Err(format!("HTTP {status}"));
    }
    Ok(body)
}

fn parse_status(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "HTTP response missing header".to_string())?;
    let header = std::str::from_utf8(&raw[..header_end]).map_err(|e| e.to_string())?;
    let line = header.lines().next().unwrap_or("");
    let status = line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("bad status line `{line}`"))?
        .parse()
        .map_err(|_| format!("bad status line `{line}`"))?;
    Ok((status, raw[header_end + 4..].to_vec()))
}

/// `true` when the content id the caller asked for is the root the node published.
#[must_use]
pub fn content_id_matches_node(content_root_hex: &str, node_data_root_hex: &str) -> bool {
    content_root_hex
        .trim()
        .eq_ignore_ascii_case(node_data_root_hex.trim())
}

impl From<ChunkFetchError> for RetrieveError {
    fn from(value: ChunkFetchError) -> Self {
        Self::Fetch(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_http::{serve_chunks, ChunkServeConfig};
    use crate::upload_artifact_store::upload_artifact_dir;
    use mfn_storage::{encrypt_upload, storage_commitment_hash};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn content_id_compare_is_case_insensitive() {
        assert!(content_id_matches_node("Ab", "ab"));
        assert!(!content_id_matches_node("aa", "ab"));
    }

    #[test]
    fn three_operators_rebuild_and_decrypt_through_socks() {
        let dir = std::env::temp_dir().join(format!("mfn-retrieve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let key = [9u8; 32];
        let nonce = [3u8; 16];
        let file = b"the file survives when any four shards remain".to_vec();
        let sealed = encrypt_upload(&file, &key, &nonce);
        let prepared = prepare_shard_stripe(&sealed).expect("stripe");
        let built = build_storage_commitment(
            &prepared.bytes,
            1,
            Some(prepared.chunk_size as usize),
            1,
            None,
        )
        .expect("built");
        let commit = storage_commitment_hash(&built.commit);
        let commit_hex = hex::encode(commit);

        let mut addrs = Vec::new();
        let mut stops = Vec::new();
        let keeps: [&[u32]; 3] = [&[0, 1, 2, 3], &[2, 3, 4, 5, 6, 7], &[6, 7, 8, 9, 10, 11]];
        for (n, keep) in keeps.iter().enumerate() {
            let wallet = dir.join(format!("op{n}.json"));
            std::fs::write(&wallet, b"{}").expect("wallet");
            let dest = upload_artifact_dir(&wallet, &commit);
            std::fs::create_dir_all(&dest).expect("dest");
            for i in *keep {
                std::fs::write(
                    dest.join(format!("shard-{i:02}.bin")),
                    &prepared.shards[*i as usize],
                )
                .expect("shard");
            }
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let addr = listener.local_addr().expect("addr").to_string();
            drop(listener);
            let stop = Arc::new(AtomicBool::new(false));
            let stop_bg = Arc::clone(&stop);
            let wallet_bg = wallet.clone();
            let addr_bg = addr.clone();
            thread::spawn(move || {
                let _ = serve_chunks(
                    ChunkServeConfig {
                        wallet_path: wallet_bg,
                        listen_addr: addr_bg,
                    },
                    stop_bg,
                );
            });
            addrs.push(addr);
            stops.push(stop);
        }
        let proxy = start_socks();
        thread::sleep(Duration::from_millis(150));
        let peers = addrs.clone();
        let got = retrieve_content(
            &built.commit.data_root,
            &commit_hex,
            &peers,
            Some(&proxy),
            Some(&key),
        )
        .expect("retrieve");
        assert_eq!(got, file);
        let without_c = peers[..2].to_vec();
        let still = retrieve_content(
            &built.commit.data_root,
            &commit_hex,
            &without_c,
            Some(&proxy),
            Some(&key),
        )
        .expect("two operators still cover the file");
        assert_eq!(still, file);
        let wrong = [1u8; 32];
        assert!(matches!(
            retrieve_content(&wrong, &commit_hex, &peers, Some(&proxy), Some(&key)),
            Err(RetrieveError::RootMismatch)
        ));
        for stop in stops {
            stop.store(true, Ordering::SeqCst);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    fn start_socks() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("socks");
        let addr = listener.local_addr().expect("addr").to_string();
        thread::spawn(move || {
            for client in listener.incoming().flatten() {
                thread::spawn(move || {
                    let _ = proxy_one(client);
                });
            }
        });
        addr
    }

    fn proxy_one(mut client: TcpStream) -> std::io::Result<()> {
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut greet = [0u8; 2];
        client.read_exact(&mut greet)?;
        let mut methods = vec![0u8; greet[1] as usize];
        client.read_exact(&mut methods)?;
        client.write_all(&[5, 0])?;
        let mut head = [0u8; 4];
        client.read_exact(&mut head)?;
        if head[3] != 3 {
            return Ok(());
        }
        let mut len = [0u8; 1];
        client.read_exact(&mut len)?;
        let mut host = vec![0u8; len[0] as usize];
        client.read_exact(&mut host)?;
        let mut portb = [0u8; 2];
        client.read_exact(&mut portb)?;
        let host = String::from_utf8(host).unwrap_or_default();
        let port = u16::from_be_bytes(portb);
        let mut upstream = TcpStream::connect((host.as_str(), port))?;
        client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
        upstream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut req = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = client.read(&mut buf)?;
            if n == 0 {
                break;
            }
            req.extend_from_slice(&buf[..n]);
            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        upstream.write_all(&req)?;
        upstream.flush()?;
        let mut resp = Vec::new();
        loop {
            match upstream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
            }
        }
        client.write_all(&resp)?;
        Ok(())
    }
}
