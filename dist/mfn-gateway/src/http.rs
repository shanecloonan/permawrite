//! GET-only HTTP. The access record has no client address.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use thiserror::Error;

use crate::store::{is_loopback_host, load_verified, GatewayError, Store};

/// One access line. There is no field for an address, on purpose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRecord {
    /// HTTP status.
    pub status: u16,
    /// Content id, when the path named one.
    pub root: Option<String>,
    /// Bytes of payload sent. Zero on an error.
    pub bytes: u64,
}

/// Why the server rejected its own configuration.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpError {
    /// The bind address is not loopback.
    #[error("refusing a non-loopback bind")]
    NotLoopback,
}

/// Format the only log line the gateway is allowed to write.
pub fn format_access(record: &AccessRecord) -> String {
    match &record.root {
        Some(root) => format!(
            "status={} root={} bytes={}",
            record.status, root, record.bytes
        ),
        None => format!("status={} bytes={}", record.status, record.bytes),
    }
}

/// Answer one HTTP/1.0 request. POST and anything except GET are refused.
pub fn respond(store: &Store, request: &str) -> (AccessRecord, Vec<u8>) {
    let Some(path) = request_path(request) else {
        return finish(400, None, None);
    };
    if !request_is_get(request) {
        return finish(405, None, None);
    }
    let Some(id) = path.strip_prefix("/content/") else {
        return finish(404, None, None);
    };
    if id.contains('/') || id.len() != 64 {
        return finish(400, Some(id.to_string()), None);
    }
    match load_verified(store, id) {
        Ok(bytes) => finish(200, Some(id.to_string()), Some(bytes)),
        Err(GatewayError::RootMismatch) | Err(GatewayError::NotFound) => {
            finish(404, Some(id.to_ascii_lowercase()), None)
        }
        Err(_) => finish(400, Some(id.to_string()), None),
    }
}

fn finish(status: u16, root: Option<String>, body: Option<Vec<u8>>) -> (AccessRecord, Vec<u8>) {
    let body = body.unwrap_or_default();
    let record = AccessRecord {
        status,
        root,
        bytes: body.len() as u64,
    };
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let mut out = format!(
        "HTTP/1.0 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nCache-Control: public, max-age=31536000\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(&body);
    (record, out)
}

fn request_is_get(request: &str) -> bool {
    request.starts_with("GET ")
}

fn request_path(request: &str) -> Option<&str> {
    let mut parts = request.split_whitespace();
    let _method = parts.next()?;
    let path = parts.next()?;
    let path = path.split('?').next().unwrap_or(path);
    if path.starts_with('/') {
        Some(path)
    } else {
        None
    }
}

/// Bind `host:port` only when `host` is loopback.
pub fn bind_loopback(host: &str, port: u16) -> Result<TcpListener, HttpError> {
    if !is_loopback_host(host) {
        return Err(HttpError::NotLoopback);
    }
    let addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    TcpListener::bind(addr).map_err(|_| HttpError::NotLoopback)
}

/// Accept one connection and return the access record.
///
/// The peer address is used only to accept the socket. It is not formatted
/// into the returned record.
pub fn serve_one(listener: &TcpListener, store: &Store) -> std::io::Result<AccessRecord> {
    listener.set_nonblocking(false)?;
    let (mut stream, _peer): (TcpStream, SocketAddr) = listener.accept()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf)?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let (record, response) = respond(store, &request);
    stream.write_all(&response)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{ingest, Store};
    use std::io::Read;
    use std::net::TcpStream;

    #[test]
    fn access_line_has_no_address_and_post_is_refused() {
        let record = AccessRecord {
            status: 200,
            root: Some("ab".repeat(32)),
            bytes: 4,
        };
        let line = format_access(&record);
        assert!(!line.contains("127.0.0.1"));
        assert!(!line.contains("peer"));
        assert!(line.contains("status=200"));
        let dir = std::env::temp_dir().join(format!("mfn-gw-http-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        let (record, body) = respond(&store, "POST /content/abcd HTTP/1.1\r\n\r\n");
        assert_eq!(record.status, 405);
        assert!(body.windows(3).any(|w| w == b"405"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_serves_only_the_matching_root() {
        let dir = std::env::temp_dir().join(format!("mfn-gw-get-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        let id = ingest(&store, b"file-bytes").unwrap();
        let (ok, body) = respond(
            &store,
            &format!("GET /content/{id} HTTP/1.1\r\nHost: x\r\n\r\n"),
        );
        assert_eq!(ok.status, 200);
        assert_eq!(ok.bytes, b"file-bytes".len() as u64);
        assert!(body.ends_with(b"file-bytes"));
        assert!(!format_access(&ok).contains("Host"));
        let other = "ff".repeat(32);
        let (missing, _) = respond(&store, &format!("GET /content/{other} HTTP/1.0\r\n\r\n"));
        assert_eq!(missing.status, 404);
        let listener = bind_loopback("127.0.0.1", 0).unwrap();
        let addr = listener.local_addr().unwrap();
        let id2 = id.clone();
        let dir2 = dir.clone();
        let handle = std::thread::spawn(move || {
            let store = Store::open(&dir2).unwrap();
            serve_one(&listener, &store).unwrap()
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(format!("GET /content/{id2} HTTP/1.0\r\n\r\n").as_bytes())
            .unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        let record = handle.join().unwrap();
        assert_eq!(record.status, 200);
        assert!(got.ends_with(b"file-bytes"));
        assert!(!format_access(&record).contains(&addr.ip().to_string()));
        assert!(bind_loopback("0.0.0.0", 9).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
