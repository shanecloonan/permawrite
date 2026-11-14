//! Read-only content gateway.
//!
//! A file is stored under the hex of its chunk-Merkle root, the same root
//! a storage commitment uses. The gateway recomputes that root before it
//! sends any byte. The access line records status, length, and content id.
//! It has no field for the requester's address.
//!
//! This does not change consensus.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

use mfn_storage::{chunk_data, merkle_tree_from_chunks, DEFAULT_CHUNK_SIZE};

/// One access line. There is no address field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessLine {
    /// HTTP status.
    pub status: u16,
    /// Body bytes sent.
    pub bytes: u64,
    /// 64 hex chars, or `-` when the request had no content id.
    pub content_id: String,
}

impl AccessLine {
    /// The only log text the gateway emits.
    pub fn render(&self) -> String {
        format!(
            "gateway status={} bytes={} id={}",
            self.status, self.bytes, self.content_id
        )
    }
}

/// Why a file was not served.
#[derive(Debug)]
pub enum GatewayError {
    /// Chunk size is not a positive power of two.
    ChunkSize,
    /// The id is not 64 hex characters.
    BadId,
    /// The bytes on disk do not hash to the requested id.
    RootMismatch,
    /// No such file, or the path left the store.
    Missing,
    /// Filesystem error.
    Io(String),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChunkSize => write!(f, "chunk size must be a power of two"),
            Self::BadId => write!(f, "content id must be 64 hex characters"),
            Self::RootMismatch => write!(f, "stored bytes do not match the content id"),
            Self::Missing => write!(f, "content not in the local store"),
            Self::Io(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for GatewayError {}

/// Local directory of `<content-id>.bin` files.
#[derive(Clone, Debug)]
pub struct Store {
    dir: PathBuf,
    chunk_size: usize,
}

impl Store {
    /// Open a store. `chunk_size` must be a power of two. Production uses
    /// [`DEFAULT_CHUNK_SIZE`].
    pub fn open(dir: impl Into<PathBuf>, chunk_size: usize) -> Result<Self, GatewayError> {
        if chunk_size == 0 || !chunk_size.is_power_of_two() {
            return Err(GatewayError::ChunkSize);
        }
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|e| GatewayError::Io(e.to_string()))?;
        Ok(Self { dir, chunk_size })
    }

    /// Chunk size used for the Merkle root. Default production size.
    pub fn production(dir: impl Into<PathBuf>) -> Result<Self, GatewayError> {
        Self::open(dir, DEFAULT_CHUNK_SIZE)
    }

    /// Root of `bytes` under this store's chunk size.
    pub fn content_id(&self, bytes: &[u8]) -> Result<String, GatewayError> {
        let chunks = chunk_data(bytes, self.chunk_size).map_err(|_| GatewayError::ChunkSize)?;
        let tree = merkle_tree_from_chunks(&chunks).map_err(|_| GatewayError::ChunkSize)?;
        Ok(hex::encode(tree.root()))
    }

    /// Write `bytes` under their own root. Returns the content id.
    pub fn put(&self, bytes: &[u8]) -> Result<String, GatewayError> {
        let id = self.content_id(bytes)?;
        let path = self.file_path(&id)?;
        fs::write(&path, bytes).map_err(|e| GatewayError::Io(e.to_string()))?;
        Ok(id)
    }

    /// Read and re-check the root. A flipped byte is `RootMismatch` and
    /// the caller must not send the bytes.
    pub fn read_verified(&self, id: &str) -> Result<Vec<u8>, GatewayError> {
        let path = self.file_path(id)?;
        let meta = fs::symlink_metadata(&path).map_err(|_| GatewayError::Missing)?;
        if !meta.file_type().is_file() {
            return Err(GatewayError::Missing);
        }
        let bytes = fs::read(&path).map_err(|e| GatewayError::Io(e.to_string()))?;
        let actual = self.content_id(&bytes)?;
        if actual != id {
            return Err(GatewayError::RootMismatch);
        }
        Ok(bytes)
    }

    fn file_path(&self, id: &str) -> Result<PathBuf, GatewayError> {
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(GatewayError::BadId);
        }
        let id = id.to_ascii_lowercase();
        Ok(self.dir.join(format!("{id}.bin")))
    }
}

/// Tor hidden-service snippet. The HTTP port stays on loopback.
pub fn onion_torrc(http_port: u16) -> String {
    format!(
        "\
SafeLogging 1
SocksPolicy reject *
HiddenServiceDir /var/lib/tor/permawrite-gateway
HiddenServicePort {http_port} 127.0.0.1:{http_port}
"
    )
}

/// Answer one HTTP/1.0 request. `peer` is not an argument.
pub fn respond(store: &Store, request: &str) -> (u16, Vec<u8>, AccessLine) {
    let path = request_path(request);
    let (status, body, id) = match path.as_deref() {
        Some("/health") => (200, b"ok\n".to_vec(), "-".to_string()),
        Some(p) if p.starts_with("/content/") => {
            let id = &p["/content/".len()..];
            match store.read_verified(id) {
                Ok(bytes) => (200, bytes, id.to_ascii_lowercase()),
                Err(GatewayError::RootMismatch) => (409, Vec::new(), id.to_ascii_lowercase()),
                Err(_) => (404, Vec::new(), "-".to_string()),
            }
        }
        Some(_) => (404, Vec::new(), "-".to_string()),
        None => (400, Vec::new(), "-".to_string()),
    };
    let line = AccessLine {
        status,
        bytes: body.len() as u64,
        content_id: id,
    };
    (status, body, line)
}

fn request_path(request: &str) -> Option<String> {
    let line = request.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    if method != "GET" || path.contains("..") || path.contains('%') {
        return None;
    }
    Some(path.to_string())
}

/// HTTP/1.0 response bytes.
pub fn http_response(status: u16, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.0 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Accept a single connection. The peer address is dropped before the
/// request is read, so it cannot reach the log.
pub fn serve_one(listener: &TcpListener, store: &Store) -> std::io::Result<AccessLine> {
    // `_peer` is the client address. It is never formatted into the access line.
    let (mut stream, _peer) = listener.accept()?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let (status, body, line) = respond(store, &request);
    stream.write_all(&http_response(status, &body))?;
    Ok(line)
}

/// Bind loopback only.
pub fn bind_loopback(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind(("127.0.0.1", port))
}

/// True when a rendered log line contains an IPv4 dotted quad.
pub fn log_contains_address(line: &str) -> bool {
    line.split(|c: char| !c.is_ascii_digit() && c != '.')
        .any(|part| {
            let octets: Vec<_> = part.split('.').collect();
            octets.len() == 4
                && octets
                    .iter()
                    .all(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mfn-gateway-{n}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn serves_only_when_the_root_matches() {
        let dir = scratch();
        let store = Store::open(&dir, 4).unwrap();
        let id = store.put(b"hello gateway").unwrap();
        assert_eq!(id.len(), 64);
        let (status, body, line) = respond(&store, &format!("GET /content/{id} HTTP/1.0\r\n\r\n"));
        assert_eq!(status, 200);
        assert_eq!(body, b"hello gateway");
        assert_eq!(line.content_id, id);
        assert!(!line.render().contains("127.0.0.1"));
        fs::write(dir.join(format!("{id}.bin")), b"hello gateway!").unwrap();
        let (status, body, _) = respond(&store, &format!("GET /content/{id} HTTP/1.0\r\n"));
        assert_eq!(status, 409);
        assert!(body.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn health_and_bad_paths_do_not_echo_a_client() {
        let dir = scratch();
        let store = Store::open(&dir, 4).unwrap();
        let (status, body, line) = respond(&store, "GET /health HTTP/1.0\r\n");
        assert_eq!(status, 200);
        assert_eq!(body, b"ok\n");
        assert_eq!(line.render(), "gateway status=200 bytes=3 id=-");
        let (status, _, line) = respond(&store, "GET /content/../secret HTTP/1.0\r\n");
        assert_eq!(status, 400);
        assert_eq!(line.content_id, "-");
        let (status, _, _) = respond(&store, "GET /content/abcd HTTP/1.0\r\n");
        assert_eq!(status, 404);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_request_log_has_no_client_address() {
        let dir = scratch();
        let store = Store::open(&dir, 8).unwrap();
        let id = store.put(b"abcdefg").unwrap();
        let listener = bind_loopback(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let store2 = store.clone();
        let handle = std::thread::spawn(move || serve_one(&listener, &store2).unwrap());
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            client,
            "GET /content/{id} HTTP/1.1\r\nHost: ignored\r\n\r\n"
        )
        .unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        let line = handle.join().unwrap();
        let text = line.render();
        assert!(buf.windows(b"abcdefg".len()).any(|w| w == b"abcdefg"));
        assert!(!log_contains_address(&text));
        assert!(!text.contains("127.0.0.1"));
        assert!(!text.contains("Host"));
        assert_eq!(line.content_id, id);
        assert!(onion_torrc(8080).contains("SafeLogging 1"));
        assert!(onion_torrc(8080).contains("HiddenServicePort 8080 127.0.0.1:8080"));
        let _ = fs::remove_dir_all(&dir);
    }
}
