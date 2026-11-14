//! Content-addressed mirrors.
//!
//! A release directory becomes three names that do not depend on GitHub:
//! a CIDv1 (raw, sha2-256), a BitTorrent v2 infohash, and a canonical
//! bundle whose SHA-256 is what an operator uploads into chain storage.
//! Fetch URLs may be `ipfs:`, `magnet:`, `file:`, or an onion HTTP URL.
//! A clearnet URL is refused.
//!
//! The bundle hash is an application checksum. It is not a consensus root.

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

const BASE32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const PIECE: usize = 16 * 1024;

/// One file in a mirror.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorFile {
    /// Relative path, `/` separators, no `..`.
    pub name: String,
    /// Lowercase hex SHA-256 of the bytes.
    pub sha256: String,
    /// Byte length.
    pub size: u64,
}

/// A mirror someone can fetch without GitHub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mirror {
    /// Short name, such as `permawrite`.
    pub name: String,
    /// SHA-256 of [`bundle_bytes`].
    pub bundle_sha256: String,
    /// CIDv1 raw of the bundle.
    pub ipfs_cid: String,
    /// BitTorrent v2 infohash of the bundle, lowercase hex.
    pub bittorrent_v2: String,
    /// Files, sorted by name.
    pub files: Vec<MirrorFile>,
    /// Fetch locations. Clearnet URLs are not stored.
    pub urls: Vec<String>,
}

/// Why a mirror was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum MirrorError {
    /// Name or path is empty or escapes.
    BadPath,
    /// A URL is clearnet or otherwise not a content-addressed / onion locator.
    ClearnetUrl,
    /// A file's bytes do not match the mirror.
    Mismatch,
    /// Filesystem error.
    Io(String),
}

impl std::fmt::Display for MirrorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPath => write!(f, "path escapes the mirror"),
            Self::ClearnetUrl => write!(f, "refusing a clearnet URL"),
            Self::Mismatch => write!(f, "file bytes do not match the mirror"),
            Self::Io(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for MirrorError {}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let dig = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn path_ok(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.contains(' ')
        && !name
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
}

/// RFC 4648 base32, lowercase, no padding.
pub fn base32_nopad(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer = 0u64;
    let mut bits = 0;
    for byte in data {
        buffer = (buffer << 8) | u64::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32[idx] as char);
    }
    out
}

/// CIDv1 for a raw block: multibase base32 of `version || raw || sha2-256`.
pub fn cid_v1_raw(bytes: &[u8]) -> String {
    let dig = sha256(bytes);
    let mut raw = Vec::with_capacity(36);
    raw.extend_from_slice(&[0x01, 0x55, 0x12, 0x20]);
    raw.extend_from_slice(&dig);
    format!("b{}", base32_nopad(&raw))
}

/// SHA-256 of one 16 KiB piece, zero-padded when `block` is shorter.
pub fn piece_root(block: &[u8]) -> [u8; 32] {
    if block.len() == PIECE {
        return sha256(block);
    }
    let mut padded = vec![0u8; PIECE];
    let n = block.len().min(PIECE);
    padded[..n].copy_from_slice(&block[..n]);
    sha256(&padded)
}

fn bencode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("{}:", bytes.len()).into_bytes();
    out.extend_from_slice(bytes);
    out
}

/// BitTorrent v2 infohash (sha256 of the bencoded info dict) for one file.
pub fn bittorrent_v2_infohash(file_name: &str, bytes: &[u8]) -> String {
    let root = piece_root(bytes);
    let mut info = Vec::new();
    info.extend_from_slice(b"d");
    info.extend_from_slice(b"9:file treed");
    info.extend(bencode_bytes(file_name.as_bytes()));
    info.extend_from_slice(b"d");
    info.extend_from_slice(format!("6:lengthi{}e", bytes.len()).as_bytes());
    info.extend_from_slice(b"11:pieces root");
    info.extend(bencode_bytes(&root));
    info.extend_from_slice(b"ee");
    info.extend_from_slice(b"12:meta versioni2e");
    info.extend_from_slice(b"4:name");
    info.extend(bencode_bytes(file_name.as_bytes()));
    info.extend_from_slice(format!("12:piece lengthi{PIECE}e").as_bytes());
    info.extend_from_slice(b"e");
    hex32(&sha256(&info))
}

/// Canonical upload body: one record per file, names sorted.
pub fn bundle_bytes(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, MirrorError> {
    let mut rows = files.to_vec();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    out.extend_from_slice(b"permawrite-bundle-v1\n");
    for (name, bytes) in &rows {
        if !path_ok(name) {
            return Err(MirrorError::BadPath);
        }
        out.extend_from_slice(format!("{name}\n{}\n", bytes.len()).as_bytes());
        out.extend_from_slice(hex32(&sha256(bytes)).as_bytes());
        out.push(b'\n');
        out.extend_from_slice(bytes);
        out.push(b'\n');
    }
    Ok(out)
}

/// `true` when the URL is onion HTTP(S), ipfs, magnet, or file.
pub fn url_allowed(url: &str) -> bool {
    if url.starts_with("ipfs://") || url.starts_with("magnet:?") || url.starts_with("file://") {
        return !url.contains("..");
    }
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"));
    let Some(rest) = rest else {
        return false;
    };
    let host = rest.split(['/', ':']).next().unwrap_or("");
    host.ends_with(".onion") && host.len() > ".onion".len() && !host.contains("..")
}

/// Build a mirror from named blobs.
pub fn from_files(
    name: &str,
    files: &[(String, Vec<u8>)],
    urls: &[String],
) -> Result<Mirror, MirrorError> {
    if !path_ok(name) {
        return Err(MirrorError::BadPath);
    }
    for url in urls {
        if !url_allowed(url) {
            return Err(MirrorError::ClearnetUrl);
        }
    }
    let bundle = bundle_bytes(files)?;
    let mut described = Vec::new();
    let mut rows = files.to_vec();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    for (file_name, bytes) in rows {
        described.push(MirrorFile {
            name: file_name,
            sha256: hex32(&sha256(&bytes)),
            size: bytes.len() as u64,
        });
    }
    Ok(Mirror {
        name: name.to_string(),
        bundle_sha256: hex32(&sha256(&bundle)),
        ipfs_cid: cid_v1_raw(&bundle),
        bittorrent_v2: bittorrent_v2_infohash(name, &bundle),
        files: described,
        urls: urls.to_vec(),
    })
}

/// Text form. Stable for the same mirror.
pub fn render(mirror: &Mirror) -> String {
    let mut out = String::new();
    out.push_str("permawrite-mirror-v1\n");
    out.push_str("name=");
    out.push_str(&mirror.name);
    out.push('\n');
    out.push_str("bundle_sha256=");
    out.push_str(&mirror.bundle_sha256);
    out.push('\n');
    out.push_str("ipfs_cid=");
    out.push_str(&mirror.ipfs_cid);
    out.push('\n');
    out.push_str("bittorrent_v2=");
    out.push_str(&mirror.bittorrent_v2);
    out.push('\n');
    for file in &mirror.files {
        out.push_str("file ");
        out.push_str(&file.sha256);
        out.push(' ');
        out.push_str(&file.size.to_string());
        out.push(' ');
        out.push_str(&file.name);
        out.push('\n');
    }
    for url in &mirror.urls {
        out.push_str("url ");
        out.push_str(url);
        out.push('\n');
    }
    out
}

/// Check files under `root` against the mirror. Extra files are ignored.
pub fn verify_dir(root: &Path, mirror: &Mirror) -> Result<(), MirrorError> {
    for file in &mirror.files {
        if !path_ok(&file.name) {
            return Err(MirrorError::BadPath);
        }
        let path = root.join(&file.name);
        let bytes = fs::read(&path).map_err(|_| MirrorError::Mismatch)?;
        if bytes.len() as u64 != file.size || hex32(&sha256(&bytes)) != file.sha256 {
            return Err(MirrorError::Mismatch);
        }
    }
    Ok(())
}

/// Read a directory of regular files (one level of subdirectories).
pub fn read_tree(root: &Path) -> Result<Vec<(String, Vec<u8>)>, MirrorError> {
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), MirrorError> {
    let entries = fs::read_dir(dir).map_err(|e| MirrorError::Io(e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| MirrorError::Io(e.to_string()))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if !path_ok(&rel) {
            return Err(MirrorError::BadPath);
        }
        let meta = fs::symlink_metadata(&path).map_err(|e| MirrorError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() {
            return Err(MirrorError::BadPath);
        }
        if meta.is_dir() {
            walk(root, &path, out)?;
        } else if meta.is_file() {
            let bytes = fs::read(&path).map_err(|e| MirrorError::Io(e.to_string()))?;
            out.push((rel, bytes));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_raw_cid_matches_the_published_vector() {
        assert_eq!(
            cid_v1_raw(b""),
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        );
    }

    #[test]
    fn clearnet_urls_are_refused_and_onion_ipfs_are_not() {
        assert!(url_allowed(
            "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion/bundle"
        ));
        assert!(url_allowed(
            "ipfs://bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        ));
        assert!(url_allowed("magnet:?xt=urn:btmh:1220ab"));
        assert!(url_allowed("file:///var/lib/permawrite/bundle"));
        assert!(!url_allowed("https://github.com/shanecloonan/permawrite"));
        assert!(!url_allowed("http://5.161.201.73/mfnd"));
        let err = from_files(
            "permawrite",
            &[("mfnd".into(), b"abc".to_vec())],
            &["https://example.com/mfnd".into()],
        );
        assert!(matches!(err, Err(MirrorError::ClearnetUrl)));
    }

    #[test]
    fn mirror_is_stable_and_a_byte_changes_every_name() {
        let files = vec![
            ("mfnd".into(), b"abc".to_vec()),
            ("readme".into(), b"hi".to_vec()),
        ];
        let urls = vec!["ipfs://bafkreiexample".into()];
        let a = from_files("permawrite", &files, &urls).unwrap();
        let b = from_files("permawrite", &files, &urls).unwrap();
        assert_eq!(render(&a), render(&b));
        assert!(a.ipfs_cid.starts_with('b'));
        assert_eq!(a.bittorrent_v2.len(), 64);
        let mut flipped = files.clone();
        flipped[0].1 = b"abd".to_vec();
        let c = from_files("permawrite", &flipped, &urls).unwrap();
        assert_ne!(a.bundle_sha256, c.bundle_sha256);
        assert_ne!(a.ipfs_cid, c.ipfs_cid);
        assert_ne!(a.bittorrent_v2, c.bittorrent_v2);
        assert!(from_files("permawrite", &[("../x".into(), b"a".to_vec())], &[]).is_err());
    }

    #[test]
    fn directory_round_trip_catches_a_tampered_file() {
        let dir = std::env::temp_dir().join(format!(
            "mfn-mirror-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::write(dir.join("bin/mfnd"), b"binary").unwrap();
        let files = read_tree(&dir).unwrap();
        let mirror = from_files("permawrite", &files, &["file:///tmp/bundle".into()]).unwrap();
        assert!(verify_dir(&dir, &mirror).is_ok());
        fs::write(dir.join("bin/mfnd"), b"binarY").unwrap();
        assert!(verify_dir(&dir, &mirror).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn piece_root_pads_a_short_block_with_zeros() {
        let short = piece_root(b"abc");
        let mut padded = vec![0u8; PIECE];
        padded[..3].copy_from_slice(b"abc");
        assert_eq!(short, sha256(&padded));
        assert_ne!(piece_root(b"abd"), short);
    }
}
