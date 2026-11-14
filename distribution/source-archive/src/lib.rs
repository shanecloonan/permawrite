//! Deterministic source archives.
//!
//! Two machines that pack the same files get the same ustar bytes: names
//! are sorted, the timestamp is zero, and the owner is zero. The archive
//! checksum is a SHA-256 of those bytes. A path that escapes the tree is
//! refused. This is how a source tarball can be checked without trusting
//! the clock or the user id of the machine that packed it.

use std::fs;
use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};

/// One archived file. Directories are recorded with empty bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveEntry {
    /// Relative path using `/`.
    pub name: String,
    /// File bytes. Empty for a directory.
    pub bytes: Vec<u8>,
    /// True when this entry is a directory.
    pub dir: bool,
}

/// Why packing or reading failed.
#[derive(Debug, PartialEq, Eq)]
pub enum ArchiveError {
    /// Name is absolute, empty, too long, or contains `..`.
    BadPath,
    /// Header checksum did not match.
    Checksum,
    /// The archive was truncated or not ustar.
    Truncated,
    /// Filesystem error.
    Io(String),
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPath => write!(f, "archive path escapes the tree"),
            Self::Checksum => write!(f, "ustar header checksum mismatch"),
            Self::Truncated => write!(f, "archive is truncated"),
            Self::Io(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ArchiveError {}

fn path_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
}

fn write_octal(slot: &mut [u8], value: u64) {
    let width = slot.len() - 1;
    let text = format!("{value:0width$o}");
    let bytes = text.as_bytes();
    let n = bytes.len().min(width);
    slot[..n].copy_from_slice(&bytes[bytes.len() - n..]);
}

fn header(name: &str, size: u64, dir: bool) -> Result<[u8; 512], ArchiveError> {
    if !path_ok(name) {
        return Err(ArchiveError::BadPath);
    }
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    let mode = if dir { 0o755 } else { 0o644 };
    write_octal(&mut h[100..108], mode);
    write_octal(&mut h[108..116], 0);
    write_octal(&mut h[116..124], 0);
    write_octal(&mut h[124..136], size);
    write_octal(&mut h[136..148], 0);
    h[148..156].fill(b' ');
    h[156] = if dir { b'5' } else { b'0' };
    h[257..262].copy_from_slice(b"ustar");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    let digits = format!("{sum:06o}");
    h[148..154].copy_from_slice(digits.as_bytes());
    h[154] = 0;
    h[155] = b' ';
    Ok(h)
}

fn header_checksum_ok(h: &[u8; 512]) -> bool {
    let mut scratch = *h;
    scratch[148..156].fill(b' ');
    let sum: u32 = scratch.iter().map(|b| u32::from(*b)).sum();
    let digits = format!("{sum:06o}");
    &h[148..154] == digits.as_bytes() && h[154] == 0 && h[155] == b' '
}

/// Pack entries into a ustar archive. Names are sorted. Timestamps are zero.
pub fn pack(entries: &[ArchiveEntry]) -> Result<Vec<u8>, ArchiveError> {
    let mut rows = entries.to_vec();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = Vec::new();
    for entry in rows {
        let size = if entry.dir {
            0
        } else {
            entry.bytes.len() as u64
        };
        let h = header(&entry.name, size, entry.dir)?;
        out.extend_from_slice(&h);
        if !entry.dir {
            out.extend_from_slice(&entry.bytes);
            let pad = (512 - (entry.bytes.len() % 512)) % 512;
            out.extend(std::iter::repeat(0).take(pad));
        }
    }
    out.extend_from_slice(&[0u8; 1024]);
    Ok(out)
}

/// Read a ustar archive produced by [`pack`].
pub fn unpack(archive: &[u8]) -> Result<Vec<ArchiveEntry>, ArchiveError> {
    if archive.len() < 1024 || archive.len() % 512 != 0 {
        return Err(ArchiveError::Truncated);
    }
    let mut out = Vec::new();
    let mut off = 0;
    while off + 512 <= archive.len() {
        let mut h = [0u8; 512];
        h.copy_from_slice(&archive[off..off + 512]);
        off += 512;
        if h.iter().all(|b| *b == 0) {
            break;
        }
        if !header_checksum_ok(&h) || &h[257..262] != b"ustar" {
            return Err(ArchiveError::Checksum);
        }
        let name_end = h[..100].iter().position(|b| *b == 0).unwrap_or(100);
        let name = std::str::from_utf8(&h[..name_end]).map_err(|_| ArchiveError::BadPath)?;
        if !path_ok(name) {
            return Err(ArchiveError::BadPath);
        }
        let dir = h[156] == b'5';
        let size = parse_octal(&h[124..136]).ok_or(ArchiveError::Truncated)?;
        let nbytes = usize::try_from(size).map_err(|_| ArchiveError::Truncated)?;
        let bytes = if dir {
            Vec::new()
        } else {
            let blocks = nbytes.div_ceil(512);
            if off + blocks * 512 > archive.len() {
                return Err(ArchiveError::Truncated);
            }
            let data = archive[off..off + nbytes].to_vec();
            off += blocks * 512;
            data
        };
        out.push(ArchiveEntry {
            name: name.to_string(),
            bytes,
            dir,
        });
    }
    Ok(out)
}

fn parse_octal(slot: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(slot).ok()?;
    let text = text.trim_end_matches('\0').trim();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

/// SHA-256 of an archive, lowercase hex.
pub fn archive_sha256(archive: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let dig = Sha256::digest(archive);
    let mut s = String::with_capacity(64);
    for b in dig {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Read regular files under `root`. Symlinks are refused.
pub fn read_tree(root: &Path) -> Result<Vec<ArchiveEntry>, ArchiveError> {
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<ArchiveEntry>) -> Result<(), ArchiveError> {
    let entries = fs::read_dir(dir).map_err(|e| ArchiveError::Io(e.to_string()))?;
    let mut names: Vec<_> = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ArchiveError::Io(e.to_string()))?;
    names.sort_by_key(|e| e.file_name());
    for entry in names {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if !path_ok(&rel) {
            return Err(ArchiveError::BadPath);
        }
        let meta = fs::symlink_metadata(&path).map_err(|e| ArchiveError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() {
            return Err(ArchiveError::BadPath);
        }
        if meta.is_dir() {
            out.push(ArchiveEntry {
                name: rel,
                bytes: Vec::new(),
                dir: true,
            });
            walk(root, &path, out)?;
        } else if meta.is_file() {
            let bytes = fs::read(&path).map_err(|e| ArchiveError::Io(e.to_string()))?;
            out.push(ArchiveEntry {
                name: rel,
                bytes,
                dir: false,
            });
        }
    }
    Ok(())
}

/// Write `entries` as a ustar file and return its SHA-256.
pub fn write_archive(path: &Path, entries: &[ArchiveEntry]) -> Result<String, ArchiveError> {
    let bytes = pack(entries)?;
    let digest = archive_sha256(&bytes);
    let mut file = fs::File::create(path).map_err(|e| ArchiveError::Io(e.to_string()))?;
    file.write_all(&bytes)
        .map_err(|e| ArchiveError::Io(e.to_string()))?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<ArchiveEntry> {
        vec![
            ArchiveEntry {
                name: "src/main.rs".into(),
                bytes: b"fn main() {}\n".to_vec(),
                dir: false,
            },
            ArchiveEntry {
                name: "README".into(),
                bytes: b"hello\n".to_vec(),
                dir: false,
            },
        ]
    }

    #[test]
    fn two_packs_are_byte_identical_and_round_trip() {
        let a = pack(&sample()).unwrap();
        let b = pack(&sample()).unwrap();
        assert_eq!(a, b);
        assert_eq!(archive_sha256(&a), archive_sha256(&b));
        let back = unpack(&a).unwrap();
        assert_eq!(back[0].name, "README");
        assert_eq!(back[1].bytes, b"fn main() {}\n");
        assert!(a.windows(5).any(|w| w == b"ustar"));
    }

    #[test]
    fn timestamp_and_owner_fields_are_zero() {
        let a = pack(&sample()).unwrap();
        let mtime = &a[136..148];
        let uid = &a[108..116];
        assert!(mtime.starts_with(b"00000000000"));
        assert!(uid.starts_with(b"0000000"));
    }

    #[test]
    fn a_flipped_header_byte_fails_the_checksum() {
        let mut a = pack(&sample()).unwrap();
        a[0] ^= 0x01;
        assert!(matches!(unpack(&a), Err(ArchiveError::Checksum)));
        assert!(pack(&[ArchiveEntry {
            name: "../secret".into(),
            bytes: b"x".to_vec(),
            dir: false,
        }])
        .is_err());
    }

    #[test]
    fn directory_pack_is_stable() {
        let dir = std::env::temp_dir().join(format!(
            "mfn-archive-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/lib.rs"), b"pub fn x() {}\n").unwrap();
        let entries = read_tree(&dir).unwrap();
        let first = pack(&entries).unwrap();
        let second = pack(&read_tree(&dir).unwrap()).unwrap();
        assert_eq!(first, second);
        let _ = fs::remove_dir_all(&dir);
    }
}
