//! ustar pack and unpack with a fixed header.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// One file in a source bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFile {
    /// Relative path using `/`.
    pub path: String,
    /// File bytes.
    pub bytes: Vec<u8>,
}

/// Why a path was refused or an archive could not be read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BundleError {
    /// The path is absolute, empty, or escapes the bundle.
    #[error("path is not source: {0}")]
    BadPath(String),
    /// The archive header is not a ustar we wrote.
    #[error("archive is not a source bundle")]
    BadArchive,
    /// A file is larger than a ustar header can name.
    #[error("file is too large: {0}")]
    TooLarge(String),
}

const EPOCH_FIELD: u64 = 0;

/// Pack `files` at `source_date_epoch`. Order of `files` does not matter.
pub fn pack(files: &[SourceFile], source_date_epoch: u64) -> Result<Vec<u8>, BundleError> {
    let mut ordered = files.to_vec();
    for file in &mut ordered {
        file.path = normalize(&file.path)?;
    }
    ordered.sort_by(|a, b| a.path.cmp(&b.path));
    for pair in ordered.windows(2) {
        if pair[0].path == pair[1].path {
            return Err(BundleError::BadPath(pair[0].path.clone()));
        }
    }
    let mut out = Vec::new();
    for file in &ordered {
        if file.bytes.len() > 8_000_000_000 {
            return Err(BundleError::TooLarge(file.path.clone()));
        }
        out.extend_from_slice(&header(
            &file.path,
            file.bytes.len() as u64,
            source_date_epoch,
        )?);
        out.extend_from_slice(&file.bytes);
        let pad = (512 - (file.bytes.len() % 512)) % 512;
        out.extend(std::iter::repeat(0).take(pad));
    }
    out.extend(std::iter::repeat(0).take(1024));
    let _ = EPOCH_FIELD;
    Ok(out)
}

/// Read a bundle produced by [`pack`].
pub fn unpack(archive: &[u8]) -> Result<Vec<SourceFile>, BundleError> {
    if archive.len() < 1024 || archive.len() % 512 != 0 {
        return Err(BundleError::BadArchive);
    }
    let mut files = Vec::new();
    let mut offset = 0;
    while offset + 512 <= archive.len() {
        let header = &archive[offset..offset + 512];
        offset += 512;
        if header.iter().all(|b| *b == 0) {
            break;
        }
        if &header[257..262] != b"ustar" {
            return Err(BundleError::BadArchive);
        }
        let name = field_str(&header[..100])?;
        let prefix = field_str(&header[345..500])?;
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let size = parse_octal(&header[124..136])?;
        let end = offset + size as usize;
        if end > archive.len() {
            return Err(BundleError::BadArchive);
        }
        let bytes = archive[offset..end].to_vec();
        offset = end + ((512 - (size as usize % 512)) % 512);
        files.push(SourceFile { path, bytes });
    }
    Ok(files)
}

/// SHA-256 of a packed bundle. Useful as the content address of the source.
pub fn bundle_sha256(archive: &[u8]) -> String {
    hex::encode(Sha256::digest(archive))
}

fn normalize(raw: &str) -> Result<String, BundleError> {
    let path = raw.replace('\\', "/");
    if path.is_empty() || path.starts_with('/') {
        return Err(BundleError::BadPath(raw.to_string()));
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part == ".git" || part == "target" {
            return Err(BundleError::BadPath(raw.to_string()));
        }
        parts.push(part);
    }
    if parts.is_empty() || parts[0] == ".git" {
        return Err(BundleError::BadPath(raw.to_string()));
    }
    let joined = parts.join("/");
    if joined.starts_with(".git/") || joined.starts_with("target/") {
        return Err(BundleError::BadPath(joined));
    }
    if joined.len() > 255 {
        return Err(BundleError::TooLarge(joined));
    }
    Ok(joined)
}

fn header(path: &str, size: u64, mtime: u64) -> Result<[u8; 512], BundleError> {
    let mut block = [0u8; 512];
    let (name, prefix) = split_name(path)?;
    write_str(&mut block[0..100], name);
    write_str(&mut block[100..108], "0000644");
    write_str(&mut block[108..116], "0000000");
    write_str(&mut block[116..124], "0000000");
    write_octal(&mut block[124..136], size);
    write_octal(&mut block[136..148], mtime);
    for byte in &mut block[148..156] {
        *byte = b' ';
    }
    block[156] = b'0';
    write_str(&mut block[257..263], "ustar");
    block[263] = 0;
    write_str(&mut block[263..265], "00");
    write_str(&mut block[265..297], "root");
    write_str(&mut block[297..329], "root");
    write_str(&mut block[345..500], prefix);
    let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
    let text = format!("{sum:06o}\0 ");
    block[148..156].copy_from_slice(text.as_bytes());
    Ok(block)
}

fn split_name(path: &str) -> Result<(&str, &str), BundleError> {
    if path.len() <= 100 {
        return Ok((path, ""));
    }
    if let Some((prefix, name)) = path.rsplit_once('/') {
        if prefix.len() <= 155 && name.len() <= 100 {
            return Ok((name, prefix));
        }
    }
    Err(BundleError::TooLarge(path.to_string()))
}

fn write_str(dest: &mut [u8], text: &str) {
    let bytes = text.as_bytes();
    let n = bytes.len().min(dest.len());
    dest[..n].copy_from_slice(&bytes[..n]);
}

fn write_octal(dest: &mut [u8], value: u64) {
    let text = format!("{value:011o}");
    write_str(dest, &text);
}

fn field_str(bytes: &[u8]) -> Result<String, BundleError> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let text = std::str::from_utf8(&bytes[..end]).map_err(|_| BundleError::BadArchive)?;
    Ok(text.trim_end_matches(' ').to_string())
}

fn parse_octal(bytes: &[u8]) -> Result<u64, BundleError> {
    let text = field_str(bytes)?;
    u64::from_str_radix(text.trim(), 8).map_err(|_| BundleError::BadArchive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_packs_match_and_round_trip() {
        let files = vec![
            SourceFile {
                path: "src/b.rs".into(),
                bytes: b"b".to_vec(),
            },
            SourceFile {
                path: "src/a.rs".into(),
                bytes: b"aaa".to_vec(),
            },
        ];
        let first = pack(&files, 1_700_000_000).unwrap();
        let mut reversed = files.clone();
        reversed.reverse();
        let second = pack(&reversed, 1_700_000_000).unwrap();
        assert_eq!(first, second);
        assert_eq!(bundle_sha256(&first), bundle_sha256(&second));
        let back = unpack(&first).unwrap();
        assert_eq!(back[0].path, "src/a.rs");
        assert_eq!(back[0].bytes, b"aaa");
        assert_eq!(back[1].bytes, b"b");
    }

    #[test]
    fn git_target_and_dotdot_are_refused() {
        assert!(pack(
            &[SourceFile {
                path: ".git/config".into(),
                bytes: b"x".to_vec(),
            }],
            1
        )
        .is_err());
        assert!(pack(
            &[SourceFile {
                path: "target/release/mfnd".into(),
                bytes: b"x".to_vec(),
            }],
            1
        )
        .is_err());
        assert!(pack(
            &[SourceFile {
                path: "../secret".into(),
                bytes: b"x".to_vec(),
            }],
            1
        )
        .is_err());
    }
}
