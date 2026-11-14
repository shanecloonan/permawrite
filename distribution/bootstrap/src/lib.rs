//! Offline bootstrap check.
//!
//! A bootstrap document names every file by SHA-256 and lists places to
//! fetch the tree from. This crate checks a directory you already have.
//! It does not open a socket. A clearnet URL anywhere in the document
//! refuses the whole document, so a GitHub link cannot sit beside an
//! onion mirror and still count.

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

/// One file the document promises.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootFile {
    /// Relative path.
    pub name: String,
    /// Lowercase hex SHA-256.
    pub sha256: String,
    /// Byte length.
    pub size: u64,
}

/// Where a copy may be fetched. Only the classes this crate allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchClass {
    /// `ipfs://…`
    Ipfs,
    /// `magnet:?…`
    Magnet,
    /// `file://…` on a disk you already trust.
    File,
    /// `http(s)://*.onion/…`
    Onion,
}

/// A bootstrap document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bootstrap {
    /// SHA-256 of the canonical bundle, lowercase hex.
    pub bundle_sha256: String,
    /// Files, sorted by name.
    pub files: Vec<BootFile>,
    /// Allowed fetch locations.
    pub urls: Vec<(FetchClass, String)>,
}

/// Why a document or a tree was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum BootError {
    /// The text was not a bootstrap document.
    Format(&'static str),
    /// A URL is clearnet, or there is no fetch location at all.
    Clearnet,
    /// A path escapes the tree.
    BadPath,
    /// A file is missing or its bytes differ.
    Mismatch,
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(msg) => write!(f, "bootstrap document: {msg}"),
            Self::Clearnet => write!(f, "refusing a clearnet URL"),
            Self::BadPath => write!(f, "path escapes the tree"),
            Self::Mismatch => write!(f, "local file does not match the bootstrap document"),
        }
    }
}

impl std::error::Error for BootError {}

fn path_ok(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.contains(' ')
        && !name
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
}

fn digest_ok(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Classify a URL. Clearnet is `None`.
pub fn classify_url(url: &str) -> Option<FetchClass> {
    if url.starts_with("ipfs://") && !url.contains("..") {
        return Some(FetchClass::Ipfs);
    }
    if url.starts_with("magnet:?") && !url.contains("..") {
        return Some(FetchClass::Magnet);
    }
    if url.starts_with("file://") && !url.contains("..") {
        return Some(FetchClass::File);
    }
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let host = rest.split(['/', ':']).next().unwrap_or("");
    if host.ends_with(".onion") && host.len() > ".onion".len() && !host.contains("..") {
        return Some(FetchClass::Onion);
    }
    None
}

/// Parse a document. One clearnet URL refuses everything.
pub fn parse(text: &str) -> Result<Bootstrap, BootError> {
    let mut lines = text.lines().filter(|l| !l.is_empty());
    if lines.next() != Some("permawrite-bootstrap-v1") {
        return Err(BootError::Format("missing header"));
    }
    let bundle = lines
        .next()
        .and_then(|l| l.strip_prefix("bundle_sha256="))
        .ok_or(BootError::Format("missing bundle hash"))?;
    if !digest_ok(bundle) {
        return Err(BootError::Format("bundle hash"));
    }
    let mut files = Vec::new();
    let mut urls = Vec::new();
    for line in lines {
        if let Some(rest) = line.strip_prefix("file ") {
            let mut parts = rest.splitn(3, ' ');
            let sha = parts.next().ok_or(BootError::Format("file"))?;
            let size: u64 = parts
                .next()
                .ok_or(BootError::Format("file"))?
                .parse()
                .map_err(|_| BootError::Format("file size"))?;
            let name = parts.next().ok_or(BootError::Format("file"))?;
            if !digest_ok(sha) || !path_ok(name) {
                return Err(BootError::BadPath);
            }
            files.push(BootFile {
                name: name.to_string(),
                sha256: sha.to_ascii_lowercase(),
                size,
            });
        } else if let Some(url) = line.strip_prefix("url ") {
            let Some(class) = classify_url(url) else {
                return Err(BootError::Clearnet);
            };
            urls.push((class, url.to_string()));
        } else {
            return Err(BootError::Format("unknown line"));
        }
    }
    if urls.is_empty() {
        return Err(BootError::Clearnet);
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Bootstrap {
        bundle_sha256: bundle.to_ascii_lowercase(),
        files,
        urls,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let dig = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in dig {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Check `root` against the document. Does not contact any URL.
pub fn check_dir(root: &Path, doc: &Bootstrap) -> Result<(), BootError> {
    for file in &doc.files {
        if !path_ok(&file.name) {
            return Err(BootError::BadPath);
        }
        let path = root.join(&file.name);
        let bytes = fs::read(&path).map_err(|_| BootError::Mismatch)?;
        if bytes.len() as u64 != file.size || sha256_hex(&bytes) != file.sha256 {
            return Err(BootError::Mismatch);
        }
    }
    Ok(())
}

/// Build a document from files and URLs. Clearnet URLs are refused.
pub fn from_files(
    files: &[(String, Vec<u8>)],
    urls: &[String],
) -> Result<(Bootstrap, String), BootError> {
    if urls.is_empty() || urls.iter().any(|u| classify_url(u).is_none()) {
        return Err(BootError::Clearnet);
    }
    let mut rows = files.to_vec();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut body = String::from("permawrite-bootstrap-v1\n");
    let mut described = Vec::new();
    let mut bundle = Vec::from(&b"permawrite-bundle-v1\n"[..]);
    for (name, bytes) in &rows {
        if !path_ok(name) {
            return Err(BootError::BadPath);
        }
        let sha = sha256_hex(bytes);
        let size = bytes.len() as u64;
        body.push_str(&format!("file {sha} {size} {name}\n"));
        bundle.extend_from_slice(format!("{name}\n{size}\n{sha}\n").as_bytes());
        bundle.extend_from_slice(bytes);
        bundle.push(b'\n');
        described.push(BootFile {
            name: name.clone(),
            sha256: sha,
            size,
        });
    }
    let bundle_sha256 = sha256_hex(&bundle);
    let mut text = format!("permawrite-bootstrap-v1\nbundle_sha256={bundle_sha256}\n");
    text.push_str(&body["permawrite-bootstrap-v1\n".len()..]);
    let mut stored = Vec::new();
    for url in urls {
        let class = classify_url(url).ok_or(BootError::Clearnet)?;
        text.push_str("url ");
        text.push_str(url);
        text.push('\n');
        stored.push((class, url.clone()));
    }
    Ok((
        Bootstrap {
            bundle_sha256,
            files: described,
            urls: stored,
        },
        text,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str =
        "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion/bundle";

    #[test]
    fn clearnet_refuses_the_whole_document() {
        let (doc, text) = from_files(
            &[("mfnd".into(), b"abc".to_vec())],
            &[ONION.into(), "ipfs://bafkreiabc".into()],
        )
        .unwrap();
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed.bundle_sha256, doc.bundle_sha256);
        assert!(parse(&format!(
            "{text}url https://github.com/shanecloonan/permawrite\n"
        ))
        .is_err());
        assert!(parse(&format!("{text}url http://5.161.201.73/mfnd\n")).is_err());
        assert!(from_files(&[("mfnd".into(), b"abc".to_vec())], &[]).is_err());
    }

    #[test]
    fn local_tree_must_match_and_a_byte_must_not() {
        let dir = std::env::temp_dir().join(format!(
            "mfn-boot-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("mfnd"), b"abc").unwrap();
        let (doc, text) = from_files(
            &[("mfnd".into(), b"abc".to_vec())],
            &["file:///var/bundle".into()],
        )
        .unwrap();
        assert!(check_dir(&dir, &parse(&text).unwrap()).is_ok());
        fs::write(dir.join("mfnd"), b"abC").unwrap();
        assert!(check_dir(&dir, &doc).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn escaped_paths_and_unknown_lines_are_refused() {
        let text = "\
permawrite-bootstrap-v1
bundle_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
file aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 ../x
url file:///tmp/x
";
        assert!(matches!(parse(text), Err(BootError::BadPath)));
        assert!(classify_url("https://example.com/mfnd").is_none());
        assert_eq!(classify_url(ONION), Some(FetchClass::Onion));
    }
}
