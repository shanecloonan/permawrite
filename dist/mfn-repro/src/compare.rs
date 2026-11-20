//! SHA-256 manifest parse and compare.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// One named digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashEntry {
    /// Lower-case hex SHA-256.
    pub sha256_hex: String,
    /// Relative artifact name.
    pub name: String,
}

/// Why a manifest line was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    /// The line was not `hex  name`.
    #[error("manifest line is not 'sha256  name': {0}")]
    BadLine(String),
    /// The digest was not 64 hex characters.
    #[error("sha256 must be 64 hex characters")]
    BadDigest,
    /// The artifact name escapes the manifest directory.
    #[error("artifact name is not a single relative path: {0}")]
    BadName(String),
    /// The same name appears twice.
    #[error("duplicate artifact name: {0}")]
    Duplicate(String),
}

/// Result of comparing two manifests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompareReport {
    /// Names whose digests differ.
    pub mismatched: Vec<String>,
    /// Names present only on the left.
    pub only_left: Vec<String>,
    /// Names present only on the right.
    pub only_right: Vec<String>,
}

impl CompareReport {
    /// Both manifests list the same names and digests.
    pub fn is_match(&self) -> bool {
        self.mismatched.is_empty() && self.only_left.is_empty() && self.only_right.is_empty()
    }
}

/// SHA-256 of `bytes`, lower-case hex.
pub fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Parse a `sha256sum` manifest. Blank lines are ignored.
pub fn parse_manifest(text: &str) -> Result<Vec<HashEntry>, ManifestError> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (digest, name) = split_line(line)?;
        if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ManifestError::BadDigest);
        }
        let name = check_name(name)?;
        if out.iter().any(|e: &HashEntry| e.name == name) {
            return Err(ManifestError::Duplicate(name));
        }
        out.push(HashEntry {
            sha256_hex: digest.to_ascii_lowercase(),
            name,
        });
    }
    Ok(out)
}

fn split_line(line: &str) -> Result<(&str, &str), ManifestError> {
    // GNU sha256sum: "hex  name" (text) or "hex *name" (binary).
    let (digest, rest) = line
        .split_once(' ')
        .ok_or_else(|| ManifestError::BadLine(line.to_string()))?;
    if digest.len() != 64 {
        return Err(ManifestError::BadDigest);
    }
    let name = rest.trim_start_matches([' ', '*']);
    if name.is_empty() || name.chars().any(char::is_whitespace) {
        return Err(ManifestError::BadLine(line.to_string()));
    }
    Ok((digest, name))
}

fn check_name(name: &str) -> Result<String, ManifestError> {
    if name.is_empty()
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains(':')
        || name.split(['/', '\\']).any(|p| p == ".." || p.is_empty())
    {
        return Err(ManifestError::BadName(name.to_string()));
    }
    Ok(name.replace('\\', "/"))
}

/// Compare two manifests by artifact name. Order does not matter.
pub fn compare_manifests(left: &[HashEntry], right: &[HashEntry]) -> CompareReport {
    let mut mismatched = Vec::new();
    let mut only_left = Vec::new();
    let mut only_right = Vec::new();
    for entry in left {
        match right.iter().find(|r| r.name == entry.name) {
            Some(other) if other.sha256_hex != entry.sha256_hex => {
                mismatched.push(entry.name.clone())
            }
            Some(_) => {}
            None => only_left.push(entry.name.clone()),
        }
    }
    for entry in right {
        if !left.iter().any(|l| l.name == entry.name) {
            only_right.push(entry.name.clone());
        }
    }
    mismatched.sort();
    only_left.sort();
    only_right.sort();
    CompareReport {
        mismatched,
        only_left,
        only_right,
    }
}

/// Render entries in `sha256sum` text mode, sorted by name.
pub fn render_manifest(entries: &[HashEntry]) -> String {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = String::new();
    for entry in sorted {
        out.push_str(&entry.sha256_hex);
        out.push_str("  ");
        out.push_str(&entry.name);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, byte: u8) -> HashEntry {
        HashEntry {
            sha256_hex: hash_bytes(&[byte]),
            name: name.to_string(),
        }
    }

    #[test]
    fn identical_manifests_match_in_either_order() {
        let a = vec![entry("mfnd", 1), entry("mfn-cli", 2)];
        let b = vec![entry("mfn-cli", 2), entry("mfnd", 1)];
        assert!(compare_manifests(&a, &b).is_match());
    }

    #[test]
    fn digest_mismatch_is_named() {
        let report = compare_manifests(&[entry("mfnd", 1)], &[entry("mfnd", 9)]);
        assert_eq!(report.mismatched, vec!["mfnd".to_string()]);
        assert!(!report.is_match());
    }

    #[test]
    fn missing_and_extra_names_are_reported() {
        let report = compare_manifests(&[entry("mfnd", 1)], &[entry("mfn-cli", 1)]);
        assert_eq!(report.only_left, vec!["mfnd".to_string()]);
        assert_eq!(report.only_right, vec!["mfn-cli".to_string()]);
    }

    #[test]
    fn gnu_text_and_binary_lines_parse() {
        let digest = hash_bytes(b"mfnd");
        let text = format!("{digest}  mfnd\n{digest} *mfn-cli\n\n# comment\n");
        let parsed = parse_manifest(&text).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].name, "mfn-cli");
    }

    #[test]
    fn short_digest_and_traversal_are_rejected() {
        assert_eq!(
            parse_manifest("abcd  mfnd\n").unwrap_err(),
            ManifestError::BadDigest
        );
        let digest = "ab".repeat(32);
        assert!(matches!(
            parse_manifest(&format!("{digest}  ../mfnd\n")),
            Err(ManifestError::BadName(_))
        ));
        assert!(matches!(
            parse_manifest(&format!("{digest}  /tmp/mfnd\n")),
            Err(ManifestError::BadName(_))
        ));
    }

    #[test]
    fn duplicate_name_is_rejected() {
        let digest = "aa".repeat(32);
        let text = format!("{digest}  mfnd\n{digest}  mfnd\n");
        assert!(matches!(
            parse_manifest(&text),
            Err(ManifestError::Duplicate(_))
        ));
    }

    #[test]
    fn render_is_stable() {
        let text = render_manifest(&[entry("b", 2), entry("a", 1)]);
        let again = render_manifest(&parse_manifest(&text).unwrap());
        assert_eq!(text, again);
        assert!(text.find("  a\n").unwrap() < text.find("  b\n").unwrap());
    }
}
