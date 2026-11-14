//! Reproducible release builds.
//!
//! The release workflow used to float on `stable` and embed absolute
//! runner paths in the binaries. This crate is the profile those builds
//! must use, plus the comparison that tells two builds apart.
//!
//! It does not change consensus, genesis, or the default node.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path};

use sha2::{Digest, Sha256};

/// Rust toolchain the release binaries are pinned to.
pub const TOOLCHAIN: &str = "1.83.0";

/// Fixed timestamp so object files do not embed the build clock.
pub const SOURCE_DATE_EPOCH: &str = "0";

/// Crate identity printed into plans and checksum headers.
pub const PROFILE_NAME: &str = "permawrite-repro-v1";

/// Binaries a release must ship, in plan order.
pub const RELEASE_BINS: &[&str] = &["mfnd", "mfn-cli", "mfn-storage-operator"];

/// One hashed file, path relative to the directory that was walked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHash {
    /// Relative path using `/` separators, sorted lexicographically.
    pub rel: String,
    /// Lowercase hex SHA-256 of the file bytes.
    pub sha256: String,
    /// Byte length.
    pub len: u64,
}

/// Why a tree could not be hashed or compared.
#[derive(Debug)]
pub enum ReproError {
    /// Filesystem failure. The path is the caller's input, not a peer address.
    Io {
        /// What we were touching.
        path: String,
        /// OS error.
        source: io::Error,
    },
    /// A symlink, device, or other non-regular file. Those are not reproducible.
    NotRegular {
        /// Relative path.
        path: String,
    },
    /// A path component was `..` or absolute. The walk stays inside the root.
    Escapes {
        /// Relative path.
        path: String,
    },
    /// Checksum file could not be parsed.
    Checksum {
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        reason: &'static str,
    },
}

impl std::fmt::Display for ReproError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "io error at {path}: {source}"),
            Self::NotRegular { path } => write!(f, "not a regular file: {path}"),
            Self::Escapes { path } => write!(f, "path escapes the tree: {path}"),
            Self::Checksum { line, reason } => write!(f, "checksum line {line}: {reason}"),
        }
    }
}

impl std::error::Error for ReproError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// One file whose digest or presence disagrees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    /// Relative path.
    pub rel: String,
    /// What the left tree had, if anything.
    pub left: Option<String>,
    /// What the right tree had, if anything.
    pub right: Option<String>,
}

/// Flags and environment for one target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildProfile {
    /// `rustc` target triple, or `host` when the caller did not cross-compile.
    pub target: String,
    /// `RUSTFLAGS` value, including `-D warnings`.
    pub rustflags: String,
    /// Environment assignments in a stable order.
    pub env: Vec<(String, String)>,
}

/// `RUSTFLAGS` for `target_os` (`linux`, `macos`, `windows`).
///
/// `workspace` is rewritten to `/permawrite` inside the binary so a
/// `/home/runner` path cannot leak into the artifact or change the hash.
/// GNU `ld` gets `--build-id=none`. MSVC and Apple linkers do not
/// understand that flag, so it is Linux-only.
pub fn rustflags(target_os: &str, workspace: &str) -> String {
    let mut flags = format!("-D warnings --remap-path-prefix={workspace}=/permawrite");
    flags.push_str(" -C symbol-mangling-version=v0");
    if target_os == "linux" {
        flags.push_str(" -C link-arg=-Wl,--build-id=none");
    }
    flags
}

/// Full profile. `target_os` selects linker flags. `workspace` is the
/// absolute path that must be remapped away.
pub fn build_profile(target_os: &str, workspace: &str) -> BuildProfile {
    let rustflags = rustflags(target_os, workspace);
    let env = vec![
        ("RUSTUP_TOOLCHAIN".to_string(), TOOLCHAIN.to_string()),
        (
            "SOURCE_DATE_EPOCH".to_string(),
            SOURCE_DATE_EPOCH.to_string(),
        ),
        ("CARGO_INCREMENTAL".to_string(), "0".to_string()),
        (
            "CARGO_PROFILE_RELEASE_DEBUG".to_string(),
            "none".to_string(),
        ),
        (
            "CARGO_PROFILE_RELEASE_CODEGEN_UNITS".to_string(),
            "1".to_string(),
        ),
        ("CARGO_PROFILE_RELEASE_LTO".to_string(), "thin".to_string()),
        ("TZ".to_string(), "UTC".to_string()),
        ("LC_ALL".to_string(), "C".to_string()),
        ("RUSTFLAGS".to_string(), rustflags.clone()),
    ];
    BuildProfile {
        target: target_os.to_string(),
        rustflags,
        env,
    }
}

/// Human-readable plan. Same bytes for the same inputs.
pub fn plan(workspace: &str) -> String {
    let mut out = String::new();
    out.push_str(PROFILE_NAME);
    out.push('\n');
    out.push_str("toolchain=");
    out.push_str(TOOLCHAIN);
    out.push('\n');
    out.push_str("bins=");
    out.push_str(&RELEASE_BINS.join(","));
    out.push('\n');
    for os in ["linux", "macos", "windows"] {
        let profile = build_profile(os, workspace);
        out.push_str("target_os=");
        out.push_str(os);
        out.push('\n');
        for (key, value) in profile.env {
            out.push_str(&key);
            out.push('=');
            out.push_str(&value);
            out.push('\n');
        }
    }
    out.push_str("compare=hash every regular file, fail if any digest or name differs\n");
    out
}

fn sha256_file(path: &Path) -> io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut len = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), len))
}

fn rel_ok(rel: &str) -> bool {
    let path = Path::new(rel);
    path.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
        && !rel.starts_with('/')
        && !rel.contains('\\')
}

/// Hash every regular file under `root`. Symlinks are rejected.
/// Directories are not entries. The result is sorted by relative path.
pub fn hash_tree(root: &Path) -> Result<Vec<FileHash>, ReproError> {
    let mut out = Vec::new();
    hash_tree_into(root, root, &mut out)?;
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

fn hash_tree_into(root: &Path, dir: &Path, out: &mut Vec<FileHash>) -> Result<(), ReproError> {
    let entries = fs::read_dir(dir).map_err(|e| ReproError::Io {
        path: dir.display().to_string(),
        source: e,
    })?;
    let mut names: Vec<_> = entries
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ReproError::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
    names.sort_by_key(|e| e.file_name());
    for entry in names {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if !rel_ok(&rel) {
            return Err(ReproError::Escapes { path: rel });
        }
        let meta = fs::symlink_metadata(&path).map_err(|e| ReproError::Io {
            path: rel.clone(),
            source: e,
        })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() && !meta.is_dir() {
            return Err(ReproError::NotRegular { path: rel });
        }
        if meta.is_dir() {
            hash_tree_into(root, &path, out)?;
            continue;
        }
        let (sha256, len) = sha256_file(&path).map_err(|e| ReproError::Io {
            path: rel.clone(),
            source: e,
        })?;
        out.push(FileHash { rel, sha256, len });
    }
    Ok(())
}

/// GNU `sha256sum` text: 64 hex digits, two spaces, relative path, newline.
pub fn format_checksums(files: &[FileHash]) -> String {
    let mut out = String::new();
    for file in files {
        out.push_str(&file.sha256);
        out.push_str("  ");
        out.push_str(&file.rel);
        out.push('\n');
    }
    out
}

/// Parse GNU `sha256sum` text. Rejects a single space, a short digest, or `..`.
pub fn parse_checksums(text: &str) -> Result<Vec<FileHash>, ReproError> {
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let line_no = idx + 1;
        let (digest, rest) = line.split_once("  ").ok_or(ReproError::Checksum {
            line: line_no,
            reason: "expected two spaces between digest and name",
        })?;
        if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ReproError::Checksum {
                line: line_no,
                reason: "digest must be 64 hex characters",
            });
        }
        if !rel_ok(rest) || rest.is_empty() {
            return Err(ReproError::Checksum {
                line: line_no,
                reason: "name escapes the tree",
            });
        }
        out.push(FileHash {
            rel: rest.to_string(),
            sha256: digest.to_ascii_lowercase(),
            len: 0,
        });
    }
    Ok(out)
}

/// Compare two hashed trees. Every name and digest must match.
pub fn compare(left: &[FileHash], right: &[FileHash]) -> Result<(), Vec<Mismatch>> {
    let mut lmap: BTreeMap<&str, &str> = BTreeMap::new();
    for file in left {
        lmap.insert(file.rel.as_str(), file.sha256.as_str());
    }
    let mut rmap: BTreeMap<&str, &str> = BTreeMap::new();
    for file in right {
        rmap.insert(file.rel.as_str(), file.sha256.as_str());
    }
    let mut names: Vec<&str> = lmap.keys().copied().chain(rmap.keys().copied()).collect();
    names.sort_unstable();
    names.dedup();
    let mut bad = Vec::new();
    for name in names {
        let l = lmap.get(name).copied();
        let r = rmap.get(name).copied();
        if l != r {
            bad.push(Mismatch {
                rel: name.to_string(),
                left: l.map(str::to_string),
                right: r.map(str::to_string),
            });
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad)
    }
}

/// Hash `root` and check it against a parsed checksum list.
/// Lengths in the checksum file are ignored; the digest is the check.
pub fn verify_tree(root: &Path, expected: &[FileHash]) -> Result<(), Vec<Mismatch>> {
    let actual = hash_tree(root).map_err(|e| {
        vec![Mismatch {
            rel: root.display().to_string(),
            left: Some(e.to_string()),
            right: None,
        }]
    })?;
    compare(&actual, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> std::path::PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mfn-repro-{n}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn plan_is_stable_and_pins_the_toolchain() {
        let a = plan("/tmp/permawrite");
        let b = plan("/tmp/permawrite");
        assert_eq!(a, b);
        assert!(a.contains("toolchain=1.83.0"));
        assert!(a.contains("SOURCE_DATE_EPOCH=0"));
        assert!(a.contains("--remap-path-prefix=/tmp/permawrite=/permawrite"));
        assert!(a.contains("mfnd,mfn-cli,mfn-storage-operator"));
        assert!(a.contains("-C link-arg=-Wl,--build-id=none"));
        assert!(!a.contains("0.0.0.0"));
    }

    #[test]
    fn windows_flags_omit_gnu_build_id() {
        let flags = rustflags("windows", r"D:\src");
        assert!(!flags.contains("build-id"));
        assert!(flags.contains("--remap-path-prefix=D:\\src=/permawrite"));
        assert!(rustflags("linux", "/src").contains("build-id=none"));
        assert!(!rustflags("macos", "/src").contains("build-id"));
    }

    #[test]
    fn identical_trees_match_and_a_byte_does_not() {
        let root = scratch();
        let a = root.join("a");
        let b = root.join("b");
        fs::create_dir_all(a.join("sub")).unwrap();
        fs::create_dir_all(b.join("sub")).unwrap();
        fs::write(a.join("sub/mfnd"), b"same-bytes").unwrap();
        fs::write(b.join("sub/mfnd"), b"same-bytes").unwrap();
        let ha = hash_tree(&a).unwrap();
        let hb = hash_tree(&b).unwrap();
        assert!(compare(&ha, &hb).is_ok());
        fs::write(b.join("sub/mfnd"), b"same-byteS").unwrap();
        let hb = hash_tree(&b).unwrap();
        let err = compare(&ha, &hb).unwrap_err();
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].rel, "sub/mfnd");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_file_is_a_mismatch() {
        let left = vec![FileHash {
            rel: "mfnd".into(),
            sha256: "ab".into(),
            len: 1,
        }];
        let right = vec![FileHash {
            rel: "mfn-cli".into(),
            sha256: "cd".into(),
            len: 1,
        }];
        let err = compare(&left, &right).unwrap_err();
        assert_eq!(err.len(), 2);
    }

    #[test]
    fn checksum_round_trip_rejects_escape_and_one_space() {
        let files = vec![FileHash {
            rel: "linux/mfnd".into(),
            sha256: "ab".repeat(32),
            len: 4,
        }];
        let text = format_checksums(&files);
        assert_eq!(text.matches("  ").count(), 1);
        let parsed = parse_checksums(&text).unwrap();
        assert_eq!(parsed[0].rel, "linux/mfnd");
        let evil = format!("{}  ../secret\n", "aa".repeat(32));
        assert!(parse_checksums(&evil).is_err());
        let one_space = format!("{} mfnd\n", "aa".repeat(32));
        assert!(parse_checksums(&one_space).is_err());
    }

    #[test]
    fn verify_tree_accepts_its_own_checksum_and_rejects_a_swap() {
        let root = scratch();
        fs::write(root.join("mfnd"), b"bin-a").unwrap();
        fs::write(root.join("mfn-cli"), b"bin-b").unwrap();
        let hashed = hash_tree(&root).unwrap();
        assert!(verify_tree(&root, &hashed).is_ok());
        let mut swapped = hashed.clone();
        swapped[0].sha256 = hashed[1].sha256.clone();
        assert!(verify_tree(&root, &swapped).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn symlink_is_rejected() {
        let root = scratch();
        fs::write(root.join("real"), b"x").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("real", root.join("link")).unwrap();
            let err = hash_tree(&root).unwrap_err();
            assert!(matches!(err, ReproError::NotRegular { .. }));
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn known_sha256_of_empty_and_abc() {
        let root = scratch();
        fs::write(root.join("empty"), b"").unwrap();
        fs::write(root.join("abc"), b"abc").unwrap();
        let hashed = hash_tree(&root).unwrap();
        assert_eq!(
            hashed[0].sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hashed[1].sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
