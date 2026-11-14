//! Signed release manifests.
//!
//! A release is a list of file digests. Maintainers sign that list with
//! the same Schnorr scheme the chain already uses for application
//! messages. Verification accepts the list only when at least
//! `threshold` distinct keyring keys produce a valid signature.
//!
//! This is not a consensus rule. Path A and F-A are unchanged.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use mfn_crypto::{
    bytes_to_scalar, decode_schnorr_signature, encode_schnorr_signature, point_from_bytes,
    point_to_bytes, scalar_to_bytes, schnorr_sign, schnorr_verify, SchnorrKeypair,
    SCHNORR_SIGNATURE_BYTES,
};
use serde::{Deserialize, Serialize};

const DOMAIN: &str = "MFBN-1/release-manifest-v1";

/// Why a manifest, keyring, or signature set was refused.
#[derive(Debug)]
pub enum ReleaseError {
    /// Threshold was zero or larger than the keyring.
    Threshold,
    /// Two keys share a name or a public key.
    Duplicate,
    /// Maintainer name is empty or has characters outside the allow-list.
    BadName,
    /// A packaged path is absolute, empty, or contains `..`.
    BadPath,
    /// A digest is not 64 hex characters.
    BadDigest,
    /// A signature names a key the keyring does not have.
    UnknownSigner,
    /// Fewer than `threshold` valid signatures.
    Insufficient {
        /// How many distinct valid signatures were present.
        have: usize,
        /// How many the keyring requires.
        need: usize,
    },
    /// Signature bytes are the wrong length or do not verify.
    BadSignature,
    /// A scalar was zero, so it is not a signing key.
    ZeroKey,
    /// JSON or hex could not be read.
    Format(String),
    /// A file on disk did not match the manifest.
    FileMismatch {
        /// Manifest path.
        name: String,
    },
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Threshold => write!(f, "threshold must be at least 1 and at most the key count"),
            Self::Duplicate => write!(f, "duplicate maintainer name or public key"),
            Self::BadName => write!(f, "maintainer name must be 1-64 of [A-Za-z0-9._-]"),
            Self::BadPath => write!(f, "packaged path escapes the tree"),
            Self::BadDigest => write!(f, "digest must be 64 hex characters"),
            Self::UnknownSigner => write!(f, "signature names a key that is not in the keyring"),
            Self::Insufficient { have, need } => {
                write!(f, "need {need} maintainer signatures, have {have}")
            }
            Self::BadSignature => write!(f, "signature does not verify"),
            Self::ZeroKey => write!(f, "signing key is zero"),
            Self::Format(msg) => write!(f, "{msg}"),
            Self::FileMismatch { name } => write!(f, "file does not match manifest: {name}"),
        }
    }
}

impl std::error::Error for ReleaseError {}

/// One file the release promises.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseFile {
    /// Relative path. No spaces, no `..`.
    pub name: String,
    /// Lowercase hex SHA-256.
    pub sha256: String,
    /// Exact byte length.
    pub size: u64,
}

/// The bytes maintainers sign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    /// Release version string, such as `0.1.0`. Not a header version.
    pub version: String,
    /// Rust target triple or `source`.
    pub target: String,
    /// Files, stored sorted by name.
    pub files: Vec<ReleaseFile>,
}

/// A public maintainer key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    /// Stable name (`alice`, `release-2`).
    pub name: String,
    /// Compressed Edwards Y, 32 bytes hex.
    pub public_hex: String,
}

/// Who must sign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyring {
    /// Minimum number of distinct valid signatures.
    pub threshold: usize,
    /// Allowed signers.
    pub keys: Vec<PublicKey>,
}

/// One signature over [`ReleaseManifest::canonical`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintainerSignature {
    /// Keyring name.
    pub name: String,
    /// Hex of the 64-byte Schnorr signature.
    pub signature_hex: String,
}

/// The set shipped next to a manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureSet {
    /// One entry per signer.
    pub signatures: Vec<MaintainerSignature>,
}

/// Secret half of a maintainer key. The hex scalar is wiped on drop.
#[derive(Clone, Serialize, Deserialize)]
pub struct MaintainerSecret {
    /// Same name as the public key.
    pub name: String,
    /// Hex scalar. Not a public value.
    pub secret_hex: String,
}

impl Drop for MaintainerSecret {
    fn drop(&mut self) {
        wipe(&mut self.secret_hex);
    }
}

fn wipe(text: &mut String) {
    let mut bytes = std::mem::take(text).into_bytes();
    for byte in &mut bytes {
        *byte = 0;
    }
    std::mem::drop(bytes);
}

impl std::fmt::Debug for MaintainerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaintainerSecret")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
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

fn digest_ok(hex_digest: &str) -> bool {
    hex_digest.len() == 64 && hex_digest.bytes().all(|b| b.is_ascii_hexdigit())
}

fn decode_hex_32(text: &str) -> Result<[u8; 32], ReleaseError> {
    let bytes = hex::decode(text).map_err(|_| ReleaseError::Format("hex".into()))?;
    if bytes.len() != 32 {
        return Err(ReleaseError::BadDigest);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

impl ReleaseManifest {
    /// Sort files and refuse a bad name, path, or digest.
    pub fn normalize(mut self) -> Result<Self, ReleaseError> {
        if self.version.is_empty() || self.version.len() > 64 || !name_ok(&self.version) {
            return Err(ReleaseError::BadName);
        }
        if self.target.is_empty() || self.target.len() > 64 || !name_ok(&self.target) {
            return Err(ReleaseError::BadName);
        }
        self.files.sort_by(|a, b| a.name.cmp(&b.name));
        let mut seen = BTreeSet::new();
        for file in &mut self.files {
            if !path_ok(&file.name) || !seen.insert(file.name.clone()) {
                return Err(ReleaseError::BadPath);
            }
            file.sha256.make_ascii_lowercase();
            if !digest_ok(&file.sha256) {
                return Err(ReleaseError::BadDigest);
            }
        }
        Ok(self)
    }

    /// Bytes every maintainer signs. Stable for the same manifest.
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        out.push_str(DOMAIN);
        out.push('\n');
        out.push_str("version=");
        out.push_str(&self.version);
        out.push('\n');
        out.push_str("target=");
        out.push_str(&self.target);
        out.push('\n');
        for file in &self.files {
            out.push_str("file ");
            out.push_str(&file.sha256);
            out.push(' ');
            out.push_str(&file.size.to_string());
            out.push(' ');
            out.push_str(&file.name);
            out.push('\n');
        }
        out
    }
}

impl Keyring {
    /// Refuse an empty threshold, a duplicate, or a public key that is not a point.
    pub fn validate(&self) -> Result<(), ReleaseError> {
        if self.threshold == 0 || self.threshold > self.keys.len() {
            return Err(ReleaseError::Threshold);
        }
        let mut names = BTreeSet::new();
        let mut pubs = BTreeSet::new();
        for key in &self.keys {
            if !name_ok(&key.name) {
                return Err(ReleaseError::BadName);
            }
            let raw = decode_hex_32(&key.public_hex)?;
            let point = point_from_bytes(&raw).map_err(|_| ReleaseError::BadSignature)?;
            let bytes = point_to_bytes(&point);
            if bytes[0] == 1 && bytes[1..].iter().all(|b| *b == 0) {
                return Err(ReleaseError::ZeroKey);
            }
            if !names.insert(key.name.clone()) || !pubs.insert(point_to_bytes(&point)) {
                return Err(ReleaseError::Duplicate);
            }
        }
        Ok(())
    }
}

impl MaintainerSecret {
    /// Build a secret from a fresh keypair.
    pub fn generate(name: &str) -> Result<Self, ReleaseError> {
        if !name_ok(name) {
            return Err(ReleaseError::BadName);
        }
        let kp = mfn_crypto::schnorr_keygen();
        Ok(Self {
            name: name.to_string(),
            secret_hex: hex::encode(scalar_to_bytes(&kp.priv_key)),
        })
    }

    /// Public key derived from the scalar. The file's claimed public key is not trusted.
    pub fn public_key(&self) -> Result<PublicKey, ReleaseError> {
        let kp = self.keypair()?;
        Ok(PublicKey {
            name: self.name.clone(),
            public_hex: hex::encode(point_to_bytes(&kp.pub_key)),
        })
    }

    fn keypair(&self) -> Result<SchnorrKeypair, ReleaseError> {
        if !name_ok(&self.name) {
            return Err(ReleaseError::BadName);
        }
        let raw = decode_hex_32(&self.secret_hex)?;
        let priv_key = bytes_to_scalar(&raw);
        if scalar_to_bytes(&priv_key) == [0u8; 32] {
            return Err(ReleaseError::ZeroKey);
        }
        let pub_key = mfn_crypto::generator_g() * priv_key;
        Ok(SchnorrKeypair { priv_key, pub_key })
    }

    /// Sign the manifest. The signature covers [`ReleaseManifest::canonical`].
    pub fn sign(&self, manifest: &ReleaseManifest) -> Result<MaintainerSignature, ReleaseError> {
        let kp = self.keypair()?;
        let sig = schnorr_sign(manifest.canonical().as_bytes(), &kp);
        Ok(MaintainerSignature {
            name: self.name.clone(),
            signature_hex: hex::encode(encode_schnorr_signature(&sig)),
        })
    }
}

/// Check signatures against the keyring. Unknown names and bad signatures fail.
pub fn verify(
    manifest: &ReleaseManifest,
    keyring: &Keyring,
    sigs: &SignatureSet,
) -> Result<(), ReleaseError> {
    keyring.validate()?;
    let message = manifest.canonical();
    let mut seen = BTreeSet::new();
    let mut valid = 0usize;
    for sig in &sigs.signatures {
        if !seen.insert(sig.name.clone()) {
            return Err(ReleaseError::Duplicate);
        }
        let Some(key) = keyring.keys.iter().find(|k| k.name == sig.name) else {
            return Err(ReleaseError::UnknownSigner);
        };
        let raw_pub = decode_hex_32(&key.public_hex)?;
        let point = point_from_bytes(&raw_pub).map_err(|_| ReleaseError::BadSignature)?;
        let sig_bytes = hex::decode(&sig.signature_hex).map_err(|_| ReleaseError::BadSignature)?;
        if sig_bytes.len() != SCHNORR_SIGNATURE_BYTES {
            return Err(ReleaseError::BadSignature);
        }
        let mut arr = [0u8; SCHNORR_SIGNATURE_BYTES];
        arr.copy_from_slice(&sig_bytes);
        let decoded = decode_schnorr_signature(&arr).map_err(|_| ReleaseError::BadSignature)?;
        if !schnorr_verify(message.as_bytes(), &decoded, &point) {
            return Err(ReleaseError::BadSignature);
        }
        valid += 1;
    }
    if valid < keyring.threshold {
        return Err(ReleaseError::Insufficient {
            have: valid,
            need: keyring.threshold,
        });
    }
    Ok(())
}

/// Hash files named by the manifest and refuse a size or digest mismatch.
/// Symlinks are refused. Paths are resolved under `root` and must stay there.
pub fn verify_files(root: &Path, manifest: &ReleaseManifest) -> Result<(), ReleaseError> {
    let root = root
        .canonicalize()
        .map_err(|e| ReleaseError::Format(e.to_string()))?;
    for file in &manifest.files {
        if !path_ok(&file.name) {
            return Err(ReleaseError::BadPath);
        }
        let path = root.join(&file.name);
        let canon = path
            .canonicalize()
            .map_err(|_| ReleaseError::FileMismatch {
                name: file.name.clone(),
            })?;
        if !canon.starts_with(&root) {
            return Err(ReleaseError::BadPath);
        }
        let meta = fs::symlink_metadata(&path).map_err(|_| ReleaseError::FileMismatch {
            name: file.name.clone(),
        })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(ReleaseError::FileMismatch {
                name: file.name.clone(),
            });
        }
        let bytes = fs::read(&path).map_err(|_| ReleaseError::FileMismatch {
            name: file.name.clone(),
        })?;
        if bytes.len() as u64 != file.size {
            return Err(ReleaseError::FileMismatch {
                name: file.name.clone(),
            });
        }
        let sha = sha256(&bytes);
        if sha != file.sha256 || bytes.len() as u64 != file.size {
            return Err(ReleaseError::FileMismatch {
                name: file.name.clone(),
            });
        }
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// SHA-256 helper used when building a manifest from a directory.
pub fn hash_file_bytes(bytes: &[u8]) -> String {
    sha256(bytes)
}

/// Read JSON.
pub fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ReleaseError> {
    serde_json::from_str(text).map_err(|e| ReleaseError::Format(e.to_string()))
}

/// Write JSON with a trailing newline.
pub fn to_json<T: serde::Serialize>(value: &T) -> Result<String, ReleaseError> {
    let mut text =
        serde_json::to_string_pretty(value).map_err(|e| ReleaseError::Format(e.to_string()))?;
    text.push('\n');
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ReleaseManifest {
        ReleaseManifest {
            version: "0.1.0".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            files: vec![
                ReleaseFile {
                    name: "mfnd".into(),
                    sha256: "ab".repeat(32),
                    size: 3,
                },
                ReleaseFile {
                    name: "mfn-cli".into(),
                    sha256: "cd".repeat(32),
                    size: 4,
                },
            ],
        }
        .normalize()
        .unwrap()
    }

    fn ring(names: &[&str], threshold: usize) -> (Vec<MaintainerSecret>, Keyring) {
        let secrets: Vec<_> = names
            .iter()
            .map(|n| MaintainerSecret::generate(n).unwrap())
            .collect();
        let keys = secrets.iter().map(|s| s.public_key().unwrap()).collect();
        let keyring = Keyring { threshold, keys };
        keyring.validate().unwrap();
        (secrets, keyring)
    }

    #[test]
    fn two_of_three_accepts_and_one_does_not() {
        let m = manifest();
        let (secrets, keyring) = ring(&["alice", "bob", "cara"], 2);
        let sigs = SignatureSet {
            signatures: vec![secrets[0].sign(&m).unwrap(), secrets[1].sign(&m).unwrap()],
        };
        assert!(verify(&m, &keyring, &sigs).is_ok());
        let one = SignatureSet {
            signatures: vec![secrets[0].sign(&m).unwrap()],
        };
        assert!(matches!(
            verify(&m, &keyring, &one),
            Err(ReleaseError::Insufficient { have: 1, need: 2 })
        ));
    }

    #[test]
    fn tampered_digest_breaks_every_signature() {
        let m = manifest();
        let (secrets, keyring) = ring(&["alice", "bob"], 2);
        let sigs = SignatureSet {
            signatures: vec![secrets[0].sign(&m).unwrap(), secrets[1].sign(&m).unwrap()],
        };
        let mut bad = m.clone();
        bad.files[0].sha256 = "ff".repeat(32);
        assert!(matches!(
            verify(&bad, &keyring, &sigs),
            Err(ReleaseError::BadSignature)
        ));
    }

    #[test]
    fn unknown_signer_and_duplicate_key_are_refused() {
        let m = manifest();
        let (secrets, keyring) = ring(&["alice", "bob"], 1);
        let outsider = MaintainerSecret::generate("mallory").unwrap();
        let sigs = SignatureSet {
            signatures: vec![outsider.sign(&m).unwrap()],
        };
        assert!(matches!(
            verify(&m, &keyring, &sigs),
            Err(ReleaseError::UnknownSigner)
        ));
        let dup = Keyring {
            threshold: 1,
            keys: vec![
                secrets[0].public_key().unwrap(),
                secrets[0].public_key().unwrap(),
            ],
        };
        assert!(matches!(dup.validate(), Err(ReleaseError::Duplicate)));
        assert!(matches!(
            Keyring {
                threshold: 0,
                keys: keyring.keys.clone()
            }
            .validate(),
            Err(ReleaseError::Threshold)
        ));
    }

    #[test]
    fn canonical_form_is_sorted_and_stable() {
        let m = manifest();
        let again = m.canonical();
        assert_eq!(m.canonical(), again);
        assert!(again.starts_with("MFBN-1/release-manifest-v1\n"));
        assert!(again.find("mfn-cli").unwrap() < again.find("mfnd").unwrap());
        let mut evil = m.clone();
        evil.files[0].name = "../mfnd".into();
        assert!(evil.normalize().is_err());
    }

    #[test]
    fn directory_must_match_the_manifest_bytes() {
        let dir = std::env::temp_dir().join(format!(
            "mfn-release-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("mfnd"), b"abc").unwrap();
        let good = ReleaseManifest {
            version: "0.1.0".into(),
            target: "source".into(),
            files: vec![ReleaseFile {
                name: "mfnd".into(),
                sha256: hash_file_bytes(b"abc"),
                size: 3,
            }],
        }
        .normalize()
        .unwrap();
        assert!(verify_files(&dir, &good).is_ok());
        let mut bad = good.clone();
        bad.files[0].sha256 = "ab".repeat(32);
        assert!(verify_files(&dir, &bad).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_message_signature_does_not_verify() {
        let m = manifest();
        let (secrets, keyring) = ring(&["alice"], 1);
        let mut other = m.clone();
        other.version = "9.9.9".into();
        let sigs = SignatureSet {
            signatures: vec![secrets[0].sign(&other).unwrap()],
        };
        assert!(verify(&m, &keyring, &sigs).is_err());
    }
}
