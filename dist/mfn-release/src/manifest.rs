//! Canonical release manifest and threshold verification.

use mfn_crypto::{
    decode_schnorr_signature, encode_schnorr_signature, point_from_bytes, schnorr_sign,
    schnorr_verify,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::keys::{KeyError, Keyring, MaintainerKey, Revocation};

/// One published file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    /// Relative file name. No directories that escape the bundle.
    pub name: String,
    /// Lower-case SHA-256 hex.
    pub sha256_hex: String,
    /// File length in bytes.
    pub size: u64,
}

/// The signed document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseManifest {
    /// Git commit the binaries were built from. 40 hex characters.
    pub git: String,
    /// Pinned rustc version.
    pub rustc: String,
    /// Cargo target triple.
    pub target: String,
    /// How many distinct maintainer signatures are required.
    pub threshold: u32,
    /// Files covered by the signature. Stored sorted by name.
    pub artifacts: Vec<Artifact>,
    /// Signatures already attached, in file order.
    pub signatures: Vec<AttachedSignature>,
}

/// One signature line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachedSignature {
    /// Key id in the maintainer keyring.
    pub key_id: String,
    /// Lower-case signature hex (64 bytes).
    pub signature_hex: String,
}

/// Why a manifest or a verification was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    /// The text is not a v1 manifest.
    #[error("manifest is not permawrite-release-manifest v1")]
    BadHeader,
    /// A required field is missing or repeated.
    #[error("bad field {0}")]
    BadField(String),
    /// An artifact name is absolute or contains `..`.
    #[error("artifact name is not a single relative path: {0}")]
    BadName(String),
    /// A digest or signature is not hex of the right length.
    #[error("bad hex for {0}")]
    BadHex(String),
    /// The keyring rejected a key.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// A signature line names a key that is not in the ring.
    #[error("unknown signer {0}")]
    UnknownSigner(String),
    /// The signature bytes do not verify.
    #[error("bad signature from {0}")]
    BadSignature(String),
    /// The same key signed twice.
    #[error("duplicate signature from {0}")]
    DuplicateSigner(String),
    /// A signer is on the revocation list.
    #[error("revoked signer {0}")]
    RevokedSigner(String),
    /// Fewer than `threshold` valid signatures.
    #[error("need {need} signatures, got {got}")]
    BelowThreshold {
        /// Required signatures.
        need: u32,
        /// Signatures that verified.
        got: u32,
    },
}

/// Verification succeeded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyOk {
    /// Key ids that signed, sorted.
    pub signers: Vec<String>,
}

/// SHA-256, lower-case hex, plus the byte length.
pub fn hash_bytes(bytes: &[u8]) -> (String, u64) {
    (hex::encode(Sha256::digest(bytes)), bytes.len() as u64)
}

impl ReleaseManifest {
    /// Build an unsigned manifest. Artifacts are sorted by name.
    pub fn new(
        git: &str,
        rustc: &str,
        target: &str,
        threshold: u32,
        mut artifacts: Vec<Artifact>,
    ) -> Result<Self, ManifestError> {
        let git = git.trim().to_ascii_lowercase();
        if git.len() != 40 || !git.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ManifestError::BadField("git".into()));
        }
        if rustc.is_empty() || rustc.chars().any(char::is_whitespace) {
            return Err(ManifestError::BadField("rustc".into()));
        }
        if target.is_empty()
            || !target
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ManifestError::BadField("target".into()));
        }
        if threshold == 0 {
            return Err(ManifestError::BadField("threshold".into()));
        }
        if artifacts.is_empty() {
            return Err(ManifestError::BadField("artifact".into()));
        }
        for artifact in &mut artifacts {
            artifact.name = check_name(&artifact.name)?;
            artifact.sha256_hex = check_sha(&artifact.sha256_hex)?;
        }
        artifacts.sort_by(|a, b| a.name.cmp(&b.name));
        for pair in artifacts.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(ManifestError::BadField(format!(
                    "duplicate {}",
                    pair[0].name
                )));
            }
        }
        Ok(Self {
            git,
            rustc: rustc.to_string(),
            target: target.to_string(),
            threshold,
            artifacts,
            signatures: Vec::new(),
        })
    }

    /// Bytes every maintainer signs. Does not include signature lines.
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        out.push_str("permawrite-release-manifest v1\n");
        out.push_str("git ");
        out.push_str(&self.git);
        out.push('\n');
        out.push_str("rustc ");
        out.push_str(&self.rustc);
        out.push('\n');
        out.push_str("target ");
        out.push_str(&self.target);
        out.push('\n');
        out.push_str("threshold ");
        out.push_str(&self.threshold.to_string());
        out.push('\n');
        for artifact in &self.artifacts {
            out.push_str("artifact ");
            out.push_str(&artifact.name);
            out.push(' ');
            out.push_str(&artifact.sha256_hex);
            out.push(' ');
            out.push_str(&artifact.size.to_string());
            out.push('\n');
        }
        out
    }

    /// Full file, body then signature lines.
    pub fn render(&self) -> String {
        let mut out = self.canonical();
        for sig in &self.signatures {
            out.push_str("signature ");
            out.push_str(&sig.key_id);
            out.push(' ');
            out.push_str(&sig.signature_hex);
            out.push('\n');
        }
        out
    }

    /// Parse a manifest file.
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        let mut lines = text.lines().filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        });
        let header = lines.next().ok_or(ManifestError::BadHeader)?;
        if header.trim() != "permawrite-release-manifest v1" {
            return Err(ManifestError::BadHeader);
        }
        let mut git = None;
        let mut rustc = None;
        let mut target = None;
        let mut threshold = None;
        let mut artifacts = Vec::new();
        let mut signatures = Vec::new();
        for raw in lines {
            let line = raw.trim();
            let (field, rest) = line
                .split_once(' ')
                .ok_or_else(|| ManifestError::BadField(line.to_string()))?;
            match field {
                "git" => set_once(&mut git, rest, "git")?,
                "rustc" => set_once(&mut rustc, rest, "rustc")?,
                "target" => set_once(&mut target, rest, "target")?,
                "threshold" => {
                    if threshold.is_some() {
                        return Err(ManifestError::BadField("threshold".into()));
                    }
                    threshold = Some(
                        rest.parse::<u32>()
                            .map_err(|_| ManifestError::BadField("threshold".into()))?,
                    );
                }
                "artifact" => artifacts.push(parse_artifact(rest)?),
                "signature" => signatures.push(parse_signature(rest)?),
                other => return Err(ManifestError::BadField(other.into())),
            }
        }
        let mut manifest = Self::new(
            git.ok_or_else(|| ManifestError::BadField("git".into()))?,
            rustc.ok_or_else(|| ManifestError::BadField("rustc".into()))?,
            target.ok_or_else(|| ManifestError::BadField("target".into()))?,
            threshold.ok_or_else(|| ManifestError::BadField("threshold".into()))?,
            artifacts,
        )?;
        manifest.signatures = signatures;
        Ok(manifest)
    }
}

fn set_once<'a>(
    slot: &mut Option<&'a str>,
    value: &'a str,
    name: &str,
) -> Result<(), ManifestError> {
    if slot.is_some() || value.is_empty() {
        return Err(ManifestError::BadField(name.into()));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_artifact(rest: &str) -> Result<Artifact, ManifestError> {
    let mut parts = rest.split(' ');
    let name = parts
        .next()
        .ok_or_else(|| ManifestError::BadField("artifact".into()))?;
    let sha = parts
        .next()
        .ok_or_else(|| ManifestError::BadField("artifact".into()))?;
    let size = parts
        .next()
        .ok_or_else(|| ManifestError::BadField("artifact".into()))?;
    if parts.next().is_some() {
        return Err(ManifestError::BadField("artifact".into()));
    }
    let size = size
        .parse::<u64>()
        .map_err(|_| ManifestError::BadField("artifact size".into()))?;
    Ok(Artifact {
        name: name.to_string(),
        sha256_hex: sha.to_string(),
        size,
    })
}

fn parse_signature(rest: &str) -> Result<AttachedSignature, ManifestError> {
    let (key_id, sig) = rest
        .split_once(' ')
        .ok_or_else(|| ManifestError::BadField("signature".into()))?;
    if sig.len() != 128 || !sig.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ManifestError::BadHex("signature".into()));
    }
    Ok(AttachedSignature {
        key_id: key_id.to_string(),
        signature_hex: sig.to_ascii_lowercase(),
    })
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

fn check_sha(text: &str) -> Result<String, ManifestError> {
    if text.len() != 64 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ManifestError::BadHex("sha256".into()));
    }
    Ok(text.to_ascii_lowercase())
}

/// Append this maintainer's signature. The same id cannot sign twice.
pub fn sign_manifest(
    manifest: &mut ReleaseManifest,
    key: &MaintainerKey,
) -> Result<(), ManifestError> {
    if manifest.signatures.iter().any(|s| s.key_id == key.id) {
        return Err(ManifestError::DuplicateSigner(key.id.clone()));
    }
    let signature = schnorr_sign(manifest.canonical().as_bytes(), key.signing());
    manifest.signatures.push(AttachedSignature {
        key_id: key.id.clone(),
        signature_hex: hex::encode(encode_schnorr_signature(&signature)),
    });
    Ok(())
}

/// Check every signature and the threshold.
pub fn verify_manifest(
    manifest: &ReleaseManifest,
    keyring: &Keyring,
    revoked: &Revocation,
) -> Result<VerifyOk, ManifestError> {
    let body = manifest.canonical();
    let mut seen = Vec::new();
    for attached in &manifest.signatures {
        if seen.iter().any(|id: &String| id == &attached.key_id) {
            return Err(ManifestError::DuplicateSigner(attached.key_id.clone()));
        }
        let public = keyring
            .get(&attached.key_id)
            .ok_or_else(|| ManifestError::UnknownSigner(attached.key_id.clone()))?;
        if revoked.contains(&public) {
            return Err(ManifestError::RevokedSigner(attached.key_id.clone()));
        }
        let point =
            point_from_bytes(&public).map_err(|_| ManifestError::BadHex("public".into()))?;
        let bytes = hex::decode(&attached.signature_hex)
            .map_err(|_| ManifestError::BadHex("signature".into()))?;
        if bytes.len() != 64 {
            return Err(ManifestError::BadHex("signature".into()));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&bytes);
        let signature = decode_schnorr_signature(&sig_bytes)
            .map_err(|_| ManifestError::BadHex("signature".into()))?;
        if !schnorr_verify(body.as_bytes(), &signature, &point) {
            return Err(ManifestError::BadSignature(attached.key_id.clone()));
        }
        seen.push(attached.key_id.clone());
    }
    if (seen.len() as u32) < manifest.threshold {
        return Err(ManifestError::BelowThreshold {
            need: manifest.threshold,
            got: seen.len() as u32,
        });
    }
    seen.sort();
    Ok(VerifyOk { signers: seen })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{key_from_seed, Keyring};

    fn artifact(name: &str, byte: u8) -> Artifact {
        let (sha, size) = hash_bytes(&[byte]);
        Artifact {
            name: name.to_string(),
            sha256_hex: sha,
            size,
        }
    }

    fn sample(threshold: u32) -> ReleaseManifest {
        ReleaseManifest::new(
            "0123456789abcdef0123456789abcdef01234567",
            "1.83.0",
            "x86_64-unknown-linux-gnu",
            threshold,
            vec![artifact("mfnd", 1), artifact("mfn-cli", 2)],
        )
        .unwrap()
    }

    fn ring(keys: &[&MaintainerKey]) -> Keyring {
        let text: String = keys.iter().map(|k| k.render_public()).collect();
        Keyring::parse(&text).unwrap()
    }

    #[test]
    fn two_of_three_verifies_and_one_does_not() {
        let alice = key_from_seed("alice", &[1u8; 32]).unwrap();
        let bob = key_from_seed("bob", &[2u8; 32]).unwrap();
        let carol = key_from_seed("carol", &[3u8; 32]).unwrap();
        let keys = ring(&[&alice, &bob, &carol]);
        let mut manifest = sample(2);
        sign_manifest(&mut manifest, &alice).unwrap();
        assert!(matches!(
            verify_manifest(&manifest, &keys, &Revocation::default()),
            Err(ManifestError::BelowThreshold { need: 2, got: 1 })
        ));
        sign_manifest(&mut manifest, &bob).unwrap();
        let ok = verify_manifest(&manifest, &keys, &Revocation::default()).unwrap();
        assert_eq!(ok.signers, vec!["alice".to_string(), "bob".to_string()]);
    }

    #[test]
    fn tampered_artifact_breaks_every_signature() {
        let alice = key_from_seed("alice", &[4u8; 32]).unwrap();
        let bob = key_from_seed("bob", &[5u8; 32]).unwrap();
        let keys = ring(&[&alice, &bob]);
        let mut manifest = sample(2);
        sign_manifest(&mut manifest, &alice).unwrap();
        sign_manifest(&mut manifest, &bob).unwrap();
        let text = manifest.render();
        let again = ReleaseManifest::parse(&text).unwrap();
        assert_eq!(again.canonical(), manifest.canonical());
        let mut tampered = again;
        tampered.artifacts[0].size += 1;
        assert!(matches!(
            verify_manifest(&tampered, &keys, &Revocation::default()),
            Err(ManifestError::BadSignature(_))
        ));
    }

    #[test]
    fn revoked_and_unknown_keys_fail_closed() {
        let alice = key_from_seed("alice", &[6u8; 32]).unwrap();
        let bob = key_from_seed("bob", &[7u8; 32]).unwrap();
        let eve = key_from_seed("eve", &[8u8; 32]).unwrap();
        let keys = ring(&[&alice, &bob]);
        let mut manifest = sample(1);
        sign_manifest(&mut manifest, &eve).unwrap();
        assert!(matches!(
            verify_manifest(&manifest, &keys, &Revocation::default()),
            Err(ManifestError::UnknownSigner(_))
        ));
        let mut honest = sample(1);
        sign_manifest(&mut honest, &alice).unwrap();
        let revoked = Revocation::parse(&alice.public_hex()).unwrap();
        assert!(matches!(
            verify_manifest(&honest, &keys, &revoked),
            Err(ManifestError::RevokedSigner(_))
        ));
    }

    #[test]
    fn duplicate_signature_and_path_escape_are_rejected() {
        let alice = key_from_seed("alice", &[9u8; 32]).unwrap();
        let mut manifest = sample(1);
        sign_manifest(&mut manifest, &alice).unwrap();
        assert!(matches!(
            sign_manifest(&mut manifest, &alice),
            Err(ManifestError::DuplicateSigner(_))
        ));
        let err = ReleaseManifest::new(
            "0123456789abcdef0123456789abcdef01234567",
            "1.83.0",
            "x86_64-unknown-linux-gnu",
            1,
            vec![artifact("../mfnd", 1)],
        );
        assert!(matches!(err, Err(ManifestError::BadName(_))));
    }

    #[test]
    fn canonical_form_is_sorted_and_stable() {
        let manifest = ReleaseManifest::new(
            "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
            "1.83.0",
            "x86_64-unknown-linux-gnu",
            1,
            vec![artifact("b", 2), artifact("a", 1)],
        )
        .unwrap();
        let text = manifest.canonical();
        let parsed = ReleaseManifest::parse(&text).unwrap();
        assert_eq!(parsed.git, manifest.git);
        assert!(text.find("\nartifact a ").unwrap() < text.find("\nartifact b ").unwrap());
        assert_eq!(parsed.canonical(), text);
    }
}
