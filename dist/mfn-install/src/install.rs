//! Verify a signed file list, then copy.

use std::fs;
use std::path::Path;

use mfn_crypto::{
    decode_schnorr_signature, encode_schnorr_signature, point_to_bytes, schnorr_sign,
    schnorr_verify, SchnorrKeypair,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// One file to install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallFile {
    /// File name in the destination. A single path segment.
    pub name: String,
    /// Bytes that will be written.
    pub bytes: Vec<u8>,
}

/// A signed list of files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Files, sorted by name in the canonical form.
    pub files: Vec<InstallFile>,
    /// Public key that signed the list.
    pub signer: [u8; 32],
    /// Signature over [`Plan::canonical_hashes`].
    pub signature: [u8; 64],
}

/// Why an install did not happen.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InstallError {
    /// A file name is not a single segment.
    #[error("bad file name: {0}")]
    BadName(String),
    /// The signature does not match the hash list.
    #[error("signature does not match the file list")]
    BadSignature,
    /// A destination file already has different bytes.
    #[error("destination already has a different {0}")]
    Conflict(String),
    /// The plan has no files.
    #[error("nothing to install")]
    Empty,
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(String),
}

impl Plan {
    /// Hash list that is signed. Names are sorted.
    pub fn canonical_hashes(&self) -> Result<String, InstallError> {
        let mut rows: Vec<(&str, String, usize)> = Vec::new();
        for file in &self.files {
            let name = check_name(&file.name)?;
            let digest = hex::encode(Sha256::digest(&file.bytes));
            rows.push((name, digest, file.bytes.len()));
        }
        if rows.is_empty() {
            return Err(InstallError::Empty);
        }
        rows.sort_by(|a, b| a.0.cmp(b.0));
        for pair in rows.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(InstallError::BadName(pair[0].0.to_string()));
            }
        }
        let mut out = String::from("permawrite-install v1\n");
        for (name, digest, len) in rows {
            out.push_str("file ");
            out.push_str(name);
            out.push(' ');
            out.push_str(&digest);
            out.push(' ');
            out.push_str(&len.to_string());
            out.push('\n');
        }
        Ok(out)
    }
}

/// Sign `files` with `key`.
pub fn sign_plan(files: Vec<InstallFile>, key: &SchnorrKeypair) -> Result<Plan, InstallError> {
    let mut plan = Plan {
        files,
        signer: point_to_bytes(&key.pub_key),
        signature: [0u8; 64],
    };
    let body = plan.canonical_hashes()?;
    plan.signature = encode_schnorr_signature(&schnorr_sign(body.as_bytes(), key));
    Ok(plan)
}

/// Copy `plan` into `dest` only when the signature matches `expected_signer`.
pub fn install(dest: &Path, plan: &Plan, expected_signer: &[u8; 32]) -> Result<(), InstallError> {
    if &plan.signer != expected_signer {
        return Err(InstallError::BadSignature);
    }
    let body = plan.canonical_hashes()?;
    let point =
        mfn_crypto::point_from_bytes(&plan.signer).map_err(|_| InstallError::BadSignature)?;
    let sig = decode_schnorr_signature(&plan.signature).map_err(|_| InstallError::BadSignature)?;
    if !schnorr_verify(body.as_bytes(), &sig, &point) {
        return Err(InstallError::BadSignature);
    }
    fs::create_dir_all(dest).map_err(|e| InstallError::Io(e.to_string()))?;
    for file in &plan.files {
        let target = dest.join(check_name(&file.name)?);
        if target.is_file() {
            let existing = fs::read(&target).map_err(|e| InstallError::Io(e.to_string()))?;
            if existing != file.bytes {
                return Err(InstallError::Conflict(file.name.clone()));
            }
        }
    }
    let staging = dest.join(format!(".mfn-install-{}", std::process::id()));
    if staging.exists() {
        fs::remove_dir_all(&staging).map_err(|e| InstallError::Io(e.to_string()))?;
    }
    fs::create_dir(&staging).map_err(|e| InstallError::Io(e.to_string()))?;
    for file in &plan.files {
        let name = check_name(&file.name)?;
        fs::write(staging.join(name), &file.bytes).map_err(|e| InstallError::Io(e.to_string()))?;
    }
    for file in &plan.files {
        let name = check_name(&file.name)?;
        let target = dest.join(name);
        if target.is_file() {
            continue;
        }
        fs::rename(staging.join(name), &target).map_err(|e| InstallError::Io(e.to_string()))?;
    }
    let _ = fs::remove_dir_all(&staging);
    Ok(())
}

fn check_name(name: &str) -> Result<&str, InstallError> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.starts_with('.')
    {
        return Err(InstallError::BadName(name.to_string()));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfn_crypto::schnorr_keygen;
    use std::path::PathBuf;

    fn temp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mfn-install-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn signed_files_land_and_a_second_run_is_a_no_op() {
        let key = schnorr_keygen();
        let plan = sign_plan(
            vec![
                InstallFile {
                    name: "mfnd".into(),
                    bytes: b"bin-mfnd".to_vec(),
                },
                InstallFile {
                    name: "mfn-cli".into(),
                    bytes: b"bin-cli".to_vec(),
                },
            ],
            &key,
        )
        .unwrap();
        let dest = temp();
        install(&dest, &plan, &plan.signer).unwrap();
        assert_eq!(fs::read(dest.join("mfnd")).unwrap(), b"bin-mfnd");
        assert_eq!(fs::read(dest.join("mfn-cli")).unwrap(), b"bin-cli");
        install(&dest, &plan, &plan.signer).unwrap();
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn bad_signature_and_bad_name_do_not_write() {
        let key = schnorr_keygen();
        let mut plan = sign_plan(
            vec![InstallFile {
                name: "mfnd".into(),
                bytes: b"good".to_vec(),
            }],
            &key,
        )
        .unwrap();
        plan.files[0].bytes = b"evil".to_vec();
        let dest = temp();
        assert_eq!(
            install(&dest, &plan, &plan.signer),
            Err(InstallError::BadSignature)
        );
        assert!(!dest.join("mfnd").exists());
        let other = schnorr_keygen();
        let plan = sign_plan(
            vec![InstallFile {
                name: "mfnd".into(),
                bytes: b"good".to_vec(),
            }],
            &key,
        )
        .unwrap();
        assert_eq!(
            install(&dest, &plan, &point_to_bytes(&other.pub_key)),
            Err(InstallError::BadSignature)
        );
        assert!(sign_plan(
            vec![InstallFile {
                name: "../mfnd".into(),
                bytes: b"x".to_vec(),
            }],
            &key,
        )
        .is_err());
        let _ = fs::remove_dir_all(&dest);
    }

    #[test]
    fn a_different_existing_file_is_left_alone() {
        let key = schnorr_keygen();
        let plan = sign_plan(
            vec![InstallFile {
                name: "mfnd".into(),
                bytes: b"new".to_vec(),
            }],
            &key,
        )
        .unwrap();
        let dest = temp();
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("mfnd"), b"old").unwrap();
        assert_eq!(
            install(&dest, &plan, &plan.signer),
            Err(InstallError::Conflict("mfnd".into()))
        );
        assert_eq!(fs::read(dest.join("mfnd")).unwrap(), b"old");
        let _ = fs::remove_dir_all(&dest);
    }
}
