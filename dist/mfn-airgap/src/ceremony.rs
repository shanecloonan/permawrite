//! Request, sign, and verify. The seed is an argument, never a field of the output.

use std::fs;
use std::path::Path;

use mfn_crypto::{
    decode_schnorr_signature, encode_schnorr_signature, point_from_bytes, point_to_bytes,
    schnorr_sign, schnorr_verify, SchnorrKeypair,
};
use mfn_wallet::wallet_from_seed;
use thiserror::Error;

/// Why a ceremony step failed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AirgapError {
    /// The request is not the v1 text form.
    #[error("bad payment request")]
    BadRequest,
    /// A label or a digest is not the shape the ceremony allows.
    #[error("bad field {0}")]
    BadField(String),
    /// The signature does not match the pinned spend key.
    #[error("signature does not match the spend key")]
    BadSignature,
    /// The file names a different spend key than the one that was shown in person.
    #[error("spend key does not match the key that was shown in person")]
    WrongKey,
    /// The seed file can be read by someone other than the owner.
    #[error("seed file must not be group or world readable")]
    SeedReadable,
    /// The seed file is not `seed <64 hex>`.
    #[error("seed file is not a 32-byte hex seed")]
    BadSeed,
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(String),
}

/// What the online machine wants the offline machine to authorize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRequest {
    /// Fee in base units.
    pub fee: u64,
    /// `(label, amount)` pairs. Labels are sorted in the canonical form.
    pub outputs: Vec<(String, u64)>,
    /// SHA-256 of the transaction bytes the offline machine built, or `-` if none.
    pub payload_sha256: String,
}

/// A request plus the spend-key signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRequest {
    /// The authorized request.
    pub request: PaymentRequest,
    /// Compressed spend public key.
    pub spend_pub: [u8; 32],
    /// Schnorr signature over the canonical request.
    pub signature: [u8; 64],
}

impl PaymentRequest {
    /// Canonical bytes that are signed.
    pub fn canonical(&self) -> Result<String, AirgapError> {
        if self.payload_sha256 != "-"
            && (self.payload_sha256.len() != 64
                || !self.payload_sha256.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(AirgapError::BadField("payload_sha256".into()));
        }
        let mut outputs = self.outputs.clone();
        if outputs.is_empty() {
            return Err(AirgapError::BadField("output".into()));
        }
        for (label, _) in &outputs {
            if label.is_empty()
                || label.len() > 64
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
            {
                return Err(AirgapError::BadField("output".into()));
            }
        }
        outputs.sort_by(|a, b| a.0.cmp(&b.0));
        for pair in outputs.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(AirgapError::BadField("duplicate output".into()));
            }
        }
        let mut out = format!("permawrite-airgap-request v1\nfee {}\n", self.fee);
        for (label, amount) in &outputs {
            out.push_str("output ");
            out.push_str(label);
            out.push(' ');
            out.push_str(&amount.to_string());
            out.push('\n');
        }
        out.push_str("payload_sha256 ");
        out.push_str(&self.payload_sha256.to_ascii_lowercase());
        out.push('\n');
        Ok(out)
    }

    /// Parse a canonical request with no signature lines.
    pub fn parse(text: &str) -> Result<Self, AirgapError> {
        parse_request(text)
    }
}

impl SignedRequest {
    /// Text the online machine receives. No seed.
    pub fn render(&self) -> Result<String, AirgapError> {
        let mut out = self.request.canonical()?;
        out.push_str("spend_pub ");
        out.push_str(&hex::encode(self.spend_pub));
        out.push('\n');
        out.push_str("signature ");
        out.push_str(&hex::encode(self.signature));
        out.push('\n');
        Ok(out)
    }

    /// Parse [`Self::render`].
    pub fn parse(text: &str) -> Result<Self, AirgapError> {
        let mut spend_pub = None;
        let mut signature = None;
        let mut body = String::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("spend_pub ") {
                spend_pub = Some(parse_hex32(rest)?);
            } else if let Some(rest) = line.strip_prefix("signature ") {
                signature = Some(parse_hex64(rest)?);
            } else {
                body.push_str(line);
                body.push('\n');
            }
        }
        Ok(Self {
            request: PaymentRequest::parse(&body)?,
            spend_pub: spend_pub.ok_or(AirgapError::BadRequest)?,
            signature: signature.ok_or(AirgapError::BadRequest)?,
        })
    }
}

/// Public keys the online machine may keep. The seed is not included.
pub fn watch_only(seed: &[u8; 32]) -> String {
    let keys = wallet_from_seed(seed);
    format!(
        "view_pub {}\nspend_pub {}\n",
        hex::encode(point_to_bytes(&keys.view_pub())),
        hex::encode(point_to_bytes(&keys.spend_pub()))
    )
}

/// Sign `request` with the wallet spend key derived from `seed`.
pub fn sign_request(
    seed: &[u8; 32],
    request: &PaymentRequest,
) -> Result<SignedRequest, AirgapError> {
    let keys = wallet_from_seed(seed);
    let kp = SchnorrKeypair {
        priv_key: keys.inner().spend_priv,
        pub_key: keys.spend_pub(),
    };
    let body = request.canonical()?;
    let signature = schnorr_sign(body.as_bytes(), &kp);
    Ok(SignedRequest {
        request: request.clone(),
        spend_pub: point_to_bytes(&keys.spend_pub()),
        signature: encode_schnorr_signature(&signature),
    })
}

/// Check `signed` against the spend key that was shown in person.
pub fn verify_signed(signed: &SignedRequest, expected_spend: &[u8; 32]) -> Result<(), AirgapError> {
    if &signed.spend_pub != expected_spend {
        return Err(AirgapError::WrongKey);
    }
    let point = point_from_bytes(&signed.spend_pub).map_err(|_| AirgapError::BadSignature)?;
    let sig = decode_schnorr_signature(&signed.signature).map_err(|_| AirgapError::BadSignature)?;
    let body = signed.request.canonical()?;
    if !schnorr_verify(body.as_bytes(), &sig, &point) {
        return Err(AirgapError::BadSignature);
    }
    Ok(())
}

/// Read a seed file. On Unix it must be mode `0600` or tighter.
pub fn load_seed_file(path: &Path) -> Result<[u8; 32], AirgapError> {
    ensure_private(path)?;
    let text = fs::read_to_string(path).map_err(|e| AirgapError::Io(e.to_string()))?;
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("seed ") {
            return parse_hex32(rest);
        }
    }
    Err(AirgapError::BadSeed)
}

fn parse_request(text: &str) -> Result<PaymentRequest, AirgapError> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    if lines.next().map(str::trim) != Some("permawrite-airgap-request v1") {
        return Err(AirgapError::BadRequest);
    }
    let mut fee = None;
    let mut outputs = Vec::new();
    let mut payload = None;
    for line in lines {
        let (key, rest) = line.split_once(' ').ok_or(AirgapError::BadRequest)?;
        match key {
            "fee" => {
                if fee.is_some() {
                    return Err(AirgapError::BadField("fee".into()));
                }
                fee = Some(
                    rest.parse::<u64>()
                        .map_err(|_| AirgapError::BadField("fee".into()))?,
                );
            }
            "output" => {
                let (label, amount) = rest
                    .split_once(' ')
                    .ok_or(AirgapError::BadField("output".into()))?;
                let amount = amount
                    .parse::<u64>()
                    .map_err(|_| AirgapError::BadField("output".into()))?;
                outputs.push((label.to_string(), amount));
            }
            "payload_sha256" => {
                if payload.is_some() {
                    return Err(AirgapError::BadField("payload_sha256".into()));
                }
                payload = Some(rest.to_string());
            }
            _ => return Err(AirgapError::BadRequest),
        }
    }
    let mut request = PaymentRequest {
        fee: fee.ok_or(AirgapError::BadField("fee".into()))?,
        outputs,
        payload_sha256: payload.ok_or(AirgapError::BadField("payload_sha256".into()))?,
    };
    request.outputs.sort_by(|a, b| a.0.cmp(&b.0));
    request.payload_sha256 = request.payload_sha256.to_ascii_lowercase();
    let _ = request.canonical()?;
    Ok(request)
}

fn parse_hex32(text: &str) -> Result<[u8; 32], AirgapError> {
    if text.len() != 64 {
        return Err(AirgapError::BadSeed);
    }
    let bytes = hex::decode(text).map_err(|_| AirgapError::BadSeed)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex64(text: &str) -> Result<[u8; 64], AirgapError> {
    if text.len() != 128 {
        return Err(AirgapError::BadSignature);
    }
    let bytes = hex::decode(text).map_err(|_| AirgapError::BadSignature)?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(unix)]
fn ensure_private(path: &Path) -> Result<(), AirgapError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|e| AirgapError::Io(e.to_string()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(AirgapError::SeedReadable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private(_path: &Path) -> Result<(), AirgapError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> PaymentRequest {
        PaymentRequest {
            fee: 10,
            outputs: vec![("bob".into(), 50), ("alice".into(), 40)],
            payload_sha256: "ab".repeat(32),
        }
    }

    #[test]
    fn sign_verify_and_the_file_does_not_contain_the_seed() {
        let seed = [9u8; 32];
        let signed = sign_request(&seed, &request()).unwrap();
        verify_signed(&signed, &signed.spend_pub).unwrap();
        let text = signed.render().unwrap();
        assert!(!text.contains(&hex::encode(seed)));
        assert!(text.find("output alice ").unwrap() < text.find("output bob ").unwrap());
        let watch = watch_only(&seed);
        assert!(watch.contains(&hex::encode(signed.spend_pub)));
        assert!(!watch.contains(&hex::encode(seed)));
        let again = SignedRequest::parse(&text).unwrap();
        verify_signed(&again, &signed.spend_pub).unwrap();
    }

    #[test]
    fn tampered_fee_and_swapped_key_fail() {
        let seed = [3u8; 32];
        let other = [4u8; 32];
        let signed = sign_request(&seed, &request()).unwrap();
        let mut tampered = signed.clone();
        tampered.request.fee += 1;
        assert_eq!(
            verify_signed(&tampered, &signed.spend_pub),
            Err(AirgapError::BadSignature)
        );
        let other_pub = {
            let keys = wallet_from_seed(&other);
            point_to_bytes(&keys.spend_pub())
        };
        assert_eq!(
            verify_signed(&signed, &other_pub),
            Err(AirgapError::WrongKey)
        );
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_seed_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mfn-airgap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seed");
        fs::write(&path, format!("seed {}\n", hex::encode([7u8; 32]))).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).unwrap();
        assert_eq!(
            load_seed_file(&path).unwrap_err(),
            AirgapError::SeedReadable
        );
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).unwrap();
        assert_eq!(load_seed_file(&path).unwrap(), [7u8; 32]);
        let _ = fs::remove_dir_all(&dir);
    }
}
