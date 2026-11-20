//! Maintainer keys, the public keyring, and the revocation list.
//!
//! Signatures are the same Schnorr scheme `mfn-crypto` uses everywhere else.
//! A release does not introduce a second signature primitive.

use mfn_crypto::{
    bytes_to_scalar, generator_g, point_from_bytes, point_to_bytes, scalar_to_bytes,
    schnorr_keygen, SchnorrKeypair,
};
use thiserror::Error;

/// A maintainer signing key. The secret is zeroized when the keypair drops.
///
/// `Debug` prints the id and the public key only.
pub struct MaintainerKey {
    /// Short public name, for example `alice`.
    pub id: String,
    signing: SchnorrKeypair,
}

impl std::fmt::Debug for MaintainerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaintainerKey")
            .field("id", &self.id)
            .field("public", &self.public_hex())
            .finish()
    }
}

impl MaintainerKey {
    /// Public key bytes.
    pub fn public_bytes(&self) -> [u8; 32] {
        point_to_bytes(&self.signing.pub_key)
    }

    /// Public key, lower-case hex.
    pub fn public_hex(&self) -> String {
        hex::encode(self.public_bytes())
    }

    /// Borrow the signing key.
    pub(crate) fn signing(&self) -> &SchnorrKeypair {
        &self.signing
    }
}

/// Generate a new maintainer key from the operating-system RNG.
pub fn generate_key(id: &str) -> Result<MaintainerKey, KeyError> {
    check_id(id)?;
    Ok(MaintainerKey {
        id: id.to_string(),
        signing: schnorr_keygen(),
    })
}

/// Rebuild a key from a 32-byte scalar. Used by tests and by secret files.
pub fn key_from_seed(id: &str, seed: &[u8; 32]) -> Result<MaintainerKey, KeyError> {
    check_id(id)?;
    let scalar = bytes_to_scalar(seed);
    if scalar == bytes_to_scalar(&[0u8; 32]) {
        return Err(KeyError::BadHex { expected: 64 });
    }
    Ok(MaintainerKey {
        id: id.to_string(),
        signing: SchnorrKeypair {
            priv_key: scalar,
            pub_key: generator_g() * scalar,
        },
    })
}

/// Why a key file or keyring was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    /// The key id is empty or has characters a file name should not.
    #[error("key id must be 1-32 bytes of [a-z0-9_-]: {0}")]
    BadId(String),
    /// A hex field was the wrong length or not hex.
    #[error("expected {expected} hex characters")]
    BadHex {
        /// How many hex characters were required.
        expected: usize,
    },
    /// The same id or the same public key appears twice.
    #[error("duplicate keyring entry: {0}")]
    Duplicate(String),
    /// The secret file is missing a field.
    #[error("secret file is missing {0}")]
    MissingField(&'static str),
    /// The public key does not match the secret.
    #[error("public key does not match the secret")]
    PublicMismatch,
}

pub(crate) fn check_id(id: &str) -> Result<(), KeyError> {
    if id.is_empty()
        || id.len() > 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(KeyError::BadId(id.to_string()));
    }
    Ok(())
}

fn parse_hex_32(text: &str) -> Result<[u8; 32], KeyError> {
    let text = text.trim();
    if text.len() != 64 {
        return Err(KeyError::BadHex { expected: 64 });
    }
    let bytes = hex::decode(text).map_err(|_| KeyError::BadHex { expected: 64 })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

impl MaintainerKey {
    /// Secret file text. Contains the seed. Do not publish this file.
    pub fn render_secret(&self) -> String {
        format!(
            "id {}\nsecret {}\npublic {}\n",
            self.id,
            hex::encode(scalar_to_bytes(&self.signing.priv_key)),
            self.public_hex()
        )
    }

    /// One public keyring line.
    pub fn render_public(&self) -> String {
        format!("{} {}\n", self.id, self.public_hex())
    }

    /// Parse a secret file produced by [`Self::render_secret`].
    pub fn parse_secret(text: &str) -> Result<Self, KeyError> {
        let mut id = None;
        let mut secret = None;
        let mut public = None;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (field, value) = line
                .split_once(' ')
                .ok_or(KeyError::MissingField("field"))?;
            match field {
                "id" => id = Some(value.to_string()),
                "secret" => secret = Some(parse_hex_32(value)?),
                "public" => public = Some(parse_hex_32(value)?),
                _ => return Err(KeyError::MissingField("known field")),
            }
        }
        let id = id.ok_or(KeyError::MissingField("id"))?;
        let secret = secret.ok_or(KeyError::MissingField("secret"))?;
        let public = public.ok_or(KeyError::MissingField("public"))?;
        let key = key_from_seed(&id, &secret)?;
        if key.public_bytes() != public {
            return Err(KeyError::PublicMismatch);
        }
        Ok(key)
    }
}

/// Public keys that are allowed to sign a release.
#[derive(Clone, Debug)]
pub struct Keyring {
    entries: Vec<(String, [u8; 32])>,
}

impl Keyring {
    /// Parse `id <64 hex>` lines.
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        let mut entries = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (id, hex_key) = line
                .split_once(' ')
                .ok_or(KeyError::MissingField("public"))?;
            check_id(id)?;
            let bytes = parse_hex_32(hex_key)?;
            point_from_bytes(&bytes).map_err(|_| KeyError::BadHex { expected: 64 })?;
            if entries.iter().any(|(have, _)| have == id) {
                return Err(KeyError::Duplicate(id.to_string()));
            }
            if entries.iter().any(|(_, key)| key == &bytes) {
                return Err(KeyError::Duplicate(hex::encode(bytes)));
            }
            entries.push((id.to_string(), bytes));
        }
        Ok(Self { entries })
    }

    /// Look up a key id. The bytes are a compressed public point.
    pub fn get(&self, id: &str) -> Option<[u8; 32]> {
        self.entries
            .iter()
            .find(|(have, _)| have == id)
            .map(|(_, key)| *key)
    }

    /// How many keys are in the ring.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the ring has no keys.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Public keys that must not count, even if they still appear in an old ring.
#[derive(Clone, Debug, Default)]
pub struct Revocation {
    keys: Vec<[u8; 32]>,
}

impl Revocation {
    /// Parse one public key hex per line. An empty file revokes nobody.
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        let mut keys = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            keys.push(parse_hex_32(line)?);
        }
        Ok(Self { keys })
    }

    /// True when this public key has been revoked.
    pub fn contains(&self, public: &[u8; 32]) -> bool {
        self.keys.iter().any(|k| k == public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_file_round_trips_and_rejects_a_swapped_public_key() {
        let key = key_from_seed("alice", &[7u8; 32]).unwrap();
        let parsed = MaintainerKey::parse_secret(&key.render_secret()).unwrap();
        assert_eq!(parsed.id, "alice");
        assert_eq!(parsed.public_bytes(), key.public_bytes());

        let mut text = key.render_secret();
        text = text.replace(&key.public_hex(), &"ab".repeat(32));
        assert_eq!(
            MaintainerKey::parse_secret(&text).unwrap_err(),
            KeyError::PublicMismatch
        );
    }

    #[test]
    fn keyring_rejects_duplicate_ids_and_bad_ids() {
        let alice = key_from_seed("alice", &[1u8; 32]).unwrap();
        let text = format!("{}{}", alice.render_public(), alice.render_public());
        assert!(matches!(Keyring::parse(&text), Err(KeyError::Duplicate(_))));
        assert!(matches!(generate_key("Alice"), Err(KeyError::BadId(_))));
    }
}
