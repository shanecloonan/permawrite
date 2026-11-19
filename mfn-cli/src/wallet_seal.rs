//! Passphrase seal for a wallet seed.
//!
//! New files use Argon2id (memory-hard) and ChaCha20-Poly1305. Files sealed
//! with the earlier PBKDF2-HMAC-SHA256 construction still open, and the next
//! save rewrites them as Argon2id. The passphrase is never stored.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// Argon2id memory (KiB), passes, and lanes for a new seal.
/// 19 MiB and 2 passes is the OWASP 2023 Argon2id recommendation at one lane.
pub const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
pub const ARGON2_TIME: u32 = 2;
pub const ARGON2_LANES: u32 = 1;

const SALT_LEN: usize = 16;
const CHACHA_NONCE_LEN: usize = 12;
/// Iterations used by version 3 PBKDF2 seals.
const PBKDF2_ITERS: u32 = 100_000;

/// How a sealed seed was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealKdf {
    /// Current construction.
    Argon2id {
        /// Memory cost in KiB.
        memory_kib: u32,
        /// Passes.
        time: u32,
        /// Lanes.
        lanes: u32,
    },
    /// Previous construction. Opened only so it can be rewritten.
    Pbkdf2Sha256 {
        /// Iteration count.
        iters: u32,
    },
}

/// Sealed 32-byte seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSeed {
    /// Key derivation.
    pub kdf: SealKdf,
    /// Salt for the KDF.
    pub salt: Vec<u8>,
    /// AEAD nonce. 12 bytes for Argon2id seals, 16 bytes for the PBKDF2 keystream.
    pub nonce: Vec<u8>,
    /// Ciphertext, including the authentication tag for Argon2id seals.
    pub ciphertext: Vec<u8>,
}

/// Passphrase held in memory. Debug output does not show it.
#[derive(Clone, PartialEq, Eq)]
pub struct HeldPassphrase(String);

impl std::fmt::Debug for HeldPassphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HeldPassphrase([redacted])")
    }
}

impl HeldPassphrase {
    /// Reject a short passphrase.
    pub fn new(raw: &str) -> Result<Self, SealError> {
        check_passphrase(raw)?;
        Ok(Self(raw.trim().to_string()))
    }

    /// Borrow the passphrase for the KDF.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// On-disk seal. The passphrase is not a field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeedLockRecord {
    /// `argon2id` or `pbkdf2-sha256`.
    pub kdf: String,
    /// Argon2id memory in KiB.
    #[serde(default)]
    pub memory_kib: Option<u32>,
    /// Argon2id passes.
    #[serde(default)]
    pub time: Option<u32>,
    /// Argon2id lanes.
    #[serde(default)]
    pub lanes: Option<u32>,
    /// PBKDF2 iterations.
    #[serde(default)]
    pub iters: Option<u32>,
    /// Hex salt.
    pub salt_hex: String,
    /// Hex nonce.
    pub nonce_hex: String,
    /// Hex ciphertext (and tag).
    pub ciphertext_hex: String,
}

impl SealedSeed {
    /// Encode for the wallet file.
    pub fn to_record(&self) -> SeedLockRecord {
        let (kdf, memory_kib, time, lanes, iters) = match self.kdf {
            SealKdf::Argon2id {
                memory_kib,
                time,
                lanes,
            } => (
                "argon2id".to_string(),
                Some(memory_kib),
                Some(time),
                Some(lanes),
                None,
            ),
            SealKdf::Pbkdf2Sha256 { iters } => {
                ("pbkdf2-sha256".to_string(), None, None, None, Some(iters))
            }
        };
        SeedLockRecord {
            kdf,
            memory_kib,
            time,
            lanes,
            iters,
            salt_hex: hex::encode(&self.salt),
            nonce_hex: hex::encode(&self.nonce),
            ciphertext_hex: hex::encode(&self.ciphertext),
        }
    }

    /// Decode a wallet-file seal.
    pub fn from_record(record: &SeedLockRecord) -> Result<Self, SealError> {
        let kdf = match record.kdf.as_str() {
            "argon2id" => SealKdf::Argon2id {
                memory_kib: record.memory_kib.ok_or(SealError::Rejected)?,
                time: record.time.ok_or(SealError::Rejected)?,
                lanes: record.lanes.ok_or(SealError::Rejected)?,
            },
            "pbkdf2-sha256" => SealKdf::Pbkdf2Sha256 {
                iters: record.iters.ok_or(SealError::Rejected)?,
            },
            _ => return Err(SealError::Rejected),
        };
        Ok(Self {
            kdf,
            salt: decode_hex(&record.salt_hex)?,
            nonce: decode_hex(&record.nonce_hex)?,
            ciphertext: decode_hex(&record.ciphertext_hex)?,
        })
    }
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, SealError> {
    hex::decode(raw.trim()).map_err(|_| SealError::Rejected)
}

/// Read `MFN_WALLET_PASSPHRASE`.
pub fn passphrase_from_env() -> Result<HeldPassphrase, SealError> {
    match std::env::var("MFN_WALLET_PASSPHRASE") {
        Ok(value) => HeldPassphrase::new(&value),
        Err(_) => Err(SealError::MissingPassphrase),
    }
}

/// Why a seal could not be opened or created.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// Passphrase too short.
    #[error("passphrase must be at least 8 characters")]
    PassphraseTooShort,
    /// Environment variable was not set.
    #[error(
        "Set MFN_WALLET_PASSPHRASE in the environment. The passphrase is not stored in the wallet file and is not accepted on the command line"
    )]
    MissingPassphrase,
    /// KDF or AEAD failed, or the passphrase is wrong.
    #[error("could not unlock the wallet. The passphrase is wrong, or the file was modified")]
    Rejected,
}

impl SealedSeed {
    /// True when the next save should rewrite this as Argon2id.
    pub fn needs_argon2_migration(&self) -> bool {
        matches!(self.kdf, SealKdf::Pbkdf2Sha256 { .. })
    }
}

/// Seal with Argon2id and ChaCha20-Poly1305.
pub fn seal_seed(seed: &[u8; 32], passphrase: &str) -> Result<SealedSeed, SealError> {
    check_passphrase(passphrase)?;
    let mut salt = vec![0u8; SALT_LEN];
    let mut nonce = vec![0u8; CHACHA_NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = argon2id_key(
        passphrase.as_bytes(),
        &salt,
        ARGON2_MEMORY_KIB,
        ARGON2_TIME,
        ARGON2_LANES,
    )?;
    let ciphertext = chacha_encrypt(&key, &nonce, seed)?;
    Ok(SealedSeed {
        kdf: SealKdf::Argon2id {
            memory_kib: ARGON2_MEMORY_KIB,
            time: ARGON2_TIME,
            lanes: ARGON2_LANES,
        },
        salt,
        nonce,
        ciphertext,
    })
}

/// Open a seal. Argon2id and the legacy PBKDF2 construction both work.
pub fn open_seed(sealed: &SealedSeed, passphrase: &str) -> Result<[u8; 32], SealError> {
    check_passphrase(passphrase)?;
    match sealed.kdf {
        SealKdf::Argon2id {
            memory_kib,
            time,
            lanes,
        } => {
            let key = argon2id_key(passphrase.as_bytes(), &sealed.salt, memory_kib, time, lanes)?;
            chacha_decrypt(&key, &sealed.nonce, &sealed.ciphertext)
        }
        SealKdf::Pbkdf2Sha256 { iters } => open_pbkdf2(sealed, passphrase, iters),
    }
}

/// Read a version 3 wallet blob: salt || nonce || tag || ciphertext.
pub(crate) fn sealed_from_v3_blob(blob: &[u8]) -> Result<SealedSeed, SealError> {
    if blob.len() != 80 {
        return Err(SealError::Rejected);
    }
    let mut ciphertext = blob[48..80].to_vec();
    ciphertext.extend_from_slice(&blob[32..48]);
    Ok(SealedSeed {
        kdf: SealKdf::Pbkdf2Sha256 {
            iters: PBKDF2_ITERS,
        },
        salt: blob[..16].to_vec(),
        nonce: blob[16..32].to_vec(),
        ciphertext,
    })
}

/// Build a legacy PBKDF2 seal. Tests use it to prove migration.
#[cfg(test)]
pub(crate) fn seal_seed_pbkdf2_for_migration(
    seed: &[u8; 32],
    passphrase: &str,
) -> Result<SealedSeed, SealError> {
    check_passphrase(passphrase)?;
    let mut salt = vec![0u8; SALT_LEN];
    let mut nonce = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let (enc, mac) = pbkdf2_keys(passphrase.as_bytes(), &salt, PBKDF2_ITERS);
    let stream = hmac_sha256(&enc, &nonce);
    let mut ct = vec![0u8; 32];
    for i in 0..32 {
        ct[i] = seed[i] ^ stream[i];
    }
    let mut mac_msg = Vec::with_capacity(48);
    mac_msg.extend_from_slice(&nonce);
    mac_msg.extend_from_slice(&ct);
    let tag = hmac_sha256(&mac, &mac_msg);
    ct.extend_from_slice(&tag[..16]);
    Ok(SealedSeed {
        kdf: SealKdf::Pbkdf2Sha256 {
            iters: PBKDF2_ITERS,
        },
        salt,
        nonce,
        ciphertext: ct,
    })
}

fn check_passphrase(passphrase: &str) -> Result<(), SealError> {
    if passphrase.trim().chars().count() < 8 {
        Err(SealError::PassphraseTooShort)
    } else {
        Ok(())
    }
}

pub(super) fn argon2id_key(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    time: u32,
    lanes: u32,
) -> Result<[u8; 32], SealError> {
    let params = Params::new(memory_kib, time, lanes, Some(32)).map_err(|_| SealError::Rejected)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| SealError::Rejected)?;
    Ok(out)
}

fn chacha_encrypt(
    key: &[u8; 32],
    nonce: &[u8],
    plaintext: &[u8; 32],
) -> Result<Vec<u8>, SealError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|_| SealError::Rejected)
}

fn chacha_decrypt(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<[u8; 32], SealError> {
    if nonce.len() != CHACHA_NONCE_LEN {
        return Err(SealError::Rejected);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SealError::Rejected)?;
    if plain.len() != 32 {
        return Err(SealError::Rejected);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plain);
    Ok(seed)
}

fn open_pbkdf2(sealed: &SealedSeed, passphrase: &str, iters: u32) -> Result<[u8; 32], SealError> {
    if sealed.nonce.len() != 16 || sealed.ciphertext.len() != 48 {
        return Err(SealError::Rejected);
    }
    let ct = &sealed.ciphertext[..32];
    let tag = &sealed.ciphertext[32..];
    let (enc, mac) = pbkdf2_keys(passphrase.as_bytes(), &sealed.salt, iters);
    let mut mac_msg = Vec::with_capacity(48);
    mac_msg.extend_from_slice(&sealed.nonce);
    mac_msg.extend_from_slice(ct);
    let full = hmac_sha256(&mac, &mac_msg);
    if !ct_eq(tag, &full[..16]) {
        return Err(SealError::Rejected);
    }
    let stream = hmac_sha256(&enc, &sealed.nonce);
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = ct[i] ^ stream[i];
    }
    Ok(seed)
}

fn pbkdf2_keys(password: &[u8], salt: &[u8], iters: u32) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 64];
    pbkdf2_sha256(password, salt, iters, &mut out);
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&out[..32]);
    mac.copy_from_slice(&out[32..]);
    (enc, mac)
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iters: u32, out: &mut [u8]) {
    let mut block: u32 = 1;
    let mut offset = 0;
    while offset < out.len() {
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&block.to_be_bytes());
        let mut u = hmac_sha256(password, &msg);
        let mut t = u;
        for _ in 1..iters.max(1) {
            u = hmac_sha256(password, &u);
            for (acc, byte) in t.iter_mut().zip(u) {
                *acc ^= byte;
            }
        }
        let n = (out.len() - offset).min(32);
        out[offset..offset + n].copy_from_slice(&t[..n]);
        offset += n;
        block += 1;
    }
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let digest = Sha256::digest(key);
        k[..32].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    let digest = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_matches_the_reference_vector() {
        // argon2 crate KAT: Argon2id v1.3, m=256 KiB, t=2, p=1, password "password", salt "somesalt".
        let key = argon2id_key(b"password", b"somesalt", 256, 2, 1).expect("kdf");
        assert_eq!(
            hex::encode(key),
            "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe"
        );
    }

    #[test]
    fn production_seal_round_trips_and_rejects_a_bad_passphrase() {
        let seed = [0x11u8; 32];
        let sealed = seal_seed(&seed, "correct horse").expect("seal");
        assert!(!sealed.needs_argon2_migration());
        assert_eq!(open_seed(&sealed, "correct horse").expect("open"), seed);
        assert!(open_seed(&sealed, "wrong horse").is_err());
        let mut flipped = sealed.clone();
        let last = flipped.ciphertext.len() - 1;
        flipped.ciphertext[last] ^= 0x01;
        assert!(open_seed(&flipped, "correct horse").is_err());
    }

    #[test]
    fn pbkdf2_seal_opens_and_is_marked_for_migration() {
        let seed = [0x22u8; 32];
        let sealed = seal_seed_pbkdf2_for_migration(&seed, "correct horse").expect("old");
        assert!(sealed.needs_argon2_migration());
        assert_eq!(open_seed(&sealed, "correct horse").expect("open old"), seed);
        assert!(open_seed(&sealed, "wrong horse").is_err());
    }
}
