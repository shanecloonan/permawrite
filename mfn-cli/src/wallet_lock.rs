//! Passphrase lock for the on-disk wallet seed.
//!
//! The seed is sealed with PBKDF2-HMAC-SHA256 and an HMAC-SHA256 keystream.
//! The passphrase never goes in the file and is not accepted on the command
//! line, so it does not land in shell history. A wrong passphrase or a
//! modified file fails closed.

use sha2::{Digest, Sha256};

use crate::wallet_store::WalletStoreError;

pub(crate) const LOCK_ITERS: u32 = 100_000;
const MIN_PASSPHRASE_LEN: usize = 8;

/// Passphrase held only in memory. Debug output does not show it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct HeldPassphrase(String);

impl std::fmt::Debug for HeldPassphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HeldPassphrase([redacted])")
    }
}

impl HeldPassphrase {
    pub(crate) fn new(raw: &str) -> Result<Self, WalletStoreError> {
        let trimmed = raw.trim();
        if trimmed.chars().count() < MIN_PASSPHRASE_LEN {
            return Err(WalletStoreError::Invalid(format!(
                "passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
            )));
        }
        Ok(Self(trimmed.to_string()))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Read `MFN_WALLET_PASSPHRASE`. Empty or missing is an error.
pub(crate) fn passphrase_from_env() -> Result<HeldPassphrase, WalletStoreError> {
    match std::env::var("MFN_WALLET_PASSPHRASE") {
        Ok(value) => HeldPassphrase::new(&value),
        Err(_) => Err(WalletStoreError::Invalid(
            "Set MFN_WALLET_PASSPHRASE in the environment. The passphrase is not \
             stored in the wallet file and is not accepted on the command line"
                .into(),
        )),
    }
}

/// Seal a 32-byte seed. Output is salt || nonce || tag || ciphertext (80 bytes).
pub(crate) fn seal_seed(seed: &[u8; 32], pass: &HeldPassphrase) -> [u8; 80] {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut salt);
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
    seal_seed_with(seed, pass, &salt, &nonce, LOCK_ITERS)
}

fn seal_seed_with(
    seed: &[u8; 32],
    pass: &HeldPassphrase,
    salt: &[u8; 16],
    nonce: &[u8; 16],
    iters: u32,
) -> [u8; 80] {
    let (enc, mac) = derive_keys(pass.as_bytes(), salt, iters);
    let stream = hmac_sha256(&enc, nonce);
    let mut ct = [0u8; 32];
    for i in 0..32 {
        ct[i] = seed[i] ^ stream[i];
    }
    let mut mac_msg = [0u8; 48];
    mac_msg[..16].copy_from_slice(nonce);
    mac_msg[16..].copy_from_slice(&ct);
    let full_tag = hmac_sha256(&mac, &mac_msg);
    let mut out = [0u8; 80];
    out[..16].copy_from_slice(salt);
    out[16..32].copy_from_slice(nonce);
    out[32..48].copy_from_slice(&full_tag[..16]);
    out[48..].copy_from_slice(&ct);
    out
}

/// Open a sealed seed. A wrong passphrase or a flipped byte is the same error.
pub(crate) fn open_seed(blob: &[u8], pass: &HeldPassphrase) -> Result<[u8; 32], WalletStoreError> {
    if blob.len() != 80 {
        return Err(WalletStoreError::Invalid(
            "locked wallet secret is the wrong length. The file may be damaged".into(),
        ));
    }
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 16];
    let mut tag = [0u8; 16];
    let mut ct = [0u8; 32];
    salt.copy_from_slice(&blob[..16]);
    nonce.copy_from_slice(&blob[16..32]);
    tag.copy_from_slice(&blob[32..48]);
    ct.copy_from_slice(&blob[48..]);
    let (enc, mac) = derive_keys(pass.as_bytes(), &salt, LOCK_ITERS);
    let mut mac_msg = [0u8; 48];
    mac_msg[..16].copy_from_slice(&nonce);
    mac_msg[16..].copy_from_slice(&ct);
    let full_tag = hmac_sha256(&mac, &mac_msg);
    if !ct_eq(&tag, &full_tag[..16]) {
        return Err(WalletStoreError::Invalid(
            "could not unlock the wallet. The passphrase is wrong, or the file was modified".into(),
        ));
    }
    let stream = hmac_sha256(&enc, &nonce);
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = ct[i] ^ stream[i];
    }
    Ok(seed)
}

fn derive_keys(password: &[u8], salt: &[u8], iters: u32) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 64];
    pbkdf2_sha256(password, salt, iters, &mut out);
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&out[..32]);
    mac.copy_from_slice(&out[32..]);
    out.fill(0);
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
    fn pbkdf2_sha256_matches_the_one_iteration_vector() {
        let mut out = [0u8; 32];
        pbkdf2_sha256(b"password", b"salt", 1, &mut out);
        assert_eq!(
            hex::encode(out),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn seal_round_trips_and_rejects_a_flipped_byte() {
        let pass = HeldPassphrase::new("correct horse").expect("pass");
        let seed = [0x42u8; 32];
        let mut blob = seal_seed(&seed, &pass);
        assert_eq!(open_seed(&blob, &pass).expect("open"), seed);
        blob[70] ^= 0x01;
        assert!(open_seed(&blob, &pass).is_err());
        let other = HeldPassphrase::new("wrong horse").expect("other");
        let blob = seal_seed(&seed, &pass);
        assert!(open_seed(&blob, &other).is_err());
    }

    #[test]
    fn short_passphrase_is_refused() {
        assert!(HeldPassphrase::new("short").is_err());
    }
}
