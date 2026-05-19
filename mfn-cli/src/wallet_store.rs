//! On-disk wallet file (seed + optional scan checkpoint).

use std::fs;
use std::path::Path;

use mfn_crypto::stealth::stealth_wallet_from_seed;
use mfn_wallet::{wallet_from_seed, Wallet, WalletKeys};
use serde::{Deserialize, Serialize};

/// Current wallet file schema version.
pub const WALLET_FILE_VERSION: u32 = 1;

/// How the 32-byte `seed_hex` maps to [`WalletKeys`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyDerivation {
    /// [`mfn_wallet::wallet_from_seed`] — default user wallet.
    #[default]
    MfnWalletV1,
    /// [`mfn_crypto::stealth::stealth_wallet_from_seed`] — matches genesis
    /// `payout_seed_hex` validator coinbase routes (tests / operator payout keys).
    PayoutStealthV1,
}

/// Serialized wallet on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletFile {
    /// Schema version (must be [`WALLET_FILE_VERSION`]).
    pub version: u32,
    /// 64 hex chars (32 bytes) — the wallet backup secret.
    pub seed_hex: String,
    /// Key derivation tag (default `mfn_wallet_v1`).
    #[serde(default)]
    pub key_derivation: KeyDerivation,
    /// Last block height fully applied by `wallet scan` (informational).
    #[serde(default)]
    pub scan_height: Option<u32>,
}

/// Wallet file parse / IO errors.
#[derive(Debug, thiserror::Error)]
pub enum WalletStoreError {
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON failure.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Invalid file contents.
    #[error("{0}")]
    Invalid(String),
}

impl WalletFile {
    /// Create a new file descriptor (not yet written).
    pub fn new(seed: &[u8; 32], key_derivation: KeyDerivation) -> Self {
        Self {
            version: WALLET_FILE_VERSION,
            seed_hex: hex::encode(seed),
            key_derivation,
            scan_height: None,
        }
    }

    /// Parse seed bytes from `seed_hex`.
    pub fn seed_bytes(&self) -> Result<[u8; 32], WalletStoreError> {
        parse_seed_hex(&self.seed_hex)
    }

    /// Build an in-memory [`Wallet`] from this file (empty UTXO set).
    pub fn to_wallet(&self) -> Result<Wallet, WalletStoreError> {
        let seed = self.seed_bytes()?;
        Ok(Wallet::from_keys(keys_from_seed(&seed, self.key_derivation)))
    }

    /// Write JSON to `path` (pretty-printed, mode 0600 on Unix).
    pub fn save(&self, path: &Path) -> Result<(), WalletStoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let text = serde_json::to_string_pretty(self)?;
        fs::write(path, text.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load and validate a wallet file.
    pub fn load(path: &Path) -> Result<Self, WalletStoreError> {
        let bytes = fs::read(path)?;
        let file: WalletFile = serde_json::from_slice(&bytes)?;
        file.validate()?;
        Ok(file)
    }

    fn validate(&self) -> Result<(), WalletStoreError> {
        if self.version != WALLET_FILE_VERSION {
            return Err(WalletStoreError::Invalid(format!(
                "unsupported wallet version {} (expected {WALLET_FILE_VERSION})",
                self.version
            )));
        }
        let _ = self.seed_bytes()?;
        Ok(())
    }
}

fn parse_seed_hex(s: &str) -> Result<[u8; 32], WalletStoreError> {
    let t = s.trim();
    if t.len() != 64 {
        return Err(WalletStoreError::Invalid(format!(
            "seed_hex must be 64 hex characters (got {})",
            t.len()
        )));
    }
    if !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(WalletStoreError::Invalid("seed_hex must be hexadecimal".into()));
    }
    let bytes = hex::decode(t).map_err(|e| WalletStoreError::Invalid(format!("seed_hex: {e}")))?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn keys_from_seed(seed: &[u8; 32], derivation: KeyDerivation) -> WalletKeys {
    match derivation {
        KeyDerivation::MfnWalletV1 => wallet_from_seed(seed),
        KeyDerivation::PayoutStealthV1 => {
            WalletKeys::from_stealth(stealth_wallet_from_seed(seed))
        }
    }
}

/// Default wallet path when `--wallet` is omitted.
pub const DEFAULT_WALLET_PATH: &str = "wallet.json";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_seed_hex() {
        let seed = [0xcd; 32];
        let f = WalletFile::new(&seed, KeyDerivation::MfnWalletV1);
        assert_eq!(f.seed_bytes().unwrap(), seed);
    }

    #[test]
    fn payout_derivation_differs_from_mfn_wallet() {
        let seed = [1u8; 32];
        let a = keys_from_seed(&seed, KeyDerivation::MfnWalletV1);
        let b = keys_from_seed(&seed, KeyDerivation::PayoutStealthV1);
        assert_ne!(
            a.view_pub().compress(),
            b.view_pub().compress()
        );
    }
}
