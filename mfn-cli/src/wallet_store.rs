//! On-disk wallet file (seed + optional scan checkpoint).

use std::fs;
use std::path::Path;

use mfn_crypto::stealth::stealth_wallet_from_seed;
use mfn_wallet::{wallet_from_seed, StoredOwnedOutput, Wallet, WalletKeys};
use serde::{Deserialize, Serialize};

/// Current wallet file schema version.
pub const WALLET_FILE_VERSION: u32 = 2;

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
    /// UTXO keys (32-byte hex) spent locally by `wallet send` but not yet
    /// visible on-chain — prevents a full rescan from resurrecting them.
    #[serde(default)]
    pub pending_spent_utxo_keys: Vec<String>,
    /// Cached unspent owned outputs through [`Self::scan_height`] (**M3.6**).
    #[serde(default)]
    pub owned_outputs: Vec<StoredOwnedOutput>,
    /// Last `LightChain::encode_checkpoint` hex after `wallet light-scan` (**M3.11**).
    #[serde(default)]
    pub light_checkpoint_hex: Option<String>,
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
            pending_spent_utxo_keys: Vec::new(),
            owned_outputs: Vec::new(),
            light_checkpoint_hex: None,
        }
    }

    /// Whether a persisted UTXO snapshot can skip replaying old blocks.
    pub fn has_owned_cache(&self) -> bool {
        self.scan_height.is_some() && !self.owned_outputs.is_empty()
    }

    /// Restore cached owned outputs into `wallet` (no-op if cache empty).
    pub fn hydrate_wallet(&self, wallet: &mut Wallet) -> Result<(), WalletStoreError> {
        if !self.has_owned_cache() {
            return Ok(());
        }
        let height = self.scan_height.expect("checked in has_owned_cache");
        wallet
            .load_owned_snapshot(&self.owned_outputs, height)
            .map_err(|e| WalletStoreError::Invalid(e.to_string()))
    }

    /// Persist current wallet UTXO set and scan height into this file descriptor.
    pub fn capture_wallet_state(&mut self, wallet: &Wallet) {
        self.scan_height = wallet.scan_height();
        self.owned_outputs = wallet.export_owned_snapshot();
    }

    /// Apply [`Wallet::mark_spent_by_utxo_key`] for every pending entry.
    pub fn apply_pending_spends(&self, wallet: &mut Wallet) -> Result<(), WalletStoreError> {
        for hex_key in &self.pending_spent_utxo_keys {
            let key = parse_utxo_key_hex(hex_key)?;
            wallet.mark_spent_by_utxo_key(&key);
        }
        Ok(())
    }

    /// Record UTXO keys consumed by a broadcast that is not yet mined.
    pub fn record_pending_spends(&mut self, keys: &[[u8; 32]]) {
        for key in keys {
            let hex_key = hex::encode(key);
            if !self.pending_spent_utxo_keys.iter().any(|h| h == &hex_key) {
                self.pending_spent_utxo_keys.push(hex_key);
            }
        }
    }

    /// Parse seed bytes from `seed_hex`.
    pub fn seed_bytes(&self) -> Result<[u8; 32], WalletStoreError> {
        parse_seed_hex(&self.seed_hex)
    }

    /// Build an in-memory [`Wallet`] from this file (empty UTXO set).
    pub fn to_wallet(&self) -> Result<Wallet, WalletStoreError> {
        let seed = self.seed_bytes()?;
        Ok(Wallet::from_keys(keys_from_seed(
            &seed,
            self.key_derivation,
        )))
    }

    /// Write JSON to `path` (pretty-printed, mode 0600 on Unix).
    pub fn save(&mut self, path: &Path) -> Result<(), WalletStoreError> {
        self.version = WALLET_FILE_VERSION;
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
        if self.version != 1 && self.version != WALLET_FILE_VERSION {
            return Err(WalletStoreError::Invalid(format!(
                "unsupported wallet version {} (expected 1 or {WALLET_FILE_VERSION})",
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
        return Err(WalletStoreError::Invalid(
            "seed_hex must be hexadecimal".into(),
        ));
    }
    let bytes = hex::decode(t).map_err(|e| WalletStoreError::Invalid(format!("seed_hex: {e}")))?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn parse_utxo_key_hex(s: &str) -> Result<[u8; 32], WalletStoreError> {
    let t = s.trim();
    if t.len() != 64 {
        return Err(WalletStoreError::Invalid(format!(
            "utxo key must be 64 hex characters (got {})",
            t.len()
        )));
    }
    let bytes = hex::decode(t).map_err(|e| WalletStoreError::Invalid(format!("utxo key: {e}")))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn keys_from_seed(seed: &[u8; 32], derivation: KeyDerivation) -> WalletKeys {
    match derivation {
        KeyDerivation::MfnWalletV1 => wallet_from_seed(seed),
        KeyDerivation::PayoutStealthV1 => WalletKeys::from_stealth(stealth_wallet_from_seed(seed)),
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
    fn owned_cache_hydrate_round_trip() {
        use curve25519_dalek::scalar::Scalar;
        use mfn_crypto::point::{generator_g, generator_h};
        use mfn_wallet::OwnedOutput;
        use mfn_wallet::StoredOwnedOutput;

        let spend = Scalar::from(5u64);
        let blind = Scalar::from(9u64);
        let o = OwnedOutput {
            one_time_addr: generator_g() * spend,
            commit: (generator_g() * blind) + (generator_h() * Scalar::from(1000u64)),
            value: 1000,
            blinding: blind,
            one_time_spend: spend,
            key_image: generator_g() * Scalar::from(3u64),
            tx_id: [0x11u8; 32],
            output_idx: 0,
            height: 1,
        };
        let mut file = WalletFile::new(&[2u8; 32], KeyDerivation::MfnWalletV1);
        file.scan_height = Some(1);
        file.owned_outputs = vec![StoredOwnedOutput::from_owned(&o)];

        let mut wallet = file.to_wallet().expect("wallet");
        file.hydrate_wallet(&mut wallet).expect("hydrate");
        assert_eq!(wallet.balance(), 1000);
        assert!(file.has_owned_cache());
    }

    #[test]
    fn payout_derivation_differs_from_mfn_wallet() {
        let seed = [1u8; 32];
        let a = keys_from_seed(&seed, KeyDerivation::MfnWalletV1);
        let b = keys_from_seed(&seed, KeyDerivation::PayoutStealthV1);
        assert_ne!(a.view_pub().compress(), b.view_pub().compress());
    }
}
