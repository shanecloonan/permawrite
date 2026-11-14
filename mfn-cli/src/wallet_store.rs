//! On-disk wallet file (seed + optional scan checkpoint).

use std::fs;
use std::path::Path;

use mfn_crypto::stealth::stealth_wallet_from_seed;
use mfn_wallet::{wallet_from_seed, StoredOwnedOutput, Wallet, WalletKeys};
use serde::{Deserialize, Serialize};

use crate::rpc::LightCheckpointSummary;
use crate::wallet_seal::{self, HeldPassphrase, SealedSeed};

/// Current wallet file schema version for an unlocked file.
pub const WALLET_FILE_VERSION: u32 = 2;

/// Schema version written when the seed is sealed.
pub const WALLET_FILE_VERSION_SEALED: u32 = 4;

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
    /// Empty on disk when [`Self::seed_lock`] is set.
    pub seed_hex: String,
    /// Passphrase seal. Absent on unlocked files.
    #[serde(default)]
    pub seed_lock: Option<crate::wallet_seal::SeedLockRecord>,
    /// Passphrase kept in memory so a later save stays sealed.
    #[serde(skip)]
    pub(crate) passphrase: Option<HeldPassphrase>,
    /// The on-disk seal was PBKDF2 and the next save must rewrite it.
    #[serde(skip)]
    pub(crate) migrated_from_pbkdf2: bool,
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
    /// Pinned weak-subjectivity summary for light-scan (**M3.13**).
    #[serde(default)]
    pub trusted_light_summary: Option<LightCheckpointSummary>,
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
            seed_lock: None,
            passphrase: None,
            migrated_from_pbkdf2: false,
            key_derivation,
            scan_height: None,
            pending_spent_utxo_keys: Vec::new(),
            owned_outputs: Vec::new(),
            light_checkpoint_hex: None,
            trusted_light_summary: None,
        }
    }

    /// Whether a persisted UTXO snapshot can skip replaying old blocks.
    pub fn has_owned_cache(&self) -> bool {
        self.scan_height.is_some() && !self.owned_outputs.is_empty()
    }

    /// Restore scan height + cached owned outputs into `wallet`.
    ///
    /// Always restores `scan_height` when present — even with an empty UTXO set —
    /// so a no-op light-sync (already at tip) cannot wipe resume height via
    /// [`Self::capture_wallet_state`]. Wiping `scan_height` while keeping a pinned
    /// `trusted_light_summary` caused Nightly **B-29** (`trusted N vs checkpoint 0`).
    pub fn hydrate_wallet(&self, wallet: &mut Wallet) -> Result<(), WalletStoreError> {
        let Some(height) = self.scan_height else {
            return Ok(());
        };
        wallet
            .load_owned_snapshot(&self.owned_outputs, height)
            .map_err(|e| WalletStoreError::Invalid(e.to_string()))
    }

    /// Persist current wallet UTXO set and scan height into this file descriptor.
    ///
    /// If the in-memory wallet was never hydrated/scanned (`scan_height` is `None`),
    /// keep the on-disk resume height and UTXO cache instead of clearing them.
    pub fn capture_wallet_state(&mut self, wallet: &Wallet) {
        match wallet.scan_height() {
            Some(h) => {
                self.scan_height = Some(h);
                self.owned_outputs = wallet.export_owned_snapshot();
            }
            None => {
                // No-op sync path: do not clobber file.scan_height / owned_outputs.
            }
        }
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

    /// Whether the seed is sealed.
    pub fn is_locked(&self) -> bool {
        self.seed_lock.is_some() || self.passphrase.is_some()
    }

    /// Remember a passphrase so the next [`Self::save`] seals the seed.
    pub fn lock_with_passphrase(&mut self, passphrase: &str) -> Result<(), WalletStoreError> {
        let _ = self.seed_bytes()?;
        self.passphrase = Some(
            HeldPassphrase::new(passphrase)
                .map_err(|e| WalletStoreError::Invalid(e.to_string()))?,
        );
        Ok(())
    }

    /// Drop the seal. The next save writes the seed in plaintext.
    pub fn unlock_in_memory(&mut self) {
        self.passphrase = None;
        self.seed_lock = None;
        self.version = WALLET_FILE_VERSION;
    }

    /// Write JSON to `path` (pretty-printed, mode 0600 on Unix).
    ///
    /// A locked wallet is sealed again on the way to disk. A PBKDF2 seal is
    /// rewritten as Argon2id. The seed stays in memory.
    pub fn save(&mut self, path: &Path) -> Result<(), WalletStoreError> {
        let memory_seed = self.seed_hex.clone();
        if let Some(pass) = self.passphrase.clone() {
            let seed = self.seed_bytes()?;
            let sealed = wallet_seal::seal_seed(&seed, pass.as_str())
                .map_err(|e| WalletStoreError::Invalid(e.to_string()))?;
            self.seed_hex.clear();
            self.seed_lock = Some(sealed.to_record());
            self.version = WALLET_FILE_VERSION_SEALED;
        } else {
            self.seed_lock = None;
            self.version = WALLET_FILE_VERSION;
        }
        let write_result = self.write_json(path);
        self.seed_hex = memory_seed;
        write_result
    }

    fn write_json(&self, path: &Path) -> Result<(), WalletStoreError> {
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
    ///
    /// A sealed file opens with `MFN_WALLET_PASSPHRASE`.
    pub fn load(path: &Path) -> Result<Self, WalletStoreError> {
        let bytes = fs::read(path)?;
        let mut file: WalletFile = serde_json::from_slice(&bytes)?;
        if file.seed_lock.is_some() {
            let pass = wallet_seal::passphrase_from_env()
                .map_err(|e| WalletStoreError::Invalid(e.to_string()))?;
            file.open_with(pass)?;
        }
        file.validate()?;
        Ok(file)
    }

    /// Open a sealed file with an explicit passphrase.
    pub fn load_with_passphrase(path: &Path, passphrase: &str) -> Result<Self, WalletStoreError> {
        let bytes = fs::read(path)?;
        let mut file: WalletFile = serde_json::from_slice(&bytes)?;
        if file.seed_lock.is_none() {
            return Err(WalletStoreError::Invalid(
                "wallet file is not locked".into(),
            ));
        }
        let pass = HeldPassphrase::new(passphrase)
            .map_err(|e| WalletStoreError::Invalid(e.to_string()))?;
        file.open_with(pass)?;
        file.validate()?;
        Ok(file)
    }

    fn open_with(&mut self, pass: HeldPassphrase) -> Result<(), WalletStoreError> {
        let record = self
            .seed_lock
            .clone()
            .ok_or_else(|| WalletStoreError::Invalid("wallet file is not locked".into()))?;
        let sealed = SealedSeed::from_record(&record)
            .map_err(|e| WalletStoreError::Invalid(e.to_string()))?;
        let seed = wallet_seal::open_seed(&sealed, pass.as_str())
            .map_err(|e| WalletStoreError::Invalid(e.to_string()))?;
        self.seed_hex = hex::encode(seed);
        self.migrated_from_pbkdf2 = sealed.needs_argon2_migration();
        self.passphrase = Some(pass);
        Ok(())
    }

    fn validate(&self) -> Result<(), WalletStoreError> {
        if self.version != 1
            && self.version != WALLET_FILE_VERSION
            && self.version != WALLET_FILE_VERSION_SEALED
        {
            return Err(WalletStoreError::Invalid(format!(
                "unsupported wallet version {} (expected 1, {WALLET_FILE_VERSION}, or {WALLET_FILE_VERSION_SEALED})",
                self.version
            )));
        }
        if self.seed_lock.is_some() && self.passphrase.is_none() && self.seed_hex.is_empty() {
            return Err(WalletStoreError::Invalid(
                "this wallet is locked. Set MFN_WALLET_PASSPHRASE in the environment".into(),
            ));
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
    fn argon2id_lock_hides_the_seed_and_pbkdf2_files_migrate() {
        let path = std::env::temp_dir().join(format!(
            "mfn-argon-lock-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let seed = [0x5au8; 32];
        let mut file = WalletFile::new(&seed, KeyDerivation::MfnWalletV1);
        file.lock_with_passphrase("correct horse").expect("lock");
        file.save(&path).expect("save");
        let on_disk = std::fs::read_to_string(&path).expect("read");
        assert!(!on_disk.contains(&hex::encode(seed)));
        assert!(on_disk.contains("argon2id"));
        assert!(!format!("{file:?}").contains("correct horse"));
        let err = WalletFile::load(&path).expect_err("no passphrase");
        assert!(err.to_string().contains("MFN_WALLET_PASSPHRASE"));
        let opened = WalletFile::load_with_passphrase(&path, "correct horse").expect("open");
        assert_eq!(opened.seed_bytes().expect("seed"), seed);

        let legacy = crate::wallet_seal::seal_seed_pbkdf2_for_migration(&seed, "correct horse")
            .expect("legacy");
        let mut legacy_file = WalletFile::new(&seed, KeyDerivation::MfnWalletV1);
        legacy_file.seed_hex.clear();
        legacy_file.seed_lock = Some(legacy.to_record());
        legacy_file.version = WALLET_FILE_VERSION_SEALED;
        let legacy_path = path.with_extension("legacy.json");
        legacy_file.write_json(&legacy_path).expect("write legacy");
        let mut migrated =
            WalletFile::load_with_passphrase(&legacy_path, "correct horse").expect("migrate open");
        assert!(migrated.migrated_from_pbkdf2);
        assert_eq!(migrated.seed_bytes().expect("seed"), seed);
        migrated.save(&legacy_path).expect("rewrite");
        let rewritten = std::fs::read_to_string(&legacy_path).expect("read rewrite");
        assert!(rewritten.contains("argon2id"));
        assert!(!rewritten.contains("pbkdf2"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&legacy_path);
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
    fn hydrate_restores_scan_height_with_empty_owned_cache() {
        let mut file = WalletFile::new(&[4u8; 32], KeyDerivation::MfnWalletV1);
        file.scan_height = Some(4);
        file.owned_outputs.clear();
        assert!(!file.has_owned_cache());

        let mut wallet = file.to_wallet().expect("wallet");
        assert_eq!(wallet.scan_height(), None);
        file.hydrate_wallet(&mut wallet).expect("hydrate");
        assert_eq!(wallet.scan_height(), Some(4));
        assert_eq!(wallet.balance(), 0);
    }

    #[test]
    fn capture_wallet_state_preserves_scan_height_when_wallet_unscanned() {
        let mut file = WalletFile::new(&[5u8; 32], KeyDerivation::MfnWalletV1);
        file.scan_height = Some(4);
        file.owned_outputs.clear();

        let wallet = file.to_wallet().expect("wallet");
        assert_eq!(wallet.scan_height(), None);
        file.capture_wallet_state(&wallet);
        assert_eq!(
            file.scan_height,
            Some(4),
            "no-op persist must not wipe resume height (B-29)"
        );
    }

    #[test]
    fn trusted_light_summary_round_trips_in_json() {
        use crate::rpc::LightCheckpointSummary;

        let mut file = WalletFile::new(&[3u8; 32], KeyDerivation::MfnWalletV1);
        file.trusted_light_summary = Some(LightCheckpointSummary {
            genesis_id: "aa".repeat(32),
            tip_height: 0,
            tip_block_id: "bb".repeat(32),
            validator_count: 0,
            validator_set_root: "cc".repeat(32),
            checkpoint_digest: "dd".repeat(32),
            anchor_peers: vec!["203.0.113.10:8333".into()],
        });
        let raw = serde_json::to_string(&file).expect("json");
        let back: WalletFile = serde_json::from_str(&raw).expect("parse");
        assert_eq!(back.trusted_light_summary, file.trusted_light_summary);
    }

    #[test]
    fn payout_derivation_differs_from_mfn_wallet() {
        let seed = [1u8; 32];
        let a = keys_from_seed(&seed, KeyDerivation::MfnWalletV1);
        let b = keys_from_seed(&seed, KeyDerivation::PayoutStealthV1);
        assert_ne!(a.view_pub().compress(), b.view_pub().compress());
    }
}
