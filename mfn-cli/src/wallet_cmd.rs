//! `mfn-cli wallet` subcommands (**M3.1**).

use std::path::{Path, PathBuf};

use mfn_consensus::decode_block;
use mfn_wallet::Wallet;
use rand_core::{OsRng, RngCore};

use crate::rpc::RpcClient;
use crate::wallet_store::{KeyDerivation, WalletFile, WalletStoreError, DEFAULT_WALLET_PATH, WALLET_FILE_VERSION};

/// Wallet command errors.
#[derive(Debug, thiserror::Error)]
pub enum WalletCmdError {
    /// Wallet file error.
    #[error("{0}")]
    Store(#[from] WalletStoreError),
    /// Node RPC error.
    #[error("{0}")]
    Rpc(#[from] crate::rpc::RpcError),
    /// Usage / validation.
    #[error("{0}")]
    Usage(String),
}

/// `wallet new` — generate seed and write wallet file.
pub fn wallet_new(path: &Path, force: bool) -> Result<(), WalletCmdError> {
    if path.exists() && !force {
        return Err(WalletCmdError::Usage(format!(
            "wallet file already exists at {}; pass --force to overwrite",
            path.display()
        )));
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let file = WalletFile::new(&seed, KeyDerivation::MfnWalletV1);
    file.save(path)?;
    print_address_lines(&file)?;
    println!("wallet_path={}", path.display());
    println!("wallet_version={WALLET_FILE_VERSION}");
    eprintln!(
        "warning: back up wallet file and seed_hex; loss of either means permanent loss of funds"
    );
    Ok(())
}

/// `wallet address` — print receive pubkeys from wallet file.
pub fn wallet_address(path: &Path) -> Result<(), WalletCmdError> {
    let file = WalletFile::load(path)?;
    print_address_lines(&file)?;
    println!("wallet_path={}", path.display());
    if let Some(h) = file.scan_height {
        println!("scan_height={h}");
    }
    Ok(())
}

/// `wallet scan` — ingest blocks from the node through chain tip.
pub fn wallet_scan(path: &Path, client: &mut RpcClient) -> Result<(), WalletCmdError> {
    let mut file = WalletFile::load(path)?;
    let mut wallet = file.to_wallet()?;
    let stats = sync_wallet_from_node(&mut wallet, client)?;
    file.scan_height = wallet.scan_height();
    file.save(path)?;
    print_scan_summary(&stats, wallet.scan_height(), wallet.balance(), wallet.owned_count());
    println!("wallet_path={}", path.display());
    Ok(())
}

/// `wallet balance` — scan chain then print balance.
pub fn wallet_balance(path: &Path, client: &mut RpcClient) -> Result<(), WalletCmdError> {
    let mut file = WalletFile::load(path)?;
    let mut wallet = file.to_wallet()?;
    let stats = sync_wallet_from_node(&mut wallet, client)?;
    file.scan_height = wallet.scan_height();
    file.save(path)?;
    print_scan_summary(&stats, wallet.scan_height(), wallet.balance(), wallet.owned_count());
    println!("balance={}", wallet.balance());
    println!("owned_count={}", wallet.owned_count());
    println!("wallet_path={}", path.display());
    Ok(())
}

/// Resolve `--wallet` or default [`DEFAULT_WALLET_PATH`].
pub fn resolve_wallet_path(opt: Option<&str>) -> PathBuf {
    opt.map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WALLET_PATH))
}

struct SyncStats {
    tip_height: u64,
    blocks_fetched: u32,
}

fn sync_wallet_from_node(
    wallet: &mut Wallet,
    client: &mut RpcClient,
) -> Result<SyncStats, WalletCmdError> {
    let tip = client.get_tip()?;
    let tip_height = tip.tip_height.unwrap_or(0);
    let mut blocks_fetched = 0u32;
    if tip_height >= 1 {
        for h in 1..=tip_height {
            let height = u32::try_from(h).map_err(|_| {
                WalletCmdError::Usage(format!("tip height {h} exceeds u32::MAX"))
            })?;
            let raw = client.get_block(height)?;
            let block = decode_block(&raw).map_err(|e| {
                WalletCmdError::Usage(format!("decode block at height {height}: {e}"))
            })?;
            wallet.ingest_block(&block);
            blocks_fetched = blocks_fetched.saturating_add(1);
        }
    }
    Ok(SyncStats {
        tip_height,
        blocks_fetched,
    })
}

fn print_scan_summary(stats: &SyncStats, scan_height: Option<u32>, balance: u64, owned: usize) {
    println!("tip_height={}", stats.tip_height);
    println!("blocks_scanned={}", stats.blocks_fetched);
    if let Some(h) = scan_height {
        println!("scan_height={h}");
    }
    println!("balance={balance}");
    println!("owned_count={owned}");
}

fn key_derivation_label(d: KeyDerivation) -> &'static str {
    match d {
        KeyDerivation::MfnWalletV1 => "mfn_wallet_v1",
        KeyDerivation::PayoutStealthV1 => "payout_stealth_v1",
    }
}

fn print_address_lines(file: &WalletFile) -> Result<(), WalletCmdError> {
    let wallet = file.to_wallet()?;
    let keys = wallet.keys();
    println!(
        "view_pub_hex={}",
        hex::encode(keys.view_pub().compress().to_bytes())
    );
    println!(
        "spend_pub_hex={}",
        hex::encode(keys.spend_pub().compress().to_bytes())
    );
    println!("key_derivation={}", key_derivation_label(file.key_derivation));
    Ok(())
}
