//! `mfn-cli wallet` subcommands (**M3.1** / **M3.2**).

use std::path::{Path, PathBuf};

use curve25519_dalek::edwards::EdwardsPoint;
use mfn_consensus::{
    decode_block, decode_chain_checkpoint, encode_transaction, Recipient, ChainState,
};
use mfn_crypto::{crypto_random, point_from_bytes};
use mfn_wallet::{TransferRecipient, Wallet, WalletError};
use rand_core::{OsRng, RngCore};

use crate::rpc::RpcClient;
use crate::wallet_store::{
    KeyDerivation, WalletFile, WalletStoreError, DEFAULT_WALLET_PATH, WALLET_FILE_VERSION,
};

/// Default CLSAG ring size (including the real input).
pub const DEFAULT_RING_SIZE: usize = 8;

/// Default transfer fee (atomic units) when `--fee` is omitted.
pub const DEFAULT_TRANSFER_FEE: u64 = 10_000;

/// Wallet command errors.
#[derive(Debug, thiserror::Error)]
pub enum WalletCmdError {
    /// Wallet file error.
    #[error("{0}")]
    Store(#[from] WalletStoreError),
    /// Node RPC error.
    #[error("{0}")]
    Rpc(#[from] crate::rpc::RpcError),
    /// Wallet build / coin-selection error.
    #[error("{0}")]
    Wallet(#[from] WalletError),
    /// Usage / validation.
    #[error("{0}")]
    Usage(String),
}

/// Parameters for `wallet send`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendParams {
    /// Recipient view public key (32-byte compressed hex).
    pub to_view_hex: String,
    /// Recipient spend public key (32-byte compressed hex).
    pub to_spend_hex: String,
    /// Amount to pay (atomic units, excluding fee).
    pub amount: u64,
    /// Transaction fee (atomic units).
    pub fee: u64,
    /// Ring size (≥ 2, includes real input).
    pub ring_size: usize,
    /// Optional `tx.extra` memo bytes (hex).
    pub extra: Vec<u8>,
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
    let stats = sync_wallet_from_node(&mut wallet, &file, client)?;
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
    let stats = sync_wallet_from_node(&mut wallet, &file, client)?;
    file.scan_height = wallet.scan_height();
    file.save(path)?;
    print_scan_summary(&stats, wallet.scan_height(), wallet.balance(), wallet.owned_count());
    println!("balance={}", wallet.balance());
    println!("owned_count={}", wallet.owned_count());
    println!("wallet_path={}", path.display());
    Ok(())
}

/// `wallet send` — scan, build CLSAG transfer, `submit_tx`, persist pending spends.
pub fn wallet_send(
    path: &Path,
    client: &mut RpcClient,
    params: &SendParams,
) -> Result<(), WalletCmdError> {
    if params.amount == 0 {
        return Err(WalletCmdError::Usage("amount must be greater than 0".into()));
    }
    if params.ring_size < 2 {
        return Err(WalletCmdError::Usage(
            "ring-size must be at least 2".into(),
        ));
    }
    let recipient = parse_recipient(&params.to_view_hex, &params.to_spend_hex)?;
    let mut file = WalletFile::load(path)?;
    let mut wallet = file.to_wallet()?;
    file.apply_pending_spends(&mut wallet)?;
    let stats = sync_wallet_from_node(&mut wallet, &file, client)?;
    let chain_state = fetch_chain_state(client)?;

    let pre_owned: Vec<[u8; 32]> = wallet.owned().map(|o| o.utxo_key()).collect();
    let mut rng = crypto_random;
    let signed = wallet.build_transfer(
        &[TransferRecipient {
            recipient,
            value: params.amount,
        }],
        params.fee,
        params.ring_size,
        &chain_state,
        &params.extra,
        &mut rng,
    )?;

    let consumed: Vec<[u8; 32]> = pre_owned
        .into_iter()
        .filter(|k| !wallet.owned().any(|o| o.utxo_key() == *k))
        .collect();
    file.record_pending_spends(&consumed);
    file.scan_height = wallet.scan_height();
    file.save(path)?;

    let tx_bytes = encode_transaction(&signed.tx);
    let submit = client.submit_tx(&tx_bytes)?;

    println!("tip_height={}", stats.tip_height);
    println!("blocks_scanned={}", stats.blocks_fetched);
    println!("amount={}", params.amount);
    println!("fee={}", params.fee);
    println!("ring_size={}", params.ring_size);
    println!("tx_id={}", submit.tx_id);
    println!("mempool_len={}", submit.pool_len);
    println!("outcome={}", submit.outcome_kind);
    println!("balance_after_send={}", wallet.balance());
    println!("owned_count_after_send={}", wallet.owned_count());
    println!("wallet_path={}", path.display());
    if submit.outcome_kind != "Fresh" && submit.outcome_kind != "Duplicate" {
        eprintln!(
            "warning: submit_tx outcome is {}; tx may not be in the mempool",
            submit.outcome_kind
        );
    }
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
    file: &WalletFile,
    client: &mut RpcClient,
) -> Result<SyncStats, WalletCmdError> {
    file.apply_pending_spends(wallet)?;
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
    file.apply_pending_spends(wallet)?;
    Ok(SyncStats {
        tip_height,
        blocks_fetched,
    })
}

fn fetch_chain_state(client: &mut RpcClient) -> Result<ChainState, WalletCmdError> {
    let bytes = client.get_checkpoint()?;
    let cp = decode_chain_checkpoint(&bytes).map_err(|e| {
        WalletCmdError::Usage(format!("decode chain checkpoint: {e}"))
    })?;
    Ok(cp.state)
}

fn parse_recipient(view_hex: &str, spend_hex: &str) -> Result<Recipient, WalletCmdError> {
    Ok(Recipient {
        view_pub: parse_compressed_point(view_hex, "view_pub")?,
        spend_pub: parse_compressed_point(spend_hex, "spend_pub")?,
    })
}

fn parse_compressed_point(hex_str: &str, field: &str) -> Result<EdwardsPoint, WalletCmdError> {
    let t = hex_str.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() != 64 {
        return Err(WalletCmdError::Usage(format!(
            "{field} must be 64 hex characters (got {})",
            t.len()
        )));
    }
    let bytes = hex::decode(t)
        .map_err(|e| WalletCmdError::Usage(format!("{field} hex decode: {e}")))?;
    point_from_bytes(&bytes)
        .map_err(|e| WalletCmdError::Usage(format!("{field} is not a valid Edwards point: {e}")))
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
