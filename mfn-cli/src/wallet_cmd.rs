//! `mfn-cli wallet` subcommands (**M3.1**–**M3.4**).

use std::path::{Path, PathBuf};

use curve25519_dalek::edwards::EdwardsPoint;
use mfn_consensus::{
    decode_block, decode_chain_checkpoint, encode_transaction, ChainState, Recipient,
};
use mfn_crypto::authorship::MAX_CLAIM_MESSAGE_LEN;
use mfn_crypto::authorship::UNBOUND_COMMIT_HASH;
use mfn_crypto::{crypto_random, point_from_bytes};
use mfn_storage::storage_commitment_hash;
use mfn_wallet::{ClaimingIdentity, TransferRecipient, Wallet, WalletError};
use rand_core::{OsRng, RngCore};

use crate::rpc::RpcClient;
use crate::wallet_store::{
    KeyDerivation, WalletFile, WalletStoreError, DEFAULT_WALLET_PATH, WALLET_FILE_VERSION,
};

/// Default CLSAG ring size (including the real input).
pub const DEFAULT_RING_SIZE: usize = 8;

/// Default transfer fee (atomic units) when `--fee` is omitted.
pub const DEFAULT_TRANSFER_FEE: u64 = 10_000;

/// Default storage replication factor (must be within chain endowment params).
pub const DEFAULT_UPLOAD_REPLICATION: u8 = 3;

/// Default anchor output value for storage uploads (atomic units).
pub const DEFAULT_UPLOAD_ANCHOR_VALUE: u64 = 1_000;

/// Producer tip added on top of `upload_min_fee` when `--fee` is omitted.
pub const DEFAULT_UPLOAD_FEE_TIP: u64 = 1_000;

/// Maximum payload size for `wallet upload` (32 MiB).
pub const MAX_UPLOAD_BYTES: usize = 32 * 1024 * 1024;

/// Default fee for standalone authorship claim txs when `--fee` is omitted.
pub const DEFAULT_CLAIM_FEE: u64 = DEFAULT_TRANSFER_FEE;

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

/// Parameters for `wallet upload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadParams {
    /// Path to file bytes to anchor on-chain.
    pub file_path: PathBuf,
    /// Replication factor (chain endowment params).
    pub replication: u8,
    /// Transaction fee; `None` → `upload_min_fee` + [`DEFAULT_UPLOAD_FEE_TIP`].
    pub fee: Option<u64>,
    /// Value paid to the anchor output (excluding fee).
    pub anchor_value: u64,
    /// Ring size (≥ 2).
    pub ring_size: usize,
    /// Optional `tx.extra` memo bytes.
    pub extra: Vec<u8>,
    /// Anchor recipient view key hex; `None` → pay anchor to this wallet.
    pub anchor_view_hex: Option<String>,
    /// Anchor recipient spend key hex; required with `anchor_view_hex` when not self.
    pub anchor_spend_hex: Option<String>,
    /// MFCL claim message; bound to upload `data_root` + `commit_hash` in `tx.extra`.
    pub message: Option<Vec<u8>>,
}

/// Parameters for `wallet claim`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimParams {
    /// 32-byte `data_root` (64 hex chars).
    pub data_root_hex: String,
    /// Optional storage `commit_hash` (64 hex); `None` → unbound claim.
    pub commit_hash_hex: Option<String>,
    /// Claim message bytes (UTF-8 from `--message` or raw from `--message-hex`).
    pub message: Vec<u8>,
    /// Transaction fee (atomic units).
    pub fee: u64,
    /// Ring size (≥ 2).
    pub ring_size: usize,
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
    let mut file = WalletFile::new(&seed, KeyDerivation::MfnWalletV1);
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
    persist_wallet(path, &mut file, &wallet)?;
    print_scan_summary(
        &stats,
        wallet.scan_height(),
        wallet.balance(),
        wallet.owned_count(),
    );
    println!("wallet_path={}", path.display());
    Ok(())
}

/// `wallet balance` — scan chain then print balance.
pub fn wallet_balance(path: &Path, client: &mut RpcClient) -> Result<(), WalletCmdError> {
    let mut file = WalletFile::load(path)?;
    let mut wallet = file.to_wallet()?;
    let stats = sync_wallet_from_node(&mut wallet, &file, client)?;
    persist_wallet(path, &mut file, &wallet)?;
    print_scan_summary(
        &stats,
        wallet.scan_height(),
        wallet.balance(),
        wallet.owned_count(),
    );
    println!("wallet_path={}", path.display());
    Ok(())
}

/// `wallet status` — print cached UTXO snapshot vs node tip without fetching blocks.
pub fn wallet_status(path: &Path, client: &mut RpcClient) -> Result<(), WalletCmdError> {
    let file = WalletFile::load(path)?;
    let mut wallet = file.to_wallet()?;
    file.hydrate_wallet(&mut wallet)?;
    let tip = client.get_tip()?;
    let tip_height = tip.tip_height.unwrap_or(0);
    let scan_height = file.scan_height.unwrap_or(0);
    let cached = file.has_owned_cache();

    println!("tip_height={tip_height}");
    println!("scan_height={scan_height}");
    println!("utxo_cache={cached}");
    println!("balance_cached={}", wallet.balance());
    println!("owned_count_cached={}", wallet.owned_count());
    println!("pending_spent_count={}", file.pending_spent_utxo_keys.len());
    if tip_height > u64::from(scan_height) {
        println!("sync_needed=true");
        println!("blocks_behind={}", tip_height - u64::from(scan_height));
    } else {
        println!("sync_needed=false");
        println!("blocks_behind=0");
    }
    println!("wallet_path={}", path.display());
    println!("wallet_version={}", file.version);
    Ok(())
}

/// `wallet send` — scan, build CLSAG transfer, `submit_tx`, persist pending spends.
pub fn wallet_send(
    path: &Path,
    client: &mut RpcClient,
    params: &SendParams,
) -> Result<(), WalletCmdError> {
    if params.amount == 0 {
        return Err(WalletCmdError::Usage(
            "amount must be greater than 0".into(),
        ));
    }
    if params.ring_size < 2 {
        return Err(WalletCmdError::Usage("ring-size must be at least 2".into()));
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
    persist_wallet(path, &mut file, &wallet)?;

    let tx_bytes = encode_transaction(&signed.tx);
    let submit = client.submit_tx(&tx_bytes)?;

    println!("tip_height={}", stats.tip_height);
    println!("blocks_scanned={}", stats.blocks_fetched);
    println!("utxo_cache={}", stats.used_utxo_cache);
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

/// `wallet upload` — read file, build storage upload tx, `submit_tx`.
pub fn wallet_upload(
    path: &Path,
    client: &mut RpcClient,
    params: &UploadParams,
) -> Result<(), WalletCmdError> {
    if params.ring_size < 2 {
        return Err(WalletCmdError::Usage("ring-size must be at least 2".into()));
    }
    if params.replication == 0 {
        return Err(WalletCmdError::Usage(
            "replication must be at least 1".into(),
        ));
    }
    let data = std::fs::read(&params.file_path)
        .map_err(|e| WalletCmdError::Usage(format!("read {}: {e}", params.file_path.display())))?;
    if data.is_empty() {
        return Err(WalletCmdError::Usage("upload file is empty".into()));
    }
    if data.len() > MAX_UPLOAD_BYTES {
        return Err(WalletCmdError::Usage(format!(
            "upload file exceeds maximum size ({} bytes > {MAX_UPLOAD_BYTES})",
            data.len()
        )));
    }
    if params.message.is_some() && !params.extra.is_empty() {
        return Err(WalletCmdError::Usage(
            "cannot set both --message (authorship claim) and --extra on upload".into(),
        ));
    }
    if let Some(msg) = &params.message {
        if msg.len() > MAX_CLAIM_MESSAGE_LEN {
            return Err(WalletCmdError::Usage(format!(
                "message length {} exceeds max {MAX_CLAIM_MESSAGE_LEN}",
                msg.len()
            )));
        }
    }

    let anchor_recipient = match (
        params.anchor_view_hex.as_deref(),
        params.anchor_spend_hex.as_deref(),
    ) {
        (None, None) => None,
        (Some(view), Some(spend)) => Some(parse_recipient(view, spend)?),
        _ => {
            return Err(WalletCmdError::Usage(
                "anchor requires both --anchor-view and --anchor-spend (or neither for self-anchor)"
                    .into(),
            ));
        }
    };

    let mut file = WalletFile::load(path)?;
    let mut wallet = file.to_wallet()?;
    file.apply_pending_spends(&mut wallet)?;
    let stats = sync_wallet_from_node(&mut wallet, &file, client)?;
    let chain_state = fetch_chain_state(client)?;

    let fee = match params.fee {
        Some(f) => f,
        None => wallet
            .upload_min_fee(data.len() as u64, params.replication, &chain_state)?
            .saturating_add(DEFAULT_UPLOAD_FEE_TIP),
    };

    let anchor = anchor_recipient.unwrap_or_else(|| wallet.recipient());

    let pre_owned: Vec<[u8; 32]> = wallet.owned().map(|o| o.utxo_key()).collect();
    let mut rng = crypto_random;
    let art = if let Some(message) = &params.message {
        let seed = file.seed_bytes()?;
        let identity = ClaimingIdentity::from_seed(&seed);
        wallet.build_storage_upload_with_authorship(
            &data,
            params.replication,
            fee,
            anchor,
            params.anchor_value,
            None,
            params.ring_size,
            &chain_state,
            message,
            &identity,
            &mut rng,
        )?
    } else {
        wallet.build_storage_upload(
            &data,
            params.replication,
            fee,
            anchor,
            params.anchor_value,
            None,
            params.ring_size,
            &chain_state,
            &params.extra,
            &mut rng,
        )?
    };

    let consumed: Vec<[u8; 32]> = pre_owned
        .into_iter()
        .filter(|k| !wallet.owned().any(|o| o.utxo_key() == *k))
        .collect();
    file.record_pending_spends(&consumed);
    persist_wallet(path, &mut file, &wallet)?;

    let upload_hash = storage_commitment_hash(&art.built.commit);
    let data_root = art.built.commit.data_root;
    let tx_bytes = encode_transaction(&art.signed.tx);
    let submit = client.submit_tx(&tx_bytes)?;

    match mfn_storage_operator::upload_artifact_store::save_upload_artifact(
        path,
        &art.built,
        &data,
        &params.file_path,
        Some(&submit.tx_id),
    ) {
        Ok(meta) => {
            println!("upload_artifact_dir={}", meta.dir.display());
            println!("upload_artifact_payload_bytes={}", meta.payload_bytes);
        }
        Err(e) => {
            eprintln!("warning: could not persist upload artifact: {e}");
        }
    }

    println!("tip_height={}", stats.tip_height);
    println!("blocks_scanned={}", stats.blocks_fetched);
    println!("utxo_cache={}", stats.used_utxo_cache);
    println!("file={}", params.file_path.display());
    println!("bytes={}", data.len());
    println!("replication={}", params.replication);
    println!("anchor_value={}", params.anchor_value);
    println!("fee={fee}");
    println!("min_fee={}", art.min_fee);
    println!("burden={}", art.burden);
    println!("data_root={}", hex::encode(data_root));
    println!("storage_commitment_hash={}", hex::encode(upload_hash));
    if params.message.is_some() {
        println!("authorship_claim=bound");
        println!(
            "claim_message_len={}",
            params.message.as_ref().map_or(0, Vec::len)
        );
    }
    println!("ring_size={}", params.ring_size);
    println!("tx_id={}", submit.tx_id);
    println!("mempool_len={}", submit.pool_len);
    println!("outcome={}", submit.outcome_kind);
    println!("balance_after_upload={}", wallet.balance());
    println!("owned_count_after_upload={}", wallet.owned_count());
    println!("wallet_path={}", path.display());
    eprintln!(
        "note: payload + Merkle metadata saved under upload_artifact_dir for operator prove without --file"
    );
    if submit.outcome_kind != "Fresh" && submit.outcome_kind != "Duplicate" {
        eprintln!(
            "warning: submit_tx outcome is {}; tx may not be in the mempool",
            submit.outcome_kind
        );
    }
    Ok(())
}

/// `wallet claim` — publish a standalone MFCL authorship claim via `submit_tx`.
pub fn wallet_claim(
    path: &Path,
    client: &mut RpcClient,
    params: &ClaimParams,
) -> Result<(), WalletCmdError> {
    if params.ring_size < 2 {
        return Err(WalletCmdError::Usage("ring-size must be at least 2".into()));
    }
    let data_root = parse_hash32(&params.data_root_hex, "data_root")?;
    let commit_hash = match params.commit_hash_hex.as_deref() {
        None => UNBOUND_COMMIT_HASH,
        Some(hex) => parse_hash32(hex, "commit_hash")?,
    };

    let mut file = WalletFile::load(path)?;
    let seed = file.seed_bytes()?;
    let claiming = ClaimingIdentity::from_seed(&seed);
    let mut wallet = file.to_wallet()?;
    file.apply_pending_spends(&mut wallet)?;
    let stats = sync_wallet_from_node(&mut wallet, &file, client)?;
    let chain_state = fetch_chain_state(client)?;

    let pre_owned: Vec<[u8; 32]> = wallet.owned().map(|o| o.utxo_key()).collect();
    let mut rng = crypto_random;
    let signed = wallet.publish_claim_tx(
        &claiming,
        data_root,
        commit_hash,
        &params.message,
        params.fee,
        params.ring_size,
        &chain_state,
        &mut rng,
    )?;

    let consumed: Vec<[u8; 32]> = pre_owned
        .into_iter()
        .filter(|k| !wallet.owned().any(|o| o.utxo_key() == *k))
        .collect();
    file.record_pending_spends(&consumed);
    persist_wallet(path, &mut file, &wallet)?;

    let tx_bytes = encode_transaction(&signed.tx);
    let submit = client.submit_tx(&tx_bytes)?;

    println!("tip_height={}", stats.tip_height);
    println!("blocks_scanned={}", stats.blocks_fetched);
    println!("utxo_cache={}", stats.used_utxo_cache);
    println!(
        "claim_pubkey_hex={}",
        hex::encode(claiming.claim_pubkey().compress().to_bytes())
    );
    println!("data_root={}", hex::encode(data_root));
    println!("commit_hash={}", hex::encode(commit_hash));
    println!("message_len={}", params.message.len());
    println!("fee={}", params.fee);
    println!("ring_size={}", params.ring_size);
    println!("tx_id={}", submit.tx_id);
    println!("mempool_len={}", submit.pool_len);
    println!("outcome={}", submit.outcome_kind);
    println!("balance_after_claim={}", wallet.balance());
    println!("owned_count_after_claim={}", wallet.owned_count());
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

pub(crate) struct SyncStats {
    pub(crate) tip_height: u64,
    pub(crate) blocks_fetched: u32,
    pub(crate) used_utxo_cache: bool,
    /// Max light-follow quorum batch count seen during sync (**M3.12**).
    pub(crate) quorum_batches: usize,
    /// Weak-subjectivity pin was compared at sync start (**M3.13**).
    pub(crate) weak_subjectivity_checked: bool,
    /// Trusted summary was written or refreshed (**M3.13**).
    pub(crate) weak_subjectivity_pinned: bool,
}

pub(crate) fn persist_wallet(
    path: &Path,
    file: &mut WalletFile,
    wallet: &Wallet,
) -> Result<(), WalletCmdError> {
    file.capture_wallet_state(wallet);
    file.save(path)?;
    Ok(())
}

fn sync_wallet_from_node(
    wallet: &mut Wallet,
    file: &WalletFile,
    client: &mut RpcClient,
) -> Result<SyncStats, WalletCmdError> {
    let used_utxo_cache = file.has_owned_cache();
    if used_utxo_cache {
        file.hydrate_wallet(wallet)?;
    }
    file.apply_pending_spends(wallet)?;
    let tip = client.get_tip()?;
    let tip_height = tip.tip_height.unwrap_or(0);
    let start_height = if used_utxo_cache {
        file.scan_height
            .expect("has_owned_cache implies scan_height")
            .saturating_add(1)
    } else {
        1
    };
    let mut blocks_fetched = 0u32;
    if tip_height >= u64::from(start_height) {
        for h in u64::from(start_height)..=tip_height {
            let height = u32::try_from(h)
                .map_err(|_| WalletCmdError::Usage(format!("tip height {h} exceeds u32::MAX")))?;
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
        used_utxo_cache,
        quorum_batches: 1,
        weak_subjectivity_checked: false,
        weak_subjectivity_pinned: false,
    })
}

fn fetch_chain_state(client: &mut RpcClient) -> Result<ChainState, WalletCmdError> {
    let bytes = client.get_checkpoint()?;
    let cp = decode_chain_checkpoint(&bytes)
        .map_err(|e| WalletCmdError::Usage(format!("decode chain checkpoint: {e}")))?;
    Ok(cp.state)
}

fn parse_recipient(view_hex: &str, spend_hex: &str) -> Result<Recipient, WalletCmdError> {
    Ok(Recipient {
        view_pub: parse_compressed_point(view_hex, "view_pub")?,
        spend_pub: parse_compressed_point(spend_hex, "spend_pub")?,
    })
}

fn parse_hash32(hex_str: &str, field: &str) -> Result<[u8; 32], WalletCmdError> {
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
    let bytes =
        hex::decode(t).map_err(|e| WalletCmdError::Usage(format!("{field} hex decode: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| WalletCmdError::Usage(format!("{field} must be 32 bytes")))
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
    let bytes =
        hex::decode(t).map_err(|e| WalletCmdError::Usage(format!("{field} hex decode: {e}")))?;
    point_from_bytes(&bytes)
        .map_err(|e| WalletCmdError::Usage(format!("{field} is not a valid Edwards point: {e}")))
}

pub(crate) fn print_scan_summary(
    stats: &SyncStats,
    scan_height: Option<u32>,
    balance: u64,
    owned: usize,
) {
    println!("tip_height={}", stats.tip_height);
    println!("blocks_scanned={}", stats.blocks_fetched);
    println!("utxo_cache={}", stats.used_utxo_cache);
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
    println!(
        "key_derivation={}",
        key_derivation_label(file.key_derivation)
    );
    Ok(())
}
