//! Light-wallet sync for `mfn-cli wallet light-scan` (**M3.11**–**M3.21**).
//!
//! Verifies BLS headers + validator-set evolution via [`mfn_light::LightChain`],
//! scans txs via `get_block_txs` (no full blocks), matching the browser demo path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use mfn_consensus::{
    block_id, decode_block_header, decode_bond_op, decode_evidence, decode_transaction,
    verify_header, Block, BondOp, SlashEvidence,
};
use mfn_light::{LightChain, LightChainError};
use mfn_wallet::Wallet;

use crate::checkpoint_log::{
    cross_check_summary_against_checkpoint_log, CheckpointLogCrossCheckReport,
};
use crate::light_follow_quorum::light_follow_pages_quorum;
use crate::light_subjectivity::{
    load_trusted_summary_file, summary_from_checkpoint_hex, weak_subjectivity_agrees,
};
use crate::rpc::{LightCheckpointSummary, LightFollowPage, RpcClient};
use crate::wallet_cmd::{persist_wallet, print_scan_summary, SyncStats, WalletCmdError};
use crate::wallet_store::WalletFile;

/// Max inclusive span per `get_block_headers` / `get_light_follow` batch.
const LIGHT_SCAN_CHUNK: u32 = 512;

/// Options for `wallet light-scan` (**M3.12**–**M3.21**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightScanParams {
    /// Extra `HOST:PORT` RPC bases for `get_light_follow` quorum (M4.14).
    pub quorum_rpc_addrs: Vec<String>,
    /// P2P peers for `get_light_follow_p2p` on the primary `--rpc` node (M4.15).
    pub quorum_p2p_peers: Vec<String>,
    /// Verify against this summary file without persisting it (**M3.13**).
    pub trusted_summary_path: Option<PathBuf>,
    /// Pin summary from file into `wallet.json` before sync (**M3.18**).
    pub import_trusted_summary_path: Option<PathBuf>,
    /// Clear `trusted_light_summary` in the wallet file before sync.
    pub reset_trusted_summary: bool,
    /// TOFU-pin summary from RPC/bootstrap when none is stored yet.
    pub pin_trusted_summary: bool,
    /// Refresh pinned summary from the post-sync checkpoint (default browser behavior).
    pub update_trusted_summary: bool,
    /// Stop after this inclusive height even if the node tip is higher (**M3.21**).
    pub max_height: Option<u32>,
    /// Cross-check post-sync summary against signed checkpoint log (**F12** phase 2).
    pub checkpoint_log_path: Option<PathBuf>,
}

impl Default for LightScanParams {
    fn default() -> Self {
        Self {
            quorum_rpc_addrs: Vec::new(),
            quorum_p2p_peers: Vec::new(),
            trusted_summary_path: None,
            import_trusted_summary_path: None,
            reset_trusted_summary: false,
            pin_trusted_summary: false,
            update_trusted_summary: true,
            max_height: None,
            checkpoint_log_path: None,
        }
    }
}

fn scan_through_height(
    tip_height: u64,
    start_height: u32,
    max_height: Option<u32>,
) -> Result<u64, WalletCmdError> {
    let mut through = tip_height;
    if let Some(cap) = max_height {
        if cap == 0 {
            return Err(WalletCmdError::Usage(
                "wallet light-scan --max-height must be >= 1".into(),
            ));
        }
        if u64::from(cap) < u64::from(start_height) {
            return Err(WalletCmdError::Usage(format!(
                "wallet light-scan --max-height {cap} is below resume height {start_height}"
            )));
        }
        through = through.min(u64::from(cap));
    }
    Ok(through)
}

/// `wallet light-scan` — header + evolution verified sync through chain tip.
pub fn wallet_light_scan(
    path: &Path,
    client: &mut RpcClient,
    params: &LightScanParams,
) -> Result<(), WalletCmdError> {
    let mut file = WalletFile::load(path)?;
    let mut wallet = file.to_wallet()?;
    let stats = sync_wallet_light_from_node(&mut wallet, &mut file, client, params)?;
    persist_wallet(path, &mut file, &wallet)?;
    print_scan_summary(
        &stats,
        wallet.scan_height(),
        wallet.balance(),
        wallet.owned_count(),
    );
    println!("sync_mode=light");
    println!("light_follow_quorum_batches={}", stats.quorum_batches);
    if stats.weak_subjectivity_checked {
        println!("weak_subjectivity=checked");
    }
    if stats.weak_subjectivity_pinned {
        println!("weak_subjectivity=pinned");
    }
    if let Some(ref report) = stats.checkpoint_log_cross_check {
        println!("checkpoint_log=matched");
        println!(
            "checkpoint_log_signers={}",
            report.matching_signer_ids.join(",")
        );
        println!(
            "checkpoint_log_entries_at_height={}",
            report.entries_at_height
        );
    }
    println!(
        "light_checkpoint_tip={}",
        file.light_checkpoint_hex
            .as_ref()
            .map(|_| file.scan_height.unwrap_or(0))
            .unwrap_or(0)
    );
    println!("wallet_path={}", path.display());
    Ok(())
}

fn sync_wallet_light_from_node(
    wallet: &mut Wallet,
    file: &mut WalletFile,
    client: &mut RpcClient,
    params: &LightScanParams,
) -> Result<SyncStats, WalletCmdError> {
    let used_utxo_cache = file.has_owned_cache();
    if used_utxo_cache {
        file.hydrate_wallet(wallet)?;
    }
    file.apply_pending_spends(wallet)?;

    let tip = client.get_tip()?;
    let chain_tip_height = tip.tip_height.unwrap_or(0);
    let start_height = if used_utxo_cache {
        file.scan_height
            .expect("has_owned_cache implies scan_height")
            .saturating_add(1)
    } else {
        1
    };

    if params.reset_trusted_summary {
        file.trusted_light_summary = None;
    }

    if let Some(import_path) = &params.import_trusted_summary_path {
        let summary = load_trusted_summary_file(import_path)?;
        if let Some(cp_hex) = file.light_checkpoint_hex.as_ref() {
            weak_subjectivity_agrees(&summary, cp_hex).map_err(|e| {
                WalletCmdError::Usage(format!(
                    "import trusted summary disagrees with wallet checkpoint: {e}"
                ))
            })?;
        }
        file.trusted_light_summary = Some(summary);
    }

    let scan_through = scan_through_height(chain_tip_height, start_height, params.max_height)?;

    if scan_through < u64::from(start_height) {
        let (weak_subjectivity_checked, mut weak_subjectivity_pinned) =
            gate_weak_subjectivity(file, params)?;
        if refresh_trusted_summary_from_checkpoint(file, params)? {
            weak_subjectivity_pinned = true;
        }
        let checkpoint_log_cross_check = cross_check_checkpoint_log_if_requested(file, params)?;
        file.apply_pending_spends(wallet)?;
        return Ok(SyncStats {
            tip_height: chain_tip_height,
            blocks_fetched: 0,
            used_utxo_cache,
            quorum_batches: 1,
            weak_subjectivity_checked,
            weak_subjectivity_pinned,
            checkpoint_log_cross_check,
        });
    }

    let mut light = bootstrap_light_chain(client, file, start_height, params)?;
    let (weak_subjectivity_checked, mut weak_subjectivity_pinned) =
        gate_weak_subjectivity(file, params)?;

    let mut blocks_fetched = 0u32;
    let mut quorum_batches = 1usize;
    let mut from = u64::from(start_height);

    while from <= scan_through {
        let chunk_end = from
            .saturating_add(u64::from(LIGHT_SCAN_CHUNK))
            .saturating_sub(1)
            .min(scan_through);
        let from_h = u32::try_from(from)
            .map_err(|_| WalletCmdError::Usage(format!("height {from} exceeds u32::MAX")))?;
        let to_h = u32::try_from(chunk_end)
            .map_err(|_| WalletCmdError::Usage(format!("height {chunk_end} exceeds u32::MAX")))?;

        let headers_page = client.get_block_headers(from_h, to_h)?;
        let (follow_page, batch_count) =
            fetch_light_follow_with_quorum(client, from_h, to_h, params)?;
        quorum_batches = quorum_batches.max(batch_count);
        let genesis_id = parse_block_id_hex(&headers_page.genesis_id)?;
        let mut expected_prev = if from_h == 1 {
            genesis_id
        } else {
            *light.tip_id()
        };

        let follow_by_height: HashMap<u32, _> =
            follow_page.rows.iter().map(|r| (r.height, r)).collect();

        for row in &headers_page.headers {
            let h = row.height;
            let prev_block_id = parse_block_id_hex(&row.prev_block_id)?;
            if prev_block_id != expected_prev {
                return Err(WalletCmdError::Usage(format!(
                    "prev_block_id mismatch at height {h}"
                )));
            }
            let follow = follow_by_height.get(&h).ok_or_else(|| {
                WalletCmdError::Usage(format!("get_light_follow missing height {h}"))
            })?;

            let header_bytes = decode_hex(&row.header_hex, "header_hex")?;
            let header = decode_block_header(&header_bytes)
                .map_err(|e| WalletCmdError::Usage(format!("decode header at height {h}: {e}")))?;

            verify_header(&header, light.trusted_validators(), light.params())
                .map_err(|e| WalletCmdError::Usage(format!("verify_header at height {h}: {e}")))?;

            let computed_id = block_id(&header);
            let rpc_id = parse_block_id_hex(&row.block_id)?;
            if computed_id != rpc_id {
                return Err(WalletCmdError::Usage(format!(
                    "block_id mismatch at height {h}"
                )));
            }
            expected_prev = computed_id;

            let txs_page = client.get_block_txs(h)?;
            let mut txs = Vec::with_capacity(txs_page.txs.len());
            for t in &txs_page.txs {
                let wire = decode_hex(&t.tx_hex, "tx_hex")?;
                txs.push(
                    decode_transaction(&wire).map_err(|e| {
                        WalletCmdError::Usage(format!("decode tx at height {h}: {e}"))
                    })?,
                );
            }

            let block = Block {
                header: header.clone(),
                txs,
                slashings: Vec::new(),
                bond_ops: Vec::new(),
                storage_proofs: Vec::new(),
                storage_operator_ops: Vec::new(),
            };
            wallet.ingest_block(&block);

            let slashings = decode_slashings(follow)?;
            let bond_ops = decode_bond_ops(follow)?;
            light
                .apply_trusted_evolution(&header, &slashings, &bond_ops)
                .map_err(|e| light_apply_err(h, e))?;

            blocks_fetched = blocks_fetched.saturating_add(1);
        }

        from = chunk_end.saturating_add(1);
        file.light_checkpoint_hex = Some(hex::encode(light.encode_checkpoint()));
    }

    if refresh_trusted_summary_from_checkpoint(file, params)? {
        weak_subjectivity_pinned = true;
    }

    let checkpoint_log_cross_check = cross_check_checkpoint_log_if_requested(file, params)?;

    file.apply_pending_spends(wallet)?;
    Ok(SyncStats {
        tip_height: chain_tip_height,
        blocks_fetched,
        used_utxo_cache,
        quorum_batches,
        weak_subjectivity_checked,
        weak_subjectivity_pinned,
        checkpoint_log_cross_check,
    })
}

fn gate_weak_subjectivity(
    file: &mut WalletFile,
    params: &LightScanParams,
) -> Result<(bool, bool), WalletCmdError> {
    let mut checked = false;
    let mut pinned = false;
    if let Some(cp_hex) = file.light_checkpoint_hex.as_ref() {
        let trusted = resolve_trusted_summary(file, params)?;
        if let Some(ref summary) = trusted {
            weak_subjectivity_agrees(summary, cp_hex)
                .map_err(|e| WalletCmdError::Usage(format!("weak-subjectivity: {e}")))?;
            checked = true;
        } else if params.pin_trusted_summary {
            file.trusted_light_summary = Some(
                summary_from_checkpoint_hex(cp_hex)
                    .map_err(|e| WalletCmdError::Usage(format!("pin summary: {e}")))?,
            );
            pinned = true;
        }
    }
    Ok((checked, pinned))
}

fn cross_check_checkpoint_log_if_requested(
    file: &WalletFile,
    params: &LightScanParams,
) -> Result<Option<CheckpointLogCrossCheckReport>, WalletCmdError> {
    let Some(log_path) = &params.checkpoint_log_path else {
        return Ok(None);
    };
    let cp_hex = file.light_checkpoint_hex.as_ref().ok_or_else(|| {
        WalletCmdError::Usage(
            "wallet light-scan --checkpoint-log requires light_checkpoint_hex after sync".into(),
        )
    })?;
    let summary = summary_from_checkpoint_hex(cp_hex)
        .map_err(|e| WalletCmdError::Usage(format!("checkpoint log cross-check: {e}")))?;
    cross_check_summary_against_checkpoint_log(&summary, log_path).map(Some)
}

fn refresh_trusted_summary_from_checkpoint(
    file: &mut WalletFile,
    params: &LightScanParams,
) -> Result<bool, WalletCmdError> {
    if !params.update_trusted_summary {
        return Ok(false);
    }
    let Some(cp_hex) = file.light_checkpoint_hex.as_ref() else {
        return Ok(false);
    };
    file.trusted_light_summary = Some(
        summary_from_checkpoint_hex(cp_hex)
            .map_err(|e| WalletCmdError::Usage(format!("update trusted summary: {e}")))?,
    );
    Ok(true)
}

fn resolve_trusted_summary(
    file: &WalletFile,
    params: &LightScanParams,
) -> Result<Option<LightCheckpointSummary>, WalletCmdError> {
    if let Some(path) = &params.trusted_summary_path {
        return Ok(Some(load_trusted_summary_file(path)?));
    }
    Ok(file.trusted_light_summary.clone())
}

fn fetch_light_follow_with_quorum(
    primary: &mut RpcClient,
    from_h: u32,
    to_h: u32,
    params: &LightScanParams,
) -> Result<(LightFollowPage, usize), WalletCmdError> {
    let mut pages = vec![primary.get_light_follow(from_h, to_h)?];
    let primary_addr = primary.addr().to_string();

    for addr in &params.quorum_rpc_addrs {
        if addr == &primary_addr {
            continue;
        }
        let mut peer_client = primary.peer_client(addr);
        pages.push(peer_client.get_light_follow(from_h, to_h)?);
    }

    for peer in &params.quorum_p2p_peers {
        pages.push(primary.get_light_follow_p2p(peer, from_h, to_h)?);
    }

    let batch_count = if pages.len() > 1 {
        light_follow_pages_quorum(&pages)
            .map_err(|e| WalletCmdError::Usage(format!("light-follow quorum: {e}")))?
    } else {
        1
    };
    Ok((
        pages.into_iter().next().expect("at least local page"),
        batch_count,
    ))
}

fn bootstrap_light_chain(
    client: &mut RpcClient,
    file: &mut WalletFile,
    start_height: u32,
    params: &LightScanParams,
) -> Result<LightChain, WalletCmdError> {
    if let Some(cp_hex) = &file.light_checkpoint_hex {
        let bytes = decode_hex(cp_hex, "light_checkpoint_hex")?;
        let chain = LightChain::decode_checkpoint(&bytes)
            .map_err(|e| WalletCmdError::Usage(format!("decode light checkpoint: {e}")))?;
        let expected_tip = start_height.saturating_sub(1);
        if chain.tip_height() != expected_tip {
            return Err(WalletCmdError::Usage(format!(
                "light checkpoint tip_height {} does not match wallet scan resume at {}",
                chain.tip_height(),
                start_height
            )));
        }
        return Ok(chain);
    }

    let resume = file.scan_height;
    let bootstrap_height = start_height.saturating_sub(1);
    let snap_height = resume.unwrap_or(bootstrap_height);
    if snap_height != bootstrap_height && file.light_checkpoint_hex.is_none() {
        return Err(WalletCmdError::Usage(format!(
            "wallet scan_height {:?} does not match light-scan resume at height {start_height}",
            resume
        )));
    }
    let snap = client.get_light_snapshot(Some(snap_height))?;
    if snap.tip_height != snap_height {
        return Err(WalletCmdError::Usage(format!(
            "get_light_snapshot at {snap_height} returned tip_height {}",
            snap.tip_height
        )));
    }
    let bytes = decode_hex(&snap.checkpoint_hex, "checkpoint_hex")?;
    let chain = LightChain::decode_checkpoint(&bytes)
        .map_err(|e| WalletCmdError::Usage(format!("decode light snapshot: {e}")))?;
    if chain.tip_height() != snap_height {
        return Err(WalletCmdError::Usage(format!(
            "checkpoint tip_height {} != requested {snap_height}",
            chain.tip_height()
        )));
    }
    file.light_checkpoint_hex = Some(snap.checkpoint_hex.clone());
    if file.trusted_light_summary.is_none() && params.pin_trusted_summary {
        file.trusted_light_summary = Some(snap.summary);
    }
    Ok(chain)
}

fn decode_slashings(
    row: &crate::rpc::LightFollowRow,
) -> Result<Vec<SlashEvidence>, WalletCmdError> {
    let mut out = Vec::with_capacity(row.slashings.len());
    for (i, s) in row.slashings.iter().enumerate() {
        let bytes = decode_hex(&s.evidence_hex, "evidence_hex")?;
        out.push(decode_evidence(&bytes).map_err(|e| {
            WalletCmdError::Usage(format!("slashings[{i}] at height {}: {e}", row.height))
        })?);
    }
    Ok(out)
}

fn decode_bond_ops(row: &crate::rpc::LightFollowRow) -> Result<Vec<BondOp>, WalletCmdError> {
    let mut out = Vec::with_capacity(row.bond_ops.len());
    for (i, b) in row.bond_ops.iter().enumerate() {
        let bytes = decode_hex(&b.op_hex, "op_hex")?;
        out.push(decode_bond_op(&bytes).map_err(|e| {
            WalletCmdError::Usage(format!("bond_ops[{i}] at height {}: {e}", row.height))
        })?);
    }
    Ok(out)
}

fn light_apply_err(height: u32, e: LightChainError) -> WalletCmdError {
    WalletCmdError::Usage(format!("light evolution at height {height}: {e}"))
}

fn decode_hex(s: &str, label: &str) -> Result<Vec<u8>, WalletCmdError> {
    let t = s
        .trim()
        .strip_prefix("0x")
        .or_else(|| s.trim().strip_prefix("0X"))
        .unwrap_or(s.trim());
    hex::decode(t).map_err(|e| WalletCmdError::Usage(format!("{label}: {e}")))
}

fn decode_hex32(s: &str, label: &str) -> Result<[u8; 32], WalletCmdError> {
    let bytes = decode_hex(s, label)?;
    bytes
        .try_into()
        .map_err(|_| WalletCmdError::Usage(format!("{label} must be 32 bytes")))
}

fn parse_block_id_hex(s: &str) -> Result<[u8; 32], WalletCmdError> {
    decode_hex32(s, "block_id")
}
