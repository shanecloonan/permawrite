//! Minimal `mfnd` command-line driver (M2.1.1 + M2.1.2 + M2.1.3 + M2.1.4 + M2.1.5 + M2.1.6 + M2.1.8 + M2.1.8.1 + M2.1.9 + M2.1.10 + M2.1.11 + M2.1.12 + M2.1.13 + M2.1.14 + M2.1.15 + M2.1.16 + M2.1.17 + M2.1.18 + M2.2.8 + M2.2.10 + M2.3.3 + M2.3.6 + M2.3.8 + M2.3.9 + M2.3.10 + M2.3.11 + M2.3.12 + M2.3.13 + M2.3.14 + M2.3.15).
//!
//! Backs the `mfnd` binary: load-or-genesis against a [`ChainStore`], print
//! status, save checkpoints, or block until a graceful shutdown trigger then
//! persist. On Unix the `run` command installs a Ctrl+C handler; on Windows it
//! waits for Enter (so the crate stays buildable on `windows-gnu` hosts without
//! pulling `windows-sys`). Optional `--genesis` loads a JSON chain spec; see
//! [`crate::genesis_spec`]. The `step` command advances a solo-validator chain
//! when operator seeds are set in the environment; each iteration builds a
//! coinbase plus any txs drained from an in-memory [`crate::Mempool`], then
//! `produce_solo_block` → `apply` → `remove_mined` → **`append_block`** (M2.1.7
//! `chain.blocks`) → checkpoint save. Use `--blocks N` to apply
//! N sequential blocks in one process (by default one checkpoint write at
//! the end; `--checkpoint-each` writes after every applied block).
//! **`serve`** (M2.1.6 + **M2.1.8** + **M2.1.10** + **M2.1.11** + **M2.1.12** + **M2.1.13** + **M2.1.14** + **M2.1.15** + **M2.1.16** + **M2.1.17** + **M2.1.18** + **M2.2.8** + **M2.2.10** + **M2.3.3** optional `--p2p-listen` + **M2.3.6** optional `--p2p-dial` + **M2.3.8** P2P ChainTipV1 + **M2.3.9** `mfnd_p2p_peer_tip` + **M2.3.10** GoodbyeV1 + **M2.3.11** `mfnd_p2p_height_cmp` + **M2.3.12** `mfnd_p2p_handshake_ms` + **M2.3.13** `hid=` + **M2.3.14** sequential-`hid` smoke + **M2.3.15** `mfnd_p2p_handshake_abort` on inbound P2P failures) binds a loopback TCP port and answers one
//! newline-delimited JSON request per connection (`get_tip`, `get_chain_params`, `submit_tx`, `get_block`, `get_block_header`, `get_block_headers`, `get_block_txs`, `get_mempool`, `get_mempool_tx`, `remove_mempool_tx`, `clear_mempool`, `get_checkpoint`, `save_checkpoint`, `list_methods`, `list_utxos`, `get_claims_for`, `get_claims_by_pubkey`, `list_recent_uploads`, `list_recent_claims`, `list_data_roots_with_claims`)
//! against a live chain + mempool until the process exits; each response is a
//! single JSON-RPC 2.0 object (`jsonrpc`, `id`, `result` or `error`).
//! Batching, HTTP/WebSocket, P2P, and durable mempool persistence still land
//! in later M2.x milestones.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::thread;

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{
    block_coinbase_specs, build_coinbase_outputs, PayoutAddress, ValidatorSecrets,
};
use mfn_crypto::vrf::vrf_keygen_from_seed;

use crate::{
    demo_genesis, genesis_config_from_json_path, hex_seed32, produce_solo_block, BlockInputs,
    Chain, ChainConfig, Mempool, MempoolConfig, NodeStore, StoreBackend,
};
use mfn_store::{
    load_mempool, load_or_genesis_replaying_block_log, load_proof_pool, save_mempool,
    save_proof_pool, ChainPersistence,
};

/// Entry point for the `mfnd` binary. Returns a process exit code.
pub fn mfnd_main() -> ExitCode {
    match run(std::env::args().collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmd {
    Status,
    Save,
    Run,
    Step,
    Serve,
    /// **F5-PM10**: export a self-verifying chain + chunk archive.
    ArchiveExport,
    /// **F5-PM10**: verify an archive offline against the genesis spec.
    ArchiveVerify,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Parsed {
    data_dir: PathBuf,
    genesis_toml: Option<PathBuf>,
    cmd: Cmd,
    /// Solo `step` only: number of blocks to produce (default 1, max 10_000).
    step_count: u32,
    /// Solo `step` only: persist checkpoint after every block (not only at end).
    checkpoint_each_block: bool,
    /// Solo `serve` only: `HOST:PORT` to bind (default `127.0.0.1:18731`).
    rpc_listen: Option<String>,
    /// Solo `serve` only: API key required for wallet-write/operator-admin RPC methods.
    rpc_api_key: Option<String>,
    /// Solo `serve` only: optional second `HOST:PORT` for binary P2P [`hello_v1_handshake`](crate::network::hello_v1_handshake).
    p2p_listen: Option<String>,
    /// Solo `serve` only: boot peer `HOST:PORT` list (repeat `--p2p-dial`; merged with genesis manifest `seed_nodes` when present — **M2.4.4**).
    p2p_dials: Vec<String>,
    /// Solo `serve` only: Dandelion++ stem/fluff tx relay (**F5-P3** / B7).
    dandelion: bool,
    /// Persistence backend (`fs` default, or `redb`).
    store_backend: StoreBackend,
    /// `serve` only: slot-driven multi-validator production (**M2.3.23**).
    produce: bool,
    /// `serve` only: ProposalV1/VoteV1 handler without slot loop (needs P2P + env keys).
    committee_vote: bool,
    /// `serve --produce` / `--committee-vote` only: milliseconds between slot ticks (default 1000).
    slot_duration_ms: u64,
    /// `archive-export` / `archive-verify` only: archive directory (**F5-PM10**).
    archive_dir: Option<PathBuf>,
}

fn usage() -> &'static str {
    "usage: mfnd --data-dir <DIR> [OPTIONS] <COMMAND>\n\
     \n\
     options:\n\
       --store BACKEND  checkpoint backend: `redb` (default) or `fs` (`chain.redb`)\n\
       --genesis PATH   optional JSON genesis spec (version 1; see crate testdata/)\n\
       --blocks N       only for `step`: produce and apply N blocks in sequence\n\
                        (default 1; by default one checkpoint after the last block)\n\
       --checkpoint-each  only for `step`: write checkpoint after every applied block\n\
       --rpc-listen ADDR:PORT   only for `serve` (default 127.0.0.1:18731)\n\
       --rpc-api-key KEY        only for `serve`: require KEY for wallet-write/operator-admin RPC\n\
                                  methods (or set MFND_RPC_API_KEY)\n\
      env MFND_RPC_MAX_IN_FLIGHT  only for `serve`: override RPC in-flight connection cap\n\
                                  (default 64; use get_status to inspect active value)\n\
       --p2p-listen ADDR:PORT   only for `serve` (optional): length-prefixed HelloV1 handshake\n\
                                  on a separate TCP port (see `network::handshake`)\n\
       --p2p-dial ADDR:PORT     only for `serve` (optional, repeatable): outbound dials to peer P2P\n\
                                  listeners; also merges `<genesis_stem>.manifest.json` seed_nodes when\n\
                                  `--genesis` is set (M2.4.4). Each dial runs hello + ping/pong + ChainTipV1\n\
                                  + GoodbyeV1; on success prints mfnd_p2p_dial_ok=… then mfnd_p2p_peer_tip /\n\
                                  mfnd_p2p_height_cmp / mfnd_p2p_handshake_ms (hid=; see mfnd_serve)\n\
       --dandelion              only for `serve`: Dandelion++ stem/fluff tx relay (opt-in; default off)\n\
                                  or set env MFND_DANDELION=1\n\
      env MFND_P2P_TRANSPORT     only for `serve`: outbound P2P dial transport `tcp` (default) or `tor` (B8.1 stub)\n\
      env MFND_TOR_SOCKS5         only for `serve` with `tor`: SOCKS5 proxy (default 127.0.0.1:9050)\n\
      env MFND_REPAIR_THRESHOLD_SLOTS only for `serve`: proactive repair staleness threshold slots (0 disables; default 14400)\n\
      env MFND_REPAIR_INTERVAL_MS     only for `serve`: repair sweep interval in ms (default 300000)\n\
      env MFND_CHUNK_INBOX_MAX_BYTES  only for `serve`: chunk-inbox disk quota in bytes (0 disables; default 64GiB)\n\
       --produce                only for `serve`: slot loop + ProposalV1/VoteV1 (needs P2P + env keys)\n\
       --committee-vote         only for `serve`: vote on proposals without slot loop (needs P2P + env keys)\n\
       --slot-duration-ms MS    producer tick / catch-up sweep interval for `serve` (default 1000)\n\
                                  set MFND_VALIDATOR_INDEX + MFND_VRF_SEED_HEX + MFND_BLS_SEED_HEX\n\
                                  (or MFND_SOLO_* aliases) matching the JSON genesis validator row\n\
       --archive-dir DIR        only for `archive-export` (output) / `archive-verify` (input)\n\
     \n\
     commands:\n\
       status  print tip height, ids, and whether a checkpoint existed on disk\n\
       save    persist the current chain checkpoint and exit\n\
       run     load or genesis, then wait for shutdown and save checkpoint:\n\
               Unix: Ctrl+C   Windows: press Enter\n\
       step    solo-validator: produce next block(s), apply, save checkpoint\n\
               (requires genesis with exactly one validator + payout;\n\
                set MFND_SOLO_VRF_SEED_HEX and MFND_SOLO_BLS_SEED_HEX to the\n\
                same 64-hex seeds as in the JSON genesis for validator index 0)\n\
       serve   load chain + empty mempool; TCP newline-delimited JSON-RPC 2.0 on --rpc-listen\n\
               (one request line per connection; methods: get_tip, get_chain_params, submit_tx, get_block, get_block_header, get_mempool, get_mempool_tx, remove_mempool_tx, clear_mempool, get_checkpoint, save_checkpoint, list_utxos, list_methods, …;\n\
                submit_tx params: {\"tx_hex\":...} or [\"...\"] hex string;\n\
                get_block / get_block_header params: {\"height\":N} or [N] for heights 1..=tip;\n\
                get_mempool / clear_mempool / get_checkpoint / save_checkpoint params: omit, null, {}, or [];\n\
                get_mempool_tx / remove_mempool_tx params: {\"tx_id\":...} or [\"...\"] 64-char hex (32-byte tx id))\n\
       archive-export  write the canonical chain + locally-complete chunk sets to --archive-dir\n\
                       as a self-verifying offline archive (manifest.json + chain.blocks + chunk-inbox/)\n\
       archive-verify  replay --archive-dir from the genesis spec through the full consensus STF\n\
                       and Merkle-verify every exported chunk set; no live network needed\n"
}

fn resolve_chain_config(parsed: &Parsed) -> Result<ChainConfig, String> {
    let genesis = match &parsed.genesis_toml {
        Some(p) => genesis_config_from_json_path(Path::new(p)).map_err(|e| e.to_string())?,
        None => demo_genesis::empty_local_dev_genesis(),
    };
    Ok(ChainConfig::new(genesis))
}

const MFND_SOLO_VRF_SEED_HEX: &str = "MFND_SOLO_VRF_SEED_HEX";
const MFND_SOLO_BLS_SEED_HEX: &str = "MFND_SOLO_BLS_SEED_HEX";
const MFND_RPC_API_KEY: &str = "MFND_RPC_API_KEY";

/// Max regular txs pulled from the mempool into one block body (coinbase is extra).
const MFND_MEMPOOL_DRAIN_MAX: usize = 256;

fn run_solo_step(
    store: &dyn ChainPersistence,
    cfg: &ChainConfig,
    step_count: u32,
    checkpoint_each_block: bool,
) -> Result<(), String> {
    if step_count == 0 {
        return Err("mfnd step: --blocks must be at least 1".into());
    }
    if step_count > 10_000 {
        return Err("mfnd step: --blocks exceeds maximum (10000)".into());
    }

    let (mut chain, _) =
        load_or_genesis_replaying_block_log(store, cfg.clone()).map_err(|e| format!("{e}"))?;
    let vals = chain.validators();
    if vals.len() != 1 {
        return Err(format!(
            "mfnd step requires exactly one validator in genesis (got {})",
            vals.len()
        ));
    }
    let producer = vals[0].clone();
    let payout = producer.payout.as_ref().ok_or_else(|| {
        "mfnd step: genesis validator[0] must have a payout (coinbase route)".to_string()
    })?;
    let vrf_hex = std::env::var(MFND_SOLO_VRF_SEED_HEX).map_err(|_| {
        format!("mfnd step: set {MFND_SOLO_VRF_SEED_HEX} to the 64-hex vrf seed for validator[0]")
    })?;
    let bls_hex = std::env::var(MFND_SOLO_BLS_SEED_HEX).map_err(|_| {
        format!("mfnd step: set {MFND_SOLO_BLS_SEED_HEX} to the 64-hex bls seed for validator[0]")
    })?;
    let vrf_seed = hex_seed32(MFND_SOLO_VRF_SEED_HEX, &vrf_hex).map_err(|e| e.to_string())?;
    let bls_seed = hex_seed32(MFND_SOLO_BLS_SEED_HEX, &bls_hex).map_err(|e| e.to_string())?;
    let vrf =
        vrf_keygen_from_seed(&vrf_seed).map_err(|e| format!("{MFND_SOLO_VRF_SEED_HEX}: {e}"))?;
    let bls = bls_keygen_from_seed(&bls_seed);
    if vrf.pk != producer.vrf_pk || bls.pk != producer.bls_pk {
        return Err(
            "mfnd step: keys derived from env seeds do not match genesis validator[0]".into(),
        );
    }
    let secrets = ValidatorSecrets {
        index: producer.index,
        vrf,
        bls: bls.clone(),
    };

    let mut pool = Mempool::new(MempoolConfig::default());
    let mut proof_pool = mfn_runtime::ProofPool::new(mfn_runtime::ProofPoolConfig::default());
    {
        let stats = load_mempool(store, &mut pool, chain.state())
            .map_err(|e| format!("mfnd step: load mempool: {e}"))?;
        println!(
            "mfnd_step_mempool_load loaded={} admitted={} skipped={}",
            stats.loaded, stats.admitted, stats.skipped
        );
    }
    {
        let prev = chain
            .tip_id()
            .copied()
            .unwrap_or_else(|| *chain.genesis_id());
        let next_h = chain.tip_height().map(|h| h.saturating_add(1)).unwrap_or(0);
        let stats = load_proof_pool(store, &mut proof_pool, chain.state(), &prev, next_h)
            .map_err(|e| format!("mfnd step: load proof pool: {e}"))?;
        println!(
            "mfnd_step_proof_pool_load loaded={} admitted={} skipped={}",
            stats.loaded, stats.admitted, stats.skipped
        );
    }

    for bi in 0..step_count {
        let tip = chain
            .tip_height()
            .ok_or_else(|| "mfnd step: internal error: missing tip height".to_string())?;
        let next_height = tip
            .checked_add(1)
            .ok_or_else(|| "mfnd step: tip height overflow".to_string())?;
        let timestamp = cfg.genesis.timestamp.saturating_add(u64::from(next_height));
        let (params, emission_params) = {
            let st = chain.state();
            (st.params, st.emission_params)
        };

        let drained = pool.drain(MFND_MEMPOOL_DRAIN_MAX);
        let mut fee_sum: u128 = 0;
        for t in &drained {
            fee_sum = fee_sum.saturating_add(u128::from(t.fee));
        }

        let prev = chain
            .tip_id()
            .copied()
            .unwrap_or_else(|| *chain.genesis_id());
        let storage_proofs = proof_pool.drain_verified(chain.state(), &prev, next_height);
        let st = chain.state();
        let storage_bonus_pairs: Vec<(mfn_storage::StorageProof, u128)> = storage_proofs
            .iter()
            .map(|proof| {
                let bonus = st
                    .storage
                    .get(&proof.commit_hash)
                    .map(|entry| {
                        mfn_storage::accrue_proof_reward(mfn_storage::AccrueArgs {
                            size_bytes: entry.commit.size_bytes,
                            replication: entry.commit.replication,
                            pending_ppb: entry.pending_yield_ppb,
                            last_proven_slot: entry.last_proven_slot,
                            current_slot: u64::from(next_height),
                            params: &st.endowment_params,
                        })
                        .map(|a| a.payout)
                        .unwrap_or(0)
                    })
                    .unwrap_or(0);
                (proof.clone(), bonus)
            })
            .collect();

        let cb_payout = PayoutAddress {
            view_pub: payout.view_pub,
            spend_pub: payout.spend_pub,
        };
        let specs = block_coinbase_specs(
            u64::from(next_height),
            &emission_params,
            fee_sum,
            cb_payout,
            &storage_bonus_pairs,
        );
        let cb = build_coinbase_outputs(u64::from(next_height), &payout.spend_pub, &specs)
            .map_err(|e| format!("build_coinbase_outputs: {e}"))?;
        let mut txs = Vec::with_capacity(1 + drained.len());
        txs.push(cb);
        txs.extend(drained);
        let inputs = BlockInputs {
            height: next_height,
            slot: next_height,
            timestamp,
            txs,
            bond_ops: Vec::new(),
            slashings: Vec::new(),
            storage_proofs,
            storage_operator_ops: Vec::new(),
        };
        let block = produce_solo_block(&chain, &producer, &secrets, params, inputs)
            .map_err(|e| format!("produce_solo_block: {e}"))?;
        chain
            .apply(&block)
            .map_err(|e| format!("apply_block: {e}"))?;
        pool.remove_mined(&block);
        let mined: Vec<[u8; 32]> = block.storage_proofs.iter().map(|p| p.commit_hash).collect();
        let _ = proof_pool.remove_mined(mined);
        if let Err(e) = save_proof_pool(store, &proof_pool) {
            eprintln!("mfnd_step_proof_pool_save_abort {e}");
        }
        store
            .append_block(&block)
            .map_err(|e| format!("append_block: {e}"))?;

        if checkpoint_each_block {
            let meta = store.save(&chain).map_err(|e| format!("{e}"))?;
            let h = chain
                .tip_height()
                .ok_or_else(|| "tip missing after apply".to_string())?;
            println!(
                "step_checkpoint tip_height={h} saved_checkpoint_bytes={} path={}",
                meta.bytes_written,
                meta.checkpoint_path.display()
            );
        } else if bi + 1 == step_count {
            let meta = store.save(&chain).map_err(|e| format!("{e}"))?;
            println!(
                "saved_checkpoint_bytes={} path={}",
                meta.bytes_written,
                meta.checkpoint_path.display()
            );
        }
    }

    let last_tip_id = chain
        .tip_id()
        .ok_or_else(|| "mfnd step: internal error: missing tip id after apply".to_string())?;
    let tip_height = chain
        .tip_height()
        .ok_or_else(|| "mfnd step: internal error: missing tip height after apply".to_string())?;
    println!("new_tip_height={tip_height}");
    println!("new_tip_id={}", hex32(last_tip_id));
    save_mempool(store, &pool).map_err(|e| format!("mfnd step: save mempool: {e}"))?;
    Ok(())
}

fn run(args: Vec<String>) -> Result<(), String> {
    let argv: Vec<String> = args.into_iter().skip(1).collect();
    let parsed = parse_args(&argv)?;
    let store =
        NodeStore::open(parsed.store_backend, &parsed.data_dir).map_err(|e| format!("{e}"))?;
    let cfg = resolve_chain_config(&parsed)?;

    match parsed.cmd {
        Cmd::Status => {
            let had_checkpoint = store.has_any_checkpoint();
            let (chain, _) =
                load_or_genesis_replaying_block_log(&store, cfg).map_err(|e| format!("{e}"))?;
            print_status(&chain, had_checkpoint, parsed.store_backend);
        }
        Cmd::Save => {
            let (chain, _) =
                load_or_genesis_replaying_block_log(&store, cfg).map_err(|e| format!("{e}"))?;
            let meta = store.save(&chain).map_err(|e| format!("{e}"))?;
            println!(
                "saved_checkpoint_bytes={} path={}",
                meta.bytes_written,
                meta.checkpoint_path.display()
            );
        }
        Cmd::Run => {
            let had_checkpoint = store.has_any_checkpoint();
            let (loaded_chain, _) =
                load_or_genesis_replaying_block_log(&store, cfg).map_err(|e| format!("{e}"))?;
            let chain = Arc::new(Mutex::new(loaded_chain));
            {
                let c = chain
                    .lock()
                    .map_err(|_| "mfnd: internal error: chain mutex poisoned".to_string())?;
                #[cfg(unix)]
                println!(
                    "mfnd run: tip_height={:?} had_checkpoint_on_disk={had_checkpoint}\n\
                     Press Ctrl+C to write `chain.checkpoint` and exit.",
                    c.tip_height()
                );
                #[cfg(windows)]
                println!(
                    "mfnd run: tip_height={:?} had_checkpoint_on_disk={had_checkpoint}\n\
                     Press Enter to write `chain.checkpoint` and exit.",
                    c.tip_height()
                );
            }
            #[cfg(unix)]
            {
                let chain_c = Arc::clone(&chain);
                let dir = parsed.data_dir.clone();
                let backend = parsed.store_backend;
                ctrlc::set_handler(move || {
                    let guard = match chain_c.lock() {
                        Ok(g) => g,
                        Err(_) => {
                            eprintln!("mfnd: chain mutex poisoned on shutdown");
                            std::process::exit(1);
                        }
                    };
                    match NodeStore::open(backend, &dir).and_then(|s| s.save(&guard)) {
                        Ok(m) => {
                            eprintln!(
                                "mfnd: saved {} bytes to {}",
                                m.bytes_written,
                                m.checkpoint_path.display()
                            );
                        }
                        Err(e) => eprintln!("mfnd: checkpoint save failed: {e}"),
                    }
                    std::process::exit(0);
                })
                .map_err(|e| format!("failed to install Ctrl+C handler: {e}"))?;
                thread::park();
            }
            #[cfg(windows)]
            {
                let mut buf = String::new();
                std::io::stdin()
                    .read_line(&mut buf)
                    .map_err(|e| format!("stdin read failed: {e}"))?;
                let guard = chain
                    .lock()
                    .map_err(|_| "mfnd: internal error: chain mutex poisoned".to_string())?;
                let meta = NodeStore::open(parsed.store_backend, &parsed.data_dir)
                    .map_err(|e| format!("{e}"))?
                    .save(&guard)
                    .map_err(|e| format!("{e}"))?;
                println!(
                    "saved_checkpoint_bytes={} path={}",
                    meta.bytes_written,
                    meta.checkpoint_path.display()
                );
            }
        }
        Cmd::Step => {
            run_solo_step(
                &store,
                &cfg,
                parsed.step_count,
                parsed.checkpoint_each_block,
            )?;
        }
        Cmd::ArchiveExport => {
            let out_dir = parsed
                .archive_dir
                .as_deref()
                .ok_or_else(|| "archive-export requires --archive-dir <DIR>".to_string())?;
            let report = crate::archive_export::export_archive(&store, cfg, out_dir)
                .map_err(|e| format!("{e}"))?;
            println!(
                "mfnd_archive_export ok=1 blocks={} tip_height={} tip_id={} genesis_id={} commitments={} chunk_sets_exported={} path={}",
                report.blocks,
                report.tip_height,
                report.tip_id,
                report.genesis_id,
                report.commitments_total,
                report.chunk_sets_exported,
                out_dir.display()
            );
        }
        Cmd::ArchiveVerify => {
            let archive_dir = parsed
                .archive_dir
                .as_deref()
                .ok_or_else(|| "archive-verify requires --archive-dir <DIR>".to_string())?;
            let report = crate::archive_export::verify_archive(archive_dir, cfg)
                .map_err(|e| format!("{e}"))?;
            println!(
                "mfnd_archive_verify ok=1 blocks_verified={} tip_height={} tip_id={} commitments={} chunk_sets_verified={} path={}",
                report.blocks_verified,
                report.tip_height,
                report.tip_id,
                report.commitments_total,
                report.chunk_sets_verified,
                archive_dir.display()
            );
        }
        Cmd::Serve => {
            let listen = parsed.rpc_listen.as_deref().unwrap_or("127.0.0.1:18731");
            let rpc_api_key = parsed.rpc_api_key.or_else(|| {
                std::env::var(MFND_RPC_API_KEY)
                    .ok()
                    .filter(|s| !s.is_empty())
            });
            let store: std::sync::Arc<dyn mfn_store::ChainPersistence + Send + Sync> =
                std::sync::Arc::new(store);
            let network_label = parsed.genesis_toml.as_ref().and_then(|p| {
                p.file_stem()
                    .and_then(|s| s.to_str())
                    .filter(|s| !s.is_empty())
            });
            let mut p2p_dials = parsed.p2p_dials.clone();
            let boot_report = crate::p2p_boot::merge_boot_peer_dials(
                &mut p2p_dials,
                parsed.genesis_toml.as_deref(),
            )?;
            if let Some(line) = boot_dials_capped_log_line(&boot_report) {
                println!("{line}");
                std::io::stdout().flush().ok();
            }
            if !p2p_dials.is_empty() {
                println!("mfnd_p2p_boot_dials={}", p2p_dials.join(","));
                std::io::stdout().flush().ok();
            }
            crate::mfnd_serve::run_serve(
                store,
                cfg,
                listen,
                rpc_api_key,
                parsed.p2p_listen.as_deref(),
                &p2p_dials,
                parsed.produce,
                parsed.committee_vote,
                parsed.slot_duration_ms,
                network_label,
                parsed.dandelion,
            )?;
        }
    }
    Ok(())
}

fn print_status(chain: &Chain, had_checkpoint_on_disk: bool, store_backend: StoreBackend) {
    let tip_h = chain
        .tip_height()
        .map_or_else(|| "none".to_string(), |h| h.to_string());
    let tip_id = chain
        .tip_id()
        .map(hex32)
        .unwrap_or_else(|| "none".to_string());
    let genesis_id = hex32(chain.genesis_id());
    println!("tip_height={tip_h}");
    println!("tip_id={tip_id}");
    println!("genesis_id={genesis_id}");
    println!("had_checkpoint_on_disk={had_checkpoint_on_disk}");
    println!("store_backend={}", store_backend.as_str());
    println!("validator_count={}", chain.validators().len());
}

fn hex32(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in id {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn boot_dials_capped_log_line(report: &crate::p2p_boot::BootPeerDialMergeReport) -> Option<String> {
    (report.dropped > 0).then(|| {
        format!(
            "mfnd_p2p_boot_dials_capped configured={} retained={} dropped={} cap={}",
            report.configured, report.retained, report.dropped, report.cap
        )
    })
}

fn parse_args(args: &[String]) -> Result<Parsed, String> {
    let mut data_dir: Option<PathBuf> = None;
    let mut genesis_toml: Option<PathBuf> = None;
    let mut step_count: Option<u32> = None;
    let mut checkpoint_each_block = false;
    let mut rpc_listen: Option<String> = None;
    let mut rpc_api_key: Option<String> = None;
    let mut p2p_listen: Option<String> = None;
    let mut p2p_dials: Vec<String> = Vec::new();
    let mut store_backend = StoreBackend::default();
    let mut produce = false;
    let mut committee_vote = false;
    let mut slot_duration_ms = 1000u64;
    let mut archive_dir: Option<PathBuf> = None;
    let mut dandelion = false;
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--data-dir" || a == "--datadir" {
            let Some(v) = args.get(i + 1) else {
                return Err("--data-dir requires a path".into());
            };
            if v.starts_with('-') {
                return Err("expected path after --data-dir".into());
            }
            data_dir = Some(PathBuf::from(v));
            i += 2;
            continue;
        }
        if a == "--store" {
            let Some(v) = args.get(i + 1) else {
                return Err("--store requires `fs` or `redb`".into());
            };
            if v.starts_with('-') {
                return Err("expected backend name after --store".into());
            }
            store_backend = StoreBackend::parse(v)?;
            i += 2;
            continue;
        }
        if a == "--genesis" || a == "--genesis-spec" {
            let Some(v) = args.get(i + 1) else {
                return Err("--genesis requires a path to a JSON genesis spec".into());
            };
            if v.starts_with('-') {
                return Err("expected path after --genesis".into());
            }
            genesis_toml = Some(PathBuf::from(v));
            i += 2;
            continue;
        }
        if a == "--blocks" {
            let Some(v) = args.get(i + 1) else {
                return Err("--blocks requires a positive integer".into());
            };
            if v.starts_with('-') {
                return Err("expected integer after --blocks".into());
            }
            let n: u32 = v
                .parse()
                .map_err(|_| format!("invalid --blocks value `{v}`"))?;
            if n == 0 {
                return Err("--blocks must be at least 1".into());
            }
            if n > 10_000 {
                return Err("--blocks exceeds maximum (10000)".into());
            }
            step_count = Some(n);
            i += 2;
            continue;
        }
        if a == "--checkpoint-each" {
            checkpoint_each_block = true;
            i += 1;
            continue;
        }
        if a == "--rpc-listen" {
            let Some(v) = args.get(i + 1) else {
                return Err("--rpc-listen requires HOST:PORT (e.g. 127.0.0.1:18731)".into());
            };
            if v.starts_with('-') {
                return Err("expected HOST:PORT after --rpc-listen".into());
            }
            rpc_listen = Some(v.clone());
            i += 2;
            continue;
        }
        if a == "--rpc-api-key" {
            let Some(v) = args.get(i + 1) else {
                return Err("--rpc-api-key requires a non-empty key".into());
            };
            if v.is_empty() || v.starts_with('-') {
                return Err("expected non-empty KEY after --rpc-api-key".into());
            }
            rpc_api_key = Some(v.clone());
            i += 2;
            continue;
        }
        if a == "--p2p-listen" {
            let Some(v) = args.get(i + 1) else {
                return Err("--p2p-listen requires HOST:PORT (e.g. 127.0.0.1:0)".into());
            };
            if v.starts_with('-') {
                return Err("expected HOST:PORT after --p2p-listen".into());
            }
            p2p_listen = Some(v.clone());
            i += 2;
            continue;
        }
        if a == "--p2p-dial" {
            let Some(v) = args.get(i + 1) else {
                return Err("--p2p-dial requires HOST:PORT (peer P2P listener)".into());
            };
            if v.starts_with('-') {
                return Err("expected HOST:PORT after --p2p-dial".into());
            }
            p2p_dials.push(v.clone());
            i += 2;
            continue;
        }
        if a == "--dandelion" {
            dandelion = true;
            i += 1;
            continue;
        }
        if a == "--produce" {
            produce = true;
            i += 1;
            continue;
        }
        if a == "--committee-vote" {
            committee_vote = true;
            i += 1;
            continue;
        }
        if a == "--archive-dir" {
            let Some(v) = args.get(i + 1) else {
                return Err("--archive-dir requires a directory path".into());
            };
            if v.starts_with('-') {
                return Err("expected path after --archive-dir".into());
            }
            archive_dir = Some(PathBuf::from(v));
            i += 2;
            continue;
        }
        if a == "--slot-duration-ms" {
            let Some(v) = args.get(i + 1) else {
                return Err("--slot-duration-ms requires a positive integer".into());
            };
            slot_duration_ms = v
                .parse()
                .map_err(|_| format!("invalid --slot-duration-ms `{v}`"))?;
            if slot_duration_ms == 0 {
                return Err("--slot-duration-ms must be at least 1".into());
            }
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            return Err(format!("unknown option `{a}`\n{}", usage()));
        }
        positional.push(a);
        i += 1;
    }
    let data_dir = data_dir.ok_or_else(|| format!("--data-dir is required\n{}", usage()))?;
    if positional.len() != 1 {
        return Err(format!("expected exactly one COMMAND\n{}", usage()));
    }
    let cmd = match positional[0] {
        "status" => Cmd::Status,
        "save" => Cmd::Save,
        "run" => Cmd::Run,
        "step" => Cmd::Step,
        "serve" => Cmd::Serve,
        "archive-export" => Cmd::ArchiveExport,
        "archive-verify" => Cmd::ArchiveVerify,
        other => return Err(format!("unknown command `{other}`\n{}", usage())),
    };
    let step_count = match (step_count, cmd) {
        (Some(n), Cmd::Step) => n,
        (Some(_), _) => {
            return Err(format!(
                "--blocks is only valid with the step command\n{}",
                usage()
            ));
        }
        (None, Cmd::Step) => 1,
        (None, _) => 1,
    };
    if checkpoint_each_block && cmd != Cmd::Step {
        return Err(format!(
            "--checkpoint-each is only valid with the step command\n{}",
            usage()
        ));
    }
    if rpc_listen.is_some() && cmd != Cmd::Serve {
        return Err(format!(
            "--rpc-listen is only valid with the serve command\n{}",
            usage()
        ));
    }
    if rpc_api_key.is_some() && cmd != Cmd::Serve {
        return Err(format!(
            "--rpc-api-key is only valid with the serve command\n{}",
            usage()
        ));
    }
    if p2p_listen.is_some() && cmd != Cmd::Serve {
        return Err(format!(
            "--p2p-listen is only valid with the serve command\n{}",
            usage()
        ));
    }
    if !p2p_dials.is_empty() && cmd != Cmd::Serve {
        return Err(format!(
            "--p2p-dial is only valid with the serve command\n{}",
            usage()
        ));
    }
    if produce && cmd != Cmd::Serve {
        return Err(format!(
            "--produce is only valid with the serve command\n{}",
            usage()
        ));
    }
    if committee_vote && cmd != Cmd::Serve {
        return Err(format!(
            "--committee-vote is only valid with the serve command\n{}",
            usage()
        ));
    }
    if dandelion && cmd != Cmd::Serve {
        return Err(format!(
            "--dandelion is only valid with the serve command\n{}",
            usage()
        ));
    }
    if produce && committee_vote {
        return Err(format!(
            "--produce and --committee-vote are mutually exclusive\n{}",
            usage()
        ));
    }
    if archive_dir.is_some() && !matches!(cmd, Cmd::ArchiveExport | Cmd::ArchiveVerify) {
        return Err(format!(
            "--archive-dir is only valid with archive-export / archive-verify\n{}",
            usage()
        ));
    }
    if archive_dir.is_none() && matches!(cmd, Cmd::ArchiveExport | Cmd::ArchiveVerify) {
        return Err(format!(
            "archive-export / archive-verify require --archive-dir <DIR>\n{}",
            usage()
        ));
    }
    Ok(Parsed {
        data_dir,
        genesis_toml,
        cmd,
        step_count,
        checkpoint_each_block,
        rpc_listen,
        rpc_api_key,
        p2p_listen,
        p2p_dials,
        store_backend,
        produce,
        committee_vote,
        slot_duration_ms,
        archive_dir,
        dandelion,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_mentions_rpc_safety_environment_knobs() {
        let text = usage();
        assert!(text.contains("MFND_RPC_API_KEY"));
        assert!(text.contains("MFND_RPC_MAX_IN_FLIGHT"));
        assert!(text.contains("MFND_P2P_TRANSPORT"));
        assert!(text.contains("MFND_TOR_SOCKS5"));
        assert!(text.contains("get_status"));
    }

    #[test]
    fn boot_dials_capped_log_line_is_absent_without_dropped_peers() {
        let report = crate::p2p_boot::BootPeerDialMergeReport {
            configured: 4,
            retained: 4,
            dropped: 0,
            cap: crate::p2p_boot::MAX_BOOT_PEER_DIALS,
        };
        assert_eq!(boot_dials_capped_log_line(&report), None);
    }

    #[test]
    fn boot_dials_capped_log_line_pins_public_startup_contract() {
        let report = crate::p2p_boot::BootPeerDialMergeReport {
            configured: 70,
            retained: 64,
            dropped: 6,
            cap: crate::p2p_boot::MAX_BOOT_PEER_DIALS,
        };
        assert_eq!(
            boot_dials_capped_log_line(&report).as_deref(),
            Some("mfnd_p2p_boot_dials_capped configured=70 retained=64 dropped=6 cap=64")
        );
    }

    #[test]
    fn parse_args_step() {
        let args = vec!["--data-dir".into(), "/tmp/x".into(), "step".into()];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Step);
        assert_eq!(p.step_count, 1);
        assert!(!p.checkpoint_each_block);
        assert_eq!(p.rpc_listen, None);
        assert_eq!(p.p2p_listen, None);
        assert!(p.p2p_dials.is_empty());
    }

    #[test]
    fn parse_args_serve() {
        let args = vec!["--data-dir".into(), "/tmp/x".into(), "serve".into()];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Serve);
        assert_eq!(p.rpc_listen, None);
        assert_eq!(p.p2p_listen, None);
        assert!(p.p2p_dials.is_empty());
    }

    #[test]
    fn parse_args_serve_rpc_listen() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--rpc-listen".into(),
            "127.0.0.1:19999".into(),
            "serve".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Serve);
        assert_eq!(p.rpc_listen.as_deref(), Some("127.0.0.1:19999"));
        assert_eq!(p.p2p_listen, None);
        assert!(p.p2p_dials.is_empty());
    }

    #[test]
    fn parse_args_serve_rpc_api_key() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--rpc-api-key".into(),
            "secret".into(),
            "serve".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Serve);
        assert_eq!(p.rpc_api_key.as_deref(), Some("secret"));
    }

    #[test]
    fn parse_args_serve_p2p_listen() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--rpc-listen".into(),
            "127.0.0.1:18731".into(),
            "--p2p-listen".into(),
            "127.0.0.1:0".into(),
            "serve".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Serve);
        assert_eq!(p.rpc_listen.as_deref(), Some("127.0.0.1:18731"));
        assert_eq!(p.p2p_listen.as_deref(), Some("127.0.0.1:0"));
        assert!(p.p2p_dials.is_empty());
    }

    #[test]
    fn parse_args_serve_dandelion() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--dandelion".into(),
            "serve".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Serve);
        assert!(p.dandelion);
    }

    #[test]
    fn parse_args_dandelion_rejected_without_serve() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--dandelion".into(),
            "status".into(),
        ];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_serve_p2p_dial() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--rpc-listen".into(),
            "127.0.0.1:18731".into(),
            "--p2p-dial".into(),
            "127.0.0.1:19998".into(),
            "serve".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Serve);
        assert_eq!(p.rpc_listen.as_deref(), Some("127.0.0.1:18731"));
        assert_eq!(p.p2p_listen, None);
        assert_eq!(p.p2p_dials, vec!["127.0.0.1:19998".to_string()]);
    }

    #[test]
    fn parse_args_serve_multiple_p2p_dials() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--p2p-dial".into(),
            "127.0.0.1:19998".into(),
            "--p2p-dial".into(),
            "127.0.0.1:19999".into(),
            "serve".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Serve);
        assert_eq!(
            p.p2p_dials,
            vec!["127.0.0.1:19998".to_string(), "127.0.0.1:19999".to_string(),]
        );
    }

    #[test]
    fn parse_args_p2p_listen_rejected_without_serve() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--p2p-listen".into(),
            "127.0.0.1:0".into(),
            "status".into(),
        ];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_p2p_dial_rejected_without_serve() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--p2p-dial".into(),
            "127.0.0.1:1".into(),
            "status".into(),
        ];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_rpc_listen_rejected_without_serve() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--rpc-listen".into(),
            "127.0.0.1:1".into(),
            "status".into(),
        ];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_rpc_api_key_rejected_without_serve() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--rpc-api-key".into(),
            "secret".into(),
            "status".into(),
        ];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_step_checkpoint_each() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--checkpoint-each".into(),
            "--blocks".into(),
            "2".into(),
            "step".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Step);
        assert_eq!(p.step_count, 2);
        assert!(p.checkpoint_each_block);
        assert_eq!(p.rpc_listen, None);
        assert_eq!(p.p2p_listen, None);
        assert!(p.p2p_dials.is_empty());
    }

    #[test]
    fn parse_args_checkpoint_each_rejected_without_step() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--checkpoint-each".into(),
            "status".into(),
        ];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_step_blocks() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--blocks".into(),
            "5".into(),
            "step".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Step);
        assert_eq!(p.step_count, 5);
        assert!(!p.checkpoint_each_block);
        assert_eq!(p.rpc_listen, None);
        assert_eq!(p.p2p_listen, None);
        assert!(p.p2p_dials.is_empty());
    }

    #[test]
    fn parse_args_blocks_rejected_without_step() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--blocks".into(),
            "2".into(),
            "status".into(),
        ];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_with_genesis() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--genesis".into(),
            "/chain/genesis.toml".into(),
            "status".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.data_dir, PathBuf::from("/tmp/x"));
        assert_eq!(p.genesis_toml, Some(PathBuf::from("/chain/genesis.toml")));
        assert_eq!(p.cmd, Cmd::Status);
        assert_eq!(p.step_count, 1);
        assert!(!p.checkpoint_each_block);
        assert_eq!(p.rpc_listen, None);
        assert_eq!(p.p2p_listen, None);
        assert!(p.p2p_dials.is_empty());
    }

    #[test]
    fn parse_args_status() {
        let args = vec!["--data-dir".into(), "/tmp/x".into(), "status".into()];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.data_dir, PathBuf::from("/tmp/x"));
        assert_eq!(p.cmd, Cmd::Status);
        assert_eq!(p.step_count, 1);
        assert!(!p.checkpoint_each_block);
        assert_eq!(p.rpc_listen, None);
        assert_eq!(p.p2p_listen, None);
        assert!(p.p2p_dials.is_empty());
    }

    #[test]
    fn parse_args_rejects_missing_data_dir() {
        assert!(parse_args(&["status".into()]).is_err());
    }

    #[test]
    fn parse_args_archive_export() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--archive-dir".into(),
            "/tmp/archive".into(),
            "archive-export".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::ArchiveExport);
        assert_eq!(p.archive_dir, Some(PathBuf::from("/tmp/archive")));
    }

    #[test]
    fn parse_args_archive_verify() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--archive-dir".into(),
            "/tmp/archive".into(),
            "archive-verify".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::ArchiveVerify);
        assert_eq!(p.archive_dir, Some(PathBuf::from("/tmp/archive")));
    }

    #[test]
    fn parse_args_archive_export_requires_archive_dir() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "archive-export".into(),
        ];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_archive_dir_rejected_without_archive_cmd() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--archive-dir".into(),
            "/tmp/archive".into(),
            "status".into(),
        ];
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn parse_args_store_defaults_to_redb() {
        let args = vec!["--data-dir".into(), "/tmp/x".into(), "status".into()];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.store_backend, StoreBackend::Redb);
    }

    #[test]
    fn parse_args_store_fs() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--store".into(),
            "fs".into(),
            "status".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.store_backend, StoreBackend::Fs);
    }

    #[test]
    fn parse_args_store_redb() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--store".into(),
            "redb".into(),
            "status".into(),
        ];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.store_backend, StoreBackend::Redb);
    }

    #[test]
    fn parse_args_store_rejects_unknown() {
        let args = vec![
            "--data-dir".into(),
            "/tmp/x".into(),
            "--store".into(),
            "rocksdb".into(),
            "status".into(),
        ];
        assert!(parse_args(&args).is_err());
    }
}
