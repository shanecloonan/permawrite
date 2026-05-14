//! Minimal `mfnd` command-line driver (M2.1.1 + M2.1.2 + M2.1.3 + M2.1.4 + M2.1.5 + M2.1.6 + M2.1.8 + M2.1.8.1 + M2.1.9).
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
//! **`serve`** (M2.1.6 + **M2.1.8** + **M2.1.10**) binds a loopback TCP port and answers one
//! newline-delimited JSON request per connection (`get_tip`, `submit_tx`, `get_block`)
//! against a live chain + mempool until the process exits; each response is a
//! single JSON-RPC 2.0 object (`jsonrpc`, `id`, `result` or `error`).
//! Batching, HTTP/WebSocket, P2P, and durable mempool persistence still land
//! in later M2.x milestones.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::thread;

use mfn_bls::bls_keygen_from_seed;
use mfn_consensus::{build_coinbase, emission_at_height, PayoutAddress, ValidatorSecrets};
use mfn_crypto::vrf::vrf_keygen_from_seed;

use crate::{
    demo_genesis, genesis_config_from_json_path, hex_seed32, produce_solo_block, BlockInputs,
    Chain, ChainConfig, ChainStore, Mempool, MempoolConfig,
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
}

fn usage() -> &'static str {
    "usage: mfnd --data-dir <DIR> [OPTIONS] <COMMAND>\n\
     \n\
     options:\n\
       --genesis PATH   optional JSON genesis spec (version 1; see crate testdata/)\n\
       --blocks N       only for `step`: produce and apply N blocks in sequence\n\
                        (default 1; by default one checkpoint after the last block)\n\
       --checkpoint-each  only for `step`: write checkpoint after every applied block\n\
       --rpc-listen ADDR:PORT   only for `serve` (default 127.0.0.1:18731)\n\
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
               (one request line per connection; methods: get_tip, submit_tx, get_block;\n\
                submit_tx params: {\"tx_hex\":...} or [\"...\"] hex string;\n\
                get_block params: {\"height\":N} or [N] for heights 1..=tip)\n"
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

/// Max regular txs pulled from the mempool into one block body (coinbase is extra).
const MFND_MEMPOOL_DRAIN_MAX: usize = 256;

fn producer_fee_share_of_summed_fees(fee_sum: u128, fee_to_treasury_bps: u16) -> u64 {
    let treasury = fee_sum.saturating_mul(u128::from(fee_to_treasury_bps)) / 10_000u128;
    let producer = fee_sum.saturating_sub(treasury);
    u64::try_from(producer).unwrap_or(u64::MAX)
}

fn run_solo_step(
    store: &ChainStore,
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

    let mut chain = store
        .load_or_genesis(cfg.clone())
        .map_err(|e| format!("{e}"))?;
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

    for bi in 0..step_count {
        let tip = chain
            .tip_height()
            .ok_or_else(|| "mfnd step: internal error: missing tip height".to_string())?;
        let next_height = tip
            .checked_add(1)
            .ok_or_else(|| "mfnd step: tip height overflow".to_string())?;
        let timestamp = cfg.genesis.timestamp.saturating_add(u64::from(next_height));
        let (params, emission_params, emission) = {
            let st = chain.state();
            (
                st.params,
                st.emission_params,
                emission_at_height(u64::from(next_height), &st.emission_params),
            )
        };

        let drained = pool.drain(MFND_MEMPOOL_DRAIN_MAX);
        let mut fee_sum: u128 = 0;
        for t in &drained {
            fee_sum = fee_sum.saturating_add(u128::from(t.fee));
        }
        let producer_extra =
            producer_fee_share_of_summed_fees(fee_sum, emission_params.fee_to_treasury_bps);
        let coinbase_amount = emission.saturating_add(producer_extra);

        let cb_payout = PayoutAddress {
            view_pub: payout.view_pub,
            spend_pub: payout.spend_pub,
        };
        let cb = build_coinbase(u64::from(next_height), coinbase_amount, &cb_payout)
            .map_err(|e| format!("build_coinbase: {e}"))?;
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
            storage_proofs: Vec::new(),
        };
        let block = produce_solo_block(&chain, &producer, &secrets, params, inputs)
            .map_err(|e| format!("produce_solo_block: {e}"))?;
        chain
            .apply(&block)
            .map_err(|e| format!("apply_block: {e}"))?;
        pool.remove_mined(&block);
        store
            .append_block(&block)
            .map_err(|e| format!("append_block: {e}"))?;

        if checkpoint_each_block {
            let meta = store.save(&chain).map_err(|e| format!("{e}"))?;
            let h = chain.tip_height().expect("tip after apply");
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
    println!(
        "new_tip_height={}",
        chain.tip_height().expect("tip after apply")
    );
    println!("new_tip_id={}", hex32(last_tip_id));
    Ok(())
}

fn run(args: Vec<String>) -> Result<(), String> {
    let argv: Vec<String> = args.into_iter().skip(1).collect();
    let parsed = parse_args(&argv)?;
    let store = ChainStore::new(&parsed.data_dir);
    let cfg = resolve_chain_config(&parsed)?;

    match parsed.cmd {
        Cmd::Status => {
            let had_checkpoint = store.has_any_checkpoint();
            let chain = store.load_or_genesis(cfg).map_err(|e| format!("{e}"))?;
            print_status(&chain, had_checkpoint);
        }
        Cmd::Save => {
            let chain = store.load_or_genesis(cfg).map_err(|e| format!("{e}"))?;
            let meta = store.save(&chain).map_err(|e| format!("{e}"))?;
            println!(
                "saved_checkpoint_bytes={} path={}",
                meta.bytes_written,
                meta.checkpoint_path.display()
            );
        }
        Cmd::Run => {
            let had_checkpoint = store.has_any_checkpoint();
            let chain = Arc::new(Mutex::new(
                store.load_or_genesis(cfg).map_err(|e| format!("{e}"))?,
            ));
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
                ctrlc::set_handler(move || {
                    let guard = match chain_c.lock() {
                        Ok(g) => g,
                        Err(_) => {
                            eprintln!("mfnd: chain mutex poisoned on shutdown");
                            std::process::exit(1);
                        }
                    };
                    match ChainStore::new(&dir).save(&guard) {
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
                let meta = ChainStore::new(&parsed.data_dir)
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
        Cmd::Serve => {
            let listen = parsed.rpc_listen.as_deref().unwrap_or("127.0.0.1:18731");
            crate::mfnd_serve::run_serve(&store, cfg, listen)?;
        }
    }
    Ok(())
}

fn print_status(chain: &Chain, had_checkpoint_on_disk: bool) {
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

fn parse_args(args: &[String]) -> Result<Parsed, String> {
    let mut data_dir: Option<PathBuf> = None;
    let mut genesis_toml: Option<PathBuf> = None;
    let mut step_count: Option<u32> = None;
    let mut checkpoint_each_block = false;
    let mut rpc_listen: Option<String> = None;
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
    Ok(Parsed {
        data_dir,
        genesis_toml,
        cmd,
        step_count,
        checkpoint_each_block,
        rpc_listen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_step() {
        let args = vec!["--data-dir".into(), "/tmp/x".into(), "step".into()];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Step);
        assert_eq!(p.step_count, 1);
        assert!(!p.checkpoint_each_block);
        assert_eq!(p.rpc_listen, None);
    }

    #[test]
    fn parse_args_serve() {
        let args = vec!["--data-dir".into(), "/tmp/x".into(), "serve".into()];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.cmd, Cmd::Serve);
        assert_eq!(p.rpc_listen, None);
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
    }

    #[test]
    fn parse_args_rejects_missing_data_dir() {
        assert!(parse_args(&["status".into()]).is_err());
    }
}
