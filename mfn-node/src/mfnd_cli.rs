//! Minimal `mfnd` command-line driver (M2.1.1 + M2.1.2).
//!
//! Backs the `mfnd` binary: load-or-genesis against a [`ChainStore`], print
//! status, save checkpoints, or block until a graceful shutdown trigger then
//! persist. On Unix the `run` command installs a Ctrl+C handler; on Windows it
//! waits for Enter (so the crate stays buildable on `windows-gnu` hosts without
//! pulling `windows-sys`). Optional `--genesis` loads a TOML chain spec; see
//! [`crate::genesis_spec`]. No JSON-RPC, mempool wiring, or block production
//! loop yet — those attach in later M2.x milestones.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::thread;

use crate::{demo_genesis, genesis_config_from_json_path, Chain, ChainConfig, ChainStore};

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Parsed {
    data_dir: PathBuf,
    genesis_toml: Option<PathBuf>,
    cmd: Cmd,
}

fn usage() -> &'static str {
    "usage: mfnd --data-dir <DIR> [OPTIONS] <COMMAND>\n\
     \n\
     options:\n\
       --genesis PATH   optional JSON genesis spec (version 1; see crate testdata/)\n\
     \n\
     commands:\n\
       status  print tip height, ids, and whether a checkpoint existed on disk\n\
       save    persist the current chain checkpoint and exit\n\
       run     load or genesis, then wait for shutdown and save checkpoint:\n\
               Unix: Ctrl+C   Windows: press Enter\n"
}

fn resolve_chain_config(parsed: &Parsed) -> Result<ChainConfig, String> {
    let genesis = match &parsed.genesis_toml {
        Some(p) => genesis_config_from_json_path(Path::new(p)).map_err(|e| e.to_string())?,
        None => demo_genesis::empty_local_dev_genesis(),
    };
    Ok(ChainConfig::new(genesis))
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
        other => return Err(format!("unknown command `{other}`\n{}", usage())),
    };
    Ok(Parsed {
        data_dir,
        genesis_toml,
        cmd,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn parse_args_status() {
        let args = vec!["--data-dir".into(), "/tmp/x".into(), "status".into()];
        let p = parse_args(&args).unwrap();
        assert_eq!(p.data_dir, PathBuf::from("/tmp/x"));
        assert_eq!(p.cmd, Cmd::Status);
    }

    #[test]
    fn parse_args_rejects_missing_data_dir() {
        assert!(parse_args(&["status".into()]).is_err());
    }
}
