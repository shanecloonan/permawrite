//! Permawrite storage-operator daemon (`mfn-storage-operator`).

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
#[cfg(unix)]
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mfn_storage_operator::{run_daemon, OperatorDaemonConfig, DEFAULT_RPC_ADDR};

fn main() -> ExitCode {
    match run_cli(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli(args: Vec<String>) -> Result<(), String> {
    let mut rpc_addr = DEFAULT_RPC_ADDR.to_string();
    let mut wallet_path = PathBuf::from("wallet.json");
    let mut interval_secs = 30u64;
    let mut once = false;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--rpc" {
            rpc_addr = args.get(i + 1).ok_or("--rpc requires HOST:PORT")?.clone();
            i += 2;
            continue;
        }
        if a == "--wallet" {
            wallet_path = PathBuf::from(args.get(i + 1).ok_or("--wallet requires PATH")?);
            i += 2;
            continue;
        }
        if a == "--interval" {
            let s = args.get(i + 1).ok_or("--interval requires SECONDS")?;
            interval_secs = s
                .parse()
                .map_err(|_| format!("invalid --interval value: {s}"))?;
            i += 2;
            continue;
        }
        if a == "--once" {
            once = true;
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            return Err(format!("unknown option `{a}`"));
        }
        positional.push(args[i].clone());
        i += 1;
    }

    let sub = positional.first().map(String::as_str).unwrap_or("run");
    if sub != "run" {
        return Err(format!(
            "unknown subcommand `{sub}` (expected: mfn-storage-operator run)"
        ));
    }
    if positional.len() > 1 {
        return Err("too many arguments (only `run` is supported)".into());
    }

    let stop = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst))
            .map_err(|e| format!("ctrlc handler: {e}"))?;
    }

    run_daemon(
        OperatorDaemonConfig {
            rpc_addr,
            wallet_path,
            interval: Duration::from_secs(interval_secs),
            once,
        },
        stop,
    )
    .map_err(|e| e.to_string())
}
