//! Permawrite storage-operator daemon (`mfn-storage-operator`).

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
#[cfg(unix)]
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use mfn_storage_operator::{
    push_wallet_artifact_chunks_to_peers, run_daemon, serve_chunks, ChunkServeConfig,
    OperatorDaemonConfig, RpcClient, DEFAULT_RPC_ADDR,
};

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
    let mut rpc_api_key: Option<String> =
        env::var("MFN_RPC_API_KEY").ok().filter(|s| !s.is_empty());
    let mut wallet_path = PathBuf::from("wallet.json");
    let mut interval_secs = 30u64;
    let mut once = false;
    let mut listen_addr = "127.0.0.1:18780".to_string();
    let mut chunk_listen: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--rpc" {
            rpc_addr = args.get(i + 1).ok_or("--rpc requires HOST:PORT")?.clone();
            i += 2;
            continue;
        }
        if a == "--rpc-api-key" {
            let key = args
                .get(i + 1)
                .ok_or("--rpc-api-key requires a non-empty key")?;
            if key.is_empty() {
                return Err("--rpc-api-key requires a non-empty key".into());
            }
            rpc_api_key = Some(key.clone());
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
        if a == "--listen" {
            listen_addr = args
                .get(i + 1)
                .ok_or("--listen requires HOST:PORT")?
                .clone();
            i += 2;
            continue;
        }
        if a == "--chunk-listen" {
            chunk_listen = Some(
                args.get(i + 1)
                    .ok_or("--chunk-listen requires HOST:PORT")?
                    .clone(),
            );
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
    let stop = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst))
            .map_err(|e| format!("ctrlc handler: {e}"))?;
    }

    match sub {
        "run" => {
            if positional.len() > 1 {
                return Err("too many arguments for `run`".into());
            }
            run_daemon(
                OperatorDaemonConfig {
                    rpc_addr,
                    rpc_api_key,
                    wallet_path,
                    interval: Duration::from_secs(interval_secs),
                    once,
                    chunk_listen,
                },
                stop,
            )
            .map_err(|e| e.to_string())
        }
        "serve-chunks" => {
            if positional.len() > 1 {
                return Err("too many arguments for `serve-chunks`".into());
            }
            serve_chunks(
                ChunkServeConfig {
                    wallet_path,
                    listen_addr,
                },
                stop,
            )
            .map_err(|e| e.to_string())
        }
        "push-chunks" => {
            if positional.len() < 3 {
                return Err("push-chunks requires COMMITMENT_HASH_HEX PEER [PEER...]".into());
            }
            let commitment_hash_hex = positional[1].clone();
            let peers: Vec<String> = positional[2..].to_vec();
            let mut client = RpcClient::new(&rpc_addr);
            if let Some(key) = rpc_api_key {
                client = client.with_api_key(key);
            }
            let results = push_wallet_artifact_chunks_to_peers(
                &mut client,
                &wallet_path,
                &commitment_hash_hex,
                &peers,
            )
            .map_err(|e| e.to_string())?;
            for r in &results {
                println!("peer={} ok={} chunks_sent={}", r.peer, r.ok, r.chunks_sent);
                if let Some(err) = &r.error {
                    println!("peer_error={err}");
                }
            }
            if results.iter().all(|r| r.ok) {
                println!("push_chunks=ok");
                Ok(())
            } else {
                Err(format!(
                    "push-chunks failed for {} of {} peers",
                    results.iter().filter(|r| !r.ok).count(),
                    results.len()
                ))
            }
        }
        other => Err(format!(
            "unknown subcommand `{other}` (expected: run | serve-chunks | push-chunks)"
        )),
    }
}
