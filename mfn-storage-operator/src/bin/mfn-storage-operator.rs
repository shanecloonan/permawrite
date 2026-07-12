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
    list_upload_artifacts, load_network_manifest,
    pm23::{pm23_hard_fail_enabled, pm23_storage_operator_env_warnings},
    push_wallet_artifact_chunks_to_peers, run_daemon, serve_chunks, ChunkPushPeerResult,
    ChunkServeConfig, OperatorDaemonConfig, RpcClient, DEFAULT_RPC_ADDR,
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
    for warning in pm23_storage_operator_env_warnings() {
        eprintln!("{warning}");
        if pm23_hard_fail_enabled() {
            return Err(format!(
                "PM23 hard fail: {warning} (unset validator seed env or disable \
                 MFN_STORAGE_OPERATOR_PM23_HARD_FAIL / MFND_PM23_HARD_FAIL)"
            ));
        }
    }
    let mut rpc_addr = env::var("MFN_RPC")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_RPC_ADDR.to_string());
    let mut rpc_api_key: Option<String> =
        env::var("MFN_RPC_API_KEY").ok().filter(|s| !s.is_empty());
    let mut wallet_path = env::var("MFN_WALLET")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("wallet.json"));
    let mut interval_secs = 30u64;
    let mut once = false;
    let mut json = false;
    let mut listen_addr = "127.0.0.1:18780".to_string();
    let mut chunk_listen: Option<String> = None;
    let mut manifest_path: Option<PathBuf> = env::var("MFN_OPERATOR_MANIFEST")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--manifest" {
            manifest_path = Some(PathBuf::from(
                args.get(i + 1).ok_or("--manifest requires PATH")?,
            ));
            i += 2;
            continue;
        }
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
        if a == "--json" {
            json = true;
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            return Err(format!("unknown option `{a}`"));
        }
        positional.push(args[i].clone());
        i += 1;
    }

    let network_manifest = manifest_path
        .as_ref()
        .map(|p| load_network_manifest(p))
        .transpose()?;
    if let Some(manifest) = &network_manifest {
        if let Some(rpc) = &manifest.observer_rpc {
            if rpc_addr == DEFAULT_RPC_ADDR && !rpc.trim().is_empty() {
                rpc_addr = rpc.trim().to_string();
            }
        }
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
                    json_logs: json,
                },
                stop,
            )
            .map_err(|e| e.to_string())
        }
        "serve-chunks" => {
            if positional.len() > 1 {
                return Err("too many arguments for `serve-chunks`".into());
            }
            if json {
                return Err("--json is only supported for `push-chunks`, `push-all-chunks`, and `run`".into());
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
            if positional.len() < 2 {
                return Err("push-chunks requires COMMITMENT_HASH_HEX [PEER...]".into());
            }
            let commitment_hash_hex = positional[1].clone();
            let mut peers: Vec<String> = positional.get(2..).unwrap_or(&[]).to_vec();
            if peers.is_empty() {
                if let Some(manifest) = &network_manifest {
                    peers = manifest.effective_replication_peers();
                }
            }
            if peers.is_empty() {
                return Err("push-chunks requires PEER [PEER...] or manifest replication_peers".into());
            }
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
            let ok_count = results.iter().filter(|r| r.ok).count();
            if json {
                print_push_chunks_json(&commitment_hash_hex, &peers, &results)?;
                if ok_count == results.len() {
                    return Ok(());
                }
                return Err(format!(
                    "push-chunks failed for {} of {} peers",
                    results.len() - ok_count,
                    results.len()
                ));
            }
            for r in &results {
                println!("peer={} ok={} chunks_sent={}", r.peer, r.ok, r.chunks_sent);
                if let Some(err) = &r.error {
                    println!("peer_error={err}");
                }
            }
            if ok_count == results.len() {
                println!("push_chunks=ok");
                Ok(())
            } else {
                Err(format!(
                    "push-chunks failed for {} of {} peers",
                    results.len() - ok_count,
                    results.len()
                ))
            }
        }
        "push-all-chunks" => {
            if positional.len() > 1 {
                return Err("too many arguments for `push-all-chunks`".into());
            }
            let mut peers: Vec<String> = Vec::new();
            if let Some(manifest) = &network_manifest {
                peers = manifest.effective_replication_peers();
            }
            if peers.is_empty() {
                return Err(
                    "push-all-chunks requires manifest replication_peers (--manifest or MFN_OPERATOR_MANIFEST)".into(),
                );
            }
            let entries = list_upload_artifacts(&wallet_path)
                .map_err(|e| format!("list upload artifacts: {e}"))?;
            if entries.is_empty() {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "artifacts": 0,
                            "peers": peers,
                            "push_all_chunks": "ok",
                            "results": [],
                        }))
                        .map_err(|e| e.to_string())?
                    );
                } else {
                    println!("push_all_chunks=ok artifacts=0");
                }
                return Ok(());
            }
            let mut client = RpcClient::new(&rpc_addr);
            if let Some(key) = rpc_api_key {
                client = client.with_api_key(key);
            }
            let mut all_results = Vec::with_capacity(entries.len());
            let mut total_ok = 0usize;
            let mut total_fail = 0usize;
            for entry in &entries {
                let hash = entry.commitment_hash_hex.clone();
                let results = push_wallet_artifact_chunks_to_peers(
                    &mut client,
                    &wallet_path,
                    &hash,
                    &peers,
                )
                .map_err(|e| e.to_string())?;
                let ok_count = results.iter().filter(|r| r.ok).count();
                if ok_count == results.len() {
                    total_ok += 1;
                } else {
                    total_fail += 1;
                }
                all_results.push((hash, results));
            }
            if json {
                let results_json: Vec<_> = all_results
                    .iter()
                    .map(|(hash, peer_results)| {
                        push_chunks_json(hash, &peers, peer_results)
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "artifacts": entries.len(),
                        "peers": peers,
                        "artifacts_ok": total_ok,
                        "artifacts_failed": total_fail,
                        "results": results_json,
                        "push_all_chunks": if total_fail == 0 { "ok" } else { "partial_failure" },
                    }))
                    .map_err(|e| e.to_string())?
                );
            } else {
                for (hash, results) in &all_results {
                    let ok_count = results.iter().filter(|r| r.ok).count();
                    println!(
                        "commitment_hash={hash} peers_ok={ok_count}/{}",
                        results.len()
                    );
                }
                println!(
                    "push_all_chunks={} artifacts={} ok={} failed={}",
                    if total_fail == 0 { "ok" } else { "partial_failure" },
                    entries.len(),
                    total_ok,
                    total_fail
                );
            }
            if total_fail == 0 {
                Ok(())
            } else {
                Err(format!(
                    "push-all-chunks failed for {total_fail} of {} artifacts",
                    entries.len()
                ))
            }
        }
        "manifest-info" => {
            if positional.len() > 1 {
                return Err("too many arguments for `manifest-info`".into());
            }
            let manifest = network_manifest
                .ok_or("manifest-info requires --manifest PATH or MFN_OPERATOR_MANIFEST")?;
            let peers = manifest.effective_replication_peers();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "observer_rpc": manifest.observer_rpc,
                        "effective_rpc": rpc_addr,
                        "replication_peers": manifest.replication_peers,
                        "replication_peers_examples": manifest.replication_peers_examples,
                        "effective_replication_peers": peers,
                    }))
                    .map_err(|e| e.to_string())?
                );
            } else {
                if let Some(rpc) = &manifest.observer_rpc {
                    println!("observer_rpc={rpc}");
                }
                println!("effective_rpc={rpc_addr}");
                for peer in &peers {
                    println!("replication_peer={peer}");
                }
            }
            Ok(())
        }
        other => Err(format!(
            "unknown subcommand `{other}` (expected: run | serve-chunks | push-chunks | push-all-chunks | manifest-info)"
        )),
    }
}

fn print_push_chunks_json(
    commitment_hash_hex: &str,
    peers: &[String],
    results: &[ChunkPushPeerResult],
) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(&push_chunks_json(commitment_hash_hex, peers, results))
            .map_err(|e| e.to_string())?
    );
    Ok(())
}

fn push_chunks_json(
    commitment_hash_hex: &str,
    peers: &[String],
    results: &[ChunkPushPeerResult],
) -> serde_json::Value {
    let ok_count = results.iter().filter(|r| r.ok).count();
    serde_json::json!({
        "commitment_hash": commitment_hash_hex,
        "peers": peers,
        "peers_attempted": results.len(),
        "peers_ok": ok_count,
        "peers_failed": results.len().saturating_sub(ok_count),
        "results": results.iter().map(push_peer_result_json).collect::<Vec<_>>(),
        "push_chunks": if ok_count == results.len() { "ok" } else { "partial_failure" },
    })
}

fn push_peer_result_json(r: &ChunkPushPeerResult) -> serde_json::Value {
    let mut value = serde_json::json!({
        "peer": &r.peer,
        "ok": r.ok,
        "chunks_sent": r.chunks_sent,
    });
    if let Some(error) = &r.error {
        value
            .as_object_mut()
            .expect("push peer result json object literal")
            .insert("error".into(), serde_json::json!(error));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_all_chunks_empty_artifacts_json_shape() {
        let value = serde_json::json!({
            "artifacts": 0,
            "peers": ["127.0.0.1:18740"],
            "push_all_chunks": "ok",
            "results": [],
        });
        assert_eq!(value["artifacts"], 0);
        assert_eq!(value["push_all_chunks"], "ok");
        assert!(value["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn push_chunks_json_reports_peer_results() {
        let results = vec![
            ChunkPushPeerResult {
                peer: "127.0.0.1:18740".into(),
                chunks_sent: 3,
                ok: true,
                error: None,
            },
            ChunkPushPeerResult {
                peer: "127.0.0.1:18741".into(),
                chunks_sent: 0,
                ok: false,
                error: Some("connection refused".into()),
            },
        ];
        let peers = vec!["127.0.0.1:18740".into(), "127.0.0.1:18741".into()];

        let value = push_chunks_json(&"11".repeat(32), &peers, &results);

        assert_eq!(value["commitment_hash"], "11".repeat(32));
        assert_eq!(value["peers_attempted"], 2);
        assert_eq!(value["peers_ok"], 1);
        assert_eq!(value["peers_failed"], 1);
        assert_eq!(value["push_chunks"], "partial_failure");
        assert_eq!(value["results"][0]["chunks_sent"], 3);
        assert_eq!(value["results"][1]["error"], "connection refused");
    }
}
