//! Long-running SPoRA proof loop over wallet upload artifacts (**M6**).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::chunk_http::{serve_chunks, ChunkServeConfig};
use crate::prove::{prove_from_wallet_artifact, ProveError};
use crate::rpc::{RpcClient, DEFAULT_RPC_ADDR};
use crate::upload_artifact_store::list_upload_artifacts;

/// Daemon configuration.
#[derive(Debug, Clone)]
pub struct OperatorDaemonConfig {
    /// `mfnd serve` JSON-RPC address.
    pub rpc_addr: String,
    /// Wallet JSON path (upload artifacts live beside it).
    pub wallet_path: PathBuf,
    /// Sleep between prove cycles.
    pub interval: Duration,
    /// Run a single cycle then exit.
    pub once: bool,
    /// When set, serve wallet upload chunks at this `host:port` (**M6.4**).
    pub chunk_listen: Option<String>,
}

impl Default for OperatorDaemonConfig {
    fn default() -> Self {
        Self {
            rpc_addr: DEFAULT_RPC_ADDR.to_string(),
            wallet_path: PathBuf::from("wallet.json"),
            interval: Duration::from_secs(30),
            once: false,
            chunk_listen: None,
        }
    }
}

/// Outcome of one commitment prove attempt in a cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveAttemptStatus {
    /// Proof queued on the node.
    Submitted {
        /// `submit_storage_proof` outcome kind.
        outcome_kind: String,
        /// Pool length after submit.
        pool_len: u64,
        /// Next block height.
        next_height: u32,
    },
    /// Prove skipped (RPC says unknown commitment, etc.).
    Skipped {
        /// Human-readable reason.
        reason: String,
    },
    /// Prove failed (validation or I/O).
    Failed {
        /// Human-readable error.
        error: String,
    },
}

/// One row from [`run_prove_cycle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProveAttempt {
    /// Commitment hash hex.
    pub commitment_hash_hex: String,
    /// Attempt result.
    pub status: ProveAttemptStatus,
}

/// Summary of a prove cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProveCycleSummary {
    /// Artifacts scanned.
    pub artifacts: u32,
    /// Successful submits.
    pub submitted: u32,
    /// Skipped attempts.
    pub skipped: u32,
    /// Failed attempts.
    pub failed: u32,
}

/// Run one prove pass over every local upload artifact.
pub fn run_prove_cycle(
    client: &mut RpcClient,
    wallet_path: &Path,
) -> Result<(ProveCycleSummary, Vec<ProveAttempt>), ProveError> {
    let entries = list_upload_artifacts(wallet_path)
        .map_err(|e| ProveError::Usage(format!("list artifacts: {e}")))?;
    let mut summary = ProveCycleSummary {
        artifacts: u32::try_from(entries.len()).unwrap_or(u32::MAX),
        ..ProveCycleSummary::default()
    };
    let mut attempts = Vec::with_capacity(entries.len());

    for entry in entries {
        let hash = entry.commitment_hash_hex.clone();
        match prove_from_wallet_artifact(client, wallet_path, &hash) {
            Ok(ok) => {
                summary.submitted = summary.submitted.saturating_add(1);
                attempts.push(ProveAttempt {
                    commitment_hash_hex: hash,
                    status: ProveAttemptStatus::Submitted {
                        outcome_kind: ok.submit.outcome_kind,
                        pool_len: ok.submit.pool_len,
                        next_height: ok.submit.next_height,
                    },
                });
            }
            Err(ProveError::Rpc(e)) => {
                let msg = e.to_string();
                if is_skippable_rpc(&msg) {
                    summary.skipped = summary.skipped.saturating_add(1);
                    attempts.push(ProveAttempt {
                        commitment_hash_hex: hash,
                        status: ProveAttemptStatus::Skipped { reason: msg },
                    });
                } else {
                    summary.failed = summary.failed.saturating_add(1);
                    attempts.push(ProveAttempt {
                        commitment_hash_hex: hash,
                        status: ProveAttemptStatus::Failed { error: msg },
                    });
                }
            }
            Err(ProveError::Usage(e)) => {
                summary.failed = summary.failed.saturating_add(1);
                attempts.push(ProveAttempt {
                    commitment_hash_hex: hash,
                    status: ProveAttemptStatus::Failed { error: e },
                });
            }
        }
    }
    Ok((summary, attempts))
}

fn is_skippable_rpc(msg: &str) -> bool {
    msg.contains("unknown storage commitment")
        || msg.contains("not found")
        || msg.contains("UnknownCommitment")
}

/// Run the daemon until `stop` is set or `config.once` completes one cycle.
pub fn run_daemon(config: OperatorDaemonConfig, stop: Arc<AtomicBool>) -> Result<(), ProveError> {
    let mut client = RpcClient::new(&config.rpc_addr);
    println!(
        "mfno_start rpc={} wallet={}",
        config.rpc_addr,
        config.wallet_path.display()
    );
    println!("mfno_interval_secs={}", config.interval.as_secs());
    if let Some(addr) = &config.chunk_listen {
        println!("mfno_chunk_listen addr={addr}");
    }

    let chunk_thread = config.chunk_listen.as_ref().map(|listen_addr| {
        let chunk_cfg = ChunkServeConfig {
            wallet_path: config.wallet_path.clone(),
            listen_addr: listen_addr.clone(),
        };
        let stop_chunk = Arc::clone(&stop);
        thread::spawn(move || {
            if let Err(e) = serve_chunks(chunk_cfg, stop_chunk) {
                eprintln!("mfno_chunk_exit error={e}");
            }
        })
    });

    let result = run_daemon_prove_loop(&mut client, &config, stop.as_ref());

    // Keep the chunk HTTP server alive when `--chunk-listen` is set: callers
    // (integration tests, operators) fetch chunks after `run --once` returns.
    if config.chunk_listen.is_none() {
        stop.store(true, Ordering::SeqCst);
    }
    if let Some(handle) = chunk_thread {
        if let Err(e) = handle.join() {
            eprintln!("mfno_chunk_join error={e:?}");
        }
    }

    result
}

fn run_daemon_prove_loop(
    client: &mut RpcClient,
    config: &OperatorDaemonConfig,
    stop: &AtomicBool,
) -> Result<(), ProveError> {
    loop {
        if stop.load(Ordering::SeqCst) {
            println!("mfno_stopping signal=stop");
            break;
        }

        let tip = client.get_tip().ok();
        let tip_height = tip
            .as_ref()
            .and_then(|t| t.tip_height)
            .map(|h| h.to_string())
            .unwrap_or_else(|| "none".to_string());
        println!("mfno_cycle_start tip_height={tip_height}");

        let (summary, attempts) = run_prove_cycle(client, &config.wallet_path)?;
        println!(
            "mfno_cycle_summary artifacts={} submitted={} skipped={} failed={}",
            summary.artifacts, summary.submitted, summary.skipped, summary.failed
        );
        for attempt in &attempts {
            match &attempt.status {
                ProveAttemptStatus::Submitted {
                    outcome_kind,
                    pool_len,
                    next_height,
                } => println!(
                    "mfno_prove commitment_hash={} outcome={outcome_kind} pool_len={pool_len} next_height={next_height}",
                    attempt.commitment_hash_hex
                ),
                ProveAttemptStatus::Skipped { reason } => println!(
                    "mfno_prove_skip commitment_hash={} reason={reason}",
                    attempt.commitment_hash_hex
                ),
                ProveAttemptStatus::Failed { error } => println!(
                    "mfno_prove_fail commitment_hash={} error={error}",
                    attempt.commitment_hash_hex
                ),
            }
        }
        println!("mfno_cycle_end");

        if config.once {
            break;
        }
        if stop.load(Ordering::SeqCst) {
            break;
        }
        thread::sleep(config.interval);
    }

    println!("mfno_exit ok");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn prove_cycle_empty_artifacts() {
        let dir = std::env::temp_dir().join(format!(
            "permawrite-mfno-cycle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let wallet = dir.join("w.json");
        std::fs::write(&wallet, b"{}").unwrap();
        let mut client = RpcClient::new("127.0.0.1:1");
        let (summary, attempts) = run_prove_cycle(&mut client, Path::new(&wallet)).unwrap();
        assert_eq!(summary.artifacts, 0);
        assert!(attempts.is_empty());
        std::fs::remove_dir_all(dir).ok();
    }
}
