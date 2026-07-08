//! Proactive replica repair: re-fan-out complete local inboxes when on-chain
//! storage goes stale (**B4** / permanence hardening).

use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mfn_consensus::StorageCommitment;
use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;
use mfn_store::chunk_inbox_complete;

use crate::p2p_chunk_fanout::load_complete_inbox_chunks_v2_wire;
use crate::p2p_fanout::P2pPeerSet;

/// Default staleness threshold: 2× anti-hoarding `proof_reward_window_slots` (~2 days at 12s slots).
pub const DEFAULT_REPAIR_THRESHOLD_SLOTS: u64 = DEFAULT_ENDOWMENT_PARAMS
    .proof_reward_window_slots
    .saturating_mul(2);

/// Default sweep interval when `MFND_REPAIR_INTERVAL_MS` is unset (5 minutes).
pub const DEFAULT_REPAIR_INTERVAL_MS: u64 = 300_000;

/// Env: minimum `current_slot − last_proven_slot` before repair fan-out (`0` disables sweep).
pub const MFND_REPAIR_THRESHOLD_SLOTS_ENV: &str = "MFND_REPAIR_THRESHOLD_SLOTS";

/// Env: milliseconds between repair sweeps.
pub const MFND_REPAIR_INTERVAL_MS_ENV: &str = "MFND_REPAIR_INTERVAL_MS";

/// Parse [`MFND_REPAIR_THRESHOLD_SLOTS`]; `0` disables the repair loop.
pub fn repair_threshold_slots_from_env() -> Result<u64, String> {
    match std::env::var(MFND_REPAIR_THRESHOLD_SLOTS_ENV) {
        Ok(raw) => raw.trim().parse::<u64>().map_err(|_| {
            format!("{MFND_REPAIR_THRESHOLD_SLOTS_ENV} must be a non-negative integer")
        }),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_REPAIR_THRESHOLD_SLOTS),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!(
            "{MFND_REPAIR_THRESHOLD_SLOTS_ENV} must be valid UTF-8"
        )),
    }
}

/// Parse [`MFND_REPAIR_INTERVAL_MS`] with a caller-supplied default.
pub fn repair_interval_ms_from_env(default_ms: u64) -> Result<u64, String> {
    match std::env::var(MFND_REPAIR_INTERVAL_MS_ENV) {
        Ok(raw) => {
            let ms = raw
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("{MFND_REPAIR_INTERVAL_MS_ENV} must be a positive integer"))?;
            if ms == 0 {
                return Err(format!("{MFND_REPAIR_INTERVAL_MS_ENV} must be at least 1"));
            }
            Ok(ms)
        }
        Err(std::env::VarError::NotPresent) => Ok(default_ms),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{MFND_REPAIR_INTERVAL_MS_ENV} must be valid UTF-8"))
        }
    }
}

/// One commit eligible for proactive repair with measured staleness.
pub struct RepairCandidate {
    /// Commitment hash.
    pub commit_hash: [u8; 32],
    /// Anchored commitment (for fan-out wire).
    pub commit: StorageCommitment,
    /// `current_slot − last_proven_slot` at selection time.
    pub stale_slots: u64,
}

/// Select on-chain storage entries that are stale and have a complete verified local inbox.
pub fn select_stale_repair_candidates<I>(
    storage: I,
    current_slot: u64,
    repair_threshold_slots: u64,
    data_root: &Path,
) -> Vec<RepairCandidate>
where
    I: IntoIterator<Item = ([u8; 32], u64, StorageCommitment)>,
{
    if repair_threshold_slots == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (commit_hash, last_proven_slot, commit) in storage {
        let stale_slots = current_slot.saturating_sub(last_proven_slot);
        if stale_slots <= repair_threshold_slots {
            continue;
        }
        let commit_hex = hex::encode(commit_hash);
        if !chunk_inbox_complete(data_root, &commit_hex, commit.num_chunks).unwrap_or(false) {
            continue;
        }
        if load_complete_inbox_chunks_v2_wire(data_root, &commit_hash, &commit).is_none() {
            continue;
        }
        out.push(RepairCandidate {
            commit_hash,
            commit,
            stale_slots,
        });
    }
    out
}

/// Periodic proactive repair loop (**B4**).
pub struct RepairSweepLoop {
    /// Fan-out registry (chain + inbox root).
    pub peer_set: Arc<P2pPeerSet>,
    /// Sleep interval between sweeps.
    pub interval_ms: u64,
    /// Staleness threshold in slots.
    pub repair_threshold_slots: u64,
}

/// Spawn background repair sweeps; no-op when `repair_threshold_slots == 0`.
pub fn spawn_repair_sweep_loop(cfg: RepairSweepLoop) -> Result<(), String> {
    if cfg.repair_threshold_slots == 0 {
        return Ok(());
    }
    let RepairSweepLoop {
        peer_set,
        interval_ms,
        repair_threshold_slots,
    } = cfg;
    thread::Builder::new()
        .name("mfnd-repair-sweep".into())
        .spawn(move || loop {
            let current_slot = peer_set.current_chain_slot();
            let candidates = {
                let storage = match peer_set.chain_storage_snapshot() {
                    Some(s) => s,
                    None => {
                        thread::sleep(Duration::from_millis(interval_ms));
                        continue;
                    }
                };
                select_stale_repair_candidates(
                    storage,
                    current_slot,
                    repair_threshold_slots,
                    peer_set.data_root(),
                )
            };
            for cand in candidates {
                let commit_hex = hex::encode(cand.commit_hash);
                println!(
                    "mfnd_p2p_repair_fanout commit={commit_hex} stale_slots={}",
                    cand.stale_slots
                );
                let _ = std::io::Write::flush(&mut std::io::stdout());
                peer_set.fanout_inbox_chunks_for_commits(
                    std::slice::from_ref(&(cand.commit_hash, cand.commit)),
                    None,
                );
            }
            thread::sleep(Duration::from_millis(interval_ms));
        })
        .map_err(|e| format!("mfnd serve: spawn repair sweep loop: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use mfn_storage::{build_storage_commitment, DEFAULT_ENDOWMENT_PARAMS};
    use mfn_store::{save_chunk_inbox, CHUNK_INBOX_DIR};

    use super::*;

    fn sample_commit(last_proven_slot: u64) -> (mfn_storage::BuiltCommitment, [u8; 32], u64) {
        let payload: Vec<u8> = (0u32..256).map(|i| (i % 251) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(256),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let hash = mfn_consensus::storage_commitment_hash(&built.commit);
        (built, hash, last_proven_slot)
    }

    #[test]
    fn select_stale_repair_candidates_skips_fresh_and_incomplete_inbox() {
        let dir = std::env::temp_dir().join(format!("mfn-repair-sweep-{}", std::process::id()));
        let payload: Vec<u8> = (0u32..256).map(|i| (i % 251) as u8).collect();
        let (built, hash, last_proven_slot) = sample_commit(100);
        let storage = BTreeMap::from([(hash, (last_proven_slot, built.commit.clone()))]);
        assert!(select_stale_repair_candidates(
            storage.iter().map(|(h, (slot, c))| (*h, *slot, c.clone())),
            200,
            50,
            &dir
        )
        .is_empty());
        let slices =
            mfn_storage::chunk_data(&payload, built.commit.chunk_size as usize).expect("chunks");
        for (i, bytes) in slices.iter().enumerate() {
            save_chunk_inbox(&dir, &hash, u32::try_from(i).unwrap(), bytes).expect("save");
        }
        let picked = select_stale_repair_candidates(
            storage.iter().map(|(h, (slot, c))| (*h, *slot, c.clone())),
            200,
            50,
            &dir,
        );
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].commit_hash, hash);
        assert_eq!(picked[0].stale_slots, 100);
        let _ = CHUNK_INBOX_DIR;
    }

    #[test]
    fn repair_threshold_env_zero_disables_default() {
        std::env::set_var(MFND_REPAIR_THRESHOLD_SLOTS_ENV, "0");
        assert_eq!(repair_threshold_slots_from_env().expect("parse"), 0);
        std::env::remove_var(MFND_REPAIR_THRESHOLD_SLOTS_ENV);
    }
}
