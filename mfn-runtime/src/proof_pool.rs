//! In-memory SPoRA proof pool (**M3.22**).
//!
//! Storage operators submit proofs via JSON-RPC; producers drain this pool
//! into `BlockInputs::storage_proofs` on the next block. Admission validates
//! each proof against the *expected next* block context (`prev_hash` = current
//! tip, `slot` = next height).

use std::collections::BTreeMap;

use mfn_consensus::ChainState;
use mfn_storage::{decode_storage_proof, verify_storage_proof, StorageProof, StorageProofCheck};

/// Tuning for [`ProofPool`].
#[derive(Clone, Copy, Debug)]
pub struct ProofPoolConfig {
    /// Maximum distinct commitments held at once.
    pub max_entries: usize,
}

impl ProofPoolConfig {
    /// Default cap for a single-node / testnet operator queue.
    pub const fn default_config() -> Self {
        Self { max_entries: 256 }
    }
}

impl Default for ProofPoolConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Outcome of [`ProofPool::admit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofAdmitOutcome {
    /// First admission for this `commit_hash`.
    Fresh,
    /// Replaced a prior proof for the same commitment.
    Replaced,
}

/// Errors from [`ProofPool::admit`].
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ProofAdmitError {
    /// Commitment is not registered in chain storage.
    #[error("unknown storage commitment (hash={commit_hash_hex})")]
    UnknownCommitment {
        /// Hex prefix of `proof.commit_hash`.
        commit_hash_hex: String,
    },
    /// Wire decode failed.
    #[error("decode_storage_proof: {0}")]
    Decode(String),
    /// SPoRA verification failed for the next-block challenge.
    #[error("storage proof invalid for next block: {reason:?}")]
    InvalidForNextBlock {
        /// `verify_storage_proof` result.
        reason: StorageProofCheck,
    },
    /// Pool is full and this `commit_hash` is new.
    #[error("proof pool full (max_entries={max_entries})")]
    PoolFull {
        /// Configured cap.
        max_entries: usize,
    },
}

/// Pending SPoRA proofs keyed by `commit_hash` (one proof per commitment).
#[derive(Clone, Debug, Default)]
pub struct ProofPool {
    cfg: ProofPoolConfig,
    by_commit: BTreeMap<[u8; 32], StorageProof>,
}

impl ProofPool {
    /// Empty pool with default config.
    #[must_use]
    pub fn new(cfg: ProofPoolConfig) -> Self {
        Self {
            cfg,
            by_commit: BTreeMap::new(),
        }
    }

    /// Number of pending proofs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_commit.len()
    }

    /// Whether the pool has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_commit.is_empty()
    }

    /// Sorted lowercase-hex commitment hashes currently queued.
    #[must_use]
    pub fn commit_hashes(&self) -> Vec<[u8; 32]> {
        self.by_commit.keys().copied().collect()
    }

    /// Pending proofs in canonical `commit_hash` order (for snapshots).
    #[must_use]
    pub fn proofs_sorted(&self) -> Vec<StorageProof> {
        self.by_commit.values().cloned().collect()
    }

    /// Re-admit every proof from a decoded snapshot against the current next-block context.
    ///
    /// Proofs that no longer verify (tip moved, wrong challenge index) are skipped.
    pub fn restore_snapshot(
        &mut self,
        proofs: impl IntoIterator<Item = StorageProof>,
        state: &ChainState,
        prev_block_id: &[u8; 32],
        next_height: u32,
    ) -> crate::proof_pool_snapshot::ProofPoolRestoreStats {
        let mut stats = crate::proof_pool_snapshot::ProofPoolRestoreStats::default();
        for proof in proofs {
            stats.loaded = stats.loaded.saturating_add(1);
            match self.admit(proof, state, prev_block_id, next_height) {
                Ok(_) => stats.admitted = stats.admitted.saturating_add(1),
                Err(ProofAdmitError::PoolFull { .. }) => {
                    stats.skipped = stats.skipped.saturating_add(1);
                }
                Err(_) => stats.skipped = stats.skipped.saturating_add(1),
            }
        }
        stats
    }

    /// Admit a decoded proof for inclusion in the *next* block.
    pub fn admit(
        &mut self,
        proof: StorageProof,
        state: &ChainState,
        prev_block_id: &[u8; 32],
        next_height: u32,
    ) -> Result<ProofAdmitOutcome, ProofAdmitError> {
        let commit_hash = proof.commit_hash;
        let commit_hash_hex = hex_short(&commit_hash);
        let entry =
            state
                .storage
                .get(&commit_hash)
                .ok_or_else(|| ProofAdmitError::UnknownCommitment {
                    commit_hash_hex: commit_hash_hex.clone(),
                })?;
        let verdict = verify_storage_proof(&entry.commit, prev_block_id, next_height, &proof);
        if !verdict.is_valid() {
            return Err(ProofAdmitError::InvalidForNextBlock { reason: verdict });
        }
        use std::collections::btree_map::Entry;
        if let Entry::Occupied(mut e) = self.by_commit.entry(commit_hash) {
            e.insert(proof);
            return Ok(ProofAdmitOutcome::Replaced);
        }
        if self.by_commit.len() >= self.cfg.max_entries {
            return Err(ProofAdmitError::PoolFull {
                max_entries: self.cfg.max_entries,
            });
        }
        self.by_commit.insert(commit_hash, proof);
        Ok(ProofAdmitOutcome::Fresh)
    }

    /// Admit canonical wire bytes (same shape as `submit_storage_proof`).
    pub fn admit_wire(
        &mut self,
        wire: &[u8],
        state: &ChainState,
        prev_block_id: &[u8; 32],
        next_height: u32,
    ) -> Result<ProofAdmitOutcome, ProofAdmitError> {
        let proof =
            decode_storage_proof(wire).map_err(|e| ProofAdmitError::Decode(e.to_string()))?;
        self.admit(proof, state, prev_block_id, next_height)
    }

    /// Drain every proof that still verifies for the given next-block context.
    ///
    /// Proofs that fail re-verification (e.g. tip moved) are dropped.
    #[must_use]
    pub fn drain_verified(
        &mut self,
        state: &ChainState,
        prev_block_id: &[u8; 32],
        next_height: u32,
    ) -> Vec<StorageProof> {
        let keys: Vec<[u8; 32]> = self.by_commit.keys().copied().collect();
        let mut out = Vec::new();
        for hash in keys {
            let Some(proof) = self.by_commit.remove(&hash) else {
                continue;
            };
            let Some(entry) = state.storage.get(&proof.commit_hash) else {
                continue;
            };
            let verdict = verify_storage_proof(&entry.commit, prev_block_id, next_height, &proof);
            if verdict.is_valid() {
                out.push(proof);
            }
        }
        out
    }

    /// Remove proofs that landed in `block.storage_proofs`.
    #[must_use]
    pub fn remove_mined(&mut self, commit_hashes: impl IntoIterator<Item = [u8; 32]>) -> usize {
        let mut removed = 0usize;
        for h in commit_hashes {
            if self.by_commit.remove(&h).is_some() {
                removed = removed.saturating_add(1);
            }
        }
        removed
    }

    /// Drop every pending proof.
    pub fn clear(&mut self) {
        self.by_commit.clear();
    }
}

fn hex_short(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in id.iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use mfn_consensus::{
        apply_block, apply_genesis, build_genesis, build_unsealed_header, seal_block, ApplyOutcome,
        ChainState, GenesisConfig, DEFAULT_CONSENSUS_PARAMS, DEFAULT_EMISSION_PARAMS,
    };
    use mfn_storage::{
        build_storage_commitment, build_storage_proof, encode_storage_proof,
        DEFAULT_ENDOWMENT_PARAMS,
    };

    use super::*;

    fn genesis_with_storage() -> (ChainState, BuiltFixture) {
        let payload: Vec<u8> = (0u32..4096).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(4096),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commitment");
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: vec![built.commit.clone()],
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let st = apply_genesis(&g, &cfg).expect("genesis");
        (st, BuiltFixture { payload, built })
    }

    struct BuiltFixture {
        payload: Vec<u8>,
        built: mfn_storage::BuiltCommitment,
    }

    fn good_proof(st: &ChainState, fix: &BuiltFixture, height: u32) -> StorageProof {
        let prev = *st.tip_id().expect("tip");
        build_storage_proof(
            &fix.built.commit,
            &prev,
            height,
            &fix.payload,
            &fix.built.tree,
        )
        .expect("proof")
    }

    #[test]
    fn admit_and_drain_round_trip() {
        let (st, fix) = genesis_with_storage();
        let prev = *st.tip_id().expect("tip");
        let next = 1u32;
        let mut pool = ProofPool::new(ProofPoolConfig::default());
        let proof = good_proof(&st, &fix, next);
        assert_eq!(
            pool.admit(proof.clone(), &st, &prev, next),
            Ok(ProofAdmitOutcome::Fresh)
        );
        let drained = pool.drain_verified(&st, &prev, next);
        assert_eq!(drained.len(), 1);
        assert_eq!(
            encode_storage_proof(&drained[0]),
            encode_storage_proof(&proof)
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn wrong_chunk_rejects_without_mutation() {
        let (st, fix) = genesis_with_storage();
        let prev = *st.tip_id().expect("tip");
        let mut pool = ProofPool::new(ProofPoolConfig::default());
        let mut proof = good_proof(&st, &fix, 1);
        proof.proof.index = proof.proof.index.wrapping_add(1);
        let before = pool.len();
        let err = pool.admit(proof, &st, &prev, 1).unwrap_err();
        assert!(matches!(
            err,
            ProofAdmitError::InvalidForNextBlock {
                reason: StorageProofCheck::WrongChunkIndex { .. }
            }
        ));
        assert_eq!(pool.len(), before);
    }

    #[test]
    fn remove_mined_evicts_included_commitment() {
        let (st, fix) = genesis_with_storage();
        let prev = *st.tip_id().expect("tip");
        let proof = good_proof(&st, &fix, 1);
        let mut pool = ProofPool::new(ProofPoolConfig::default());
        pool.admit(proof.clone(), &st, &prev, 1).expect("admit");
        let header =
            build_unsealed_header(&st, &[], &[], &[], std::slice::from_ref(&proof), 1, 1_000);
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![proof],
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Ok { .. } => {}
            ApplyOutcome::Err { errors, .. } => panic!("{errors:?}"),
        }
        let ch = mfn_storage::storage_commitment_hash(&fix.built.commit);
        assert_eq!(pool.remove_mined([ch]), 1);
        assert!(pool.is_empty());
    }
}
