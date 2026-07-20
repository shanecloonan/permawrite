//! In-memory SPoRA proof pool (**M3.22**, **B-45** multi-op).
//!
//! Storage operators submit proofs via JSON-RPC; producers drain this pool
//! into `BlockInputs::storage_proofs` on the next block. Admission validates
//! each proof against the *expected next* block context (`prev_hash` = current
//! tip, `slot` = next height).
//!
//! When `endowment_params.operator_salted_challenges != 0`, admission uses
//! operator-salted verification and keys entries by `(commit_hash, operator_id)`
//! so distinct operators can queue proofs for the same commitment (B3 / B-32).

use std::collections::BTreeMap;

use mfn_consensus::ChainState;
use mfn_storage::{
    decode_storage_proof, operator_identity_from_payout, verify_storage_proof,
    verify_storage_proof_operator_salted, StorageProof, StorageProofCheck,
};

/// Tuning for [`ProofPool`].
#[derive(Clone, Copy, Debug)]
pub struct ProofPoolConfig {
    /// Maximum pending proofs held at once (all commit×operator pairs).
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
    /// First admission for this `(commit_hash, operator_id)` key.
    Fresh,
    /// Replaced a prior proof for the same commitment and operator.
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
        /// `verify_storage_proof` / salted result.
        reason: StorageProofCheck,
    },
    /// Pool is full and this key is new.
    #[error("proof pool full (max_entries={max_entries})")]
    PoolFull {
        /// Configured cap.
        max_entries: usize,
    },
}

/// Pool key: commitment hash + operator identity (from payout keys).
type ProofKey = ([u8; 32], [u8; 32]);

/// Pending SPoRA proofs keyed by `(commit_hash, operator_id)`.
#[derive(Clone, Debug, Default)]
pub struct ProofPool {
    cfg: ProofPoolConfig,
    by_key: BTreeMap<ProofKey, StorageProof>,
}

impl ProofPool {
    /// Empty pool with default config.
    #[must_use]
    pub fn new(cfg: ProofPoolConfig) -> Self {
        Self {
            cfg,
            by_key: BTreeMap::new(),
        }
    }

    /// Number of pending proofs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Whether the pool has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Sorted unique commitment hashes currently queued.
    #[must_use]
    pub fn commit_hashes(&self) -> Vec<[u8; 32]> {
        let mut out: Vec<[u8; 32]> = self.by_key.keys().map(|(c, _)| *c).collect();
        out.dedup();
        out
    }

    /// Pending `(commit_hash, operator_id)` keys in canonical order.
    #[must_use]
    pub fn entry_keys(&self) -> Vec<ProofKey> {
        self.by_key.keys().copied().collect()
    }

    /// Pending proofs in canonical `(commit_hash, operator_id)` order.
    #[must_use]
    pub fn proofs_sorted(&self) -> Vec<StorageProof> {
        self.by_key.values().cloned().collect()
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
        let verdict = verify_for_state(state, &entry.commit, prev_block_id, next_height, &proof);
        if !verdict.is_valid() {
            return Err(ProofAdmitError::InvalidForNextBlock { reason: verdict });
        }
        let operator_id =
            operator_identity_from_payout(&proof.operator_view_pub, &proof.operator_spend_pub);
        let key = (commit_hash, operator_id);
        use std::collections::btree_map::Entry;
        if let Entry::Occupied(mut e) = self.by_key.entry(key) {
            e.insert(proof);
            return Ok(ProofAdmitOutcome::Replaced);
        }
        if self.by_key.len() >= self.cfg.max_entries {
            return Err(ProofAdmitError::PoolFull {
                max_entries: self.cfg.max_entries,
            });
        }
        self.by_key.insert(key, proof);
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
        let keys: Vec<ProofKey> = self.by_key.keys().copied().collect();
        let mut out = Vec::new();
        for key in keys {
            let Some(proof) = self.by_key.remove(&key) else {
                continue;
            };
            let Some(entry) = state.storage.get(&proof.commit_hash) else {
                continue;
            };
            let verdict =
                verify_for_state(state, &entry.commit, prev_block_id, next_height, &proof);
            if verdict.is_valid() {
                out.push(proof);
            }
        }
        out
    }

    /// Remove proofs that landed in `block.storage_proofs` (commit + operator).
    #[must_use]
    pub fn remove_mined<'a>(
        &mut self,
        proofs: impl IntoIterator<Item = &'a StorageProof>,
    ) -> usize {
        let mut removed = 0usize;
        for proof in proofs {
            let operator_id =
                operator_identity_from_payout(&proof.operator_view_pub, &proof.operator_spend_pub);
            if self
                .by_key
                .remove(&(proof.commit_hash, operator_id))
                .is_some()
            {
                removed = removed.saturating_add(1);
            }
        }
        removed
    }

    /// Drop every pending proof.
    pub fn clear(&mut self) {
        self.by_key.clear();
    }
}

fn verify_for_state(
    state: &ChainState,
    commit: &mfn_storage::StorageCommitment,
    prev_block_id: &[u8; 32],
    next_height: u32,
    proof: &StorageProof,
) -> StorageProofCheck {
    if state.endowment_params.operator_salted_challenges != 0 {
        verify_storage_proof_operator_salted(commit, prev_block_id, next_height, proof)
    } else {
        verify_storage_proof(commit, prev_block_id, next_height, proof)
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
        build_storage_commitment, build_storage_proof_operator_salted, build_test_storage_proof,
        encode_storage_proof, operator_identity_from_payout, test_operator_payout_keys,
        test_operator_payout_keys_alt, DEFAULT_ENDOWMENT_PARAMS,
    };

    use super::*;

    fn genesis_with_storage(salted: bool) -> (ChainState, BuiltFixture) {
        // Multi-chunk payload so unsalted vs operator-salted indices can diverge.
        let payload: Vec<u8> = (0u32..16_384).map(|i| (i % 256) as u8).collect();
        let mut endowment = DEFAULT_ENDOWMENT_PARAMS;
        if salted {
            endowment.operator_salted_challenges = 1;
        }
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(4096),
            endowment.min_replication.max(2),
            None,
        )
        .expect("commitment");
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: vec![built.commit.clone()],
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: endowment,
            bonding_params: None,
            header_version: 1,
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
        build_test_storage_proof(
            &fix.built.commit,
            &prev,
            height,
            &fix.payload,
            &fix.built.tree,
        )
    }

    fn salted_proof(
        st: &ChainState,
        fix: &BuiltFixture,
        height: u32,
        view: curve25519_dalek::edwards::EdwardsPoint,
        spend: curve25519_dalek::edwards::EdwardsPoint,
    ) -> StorageProof {
        let prev = *st.tip_id().expect("tip");
        build_storage_proof_operator_salted(
            &fix.built.commit,
            &prev,
            height,
            &fix.payload,
            &fix.built.tree,
            view,
            spend,
        )
        .expect("salted proof")
    }

    #[test]
    fn admit_and_drain_round_trip() {
        let (st, fix) = genesis_with_storage(false);
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
        let (st, fix) = genesis_with_storage(false);
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
        let (st, fix) = genesis_with_storage(false);
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
            vec![proof.clone()],
        );
        match apply_block(&st, &blk) {
            ApplyOutcome::Ok { .. } => {}
            ApplyOutcome::Err { errors, .. } => panic!("{errors:?}"),
        }
        assert_eq!(pool.remove_mined(std::slice::from_ref(&proof)), 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn b3_admits_two_operators_same_commit() {
        let (st, fix) = genesis_with_storage(true);
        let prev = *st.tip_id().expect("tip");
        let next = 1u32;
        let (v0, s0) = test_operator_payout_keys();
        let (v1, s1) = test_operator_payout_keys_alt();
        let p0 = salted_proof(&st, &fix, next, v0, s0);
        let p1 = salted_proof(&st, &fix, next, v1, s1);
        assert_ne!(
            operator_identity_from_payout(&v0, &s0),
            operator_identity_from_payout(&v1, &s1)
        );
        let mut pool = ProofPool::new(ProofPoolConfig::default());
        assert_eq!(
            pool.admit(p0.clone(), &st, &prev, next),
            Ok(ProofAdmitOutcome::Fresh)
        );
        assert_eq!(
            pool.admit(p1.clone(), &st, &prev, next),
            Ok(ProofAdmitOutcome::Fresh)
        );
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.commit_hashes().len(), 1);
        let drained = pool.drain_verified(&st, &prev, next);
        assert_eq!(drained.len(), 2);
        let ids: std::collections::BTreeSet<_> = drained
            .iter()
            .map(|p| operator_identity_from_payout(&p.operator_view_pub, &p.operator_spend_pub))
            .collect();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn b3_rejects_unsalted_proof_when_salted_required() {
        let (st, fix) = genesis_with_storage(true);
        let prev = *st.tip_id().expect("tip");
        let mut pool = ProofPool::new(ProofPoolConfig::default());
        let unsalted = good_proof(&st, &fix, 1);
        let err = pool.admit(unsalted, &st, &prev, 1).unwrap_err();
        assert!(matches!(
            err,
            ProofAdmitError::InvalidForNextBlock {
                reason: StorageProofCheck::WrongChunkIndex { .. }
            }
        ));
    }
}
