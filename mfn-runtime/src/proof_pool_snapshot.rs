//! Canonical on-disk proof-pool snapshot (**M3.23**).
//!
//! Format (`proof_pool.bytes`):
//! - magic `MFNPROOF1` (8 bytes)
//! - version `u8` = 1
//! - `varint` entry count
//! - per entry: `blob` canonical [`encode_storage_proof`] wire

use mfn_storage::{decode_storage_proof, encode_storage_proof, StorageProof};

use mfn_crypto::codec::{Reader, Writer};

use crate::proof_pool::ProofPool;

/// Magic prefix for [`encode_proof_pool_snapshot`].
pub const PROOF_POOL_SNAPSHOT_MAGIC: &[u8] = b"MFNPROOF1";

/// Current snapshot version byte.
pub const PROOF_POOL_SNAPSHOT_VERSION: u8 = 1;

/// Failure encoding or decoding a snapshot.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ProofPoolSnapshotError {
    /// File shorter than the magic header.
    #[error("snapshot too short")]
    TooShort,
    /// Magic bytes do not match.
    #[error("bad magic")]
    BadMagic,
    /// Unsupported version byte.
    #[error("unsupported snapshot version {0}")]
    UnsupportedVersion(u8),
    /// Codec or proof decode failure.
    #[error("decode: {0}")]
    Decode(String),
}

/// Outcome of [`ProofPool::restore_snapshot`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProofPoolRestoreStats {
    /// Proofs read from the snapshot file.
    pub loaded: u32,
    /// Proofs successfully re-admitted for the current next-block context.
    pub admitted: u32,
    /// Proofs skipped (stale, invalid, or duplicate under current chain state).
    pub skipped: u32,
}

/// Encode the proof pool to canonical bytes (sorted by `commit_hash`).
#[must_use]
pub fn encode_proof_pool_snapshot(pool: &ProofPool) -> Vec<u8> {
    let mut w = Writer::new();
    w.blob(PROOF_POOL_SNAPSHOT_MAGIC);
    w.u8(PROOF_POOL_SNAPSHOT_VERSION);
    let proofs = pool.proofs_sorted();
    w.varint(proofs.len() as u64);
    for proof in &proofs {
        w.blob(&encode_storage_proof(proof));
    }
    w.into_bytes()
}

/// Decode a snapshot blob.
pub fn decode_proof_pool_snapshot(
    bytes: &[u8],
) -> Result<Vec<StorageProof>, ProofPoolSnapshotError> {
    let mut r = Reader::new(bytes);
    let magic = r
        .blob()
        .map_err(|e| ProofPoolSnapshotError::Decode(e.to_string()))?;
    if magic != PROOF_POOL_SNAPSHOT_MAGIC {
        return Err(if bytes.len() < PROOF_POOL_SNAPSHOT_MAGIC.len() {
            ProofPoolSnapshotError::TooShort
        } else {
            ProofPoolSnapshotError::BadMagic
        });
    }
    let version = r
        .u8()
        .map_err(|e| ProofPoolSnapshotError::Decode(e.to_string()))?;
    if version != PROOF_POOL_SNAPSHOT_VERSION {
        return Err(ProofPoolSnapshotError::UnsupportedVersion(version));
    }
    let count = r
        .varint()
        .map_err(|e| ProofPoolSnapshotError::Decode(e.to_string()))?;
    let count = usize::try_from(count)
        .map_err(|_| ProofPoolSnapshotError::Decode("count overflow".into()))?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let wire = r
            .blob()
            .map_err(|e| ProofPoolSnapshotError::Decode(e.to_string()))?;
        let proof = decode_storage_proof(wire)
            .map_err(|e| ProofPoolSnapshotError::Decode(format!("proof: {e}")))?;
        out.push(proof);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_pool::{ProofPool, ProofPoolConfig};
    use mfn_consensus::{
        apply_block, apply_genesis, build_genesis, build_unsealed_header, seal_block, ApplyOutcome,
        ChainState, GenesisConfig, DEFAULT_CONSENSUS_PARAMS, DEFAULT_EMISSION_PARAMS,
    };
    use mfn_storage::{
        build_storage_commitment, build_test_storage_proof, chunk_index_for_challenge,
        storage_commitment_hash, DEFAULT_CHUNK_SIZE, DEFAULT_ENDOWMENT_PARAMS,
    };

    fn genesis_with_storage() -> (ChainState, Vec<u8>, mfn_storage::BuiltCommitment) {
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
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: DEFAULT_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let st = apply_genesis(&g, &cfg).expect("genesis");
        (st, payload, built)
    }

    #[test]
    fn snapshot_empty_round_trip() {
        let pool = ProofPool::new(ProofPoolConfig::default());
        let bytes = encode_proof_pool_snapshot(&pool);
        let decoded = decode_proof_pool_snapshot(&bytes).expect("decode");
        assert!(decoded.is_empty());
    }

    #[test]
    fn snapshot_rejects_bad_magic() {
        let mut w = Writer::new();
        w.blob(b"NOTMAGIC!");
        let err = decode_proof_pool_snapshot(&w.into_bytes()).unwrap_err();
        assert_eq!(err, ProofPoolSnapshotError::BadMagic);
    }

    #[test]
    fn snapshot_round_trip_and_restore() {
        let (st, payload, built) = genesis_with_storage();
        let prev = *st.tip_id().expect("tip");
        let proof = build_test_storage_proof(&built.commit, &prev, 1, &payload, &built.tree);
        let mut pool = ProofPool::new(ProofPoolConfig::default());
        pool.admit(proof.clone(), &st, &prev, 1).expect("admit");
        let bytes = encode_proof_pool_snapshot(&pool);
        let decoded = decode_proof_pool_snapshot(&bytes).expect("decode");
        assert_eq!(decoded.len(), 1);

        let mut pool2 = ProofPool::new(ProofPoolConfig::default());
        let stats = pool2.restore_snapshot(decoded, &st, &prev, 1);
        assert_eq!(stats.loaded, 1);
        assert_eq!(stats.admitted, 1);
        assert_eq!(pool2.len(), 1);
    }

    #[test]
    fn restore_skips_stale_challenge_after_tip_moves() {
        // Multi-chunk commitment: a proof for (prev@h0, slot=1) must not
        // re-admit for (prev@h1, slot=2) — single-chunk fixtures always
        // challenge index 0 and would falsely pass.
        let payload: Vec<u8> = (0u32..(1024 * 1024)).map(|i| (i % 256) as u8).collect();
        let built = build_storage_commitment(
            &payload,
            1_000,
            Some(DEFAULT_CHUNK_SIZE),
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
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
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        };
        let g = build_genesis(&cfg);
        let st = apply_genesis(&g, &cfg).expect("genesis");
        let prev = *st.tip_id().expect("tip");
        let c_hash = storage_commitment_hash(&built.commit);
        let num_chunks = built.commit.num_chunks;
        let slot_old = 1u32;
        let idx_old = chunk_index_for_challenge(&prev, slot_old, &c_hash, num_chunks);
        let proof_old =
            build_test_storage_proof(&built.commit, &prev, slot_old, &payload, &built.tree);
        let bytes = encode_proof_pool_snapshot_entries(std::slice::from_ref(&proof_old));

        let header = build_unsealed_header(&st, &[], &[], &[], &[], 1, 1_000);
        let blk = seal_block(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let st2 = match apply_block(&st, &blk) {
            ApplyOutcome::Ok { state, .. } => state,
            ApplyOutcome::Err { errors, .. } => panic!("{errors:?}"),
        };
        let prev2 = *st2.tip_id().expect("tip");
        assert_ne!(prev, prev2);
        let mut next_height = 2u32;
        while chunk_index_for_challenge(&prev2, next_height, &c_hash, num_chunks) == idx_old {
            next_height += 1;
            assert!(
                next_height < 258,
                "could not find non-colliding next_height"
            );
        }
        let decoded = decode_proof_pool_snapshot(&bytes).expect("decode");
        let mut pool = ProofPool::new(ProofPoolConfig::default());
        let stats = pool.restore_snapshot(decoded, &st2, &prev2, next_height);
        assert_eq!(stats.loaded, 1);
        assert_eq!(stats.admitted, 0);
        assert_eq!(stats.skipped, 1);
        assert!(pool.is_empty());
    }

    fn encode_proof_pool_snapshot_entries(proofs: &[StorageProof]) -> Vec<u8> {
        let mut w = Writer::new();
        w.blob(PROOF_POOL_SNAPSHOT_MAGIC);
        w.u8(PROOF_POOL_SNAPSHOT_VERSION);
        w.varint(proofs.len() as u64);
        for p in proofs {
            w.blob(&encode_storage_proof(p));
        }
        w.into_bytes()
    }
}
