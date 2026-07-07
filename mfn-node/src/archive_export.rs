//! Self-verifying chain + chunk archive export/verify (**F5-PM10**).
//!
//! Defense in depth for the doomsday case: `mfnd archive-export` writes the
//! canonical chain and every locally-held, Merkle-complete chunk set into a
//! portable directory suitable for deposit in offline/third-party archives.
//! Anyone holding the export and the network's genesis spec can verify every
//! byte with **no live network**: `mfnd archive-verify` replays each block
//! from genesis through the full consensus state-transition function and
//! re-derives each chunk set's Merkle root against the anchored `data_root`.
//!
//! ## Archive layout (a portable subset of a node data dir)
//!
//! ```text
//! <archive>/
//!   manifest.json           format tag, genesis/tip ids, commitment index
//!   chain.blocks            canonical length-prefixed block log (mfn-store fs format)
//!   chunk-inbox/<commit>/N.bin   chunk payloads for exported commitments
//! ```
//!
//! Reusing the `mfn-store` filesystem formats means the archive doubles as a
//! cold-start bootstrap: point a fresh `--store fs` node at it and the block
//! log replays.

use std::path::{Path, PathBuf};

use mfn_runtime::{Chain, ChainConfig, ChainError};
use mfn_store::{
    load_or_genesis_replaying_block_log, read_chunk_inbox, save_chunk_inbox, ChainPersistence,
    ChainStore, StoreError,
};

/// Manifest filename inside the archive directory.
pub const ARCHIVE_MANIFEST_FILE: &str = "manifest.json";

/// Format tag pinned in every manifest.
pub const ARCHIVE_FORMAT_V1: &str = "permawrite-archive-v1";

/// Archive export/verify failure.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// Chain persistence failure (load, block log read/write).
    #[error("archive: {0}")]
    Store(#[from] StoreError),
    /// Consensus rejection while replaying the archived block log.
    #[error("archive replay: {0}")]
    Chain(#[from] ChainError),
    /// Filesystem failure.
    #[error("archive io at {path}: {source}")]
    Io {
        /// Path of the failing operation.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// Manifest could not be parsed or has the wrong format tag.
    #[error("archive manifest: {0}")]
    Manifest(String),
    /// The archive contents contradict the manifest or the replayed chain.
    #[error("archive verify: {0}")]
    Verify(String),
    /// Refusing to write into a directory that already holds an archive.
    #[error("archive export: output already contains {0} (refusing to overwrite)")]
    OutputNotEmpty(String),
}

fn io_err(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> ArchiveError {
    let path = path.into();
    move |source| ArchiveError::Io { path, source }
}

/// One anchored storage commitment as recorded in the archive manifest.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ArchiveCommitment {
    /// Commitment hash (hex, 64 chars) — the on-chain anchor key.
    pub commit_hash: String,
    /// Chunk Merkle root (hex, 64 chars).
    pub data_root: String,
    /// Declared payload size in bytes.
    pub size_bytes: u64,
    /// Chunk granularity (power of two).
    pub chunk_size: u32,
    /// Number of chunk leaves.
    pub num_chunks: u32,
    /// Whether this archive carries the full chunk set under `chunk-inbox/`.
    pub chunks_exported: bool,
}

/// Self-describing archive manifest (`manifest.json`).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ArchiveManifest {
    /// Format tag; must equal [`ARCHIVE_FORMAT_V1`].
    pub format: String,
    /// Genesis block id (hex). The external trust anchor: verification
    /// recomputes this from the genesis spec and hard-fails on mismatch.
    pub genesis_id: String,
    /// Height of the archived tip.
    pub tip_height: u32,
    /// Block id of the archived tip (hex).
    pub tip_id: String,
    /// Number of block records in `chain.blocks` (== `tip_height`).
    pub block_count: u64,
    /// Every storage commitment anchored in the archived chain state,
    /// sorted by `commit_hash`.
    pub commitments: Vec<ArchiveCommitment>,
}

/// Result of a successful [`export_archive`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveExportReport {
    /// Blocks written to the archive block log.
    pub blocks: usize,
    /// Archived tip height.
    pub tip_height: u32,
    /// Archived tip id (hex).
    pub tip_id: String,
    /// Genesis id (hex).
    pub genesis_id: String,
    /// Storage commitments anchored in chain state.
    pub commitments_total: usize,
    /// Commitments whose full, Merkle-verified chunk set was exported.
    pub chunk_sets_exported: usize,
}

/// Result of a successful [`verify_archive`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveVerifyReport {
    /// Blocks replayed through the state-transition function.
    pub blocks_verified: usize,
    /// Verified tip height.
    pub tip_height: u32,
    /// Verified tip id (hex).
    pub tip_id: String,
    /// Commitments listed in the manifest (== anchored in replayed state).
    pub commitments_total: usize,
    /// Chunk sets whose Merkle root was re-derived and matched `data_root`.
    pub chunk_sets_verified: usize,
}

/// Export the canonical chain plus all locally-complete chunk sets from a
/// node data dir into `out_dir`.
///
/// The chain is loaded with full block-log replay validation, and the block
/// log is re-validated against the loaded chain before a single byte is
/// copied — an inconsistent data dir can never produce an archive. Chunk
/// sets are exported only when complete **and** Merkle-consistent with the
/// anchored `data_root` (same gate as P2P fan-out, M7.12); partial or
/// corrupt inboxes are recorded as `chunks_exported = false`.
pub fn export_archive(
    store: &dyn ChainPersistence,
    cfg: ChainConfig,
    out_dir: &Path,
) -> Result<ArchiveExportReport, ArchiveError> {
    let (chain, _) = load_or_genesis_replaying_block_log(store, cfg)?;
    let blocks = store.read_block_log_validated(&chain)?;

    let out_store = ChainStore::new(out_dir);
    if out_store.block_log_path().exists() {
        return Err(ArchiveError::OutputNotEmpty(
            out_store.block_log_path().display().to_string(),
        ));
    }
    let manifest_path = out_dir.join(ARCHIVE_MANIFEST_FILE);
    if manifest_path.exists() {
        return Err(ArchiveError::OutputNotEmpty(
            manifest_path.display().to_string(),
        ));
    }
    std::fs::create_dir_all(out_dir).map_err(io_err(out_dir))?;
    for block in &blocks {
        out_store.append_block(block)?;
    }

    let mut anchored: Vec<(&[u8; 32], &mfn_consensus::block::StorageEntry)> =
        chain.state().storage.iter().collect();
    anchored.sort_by_key(|(hash, _)| **hash);

    let mut commitments = Vec::with_capacity(anchored.len());
    let mut chunk_sets_exported = 0usize;
    for (hash, entry) in anchored {
        let chunks =
            crate::p2p_chunk_fanout::load_complete_inbox_chunks(store.root(), hash, &entry.commit);
        let chunks_exported = match chunks {
            Some(chunks) => {
                for (idx, bytes) in &chunks {
                    save_chunk_inbox(out_dir, hash, *idx, bytes).map_err(|e| {
                        ArchiveError::Verify(format!(
                            "writing chunk {idx} for {}: {e}",
                            hex::encode(hash)
                        ))
                    })?;
                }
                chunk_sets_exported += 1;
                true
            }
            None => false,
        };
        commitments.push(ArchiveCommitment {
            commit_hash: hex::encode(hash),
            data_root: hex::encode(entry.commit.data_root),
            size_bytes: entry.commit.size_bytes,
            chunk_size: entry.commit.chunk_size,
            num_chunks: entry.commit.num_chunks,
            chunks_exported,
        });
    }

    let tip_height = chain.tip_height().unwrap_or(0);
    let tip_id = chain
        .tip_id()
        .map(hex::encode)
        .unwrap_or_else(|| hex::encode(chain.genesis_id()));
    let genesis_id = hex::encode(chain.genesis_id());
    let manifest = ArchiveManifest {
        format: ARCHIVE_FORMAT_V1.to_string(),
        genesis_id: genesis_id.clone(),
        tip_height,
        tip_id: tip_id.clone(),
        block_count: blocks.len() as u64,
        commitments,
    };
    let json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| ArchiveError::Manifest(format!("encode: {e}")))?;
    std::fs::write(&manifest_path, json).map_err(io_err(&manifest_path))?;

    Ok(ArchiveExportReport {
        blocks: blocks.len(),
        tip_height,
        tip_id,
        genesis_id,
        commitments_total: manifest.commitments.len(),
        chunk_sets_exported,
    })
}

/// Verify an archive directory against a genesis spec with no live network.
///
/// Trust anchor is the genesis spec (`cfg`): the genesis block id is
/// recomputed from it and must match the manifest. Every archived block is
/// then replayed through [`Chain::apply`] — the full consensus
/// state-transition function, not a checksum — so a forged, reordered, or
/// tampered block log cannot pass. Every commitment anchored in the
/// replayed state must appear in the manifest, and every exported chunk set
/// is re-chunked into its Merkle root and compared to the anchored
/// `data_root` byte-for-byte.
pub fn verify_archive(
    archive_dir: &Path,
    cfg: ChainConfig,
) -> Result<ArchiveVerifyReport, ArchiveError> {
    let manifest_path = archive_dir.join(ARCHIVE_MANIFEST_FILE);
    let manifest_bytes = std::fs::read(&manifest_path).map_err(io_err(&manifest_path))?;
    let manifest: ArchiveManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| ArchiveError::Manifest(format!("decode: {e}")))?;
    if manifest.format != ARCHIVE_FORMAT_V1 {
        return Err(ArchiveError::Manifest(format!(
            "unsupported format `{}` (expected `{ARCHIVE_FORMAT_V1}`)",
            manifest.format
        )));
    }

    let mut chain = Chain::from_genesis(cfg)?;
    let genesis_id = hex::encode(chain.genesis_id());
    if genesis_id != manifest.genesis_id {
        return Err(ArchiveError::Verify(format!(
            "genesis id mismatch: spec derives {genesis_id}, manifest claims {}",
            manifest.genesis_id
        )));
    }

    let blocks = ChainStore::new(archive_dir).read_block_log()?;
    if blocks.len() as u64 != manifest.block_count {
        return Err(ArchiveError::Verify(format!(
            "block log has {} record(s), manifest claims {}",
            blocks.len(),
            manifest.block_count
        )));
    }
    for (i, block) in blocks.iter().enumerate() {
        let expected_height = (i as u32).saturating_add(1);
        if block.header.height != expected_height {
            return Err(ArchiveError::Verify(format!(
                "block record {i} has height {} (expected {expected_height})",
                block.header.height
            )));
        }
        chain.apply(block)?;
    }
    let tip_height = chain.tip_height().unwrap_or(0);
    if tip_height != manifest.tip_height {
        return Err(ArchiveError::Verify(format!(
            "replayed tip height {tip_height} != manifest tip height {}",
            manifest.tip_height
        )));
    }
    let tip_id = chain
        .tip_id()
        .map(hex::encode)
        .unwrap_or_else(|| genesis_id.clone());
    if tip_id != manifest.tip_id {
        return Err(ArchiveError::Verify(format!(
            "replayed tip id {tip_id} != manifest tip id {}",
            manifest.tip_id
        )));
    }

    let state = chain.state();
    if manifest.commitments.len() != state.storage.len() {
        return Err(ArchiveError::Verify(format!(
            "manifest lists {} commitment(s), replayed state anchors {}",
            manifest.commitments.len(),
            state.storage.len()
        )));
    }
    let mut chunk_sets_verified = 0usize;
    for mc in &manifest.commitments {
        let hash = decode_hash32(&mc.commit_hash)
            .ok_or_else(|| ArchiveError::Manifest(format!("bad commit_hash {}", mc.commit_hash)))?;
        let entry = state.storage.get(&hash).ok_or_else(|| {
            ArchiveError::Verify(format!(
                "manifest commitment {} is not anchored in the replayed chain",
                mc.commit_hash
            ))
        })?;
        if hex::encode(entry.commit.data_root) != mc.data_root
            || entry.commit.size_bytes != mc.size_bytes
            || entry.commit.chunk_size != mc.chunk_size
            || entry.commit.num_chunks != mc.num_chunks
        {
            return Err(ArchiveError::Verify(format!(
                "manifest commitment {} disagrees with the anchored commitment",
                mc.commit_hash
            )));
        }
        if !mc.chunks_exported {
            continue;
        }
        verify_chunk_set(archive_dir, mc, &entry.commit)?;
        chunk_sets_verified += 1;
    }

    Ok(ArchiveVerifyReport {
        blocks_verified: blocks.len(),
        tip_height,
        tip_id,
        commitments_total: manifest.commitments.len(),
        chunk_sets_verified,
    })
}

/// Re-derive one exported chunk set's Merkle root and compare it to the
/// anchored `data_root`; also checks the total byte length.
fn verify_chunk_set(
    archive_dir: &Path,
    mc: &ArchiveCommitment,
    commit: &mfn_storage::StorageCommitment,
) -> Result<(), ArchiveError> {
    let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(commit.num_chunks as usize);
    let mut total_len: u64 = 0;
    for idx in 0..commit.num_chunks {
        let bytes = read_chunk_inbox(archive_dir, &mc.commit_hash, idx)
            .map_err(|e| ArchiveError::Verify(format!("commitment {}: {e}", mc.commit_hash)))?;
        total_len = total_len.saturating_add(bytes.len() as u64);
        chunks.push(bytes);
    }
    if total_len != commit.size_bytes {
        return Err(ArchiveError::Verify(format!(
            "commitment {}: chunk bytes total {total_len} != declared size {}",
            mc.commit_hash, commit.size_bytes
        )));
    }
    let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
    let tree = mfn_storage::merkle_tree_from_chunks(&refs)
        .map_err(|e| ArchiveError::Verify(format!("commitment {}: {e}", mc.commit_hash)))?;
    if tree.root() != commit.data_root {
        return Err(ArchiveError::Verify(format!(
            "commitment {}: chunk Merkle root does not match anchored data_root",
            mc.commit_hash
        )));
    }
    Ok(())
}

fn decode_hash32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use mfn_consensus::{
        build_unsealed_header, seal_block, storage_commitment_hash, ConsensusParams, GenesisConfig,
        DEFAULT_EMISSION_PARAMS,
    };
    use mfn_runtime::ChainConfig;
    use mfn_storage::{build_storage_commitment, chunk_data, DEFAULT_ENDOWMENT_PARAMS};
    use mfn_store::{save_chunk_inbox, ChainPersistence, ChainStore};

    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "permawrite-archive-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn genesis_cfg(initial_storage: Vec<mfn_storage::StorageCommitment>) -> GenesisConfig {
        GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage,
            validators: Vec::new(),
            params: ConsensusParams::default(),
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
        }
    }

    fn append_empty_next_block(store: &dyn ChainPersistence, chain: &mut mfn_runtime::Chain) {
        let next_height = chain.tip_height().expect("tip").saturating_add(1);
        let unsealed = build_unsealed_header(
            chain.state(),
            &[],
            &[],
            &[],
            &[],
            next_height,
            1_000 + u64::from(next_height),
        );
        let block = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        chain.apply(&block).expect("apply");
        store.append_block(&block).expect("append block");
    }

    #[test]
    fn export_then_verify_round_trip_with_chunks() {
        let src = temp_root("src");
        let out = temp_root("out");
        let payload: Vec<u8> = mfn_storage::pad_to_storage_size_bucket(
            &(0u32..1500).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
        );
        let built = build_storage_commitment(
            &payload,
            1_000,
            None,
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let commit_hash = storage_commitment_hash(&built.commit);
        let cfg = ChainConfig::new(genesis_cfg(vec![built.commit.clone()]));

        let store = ChainStore::new(&src);
        let mut chain = store.load_or_genesis(cfg.clone()).expect("genesis");
        append_empty_next_block(&store, &mut chain);
        append_empty_next_block(&store, &mut chain);
        store.save(&chain).expect("checkpoint");
        let slices = chunk_data(&payload, built.commit.chunk_size as usize).expect("chunks");
        for (i, bytes) in slices.iter().enumerate() {
            save_chunk_inbox(&src, &commit_hash, u32::try_from(i).expect("idx"), bytes)
                .expect("save chunk");
        }

        let export = export_archive(&store, cfg.clone(), &out).expect("export");
        assert_eq!(export.blocks, 2);
        assert_eq!(export.tip_height, 2);
        assert_eq!(export.commitments_total, 1);
        assert_eq!(export.chunk_sets_exported, 1);

        let verify = verify_archive(&out, cfg).expect("verify");
        assert_eq!(verify.blocks_verified, 2);
        assert_eq!(verify.tip_height, 2);
        assert_eq!(verify.tip_id, export.tip_id);
        assert_eq!(verify.commitments_total, 1);
        assert_eq!(verify.chunk_sets_verified, 1);

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn export_marks_incomplete_chunk_sets_and_verify_still_passes() {
        let src = temp_root("src-partial");
        let out = temp_root("out-partial");
        let payload: Vec<u8> = mfn_storage::pad_to_storage_size_bucket(&vec![7u8; 900]);
        let built = build_storage_commitment(
            &payload,
            1_000,
            None,
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let cfg = ChainConfig::new(genesis_cfg(vec![built.commit.clone()]));

        let store = ChainStore::new(&src);
        let mut chain = store.load_or_genesis(cfg.clone()).expect("genesis");
        append_empty_next_block(&store, &mut chain);
        // No chunks saved into the source inbox at all.

        let export = export_archive(&store, cfg.clone(), &out).expect("export");
        assert_eq!(export.commitments_total, 1);
        assert_eq!(export.chunk_sets_exported, 0);

        let verify = verify_archive(&out, cfg).expect("verify");
        assert_eq!(verify.chunk_sets_verified, 0);

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn verify_rejects_tampered_chunk_bytes() {
        let src = temp_root("src-tamper-chunk");
        let out = temp_root("out-tamper-chunk");
        let payload: Vec<u8> = mfn_storage::pad_to_storage_size_bucket(
            &(0u32..1200).map(|i| (i % 199) as u8).collect::<Vec<u8>>(),
        );
        let built = build_storage_commitment(
            &payload,
            1_000,
            None,
            DEFAULT_ENDOWMENT_PARAMS.min_replication,
            None,
        )
        .expect("commit");
        let commit_hash = storage_commitment_hash(&built.commit);
        let cfg = ChainConfig::new(genesis_cfg(vec![built.commit.clone()]));

        let store = ChainStore::new(&src);
        let mut chain = store.load_or_genesis(cfg.clone()).expect("genesis");
        append_empty_next_block(&store, &mut chain);
        let slices = chunk_data(&payload, built.commit.chunk_size as usize).expect("chunks");
        for (i, bytes) in slices.iter().enumerate() {
            save_chunk_inbox(&src, &commit_hash, u32::try_from(i).expect("idx"), bytes)
                .expect("save chunk");
        }
        export_archive(&store, cfg.clone(), &out).expect("export");

        // Flip one byte of chunk 0 inside the archive.
        let chunk_path = mfn_store::chunk_inbox_path(&out, &hex::encode(commit_hash), 0);
        let mut bytes = std::fs::read(&chunk_path).expect("read chunk");
        bytes[0] ^= 0xff;
        std::fs::write(&chunk_path, bytes).expect("write chunk");

        let err = verify_archive(&out, cfg).expect_err("tampered chunk must fail");
        assert!(
            matches!(err, ArchiveError::Verify(ref msg) if msg.contains("Merkle root")),
            "unexpected error: {err}"
        );

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn verify_rejects_tampered_block_log() {
        let src = temp_root("src-tamper-blocks");
        let out = temp_root("out-tamper-blocks");
        let cfg = ChainConfig::new(genesis_cfg(Vec::new()));

        let store = ChainStore::new(&src);
        let mut chain = store.load_or_genesis(cfg.clone()).expect("genesis");
        append_empty_next_block(&store, &mut chain);
        append_empty_next_block(&store, &mut chain);
        export_archive(&store, cfg.clone(), &out).expect("export");

        // Flip a byte in the middle of the archived block log.
        let log_path = ChainStore::new(&out).block_log_path();
        let mut bytes = std::fs::read(&log_path).expect("read log");
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        std::fs::write(&log_path, bytes).expect("write log");

        assert!(
            verify_archive(&out, cfg).is_err(),
            "tampered block log must fail verification"
        );

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn verify_rejects_wrong_genesis_spec() {
        let src = temp_root("src-wrong-genesis");
        let out = temp_root("out-wrong-genesis");
        let cfg = ChainConfig::new(genesis_cfg(Vec::new()));

        let store = ChainStore::new(&src);
        let mut chain = store.load_or_genesis(cfg.clone()).expect("genesis");
        append_empty_next_block(&store, &mut chain);
        export_archive(&store, cfg, &out).expect("export");

        // A different genesis (timestamp 1) derives a different genesis id.
        let mut other = genesis_cfg(Vec::new());
        other.timestamp = 1;
        let err = verify_archive(&out, ChainConfig::new(other)).expect_err("wrong genesis");
        assert!(
            matches!(err, ArchiveError::Verify(ref msg) if msg.contains("genesis id mismatch")),
            "unexpected error: {err}"
        );

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn export_refuses_to_overwrite_existing_archive() {
        let src = temp_root("src-no-overwrite");
        let out = temp_root("out-no-overwrite");
        let cfg = ChainConfig::new(genesis_cfg(Vec::new()));

        let store = ChainStore::new(&src);
        let mut chain = store.load_or_genesis(cfg.clone()).expect("genesis");
        append_empty_next_block(&store, &mut chain);
        export_archive(&store, cfg.clone(), &out).expect("first export");
        let err = export_archive(&store, cfg, &out).expect_err("second export must refuse");
        assert!(
            matches!(err, ArchiveError::OutputNotEmpty(_)),
            "unexpected error: {err}"
        );

        std::fs::remove_dir_all(&src).ok();
        std::fs::remove_dir_all(&out).ok();
    }
}
