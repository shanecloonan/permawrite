//! Replay durable block logs after loading the latest chain checkpoint.

use mfn_consensus::block_id;
use mfn_runtime::{Chain, ChainConfig};

use crate::{ChainPersistence, StoreError};

/// Summary of block-log replay performed during chain load.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockLogReplayStats {
    /// Number of block records read from the durable block log.
    pub blocks_read: usize,
    /// Number of log records already covered by the loaded checkpoint.
    pub blocks_skipped: usize,
    /// Number of suffix blocks applied after the loaded checkpoint.
    pub blocks_applied: usize,
    /// Final chain height after replay.
    pub final_height: u32,
}

/// Load the latest checkpoint or genesis, then replay any durable block-log suffix.
///
/// Checkpoints remain authoritative for state. Logged blocks at or below the loaded checkpoint
/// height are treated as a checkpoint-covered prefix and verified against the checkpoint's
/// `block_ids` before being skipped. Logged blocks above the checkpoint must be contiguous and
/// valid under the runtime state transition function.
pub fn load_or_genesis_replaying_block_log(
    store: &dyn ChainPersistence,
    cfg: ChainConfig,
) -> Result<(Chain, BlockLogReplayStats), StoreError> {
    let mut chain = store.load_or_genesis(cfg)?;
    let blocks = store.read_block_log()?;
    let mut stats = BlockLogReplayStats {
        blocks_read: blocks.len(),
        final_height: chain.tip_height().unwrap_or(0),
        ..BlockLogReplayStats::default()
    };

    for block in blocks {
        let height = block.header.height;
        let current_height = chain
            .tip_height()
            .ok_or_else(|| StoreError::BlockLog("chain tip_height is None".into()))?;
        let id = block_id(&block.header);

        if height <= current_height {
            let known = chain
                .state()
                .block_ids
                .get(height as usize)
                .ok_or_else(|| {
                    StoreError::BlockLog(format!(
                        "checkpoint missing block_id for covered log height {height}"
                    ))
                })?;
            if known != &id {
                return Err(StoreError::BlockLog(format!(
                    "checkpoint/block-log fork at covered height {height}"
                )));
            }
            stats.blocks_skipped = stats.blocks_skipped.saturating_add(1);
            continue;
        }

        let expected = current_height.saturating_add(1);
        if height != expected {
            return Err(StoreError::BlockLog(format!(
                "block log gap while replaying: expected height {expected}, got {height}"
            )));
        }
        chain.apply(&block).map_err(StoreError::Chain)?;
        stats.blocks_applied = stats.blocks_applied.saturating_add(1);
        stats.final_height = height;
    }

    stats.final_height = chain.tip_height().unwrap_or(stats.final_height);
    Ok((chain, stats))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use mfn_consensus::{
        build_unsealed_header, seal_block, ConsensusParams, GenesisConfig, DEFAULT_EMISSION_PARAMS,
    };
    use mfn_runtime::ChainConfig;
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    use crate::{
        load_or_genesis_replaying_block_log, ChainPersistence, ChainStore, RedbChainStore,
        StoreError,
    };

    fn empty_genesis_cfg(timestamp: u64) -> GenesisConfig {
        GenesisConfig {
            timestamp,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: ConsensusParams::default(),
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
            header_version: 1,
        }
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "permawrite-store-replay-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn append_empty_next_block(store: &dyn ChainPersistence, chain: &mut mfn_runtime::Chain) {
        let next_height = chain.tip_height().expect("tip").saturating_add(1);
        let unsealed = build_unsealed_header(chain.state(), &[], &[], &[], &[], next_height, 1_000);
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

    fn append_unvalidated_empty_block_at_height(
        store: &dyn ChainPersistence,
        chain: &mfn_runtime::Chain,
        height: u32,
        timestamp: u64,
    ) {
        let mut unsealed =
            build_unsealed_header(chain.state(), &[], &[], &[], &[], height, timestamp);
        unsealed.height = height;
        let block = seal_block(
            unsealed,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        store.append_block(&block).expect("append block");
    }

    #[test]
    fn replays_block_log_when_checkpoint_is_genesis() {
        let root = temp_root("fs_suffix");
        let store = ChainStore::new(&root);
        let cfg = ChainConfig::new(empty_genesis_cfg(0));
        let mut chain = store.load_or_genesis(cfg.clone()).expect("genesis");
        append_empty_next_block(&store, &mut chain);

        let (loaded, stats) =
            load_or_genesis_replaying_block_log(&store, cfg).expect("replay suffix");

        assert_eq!(loaded.tip_height(), Some(1));
        assert_eq!(stats.blocks_read, 1);
        assert_eq!(stats.blocks_skipped, 0);
        assert_eq!(stats.blocks_applied, 1);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn skips_checkpoint_covered_prefix_and_replays_suffix() {
        let root = temp_root("redb_prefix_suffix");
        let store = RedbChainStore::new(&root).expect("redb");
        let cfg = ChainConfig::new(empty_genesis_cfg(0));
        let mut chain = store.load_or_genesis(cfg.clone()).expect("genesis");
        append_empty_next_block(&store, &mut chain);
        store.save(&chain).expect("checkpoint height 1");
        append_empty_next_block(&store, &mut chain);

        let (loaded, stats) =
            load_or_genesis_replaying_block_log(&store, cfg).expect("replay suffix");

        assert_eq!(loaded.tip_height(), Some(2));
        assert_eq!(stats.blocks_read, 2);
        assert_eq!(stats.blocks_skipped, 1);
        assert_eq!(stats.blocks_applied, 1);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn rejects_forked_checkpoint_covered_prefix() {
        let root = temp_root("fs_forked_prefix");
        let store = ChainStore::new(&root);
        let cfg = ChainConfig::new(empty_genesis_cfg(0));
        let mut chain = store.load_or_genesis(cfg.clone()).expect("genesis");
        append_empty_next_block(&store, &mut chain);
        store.save(&chain).expect("checkpoint height 1");
        append_unvalidated_empty_block_at_height(&store, &chain, 1, 2_000);

        let err = load_or_genesis_replaying_block_log(&store, cfg).expect_err("fork reject");

        match err {
            StoreError::BlockLog(msg) => {
                assert!(
                    msg.contains("checkpoint/block-log fork"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn rejects_block_log_height_gap() {
        let root = temp_root("fs_gap");
        let store = ChainStore::new(&root);
        let cfg = ChainConfig::new(empty_genesis_cfg(0));
        let chain = store.load_or_genesis(cfg.clone()).expect("genesis");
        append_unvalidated_empty_block_at_height(&store, &chain, 2, 2_000);

        let err = load_or_genesis_replaying_block_log(&store, cfg).expect_err("gap reject");

        match err {
            StoreError::BlockLog(msg) => {
                assert!(msg.contains("block log gap"), "unexpected message: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        fs::remove_dir_all(root).ok();
    }
}
