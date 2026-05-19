//! P2P block-sync: serve [`GetBlocksByHeightV1`] from the validated block log (**M2.3.18**).

use std::sync::{Arc, Mutex};

use mfn_consensus::encode_block;
use mfn_net::{BlockSyncProvider, ChainTipV1, MAX_BLOCKS_PER_GET_V1};
use mfn_runtime::Chain;
use mfn_store::ChainPersistence;

/// Shared chain + store for inbound block-sync queries.
pub struct P2pBlockSyncHandler {
    chain: Arc<Mutex<Chain>>,
    store: Arc<dyn ChainPersistence + Send + Sync>,
}

impl P2pBlockSyncHandler {
    /// Build a handler wired to the live `mfnd serve` chain + persistence.
    pub fn new(
        chain: Arc<Mutex<Chain>>,
        store: Arc<dyn ChainPersistence + Send + Sync>,
    ) -> Arc<Self> {
        Arc::new(Self { chain, store })
    }
}

impl BlockSyncProvider for P2pBlockSyncHandler {
    fn chain_tip_v1(&self) -> ChainTipV1 {
        let chain = match self.chain.lock() {
            Ok(g) => g,
            Err(_) => {
                return ChainTipV1 {
                    height: 0,
                    tip_id: [0u8; 32],
                };
            }
        };
        let height = chain.tip_height().unwrap_or(0);
        let tip_id = chain
            .tip_id()
            .copied()
            .unwrap_or_else(|| *chain.genesis_id());
        ChainTipV1 { height, tip_id }
    }

    fn blocks_from_height(&self, start_height: u32, count: u32) -> Vec<Vec<u8>> {
        let count = count.min(MAX_BLOCKS_PER_GET_V1);
        let chain = match self.chain.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let blocks = match self.store.read_block_log_validated(&chain) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        blocks
            .into_iter()
            .filter(|b| b.header.height >= start_height)
            .take(count as usize)
            .map(|b| encode_block(&b))
            .collect()
    }
}
