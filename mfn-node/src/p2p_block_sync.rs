//! P2P block-sync: serve [`GetBlocksByHeightV1`] from the validated block log (**M2.3.18**).

use std::sync::{Arc, Mutex};

use mfn_consensus::{block_header_bytes, block_id, encode_block, encode_bond_op, encode_evidence};
use mfn_net::serve::{BlockSyncHook, LightFollowHook};
use mfn_net::{
    BlockSyncProvider, ChainTipV1, LightFollowProvider, LightFollowRow, LightFollowV1,
    MAX_BLOCKS_PER_GET_V1, MAX_LIGHT_FOLLOW_PER_GET_V1,
};
use mfn_runtime::Chain;
use mfn_store::ChainPersistence;

/// Shared chain + store for inbound block-sync queries.
pub struct P2pBlockSyncHandler {
    chain: Arc<Mutex<Chain>>,
    store: Arc<dyn ChainPersistence + Send + Sync>,
}

impl P2pBlockSyncHandler {
    /// Shared `Arc` for block-sync and light-follow P2P hooks (**M4.13**).
    pub fn new_hooks(
        chain: Arc<Mutex<Chain>>,
        store: Arc<dyn ChainPersistence + Send + Sync>,
    ) -> (BlockSyncHook, LightFollowHook) {
        let arc = Arc::new(Self { chain, store });
        let sync: BlockSyncHook = arc.clone();
        let light: LightFollowHook = arc;
        (sync, light)
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

impl LightFollowProvider for P2pBlockSyncHandler {
    fn light_follow_from_height(&self, start_height: u32, count: u32) -> LightFollowV1 {
        let count = count.min(MAX_LIGHT_FOLLOW_PER_GET_V1);
        let chain = match self.chain.lock() {
            Ok(g) => g,
            Err(_) => {
                return LightFollowV1 {
                    genesis_id: [0u8; 32],
                    rows: Vec::new(),
                };
            }
        };
        let genesis_id = *chain.genesis_id();
        let blocks = match self.store.read_block_log_validated(&chain) {
            Ok(b) => b,
            Err(_) => {
                return LightFollowV1 {
                    genesis_id,
                    rows: Vec::new(),
                };
            }
        };
        let rows = blocks
            .into_iter()
            .filter(|b| b.header.height >= start_height)
            .take(count as usize)
            .map(|b| {
                let h = b.header.height;
                LightFollowRow {
                    height: h,
                    block_id: block_id(&b.header),
                    header_wire: block_header_bytes(&b.header),
                    slashings: b.slashings.iter().map(encode_evidence).collect(),
                    bond_ops: b.bond_ops.iter().map(encode_bond_op).collect(),
                }
            })
            .collect();
        LightFollowV1 { genesis_id, rows }
    }
}
