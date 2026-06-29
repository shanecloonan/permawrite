//! P2P block-sync: serve [`GetBlocksByHeightV1`] from the validated block log (**M2.3.18**).

use std::sync::{Arc, Mutex};

use mfn_consensus::{block_header_bytes, block_id, encode_block, encode_bond_op, encode_evidence};
use mfn_net::serve::{BlockSyncHook, LightFollowHook};
use mfn_net::{
    BlockSyncProvider, ChainTipV1, LightFollowProvider, LightFollowRow, LightFollowV1,
    MAX_BLOCKS_PER_GET_V1, MAX_FRAME_PAYLOAD_LEN, MAX_LIGHT_FOLLOW_PER_GET_V1,
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
        let mut payload_len = BLOCKS_V1_HEADER_LEN;
        let mut out = Vec::new();
        for wire in blocks
            .into_iter()
            .filter(|b| b.header.height >= start_height)
            .take(count as usize)
            .map(|b| encode_block(&b))
        {
            if !push_block_wire_if_fits(
                &mut out,
                &mut payload_len,
                wire,
                MAX_FRAME_PAYLOAD_LEN as usize,
            ) {
                break;
            }
        }
        out
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
        let mut payload_len = LIGHT_FOLLOW_V1_HEADER_LEN;
        let mut rows = Vec::new();
        for row in blocks
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
        {
            if !push_light_follow_row_if_fits(
                &mut rows,
                &mut payload_len,
                row,
                MAX_FRAME_PAYLOAD_LEN as usize,
            ) {
                break;
            }
        }
        LightFollowV1 { genesis_id, rows }
    }
}

const BLOCKS_V1_HEADER_LEN: usize = 1 + 4;
const BLOCKS_V1_BLOCK_LEN_PREFIX: usize = 4;
const LIGHT_FOLLOW_V1_HEADER_LEN: usize = 1 + 32 + 4;
const LIGHT_FOLLOW_ROW_FIXED_LEN: usize = 4 + 32 + 4 + 4 + 4;

fn push_block_wire_if_fits(
    out: &mut Vec<Vec<u8>>,
    payload_len: &mut usize,
    wire: Vec<u8>,
    max_payload_len: usize,
) -> bool {
    let Some(next_len) = BLOCKS_V1_BLOCK_LEN_PREFIX.checked_add(wire.len()) else {
        return false;
    };
    push_item_if_fits(out, payload_len, wire, next_len, max_payload_len)
}

fn push_light_follow_row_if_fits(
    out: &mut Vec<LightFollowRow>,
    payload_len: &mut usize,
    row: LightFollowRow,
    max_payload_len: usize,
) -> bool {
    let Some(next_len) = light_follow_row_payload_len(&row) else {
        return false;
    };
    push_item_if_fits(out, payload_len, row, next_len, max_payload_len)
}

fn push_item_if_fits<T>(
    out: &mut Vec<T>,
    payload_len: &mut usize,
    item: T,
    item_len: usize,
    max_payload_len: usize,
) -> bool {
    let Some(next_payload_len) = payload_len.checked_add(item_len) else {
        return false;
    };
    if next_payload_len > max_payload_len {
        return false;
    }
    out.push(item);
    *payload_len = next_payload_len;
    true
}

fn light_follow_row_payload_len(row: &LightFollowRow) -> Option<usize> {
    let mut len = LIGHT_FOLLOW_ROW_FIXED_LEN.checked_add(row.header_wire.len())?;
    for bytes in row.slashings.iter().chain(row.bond_ops.iter()) {
        len = len.checked_add(4)?.checked_add(bytes.len())?;
    }
    Some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row(height: u32, header_len: usize) -> LightFollowRow {
        LightFollowRow {
            height,
            block_id: [height as u8; 32],
            header_wire: vec![0xab; header_len],
            slashings: vec![vec![1, 2, 3]],
            bond_ops: vec![vec![4, 5]],
        }
    }

    #[test]
    fn block_response_budget_keeps_prefix_that_fits() {
        let mut payload_len = BLOCKS_V1_HEADER_LEN;
        let mut out = Vec::new();
        let max = BLOCKS_V1_HEADER_LEN + BLOCKS_V1_BLOCK_LEN_PREFIX + 3;

        assert!(push_block_wire_if_fits(
            &mut out,
            &mut payload_len,
            vec![1, 2, 3],
            max,
        ));
        assert!(!push_block_wire_if_fits(
            &mut out,
            &mut payload_len,
            vec![4],
            max,
        ));

        assert_eq!(out, vec![vec![1, 2, 3]]);
        assert_eq!(payload_len, max);
    }

    #[test]
    fn block_response_budget_allows_empty_when_first_block_is_too_large() {
        let mut payload_len = BLOCKS_V1_HEADER_LEN;
        let mut out = Vec::new();
        let max = BLOCKS_V1_HEADER_LEN + BLOCKS_V1_BLOCK_LEN_PREFIX;

        assert!(!push_block_wire_if_fits(
            &mut out,
            &mut payload_len,
            vec![1],
            max,
        ));

        assert!(out.is_empty());
        assert_eq!(payload_len, BLOCKS_V1_HEADER_LEN);
    }

    #[test]
    fn light_follow_response_budget_keeps_prefix_that_fits() {
        let first = sample_row(1, 3);
        let first_len = light_follow_row_payload_len(&first).expect("row length");
        let mut payload_len = LIGHT_FOLLOW_V1_HEADER_LEN;
        let mut out = Vec::new();
        let max = LIGHT_FOLLOW_V1_HEADER_LEN + first_len;

        assert!(push_light_follow_row_if_fits(
            &mut out,
            &mut payload_len,
            first,
            max,
        ));
        assert!(!push_light_follow_row_if_fits(
            &mut out,
            &mut payload_len,
            sample_row(2, 1),
            max,
        ));

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].height, 1);
        assert_eq!(payload_len, max);
    }

    #[test]
    fn light_follow_response_budget_allows_empty_when_first_row_is_too_large() {
        let row = sample_row(1, 1);
        let row_len = light_follow_row_payload_len(&row).expect("row length");
        let mut payload_len = LIGHT_FOLLOW_V1_HEADER_LEN;
        let mut out = Vec::new();
        let max = LIGHT_FOLLOW_V1_HEADER_LEN + row_len - 1;

        assert!(!push_light_follow_row_if_fits(
            &mut out,
            &mut payload_len,
            row,
            max,
        ));

        assert!(out.is_empty());
        assert_eq!(payload_len, LIGHT_FOLLOW_V1_HEADER_LEN);
    }
}
