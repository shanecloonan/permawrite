//! Block-log consistency checks shared by persistence backends.

use mfn_consensus::{block_id, Block};
use mfn_runtime::Chain;

use crate::StoreError;

/// Verify `blocks` replays consistently with `chain` (heights, `prev_hash`, terminal `tip_id`).
pub fn validate_block_log(chain: &Chain, blocks: &[Block]) -> Result<(), StoreError> {
    let tip_h = chain
        .tip_height()
        .ok_or_else(|| StoreError::BlockLog("chain tip_height is None (unexpected)".into()))?;
    let tip_id = chain
        .tip_id()
        .ok_or_else(|| StoreError::BlockLog("chain tip_id is None (unexpected)".into()))?;

    if blocks.len() as u32 != tip_h {
        return Err(StoreError::BlockLog(format!(
            "block log has {} record(s) but chain tip_height is {tip_h}",
            blocks.len()
        )));
    }
    if blocks.is_empty() && tip_h != 0 {
        return Err(StoreError::BlockLog(format!(
            "block log is empty but chain tip_height is {tip_h}"
        )));
    }

    let mut expected_prev = *chain.genesis_id();
    for (i, b) in blocks.iter().enumerate() {
        let expected_height = (i as u32) + 1;
        if b.header.height != expected_height {
            return Err(StoreError::BlockLog(format!(
                "block log record {i}: header.height {} != expected {expected_height}",
                b.header.height
            )));
        }
        if b.header.prev_hash != expected_prev {
            return Err(StoreError::BlockLog(format!(
                "block log record {i}: prev_hash does not extend chain from genesis/tip"
            )));
        }
        expected_prev = block_id(&b.header);
    }

    if !blocks.is_empty() && expected_prev != *tip_id {
        return Err(StoreError::BlockLog(
            "block log terminal block_id does not match chain tip_id".into(),
        ));
    }

    Ok(())
}
