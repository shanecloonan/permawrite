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

/// Check a contiguous slice of the block log read by height range.
///
/// `total_records` is the number of records in the whole log; `start_height` is the
/// height of `blocks[0]`. Links inside the slice, to genesis when the slice starts at
/// height 1, and to the chain tip when the slice ends at the tip are verified.
pub fn validate_block_range(
    chain: &Chain,
    total_records: u64,
    start_height: u32,
    blocks: &[Block],
) -> Result<(), StoreError> {
    let tip_h = chain
        .tip_height()
        .ok_or_else(|| StoreError::BlockLog("chain tip_height is None (unexpected)".into()))?;
    let tip_id = chain
        .tip_id()
        .ok_or_else(|| StoreError::BlockLog("chain tip_id is None (unexpected)".into()))?;
    if total_records != u64::from(tip_h) {
        return Err(StoreError::BlockLog(format!(
            "block log has {total_records} record(s) but chain tip_height is {tip_h}"
        )));
    }
    let mut expected_prev: Option<[u8; 32]> = if start_height == 1 {
        Some(*chain.genesis_id())
    } else {
        None
    };
    for (i, b) in blocks.iter().enumerate() {
        let expected_height = start_height.saturating_add(i as u32);
        if b.header.height != expected_height {
            return Err(StoreError::BlockLog(format!(
                "block log record {}: header.height {} != expected {expected_height}",
                u64::from(expected_height).saturating_sub(1),
                b.header.height
            )));
        }
        if let Some(prev) = expected_prev {
            if b.header.prev_hash != prev {
                return Err(StoreError::BlockLog(format!(
                    "block log record {}: prev_hash does not extend chain from genesis/tip",
                    u64::from(expected_height).saturating_sub(1)
                )));
            }
        }
        expected_prev = Some(block_id(&b.header));
    }
    if let Some(last) = blocks.last() {
        if last.header.height == tip_h && expected_prev.as_ref() != Some(tip_id) {
            return Err(StoreError::BlockLog(
                "block log terminal block_id does not match chain tip_id".into(),
            ));
        }
    }
    Ok(())
}
