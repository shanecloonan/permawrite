//! Which operator stores which shard.
//!
//! Shard `i` is stored by operator `i % operator_count`. With six operators
//! each keeps two shards. Any two operators together hold four shards, which
//! is enough to rebuild the file. One operator does not.

use std::path::Path;

use crate::stripe::STRIPE_SHARDS;

/// `true` when this operator stores `shard`.
#[must_use]
pub fn operator_holds_shard(shard: u32, operator_index: u32, operator_count: u32) -> bool {
    operator_count > 0
        && operator_index < operator_count
        && shard % operator_count == operator_index
}

/// Delete shard files in `dir` that this operator does not hold.
///
/// Returns how many shard files remain.
pub fn retain_assigned_shards(dir: &Path, operator_index: u32, operator_count: u32) -> u32 {
    let mut kept = 0u32;
    for shard in 0..STRIPE_SHARDS {
        let path = dir.join(format!("shard-{shard:02}.bin"));
        if operator_holds_shard(shard, operator_index, operator_count) {
            if path.is_file() {
                kept = kept.saturating_add(1);
            }
        } else if path.is_file() {
            let _ = std::fs::remove_file(path);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::{open_shard_stripe, prepare_shard_stripe};

    #[test]
    fn two_of_six_operators_cover_a_dropout() {
        let dir = std::env::temp_dir().join(format!("mfn-assign-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let plain = b"each operator keeps two shards".to_vec();
        let prepared = prepare_shard_stripe(&plain).expect("stripe");
        let count = 6u32;
        for op in 0..count {
            let op_dir = dir.join(format!("op{op}"));
            std::fs::create_dir_all(&op_dir).expect("dir");
            for (i, shard) in prepared.shards.iter().enumerate() {
                std::fs::write(op_dir.join(format!("shard-{i:02}.bin")), shard).expect("shard");
            }
            let kept = retain_assigned_shards(&op_dir, op, count);
            assert_eq!(kept, 2);
        }
        let mut slots = vec![None; 12];
        for op in [0u32, 2, 4] {
            if op == 4 {
                continue;
            }
            let op_dir = dir.join(format!("op{op}"));
            for shard in 0..12u32 {
                let path = op_dir.join(format!("shard-{shard:02}.bin"));
                if let Ok(bytes) = std::fs::read(path) {
                    slots[shard as usize] = Some(bytes);
                }
            }
        }
        let opened = open_shard_stripe(&slots).expect("two operators");
        assert_eq!(opened, plain);
        let mut alone = vec![None; 12];
        for shard in 0..12u32 {
            let path = dir.join("op0").join(format!("shard-{shard:02}.bin"));
            if let Ok(bytes) = std::fs::read(path) {
                alone[shard as usize] = Some(bytes);
            }
        }
        assert!(open_shard_stripe(&alone).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
