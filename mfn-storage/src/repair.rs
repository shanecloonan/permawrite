//! Decide which chunks to fetch when a file is below its replica target.
//!
//! An upload asks for `replication` holders. This planner counts how many
//! distinct operators currently hold every chunk, and names one source for
//! each chunk the local operator is missing. A chunk nobody holds is
//! reported separately: there is no fetch that can invent it.
//!
//! Operator-side. Not an `apply_block` rule. Path A and F-A are unchanged.

/// One operator and the chunk indexes it currently holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkHolder {
    /// Operator identity.
    pub operator_id: [u8; 32],
    /// Chunk indexes this operator can serve.
    pub chunks: Vec<u32>,
}

/// One chunk the local operator should copy, and who to copy it from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkRepair {
    /// Index inside the file.
    pub chunk_index: u32,
    /// Operator that holds that index. The lowest id wins ties.
    pub from: [u8; 32],
}

/// What a repair pass should do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairPlan {
    /// Distinct operators who hold every chunk.
    pub full_replicas: u16,
    /// `target - full_replicas`, saturating at 0.
    pub shortfall: u8,
    /// Chunks the local operator does not hold, with a source.
    pub fetches: Vec<ChunkRepair>,
    /// Chunk indexes no listed operator holds.
    pub missing_everywhere: Vec<u32>,
}

/// Why a plan could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairError {
    /// `num_chunks` was 0.
    NoChunks,
    /// `target` was 0.
    TargetZero,
}

/// Build a repair plan for `local` against `holders`.
///
/// `holders` may include `local`. A repeated operator id is one holder;
/// its chunk sets are united.
///
/// # Errors
///
/// [`RepairError`] when `num_chunks` or `target` is 0.
pub fn plan_repair(
    num_chunks: u32,
    target: u8,
    local: &[u8; 32],
    holders: &[ChunkHolder],
) -> Result<RepairPlan, RepairError> {
    if num_chunks == 0 {
        return Err(RepairError::NoChunks);
    }
    if target == 0 {
        return Err(RepairError::TargetZero);
    }
    let mut merged: Vec<([u8; 32], Vec<u32>)> = Vec::new();
    for holder in holders {
        if let Some((_, chunks)) = merged.iter_mut().find(|(id, _)| id == &holder.operator_id) {
            for index in &holder.chunks {
                if *index < num_chunks && !chunks.contains(index) {
                    chunks.push(*index);
                }
            }
        } else {
            let chunks: Vec<u32> = holder
                .chunks
                .iter()
                .copied()
                .filter(|index| *index < num_chunks)
                .collect();
            merged.push((holder.operator_id, chunks));
        }
    }
    for (_, chunks) in &mut merged {
        chunks.sort_unstable();
        chunks.dedup();
    }
    let full_replicas = merged
        .iter()
        .filter(|(_, chunks)| chunks.len() == usize::try_from(num_chunks).unwrap_or(usize::MAX))
        .count();
    let full_replicas = u16::try_from(full_replicas).unwrap_or(u16::MAX);
    let shortfall =
        u8::try_from(u16::from(target).saturating_sub(full_replicas)).unwrap_or(u8::MAX);
    let local_chunks = merged
        .iter()
        .find(|(id, _)| id == local)
        .map(|(_, chunks)| chunks.clone())
        .unwrap_or_default();
    let mut fetches = Vec::new();
    let mut missing_everywhere = Vec::new();
    for index in 0..num_chunks {
        if local_chunks.contains(&index) {
            continue;
        }
        let mut sources: Vec<[u8; 32]> = merged
            .iter()
            .filter(|(id, chunks)| id != local && chunks.contains(&index))
            .map(|(id, _)| *id)
            .collect();
        sources.sort_unstable();
        if let Some(from) = sources.first().copied() {
            fetches.push(ChunkRepair {
                chunk_index: index,
                from,
            });
        } else {
            missing_everywhere.push(index);
        }
    }
    Ok(RepairPlan {
        full_replicas,
        shortfall,
        fetches,
        missing_everywhere,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn holder(byte: u8, chunks: &[u32]) -> ChunkHolder {
        ChunkHolder {
            operator_id: id(byte),
            chunks: chunks.to_vec(),
        }
    }

    #[test]
    fn three_full_copies_have_no_shortfall_and_no_fetch() {
        let holders = [holder(1, &[0, 1]), holder(2, &[0, 1]), holder(3, &[1, 0])];
        let plan = plan_repair(2, 3, &id(1), &holders).expect("plan");
        assert_eq!(plan.full_replicas, 3);
        assert_eq!(plan.shortfall, 0);
        assert!(plan.fetches.is_empty());
        assert!(plan.missing_everywhere.is_empty());
    }

    #[test]
    fn a_missing_local_chunk_is_fetched_from_the_lowest_peer() {
        let holders = [holder(1, &[0]), holder(9, &[0, 1]), holder(4, &[1])];
        let plan = plan_repair(2, 3, &id(1), &holders).expect("plan");
        assert_eq!(plan.full_replicas, 1);
        assert_eq!(plan.shortfall, 2);
        assert_eq!(
            plan.fetches,
            vec![ChunkRepair {
                chunk_index: 1,
                from: id(4),
            }]
        );
    }

    #[test]
    fn a_chunk_nobody_holds_is_not_a_fetch() {
        let holders = [holder(1, &[0]), holder(2, &[0])];
        let plan = plan_repair(2, 3, &id(1), &holders).expect("plan");
        assert!(plan.fetches.is_empty());
        assert_eq!(plan.missing_everywhere, vec![1]);
        assert_eq!(plan.full_replicas, 0);
    }

    #[test]
    fn repeated_operator_ids_are_one_replica() {
        let holders = [holder(1, &[0]), holder(1, &[1])];
        let plan = plan_repair(2, 2, &id(2), &holders).expect("plan");
        assert_eq!(plan.full_replicas, 1);
        assert_eq!(plan.fetches.len(), 2);
        assert!(plan.fetches.iter().all(|f| f.from == id(1)));
    }

    #[test]
    fn zero_chunks_or_target_is_rejected() {
        assert_eq!(
            plan_repair(0, 3, &id(1), &[]).unwrap_err(),
            RepairError::NoChunks
        );
        assert_eq!(
            plan_repair(1, 0, &id(1), &[]).unwrap_err(),
            RepairError::TargetZero
        );
    }
}
