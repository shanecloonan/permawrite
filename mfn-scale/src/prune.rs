//! Bounded block-log bodies.
//!
//! Path A stays archival: it keeps every body. A bounded node may drop
//! historical bodies strictly below a finalized checkpoint, and only those.
//! The decision is [`mfn_consensus::historical_block_body_may_prune`].
//! Storage commitments, the UTXO map, spent key images, and header ids are
//! not prune candidates. Dropping them would break permanence or the ring.

use mfn_consensus::{
    historical_block_body_may_prune, spent_key_image_may_prune, storage_may_prune, utxo_may_prune,
};

/// What a node is willing to forget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeRole {
    /// Keep every body. This is the Path A default.
    Archival,
    /// Drop historical bodies below a finalized checkpoint. Header ids stay.
    Bounded,
}

/// A class a caller might try to delete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepClass {
    /// Storage commitments.
    Storage,
    /// UTXO map, including spent outputs used as decoys.
    Utxo,
    /// Spent key images.
    SpentKeyImage,
    /// Header id. Required to link the chain after a body is gone.
    HeaderId,
}

/// One block in the local log. The body is optional after a prune.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecord {
    /// Block height.
    pub height: u32,
    /// Header id. Never removed.
    pub block_id: [u8; 32],
    /// Body bytes. `None` after a bounded prune.
    pub body: Option<Vec<u8>>,
}

/// Why a delete was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PruneError {
    /// Archival nodes do not drop bodies.
    #[error("archival node keeps every body")]
    ArchivalKeepsBodies,
    /// This class is not a prune candidate.
    #[error("{0:?} is not a prune candidate")]
    NeverPrune(KeepClass),
}

/// Local block log plus the role that decides whether bodies can go.
#[derive(Clone, Debug)]
pub struct BlockLog {
    role: NodeRole,
    records: Vec<BlockRecord>,
}

impl BlockLog {
    /// Empty log with a role.
    #[must_use]
    pub fn new(role: NodeRole) -> Self {
        Self {
            role,
            records: Vec::new(),
        }
    }

    /// Append a block that still has its body. Header id is stored beside it.
    pub fn append(&mut self, height: u32, block_id: [u8; 32], body: Vec<u8>) {
        self.records.push(BlockRecord {
            height,
            block_id,
            body: Some(body),
        });
    }

    /// Role this log was opened with.
    #[must_use]
    pub fn role(&self) -> NodeRole {
        self.role
    }

    /// Records in append order.
    #[must_use]
    pub fn records(&self) -> &[BlockRecord] {
        &self.records
    }

    /// Bytes still held in bodies.
    #[must_use]
    pub fn body_bytes(&self) -> usize {
        self.records
            .iter()
            .map(|record| record.body.as_ref().map_or(0, Vec::len))
            .sum()
    }

    /// `true` when the consensus helper allows this class to be deleted.
    ///
    /// Header ids are never allowed, even if a future helper changes.
    #[must_use]
    pub fn class_may_drop(class: KeepClass) -> bool {
        match class {
            KeepClass::Storage => storage_may_prune(),
            KeepClass::Utxo => utxo_may_prune(),
            KeepClass::SpentKeyImage => spent_key_image_may_prune(),
            KeepClass::HeaderId => false,
        }
    }

    /// Refuse to delete a permanence, privacy, or header-id class.
    ///
    /// # Errors
    ///
    /// Always [`PruneError::NeverPrune`] while the consensus helpers say
    /// those maps are not prune candidates.
    pub fn drop_class(&self, class: KeepClass) -> Result<(), PruneError> {
        // Consult the helper so a future `true` shows up in `class_may_drop`.
        // This log still refuses: it does not own those maps, and header ids stay.
        let _consulted = Self::class_may_drop(class);
        Err(PruneError::NeverPrune(class))
    }

    /// Drop bodies the helper marks as historical. Header ids stay.
    ///
    /// An archival log drops nothing. A finalized checkpoint of 0 drops
    /// nothing, because the helper refuses that.
    ///
    /// # Errors
    ///
    /// [`PruneError::ArchivalKeepsBodies`] when the role is archival.
    /// The log is unchanged in that case.
    pub fn prune_bodies(&mut self, finalized_checkpoint: u32) -> Result<usize, PruneError> {
        if self.role == NodeRole::Archival {
            return Err(PruneError::ArchivalKeepsBodies);
        }
        let mut dropped = 0usize;
        for record in &mut self.records {
            if historical_block_body_may_prune(record.height, finalized_checkpoint)
                && record.body.take().is_some()
            {
                dropped += 1;
            }
        }
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_of(role: NodeRole, n: u32) -> BlockLog {
        let mut log = BlockLog::new(role);
        for height in 0..n {
            let mut id = [0u8; 32];
            id[0] = u8::try_from(height).unwrap_or(0);
            log.append(height, id, vec![height as u8; 8]);
        }
        log
    }

    #[test]
    fn archival_keeps_every_body() {
        let mut log = log_of(NodeRole::Archival, 12);
        let before = log.body_bytes();
        assert_eq!(
            log.prune_bodies(8).unwrap_err(),
            PruneError::ArchivalKeepsBodies
        );
        assert_eq!(log.body_bytes(), before);
        assert!(log.records().iter().all(|record| record.body.is_some()));
    }

    #[test]
    fn bounded_drops_only_bodies_below_the_checkpoint() {
        let mut log = log_of(NodeRole::Bounded, 12);
        let ids: Vec<[u8; 32]> = log.records().iter().map(|r| r.block_id).collect();
        let dropped = log.prune_bodies(8).expect("prune");
        assert_eq!(dropped, 8);
        for record in log.records() {
            assert_eq!(record.body.is_none(), record.height < 8);
            assert_eq!(record.block_id, ids[record.height as usize]);
        }
        assert_eq!(log.body_bytes(), 4 * 8);
        assert_eq!(log.prune_bodies(8).expect("second"), 0);
    }

    #[test]
    fn a_zero_checkpoint_drops_nothing() {
        let mut log = log_of(NodeRole::Bounded, 5);
        assert_eq!(log.prune_bodies(0).expect("zero"), 0);
        assert!(log.records().iter().all(|record| record.body.is_some()));
    }

    #[test]
    fn storage_utxo_key_images_and_header_ids_are_not_dropped() {
        let log = log_of(NodeRole::Bounded, 2);
        for class in [
            KeepClass::Storage,
            KeepClass::Utxo,
            KeepClass::SpentKeyImage,
            KeepClass::HeaderId,
        ] {
            assert!(!BlockLog::class_may_drop(class));
            assert_eq!(
                log.drop_class(class).unwrap_err(),
                PruneError::NeverPrune(class)
            );
        }
        assert!(log.records().iter().all(|record| record.body.is_some()));
    }
}
