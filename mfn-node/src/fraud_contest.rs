//! In-memory registry of P2P-verified fraud contests (**F5** phase 1b).
//!
//! Light clients poll `list_fraud_contests` on `mfnd` while on-chain producer
//! slash for invalid blocks remains deferred.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// One contested block observed on the P2P mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FraudContestEntry {
    pub(crate) block_id: [u8; 32],
    pub(crate) height: u32,
    pub(crate) producer_index: u32,
    pub(crate) label: String,
}

/// Deduped by `block_id`; latest gossip label wins for the same block.
#[derive(Debug, Default)]
pub(crate) struct FraudContestRegistry {
    entries: BTreeMap<[u8; 32], FraudContestEntry>,
}

impl FraudContestRegistry {
    pub(crate) fn record(&mut self, entry: FraudContestEntry) {
        self.entries.insert(entry.block_id, entry);
    }

    pub(crate) fn list(&self) -> Vec<FraudContestEntry> {
        self.entries.values().cloned().collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Shared handle wired from [`crate::p2p_gossip::P2pGossipHandler`] into RPC dispatch.
pub(crate) type FraudContestRegistryCell = Arc<Mutex<FraudContestRegistry>>;

pub(crate) fn new_fraud_contest_registry() -> FraudContestRegistryCell {
    Arc::new(Mutex::new(FraudContestRegistry::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_by_block_id() {
        let mut reg = FraudContestRegistry::default();
        let bid = [0x11; 32];
        reg.record(FraudContestEntry {
            block_id: bid,
            height: 1,
            producer_index: 0,
            label: "first".into(),
        });
        reg.record(FraudContestEntry {
            block_id: bid,
            height: 1,
            producer_index: 0,
            label: "second".into(),
        });
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.list()[0].label, "second");
    }
}
