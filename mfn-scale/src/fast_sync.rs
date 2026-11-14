//! Checkpointed fast sync that still verifies headers.
//!
//! Historical bodies before the checkpoint are not downloaded. Every
//! header from the local tip through the remote tip is still linked, and
//! the checkpoint is installed only when its height and header id are on
//! that linked chain. Bodies after the checkpoint are checked with the
//! same `body_matches` predicate as a full pull.
//!
//! This does not skip header linkage and it does not trust a state root
//! whose header id is absent. No consensus rule changes.

use crate::header_sync::{
    HeaderFirstSync, HeaderSource, HeaderSyncConfig, SyncError, SyncHeader, SyncStats,
};

/// A state snapshot bound to one linked header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateCheckpoint {
    /// Height of the header the snapshot commits to.
    pub height: u32,
    /// Header id the snapshot must match.
    pub block_id: [u8; 32],
    /// Opaque state commitment. Recorded only after the header id matches.
    pub state_root: [u8; 32],
}

/// Why a fast sync refused to install a checkpoint.
#[derive(Debug, thiserror::Error)]
pub enum FastSyncError {
    /// Header linkage or a post-checkpoint body failed.
    #[error(transparent)]
    Sync(#[from] SyncError),
    /// Checkpoint height is past the remote tip.
    #[error("checkpoint height {height} is above remote tip {tip}")]
    CheckpointAboveTip {
        /// Claimed checkpoint height.
        height: u32,
        /// Remote tip the peer advertised.
        tip: u32,
    },
    /// No linked header at the checkpoint height.
    #[error("no linked header at checkpoint height {0}")]
    CheckpointMissing(u32),
    /// The linked header id is not the one the checkpoint names.
    #[error("checkpoint at {height} does not match the linked header")]
    CheckpointMismatch {
        /// Checkpoint height.
        height: u32,
        /// Id on the linked chain.
        linked_id: [u8; 32],
        /// Id the checkpoint claimed.
        claimed_id: [u8; 32],
    },
}

/// Light sync that installs a checkpoint only after header linkage.
#[derive(Clone, Debug)]
pub struct FastSync {
    chain: HeaderFirstSync,
    state_root: Option<[u8; 32]>,
    checkpoint_height: Option<u32>,
}

impl FastSync {
    /// Start from a trusted genesis id. No checkpoint is installed.
    #[must_use]
    pub fn at_genesis(genesis_id: [u8; 32], config: HeaderSyncConfig) -> Self {
        Self {
            chain: HeaderFirstSync::at_genesis(genesis_id, config),
            state_root: None,
            checkpoint_height: None,
        }
    }

    /// Highest linked height after a successful pull. Genesis is 0.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.chain.height()
    }

    /// State root recorded for the installed checkpoint.
    #[must_use]
    pub fn state_root(&self) -> Option<[u8; 32]> {
        self.state_root
    }

    /// Height of the installed checkpoint.
    #[must_use]
    pub fn checkpoint_height(&self) -> Option<u32> {
        self.checkpoint_height
    }

    /// Link every header through `remote_tip`, require `checkpoint` to name
    /// one of those headers, then download bodies strictly above it.
    ///
    /// # Errors
    ///
    /// A checkpoint that is above the tip, missing, or bound to a different
    /// header id is refused before any body request from the committing
    /// pull. Header linkage still runs so a forged checkpoint cannot skip
    /// it. On error the previous tip and state root stay in place.
    pub fn pull<S: HeaderSource>(
        &mut self,
        source: &S,
        remote_tip: u32,
        checkpoint: StateCheckpoint,
        body_matches: impl FnMut(&SyncHeader, &[u8]) -> bool,
    ) -> Result<SyncStats, FastSyncError> {
        if checkpoint.height > remote_tip {
            return Err(FastSyncError::CheckpointAboveTip {
                height: checkpoint.height,
                tip: remote_tip,
            });
        }
        let linked = self.chain.link_headers(source, remote_tip)?;
        if checkpoint.height == 0 {
            let genesis = *self.chain.tip();
            if checkpoint.block_id != genesis {
                return Err(FastSyncError::CheckpointMismatch {
                    height: 0,
                    linked_id: genesis,
                    claimed_id: checkpoint.block_id,
                });
            }
        } else {
            let found = linked
                .accepted
                .iter()
                .find(|header| header.height == checkpoint.height)
                .ok_or(FastSyncError::CheckpointMissing(checkpoint.height))?;
            if found.block_id != checkpoint.block_id {
                return Err(FastSyncError::CheckpointMismatch {
                    height: checkpoint.height,
                    linked_id: found.block_id,
                    claimed_id: checkpoint.block_id,
                });
            }
        }
        let first_body = checkpoint.height.saturating_add(1);
        let stats = self
            .chain
            .pull_bodies_from(source, remote_tip, first_body, body_matches)?;
        self.state_root = Some(checkpoint.state_root);
        self.checkpoint_height = Some(checkpoint.height);
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::header_sync::{
        synthetic_body_matches, synthetic_chain, HeaderSource, MemorySource, SyncHeader,
    };

    struct Spy {
        inner: MemorySource,
        body_heights: RefCell<Vec<u32>>,
    }

    impl HeaderSource for Spy {
        fn headers(&self, start: u32, count: u32) -> Vec<SyncHeader> {
            self.inner.headers(start, count)
        }

        fn bodies(&self, heights: &[u32]) -> Vec<Vec<u8>> {
            self.body_heights.borrow_mut().extend_from_slice(heights);
            self.inner.bodies(heights)
        }
    }

    fn genesis() -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = 0xA1;
        id
    }

    fn config() -> HeaderSyncConfig {
        HeaderSyncConfig {
            window: 8,
            parallel: 2,
        }
    }

    #[test]
    fn checkpoint_skips_older_bodies_and_still_links_headers() {
        let chain = synthetic_chain(genesis(), 50);
        let checkpoint_header = chain[19];
        let source = Spy {
            inner: MemorySource::new(chain),
            body_heights: RefCell::new(Vec::new()),
        };
        let mut sync = FastSync::at_genesis(genesis(), config());
        let stats = sync
            .pull(
                &source,
                50,
                StateCheckpoint {
                    height: 20,
                    block_id: checkpoint_header.block_id,
                    state_root: [0x5A; 32],
                },
                synthetic_body_matches,
            )
            .expect("fast");
        assert_eq!(stats.headers_verified, 50);
        assert_eq!(stats.bodies_accepted, 30);
        assert_eq!(sync.height(), 50);
        assert_eq!(sync.state_root(), Some([0x5A; 32]));
        assert_eq!(sync.checkpoint_height(), Some(20));
        let heights = source.body_heights.borrow().clone();
        assert!(heights.iter().all(|h| *h > 20));
        assert_eq!(heights.iter().min().copied(), Some(21));
        assert_eq!(heights.iter().max().copied(), Some(50));
    }

    #[test]
    fn a_checkpoint_for_a_different_header_installs_nothing() {
        let chain = synthetic_chain(genesis(), 20);
        let source = Spy {
            inner: MemorySource::new(chain),
            body_heights: RefCell::new(Vec::new()),
        };
        let mut sync = FastSync::at_genesis(genesis(), config());
        let err = sync
            .pull(
                &source,
                20,
                StateCheckpoint {
                    height: 10,
                    block_id: [0x22; 32],
                    state_root: [0x11; 32],
                },
                synthetic_body_matches,
            )
            .expect_err("mismatch");
        assert!(matches!(
            err,
            FastSyncError::CheckpointMismatch { height: 10, .. }
        ));
        assert_eq!(sync.height(), 0);
        assert_eq!(sync.state_root(), None);
        assert!(source.body_heights.borrow().is_empty());
    }

    #[test]
    fn a_checkpoint_above_the_remote_tip_is_refused() {
        let source = MemorySource::new(synthetic_chain(genesis(), 10));
        let mut sync = FastSync::at_genesis(genesis(), config());
        let err = sync
            .pull(
                &source,
                10,
                StateCheckpoint {
                    height: 11,
                    block_id: [1; 32],
                    state_root: [2; 32],
                },
                synthetic_body_matches,
            )
            .expect_err("above");
        assert!(matches!(
            err,
            FastSyncError::CheckpointAboveTip {
                height: 11,
                tip: 10
            }
        ));
        assert_eq!(sync.height(), 0);
    }

    #[test]
    fn a_bad_body_after_the_checkpoint_does_not_install_state() {
        let chain = synthetic_chain(genesis(), 12);
        let checkpoint_header = chain[3];
        let source = MemorySource::new(chain);
        let mut sync = FastSync::at_genesis(genesis(), config());
        let err = sync
            .pull(
                &source,
                12,
                StateCheckpoint {
                    height: 4,
                    block_id: checkpoint_header.block_id,
                    state_root: [9; 32],
                },
                |_header, _body| false,
            )
            .expect_err("body");
        assert!(matches!(
            err,
            FastSyncError::Sync(SyncError::BodyMismatch(5))
        ));
        assert_eq!(sync.height(), 0);
        assert_eq!(sync.state_root(), None);
    }
}
