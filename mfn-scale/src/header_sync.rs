//! Headers-first sync.
//!
//! A node that downloads full blocks from height zero spends bandwidth on
//! bodies it cannot check until the header chain links. This engine
//! fetches header windows first, checks height and `prev` linkage, and
//! only then asks for bodies. A broken header stops the pull before any
//! later body is requested, and a failed pull leaves the local tip where
//! it was.
//!
//! The header here is the scale-lane sync header (height, id, previous
//! id), not a consensus `BlockHeader`. BLS verification stays in
//! `mfn-light`. This step is the download order.

use std::cell::Cell;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

const HEADER_DOMAIN: &[u8] = b"MFN-1/scale-sync-header/v1";
const BODY_DOMAIN: &[u8] = b"MFN-1/scale-sync-body/v1";

/// How many headers to ask for at once, and how many windows to have
/// outstanding before linkage runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderSyncConfig {
    /// Headers per request. `0` is treated as 1.
    pub window: u32,
    /// Header windows issued before the next linkage pass. `0` is treated as 1.
    pub parallel: usize,
}

impl Default for HeaderSyncConfig {
    fn default() -> Self {
        Self {
            window: 32,
            parallel: 4,
        }
    }
}

/// A header the sync engine can link without a block body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncHeader {
    /// Chain height. Genesis is 0 and is not downloaded.
    pub height: u32,
    /// This header's id.
    pub block_id: [u8; 32],
    /// Id of the previous header.
    pub prev_id: [u8; 32],
}

/// What one successful pull accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncStats {
    /// Headers that linked.
    pub headers_verified: u32,
    /// Bodies that matched their header.
    pub bodies_accepted: u32,
    /// `headers` calls issued.
    pub header_requests: u32,
    /// `bodies` calls issued.
    pub body_requests: u32,
}

/// Why a pull stopped. The local tip is unchanged.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    /// Response height was not the next height.
    #[error("header height {got} at expected {expected}")]
    HeightGap {
        /// Height the engine was about to accept.
        expected: u32,
        /// Height the peer sent.
        got: u32,
    },
    /// `prev_id` did not match the previous accepted id.
    #[error("prev mismatch at height {height}")]
    PrevMismatch {
        /// Header that failed.
        height: u32,
        /// Id the engine already accepted.
        expected: [u8; 32],
        /// Id the peer put in `prev_id`.
        got: [u8; 32],
    },
    /// The peer did not return the next height.
    #[error("missing header at height {0}")]
    MissingHeader(u32),
    /// Two headers claimed the same height.
    #[error("duplicate header at height {0}")]
    DuplicateHeader(u32),
    /// Body bytes did not match the header id.
    #[error("body mismatch at height {0}")]
    BodyMismatch(u32),
    /// Body list length did not match the request.
    #[error("body response length {got} for {expected} heights")]
    BodyCount {
        /// Heights requested.
        expected: usize,
        /// Bodies returned.
        got: usize,
    },
}

/// Peer that can serve header windows and bodies by height.
pub trait HeaderSource {
    /// Headers with `height >= start`, up to `count`, in increasing height.
    fn headers(&self, start: u32, count: u32) -> Vec<SyncHeader>;
    /// Body bytes for each height, in the same order as `heights`.
    fn bodies(&self, heights: &[u32]) -> Vec<Vec<u8>>;
}

/// Local tip plus the headers accepted so far.
#[derive(Clone, Debug)]
pub struct HeaderFirstSync {
    height: u32,
    tip: [u8; 32],
    headers: Vec<SyncHeader>,
    config: HeaderSyncConfig,
}

impl HeaderFirstSync {
    /// Start from a trusted genesis id. Height is 0. Nothing is downloaded.
    #[must_use]
    pub fn at_genesis(genesis_id: [u8; 32], config: HeaderSyncConfig) -> Self {
        Self {
            height: 0,
            tip: genesis_id,
            headers: Vec::new(),
            config,
        }
    }

    /// Highest linked height. Genesis is 0.
    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Id of the highest linked header, or the genesis id at height 0.
    #[must_use]
    pub fn tip(&self) -> &[u8; 32] {
        &self.tip
    }

    /// Headers accepted by previous successful pulls, in height order.
    #[must_use]
    pub fn headers(&self) -> &[SyncHeader] {
        &self.headers
    }

    /// Link headers from `self.height + 1` through `remote_tip`, then
    /// fetch bodies. `body_matches` is the caller's check that the body
    /// is the one committed by the header.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError`] on a gap, a bad `prev`, a duplicate, or a
    /// body that fails `body_matches`. `self` is unchanged.
    pub fn pull<S: HeaderSource>(
        &mut self,
        source: &S,
        remote_tip: u32,
        mut body_matches: impl FnMut(&SyncHeader, &[u8]) -> bool,
    ) -> Result<SyncStats, SyncError> {
        if remote_tip <= self.height {
            return Ok(SyncStats {
                headers_verified: 0,
                bodies_accepted: 0,
                header_requests: 0,
                body_requests: 0,
            });
        }
        let window = self.config.window.max(1);
        let parallel = self.config.parallel.max(1);
        let mut next_fetch = self.height.saturating_add(1);
        let mut next_check = next_fetch;
        let mut buffer: BTreeMap<u32, SyncHeader> = BTreeMap::new();
        let mut header_requests = 0u32;
        let mut accepted: Vec<SyncHeader> = Vec::new();
        let mut tip = self.tip;

        while next_check <= remote_tip {
            let mut issued = 0usize;
            while issued < parallel && next_fetch <= remote_tip {
                let remaining = remote_tip - next_fetch + 1;
                let count = window.min(remaining);
                header_requests = header_requests.saturating_add(1);
                let batch = source.headers(next_fetch, count);
                if batch.is_empty() {
                    return Err(SyncError::MissingHeader(next_fetch));
                }
                for header in batch {
                    if buffer.insert(header.height, header).is_some() {
                        return Err(SyncError::DuplicateHeader(header.height));
                    }
                }
                next_fetch = next_fetch.saturating_add(count);
                issued += 1;
            }
            let before = next_check;
            while next_check <= remote_tip {
                let Some(header) = buffer.remove(&next_check) else {
                    break;
                };
                if header.height != next_check {
                    return Err(SyncError::HeightGap {
                        expected: next_check,
                        got: header.height,
                    });
                }
                if header.prev_id != tip {
                    return Err(SyncError::PrevMismatch {
                        height: header.height,
                        expected: tip,
                        got: header.prev_id,
                    });
                }
                tip = header.block_id;
                accepted.push(header);
                next_check = next_check.saturating_add(1);
            }
            if next_check == before {
                return Err(SyncError::MissingHeader(next_check));
            }
        }

        let mut body_requests = 0u32;
        let mut bodies_accepted = 0u32;
        let heights: Vec<u32> = accepted.iter().map(|h| h.height).collect();
        for chunk in heights.chunks(window as usize) {
            body_requests = body_requests.saturating_add(1);
            let bodies = source.bodies(chunk);
            if bodies.len() != chunk.len() {
                return Err(SyncError::BodyCount {
                    expected: chunk.len(),
                    got: bodies.len(),
                });
            }
            for (height, body) in chunk.iter().zip(bodies.iter()) {
                let header = accepted
                    .iter()
                    .find(|h| h.height == *height)
                    .ok_or(SyncError::MissingHeader(*height))?;
                if !body_matches(header, body) {
                    return Err(SyncError::BodyMismatch(*height));
                }
                bodies_accepted = bodies_accepted.saturating_add(1);
            }
        }

        let headers_verified = u32::try_from(accepted.len()).unwrap_or(u32::MAX);
        self.height = remote_tip;
        self.tip = tip;
        self.headers.extend(accepted);
        Ok(SyncStats {
            headers_verified,
            bodies_accepted,
            header_requests,
            body_requests,
        })
    }
}

/// Id of a synthetic header at `height` whose parent id is `prev`.
#[must_use]
pub fn synthetic_header_id(prev: &[u8; 32], height: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HEADER_DOMAIN);
    hasher.update(prev);
    hasher.update(height.to_be_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Body bytes committed to `block_id`. The test peer serves these.
#[must_use]
pub fn synthetic_body(block_id: &[u8; 32]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(BODY_DOMAIN);
    hasher.update(block_id);
    hasher.finalize().to_vec()
}

/// Honest chain of `count` headers starting at height 1.
#[must_use]
pub fn synthetic_chain(genesis_id: [u8; 32], count: u32) -> Vec<SyncHeader> {
    let mut prev = genesis_id;
    let mut out = Vec::with_capacity(count as usize);
    for height in 1..=count {
        let block_id = synthetic_header_id(&prev, height);
        out.push(SyncHeader {
            height,
            block_id,
            prev_id: prev,
        });
        prev = block_id;
    }
    out
}

/// In-memory peer over a synthetic chain. `lie_prev_at` rewrites that
/// header's `prev_id` so linkage fails.
#[derive(Clone, Debug)]
pub struct MemorySource {
    headers: Vec<SyncHeader>,
    /// Height whose `prev_id` is replaced with zeros.
    pub lie_prev_at: Option<u32>,
    /// When set, `bodies` returns an empty list if the chunk contains this height.
    pub short_body_at: Option<u32>,
    /// How many times `bodies` was called.
    pub body_calls: Cell<u32>,
}

impl MemorySource {
    /// Serve `chain` honestly.
    #[must_use]
    pub fn new(chain: Vec<SyncHeader>) -> Self {
        Self {
            headers: chain,
            lie_prev_at: None,
            short_body_at: None,
            body_calls: Cell::new(0),
        }
    }
}

impl HeaderSource for MemorySource {
    fn headers(&self, start: u32, count: u32) -> Vec<SyncHeader> {
        self.headers
            .iter()
            .filter(|h| h.height >= start)
            .take(count as usize)
            .map(|h| {
                let mut header = *h;
                if self.lie_prev_at == Some(header.height) {
                    header.prev_id = [0x11; 32];
                }
                header
            })
            .collect()
    }

    fn bodies(&self, heights: &[u32]) -> Vec<Vec<u8>> {
        self.body_calls.set(self.body_calls.get().saturating_add(1));
        if self.short_body_at.is_some_and(|h| heights.contains(&h)) {
            return Vec::new();
        }
        heights
            .iter()
            .filter_map(|height| {
                self.headers
                    .iter()
                    .find(|h| h.height == *height)
                    .map(|h| synthetic_body(&h.block_id))
            })
            .collect()
    }
}

/// `true` when `body` is [`synthetic_body`] of the header id.
#[must_use]
pub fn synthetic_body_matches(header: &SyncHeader, body: &[u8]) -> bool {
    synthetic_body(&header.block_id) == body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis() -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = 0xA1;
        id
    }

    #[test]
    fn headers_link_before_bodies_and_advance_the_tip() {
        let chain = synthetic_chain(genesis(), 100);
        let source = MemorySource::new(chain);
        let mut sync = HeaderFirstSync::at_genesis(
            genesis(),
            HeaderSyncConfig {
                window: 16,
                parallel: 3,
            },
        );
        let stats = sync
            .pull(&source, 100, synthetic_body_matches)
            .expect("pull");
        assert_eq!(stats.headers_verified, 100);
        assert_eq!(stats.bodies_accepted, 100);
        assert!(stats.header_requests >= 4, "windows should split the chain");
        assert!(stats.body_requests >= 4);
        assert_eq!(sync.height(), 100);
        assert_eq!(sync.headers().len(), 100);
        assert_eq!(sync.tip(), &sync.headers().last().unwrap().block_id);
        assert_eq!(sync.headers()[0].prev_id, genesis());
    }

    #[test]
    fn a_bad_prev_does_not_move_the_tip_or_fetch_later_bodies() {
        let chain = synthetic_chain(genesis(), 40);
        let mut source = MemorySource::new(chain);
        source.lie_prev_at = Some(9);
        let mut sync = HeaderFirstSync::at_genesis(
            genesis(),
            HeaderSyncConfig {
                window: 8,
                parallel: 2,
            },
        );
        let err = sync
            .pull(&source, 40, synthetic_body_matches)
            .expect_err("lie");
        let honest = synthetic_chain(genesis(), 8);
        assert_eq!(
            err,
            SyncError::PrevMismatch {
                height: 9,
                expected: honest[7].block_id,
                got: [0x11; 32],
            }
        );
        assert_eq!(source.body_calls.get(), 0);
        assert_eq!(sync.height(), 0);
        assert_eq!(sync.tip(), &genesis());
        assert!(sync.headers().is_empty());
    }

    #[test]
    fn a_short_body_response_is_rejected_without_advancing() {
        let chain = synthetic_chain(genesis(), 10);
        let mut source = MemorySource::new(chain);
        source.short_body_at = Some(4);
        let mut sync = HeaderFirstSync::at_genesis(genesis(), HeaderSyncConfig::default());
        let err = sync
            .pull(&source, 10, synthetic_body_matches)
            .expect_err("short");
        assert!(matches!(err, SyncError::BodyCount { .. }));
        assert_eq!(sync.height(), 0);
    }

    #[test]
    fn already_at_tip_is_a_no_op() {
        let mut sync = HeaderFirstSync::at_genesis(genesis(), HeaderSyncConfig::default());
        let source = MemorySource::new(synthetic_chain(genesis(), 5));
        let stats = sync.pull(&source, 0, synthetic_body_matches).expect("noop");
        assert_eq!(stats.header_requests, 0);
        assert_eq!(stats.body_requests, 0);
        assert_eq!(sync.height(), 0);
    }

    #[test]
    fn a_body_that_does_not_match_the_header_is_rejected() {
        let source = MemorySource::new(synthetic_chain(genesis(), 4));
        let mut sync = HeaderFirstSync::at_genesis(
            genesis(),
            HeaderSyncConfig {
                window: 4,
                parallel: 1,
            },
        );
        let err = sync
            .pull(&source, 4, |_header, _body| false)
            .expect_err("body");
        assert_eq!(err, SyncError::BodyMismatch(1));
        assert_eq!(sync.height(), 0);
    }
}
