//! Memory budget for a 2 GB phone or a 4 GB machine.
//!
//! The budget is a cache limit for headers, block bodies, the mempool, and
//! peer read buffers. It is not a license to delete storage commitments or
//! the UTXO set. Those stay on disk under the retention rules.
//!
//! The four caps add up to at most 40% of the device RAM so the operating
//! system and the permanence database still have room.

/// Which machine the node is running on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceClass {
    /// 2 GiB of RAM.
    Phone2Gb,
    /// 4 GiB of RAM.
    Small4Gb,
}

/// Byte caps for the four caches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryBudget {
    /// Header cache.
    pub header_cache: u64,
    /// Block-body cache.
    pub body_cache: u64,
    /// Mempool.
    pub mempool: u64,
    /// Peer read buffers.
    pub peer_buffers: u64,
    /// Sum of the four caps.
    pub total: u64,
    /// RAM the class names.
    pub ram: u64,
}

const GIB: u64 = 1024 * 1024 * 1024;

impl MemoryBudget {
    /// Caps for `class`. The total is at most 40% of that class's RAM.
    #[must_use]
    pub fn for_device(class: DeviceClass) -> Self {
        let ram = match class {
            DeviceClass::Phone2Gb => 2 * GIB,
            DeviceClass::Small4Gb => 4 * GIB,
        };
        let total = ram / 5 * 2;
        let fifth = total / 5;
        let header_cache = fifth;
        let mempool = fifth;
        let peer_buffers = fifth;
        let body_cache = total - header_cache - mempool - peer_buffers;
        Self {
            header_cache,
            body_cache,
            mempool,
            peer_buffers,
            total,
            ram,
        }
    }
}

/// Why a body was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmitError {
    /// One body is larger than the whole cache.
    #[error("body of {len} bytes exceeds the cache cap {cap}")]
    Oversize {
        /// Body length.
        len: u64,
        /// Cache cap.
        cap: u64,
    },
    /// Only pinned bodies remain, and they already fill the cap.
    #[error("pinned bodies fill the cache")]
    PinnedFill,
}

/// A block-body cache that evicts the oldest unpinned body first.
#[derive(Clone, Debug)]
pub struct BodyCache {
    cap: u64,
    used: u64,
    entries: Vec<CacheEntry>,
}

#[derive(Clone, Debug)]
struct CacheEntry {
    height: u32,
    bytes: Vec<u8>,
    pinned: bool,
}

impl BodyCache {
    /// Empty cache with a byte cap.
    #[must_use]
    pub fn new(cap: u64) -> Self {
        Self {
            cap,
            used: 0,
            entries: Vec::new(),
        }
    }

    /// Cap in bytes.
    #[must_use]
    pub fn cap(&self) -> u64 {
        self.cap
    }

    /// Bytes currently stored.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Heights still in the cache, oldest first.
    #[must_use]
    pub fn heights(&self) -> Vec<u32> {
        self.entries.iter().map(|entry| entry.height).collect()
    }

    /// Store `body`. Pinned bodies are not evicted to make room.
    ///
    /// # Errors
    ///
    /// [`AdmitError::Oversize`] when the body alone exceeds the cap.
    /// [`AdmitError::PinnedFill`] when evicting every unpinned body is
    /// still not enough. In both cases the cache is unchanged.
    pub fn insert(
        &mut self,
        height: u32,
        body: Vec<u8>,
        pinned: bool,
    ) -> Result<usize, AdmitError> {
        let len = u64::try_from(body.len()).unwrap_or(u64::MAX);
        if len > self.cap {
            return Err(AdmitError::Oversize { len, cap: self.cap });
        }
        if self.used.saturating_add(len) <= self.cap {
            self.entries.push(CacheEntry {
                height,
                bytes: body,
                pinned,
            });
            self.used = self.used.saturating_add(len);
            return Ok(0);
        }
        let mut freed = 0u64;
        let mut drop_count = 0usize;
        for entry in &self.entries {
            if entry.pinned {
                continue;
            }
            freed = freed.saturating_add(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX));
            drop_count += 1;
            if self.used - freed + len <= self.cap {
                break;
            }
        }
        if self.used.saturating_sub(freed).saturating_add(len) > self.cap {
            return Err(AdmitError::PinnedFill);
        }
        let mut left = drop_count;
        self.entries.retain(|entry| {
            if left > 0 && !entry.pinned {
                left -= 1;
                false
            } else {
                true
            }
        });
        self.used = self.used.saturating_sub(freed);
        self.entries.push(CacheEntry {
            height,
            bytes: body,
            pinned,
        });
        self.used = self.used.saturating_add(len);
        Ok(drop_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_stay_under_forty_percent_and_parts_sum() {
        for class in [DeviceClass::Phone2Gb, DeviceClass::Small4Gb] {
            let budget = MemoryBudget::for_device(class);
            assert!(budget.total <= budget.ram / 5 * 2);
            assert!(budget.total * 5 <= budget.ram * 2);
            assert_eq!(
                budget.header_cache + budget.body_cache + budget.mempool + budget.peer_buffers,
                budget.total
            );
            assert!(budget.body_cache >= budget.header_cache);
        }
        let phone = MemoryBudget::for_device(DeviceClass::Phone2Gb);
        let small = MemoryBudget::for_device(DeviceClass::Small4Gb);
        assert!(small.total > phone.total);
        assert!(phone.total < 900 * 1024 * 1024);
    }

    #[test]
    fn oldest_unpinned_body_is_evicted_and_pinned_stays() {
        let mut cache = BodyCache::new(10);
        assert_eq!(cache.insert(1, vec![1; 4], false).expect("1"), 0);
        assert_eq!(cache.insert(2, vec![2; 4], true).expect("2"), 0);
        let evicted = cache.insert(3, vec![3; 4], false).expect("3");
        assert_eq!(evicted, 1);
        assert_eq!(cache.heights(), vec![2, 3]);
        assert!(cache.used() <= cache.cap());
    }

    #[test]
    fn an_oversize_body_does_not_change_the_cache() {
        let mut cache = BodyCache::new(8);
        cache.insert(1, vec![1; 4], true).expect("pin");
        let err = cache.insert(2, vec![2; 9], false).expect_err("big");
        assert_eq!(err, AdmitError::Oversize { len: 9, cap: 8 });
        assert_eq!(cache.heights(), vec![1]);
        assert_eq!(cache.used(), 4);
    }

    #[test]
    fn pinned_bodies_are_not_evicted_to_admit_another() {
        let mut cache = BodyCache::new(8);
        cache.insert(1, vec![1; 4], true).expect("a");
        cache.insert(2, vec![2; 4], true).expect("b");
        let err = cache.insert(3, vec![3; 4], false).expect_err("full");
        assert_eq!(err, AdmitError::PinnedFill);
        assert_eq!(cache.heights(), vec![1, 2]);
        assert_eq!(cache.used(), 8);
    }
}
