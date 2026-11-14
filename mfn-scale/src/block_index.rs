//! Height index over an append-only block log.
//!
//! Reading a body by height walks the index, not the log. The index stores
//! the offset and the length. The body stays in the log. Rebuilding the
//! index from the log must reproduce the same offsets, so a crash between
//! appends can be repaired by a scan.

/// Where one body sits in the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockSpan {
    /// Block height.
    pub height: u32,
    /// Header id stored next to the body.
    pub block_id: [u8; 32],
    /// Byte offset of the body inside the log.
    pub offset: u64,
    /// Body length.
    pub body_len: u32,
}

/// Why a log could not be indexed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IndexError {
    /// The log ended inside a record.
    #[error("truncated block log")]
    Truncated,
    /// Heights were not 0, 1, 2, ... in order.
    #[error("height {got}, expected {expected}")]
    Gap {
        /// Next height the index expected.
        expected: u32,
        /// Height found in the log.
        got: u32,
    },
    /// A length field did not match the body that followed.
    #[error("body length does not fit in the log")]
    BadLength,
}

/// Dense height-to-span map. Height `n` is `spans[n]` when the log starts at 0.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockIndex {
    spans: Vec<BlockSpan>,
}

impl BlockIndex {
    /// Empty index.
    #[must_use]
    pub fn new() -> Self {
        Self { spans: Vec::new() }
    }

    /// Number of indexed blocks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    /// `true` when nothing is indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// Span for `height`, if that height was indexed.
    #[must_use]
    pub fn get(&self, height: u32) -> Option<&BlockSpan> {
        self.spans.get(usize::try_from(height).ok()?)
    }

    /// Append one block. Returns the record bytes to write to the log.
    ///
    /// The body's offset in a log that already holds `log_len` bytes is
    /// recorded. Heights must be appended in order starting at 0.
    ///
    /// # Errors
    ///
    /// [`IndexError::Gap`] when `height` is not the next height.
    pub fn append(
        &mut self,
        log_len: u64,
        height: u32,
        block_id: [u8; 32],
        body: &[u8],
    ) -> Result<Vec<u8>, IndexError> {
        let expected = u32::try_from(self.spans.len()).unwrap_or(u32::MAX);
        if height != expected {
            return Err(IndexError::Gap {
                expected,
                got: height,
            });
        }
        let body_len = u32::try_from(body.len()).map_err(|_| IndexError::BadLength)?;
        let record = encode_record(height, &block_id, body);
        let header_len = 4 + 32 + 4;
        let offset = log_len.saturating_add(u64::try_from(header_len).unwrap_or(u64::MAX));
        self.spans.push(BlockSpan {
            height,
            block_id,
            offset,
            body_len,
        });
        Ok(record)
    }

    /// Body slice for `height` inside `log`.
    #[must_use]
    pub fn read_body<'a>(&self, height: u32, log: &'a [u8]) -> Option<&'a [u8]> {
        let span = self.get(height)?;
        let start = usize::try_from(span.offset).ok()?;
        let len = usize::try_from(span.body_len).ok()?;
        log.get(start..start.saturating_add(len))
    }

    /// Rebuild an index by scanning `log` from the start.
    ///
    /// # Errors
    ///
    /// [`IndexError`] when the log is truncated or heights are not dense from 0.
    pub fn rebuild(log: &[u8]) -> Result<Self, IndexError> {
        let mut index = Self::new();
        let mut cursor = 0usize;
        while cursor < log.len() {
            if log.len() - cursor < 4 + 32 + 4 {
                return Err(IndexError::Truncated);
            }
            let height = u32::from_be_bytes(log[cursor..cursor + 4].try_into().expect("4"));
            cursor += 4;
            let mut block_id = [0u8; 32];
            block_id.copy_from_slice(&log[cursor..cursor + 32]);
            cursor += 32;
            let body_len = u32::from_be_bytes(log[cursor..cursor + 4].try_into().expect("4"));
            cursor += 4;
            let len = usize::try_from(body_len).map_err(|_| IndexError::BadLength)?;
            if log.len() - cursor < len {
                return Err(IndexError::Truncated);
            }
            let body = &log[cursor..cursor + len];
            let record_start = cursor - (4 + 32 + 4);
            let log_len = u64::try_from(record_start).unwrap_or(u64::MAX);
            index.append(log_len, height, block_id, body)?;
            cursor += len;
        }
        Ok(index)
    }
}

fn encode_record(height: u32, block_id: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + 4 + body.len());
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(block_id);
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(height: u32) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..4].copy_from_slice(&height.to_be_bytes());
        out
    }

    #[test]
    fn lookup_reads_the_body_without_scanning_and_rebuild_matches() {
        let mut index = BlockIndex::new();
        let mut log = Vec::new();
        for height in 0..30u32 {
            let body = vec![u8::try_from(height).unwrap_or(0); 8];
            let record = index
                .append(
                    u64::try_from(log.len()).unwrap_or(0),
                    height,
                    id(height),
                    &body,
                )
                .expect("append");
            log.extend_from_slice(&record);
        }
        let span = index.get(17).expect("17");
        assert_eq!(span.block_id, id(17));
        assert_eq!(index.read_body(17, &log), Some(vec![17u8; 8].as_slice()));
        assert_eq!(index.get(30), None);
        let rebuilt = BlockIndex::rebuild(&log).expect("rebuild");
        assert_eq!(rebuilt, index);
    }

    #[test]
    fn a_gap_and_a_truncated_tail_are_errors() {
        let mut index = BlockIndex::new();
        let err = index.append(0, 3, id(3), b"body").expect_err("gap");
        assert_eq!(
            err,
            IndexError::Gap {
                expected: 0,
                got: 3
            }
        );
        let mut log = Vec::new();
        let record = index.append(0, 0, id(0), b"abcdef").expect("one");
        log.extend_from_slice(&record);
        log.pop();
        assert_eq!(
            BlockIndex::rebuild(&log).unwrap_err(),
            IndexError::Truncated
        );
    }
}
