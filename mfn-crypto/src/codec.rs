//! MFBN-1 canonical binary encoding.
//!
//! MFBN-1 codec spec. Big-endian, length-prefixed,
//! deterministic. Variable-length integers use LEB128 (7-bit groups,
//! continuation bit on the MSB).
//!
//! These encodings define **chain identity** — two different implementations
//! that disagree on a single byte produce different transaction or block IDs
//! and therefore fork the chain. Treat any change here as consensus-critical.
//!
//! Readers reject lengths and varint groups that [`Writer`] cannot emit
//! (a count bigger than the unread buffer, a 10th group that does not fit
//! in a `u64`) before they allocate. Those inputs used to panic. Bytes
//! [`Writer`] produces, including `u64::MAX`, still round-trip.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

use crate::{CryptoError, Result};

/// Streaming writer for canonical binary encoding.
///
/// All append methods are chainable.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Create an empty writer.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Create a writer with capacity pre-allocated.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Consume the writer and return the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the encoded bytes so far.
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Append a raw byte slice (no length prefix).
    pub fn push(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Append a single byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Append a big-endian u32.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a big-endian u64.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Append a LEB128 varint.
    pub fn varint(&mut self, v: u64) -> &mut Self {
        let mut n = v;
        while n >= 0x80 {
            self.buf.push(((n as u8) & 0x7f) | 0x80);
            n >>= 7;
        }
        self.buf.push(n as u8);
        self
    }

    /// Append a length-prefixed byte slice (varint length + bytes).
    pub fn blob(&mut self, b: &[u8]) -> &mut Self {
        self.varint(b.len() as u64);
        self.buf.extend_from_slice(b);
        self
    }

    /// Append a 32-byte little-endian scalar.
    pub fn scalar(&mut self, s: &Scalar) -> &mut Self {
        self.buf.extend_from_slice(s.as_bytes());
        self
    }

    /// Append a 32-byte compressed Edwards point.
    pub fn point(&mut self, p: &EdwardsPoint) -> &mut Self {
        self.buf.extend_from_slice(p.compress().as_bytes());
        self
    }

    /// Append a varint length followed by `n` scalars.
    pub fn scalars(&mut self, ss: &[Scalar]) -> &mut Self {
        self.varint(ss.len() as u64);
        for s in ss {
            self.scalar(s);
        }
        self
    }

    /// Append a varint length followed by `n` points.
    pub fn points(&mut self, ps: &[EdwardsPoint]) -> &mut Self {
        self.varint(ps.len() as u64);
        for p in ps {
            self.point(p);
        }
        self
    }
}

/// Streaming reader for canonical binary encoding.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Create a reader over the given byte slice.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    /// `true` when no bytes remain.
    pub fn end(&self) -> bool {
        self.offset >= self.buf.len()
    }

    /// Number of bytes still unread.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    /// Read exactly `n` bytes; advance the offset.
    ///
    /// A length that overflows `offset + n` is a short read, not a panic.
    /// Callers pass lengths taken from the wire.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or(CryptoError::ShortBuffer { needed: n })?;
        if end > self.buf.len() {
            return Err(CryptoError::ShortBuffer {
                needed: end - self.buf.len(),
            });
        }
        let out = &self.buf[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    /// Read a single byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    /// Read a big-endian u32.
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a big-endian u64.
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.bytes(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read a LEB128 varint.
    ///
    /// Groups that do not fit in a `u64` return [`CryptoError::VarintTooLong`].
    /// The shift is checked before it is applied: a 10th group whose low 7
    /// bits are greater than 1 used to overflow the shift and panic.
    /// Encodings [`Writer`] emits, including `u64::MAX`, still decode.
    pub fn varint(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            if shift >= 64 {
                return Err(CryptoError::VarintTooLong);
            }
            let b = self.u8()?;
            let bits = u64::from(b & 0x7f);
            let room = 64 - shift;
            // `room == 64` only on the first byte. Every later group has
            // fewer than 64 bits left, and a payload that does not fit is
            // not a `u64`.
            if room < 64 && bits >= (1u64 << room) {
                return Err(CryptoError::VarintTooLong);
            }
            result |= bits << shift;
            if (b & 0x80) == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    /// Read a varint length and then that many bytes.
    ///
    /// The length is rejected when it is larger than the unread buffer,
    /// before any addition that could overflow.
    pub fn blob(&mut self) -> Result<&'a [u8]> {
        let n_raw = self.varint()?;
        let n = self.repeat_len(n_raw, 1)?;
        self.bytes(n)
    }

    /// Read a 32-byte little-endian scalar, reduced mod ℓ.
    pub fn scalar(&mut self) -> Result<Scalar> {
        let b = self.bytes(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(b);
        Ok(Scalar::from_bytes_mod_order(arr))
    }

    /// Read a 32-byte compressed Edwards point.
    pub fn point(&mut self) -> Result<EdwardsPoint> {
        let b = self.bytes(32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(b);
        CompressedEdwardsY(arr)
            .decompress()
            .ok_or(CryptoError::InvalidPoint)
    }

    /// Read a varint length and then that many scalars.
    ///
    /// `n` is accepted only when `n * 32` bytes remain. The `Vec` is then
    /// bounded by the buffer, so a short frame cannot force a multi-gigabyte
    /// allocation.
    pub fn scalars(&mut self) -> Result<Vec<Scalar>> {
        let n_raw = self.varint()?;
        let n = self.repeat_len(n_raw, 32)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.scalar()?);
        }
        Ok(out)
    }

    /// Read a varint length and then that many points.
    ///
    /// Same budget as [`Self::scalars`]: one compressed point is 32 bytes,
    /// and the allocation happens only after that budget fits.
    pub fn points(&mut self) -> Result<Vec<EdwardsPoint>> {
        let n_raw = self.varint()?;
        let n = self.repeat_len(n_raw, 32)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.point()?);
        }
        Ok(out)
    }

    /// Turn a wire count into a `Vec` length that fits in the unread buffer.
    ///
    /// `elem_len` is the minimum bytes each item consumes (1 for a blob
    /// byte, 32 for a scalar or a compressed point).
    fn repeat_len(&self, n_raw: u64, elem_len: usize) -> Result<usize> {
        let n = usize::try_from(n_raw).map_err(|_| CryptoError::CountExceedsBuffer {
            claimed: n_raw,
            remaining: self.remaining() as u64,
        })?;
        let need = n
            .checked_mul(elem_len)
            .ok_or(CryptoError::CountExceedsBuffer {
                claimed: n_raw,
                remaining: self.remaining() as u64,
            })?;
        if need > self.remaining() {
            return Err(CryptoError::ShortBuffer {
                needed: need - self.remaining(),
            });
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        let cases: &[u64] = &[0, 1, 127, 128, 16383, 16384, 1 << 20, u64::MAX >> 1];
        for &v in cases {
            let mut w = Writer::new();
            w.varint(v);
            let mut r = Reader::new(w.bytes());
            let decoded = r.varint().expect("varint decode");
            assert_eq!(decoded, v);
            assert!(r.end(), "trailing bytes for {v}");
        }
    }

    #[test]
    fn blob_round_trip() {
        let payload: &[u8] = b"hello mfn world!";
        let mut w = Writer::new();
        w.blob(payload);
        let mut r = Reader::new(w.bytes());
        let out = r.blob().expect("blob");
        assert_eq!(out, payload);
        assert!(r.end());
    }

    #[test]
    fn fixed_width_round_trip() {
        let mut w = Writer::new();
        w.u8(0x42).u32(0xdead_beef).u64(0x1122_3344_5566_7788);
        let mut r = Reader::new(w.bytes());
        assert_eq!(r.u8().unwrap(), 0x42);
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.u64().unwrap(), 0x1122_3344_5566_7788);
        assert!(r.end());
    }

    #[test]
    fn short_buffer_errors() {
        let mut r = Reader::new(&[0x01, 0x02]);
        assert!(matches!(r.bytes(8), Err(CryptoError::ShortBuffer { .. })));
    }

    #[test]
    fn u64_max_varint_round_trips() {
        let mut w = Writer::new();
        w.varint(u64::MAX);
        let encoded = w.bytes().to_vec();
        assert_eq!(encoded.len(), 10, "u64::MAX is ten LEB128 groups");
        let mut r = Reader::new(&encoded);
        assert_eq!(r.varint().expect("u64::MAX"), u64::MAX);
        assert!(r.end());
    }

    #[test]
    fn tenth_varint_group_that_does_not_fit_is_an_error() {
        // Nine continuation bytes, then a payload of 2 at shift 63.
        // `2 << 63` does not fit in u64 and used to panic under overflow checks.
        for last in [0x02u8, 0x7f, 0xff] {
            let mut raw = vec![0xff; 9];
            raw.push(last);
            let mut r = Reader::new(&raw);
            assert!(
                matches!(r.varint(), Err(CryptoError::VarintTooLong)),
                "last byte {last:#x}"
            );
        }
    }

    #[test]
    fn oversized_blob_and_repeat_counts_do_not_allocate() {
        // Length prefix for 2^63, then two payload bytes. The addition
        // `offset + length` used to overflow.
        let mut huge = vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        huge.extend_from_slice(&[0xaa, 0xbb]);
        let mut r = Reader::new(&huge);
        assert!(matches!(r.blob(), Err(CryptoError::ShortBuffer { .. })));

        // One million points declared, four bytes present.
        let mut points = Vec::new();
        {
            let mut w = Writer::new();
            w.varint(1_000_000);
            points.extend_from_slice(w.bytes());
        }
        points.extend_from_slice(&[1, 2, 3, 4]);
        let mut r = Reader::new(&points);
        assert!(matches!(r.points(), Err(CryptoError::ShortBuffer { .. })));
        let mut r = Reader::new(&points);
        assert!(matches!(r.scalars(), Err(CryptoError::ShortBuffer { .. })));
    }

    #[test]
    fn bytes_rejects_length_that_overflows_the_offset() {
        let mut r = Reader::new(&[0u8; 8]);
        assert!(matches!(
            r.bytes(usize::MAX),
            Err(CryptoError::ShortBuffer { .. })
        ));
    }
}
