//! Bounds for integers taken from a peer.
//!
//! Frame bodies are already capped at 4 MiB. A count inside that body can
//! still ask for a `Vec` far larger than the body if the decoder allocates
//! before it checks that the items fit. These helpers reject that count
//! first. They do not change bytes an honest encoder writes.

/// A LEB128 group did not fit in a `u64`, or the buffer ended mid-group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Leb128Error {
    /// Not enough bytes to finish the integer.
    Truncated,
    /// A group would shift past bit 63, or its payload does not fit there.
    Overflow,
}

/// Read one unsigned LEB128 integer.
///
/// The shift is checked before it is applied. A 10th group whose low 7 bits
/// are greater than 1 used to execute `2 << 63` and panic when overflow
/// checks are on. `u64::MAX`, which honest encoders do emit, still decodes.
pub fn read_leb128_u64(buf: &[u8], offset: &mut usize) -> Result<u64, Leb128Error> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if shift >= 64 {
            return Err(Leb128Error::Overflow);
        }
        if *offset >= buf.len() {
            return Err(Leb128Error::Truncated);
        }
        let byte = buf[*offset];
        *offset += 1;
        let bits = u64::from(byte & 0x7f);
        let room = 64 - shift;
        if room < 64 && bits >= (1u64 << room) {
            return Err(Leb128Error::Overflow);
        }
        result |= bits << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

/// `true` when `declared` items of at least `min_each` bytes fit in `remaining`.
///
/// A zero `min_each` is rejected: every length-prefixed item costs at least
/// its length word. Multiplication overflow is a reject, not a wrap.
pub fn declared_count_fits(declared: usize, min_each: usize, remaining: usize) -> bool {
    if min_each == 0 {
        return false;
    }
    match declared.checked_mul(min_each) {
        Some(need) => need <= remaining,
        None => false,
    }
}

/// Checked end index for a `u32` length prefix that starts at byte 0 of `buf`.
///
/// Returns the exclusive end (`4 + len`) when that range is inside `buf`.
pub fn prefixed_end(buf: &[u8], len: u32) -> Option<usize> {
    let len = usize::try_from(len).ok()?;
    let end = 4usize.checked_add(len)?;
    if end > buf.len() {
        None
    } else {
        Some(end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_u64_round_trips() {
        // Writer form of u64::MAX: nine 0xFF groups and a final 0x01.
        let mut raw = vec![0xff; 9];
        raw.push(0x01);
        let mut off = 0;
        assert_eq!(read_leb128_u64(&raw, &mut off).unwrap(), u64::MAX);
        assert_eq!(off, raw.len());
    }

    #[test]
    fn tenth_group_that_does_not_fit_is_overflow() {
        for last in [0x02u8, 0x7f, 0xff] {
            let mut raw = vec![0xff; 9];
            raw.push(last);
            let mut off = 0;
            assert_eq!(
                read_leb128_u64(&raw, &mut off),
                Err(Leb128Error::Overflow),
                "last {last:#x}"
            );
        }
    }

    #[test]
    fn truncated_group_is_not_a_panic() {
        let mut off = 0;
        assert_eq!(read_leb128_u64(&[], &mut off), Err(Leb128Error::Truncated));
        let mut off = 0;
        assert_eq!(
            read_leb128_u64(&[0x80], &mut off),
            Err(Leb128Error::Truncated)
        );
        let mut off = 0;
        assert_eq!(
            read_leb128_u64(&[0xff; 9], &mut off),
            Err(Leb128Error::Truncated)
        );
    }

    #[test]
    fn small_values_match_canonical_groups() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (300, &[0xac, 0x02]),
        ];
        for (value, bytes) in cases {
            let mut off = 0;
            assert_eq!(read_leb128_u64(bytes, &mut off).unwrap(), *value);
            assert_eq!(off, bytes.len());
        }
    }

    #[test]
    fn declared_count_respects_the_unread_budget() {
        assert!(declared_count_fits(0, 4, 0));
        assert!(declared_count_fits(3, 4, 12));
        assert!(!declared_count_fits(3, 4, 11));
        assert!(!declared_count_fits(usize::MAX, 2, usize::MAX));
        assert!(!declared_count_fits(1, 0, 100));
        // The light-follow bug: a u32::MAX count inside a short row.
        assert!(!declared_count_fits(u32::MAX as usize, 4, 64));
    }

    #[test]
    fn prefixed_end_rejects_a_length_past_the_buffer() {
        assert_eq!(prefixed_end(&[0, 0, 0, 0], 0), Some(4));
        assert_eq!(prefixed_end(&[0, 0, 0, 2, 9, 9], 2), Some(6));
        assert_eq!(prefixed_end(&[0, 0, 0, 2, 9], 2), None);
        assert_eq!(prefixed_end(&[0, 0, 0], 0), None);
        assert_eq!(prefixed_end(&[0, 0, 0, 0], u32::MAX), None);
    }

    #[test]
    fn corpus_of_random_prefixes_does_not_panic() {
        let mut state = 0x7032_705f_636e_7401u64;
        for _ in 0..400 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let n = (state as usize) % 48;
            let mut buf = Vec::with_capacity(n);
            let mut s = state;
            for _ in 0..n {
                s = s.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
                buf.push(s as u8);
            }
            let mut off = 0;
            let _ = read_leb128_u64(&buf, &mut off);
            if buf.len() >= 4 {
                let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let _ = prefixed_end(&buf, len);
            }
            let _ = declared_count_fits(state as usize, 4, buf.len());
        }
    }
}
