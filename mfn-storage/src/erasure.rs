//! Reed–Solomon stripes so a file survives the loss of many operators.
//!
//! Full replication of factor 3 stores three copies and dies when two
//! operators vanish. The recommended stripe stores the same 3× bytes as
//! four data shards plus eight parity shards, and the payload comes back
//! from any four of the twelve. This is operator-side encoding. It does
//! not change `StorageCommitment`, chunking, Path A, or F-A.
//!
//! The field is GF(2^8) with primitive polynomial `0x11d`
//! (`x^8 + x^4 + x^3 + x^2 + 1`). The generator is
//! a systematic Vandermonde matrix, so the first `data_shards` shards are
//! the padded payload and the rest are parity.

use mfn_crypto::hash::dhash;

/// Domain for a shard binding. Off the consensus domain set.
const ERASURE_SHARD: &[u8] = b"MFBN-1/erasure-shard-v1";

/// Four data shards and eight parity shards: 3× storage, eight losses.
pub const RECOMMENDED_DATA_SHARDS: u8 = 4;
/// Parity count in [`RECOMMENDED_DATA_SHARDS`].
pub const RECOMMENDED_PARITY_SHARDS: u8 = 8;

/// Why a stripe could not be built or rebuilt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErasureError {
    /// `data_shards` was 0.
    DataShardsZero,
    /// `parity_shards` was 0. A stripe with no parity is not erasure coding.
    ParityShardsZero,
    /// `data_shards + parity_shards` does not fit in GF(256) indices.
    TooManyShards {
        /// Sum that was rejected.
        total: u16,
    },
    /// A present shard has a different length than the others.
    ShardLengthMismatch,
    /// Fewer than `data_shards` intact shards were offered.
    Unrecoverable {
        /// Intact shards offered.
        present: u8,
        /// Shards required.
        need: u8,
    },
    /// A shard index is outside the stripe.
    IndexOutOfRange {
        /// Index that was rejected.
        index: u8,
    },
    /// The binding does not match the bytes at that index.
    BindingMismatch {
        /// Index whose bytes were swapped or flipped.
        index: u8,
    },
    /// The generator matrix was singular. Not reachable for the Vandermonde
    /// points this module uses; kept so a future point set fails closed.
    Singular,
}

/// How many shards a stripe uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErasureLayout {
    /// Shards required to reconstruct.
    pub data_shards: u8,
    /// Extra shards. This is also the number of losses the stripe survives.
    pub parity_shards: u8,
}

impl ErasureLayout {
    /// Recommended layout: same byte overhead as replication 3, eight losses.
    #[must_use]
    pub const fn recommended() -> Self {
        Self {
            data_shards: RECOMMENDED_DATA_SHARDS,
            parity_shards: RECOMMENDED_PARITY_SHARDS,
        }
    }

    /// Total shards.
    pub fn total(self) -> Result<u8, ErasureError> {
        validate_layout(self)?;
        Ok(self.data_shards + self.parity_shards)
    }

    /// Losses that still leave a reconstructable set.
    #[must_use]
    pub const fn losses_tolerated(self) -> u8 {
        self.parity_shards
    }

    /// Storage overhead versus the payload, in basis points (10_000 = 1×).
    ///
    /// Recommended 4+8 is 30_000 (3×). Replication 3 is also 30_000 but
    /// tolerates only 2 losses.
    pub fn overhead_bps(self) -> Result<u32, ErasureError> {
        let total = u32::from(self.total()?);
        let data = u32::from(self.data_shards);
        Ok(total * 10_000 / data)
    }
}

/// One encoded file. Missing shards are `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureStripe {
    /// Layout used to encode.
    pub layout: ErasureLayout,
    /// Payload length before zero-padding to a shard multiple.
    pub original_len: u64,
    /// Shards in order. Index `0..data_shards` is systematic data.
    pub shards: Vec<Option<Vec<u8>>>,
    /// [`shard_binding`] for every index, including ones later dropped.
    pub bindings: Vec<[u8; 32]>,
}

/// `dhash` of the data root, the shard index, and the shard bytes.
///
/// A copied shard under a different index, or a flipped byte, is a
/// different binding.
#[must_use]
pub fn shard_binding(data_root: &[u8; 32], index: u8, shard: &[u8]) -> [u8; 32] {
    let idx = [index];
    dhash(ERASURE_SHARD, &[data_root, &idx, shard])
}

/// Split `payload` into a systematic stripe and bind every shard to `data_root`.
///
/// # Errors
///
/// [`ErasureError`] when the layout is unusable or the matrix is singular.
pub fn encode_stripe(
    data_root: &[u8; 32],
    payload: &[u8],
    layout: ErasureLayout,
) -> Result<ErasureStripe, ErasureError> {
    layout.total()?;
    let k = usize::from(layout.data_shards);
    let shard_len = if payload.is_empty() {
        0
    } else {
        payload.len().div_ceil(k)
    };
    let mut padded = vec![0u8; shard_len.saturating_mul(k)];
    padded[..payload.len()].copy_from_slice(payload);
    let data: Vec<Vec<u8>> = if shard_len == 0 {
        vec![Vec::new(); k]
    } else {
        padded.chunks(shard_len).map(<[u8]>::to_vec).collect()
    };
    let gen = systematic_generator(layout)?;
    let mut shards: Vec<Vec<u8>> = data.iter().take(k).cloned().collect();
    for gen_row in gen.iter().skip(k) {
        let mut parity = vec![0u8; shard_len];
        for (col, shard) in data.iter().enumerate() {
            let coeff = gen_row[col];
            if coeff == 0 {
                continue;
            }
            for (b, byte) in shard.iter().enumerate() {
                parity[b] ^= gf_mul(coeff, *byte);
            }
        }
        shards.push(parity);
    }
    let bindings = shards
        .iter()
        .enumerate()
        .map(|(i, shard)| shard_binding(data_root, u8::try_from(i).unwrap_or(u8::MAX), shard))
        .collect();
    Ok(ErasureStripe {
        layout,
        original_len: u64::try_from(payload.len()).unwrap_or(u64::MAX),
        shards: shards.into_iter().map(Some).collect(),
        bindings,
    })
}

/// Rebuild the payload from any `data_shards` intact shards.
///
/// A shard whose bytes do not match `bindings[index]` is treated as missing.
///
/// # Errors
///
/// [`ErasureError::Unrecoverable`] when fewer than `data_shards` bindings match.
/// [`ErasureError::BindingMismatch`] is not returned here; a bad shard is dropped.
pub fn reconstruct_payload(
    data_root: &[u8; 32],
    stripe: &ErasureStripe,
) -> Result<Vec<u8>, ErasureError> {
    validate_layout(stripe.layout)?;
    let n = usize::from(stripe.layout.data_shards) + usize::from(stripe.layout.parity_shards);
    if stripe.shards.len() != n || stripe.bindings.len() != n {
        return Err(ErasureError::IndexOutOfRange { index: 0 });
    }
    let mut present: Vec<Option<Vec<u8>>> = Vec::with_capacity(n);
    for (i, shard) in stripe.shards.iter().enumerate() {
        let idx = u8::try_from(i).unwrap_or(u8::MAX);
        match shard {
            Some(bytes) if shard_binding(data_root, idx, bytes) == stripe.bindings[i] => {
                present.push(Some(bytes.clone()));
            }
            _ => present.push(None),
        }
    }
    let padded = reconstruct_bytes(&present, stripe.layout)?;
    let len = usize::try_from(stripe.original_len).unwrap_or(usize::MAX);
    if len > padded.len() {
        return Err(ErasureError::Unrecoverable {
            present: 0,
            need: stripe.layout.data_shards,
        });
    }
    Ok(padded[..len].to_vec())
}

/// True when `present` intact shards are enough for `layout`.
#[must_use]
pub fn stripe_survives(present: u8, layout: ErasureLayout) -> bool {
    present >= layout.data_shards && layout.parity_shards > 0 && layout.data_shards > 0
}

fn validate_layout(layout: ErasureLayout) -> Result<(), ErasureError> {
    if layout.data_shards == 0 {
        return Err(ErasureError::DataShardsZero);
    }
    if layout.parity_shards == 0 {
        return Err(ErasureError::ParityShardsZero);
    }
    let total = u16::from(layout.data_shards) + u16::from(layout.parity_shards);
    if total > 255 {
        return Err(ErasureError::TooManyShards { total });
    }
    Ok(())
}

fn reconstruct_bytes(
    shards: &[Option<Vec<u8>>],
    layout: ErasureLayout,
) -> Result<Vec<u8>, ErasureError> {
    let k = usize::from(layout.data_shards);
    let n = k + usize::from(layout.parity_shards);
    if shards.len() != n {
        return Err(ErasureError::IndexOutOfRange { index: 0 });
    }
    let mut indexes = Vec::with_capacity(k);
    let mut rows = Vec::with_capacity(k);
    let mut shard_len = None;
    for (i, shard) in shards.iter().enumerate() {
        if let Some(bytes) = shard {
            match shard_len {
                None => shard_len = Some(bytes.len()),
                Some(len) if len != bytes.len() => return Err(ErasureError::ShardLengthMismatch),
                Some(_) => {}
            }
            if indexes.len() < k {
                indexes.push(i);
                rows.push(bytes.clone());
            }
        }
    }
    let present = u8::try_from(indexes.len()).unwrap_or(u8::MAX);
    if indexes.len() < k {
        return Err(ErasureError::Unrecoverable {
            present,
            need: layout.data_shards,
        });
    }
    let shard_len = shard_len.unwrap_or(0);
    let gen = systematic_generator(layout)?;
    let mut sub = vec![vec![0u8; k]; k];
    for (r, &idx) in indexes.iter().enumerate() {
        sub[r].clone_from(&gen[idx]);
    }
    let inv = invert(&sub)?;
    let mut data = vec![vec![0u8; shard_len]; k];
    for (out_row, inv_row) in inv.iter().enumerate() {
        for (in_row, coeff) in inv_row.iter().enumerate() {
            if *coeff == 0 {
                continue;
            }
            for (b, byte) in rows[in_row].iter().enumerate() {
                data[out_row][b] ^= gf_mul(*coeff, *byte);
            }
        }
    }
    let mut padded = Vec::with_capacity(shard_len * k);
    for shard in data {
        padded.extend_from_slice(&shard);
    }
    Ok(padded)
}

fn systematic_generator(layout: ErasureLayout) -> Result<Vec<Vec<u8>>, ErasureError> {
    let k = usize::from(layout.data_shards);
    let n = k + usize::from(layout.parity_shards);
    let mut vandermonde = vec![vec![0u8; k]; n];
    for (row, row_vals) in vandermonde.iter_mut().enumerate() {
        let x = u8::try_from(row + 1).unwrap_or(1);
        let mut power = 1u8;
        for cell in row_vals.iter_mut() {
            *cell = power;
            power = gf_mul(power, x);
        }
    }
    let mut top = vec![vec![0u8; k]; k];
    for row in 0..k {
        top[row].clone_from(&vandermonde[row]);
    }
    let top_inv = invert(&top)?;
    let mut gen = vec![vec![0u8; k]; n];
    for row in 0..n {
        for col in 0..k {
            let mut acc = 0u8;
            for (t, inv_row) in top_inv.iter().enumerate() {
                acc ^= gf_mul(vandermonde[row][t], inv_row[col]);
            }
            gen[row][col] = acc;
        }
    }
    Ok(gen)
}

fn invert(matrix: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, ErasureError> {
    let n = matrix.len();
    if n == 0 || matrix.iter().any(|row| row.len() != n) {
        return Err(ErasureError::Singular);
    }
    let mut aug = vec![vec![0u8; n * 2]; n];
    for r in 0..n {
        aug[r][..n].copy_from_slice(&matrix[r]);
        aug[r][n + r] = 1;
    }
    for col in 0..n {
        let mut pivot = None;
        for (row, aug_row) in aug.iter().enumerate().skip(col) {
            if aug_row[col] != 0 {
                pivot = Some(row);
                break;
            }
        }
        let Some(pivot) = pivot else {
            return Err(ErasureError::Singular);
        };
        aug.swap(col, pivot);
        let inv_pivot = gf_inv(aug[col][col])?;
        for v in &mut aug[col] {
            *v = gf_mul(*v, inv_pivot);
        }
        for row in 0..n {
            if row == col {
                continue;
            }
            let factor = aug[row][col];
            if factor == 0 {
                continue;
            }
            for c in 0..(n * 2) {
                let scaled = gf_mul(factor, aug[col][c]);
                aug[row][c] ^= scaled;
            }
        }
    }
    let mut out = vec![vec![0u8; n]; n];
    for r in 0..n {
        out[r].copy_from_slice(&aug[r][n..]);
    }
    Ok(out)
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = tables();
    exp[usize::from(log[usize::from(a)]) + usize::from(log[usize::from(b)])]
}

fn gf_inv(a: u8) -> Result<u8, ErasureError> {
    if a == 0 {
        return Err(ErasureError::Singular);
    }
    let (exp, log) = tables();
    Ok(exp[255 - usize::from(log[usize::from(a)])])
}

fn tables() -> (&'static [u8; 512], &'static [u8; 256]) {
    use std::sync::OnceLock;
    static TABLES: OnceLock<([u8; 512], [u8; 256])> = OnceLock::new();
    let (exp, log) = TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = u8::try_from(x & 0xff).unwrap_or(0);
            log[usize::from(exp[i])] = u8::try_from(i).unwrap_or(0);
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        (exp, log)
    });
    (exp, log)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(byte: u8) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = byte;
        r
    }

    #[test]
    fn recommended_layout_is_three_x_and_survives_eight_losses() {
        let layout = ErasureLayout::recommended();
        assert_eq!(layout.losses_tolerated(), 8);
        assert_eq!(layout.overhead_bps().expect("layout"), 30_000);
        assert!(stripe_survives(4, layout));
        assert!(!stripe_survives(3, layout));
    }

    #[test]
    fn zero_data_or_parity_is_rejected() {
        assert_eq!(
            ErasureLayout {
                data_shards: 0,
                parity_shards: 2
            }
            .total(),
            Err(ErasureError::DataShardsZero)
        );
        assert_eq!(
            ErasureLayout {
                data_shards: 2,
                parity_shards: 0
            }
            .total(),
            Err(ErasureError::ParityShardsZero)
        );
    }

    #[test]
    fn any_four_of_twelve_rebuild_the_payload() {
        let payload: Vec<u8> = (0u8..200).collect();
        let layout = ErasureLayout::recommended();
        let stripe = encode_stripe(&root(1), &payload, layout).expect("encode");
        let drops: &[&[usize]] = &[
            &[0, 1, 2, 3, 4, 5, 6, 7],
            &[4, 5, 6, 7, 8, 9, 10, 11],
            &[0, 2, 4, 6, 8, 10, 1, 3],
        ];
        for drop in drops {
            let mut damaged = stripe.clone();
            for &i in *drop {
                damaged.shards[i] = None;
            }
            let out = reconstruct_payload(&root(1), &damaged).expect("rebuild");
            assert_eq!(out, payload);
        }
    }

    #[test]
    fn a_flipped_shard_is_ignored_and_a_ninth_loss_fails() {
        let payload = b"permanence survives operators leaving".to_vec();
        let layout = ErasureLayout::recommended();
        let mut stripe = encode_stripe(&root(9), &payload, layout).expect("encode");
        if let Some(bytes) = stripe.shards[11].as_mut() {
            bytes[0] ^= 0xff;
        }
        for i in 0..7 {
            stripe.shards[i] = None;
        }
        let out = reconstruct_payload(&root(9), &stripe).expect("one bad parity still ok");
        assert_eq!(out, payload);

        stripe.shards[8] = None;
        assert!(matches!(
            reconstruct_payload(&root(9), &stripe),
            Err(ErasureError::Unrecoverable { .. })
        ));
    }

    #[test]
    fn swapped_shard_index_does_not_satisfy_the_binding() {
        let payload = b"do not relabel a shard".to_vec();
        let layout = ErasureLayout {
            data_shards: 2,
            parity_shards: 2,
        };
        let mut stripe = encode_stripe(&root(3), &payload, layout).expect("encode");
        stripe.shards.swap(0, 1);
        stripe.shards[2] = None;
        stripe.shards[3] = None;
        assert!(matches!(
            reconstruct_payload(&root(3), &stripe),
            Err(ErasureError::Unrecoverable { .. })
        ));
    }

    #[test]
    fn empty_payload_round_trips() {
        let layout = ErasureLayout {
            data_shards: 2,
            parity_shards: 1,
        };
        let stripe = encode_stripe(&root(0), b"", layout).expect("encode");
        let mut damaged = stripe.clone();
        damaged.shards[0] = None;
        assert_eq!(reconstruct_payload(&root(0), &damaged).expect("empty"), b"");
    }

    #[test]
    fn unequal_shard_lengths_fail_closed() {
        let layout = ErasureLayout {
            data_shards: 2,
            parity_shards: 1,
        };
        let mut stripe = encode_stripe(&root(4), b"abcd", layout).expect("encode");
        if let Some(bytes) = stripe.shards[0].as_mut() {
            bytes.push(1);
            stripe.bindings[0] = shard_binding(&root(4), 0, bytes);
        }
        assert_eq!(
            reconstruct_payload(&root(4), &stripe),
            Err(ErasureError::ShardLengthMismatch)
        );
    }

    #[test]
    fn gf_mul_matches_known_aes_field_products() {
        assert_eq!(gf_mul(0, 7), 0);
        assert_eq!(gf_mul(1, 7), 7);
        assert_eq!(gf_mul(2, 2), 4);
        // xtime(0x80) under polynomial 0x11d is 0x1d.
        assert_eq!(gf_mul(0x80, 2), 0x1d);
        for a in 1u16..256 {
            let a = u8::try_from(a).unwrap_or(1);
            assert_eq!(gf_mul(a, gf_inv(a).expect("inv")), 1);
        }
    }
}
