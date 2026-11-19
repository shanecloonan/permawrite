//! G-1: bytes from a hostile peer must not panic the block, transaction,
//! or header decoders, and a huge length prefix must not allocate.
//!
//! This is a deterministic mutational exerciser. It runs under `cargo test`
//! on every PR. A nightly libFuzzer job is a later unit.

use mfn_consensus::{
    decode_block, decode_block_header, decode_bond_op, decode_storage_operator_op,
    decode_transaction,
};
use mfn_crypto::bulletproofs::decode_bulletproof;
use mfn_crypto::clsag::decode_clsag;
use mfn_crypto::codec::{Reader, Writer};
use mfn_crypto::point::generator_g;
use mfn_crypto::range::decode_range_proof;
use mfn_crypto::CryptoError;

/// xorshift64* — fixed across platforms, no `rand` dependency.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() as usize) % n
        }
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.byte();
        }
    }
}

fn leb128(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out
}

fn exercise(bytes: &[u8]) {
    let _ = decode_block_header(bytes);
    let _ = decode_transaction(bytes);
    let _ = decode_block(bytes);
    let _ = decode_clsag(bytes);
    let _ = decode_bulletproof(generator_g(), bytes);
    let _ = decode_range_proof(bytes);
    let _ = decode_bond_op(bytes);
    let _ = decode_storage_operator_op(bytes);
    let _ = Reader::new(bytes).points();
    let _ = Reader::new(bytes).scalars();
    let _ = Reader::new(bytes).blob();
}

fn mutate(rng: &mut Rng, buf: &mut Vec<u8>) {
    if buf.is_empty() {
        buf.push(rng.byte());
        return;
    }
    match rng.below(8) {
        0 => {
            let i = rng.below(buf.len());
            buf[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = rng.below(buf.len());
            buf[i] = rng.byte();
        }
        2 => {
            let i = rng.below(buf.len() + 1);
            buf.insert(i, rng.byte());
        }
        3 => {
            let i = rng.below(buf.len());
            buf.remove(i);
        }
        4 => {
            let width = 1u64 << rng.below(62);
            let v = leb128(width);
            let i = rng.below(buf.len() + 1);
            buf.splice(i..i, v);
        }
        5 => {
            let extra = rng.below(64) + 1;
            for _ in 0..extra {
                buf.push(rng.byte());
            }
        }
        6 => {
            let n = rng.below(buf.len() + 1);
            buf.truncate(n);
        }
        _ => {
            let copy = buf.clone();
            buf.extend_from_slice(&copy);
        }
    }
    if buf.len() > 8 * 1024 {
        buf.truncate(8 * 1024);
    }
}

fn interesting_prefixes() -> Vec<Vec<u8>> {
    let mut out = vec![
        Vec::new(),
        vec![0],
        vec![0xff],
        leb128(0),
        leb128(1),
        leb128(127),
        leb128(128),
        leb128(1 << 20),
        leb128(1 << 32),
        leb128(1 << 40),
        leb128(u64::MAX),
        vec![
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
        ],
    ];
    for b in 0..=255u8 {
        out.push(vec![b]);
    }
    // CLSAG: 32-byte scalar, then a point-count that cannot fit.
    let mut clsag = vec![0u8; 32];
    clsag.extend(leb128(1 << 40));
    out.push(clsag);
    // Range proof: bit-width 8, then a point vector that cannot fit.
    let mut range = leb128(8);
    range.extend(leb128(1 << 33));
    out.push(range);
    // Bulletproof: bit-width that does not fit in u32.
    out.push(leb128(u64::from(u32::MAX) + 8));
    // Declared blob longer than the buffer.
    let mut blob = leb128(64);
    blob.extend(std::iter::repeat(0x11).take(8));
    out.push(blob);
    out
}

#[test]
fn g1_structured_bombs_are_errors() {
    let clsag = {
        let mut bytes = vec![0u8; 32];
        bytes.extend(leb128(1 << 40));
        bytes
    };
    let err = decode_clsag(&clsag).expect_err("clsag bomb");
    assert!(
        matches!(err, CryptoError::CountExceedsBuffer { count, .. } if count == 1 << 40),
        "{err:?}"
    );

    let range = {
        let mut bytes = leb128(8);
        bytes.extend(leb128(1 << 33));
        bytes
    };
    let err = decode_range_proof(&range).expect_err("range bomb");
    assert!(
        matches!(err, CryptoError::CountExceedsBuffer { count, .. } if count == 1 << 33),
        "{err:?}"
    );

    let wide = leb128(u64::from(u32::MAX) + 1);
    assert!(matches!(
        decode_bulletproof(generator_g(), &wide),
        Err(CryptoError::ValueOutOfRange)
    ));

    let mut blob = Writer::new();
    blob.varint(u64::MAX);
    assert!(matches!(
        Reader::new(blob.bytes()).blob(),
        Err(CryptoError::CountExceedsBuffer { .. })
    ));
}

#[test]
fn g1_random_and_mutated_bytes_do_not_panic() {
    let prefixes = interesting_prefixes();
    for (i, prefix) in prefixes.iter().enumerate() {
        exercise(prefix);
        let mut rng = Rng::new(0x61_0000 + i as u64);
        let mut buf = prefix.clone();
        if buf.is_empty() {
            let n = rng.below(128) + 1;
            buf.resize(n, 0);
            rng.fill(&mut buf);
        }
        for _ in 0..24 {
            mutate(&mut rng, &mut buf);
            exercise(&buf);
            // Every prefix of a hostile buffer is also hostile input.
            if !buf.is_empty() {
                let cut = rng.below(buf.len());
                exercise(&buf[..cut]);
            }
        }
    }
}

#[test]
fn g1_honest_small_vectors_still_round_trip() {
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::traits::Identity;
    let point = EdwardsPoint::identity();
    let mut w = Writer::new();
    w.points(&[point]);
    w.scalars(&[curve25519_dalek::scalar::Scalar::from(3u64)]);
    w.blob(&[1, 2, 3, 4]);
    let bytes = w.into_bytes();
    let mut r = Reader::new(&bytes);
    assert_eq!(r.points().expect("point").len(), 1);
    assert_eq!(r.scalars().expect("scalar").len(), 1);
    assert_eq!(r.blob().expect("blob"), &[1, 2, 3, 4]);
    assert!(r.end());
}
