//! Hostile bytes for the canonical codec and the signatures that sit on it.
//!
//! Every case must return `Ok` or a typed error. A panic here is a remote
//! crash: block, transaction, and checkpoint decoders all use [`Reader`].

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use mfn_crypto::{decode_bulletproof, decode_clsag, CryptoError, Reader, Writer};

/// xorshift64. Fixed seed so a failure names the same input next run.
struct Mix(u64);

impl Mix {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn fill(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn basepoint() -> EdwardsPoint {
    // Canonical ed25519 base point. Decompress does not need the precomputed
    // tables feature.
    let y: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];
    CompressedEdwardsY(y)
        .decompress()
        .expect("ed25519 base point")
}

fn one_scalar() -> Scalar {
    let mut b = [0u8; 32];
    b[0] = 1;
    Scalar::from_bytes_mod_order(b)
}

fn exercise(bytes: &[u8]) {
    let _ = Reader::new(bytes).varint();
    let _ = Reader::new(bytes).blob();
    let _ = Reader::new(bytes).scalars();
    let _ = Reader::new(bytes).points();
    let _ = Reader::new(bytes).u64();
    let _ = decode_clsag(bytes);
    let _ = decode_bulletproof(basepoint(), bytes);
}

#[test]
fn writer_outputs_round_trip_under_the_new_bounds() {
    let p = basepoint();
    let s = one_scalar();
    let mut w = Writer::new();
    w.varint(u64::MAX);
    w.blob(&[0, 1, 2, 255]);
    w.scalars(&[s, s]);
    w.points(&[p]);
    let bytes = w.into_bytes();

    let mut r = Reader::new(&bytes);
    assert_eq!(r.varint().unwrap(), u64::MAX);
    assert_eq!(r.blob().unwrap(), &[0, 1, 2, 255]);
    let scalars = r.scalars().unwrap();
    assert_eq!(scalars.len(), 2);
    assert_eq!(scalars[0], s);
    let points = r.points().unwrap();
    assert_eq!(points.len(), 1);
    assert_eq!(points[0].compress().as_bytes(), p.compress().as_bytes());
    assert!(r.end());
}

#[test]
fn clsag_with_a_million_s_values_and_four_payload_bytes_is_rejected() {
    let mut body = Vec::new();
    {
        let mut w = Writer::new();
        w.scalar(&one_scalar());
        w.varint(1_000_000);
        body.extend_from_slice(w.bytes());
    }
    body.extend_from_slice(&[9, 9, 9, 9]);
    let err = decode_clsag(&body).expect_err("count does not fit");
    assert!(
        matches!(err, CryptoError::ShortBuffer { .. }),
        "got {err:?}"
    );
}

#[test]
fn bulletproof_with_a_huge_ipa_vector_is_rejected() {
    let mut body = Vec::new();
    {
        let mut w = Writer::new();
        w.varint(64); // a legal bit-width, so the failure is the vector
        w.point(&basepoint());
        w.point(&basepoint());
        w.point(&basepoint());
        w.point(&basepoint());
        w.scalar(&one_scalar());
        w.scalar(&one_scalar());
        w.scalar(&one_scalar());
        w.varint(50_000);
        body.extend_from_slice(w.bytes());
    }
    body.extend_from_slice(&[1, 2, 3, 4]);
    let err = decode_bulletproof(basepoint(), &body).expect_err("ipa vector");
    assert!(
        matches!(err, CryptoError::ShortBuffer { .. }),
        "got {err:?}"
    );
}

#[test]
fn empty_and_truncated_prefixes_are_errors() {
    exercise(&[]);
    exercise(&[0x80]);
    exercise(&[0x80, 0x80]);
    exercise(&[0xff; 9]);
    let mut ten = vec![0xff; 9];
    ten.push(0x02);
    let err = Reader::new(&ten).varint().expect_err("overflow group");
    assert!(matches!(err, CryptoError::VarintTooLong));
}

#[test]
fn flipping_each_byte_of_a_valid_frame_does_not_panic() {
    let mut w = Writer::new();
    w.varint(3);
    w.blob(b"permawrite");
    w.scalars(&[one_scalar(), one_scalar(), one_scalar()]);
    w.points(&[basepoint(), basepoint()]);
    let honest = w.into_bytes();
    exercise(&honest);
    for i in 0..honest.len() {
        for bit in 0..8 {
            let mut tweaked = honest.clone();
            tweaked[i] ^= 1 << bit;
            exercise(&tweaked);
        }
    }
}

#[test]
fn deterministic_corpus_covers_short_and_medium_frames() {
    let mut mix = Mix(0x6d66_5f67_3130_0001);
    for n in 0..=96 {
        exercise(&mix.fill(n));
    }
    for _ in 0..256 {
        let n = (mix.next() as usize) % 512;
        exercise(&mix.fill(n));
    }
    // Declared counts that are individually legal u64 values but larger
    // than any frame a peer is allowed to send.
    for claimed in [0u64, 1, 31, 32, 33, 1_000, 1 << 20, u64::MAX] {
        let mut w = Writer::new();
        w.varint(claimed);
        let mut bytes = w.into_bytes();
        bytes.extend_from_slice(&mix.fill(24));
        exercise(&bytes);
    }
}
