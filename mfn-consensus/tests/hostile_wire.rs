//! Block, header, and transaction decoders must survive hostile frames.
//!
//! These codecs sit on `mfn_crypto::Reader`. A panic is a process crash on
//! any peer that gossips the bytes. Acceptance rules for honest blocks are
//! unchanged: every input here is structurally invalid.

use mfn_consensus::{decode_block, decode_block_header, decode_transaction};

fn exercise(bytes: &[u8]) {
    let _ = decode_transaction(bytes);
    let _ = decode_block_header(bytes);
    let _ = decode_block(bytes);
}

/// xorshift64, fixed seed.
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

#[test]
fn empty_and_varint_bombs_are_rejected() {
    exercise(&[]);
    exercise(&[0x80]);
    // Ten-byte varint whose last group does not fit in u64.
    let mut bomb = vec![0xff; 9];
    bomb.push(0x02);
    exercise(&bomb);
    // Transaction-shaped: version, then a blob length of 2^63.
    let mut tx = vec![0x02]; // version = 2, a single-byte varint
    tx.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]);
    exercise(&tx);
}

#[test]
fn declared_input_count_larger_than_the_frame_is_rejected() {
    // version=2, a real Edwards point for R, fee 0, empty extra, then an
    // input count of one million and four leftover bytes. The ring vector
    // must be refused before it is allocated.
    let r_pub: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];
    let mut bytes = Vec::new();
    bytes.push(0x02);
    bytes.extend_from_slice(&r_pub);
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.push(0x00);
    // 1_000_000 as LEB128.
    bytes.extend_from_slice(&[0xc0, 0x84, 0x3d]);
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    let err = decode_transaction(&bytes).expect_err("hostile tx");
    let rendered = err.to_string();
    assert!(
        rendered.contains("short buffer") || rendered.contains("codec"),
        "typed codec error, got {rendered}"
    );
}

#[test]
fn random_frames_do_not_panic_the_three_decoders() {
    let mut mix = Mix(0x6731_5f77_6972_6501);
    for n in 0..=64 {
        exercise(&mix.fill(n));
    }
    for _ in 0..128 {
        let n = (mix.next() as usize) % 400;
        exercise(&mix.fill(n));
    }
}
