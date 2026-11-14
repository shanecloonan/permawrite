//! G-3: every public P2P payload decoder must return `Err` or `Ok` on
//! hostile bytes. A length prefix must not panic the cursor arithmetic.

use std::io::Cursor;

use mfn_net::block_sync::{BlocksV1, GetBlocksByHeightV1};
use mfn_net::chunk_v1::ChunkV1;
use mfn_net::chunk_v2::ChunkV2;
use mfn_net::frame::{
    decode_frame_prefix, read_frame, BlockV1, ChainTipV1, GoodbyeV1, GossipEndV1, HelloV1, PingV1,
    PongV1, TxStemV1, TxV1,
};
use mfn_net::fraud_proof_v1::FraudProofV1;
use mfn_net::light_follow::{GetLightFollowV1, LightFollowV1};
use mfn_net::peer_addr::parse_peer_host_port;
use mfn_net::peer_exchange::{decode_addr, handle_frame};
use mfn_net::tx_pad::{decode_padded_tx, PADDED_TX_TAG, TX_PAD_BUCKET};
use mfn_net::validity_proof_v1::ValidityProofV1;
use mfn_net::MAX_FRAME_PAYLOAD_LEN;

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

fn exercise(bytes: &[u8]) {
    let _ = decode_frame_prefix(bytes);
    let _ = read_frame(&mut Cursor::new(bytes));
    let _ = HelloV1::decode(bytes);
    let _ = PingV1::decode(bytes);
    let _ = PongV1::decode(bytes);
    let _ = ChainTipV1::decode(bytes);
    let _ = GoodbyeV1::decode(bytes);
    let _ = GossipEndV1::decode(bytes);
    let _ = TxV1::decode_payload(bytes);
    let _ = TxStemV1::decode_payload(bytes);
    let _ = BlockV1::decode_payload(bytes);
    let _ = GetBlocksByHeightV1::decode_payload(bytes);
    let _ = BlocksV1::decode_payload(bytes);
    let _ = GetLightFollowV1::decode_payload(bytes);
    let _ = LightFollowV1::decode_payload(bytes);
    let _ = ChunkV1::decode_payload(bytes);
    let _ = ChunkV2::decode_payload(bytes);
    let _ = FraudProofV1::decode_payload(bytes);
    let _ = ValidityProofV1::decode_payload(bytes);
    let _ = decode_padded_tx(bytes);
    let _ = decode_addr(bytes);
    let _ = handle_frame(bytes, &mut Vec::new());
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = parse_peer_host_port(text);
    }
}

fn mutate(rng: &mut Rng, buf: &mut Vec<u8>) {
    if buf.is_empty() {
        buf.push(rng.byte());
        return;
    }
    match rng.below(5) {
        0 => {
            let i = rng.below(buf.len());
            buf[i] = rng.byte();
        }
        1 => buf.insert(rng.below(buf.len() + 1), rng.byte()),
        2 => {
            buf.remove(rng.below(buf.len()));
        }
        3 => {
            let n = u32::MAX.to_be_bytes();
            let i = rng.below(buf.len() + 1);
            buf.splice(i..i, n);
        }
        _ => buf.truncate(rng.below(buf.len() + 1)),
    }
    if buf.len() > 2048 {
        buf.truncate(2048);
    }
}

#[test]
fn g3_declared_frame_longer_than_the_cap_is_an_error() {
    let mut wire = (MAX_FRAME_PAYLOAD_LEN + 1).to_be_bytes().to_vec();
    wire.extend_from_slice(&[0u8; 8]);
    assert!(decode_frame_prefix(&wire).is_err());
    assert!(read_frame(&mut Cursor::new(wire)).is_err());
}

#[test]
fn g3_padded_tx_rejects_a_length_past_the_bucket() {
    let mut payload = vec![0u8; TX_PAD_BUCKET];
    payload[0] = PADDED_TX_TAG;
    payload[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode_padded_tx(&payload).is_err());
}

#[test]
fn g3_blocks_reject_an_inner_length_past_the_buffer() {
    let mut payload = vec![0x0a, 0, 0, 0, 1];
    payload.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(BlocksV1::decode_payload(&payload).is_err());
}

#[test]
fn g3_random_payloads_do_not_panic() {
    for seed in 0..48u64 {
        let mut rng = Rng::new(0x6300_0000 + seed);
        let n = rng.below(512) + 1;
        let mut buf = vec![0u8; n];
        rng.fill(&mut buf);
        exercise(&buf);
        for _ in 0..12 {
            mutate(&mut rng, &mut buf);
            exercise(&buf);
        }
    }
}
