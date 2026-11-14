//! Fixed-size buckets for transaction gossip.
//!
//! A passive observer that only sees frame lengths can still tell a small
//! payment from a large one. Padded frames round the body up to a 1024-byte
//! bucket and align the send to a 100ms grid so two transactions that enter
//! in the same window leave together.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Gossip tag for a length-prefixed, zero-padded transaction body.
pub const PADDED_TX_TAG: u8 = 0x17;
/// Bucket size. Every padded frame payload is a multiple of this.
pub const TX_PAD_BUCKET: usize = 1024;
/// Relay grid. Sends wait until the next boundary.
pub const TX_RELAY_QUANTUM: Duration = Duration::from_millis(100);

static TX_PADDING: AtomicBool = AtomicBool::new(false);

/// Turn on padded transaction sends for this process.
pub fn enable_tx_padding() {
    TX_PADDING.store(true, Ordering::Relaxed);
}

/// Whether sends should use [`encode_padded_tx`].
pub fn tx_padding_enabled() -> bool {
    TX_PADDING.load(Ordering::Relaxed)
}

/// `tag || u32be real_len || body || zeros`, length a multiple of [`TX_PAD_BUCKET`].
pub fn encode_padded_tx(body: &[u8]) -> Result<Vec<u8>, String> {
    let raw = 5usize.saturating_add(body.len());
    if raw > 4 * 1024 * 1024 {
        return Err("padded transaction exceeds 4 MiB".into());
    }
    let buckets = raw.div_ceil(TX_PAD_BUCKET);
    let mut out = vec![0u8; buckets * TX_PAD_BUCKET];
    out[0] = PADDED_TX_TAG;
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    out[1..5].copy_from_slice(&len.to_be_bytes());
    out[5..5 + body.len()].copy_from_slice(body);
    Ok(out)
}

/// Recover the transaction body from [`encode_padded_tx`].
pub fn decode_padded_tx(payload: &[u8]) -> Result<&[u8], String> {
    if payload.first() != Some(&PADDED_TX_TAG) {
        return Err("not a padded transaction".into());
    }
    if payload.len() < 5 || payload.len() % TX_PAD_BUCKET != 0 {
        return Err("padded transaction is not a full bucket".into());
    }
    let len = u32::from_be_bytes(payload[1..5].try_into().unwrap_or([0; 4])) as usize;
    let Some(end) = 5usize.checked_add(len) else {
        return Err("padded length exceeds the bucket".into());
    };
    let body = payload
        .get(5..end)
        .ok_or("padded length exceeds the bucket")?;
    Ok(body)
}

fn relay_epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Next grid instant strictly after `now`.
pub fn next_relay_instant(now: Instant) -> Instant {
    let start = relay_epoch();
    if now < start {
        return now + TX_RELAY_QUANTUM;
    }
    let elapsed = now.saturating_duration_since(start);
    let quantum = TX_RELAY_QUANTUM.as_nanos().max(1);
    let steps = elapsed.as_nanos() / quantum;
    let boundary =
        start + Duration::from_nanos(u64::try_from((steps + 1) * quantum).unwrap_or(u64::MAX));
    if boundary <= now {
        now + TX_RELAY_QUANTUM
    } else {
        boundary
    }
}

/// Wait used by the send path. Zero when padding is off.
pub fn relay_wait(now: Instant) -> Duration {
    if !tx_padding_enabled() {
        return Duration::ZERO;
    }
    next_relay_instant(now).saturating_duration_since(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn different_bodies_share_a_bucket_and_round_trip() {
        let small = encode_padded_tx(&[1u8; 10]).unwrap();
        let medium = encode_padded_tx(&[2u8; 400]).unwrap();
        assert_eq!(small.len(), TX_PAD_BUCKET);
        assert_eq!(medium.len(), TX_PAD_BUCKET);
        assert_eq!(decode_padded_tx(&small).unwrap(), &[1u8; 10]);
        assert_eq!(decode_padded_tx(&medium).unwrap(), &[2u8; 400]);
        assert_ne!(small.len(), 10);
        assert_ne!(medium.len(), 400);
    }

    #[test]
    fn two_sockets_exchange_a_padded_transaction() {
        let body = b"padded-payment-body";
        let wire = encode_padded_tx(body).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let expected = wire.clone();
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut got = vec![0u8; expected.len()];
            sock.read_exact(&mut got).unwrap();
            assert_eq!(got.len(), TX_PAD_BUCKET);
            assert_ne!(got.len(), body.len());
            decode_padded_tx(&got).unwrap().to_vec()
        });
        let mut sock = std::net::TcpStream::connect(addr).unwrap();
        sock.write_all(&wire).unwrap();
        assert_eq!(server.join().unwrap(), body);
    }

    #[test]
    fn same_quantum_shares_one_release_instant() {
        let _ = next_relay_instant(Instant::now());
        let now = Instant::now();
        let a = next_relay_instant(now);
        let b = next_relay_instant(now + Duration::from_millis(1));
        assert_eq!(a, b);
        assert!(a >= now);
        assert!(a - now <= TX_RELAY_QUANTUM);
    }
}
